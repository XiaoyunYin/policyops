"""Bounded serial stdio worker. One response per request; EOF terminates the worker."""
from __future__ import annotations

import argparse
from collections.abc import Callable
import json
from pathlib import Path
import sys
from typing import Any, BinaryIO

from policyops_reranker.model import canonical, load
from policyops_reranker.score import MAX_LINE, MAX_TEXT, scores


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def request(raw: bytes) -> tuple[str, list[tuple[str, str]], int]:
    if len(raw) > MAX_LINE or not raw.endswith(b"\n"):
        raise ValueError("line_bound")
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) != {"query", "passages", "top_k"}:
        raise ValueError("request_fields")
    query, passages, top_k = value["query"], value["passages"], value["top_k"]
    if not isinstance(passages, list) or not 1 <= len(passages) <= 50:
        raise ValueError("passage_count")
    if type(top_k) is not int or not 1 <= top_k <= len(passages):
        raise ValueError("top_k_bound")
    selected = []
    for row in passages:
        if (not isinstance(row, dict) or set(row) != {"id", "text"} or not isinstance(row["id"], str)
                or not 1 <= len(row["id"]) <= 100 or not row["id"].isascii()
                or any(ord(c) < 32 for c in row["id"])):
            raise ValueError("passage_shape")
        selected.append((row["id"], row["text"]))
    for text in [query, *(p[1] for p in selected)]:
        if not isinstance(text, str) or not 1 <= len(text) <= MAX_TEXT or "\x00" in text:
            raise ValueError("text_bound")
        text.encode("utf-8", errors="strict")
    if len({p[0] for p in selected}) != len(selected):
        raise ValueError("duplicate_passage")
    return query, selected, top_k


def worker(source: BinaryIO, sink: BinaryIO, identity: str,
           score: Callable[[str, list[tuple[str, str]]], list[dict[str, Any]]]) -> int:
    while raw := source.readline(MAX_LINE + 1):
        # Never drain an attacker-controlled oversized line.
        if len(raw) > MAX_LINE:
            sink.write(canonical({"error": "line_bound"}) + b"\n")
            sink.flush()
            return 2
        try:
            query, passages, top_k = request(raw)
            rows = score(query, passages)
            ranking = sorted(rows, key=lambda r: (-r["score"], r["id"]))[:top_k]
            response = {"artifact_sha256": identity, "scores": rows, "ranking": [r["id"] for r in ranking]}
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            response = {"error": "invalid_request_or_score"}
        sink.write(canonical(response) + b"\n")
        sink.flush()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    model, tokenizer, identity = load(args.artifact, threads=args.threads, expected_sha256=args.expected_sha256)
    return worker(sys.stdin.buffer, sys.stdout.buffer, identity,
                  lambda query, passages: scores(model, tokenizer, query, passages))


if __name__ == "__main__":
    raise SystemExit(main())
