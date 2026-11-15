"""Read-only BM25 snapshot probe: paired cached/recomputed statistics, no provider calls or query text output."""
from __future__ import annotations

import argparse
from collections.abc import Sequence
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any
from uuid import UUID

import psycopg
from sqlalchemy import text

from policyops.persistence.database import RUNTIME_CONNECT_OPTIONS, SqlProfile, make_engine, workspace_transaction
from policyops.persistence.retrieval import (
    ANY_TERMS_QUERY_SQL,
    BM25_DF_CTE,
    BM25_STATS_SQL,
    RetrievalStore,
    StepRefused,
)
from policyops.providers.tokenizer import load as load_tokenizer


ROOT = Path(__file__).resolve().parents[1]


def queries(path: Path, manifest: Path, limit: int, profile: str) -> tuple[list[tuple[str, str]], str]:
    """Only the manifest's dev cohort; bound and hash the entire private materialization before any DB call."""
    value = json.loads(manifest.read_bytes())
    ids = value["cohorts"]["dev"]["query_ids"][:limit]
    wanted = set(ids)
    found = {}
    digest = hashlib.sha256()
    total = 0
    tokenizer = load_tokenizer()
    with path.open("rb") as handle:
        while line := handle.readline(200_001):
            total += len(line)
            if len(line) > 200_000 or total > 128_000_000:
                raise ValueError("materialization_bounds")
            digest.update(line)
            row = json.loads(line)
            identity = row["query_id"]
            if identity in wanted:
                query = row["retrieval" if profile == "history-four-v1" else "last_turn"]
                if (identity in found or not isinstance(query, str) or not 1 <= len(query) <= 100_000
                        or tokenizer.count(query) > 1024):
                    raise ValueError("query_bounds_or_duplicate")
                found[identity] = query
    if digest.hexdigest() != value["materialization_sha256"]["queries.jsonl"] or found.keys() != wanted:
        raise ValueError("materialization_identity")
    return [(q, found[q]) for q in ids], digest.hexdigest()


def percentile(samples: list[float], fraction: float) -> float | None:
    return sorted(samples)[max(0, math.ceil(fraction * len(samples)) - 1)] if samples else None


def output_path(path: Path) -> Path:
    raw = os.environ.get("POLICYOPS_TEMP_DIR")
    if not raw or not Path(raw).is_absolute():
        raise ValueError("absolute_POLICYOPS_TEMP_DIR_required")
    root, target = Path(raw).resolve(), path.resolve()
    if (not target.is_relative_to(root) or target == root or target.is_relative_to(ROOT)
            or any(p.is_symlink() or p.is_junction() for p in (path, *path.parents))):
        raise ValueError("output_must_be_private_temporary_file")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def probe(args: argparse.Namespace) -> dict[str, Any]:
    target = output_path(args.out)
    selected, query_hash = queries(args.queries, args.manifest, args.limit, args.profile)
    dsn = args.app_dsn_file.read_text(encoding="utf-8").strip()
    engine = make_engine(lambda: psycopg.connect(dsn, options=RUNTIME_CONNECT_OPTIONS, connect_timeout=5))
    records: list[dict[str, Any]] = []
    try:
        cached = RetrievalStore(engine, args.workspace)
        with workspace_transaction(engine, args.workspace, profile=SqlProfile.RETRIEVAL) as connection:
            stats = dict(connection.execute(text(BM25_STATS_SQL), {"g": args.generation}).mappings().one())
            if stats["n"] != args.expected_chunks:
                raise ValueError("generation_chunk_count_mismatch")
            parsed = connection.execute(text(ANY_TERMS_QUERY_SQL),
                                        {"q": selected[0][1], "lexeme_cap": 64}).mappings().one()
            # Composed exclusively from the module's static SQL; all data remains bound.
            plan = connection.execute(text("EXPLAIN (FORMAT JSON) WITH " + BM25_DF_CTE.rstrip(", ") +  # noqa: S608
                                           " SELECT * FROM df"),
                                      {"g": args.generation, "lexemes": parsed["lexemes"]}).scalar_one()

        def snapshot(store: RetrievalStore, query: str) -> tuple[tuple[object, ...], ...]:
            result = store.snapshot(corpus_key=args.corpus, mode="lexical", query=query, query_vector=None,
                                    document_ids=(), branch_documents=20, chunks_per_document=1,
                                    full_policy_max_chunks=1, lexical_mode="bm25")
            if result.generation_id != args.generation or result.text_oversized:
                raise ValueError("snapshot_generation_or_text_mismatch")
            return tuple((h.document_id, h.score, h.chunk_ids) for h in result.lexical)

        for _ in range(args.warmup):
            snapshot(cached, selected[0][1])
        for repetition in range(args.repetitions):
            for index, (identity, query) in enumerate(selected):
                outputs = []
                variants = ("cached", "recomputed") if index % 2 == 0 else ("recomputed", "cached")
                for variant in variants:
                    # Constructor role verification is outside both timers. A fresh store has an empty stats cache.
                    store = cached if variant == "cached" else RetrievalStore(engine, args.workspace)
                    start = time.perf_counter()
                    status = "ok"
                    try:
                        outputs.append(snapshot(store, query))
                    except StepRefused as error:
                        if error.code != "lexical_query_too_many_lexemes":
                            raise
                        outputs.append(())
                        status = error.code
                    records.append({"question_id": identity, "repetition": repetition, "variant": variant,
                                    "status": status, "milliseconds": (time.perf_counter() - start) * 1000})
                if outputs[0] != outputs[1]:
                    raise ValueError("cached_recomputed_score_mismatch")
        summary = {}
        for variant in ("cached", "recomputed"):
            rows = [r for r in records if r["variant"] == variant]
            times = [r["milliseconds"] for r in rows if r["status"] == "ok"]
            summary[variant] = {"successful": len(times), "refused": len(rows) - len(times),
                                "p50_ms": percentile(times, 0.5), "p95_ms": percentile(times, 0.95)}
        report = {"schema": "policyops.bm25-latency/v1", "generation": str(args.generation),
                  "workspace": str(args.workspace), "chunks": stats["n"], "avgdl": stats["avgdl"],
                  "profile": args.profile, "query_materialization_sha256": query_hash,
                  "machine": platform.platform(), "python": platform.python_version(),
                  "warmup": args.warmup, "branch_documents": 20, "summary": summary,
                  "percentile": "nearest-rank; successful snapshots only; refusals reported separately",
                  "timing": "full snapshot; constructor role verification excluded; alternated paired variants",
                  "df_plan": plan, "samples": records,
                  "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in
                      ("scripts/bm25_latency_probe.py", "packages/policyops/src/policyops/persistence/retrieval.py")}}
        target.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        return {"artifact": str(target), "summary": summary, "chunks": stats["n"]}
    finally:
        engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-dsn-file", type=Path, required=True)
    parser.add_argument("--workspace", type=UUID, required=True)
    parser.add_argument("--generation", type=UUID, required=True)
    parser.add_argument("--corpus", default="multidoc2dial-v1-struct")
    parser.add_argument("--queries", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=ROOT / "evals/manifests/multidoc2dial-v1/manifest.json")
    parser.add_argument("--profile", choices=("history-four-v1", "last-user-turn-v1"), default="history-four-v1")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--expected-chunks", type=int, default=4110)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not (1 <= args.limit <= 500 and 1 <= args.repetitions <= 10 and 1 <= args.warmup <= 20
            and 1 <= args.expected_chunks <= 10_000):
        parser.error("probe bounds exceeded")
    try:
        print(json.dumps(probe(args), sort_keys=True))
        return 0
    except Exception as error:
        # Connection exceptions can contain credentials. Emit only the exception class, never its text or locals.
        print(json.dumps({"failed": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
