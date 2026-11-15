"""Identical, explicit prefix truncation for base, tuned, training and validation pairs."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
import math
from typing import Any

import torch


POLICY = "g8.bert-prefix-query128-pair384/v1"
MAX_TEXT = 20_000
MAX_LINE = 4_200_000


@dataclass(frozen=True)
class Truncation:
    policy: str
    query_tokens: int
    query_used: int
    passage_tokens: int
    passage_used: int


def pair(tokenizer: Any, query: str, passage: str) -> tuple[dict[str, list[int]], Truncation]:
    for value in (query, passage):
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_TEXT or "\x00" in value:
            raise ValueError("text_bound")
        value.encode("utf-8", errors="strict")
    q: list[int] = tokenizer.encode(query, add_special_tokens=False)
    p: list[int] = tokenizer.encode(passage, add_special_tokens=False)
    used_q = q[:128]
    used_p = p[:384 - 3 - len(used_q)]
    result = {"input_ids": tokenizer.build_inputs_with_special_tokens(used_q, used_p),
              "token_type_ids": tokenizer.create_token_type_ids_from_sequences(used_q, used_p)}
    result["attention_mask"] = [1] * len(result["input_ids"])
    return result, Truncation(POLICY, len(q), len(used_q), len(p), len(used_p))


def batch(tokenizer: Any, pairs: Sequence[tuple[str, str]]) -> tuple[dict[str, torch.Tensor], list[Truncation]]:
    encoded, truncation = [], []
    for query, passage in pairs:
        row, record = pair(tokenizer, query, passage)
        encoded.append(row)
        truncation.append(record)
    width = max(len(row["input_ids"]) for row in encoded)
    tensors = {}
    for key in ("input_ids", "attention_mask", "token_type_ids"):
        pad = tokenizer.pad_token_id if key == "input_ids" else 0
        tensors[key] = torch.tensor([r[key] + [pad] * (width - len(r[key])) for r in encoded], dtype=torch.long)
    return tensors, truncation


def scores(model: Any, tokenizer: Any, query: str, passages: Sequence[tuple[str, str]]) -> list[dict[str, Any]]:
    if not 1 <= len(passages) <= 50 or len({p[0] for p in passages}) != len(passages):
        raise ValueError("passage_count_or_duplicate")
    model.eval()
    result: list[dict[str, Any]] = []
    with torch.inference_mode():
        for start in range(0, len(passages), 8):
            selected = passages[start:start + 8]
            inputs, truncation = batch(tokenizer, [(query, text) for _, text in selected])
            values = model(**inputs).logits.reshape(-1).tolist()
            if any(not math.isfinite(v) for v in values):
                raise ValueError("nonfinite_score")
            result.extend({"id": identity, "score": value, "truncation": asdict(record)}
                          for (identity, _), value, record in zip(selected, values, truncation, strict=True))
    return result
