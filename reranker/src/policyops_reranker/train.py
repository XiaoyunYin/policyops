"""Preregistered G8 CPU recipe. No paid calls, downloads or pickle checkpoints.

Unstable means nonfinite loss/gradient or final internal nDCG@10 more than 0.02
below the initial checkpoint. Only that condition permits one fresh 1e-5 attempt.
Every attempt survives in attempts.json, including exceptions and interrupted runs.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
import random
import time
from typing import Any

import torch
from torch.nn import functional as functional

from policyops_reranker.model import canonical, load, private_output, seal, sha256
from policyops_reranker.score import POLICY, batch, pair, scores


SEED = 20261114
RECIPE = {"dtype": "float32", "device": "cpu", "batch": 8, "accumulation": 4,
          "optimizer": "AdamW", "weight_decay": 0.01, "learning_rate": 2e-5, "retry_learning_rate": 1e-5,
          "epochs": 1, "seed": SEED, "max_optimizer_steps": 1500, "checkpoint_every": 100,
          "truncation_policy": POLICY, "unstable": "nonfinite loss/gradient or final ndcg10 < initial - 0.02"}


class Unstable(ValueError):
    pass


def read_rows(path: Path, manifest: Path) -> list[dict[str, Any]]:
    # 6,600 mined queries with 40 frozen validation candidates each measured 743 MB; bound at 1 GB.
    if manifest.stat().st_size > 1_000_000 or path.stat().st_size > 1_000_000_000:
        raise ValueError("triples_manifest_bounds")
    value = json.loads(manifest.read_bytes())
    if sha256(path) != value["triples_sha256"]:
        raise ValueError("triples_identity_or_bound")
    rows: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        while raw := handle.readline(5_000_001):
            if len(raw) > 5_000_000 or len(rows) >= 10_000:
                raise ValueError("triples_bounds")
            row = json.loads(raw)
            if (row["partition"] not in {"train", "internal_validation"}
                    or not isinstance(row["query"], str) or not 1 <= len(row["negatives"]) <= 2
                    or not 1 <= len(row["candidates"]) <= 50):
                raise ValueError("triples_shape")
            positive = row["positive"]["id"]
            known = set(row["known_positive_ids"])
            if positive not in known or any(n["id"] in known for n in row["negatives"]):
                raise ValueError("negative_is_positive")
            if any(type(p["relevant"]) is not bool or p["relevant"] != (p["id"] in known)
                   for p in row["candidates"]):
                raise ValueError("validation_labels")
            rows.append(row)
    train = [r for r in rows if r["partition"] == "train"]
    valid = [r for r in rows if r["partition"] == "internal_validation"]
    if (not train or not valid or len(train) > 6000 or len({r["query_id"] for r in rows}) != len(rows)
            or {r["dialogue_id"] for r in train} & {r["dialogue_id"] for r in valid}):
        raise ValueError("training_partition_audit")
    return rows


def ndcg(model: Any, tokenizer: Any, rows: list[dict[str, Any]]) -> float:
    total = 0.0
    for row in rows:
        candidates = row["candidates"]
        ranked = sorted(scores(model, tokenizer, row["query"], [(p["id"], p["text"]) for p in candidates]),
                        key=lambda p: (-p["score"], p["id"]))[:10]
        gold = set(row["known_positive_ids"])
        dcg = sum(1 / math.log2(i + 2) for i, p in enumerate(ranked) if p["id"] in gold)
        ideal = sum(1 / math.log2(i + 2) for i in range(min(10, len(gold))))
        total += dcg / ideal if ideal else 0
    return total / len(rows)


def fit(model: Any, tokenizer: Any, train: list[dict[str, Any]], validation: list[dict[str, Any]], *,
        learning_rate: float, record: dict[str, Any]) -> dict[str, torch.Tensor]:
    """One shuffled epoch; a partial final accumulation is normalized by its actual examples."""
    torch.manual_seed(SEED)
    examples = [(r["query"], r["positive"]["text"], n["text"]) for r in train for n in r["negatives"]]
    random.Random(SEED).shuffle(examples)  # noqa: S311 -- reproducible experimental order, not security
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    baseline = ndcg(model, tokenizer, validation)
    record.update(initial_ndcg10=baseline, steps=0, checkpoints=[{"step": 0, "ndcg10": baseline}], selected_step=0)
    best, selected = baseline, {k: v.detach().clone() for k, v in model.state_dict().items()}
    # 32 examples = batch8 x accumulation4. Forward halves keep physical batches at <=8 pairs.
    for offset in range(0, min(len(examples), 1500 * 32), 32):
        group = examples[offset:offset + 32]
        optimizer.zero_grad(set_to_none=True)
        model.train()
        loss_sum = 0.0
        for start in range(0, len(group), 8):
            micro = group[start:start + 8]
            positive, _ = batch(tokenizer, [(q, p) for q, p, _ in micro])
            negative, _ = batch(tokenizer, [(q, n) for q, _, n in micro])
            loss = functional.softplus(-(model(**positive).logits.reshape(-1)
                                        - model(**negative).logits.reshape(-1))).sum() / len(group)
            if not torch.isfinite(loss).item():
                raise Unstable("nonfinite_loss")
            loss.backward()  # type: ignore[no-untyped-call]  # torch's Tensor.backward lacks argument types
            loss_sum += float(loss.detach())
        if any(p.grad is not None and not torch.isfinite(p.grad).all().item() for p in model.parameters()):
            raise Unstable("nonfinite_gradient")
        optimizer.step()
        record["steps"] += 1
        record.setdefault("loss", []).append(loss_sum)
        final = offset + 32 >= min(len(examples), 1500 * 32)
        if record["steps"] % 100 == 0 or final:
            value = ndcg(model, tokenizer, validation)
            record["checkpoints"].append({"step": record["steps"], "ndcg10": value})
            if value > best:  # deterministic ties retain the earliest checkpoint, including baseline
                best, selected = value, {k: v.detach().clone() for k, v in model.state_dict().items()}
                record["selected_step"] = record["steps"]
            if final and value < baseline - 0.02:
                raise Unstable("validation_drop_gt_0.02")
    record["selected_ndcg10"] = best
    return selected


def code_hash() -> str:
    directory = Path(__file__).parent
    return hashlib.sha256(canonical({p.name: sha256(p) for p in sorted(directory.glob("*.py"))})).hexdigest()


def train(base: Path, triples: Path, mining_manifest: Path, output: Path, *, threads: int) -> str:
    private_output(output)
    rows = read_rows(triples, mining_manifest)
    output.mkdir(parents=True, exist_ok=False)
    train_rows = [r for r in rows if r["partition"] == "train"]
    validation = [r for r in rows if r["partition"] == "internal_validation"]
    attempts: list[dict[str, Any]] = []
    started = time.monotonic()
    for learning_rate in (2e-5, 1e-5):
        record: dict[str, Any] = {"attempt": len(attempts) + 1, "learning_rate": learning_rate, "status": "running"}
        attempts.append(record)
        receipt = output / "attempts.json"
        receipt.write_bytes(canonical({"recipe": RECIPE, "attempts": attempts}))
        attempt_started = time.monotonic()
        try:
            model, tokenizer, base_identity = load(base, threads=threads)
            # Persist exact per-pair truncation once, identically for either attempt.
            if len(attempts) == 1:
                with (output / "truncation.jsonl").open("xb") as handle:
                    for row in rows:
                        pairs = {p["id"]: p for p in [row["positive"], *row["negatives"], *row["candidates"]]}
                        for passage in pairs.values():
                            _, truncation = pair(tokenizer, row["query"], passage["text"])
                            handle.write(canonical({"query_id": row["query_id"], "passage_id": passage["id"],
                                                    **asdict(truncation)}) + b"\n")
            selected = fit(model, tokenizer, train_rows, validation, learning_rate=learning_rate, record=record)
            record["status"] = "complete"
        except Unstable as error:
            record.update(status="unstable", reason=str(error))
            if len(attempts) == 2:
                raise
            continue
        except BaseException as error:
            record.update(status="failed", reason=type(error).__name__)
            raise
        finally:
            record["seconds"] = time.monotonic() - attempt_started
            receipt.write_bytes(canonical({"recipe": RECIPE, "attempts": attempts}))
        artifact = output / "artifact"
        artifact.mkdir()
        model.load_state_dict(selected)
        model.save_pretrained(str(artifact), safe_serialization=True)
        tokenizer.save_pretrained(str(artifact))
        if (base / "README.md").is_file():
            (artifact / "README.md").write_bytes((base / "README.md").read_bytes())
        (artifact / "truncation.jsonl").write_bytes((output / "truncation.jsonl").read_bytes())
        manifest = {"schema": "policyops.g8-training/v1", "recipe": RECIPE, "attempts": attempts,
                    "base_artifact_sha256": base_identity, "triples_sha256": sha256(triples),
                    "mining_manifest_sha256": sha256(mining_manifest), "code_sha256": code_hash(),
                    "lock_sha256": sha256(Path(__file__).resolve().parents[2] / "uv.lock"),
                    "threads": threads, "train_queries": len(train_rows), "validation_queries": len(validation),
                    "selected_checkpoint": record["selected_step"], "seconds": time.monotonic() - started,
                    "rights": "base Apache-2.0; MS MARCO non-commercial research lineage; MultiDoc2Dial CC BY 3.0"}
        (artifact / "training-manifest.json").write_bytes(canonical(manifest))
        identity = seal(artifact)
        (output / "artifact.sha256").write_bytes((identity + "\n").encode())
        return identity
    raise ValueError("no_stable_attempt")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--triples", type=Path, required=True)
    parser.add_argument("--mining-manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    print(json.dumps({"artifact_sha256": train(args.base, args.triples, args.mining_manifest,
                                             args.out, threads=args.threads)}))


if __name__ == "__main__":
    main()
