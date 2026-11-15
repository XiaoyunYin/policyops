"""Train-only G8 mining; pinned dataset, frozen retrieval and one capped embedding job.

Internal validation is the first ceil(10% of eligible pool dialogues) by a separate
seeded hash. Independently hash-rank queries within each partition, taking <=6000
training and <=600 internal-validation queries. Dev and all official validation
queries participate only in duplicate exclusion, never retrieval or training.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import replace
from decimal import Decimal
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Literal
from uuid import UUID

import psycopg
from sqlalchemy import Engine

from policyops.budget.config import Caps, Configuration, EmbeddingActor
from policyops.budget.ledger import Ledger
from policyops.persistence.budget import AppLedgerStore
from policyops.persistence.database import RUNTIME_CONNECT_OPTIONS, make_engine
from policyops.persistence.retrieval import RetrievalStore, Snapshot, StepRefused
from policyops.providers.calls import Providers
from policyops.providers.embedding_calls import pack, prepare_job, run_job_sync
from policyops.providers.tokenizer import load as load_tokenizer
from policyops.retrieval.rank import fuse
from policyops_contracts.embedding import EmbeddingJob
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.datasets import multidoc2dial as md
from policyops_evals.qa_studies.runner import RetrieverExecutor
from policyops_evals.studies import bundles


SEED = 20261114
LexicalMode = Literal["all_terms", "any_terms"]
ROOT = Path(__file__).resolve().parents[4]


def rank(identity: str, prefix: str) -> tuple[str, str]:
    return sha256_bytes(f"{prefix}|{SEED}|{identity}".encode()), identity


def partition(dataset: md.Dataset, *, train_limit: int = 6000, validation_limit: int = 600
              ) -> tuple[list[md.Query], list[md.Query], dict[str, Any]]:
    if not 1 <= train_limit <= 6000 or not 1 <= validation_limit <= 600:
        raise ValueError("g8_query_caps")
    selected = md.cohorts(dataset)
    audit = md.audit(dataset, selected)
    excluded = set(audit["g8_excluded_query_ids"])
    pool = set(selected["g8_pool"])
    eligible = [q for q in dataset.queries if q.split == "train" and q.dialogue_key in pool
                and q.query_id not in excluded]
    dialogues = sorted({q.dialogue_key for q in eligible}, key=lambda d: rank(d, "g8/internal-validation/v1"))
    valid_dialogues = set(dialogues[:math.ceil(len(dialogues) / 10)])
    training = sorted((q for q in eligible if q.dialogue_key not in valid_dialogues),
                      key=lambda q: rank(q.query_id, "g8/query/v1"))[:train_limit]
    validation = sorted((q for q in eligible if q.dialogue_key in valid_dialogues),
                        key=lambda q: rank(q.query_id, "g8/query/v1"))[:validation_limit]
    forbidden = {q.query_id for q in dataset.queries if q.split != "train" or q.dialogue_key not in pool} | excluded
    if (not training or not validation or forbidden & {q.query_id for q in training + validation}
            or {q.dialogue_key for q in training} & {q.dialogue_key for q in validation}):
        raise ValueError("g8_partition_audit")
    return training, validation, {
        "partition": "ceil(10% eligible pool dialogues) hash-selected internal validation, disjoint dialogues",
        "dialogue_rank": "sha256 g8/internal-validation/v1|20261114|domain/dialogue",
        "query_rank": "sha256 g8/query/v1|20261114|query_id; ties by ID",
        "training_cap": train_limit, "internal_validation_cap": validation_limit,
        "pool_dialogues": len(dialogues), "internal_validation_pool_dialogues": len(valid_dialogues),
        "duplicate_exclusions": len(excluded), "duplicate_excluded_ids_sha256": md.ids_hash(sorted(excluded)),
        "exclusion_rule": audit["g8_exclusion_rule"],
        "training_query_ids": [q.query_id for q in training],
        "internal_validation_query_ids": [q.query_id for q in validation],
        "dev_or_official_validation_selected": 0}


def safe_negative(candidate: md.Passage, gold: Sequence[md.Passage]) -> bool:
    return all(candidate.passage_id != p.passage_id and not (
        candidate.domain == p.domain and candidate.document_id == p.document_id
        and (max(candidate.start, p.start) < min(candidate.end, p.end)
             or bool(set(candidate.span_ids) & set(p.span_ids)))) for p in gold)


def triple(query: md.Query, passages: dict[str, md.Passage], dense: Sequence[str], fused: Sequence[str], *,
           split: str, lexical: Sequence[str] = ()) -> dict[str, Any] | None:
    known = set(query.passage_ids)
    if not known or not known <= passages.keys():
        raise ValueError("mining_qrel_identity")
    pool = list(dict.fromkeys(fused))
    if (len(pool) > 50 or not set(pool) <= passages.keys() or not set(dense) <= set(pool)
            or not set(lexical) <= set(pool)):
        raise ValueError("mining_candidate_identity")
    gold = [passages[p] for p in sorted(known)]
    negatives = []
    # One highest dense negative then one highest fused negative, never duplicate.
    for branch in (dense, pool):
        candidate = next((p for p in branch if p not in negatives and safe_negative(passages[p], gold)), None)
        if candidate is not None:
            negatives.append(candidate)
    if not negatives:
        return None

    def rendered(identity: str) -> dict[str, str]:
        return {"id": identity, "text": passages[identity].rendered}

    positive = min(known, key=lambda p: rank(query.query_id + "|" + p, "g8/positive/v1"))
    return {"query_id": query.query_id, "dialogue_id": query.dialogue_key, "partition": split,
            "query": query.retrieval, "positive": rendered(positive), "known_positive_ids": sorted(known),
            "negatives": [rendered(p) for p in negatives],
            "candidates": [{**rendered(p), "relevant": p in known} for p in pool],
            "frozen_dense_ids": list(dense), "frozen_fts_ids": list(lexical), "frozen_rrf_ids": pool}


def lexical_snapshot(store: RetrievalStore, corpus: str, query: str, vector: str, mode: LexicalMode) -> Snapshot:
    """G1a switch point. Fail closed if a requested lexical mode is unavailable.

    Pre-G1a all_terms remains callable; any_terms is never silently mapped to it.
    """
    arguments: dict[str, Any] = {"corpus_key": corpus, "mode": "hybrid", "query": query,
        "query_vector": vector, "document_ids": (), "branch_documents": 20,
        "chunks_per_document": 1, "full_policy_max_chunks": 1}
    if "lexical_mode" in inspect.signature(store.snapshot).parameters:
        arguments["lexical_mode"] = mode
    elif mode != "all_terms":
        raise ValueError("G1a_lexical_mode_adapter_required")
    return store.snapshot(**arguments)


def mining_snapshot(store: RetrievalStore, corpus: str, query: str, vector: str,
                    mode: LexicalMode) -> tuple[Snapshot, bool]:
    """Hybrid candidates; a query refused by the bounded any_terms lexeme cap falls back to dense-only candidates
    (recorded per query and counted), instead of aborting the whole mining run. Any other refusal still fails."""
    try:
        return lexical_snapshot(store, corpus, query, vector, mode), False
    except StepRefused as refused:
        if refused.code != "lexical_query_too_many_lexemes":
            raise
    return store.snapshot(corpus_key=corpus, mode="dense", query=query, query_vector=vector, document_ids=(),
                          branch_documents=20, chunks_per_document=1, full_policy_max_chunks=1), True


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def load_dataset(archive: Path) -> md.Dataset:
    tokenizer = load_tokenizer()
    dataset = md.build_dataset(md.read_archive(archive), tokenizer.count)
    md.verify_manifest(md.manifest(dataset, tokenizer.identity_sha256))
    return dataset


def planning(dataset: md.Dataset, *, mode: LexicalMode, train_limit: int, validation_limit: int,
             max_usd: Decimal, max_calls: int, max_tokens: int, max_seconds: int
             ) -> tuple[dict[str, Any], EmbeddingJob, Configuration]:
    if (not max_usd.is_finite() or not 0 < max_usd <= 1 or not 1 <= max_calls <= 2000
            or not 1 <= max_tokens <= 10_000_000 or not 1 <= max_seconds <= 7200):
        raise ValueError("mining_caps")
    training, validation, audit = partition(dataset, train_limit=train_limit, validation_limit=validation_limit)
    queries = training + validation
    binding = {"schema": "policyops.g8-mining/v1", "dataset_manifest_sha256": file_hash(md.default_manifest()),
        "miner_sha256": file_hash(Path(__file__)), "eval_lock_sha256": file_hash(ROOT / "evals/uv.lock"),
        "app_lock_sha256": file_hash(ROOT / "uv.lock"), "lexical_mode": mode, "branch_documents": 20, "rrf_k": 60,
        "price_revision": "pricing.2026-11-05.v1",
        "embedding_model": "text-embedding-3-small", "dimension": 1536, "query_profile": "history-four-v1",
        "caps": {"usd": str(max_usd), "calls": max_calls, "input_tokens": max_tokens, "seconds": max_seconds},
        "selection": audit, "false_negative_caveat": "unlabelled negatives can still be relevant"}
    identity = sha256_bytes(canonical_bytes(binding))
    job = EmbeddingJob(purpose="g8-mining-v1", subject_key="g8." + identity,
                       inputs=tuple(q.retrieval for q in queries))
    base = Configuration(caps=Caps(operation_usd=max_usd, operation_calls=max_calls, active_seconds=max_seconds))
    configuration = replace(base, actors=dict(base.actors) | {
        "embedding": EmbeddingActor("text-embedding-3-small", 1536, 8192, 64)})
    tokenizer = load_tokenizer()
    prepared = prepare_job(job, configuration, tokenizer, deadline=time.monotonic() + 60)
    batches = pack(prepared, configuration)(UUID(int=0), frozenset())
    tokens = sum(item.local_tokens for item in prepared.inputs)
    ceiling = len(batches) * configuration.reservation("embedding").worst_usd
    if tokens > max_tokens or len(batches) > max_calls or ceiling > max_usd:
        raise ValueError("mining_preflight_exceeds_caps")
    return {**binding, "binding_sha256": identity, "queries": len(queries), "local_input_tokens": tokens,
        "cold_batches": len(batches), "estimated_usd": str(Decimal(tokens) * Decimal("0.02") / 1_000_000),
        "reservation_ceiling_usd": str(ceiling), "rough_estimate": "6600 queries x ~100 tokens = ~$0.0132",
        "preflight_is_offline": True}, job, configuration


def mine(dataset: md.Dataset, plan: dict[str, Any], job: EmbeddingJob, configuration: Configuration, *,
         engine: Engine, workspace: UUID, corpus: str, output: Path, providers: Providers) -> dict[str, Any]:
    bundles.output_path(output / "manifest.json")
    output.mkdir(parents=True, exist_ok=False)
    # Freeze intent before provider calls; failures leave this plus the stable app job/ledger.
    bundles.write(output / "preflight.json", canonical_bytes(plan))
    training, validation, _ = partition(dataset, train_limit=plan["selection"]["training_cap"],
                                       validation_limit=plan["selection"]["internal_validation_cap"])
    passages = {p.passage_id: p for p in dataset.passages}
    expected = {p.passage_id: sha256_bytes(canonical_bytes([p.heading, p.body])) for p in dataset.passages}
    executor = RetrieverExecutor(engine, workspace, corpus, providers=lambda: providers, expected_passages=expected)
    ledger = Ledger(AppLedgerStore(engine, workspace, env="evaluation"), configuration)
    started = time.monotonic()
    deadline = started + configuration.caps.active_seconds
    prepared = prepare_job(job, configuration, executor.tokenizer, deadline=deadline)
    report = run_job_sync(ledger, executor.embeddings, providers, prepared, deadline=deadline)
    bundles.write(output / "embedding.json", canonical_bytes({"job_id": str(report.job_id),
                  "status": report.status, "reason": report.reason, "vectors": len(report.vectors)}))
    if report.status != "complete" or len(report.vectors) != len(training) + len(validation):
        raise ValueError("mining_embedding_incomplete_ledger_retained")
    vectors = {v.position: v.vector for v in report.vectors}
    counts = {"train": 0, "internal_validation": 0, "no_safe_negative": 0, "negatives": 0, "lexical_cap_dense_only": 0}
    triples_path = output / "triples.jsonl"
    with triples_path.open("xb") as handle:
        for index, query in enumerate(training + validation):
            if time.monotonic() >= deadline:
                raise ValueError("mining_deadline_partial_retained")
            vector = "[" + ",".join(str(v) for v in vectors[index]) + "]"
            snapshot, dense_only = mining_snapshot(executor.retrieval, corpus, query.retrieval, vector,
                                                   plan["lexical_mode"])
            counts["lexical_cap_dense_only"] += int(dense_only)
            if (snapshot.generation_id != executor.generation or snapshot.text_oversized or snapshot.dense_nan_distance
                    or snapshot.embedding_model != "text-embedding-3-small" or snapshot.dimension != 1536):
                raise ValueError("mining_corpus_snapshot_integrity")
            dense = [p.source_uri.split("/", 1)[-1] for p in snapshot.dense]
            lexical = [p.source_uri.split("/", 1)[-1] for p in snapshot.lexical]
            fused = [p.source_uri.split("/", 1)[-1] for p in fuse(snapshot.lexical, snapshot.dense, 60)]
            split = "train" if index < len(training) else "internal_validation"
            row = triple(query, passages, dense, fused, split=split, lexical=lexical)
            if row is None:
                counts["no_safe_negative"] += 1
                continue
            handle.write(md.canonical(row) + b"\n")
            counts[split] += 1
            counts["negatives"] += len(row["negatives"])
    result = {**plan, "corpus_binding": executor.binding(), "counts": counts,
        "triples_sha256": file_hash(triples_path), "seconds": time.monotonic() - started,
        "positive_selection": "lowest seeded g8/positive/v1 hash among all qrels",
        "negative_selection": "first safe dense, then first distinct safe RRF; "
                              "all qrels and positive-span overlap excluded"}
    bundles.write(output / "manifest.json", canonical_bytes(result))
    return result


def command(args: argparse.Namespace) -> int:
    try:
        if args.g8_command == "mine" and not args.allow_paid:
            raise ValueError("paid_opt_in_required_before_credentials")
        dataset = load_dataset(args.archive)
        plan, job, configuration = planning(dataset, mode=args.lexical_mode, train_limit=args.train_limit,
            validation_limit=args.validation_limit, max_usd=args.max_usd, max_calls=args.max_calls,
            max_tokens=args.max_input_tokens, max_seconds=args.max_seconds)
        if args.g8_command == "mine":
            import httpx2
            from pydantic import SecretStr

            key = os.environ.get("OPENAI_API_KEY")
            providers = Providers(credentials={"openai": SecretStr(key)} if key else {},
                                  transport=lambda _: httpx2.AsyncHTTPTransport())
            engine = make_engine(lambda: psycopg.connect(args.app_dsn_file.read_text(encoding="utf-8"),
                                connect_timeout=5, options=RUNTIME_CONNECT_OPTIONS))
            try:
                plan = mine(dataset, plan, job, configuration, engine=engine, workspace=args.workspace,
                            corpus=args.corpus, output=args.out, providers=providers)
            finally:
                engine.dispose()
        else:
            bundles.write(args.out, canonical_bytes(plan))
        print(json.dumps({k: plan[k] for k in ("binding_sha256", "queries", "local_input_tokens", "estimated_usd")},
                         sort_keys=True))
        return 0
    except Exception as error:
        print(f"policyops-evals: G8 refused: {type(error).__name__}", file=sys.stderr)
        return 1


