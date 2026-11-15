"""QA retrieval and answer composition. Claims fence slots; ledgers fence physical calls.

The app embedding ledger/cache remains authoritative for its workspace. A second,
claim-bound evaluator ledger reserves first and settles last, so a process loss
between databases keeps liability rather than permitting a replacement dispatch.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Protocol
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import psycopg
from sqlalchemy import Engine, text

from policyops.budget.config import Actor, ChatActor, Configuration, EmbeddingActor
from policyops.budget.config import Caps as LedgerCaps
from policyops.budget.ledger import (
    Attempt,
    Binding,
    CountGranted,
    CountRefused,
    Diagnostic,
    DispatchGranted,
    DispatchRefused,
    EvalBinding,
    Ledger,
    Reserved,
    Settled,
    Settlement,
)
from policyops.persistence.budget import AppLedgerStore, EvalLedgerStore
from policyops.persistence.database import RUNTIME_CONNECT_OPTIONS, make_engine, transaction, workspace_transaction
from policyops.persistence.embeddings import EmbeddingStore
from policyops.persistence.evaluation import (
    EvaluationClaimToken,
    EvaluationRepository,
    EvaluationTrial,
    Slot,
    StudyLock,
)
from policyops.persistence.retrieval import RetrievalStore, StepRefused
from policyops.providers.calls import CallLimits, Providers, call_sync
from policyops.providers.embedding_calls import prepare_job, run_job_sync
from policyops.providers.tokenizer import Tokenizer
from policyops.providers.tokenizer import load as load_tokenizer
from policyops.retrieval.rank import ChunkRow, Fused, fuse
import policyops.retrieval.rerank as t14
from policyops_contracts.embedding import EmbeddingJob
from policyops_contracts.model import ModelRequest
from policyops_contracts.retrieval import RerankConfig
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies import answers, judges, registration
from policyops_evals.qa_studies.calibration import G6_REGISTRY, billing_record, verdict_record
from policyops_evals.qa_studies.config import (
    ROOT,
    AnswerGeneration,
    Arm,
    Caps,
    CascadePolicy,
    ClosedBook,
    CrossEncoder,
    FullContext,
    LunaReranker,
    ModelBinding,
    PolicyArm,
    QAStudy,
    Rerank,
    RetrievalOnly,
    Stage,
    preflight,
)
from policyops_evals.qa_studies.cross_encoder import POLICY, CrossEncoderClient, Passage, WorkerError
from policyops_evals.qa_studies.metrics import (
    Citation,
    Measurement,
    answerable_false_abstention_rate,
    citation_metrics,
    cost_per_question,
    gold_citation,
    latency_percentile,
    lexical_metrics,
    policy_latency_percentile,
    quality_q,
    retrieval_metrics,
)
from policyops_evals.qa_studies.statistics import QuestionObservation, comparison_result, paired_difference
from policyops_evals.studies import bundles
from policyops_evals.studies.runner_v2 import raw_inventory
from policyops_evals.studies.taxonomy import inventory, linked


class Refused(ValueError):
    pass


QA_BUNDLE_BYTES = 64_000_000  # bounded QA schedules/exports exceed the retail snapshot's 4 MB per-file envelope


@dataclass(frozen=True)
class QueryInput:
    question_id: str
    dialogue_id: str
    history: str
    last_turn: str
    generation: str = ""


@dataclass(frozen=True)
class Gold:
    passage_ids: tuple[str, ...]
    stratum: str


@dataclass(frozen=True)
class Inputs:
    queries: dict[str, QueryInput]
    gold: dict[str, Gold]
    cohorts: dict[str, tuple[str, ...]]
    passages: dict[str, str] = field(default_factory=dict)
    passage_text: dict[str, answers.Passage] = field(default_factory=dict)
    references: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SharedUsage:
    usd: Decimal = Decimal(0)
    held: Decimal = Decimal(0)
    calls: int = 0
    inputs: int = 0
    seconds: Decimal = Decimal(0)


@dataclass(frozen=True)
class Scheduled:
    id: UUID
    cohort: str
    question: str
    arm: str
    repetition: int

    @property
    def task(self) -> str:
        # Existing task columns allow 100 characters; retain the full public ID in the frozen schedule.
        return sha256_bytes(canonical_bytes([self.cohort, self.question]))


def read_private(path: Path, expected: str) -> list[dict[str, Any]]:
    bundles.output_path(path)
    if path.stat().st_size > 128_000_000:
        raise Refused("private_materialization_bounds")
    import hashlib

    digest = hashlib.sha256()
    rows: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        while line := handle.readline(200_001):
            if len(line) > 200_000 or len(rows) >= 100_000:
                raise Refused("private_materialization_bounds")
            digest.update(line)
            row = json.loads(line)
            if not isinstance(row, dict):
                raise Refused("private_materialization_record")
            rows.append(row)
    if digest.hexdigest() != expected:
        raise Refused("private_materialization_hash")
    return rows


def load_inputs(study: QAStudy, directory: Path, *, root: Path = ROOT) -> Inputs:
    study.validate_data(root)
    manifest = json.loads((root / study.data.queries.path).read_bytes())
    references = json.loads((root / study.data.references.path).read_bytes())
    query_rows = read_private(directory / "queries.jsonl", manifest["materialization_sha256"]["queries.jsonl"])
    gold_rows = read_private(directory / "references.jsonl", references["materialization_sha256"]["references.jsonl"])
    cohorts = {}
    for cohort in study.schedule.cohorts:
        if cohort.included:
            value = json.loads((root / cohort.manifest.path).read_bytes())
            cohorts[cohort.name] = tuple(value["cohorts"][cohort.manifest_cohort]["query_ids"])
    wanted = {q for ids in cohorts.values() for q in ids}
    queries, gold, reference_text = {}, {}, {}
    for row in query_rows:
        if {"answer", "reference_answer", "target_act", "passage_ids"} & row.keys():
            raise Refused("gold_in_query_materialization")
        q = row["query_id"]
        if q in wanted:
            if q in queries:
                raise Refused("duplicate_query")
            history, last = row["retrieval"], row["last_turn"]
            if any(not isinstance(v, str) or not v or len(v) > 100_000 for v in (history, last)):
                raise Refused("query_bounds")
            generation = row.get("generation_history", "")
            if not isinstance(generation, str) or len(generation) > 100_000:
                raise Refused("generation_history_bounds")
            queries[q] = QueryInput(q, row["domain"] + "/" + row["dialogue_id"], history, last, generation)
    for row in gold_rows:
        q = row["query_id"]
        if q in wanted:
            ids = row["passage_ids"]
            if (q in gold or not isinstance(ids, list) or not ids or len(ids) > 5000
                    or any(not isinstance(p, str) or not p.startswith("md2d.p/") or len(p) > 100 for p in ids)):
                raise Refused("qrel_identity")
            gold[q] = Gold(tuple(ids), "clarification" if row["target_act"] == "query_condition" else "responding")
            reference = row.get("answer", "")
            if not isinstance(reference, str) or len(reference) > 100_000:
                raise Refused("reference_bounds")
            reference_text[q] = reference
    if queries.keys() != wanted or gold.keys() != wanted:
        raise Refused("materialization_schedule_bijection")
    passage_manifest = json.loads((root / study.data.passages.path).read_bytes())
    passage_rows = read_private(directory / "passages.jsonl",
                                passage_manifest["materialization_sha256"]["passages.jsonl"])
    passages = {p["passage_id"]: sha256_bytes(canonical_bytes([p["heading"], p["body"]])) for p in passage_rows}
    if len(passages) != len(passage_rows) or not 1 <= len(passages) <= 5000:
        raise Refused("passage_bijection")
    text_by_id = {p["passage_id"]: answers.Passage(p["passage_id"], p["heading"], p["body"]) for p in passage_rows}
    return Inputs(queries, gold, cohorts, passages, text_by_id, reference_text)


def schedule(study: QAStudy, inputs: Inputs) -> tuple[Scheduled, ...]:
    slots = []
    for cohort in study.schedule.cohorts:
        if not cohort.included:
            continue
        ids = inputs.cohorts[cohort.name]
        if len(ids) != cohort.question_count or len(set(ids)) != len(ids) or tuple(sorted(ids)) != ids:
            raise Refused("schedule_cohort_bijection")
        if len({inputs.queries[q].dialogue_id for q in ids}) != cohort.dialogue_count:
            raise Refused("schedule_dialogue_bijection")
        for index, question in enumerate(ids):
            for repetition in range(study.schedule.repetitions):
                for arm in study.arm_order(cohort.name, index, repetition):
                    slots.append(Scheduled(study.slot_id(cohort.name, question, arm, repetition),
                                           cohort.name, question, arm, repetition))
    if len(slots) > min(16384, study.execution.artifact_max_observations) or len({s.id for s in slots}) != len(slots):
        raise Refused("schedule_capacity_or_bijection")
    return tuple(slots)


class ArmExecutor(Protocol):
    """Future answer/rerank/closed-book/policy/full-context implementations receive no Gold object."""
    def execute(self, arm: RetrievalOnly, query: QueryInput, identity: Scheduled,
                ledger: Ledger, deadline: float) -> tuple[str, ...]: ...

    def needs_embedding(self, arm: RetrievalOnly, query: QueryInput) -> bool: ...

    def binding(self) -> dict[str, str]: ...

    def preprocessing(self) -> SharedUsage: ...


def retrieval_arm(arm: Arm) -> RetrievalOnly:
    if isinstance(arm, (AnswerGeneration, Rerank, PolicyArm)):
        return RetrievalOnly(kind="retrieval_only", name=arm.name, retrieval=arm.retrieval)
    if isinstance(arm, ClosedBook):
        raise Refused("closed_book_has_no_retriever")
    if not isinstance(arm, RetrievalOnly):
        name = arm.kind
        raise Refused(f"{name}: not implemented in this slice")
    return arm


def supported(study: QAStudy) -> None:
    ce_contracts = set()
    for arm in study.arms:
        if not isinstance(arm, (RetrievalOnly, AnswerGeneration, Rerank, ClosedBook, PolicyArm)):
            name = arm.kind
            raise Refused(f"{name}: not implemented in this slice")
        if isinstance(arm, RetrievalOnly):
            continue
        if isinstance(arm, PolicyArm):
            if not isinstance(arm.policy, CascadePolicy):
                raise Refused("selective_rerank: not implemented in this slice")
            policy = arm.policy
            if (policy.first.model != "gpt-6-luna" or policy.first.effort != "none"
                    or policy.first.max_output_tokens != 512
                    or policy.first.prompt_sha256 != sha256_bytes(answers.cascade_prompt(policy.max_claims).encode())
                    or policy.first.schema_sha256 != answers.CASCADE_SCHEMA_SHA256
                    or policy.fallback.model != "claude-haiku-5-5" or policy.fallback.effort != "low"
                    or policy.fallback.max_output_tokens > 1024
                    or policy.fallback.prompt_sha256 != sha256_bytes(answers.prompt(policy.max_claims).encode())
                    or policy.fallback.schema_sha256 != answers.SCHEMA_SHA256
                    or policy.first_context.max_passages > 2 or policy.first_context.evidence_tokens > 1536
                    or policy.fallback_context.max_passages > 5 or policy.fallback_context.evidence_tokens > 4096
                    or any(c.policy != "whole-passages-skip-overflow-v1"
                           for c in (policy.first_context, policy.fallback_context))):
                raise Refused("cascade_contract_binding")
            if policy.reranker is None:
                continue
            # Validate the shared CE ranking with the same contract as standalone arms.
            arm = Rerank(kind="rerank", name=arm.name, retrieval=arm.retrieval,
                         reranker=policy.reranker, generator=policy.fallback,
                         context=policy.fallback_context, max_claims=policy.max_claims)
        generator = arm.generator
        if generator is not None and (generator.effort not in (
                {"none", "low"} if generator.model == "gpt-6-luna" else {"low"})
                or generator.max_output_tokens > 1024
                or generator.prompt_sha256 != sha256_bytes(answers.prompt(arm.max_claims).encode())
                or generator.schema_sha256 != answers.SCHEMA_SHA256):
            raise Refused("generator_contract_binding")
        if isinstance(arm, (AnswerGeneration, Rerank)) and (
                arm.context.max_passages > 5 or arm.context.evidence_tokens > 4096
                or arm.context.policy != "whole-passages-skip-overflow-v1"):
            raise Refused("evidence_contract")
        if isinstance(arm, Rerank):
            if arm.generator is None:
                raise Refused("rerank_generator_required_in_this_slice")
            if arm.retrieval.candidate_count != 20:
                raise Refused("rerank_requires_top20_pool")
            if isinstance(arm.reranker, LunaReranker):
                model = arm.reranker.model
                if (model.prompt_sha256 != t14.PROMPT_SHA256 or model.effort not in {"none", "low"}
                        or model.schema_sha256 != sha256_bytes(t14.output_schema([t14.label(i)
                            for i in range(1, 21)]).encode())
                        or arm.reranker.excerpt_policy_sha256 != answers.EXCERPT_SHA256):
                    raise Refused("rerank_contract_binding")
            else:
                ce = arm.reranker
                pool = sha256_bytes(canonical_bytes(arm.retrieval.model_dump(mode="json")))
                if (ce.candidate_pool_sha256 != pool or ce.truncation_policy_sha256 != sha256_bytes(POLICY.encode())
                        or ce.max_length != 384 or ce.query_token_cap != 128 or ce.threads > 32
                        or ce.runtime_sha256 != ce_runtime_digest()):
                    raise Refused("cross_encoder_contract_binding")
                ce_contracts.add((pool, ce.truncation_policy_sha256, ce.max_length, ce.query_token_cap,
                                  ce.tokenizer_sha256))
    if len(ce_contracts) > 1:
        raise Refused("cross_encoder_pools_or_truncation_differ")
    by_name = {a.name: a for a in study.arms}
    if any((c.uses_judge or c.estimand == "gold_citation")
           and any(isinstance(by_name[n], ClosedBook) for n in (c.candidate, c.reference))
           for c in study.analysis.comparisons):
        raise Refused("closed_book_judged_metrics_not_measured")
    if any(c.estimand == "gold_support" for c in study.analysis.comparisons):
        raise Refused("gold_support_not_measured_in_this_slice")


def ce_runtime_digest() -> str:
    paths = ["evals/src/policyops_evals/qa_studies/cross_encoder.py", "reranker/src/policyops_reranker/model.py",
             "reranker/src/policyops_reranker/score.py", "reranker/src/policyops_reranker/serve.py", "reranker/uv.lock"]
    return sha256_bytes(canonical_bytes({p: sha256_bytes((ROOT / p).read_bytes()) for p in paths}))


def stage_for(study: QAStudy, item: Scheduled, arm: RetrievalOnly) -> Stage:
    role = "local" if arm.retrieval.method == "fts" else "embedding"
    stages = [s for s in study.execution.stages if s.role == role
              and s.arm in (None, item.arm) and s.cohort == item.cohort]
    if len(stages) != 1:
        raise Refused("one_matching_execution_stage_required")
    stage = stages[0]
    if role == "embedding" and (stage.model != "text-embedding-3-small" or stage.max_output_tokens):
        raise Refused("embedding_stage_contract")
    return stage


def configuration(study: QAStudy, stage: Stage) -> Configuration:
    cap = study.execution.cumulative_caps
    floor = Decimal("0.000001")  # existing ledger scopes require positive caps, including local-only scopes
    caps = LedgerCaps(study_usd=max(cap.usd, floor), study_calls=max(cap.calls, 1),
        invocation_usd=max(stage.caps.usd, floor), invocation_calls=max(stage.caps.calls, 1),
        scenario_usd=max(stage.caps.usd, floor), scenario_calls=max(stage.caps.calls, 1),
        operation_usd=max(stage.caps.usd, floor), operation_calls=1,
        active_seconds=study.execution.request_deadline_seconds)
    base = Configuration(caps=caps)
    return replace(base, actors=dict(base.actors) | {"embedding": EmbeddingActor(
        "text-embedding-3-small", 1536, max(stage.max_input_tokens, 1), 1)})


class EmbeddingLedger(Ledger):
    """The app call path is unchanged; evaluator admission must win every transition first."""
    def __init__(self, app: AppLedgerStore, evaluator: Ledger, token: EvaluationClaimToken) -> None:
        super().__init__(app, evaluator.configuration)
        self.evaluator, self.token = evaluator, token

    def reserve(self, binding: Binding, attempt_id: UUID, actor: Actor, operation_id: str,
                request_sha256: str) -> Reserved:
        self.evaluator.reserve(self.token.binding, attempt_id, actor, operation_id, request_sha256)
        return super().reserve(binding, attempt_id, actor, operation_id, request_sha256)

    def claim_count(self, attempt_id: UUID, request_sha256: str) -> CountGranted | CountRefused:
        granted = self.evaluator.claim_count(attempt_id, request_sha256)
        return super().claim_count(attempt_id, request_sha256) if isinstance(granted, CountGranted) else granted

    def record_count(self, attempt_id: UUID, *, tokens: int | None, source: str) -> Attempt:
        self.evaluator.record_count(attempt_id, tokens=tokens, source=source)
        return super().record_count(attempt_id, tokens=tokens, source=source)

    def begin_dispatch(self, attempt_id: UUID, request_sha256: str) -> DispatchGranted | DispatchRefused:
        granted = self.evaluator.begin_dispatch(attempt_id, request_sha256)
        return super().begin_dispatch(attempt_id, request_sha256) if isinstance(granted, DispatchGranted) else granted

    def release(self, attempt_id: UUID) -> Attempt:
        value = super().release(attempt_id)
        self.evaluator.release(attempt_id)
        return value

    def mark_unresolved(self, attempt_id: UUID, *, block: str | None = None,
                        diagnostic: Diagnostic | None = None) -> Attempt:
        value = super().mark_unresolved(attempt_id, block=block, diagnostic=diagnostic)
        self.evaluator.mark_unresolved(attempt_id, block=block, diagnostic=diagnostic)
        return value

    def settle(self, attempt_id: UUID, settlement: Settlement) -> Settled:
        value = super().settle(attempt_id, settlement)
        self.evaluator.settle(attempt_id, settlement)
        return value


class RetrieverExecutor:
    def __init__(self, engine: Engine, workspace: UUID, corpus: str, *,
                 providers: Callable[[], Providers], tokenizer: Tokenizer | None = None,
                 env: str = "evaluation", expected_passages: dict[str, str] | None = None) -> None:
        self.engine, self.workspace, self.corpus = engine, workspace, corpus
        self.providers, self.tokenizer, self.env = providers, tokenizer or load_tokenizer(), env
        self.embeddings = EmbeddingStore(engine, workspace, env=env)
        self.retrieval = RetrievalStore(engine, workspace)
        self.generation = self.retrieval.pointer(corpus)
        if self.generation is None:
            raise Refused("structural_corpus_required")
        with workspace_transaction(engine, workspace) as connection:
            generation = connection.execute(text("SELECT parser_version, chunk_config, embedding_model, dimension "
                "FROM app.index_generations WHERE id = :id"), {"id": self.generation}).one()
            if tuple(generation) != ("policyops.md2d-title-runs/v1", "chunk.structural-complete-8192/v1",
                                     "text-embedding-3-small", 1536):
                raise Refused("structural_generation_contract")
            if expected_passages is not None:
                rows = connection.execute(text("SELECT d.source_uri, k.heading, k.text FROM app.chunks k "
                    "JOIN app.document_versions v ON v.id = k.document_version_id AND v.workspace_id = k.workspace_id "
                    "JOIN app.documents d ON d.id = v.document_id AND d.workspace_id = v.workspace_id "
                    "WHERE k.generation_id = :id LIMIT 5001"), {"id": self.generation}).all()
                actual = {row.source_uri.split("/", 1)[-1]: sha256_bytes(canonical_bytes([row.heading, row.text]))
                          for row in rows}
                if len(rows) != len(actual) or actual != expected_passages:
                    raise Refused("corpus_materialization_binding")

    def binding(self) -> dict[str, str]:
        return {"workspace": str(self.workspace), "corpus": self.corpus, "generation": str(self.generation)}

    def preprocessing(self) -> SharedUsage:
        # The dedicated QA workspace keeps all shared non-QA embedding work visible.
        # Query jobs are mirrored into evaluation and must not be counted twice.
        with workspace_transaction(self.engine, self.workspace) as connection:
            rows = connection.execute(text("SELECT a.state, a.actual_usd, a.reserved_usd, a.max_input, a.usage, "
                "extract(epoch FROM a.updated_at - a.created_at) AS seconds FROM app.usage_attempts a "
                "JOIN app.budget_scopes s ON s.id = a.scope_id AND s.workspace_id = a.workspace_id "
                "JOIN app.embedding_jobs j ON j.id::text = s.operation_key AND j.workspace_id = s.workspace_id "
                "WHERE s.operation_kind = 'embedding' AND j.purpose <> 'qa-study-v1'")).mappings().all()
        held = sum((r["reserved_usd"] for r in rows if r["state"] not in {"settled", "released"}), Decimal(0))
        return SharedUsage(sum((r["actual_usd"] or Decimal(0) for r in rows), Decimal(0)), held, len(rows),
            sum(r["usage"]["input_total"] if r["usage"] else r["max_input"] for r in rows),
            sum((r["seconds"] for r in rows), Decimal(0)))

    def needs_embedding(self, arm: RetrievalOnly, query: QueryInput) -> bool:
        from policyops.providers.embedding_contract import request_config_sha256
        from policyops.providers.embeddings import input_sha256

        value = query.history if arm.retrieval.query_profile == "history-four-v1" else query.last_turn
        return arm.retrieval.method != "fts" and not self.embeddings.cached(
            request_config_sha256("text-embedding-3-small", 1536), [input_sha256(value)])

    def execute(self, arm: RetrievalOnly, query: QueryInput, identity: Scheduled,
                ledger: Ledger, deadline: float) -> tuple[str, ...]:
        value = query.history if arm.retrieval.query_profile == "history-four-v1" else query.last_turn
        if time.monotonic() >= deadline:
            raise Refused("slot_deadline")
        vector = None
        if self.tokenizer.count(value) > 1024:
            raise Refused("query_token_bound")
        if arm.retrieval.method != "fts":
            if not isinstance(ledger.store, EvalLedgerStore) or ledger.store.claim_token is None:
                raise Refused("claim_bound_embedding_required")
            app = EmbeddingLedger(AppLedgerStore(self.engine, self.workspace, env=self.env),
                                  ledger, ledger.store.claim_token)
            job = EmbeddingJob(purpose="qa-study-v1", subject_key="qa." + str(identity.id), inputs=(value,))
            prepared = prepare_job(job, app.configuration, self.tokenizer, deadline=deadline)
            report = run_job_sync(app, self.embeddings, self.providers(), prepared, deadline=deadline)
            if report.status != "complete" or len(report.vectors) != 1:
                raise Refused("query_embedding_incomplete")
            vector = "[" + ",".join(str(v) for v in report.vectors[0].vector) + "]"
        try:
            snapshot = self.retrieval.snapshot(corpus_key=self.corpus,
                mode={"fts": "lexical", "dense": "dense", "rrf": "hybrid"}[arm.retrieval.method],
                query=value, query_vector=vector, document_ids=(), branch_documents=arm.retrieval.branch_limit,
                chunks_per_document=1, full_policy_max_chunks=1, lexical_mode=arm.retrieval.lexical_mode)
        except StepRefused as failure:
            if failure.code == "lexical_query_too_many_lexemes":
                raise Refused(failure.code) from None  # record the bound, without query text, in the slot artifact
            raise
        if (snapshot.generation_id != self.generation or snapshot.text_oversized or snapshot.dense_nan_distance
                or (vector is not None and (snapshot.embedding_model != "text-embedding-3-small"
                                            or snapshot.dimension != 1536))):
            raise Refused("corpus_snapshot_integrity")
        ranking = fuse(snapshot.lexical, snapshot.dense, arm.retrieval.rrf_k)
        ids = tuple(hit.source_uri.split("/", 1)[-1] for hit in ranking[:arm.retrieval.candidate_count])
        if any(not p.startswith("md2d.p/") or len(p) > 100 for p in ids):
            raise Refused("structural_passage_identity")
        if time.monotonic() >= deadline:
            raise Refused("slot_deadline")
        return ids


def directory_for(study: QAStudy) -> Path:
    value = os.environ.get("POLICYOPS_TEMP_DIR")
    if not value:
        raise Refused("POLICYOPS_TEMP_DIR_required")
    directory = Path(value) / "benchmarks/qa-studies" / str(study.study_id)
    bundles.output_path(directory / "study.json")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def envelope_fits(cap: Caps, *, usd: Decimal, calls: int, counts: int, inputs: int, outputs: int,
                  seconds: Decimal, next_usd: Decimal, next_inputs: int, next_seconds: int, paid: bool) -> bool:
    return (usd + next_usd <= cap.usd and calls + int(paid) <= cap.calls
            and counts + int(paid) <= cap.counts and inputs + next_inputs <= cap.input_tokens
            and outputs <= cap.output_tokens and seconds + next_seconds <= cap.seconds)


def admit(study: QAStudy, item: Scheduled, stage: Stage, repository: EvaluationRepository,
          scope: UUID, stage_id: UUID, *, paid: bool, shared: SharedUsage | None = None) -> bool:
    # Charge the complete input envelope for every reservation, even a released one.
    # This is conservative and cannot reset tokens or time through a new invocation.
    shared = shared or SharedUsage()
    with transaction(repository.engine) as connection:
        attempts = connection.execute(text("SELECT invocation_scope_id, reserved_usd, actual_usd, state, "
            "max_input, max_output, count_state FROM evaluation.usage_attempts WHERE study_scope_id = :study"),
            {"study": scope}).mappings().all()
        claims = connection.execute(text("SELECT c.invocation_scope, c.state, t.latency_ms FROM "
            "evaluation.trial_claims c LEFT JOIN evaluation.evaluation_trials t ON t.id = c.id "
            "WHERE c.study_scope = :study AND c.started_at IS NOT NULL"), {"study": scope}).mappings().all()
    reserve = configuration(study, stage).reservation("embedding").worst_usd if paid else Decimal(0)
    stage_cap = stage.caps.model_copy(update={
        "calls": min(stage.caps.calls, stage.planned_calls), "counts": min(stage.caps.counts, stage.planned_counts),
        "input_tokens": min(stage.caps.input_tokens, stage.planned_calls * stage.max_input_tokens),
        "output_tokens": min(stage.caps.output_tokens, stage.planned_calls * stage.max_output_tokens)})
    for cap, selected, times, overhead in (
        (study.execution.cumulative_caps, attempts, claims, shared),
        (stage_cap, [a for a in attempts if a["invocation_scope_id"] == stage_id],
         [c for c in claims if c["invocation_scope"] == stage_id], SharedUsage()),
    ):
        if not envelope_fits(cap,
            usd=sum((a["actual_usd"] if a["actual_usd"] is not None else a["reserved_usd"] for a in selected),
                    overhead.usd + overhead.held), calls=len(selected) + overhead.calls,
            counts=len(selected) + overhead.calls,
            inputs=sum(a["max_input"] for a in selected) + overhead.inputs,
            outputs=sum(a["max_output"] for a in selected),
            seconds=sum((Decimal(c["latency_ms"]) / 1000 if c["latency_ms"] is not None
                         else Decimal(study.execution.request_deadline_seconds) for c in times), overhead.seconds),
            next_usd=reserve, next_inputs=stage.max_input_tokens if paid else 0,
            next_seconds=study.execution.request_deadline_seconds, paid=paid):
            return False
    return True


def metrics_for(ranking: Sequence[str], gold: Gold, *, failed: bool) -> dict[str, str]:
    return {key: str(Fraction(value)) for key, value in asdict(
        retrieval_metrics(ranking, gold.passage_ids, error=failed)).items()}


ANSWER_METRICS = ("citation_precision", "citation_recall", "quality_q", "false_abstention", "token_f1", "rouge_l",
                  "delivered_coverage", "delivered_support")
COMPOSITION_METRICS = (*ANSWER_METRICS, "citation_integrity", "gold_citation")
PAID_ROLES = ("embedding", "rerank", "answer", "answer.first", "answer.fallback", "judge")


def role_stage(study: QAStudy, item: Scheduled, role: str) -> Stage:
    stages = [s for s in study.execution.stages if s.role == role and s.cohort == item.cohort
              and s.arm in (None, item.arm)]
    if len(stages) != 1:
        raise Refused("one_matching_execution_stage_required")
    return stages[0]


def composition_configuration(study: QAStudy, model: ModelBinding | None = None,
                              actor: Actor = "agent") -> Configuration:
    cap = study.execution.cumulative_caps
    floor = Decimal("0.000001")
    caps = LedgerCaps(study_usd=max(cap.usd, floor), study_calls=max(cap.calls, 1),
        invocation_usd=max(cap.usd, floor), invocation_calls=max(cap.calls, 1),
        scenario_usd=max(cap.usd, floor), scenario_calls=max(cap.calls, 1),
        operation_usd=max(cap.usd, floor), operation_calls=1,
        active_seconds=study.execution.request_deadline_seconds,
        request_max_input=max(16000, model.max_input_tokens if model else 1024),
        request_max_output=max(2048, model.max_output_tokens if model else 1))
    base = Configuration(caps=caps)
    actors = dict(base.actors) | {"embedding": EmbeddingActor("text-embedding-3-small", 1536, 1024, 1)}
    if model is not None:
        actors[actor] = ChatActor(actor, model.model, model.effort, model.cache_policy,
                                  model.max_input_tokens, model.max_output_tokens)
    return Configuration(caps=caps, actors=actors, registry=G6_REGISTRY)


def admit_role(study: QAStudy, stage: Stage, repository: EvaluationRepository, scope: UUID,
               shared: SharedUsage, reservation: Decimal) -> bool:
    """Study advisory lease serializes admission. SQL ledger still authorizes each reservation.

    Stage IDs are persisted in operation IDs, because an existing trial claim binds
    one invocation for its whole lifetime. No claim rebinding or schema change.
    Reservations (including releases) conservatively consume token/count envelopes.
    """
    with transaction(repository.engine) as connection:
        rows = connection.execute(text("SELECT operation_id, actual_usd, reserved_usd, max_input, max_output, "
            "extract(epoch FROM updated_at - created_at) AS seconds FROM evaluation.usage_attempts "
            "WHERE study_scope_id = :study"), {"study": scope}).mappings().all()
        program_usd = connection.execute(text("SELECT coalesce(sum(spent_usd + held_usd), 0) "
            "FROM evaluation.budget_scopes WHERE kind = 'study'")).scalar_one()
    if program_usd + shared.usd + shared.held + reservation > study.execution.program_cap_usd:
        return False
    prefix = "qa/" + stage.name + "/"
    for cap, chosen, overhead in ((study.execution.cumulative_caps, rows, shared),
            (stage.caps, [r for r in rows if r["operation_id"].startswith(prefix)], SharedUsage())):
        if not envelope_fits(cap,
                usd=sum((r["actual_usd"] if r["actual_usd"] is not None else r["reserved_usd"] for r in chosen),
                        overhead.usd + overhead.held), calls=len(chosen) + overhead.calls,
                counts=len(chosen) + overhead.calls, inputs=sum(r["max_input"] for r in chosen) + overhead.inputs,
                outputs=sum(r["max_output"] for r in chosen) + stage.max_output_tokens,
                seconds=sum((r["seconds"] for r in chosen), overhead.seconds), next_usd=reservation,
                next_inputs=stage.max_input_tokens, next_seconds=min(60, study.execution.request_deadline_seconds),
                paid=True):
            return False
    selected = [r for r in rows if r["operation_id"].startswith(prefix)]
    return len(selected) < min(stage.planned_calls, stage.planned_counts)


def admit_slot_time(study: QAStudy, repository: EvaluationRepository, scope: UUID, shared: SharedUsage) -> bool:
    with transaction(repository.engine) as connection:
        elapsed = connection.execute(text("SELECT coalesce(sum(coalesce(t.latency_ms / 1000.0, :deadline)), 0) "
            "FROM evaluation.trial_claims c LEFT JOIN evaluation.evaluation_trials t ON t.id = c.id "
            "WHERE c.study_scope = :study AND c.started_at IS NOT NULL"),
            {"study": scope, "deadline": study.execution.request_deadline_seconds}).scalar_one()
    return bool(elapsed + shared.seconds + study.execution.request_deadline_seconds
                <= study.execution.cumulative_caps.seconds)


class RoleLedger(Ledger):
    def __init__(self, base: Ledger, stage: Stage, admission: Callable[[Decimal], bool],
                 boundary: Callable[[str], None]) -> None:
        super().__init__(base.store, base.configuration)
        self.stage, self.admission, self.boundary = stage, admission, boundary

    def reserve(self, binding: Binding, attempt_id: UUID, actor: Actor, operation_id: str,
                request_sha256: str) -> Reserved:
        if not self.admission(self.configuration.reservation(actor).worst_usd):
            raise Refused("stage_or_cumulative_cap")
        return super().reserve(binding, attempt_id, actor,
            "qa/" + self.stage.name + "/" + sha256_bytes(operation_id.encode()), request_sha256)

    def begin_dispatch(self, attempt_id: UUID, request_sha256: str) -> DispatchGranted | DispatchRefused:
        result = super().begin_dispatch(attempt_id, request_sha256)
        if isinstance(result, DispatchGranted):
            self.boundary(self.stage.role + "_dispatched")
        return result


@dataclass
class AnswerState:
    ranking: tuple[str, ...] = ()
    ranking_complete: bool = False
    outcome_code: str | None = None
    first_stage: tuple[str, ...] = ()
    delivery: answers.Delivery = field(default_factory=lambda: answers.Delivery((), (), (), 0))
    answer: answers.Answer | None = None
    claims: tuple[str, ...] = ()
    verdicts: list[bool | None] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    stage_latency_ms: dict[str, int] = field(default_factory=dict)
    stage_cost_usd: dict[str, str | None] = field(default_factory=dict)
    rerank_metadata: dict[str, Any] = field(default_factory=dict)
    policy_latency_ms: int | None = None
    policy_started_at: float = field(default_factory=time.time)
    policy_started_monotonic: float = field(default_factory=time.monotonic)
    policy_elapsed_offset_ms: int = 0
    route: str | None = None
    escalation_reason: str | None = None


class AnswerExecutor:
    """Composes retrieval, paid calls and local CE. This object never receives Gold/references."""
    def __init__(self, study: QAStudy, repository: EvaluationRepository, scope: UUID,
                 token: EvaluationClaimToken, item: Scheduled, shared: SharedUsage,
                 providers: Callable[[], Providers], boundary: Callable[[str], None],
                 artifacts: Path | None = None) -> None:
        self.study, self.repository, self.scope, self.token, self.item = study, repository, scope, token, item
        self.shared, self.providers, self.boundary = shared, providers, boundary
        self.artifacts = artifacts

    def cost(self, actor: Actor, role: str | None = None) -> str | None:
        with transaction(self.repository.engine) as connection:
            costs = connection.execute(text("SELECT actual_usd, state FROM evaluation.usage_attempts "
                "WHERE scenario_scope_id = :scenario AND actor = :actor "
                "AND (CAST(:prefix AS text) IS NULL OR starts_with(operation_id, CAST(:prefix AS text)))"),
                {"scenario": self.token.binding.scenario_id, "actor": actor,
                 "prefix": None if role is None else "qa/" + role_stage(self.study, self.item, role).name + "/"}
            ).mappings().all()
        return (str(sum((c["actual_usd"] or Decimal(0) for c in costs), Decimal(0)))
                if all(c["state"] in {"settled", "released"} for c in costs) else None)

    def ledger(self, role: str, model: ModelBinding | None = None, actor: Actor = "agent") -> RoleLedger:
        stage = role_stage(self.study, self.item, role)
        if model is not None and (stage.model != model.model or stage.max_input_tokens != model.max_input_tokens
                or stage.max_output_tokens != model.max_output_tokens or stage.cache_policy != model.cache_policy):
            raise Refused("stage_model_envelope_mismatch")
        config = composition_configuration(self.study, model, actor)
        base = Ledger(EvalLedgerStore(self.repository.engine, env="evaluation", claim_token=self.token), config)
        return RoleLedger(base, stage, lambda reserve: admit_role(self.study, stage, self.repository, self.scope,
                                                                self.shared, reserve), self.boundary)

    def paid(self, role: str, model: ModelBinding, request: ModelRequest, state: AnswerState, deadline: float,
             index: int = 0) -> str | None:
        actor: Actor = "agent" if role.startswith("answer") else "judge" if role == "judge" else "reranker"
        ledger = self.ledger(role, model, actor)
        self.boundary("before_" + role)
        started = time.monotonic()
        from policyops.providers.accounting import AccountingUnconfirmed

        try:
            report = call_sync(ledger, self.providers(), self.token.binding, self.item.id, role + "/" + str(index),
                request, actor, deadline=min(deadline, started + 60),
                limits=CallLimits(retries_per_request=0, repairs=0, backoff_seconds=0,
                                  attempt_seconds=min(60, self.study.execution.request_deadline_seconds)))
        except AccountingUnconfirmed as failure:
            state.audit.append({"role": role, "index": index, "billing": billing_record(failure.report)})
            raise Refused("unresolved_billing") from None
        finally:
            state.stage_latency_ms[role] = (state.stage_latency_ms.get(role, 0)
                                            + int((time.monotonic() - started) * 1000))
        state.audit.append({"role": role, "index": index, "billing": billing_record(report)})
        state.audit[-1]["output"] = None if report.result is None else report.result.structured_json
        # Usage is read from this claim's attempts; no content is retained in public metadata.
        state.stage_cost_usd[role] = self.cost(actor, role) if role.startswith("answer.") else self.cost(actor)
        self.boundary("after_" + role)
        if role == "answer.first" and (report.cleanup_unconfirmed
                or any(a.fate == "unresolved" for a in report.attempts)):
            raise Refused("unresolved_billing")
        if ((role.startswith("answer") or role == "rerank") and report.result is not None
                and report.result.outcome == "truncated" and report.result.stop_reason == "max_output_tokens"):
            raise Refused(role + "_output_limit")
        if role == "judge":
            verdict, settled = verdict_record(report)
            if verdict is None or not settled:
                raise Refused("invalid_judge_verdict")
            state.verdicts.append(verdict)
        if (report.status != "result" or report.result is None or report.result.outcome != "structured"
                or report.result.tool_calls or report.cleanup_unconfirmed
                or not report.attempts or any(a.fate != "settled" for a in report.attempts)):
            raise Refused(role + "_call_failed")
        return report.result.structured_json

    def execute(self, arm: AnswerGeneration | Rerank | ClosedBook | PolicyArm, query: QueryInput,
                retriever: ArmExecutor, passage_text: dict[str, answers.Passage], tokenizer: Tokenizer,
                state: AnswerState, judge: judges.JudgeArm | None,
                ce: Callable[[CrossEncoder, float], CrossEncoderClient],
                deadline: float, *, resumed: bool = False) -> None:
        if not query.generation:
            raise Refused("chronological_generation_history_required")
        if not isinstance(arm, ClosedBook) and not resumed:
            ledger = self.ledger("embedding") if arm.retrieval.method != "fts" else self.ledger_local()
            started = time.monotonic()
            try:
                state.ranking = retriever.execute(retrieval_arm(arm), query, self.item, ledger,
                                                  min(deadline, started + 60))
            finally:
                state.stage_latency_ms["embedding"] = int((time.monotonic() - started) * 1000)
                state.stage_cost_usd["embedding"] = self.cost("embedding")
            state.first_stage = state.ranking
            ranked_arm: AnswerGeneration | Rerank | PolicyArm = arm
            if isinstance(arm, PolicyArm):
                if not (isinstance(arm.policy, CascadePolicy)):
                    raise Refused("cascade_contract_binding")
                if arm.policy.reranker is not None:
                    ranked_arm = Rerank(kind="rerank", name=arm.name, retrieval=arm.retrieval,
                        reranker=arm.policy.reranker, generator=arm.policy.fallback,
                        context=arm.policy.fallback_context, max_claims=arm.policy.max_claims)
            if isinstance(ranked_arm, Rerank) and state.ranking:
                self.rerank(ranked_arm, query, passage_text, state, ce, deadline)
            state.ranking_complete = True
            if not isinstance(arm, PolicyArm):
                state.delivery = answers.deliver(state.ranking, passage_text, arm.context, tokenizer)
        if isinstance(arm, PolicyArm):
            if not (isinstance(arm.policy, CascadePolicy)):
                raise Refused("cascade_contract_binding")
            self.cascade(arm, query, passage_text, tokenizer, state, deadline, resumed=resumed)
            max_claims = arm.policy.max_claims
        else:
            max_claims = arm.max_claims
            if arm.generator is None:
                return
            payload = self.paid("answer", arm.generator, answers.request(query.generation, state.delivery.passages,
                max_claims=max_claims, max_output=arm.generator.max_output_tokens), state, deadline)
            state.answer = answers.parse_answer(payload)
        if not (state.answer is not None):
            raise Refused("cascade_contract_binding")
        state.claims = answers.sentences(state.answer.answer, maximum=max_claims)
        if isinstance(arm, ClosedBook):
            if state.answer.citations:
                raise Refused("closed_book_citations")
            self.policy_complete(state)
            return
        checks = answers.citations(state.answer, state.delivery)
        self.policy_complete(state)
        if any(not c.valid for c in checks):
            state.outcome_code = "undelivered_citation"
            return
        document = answers.cited_document(state.answer, state.delivery)
        if not state.answer.abstain and not document:
            state.outcome_code = "uncited_answer"
            return
        if document and state.claims:
            if judge is None or self.study.judge is None:
                raise Refused("judge_binding_required")
            for index, claim in enumerate(state.claims):
                self.paid("judge", self.study.judge, judges.request(judge, document, claim), state, deadline, index)

    def policy_complete(self, state: AnswerState) -> None:
        state.policy_latency_ms = (state.policy_elapsed_offset_ms
                                   + int((time.monotonic() - state.policy_started_monotonic) * 1000))

    def cascade(self, arm: PolicyArm, query: QueryInput, passages: dict[str, answers.Passage],
                tokenizer: Tokenizer, state: AnswerState, deadline: float, *, resumed: bool) -> None:
        policy = arm.policy
        if not (isinstance(policy, CascadePolicy)):
            raise Refused("cascade_contract_binding")
        if not resumed:
            state.delivery = answers.deliver(state.ranking, passages, policy.first_context, tokenizer)
            payload, failure = None, None
            try:
                payload = self.paid("answer.first", policy.first, answers.request(query.generation,
                    state.delivery.passages, max_claims=policy.max_claims,
                    max_output=policy.first.max_output_tokens, cascade=True), state, deadline)
            except Refused as error:
                if str(error) not in {"answer.first_call_failed", "answer.first_output_limit"}:
                    raise
                failure = str(error)
            first, reason = answers.escalation_reason(payload, state.delivery,
                threshold=float(policy.confidence_threshold), max_claims=policy.max_claims, failure=failure)
            state.route, state.escalation_reason = ("first" if reason is None else "fallback"), reason
            if reason is None:
                if not (first is not None):
                    raise Refused("cascade_contract_binding")
                state.answer = answers.Answer(answer=first.answer, citations=first.citations, abstain=first.abstain)
                return
            # Only a fully settled first stage may checkpoint. No ambiguous work is replayed.
            checkpoint = {"study_sha256": self.study.digest(), "slot_id": str(self.item.id),
                          "owner": str(self.token.owner), "invocation": str(self.token.binding.invocation_id),
                          "query_sha256": sha256_bytes(query.generation.encode()), "state": private_answer(state)}
            target = directory_for(self.study) / (str(self.item.id) + "-cascade.json")
            raw = canonical_bytes(checkpoint)
            bundles.write(target, raw)
            if self.artifacts is None:
                raise Refused("cascade_checkpoint_artifacts_required")
            bundles.write(self.artifacts / target.name, raw)
            self.boundary("cascade_first_checkpoint")
        state.delivery = answers.deliver(state.ranking, passages, policy.fallback_context, tokenizer)
        # Construct from original history + ranking only. The first answer is never an input.
        payload = self.paid("answer.fallback", policy.fallback, answers.request(query.generation,
            state.delivery.passages, max_claims=policy.max_claims, max_output=policy.fallback.max_output_tokens),
            state, deadline)
        state.answer = answers.parse_answer(payload)

    def ledger_local(self) -> Ledger:
        return Ledger(EvalLedgerStore(self.repository.engine, env="evaluation", claim_token=self.token),
                      composition_configuration(self.study))

    def rerank(self, arm: Rerank, query: QueryInput, passages: dict[str, answers.Passage], state: AnswerState,
               ce: Callable[[CrossEncoder, float], CrossEncoderClient], deadline: float) -> None:
        started = time.monotonic()
        self.boundary("before_rerank")
        value = query.history if arm.retrieval.query_profile == "history-four-v1" else query.last_turn
        try:
            if isinstance(arm.reranker, CrossEncoder):
                state.stage_cost_usd["rerank"] = "0"
                result = ce(arm.reranker, deadline).rerank(value,
                    [Passage(id=p, text=passages[p].heading + "\n\n" + passages[p].body) for p in state.ranking],
                    top_k=len(state.ranking))
                state.ranking = tuple(result.ranking)
                state.rerank_metadata = {"truncation": [s.truncation.model_dump() for s in result.scores]}
                self.boundary("after_rerank")
            else:
                fused, rows = [], {}
                for i, p in enumerate(state.ranking):
                    identity = uuid5(self.item.id, p)
                    fused.append(Fused(identity, p, i + 1, Fraction(1, i + 1), i + 1, None, (identity,)))
                    text = passages[p]
                    rows[identity] = ChunkRow(identity, identity, identity, p, 1, text.heading, 0, len(text.body),
                                              text.body)
                built = t14.build_input(workspace_id=UUID(int=0), run_id=self.item.id, step=0,
                    request_sha256=sha256_bytes(value.encode()), query=value,
                    config=RerankConfig(documents=20, excerpt_bytes=1000,
                        max_output_tokens=arm.reranker.model.max_output_tokens),
                    fused=fused, rows=rows, chunks_per_document=1)
                state.rerank_metadata = {"excerpts_truncated": built.excerpts_truncated, "skipped": built.skipped}
                if built.skipped == "skipped_few_candidates":
                    return
                if built.skipped:
                    raise Refused("rerank_input_bound")
                payload = self.paid("rerank", arm.reranker.model, t14.model_request(built), state, deadline)
                ranking = t14.parse_ranking(payload, built.labels)
                if ranking is None:
                    raise Refused("invalid_rerank")
                state.ranking = tuple(f.source_uri for f in t14.reorder(fused, built.window_document_ids, ranking))
        except WorkerError:
            raise Refused("cross_encoder_failure") from None
        finally:
            state.stage_latency_ms["rerank"] = int((time.monotonic() - started) * 1000)


def answer_metrics(state: AnswerState, arm: Arm, gold: Gold, reference: str, *, failed: bool
                   ) -> dict[str, str | None]:
    closed = isinstance(arm, ClosedBook)
    result: dict[str, str | None] = dict(metrics_for(state.ranking, gold, failed=not state.ranking_complete))
    if closed:
        result = dict.fromkeys(result)
    response = state.answer
    cited = citation_metrics(answers.citations(response, state.delivery) if response else (), gold.passage_ids)
    result.update({"citation_precision": None if closed else str(cited.precision),
        "citation_recall": None if closed else str(cited.recall),
        "citation_integrity": None if closed else str(int(cited.integrity_failures == 0 and response is not None)),
        "gold_citation": None if closed else str(int(gold_citation(response.answer if response else "",
            answerable=bool(gold.passage_ids), abstained=response.abstain if response else False, citations=cited,
            error=failed and state.policy_latency_ms is None))),
        "quality_q": None if closed else str(int(quality_q(response.answer if response else "",
            abstained=response.abstain if response else False, citations=cited,
            claim_supported=state.verdicts if len(state.verdicts) == len(state.claims) else [None], error=failed))),
        "false_abstention": str(answerable_false_abstention_rate([bool(gold.passage_ids)],
            [response.abstain if response else None]) or Fraction(0)),
        "delivered_coverage": None if closed or not gold.passage_ids else str(Fraction(
            len({p.id for p in state.delivery.passages} & set(gold.passage_ids)), len(set(gold.passage_ids)))),
        "delivered_support": None if closed else str(int(bool(state.claims) and not failed
            and len(state.verdicts) == len(state.claims) and all(v is True for v in state.verdicts)))})
    try:
        lexical = lexical_metrics(response.answer if response else "", reference, error=failed)
    except ValueError:
        raise Refused("lexical_metric_bound") from None
    result.update({k: str(v) for k, v in asdict(lexical).items()})
    if failed:
        # Strict non-success for composition metrics, even if the answer was
        # parsed before a later judge failed. Completed ranking stays valid.
        for key in COMPOSITION_METRICS:
            if result[key] is not None and not (key == "gold_citation" and state.policy_latency_ms is not None):
                result[key] = "0"
    return result


def sanitized_metrics(value: Any) -> dict[str, str | None]:
    if not isinstance(value, dict):
        raise Refused("stored_metric_shape")
    names = (*asdict(retrieval_metrics((), ())), *COMPOSITION_METRICS)
    selected: dict[str, str | None] = {}
    for name in names:
        if name not in value:
            continue
        raw = value[name]
        if raw is None:
            selected[name] = None
            continue
        if not isinstance(raw, str) or len(raw) > 64 or not re.fullmatch(r"[0-9]+(?:/[1-9][0-9]*)?", raw):
            raise Refused("stored_metric_value")
        score = Fraction(raw)
        if not 0 <= score <= 1:
            raise Refused("stored_metric_value")
        selected[name] = str(score)
    return selected


def private_answer(state: AnswerState) -> dict[str, Any]:
    return {"ranked_passage_ids": state.ranking if state.ranking_complete else (),
        "ranking_complete": state.ranking_complete, "outcome_code": state.outcome_code,
        "first_stage_passage_ids": state.first_stage,
        "delivered_passage_ids": [p.id for p in state.delivery.passages],
        "skipped_overflow": state.delivery.skipped_overflow, "skipped_limit": state.delivery.skipped_limit,
        "evidence_tokens": state.delivery.tokens, "answer": None if state.answer is None else state.answer.model_dump(),
        "claims": state.claims, "verdicts": state.verdicts, "audit": state.audit,
        "rerank_metadata": state.rerank_metadata, "stage_latency_ms": state.stage_latency_ms,
        "stage_cost_usd": state.stage_cost_usd, "policy_latency_ms": state.policy_latency_ms,
        "policy_started_at": state.policy_started_at, "route": state.route,
        "escalation_reason": state.escalation_reason}


PUBLIC_FAILURES = frozenset({"abandoned_claim", "unresolved_billing", "slot_execution_error", "slot_deadline",
    "query_embedding_incomplete", "query_token_bound", "lexical_query_too_many_lexemes", "corpus_snapshot_integrity",
    "structural_passage_identity", "claim_bound_embedding_required", "chronological_generation_history_required",
    "answer_providers_required", "unsupported_arm", "evidence_contract", "unknown_ranked_passage", "invalid_answer",
    "generation_input_bound", "too_many_claims", "claim_limit", "undelivered_citation", "closed_book_citations",
    "judge_binding_required", "missing_cited_evidence", "invalid_judge_verdict", "answer_call_failed",
    "judge_call_failed", "rerank_call_failed", "answer.first_call_failed", "answer.fallback_call_failed",
    "answer.first_output_limit", "answer.fallback_output_limit", "answer_output_limit", "rerank_output_limit",
    "invalid_rerank", "rerank_input_bound", "cross_encoder_failure", "stage_or_cumulative_cap",
    "stage_model_envelope_mismatch", "one_matching_execution_stage_required", "lexical_metric_bound"})


def public_failure(value: Any) -> str | None:
    return value if value is None or (isinstance(value, str) and value in PUBLIC_FAILURES) else "unclassified_failure"


def public_stages(value: Any) -> dict[str, Any]:
    """Allowlist metadata independently of the stored private components."""
    if not isinstance(value, dict):
        raise Refused("stored_stage_shape")
    result: dict[str, Any] = {}
    for role in PAID_ROLES:
        if role not in value:
            continue
        entry = value[role]
        if not isinstance(entry, dict):
            raise Refused("stored_stage_shape")
        latency, cost = entry.get("latency_ms"), entry.get("cost_usd")
        if isinstance(cost, str) and len(cost) <= 32:
            # The ledger stores exact Decimals, which can serialize in exponent form (e.g. "0E-8" for zero).
            try:
                parsed = Decimal(cost)
            except InvalidOperation:
                raise Refused("stored_stage_cost") from None
            if parsed.is_finite() and parsed >= 0:
                cost = format(parsed, "f")
        if latency is not None and (type(latency) is not int or not 0 <= latency <= 604800000):
            raise Refused("stored_stage_latency")
        if cost is not None and (not isinstance(cost, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]{1,12})?", cost)
                                 or len(cost) > 32):
            raise Refused("stored_stage_cost")
        result[role] = {"latency_ms": latency, "cost_usd": cost}
    return result


def metric_failed(slot: dict[str, Any], metric: str) -> bool:
    """Legacy rows retain strict slot missingness; new rows bind each metric."""
    return bool(slot.get("metric_failures", {}).get(metric, slot["outcome"] != "success"))


def stored_policy_latency(components: dict[str, Any], private: dict[str, Any] | None,
                          *, complete: bool, arm: Arm) -> tuple[int | None, str | None]:
    if "policy_latency_ms" in components:
        value = components["policy_latency_ms"]
        if value is not None and (type(value) is not int or not 0 <= value <= 604800000):
            raise Refused("stored_policy_latency")
        return value if complete else None, "measured"
    # Old stage sums are sound only for the serial single-answer implementation.
    stages = None if private is None else private.get("stage_latency_ms")
    required = {"answer"}
    if not isinstance(arm, ClosedBook):
        required.add("embedding")
    if isinstance(arm, Rerank):
        required.add("rerank")
    if (not complete or isinstance(arm, (PolicyArm, FullContext, RetrievalOnly)) or not isinstance(stages, dict)
            or not required <= stages.keys() or set(stages) - {"embedding", "rerank", "answer", "judge"}
            or any(type(v) is not int or not 0 <= v <= 604800000 for v in stages.values())):
        return None, "derived-stage-sum"
    total = sum(stages.get(k, 0) for k in ("embedding", "rerank", "answer"))
    return (total if total <= 604800000 else None), "derived-stage-sum"


def citation_score(record: dict[str, Any], *, complete: bool) -> str:
    if not complete:
        return "0"
    try:
        answer = answers.parse_answer(json.dumps(record.get("answer")))
        delivered, gold = record["delivered_passage_ids"], record["gold_passage_ids"]
        if (not isinstance(delivered, (list, tuple)) or not isinstance(gold, (list, tuple))
                or len(delivered) > 5 or len(gold) > 10000
                or any(not isinstance(p, str) or len(p) > 500 for p in (*delivered, *gold))):
            raise ValueError
        cited = citation_metrics([Citation(p, identity_valid=p in delivered, access_valid=p in delivered)
                                  for p in answer.citations], gold)
        return str(int(gold_citation(answer.answer, answerable=bool(gold), abstained=answer.abstain,
                                     citations=cited)))
    except (ValueError, KeyError, TypeError):
        raise Refused("stored_citation_record") from None


def export(study: QAStudy, order: Sequence[Scheduled], repository: EvaluationRepository,
           runs: dict[str, UUID], inputs: Inputs | None = None) -> dict[str, Any]:
    rows = {row["id"]: row for run in runs.values() for row in repository.results(run)}
    claims = {s.id: s for run in runs.values() for s in repository.slots(run)}
    slots = []
    arms = {a.name: a for a in study.arms}
    legacy = any("citation_record" not in row["components"] and not isinstance(arms[item.arm], RetrievalOnly)
                 for item in order if (row := rows.get(item.id)) is not None)
    found = inventory(directory_for(study)) if legacy else {}
    for item in order:
        row = rows.get(item.id)
        claim = claims.get(item.id)
        held = Decimal(0)
        if claim is not None and ((row is not None and row["cost_status"] != "known")
                                  or claim.state == "running"):
            held = repository.usage(claim.scenario_id)["held_usd"]
        slot_value: dict[str, Any] = {"slot_id": str(item.id), "cohort": item.cohort, "question_id": item.question,
            "arm": item.arm, "repetition": item.repetition, "outcome": "missing" if row is None else row["outcome"],
            "metrics": {} if row is None else sanitized_metrics(row["components"].get("metrics", {})),
            "cost_usd": None if row is None or row["cost_usd"] is None else str(row["cost_usd"]),
            "cost_status": "unknown" if row is None else row["cost_status"],
            "held_liability_usd": str(held),
            "latency_ms": None if row is None else row["latency_ms"],
            "failure_code": "missing" if row is None else public_failure(row["error_class"])}
        if row is not None:
            failures = row["components"].get("metric_failures", {})
            if not isinstance(failures, dict) or any(type(v) is not bool for v in failures.values()):
                raise Refused("stored_metric_failures")
            slot_value["metric_failures"] = {k: failures[k] for k in slot_value["metrics"] if k in failures}
            code = row["components"].get("outcome_code")
            slot_value["outcome_code"] = (code if isinstance(code, str) and code in {
                "uncited_answer", "undelivered_citation"} else None)
        arm = arms[item.arm]
        if row is not None and not isinstance(arm, RetrievalOnly):
            components = row["components"]
            private = None
            record = components.get("citation_record")
            if record is None and row.get("artifact_sha256") is not None:
                _, result_path = linked(found, str(item.id) + ".json", row["artifact_sha256"])
                candidates = [p for (name, _), paths in found.items()
                              if name == str(item.id) + "-answer.json" for p in paths if p.parent == result_path.parent]
                if len(candidates) == 1:
                    private, _ = bundles.read(candidates[0])
                    if not isinstance(private, dict):
                        raise Refused("stored_answer_shape")
                    if inputs is not None:
                        record = dict(private, gold_passage_ids=inputs.gold[item.question].passage_ids)
            if "policy_latency_ms" in components:
                complete = components["policy_latency_ms"] is not None
            else:
                # A downstream judge failure preserves a fully validated policy answer.
                complete = (row["outcome"] == "success" or row["error_class"] in {
                    "invalid_judge_verdict", "judge_call_failed", "judge_binding_required"})
                complete = complete and private is not None and private.get("answer") is not None
            slot_value["metrics"]["gold_citation"] = (None if isinstance(arm, ClosedBook) else
                citation_score(record, complete=complete) if record is not None else "0")
            slot_value["metric_failures"]["gold_citation"] = not complete or record is None
            latency, provenance = stored_policy_latency(components, private, complete=complete, arm=arm)
            slot_value.update(policy_latency_ms=latency, policy_latency_provenance=provenance,
                              policy_latency_censored=latency is None)
            route, reason = components.get("route"), components.get("escalation_reason")
            if isinstance(arm, PolicyArm):
                if route not in {None, "first", "fallback"} or reason not in {None, *answers.ESCALATION_REASONS}:
                    raise Refused("stored_route")
                slot_value.update(route=route, escalation_reason=reason)
        if row is not None and "stages" in row["components"]:
            stages = public_stages(row["components"]["stages"])
            slot_value["stages"] = stages
            judge = stages.get("judge", {})
            policy_cost = (row["cost_usd"] - Decimal(judge.get("cost_usd") or "0")
                           if row["cost_usd"] is not None else None)
            if policy_cost is not None and policy_cost < 0:
                raise Refused("stored_stage_cost_contradiction")
            slot_value["policy_cost_usd"] = (str(policy_cost)
                if row["cost_status"] == "known" and row["cost_usd"] is not None else None)
        slots.append(slot_value)
    return {"schema_version": "policyops.qa-export/v1", "study_id": str(study.study_id),
            "specification_sha256": study.digest(), "slots": slots}


def report(study: QAStudy, inputs: Inputs, public: dict[str, Any], repository: EvaluationRepository,
           scope: UUID, source: dict[str, Any], judge_result: registration.JudgeResult | None = None) -> dict[str, Any]:
    if study.judge is None or study.judge.test_report_sha256 is None:
        judge_result = None
    by_key = {(s["cohort"], s["question_id"], s["arm"], s["repetition"]): s for s in public["slots"]}
    aggregates = []
    for assignment in study.schedule.assignments:
        rows = [s for s in public["slots"] if (s["cohort"], s["arm"]) == (assignment.cohort, assignment.arm)]
        arm = next(a for a in study.arms if a.name == assignment.arm)
        names = (*asdict(retrieval_metrics((), ())), *COMPOSITION_METRICS) if not isinstance(arm, RetrievalOnly) else (
            tuple(asdict(retrieval_metrics((), ()))))
        measurements = [Measurement(None if s.get("policy_cost_usd", s["cost_usd"]) is None else Decimal(
            s.get("policy_cost_usd", s["cost_usd"])), None if s.get("policy_latency_ms", s["latency_ms"]) is None
            else Decimal(s.get("policy_latency_ms", s["latency_ms"])) / 1000,
            "missing" if s["outcome"] == "missing" else "success" if s["outcome"] == "success" else "error",
            Decimal(s["held_liability_usd"])) for s in rows]
        policy_measurements = [Measurement(m.cost_usd,
            None if row.get("policy_latency_ms") is None else Decimal(row["policy_latency_ms"]) / 1000,
            "success" if row.get("policy_latency_ms") is not None and not row.get("policy_latency_censored", True)
            else "missing" if row["outcome"] == "missing" else "error", m.held_liability_usd)
            for row, m in zip(rows, measurements, strict=True)]
        end_to_end = [Measurement(m.cost_usd,
            None if row["latency_ms"] is None else Decimal(row["latency_ms"]) / 1000,
            "success" if row["outcome"] == "success" else "error", m.held_liability_usd)
            for row, m in zip(rows, measurements, strict=True)]
        aggregates.append({"cohort": assignment.cohort, "arm": assignment.arm, "scheduled": len(rows),
            "failed_or_missing": sum(s["outcome"] != "success" for s in rows),
            "outcome_counts": {code: sum(s.get("outcome_code") == code for s in rows)
                               for code in ("uncited_answer", "undelivered_citation")},
            "failure_counts": {code: sum(s["failure_code"] == code for s in rows)
                               for code in sorted({s["failure_code"] for s in rows if s["failure_code"] is not None})},
            "metric_failed_counts": {key: sum(metric_failed(s, key) for s in rows
                if not isinstance(arm, ClosedBook) or key in {"token_f1", "rouge_l", "false_abstention"})
                for key in names},
            "experimental_spend_usd": str(sum((Decimal(s["cost_usd"]) for s in rows
                                                 if s["cost_usd"] is not None), Decimal(0))),
            "cost": {k: str(v) if isinstance(v, Decimal) else v
                     for k, v in asdict(cost_per_question(measurements)).items()},
            "latency": {label: {k: str(v) if isinstance(v, Decimal) else v
                                for k, v in asdict(latency_percentile(end_to_end, probability)).items()}
                        for label, probability in (("p50", Fraction(1, 2)), ("p95", Fraction(19, 20)))},
            "policy_latency": {label: {k: str(v) if isinstance(v, Decimal) else v
                for k, v in asdict(policy_latency_percentile(policy_measurements, probability)).items()}
                for label, probability in (("p50", Fraction(1, 2)), ("p95", Fraction(19, 20)))},
            "policy_latency_rule": "failure-as-worst-v1",
            "policy_latency_provenance": {v: sum(s.get("policy_latency_provenance") == v for s in rows)
                for v in ("measured", "derived-stage-sum")},
            "escalation_rate": str(Fraction(sum(s.get("route") == "fallback" for s in rows), len(rows)))
                if isinstance(arm, PolicyArm) else None,
            "escalation_reason_counts": {v: sum(s.get("escalation_reason") == v for s in rows)
                for v in answers.ESCALATION_REASONS} if isinstance(arm, PolicyArm) else {},
            "route_cost": {v: {"n": sum(s.get("route") == v for s in rows),
                "known_policy_usd": str(sum((Decimal(s.get("policy_cost_usd") or "0")
                    for s in rows if s.get("route") == v), Decimal(0))),
                "unknown": sum(s.get("route") == v and s.get("policy_cost_usd") is None for s in rows)}
                for v in ("first", "fallback")} if isinstance(arm, PolicyArm) else {},
            "metrics": {key: None if isinstance(arm, ClosedBook) and key not in {
                "token_f1", "rouge_l", "false_abstention"} else str(sum((
                    Fraction(s["metrics"].get(key) or "0") if not metric_failed(s, key) else Fraction(0)
                    for s in rows), Fraction(0)) / len(rows)) for key in names},
            "stages": {role: {"known_cost_usd": str(sum((
                Decimal(s.get("stages", {}).get(role, {}).get("cost_usd") or "0") for s in rows), Decimal(0))),
                "latency_ms": sum(s.get("stages", {}).get(role, {}).get("latency_ms")
                or 0 for s in rows), "unconfirmed": sum(s["outcome"] != "success" or (
                    role in s.get("stages", {}) and s["stages"][role].get("cost_usd") is None) for s in rows)}
                for role in PAID_ROLES}})
    comparisons = []
    for comparison in study.analysis.comparisons:
        ids, clusters = [], []
        observations: dict[str, list[QuestionObservation | None]] = {comparison.candidate: [], comparison.reference: []}
        for q in inputs.cohorts[comparison.cohort]:
            if comparison.stratum != "all" and inputs.gold[q].stratum != comparison.stratum:
                continue
            for repetition in range(study.schedule.repetitions):
                ids.append(q + ":" + str(repetition))
                clusters.append(inputs.queries[q].dialogue_id)
                for arm_name, values in observations.items():
                    row = by_key[comparison.cohort, q, arm_name, repetition]
                    missing = row["outcome"] == "missing"
                    success = not metric_failed(row, comparison.estimand)
                    ranking_metric = comparison.estimand in asdict(retrieval_metrics((), ()))
                    # Ranking comparisons use that stage's completion/latency;
                    # compound gates use policy completion, independently of quality.
                    latency_ms = (sum(row.get("stages", {}).get(role, {}).get("latency_ms") or 0
                                      for role in ("embedding", "rerank")) if ranking_metric and "stages" in row
                                  else row.get("policy_latency_ms", row["latency_ms"]))
                    values.append(None if missing else QuestionObservation(
                        Fraction(row["metrics"].get(comparison.estimand) or "0") if success else None,
                        Measurement(None if row.get("policy_cost_usd", row["cost_usd"]) is None else Decimal(
                            row.get("policy_cost_usd", row["cost_usd"])),
                            None if latency_ms is None else Decimal(latency_ms) / 1000,
                            "success" if (success if ranking_metric else not row.get("policy_latency_censored", True))
                            and latency_ms is not None else "error", Decimal(row["held_liability_usd"])),
                        metric_failed=not success))
        candidate, reference = observations[comparison.candidate], observations[comparison.reference]
        result = comparison_result(study, comparison.name, ids, clusters, candidate, reference,
                                   registration_sha256=study.registration_sha256, judge=judge_result)
        estimate = paired_difference([o.value if o else None for o in candidate],
            [o.value if o else None for o in reference], clusters, seed=study.analysis.bootstrap_seed,
            alpha=Fraction(comparison.alpha))
        comparisons.append({"name": comparison.name, "result": result.model_dump(mode="json"),
            "policy_latency_rule": "failure-as-worst-v1" if comparison.decision == "noninferior_and_cheaper" else None,
            "policy_latency_failed_counts": {name: sum(o is None or o.measurement.status != "success" for o in values)
                for name, values in observations.items()} if comparison.decision == "noninferior_and_cheaper" else None,
            "ordinary_95": [str(estimate.low), str(estimate.high)], "point": str(estimate.point),
            "status": registration.comparison_status(study, result,
                DescriptiveView(repository.engine) if study.purpose == "dev" and study.registration_sha256 is None
                else repository, scope, source)})
    return {"schema_version": "policyops.qa-report/v1", "purpose": study.purpose,
            "aggregates": aggregates, "comparisons": comparisons,
            "judge_gate": None if judge_result is None else judge_result.model_dump(mode="json"),
            "limitations": ["Q is a citation/support surrogate, not human answer correctness.",
                "Closed-book citations, faithfulness and Q are N/A; gold-evidence support is not measured.",
                "Natural-unanswerable accuracy is N/A; lexical agreement is exploratory.",
                "Luna reranking uses bounded excerpts; CE uses query128/pair384 prefix truncation.",
                "Ranking metrics survive downstream failures; per-metric failure counts retain all scheduled slots.",
                "Lexical lexeme-cap refusals are strict retrieval failures, with no fallback.",
                "Cascade confidence is an uncalibrated model routing signal.",
                "Policy latency uses failure-as-worst-v1: failures rank as +infinity; "
                "a quantile is None only when its nearest rank falls in the failures. "
                "Failed counts include unavailable policy latency. End-to-end latency retains "
                "the censored-lower-bound rule.",
                "Judged comparisons are descriptive without a bound passing G6 test report."]}


class DescriptiveView(EvaluationRepository):
    """Unregistered dev runs are persisted, but cannot be mistaken for registration receipts."""
    def __init__(self, engine: Engine) -> None:
        self.engine = engine  # view only; caller already authenticated the repository

    def run_configuration(self, run_id: UUID) -> dict[str, Any] | None:
        return None


def resume_cascade(study: QAStudy, item: Scheduled, inputs: Inputs, repository: EvaluationRepository,
                   slot: Slot, lease: StudyLock) -> tuple[EvaluationClaimToken, AnswerState] | None:
    """Recover only the frozen between-stage checkpoint under the current study lease.

    Keep the original owner, invocation, scenario and operation identities. Any
    fallback attempt, held billing or missing checkpoint falls back to abort.
    This evaluator-only recovery uses the existing claim fencing contract.
    """
    target = directory_for(study) / (str(item.id) + "-cascade.json")
    if not target.exists():
        return None
    value, raw_checkpoint = bundles.read(target)
    linked(inventory(directory_for(study)), target.name, sha256_bytes(raw_checkpoint))
    if (not isinstance(value, dict) or value.get("study_sha256") != study.digest()
            or value.get("slot_id") != str(item.id)
            or value.get("query_sha256") != sha256_bytes(inputs.queries[item.question].generation.encode())):
        raise Refused("cascade_checkpoint_binding")
    with transaction(repository.engine) as connection:
        lease.check(connection)
        row = connection.execute(text("SELECT owner_token, invocation_scope, state FROM evaluation.trial_claims "
            "WHERE id = :id AND study_scope = :study AND scenario_scope = :scenario FOR UPDATE"),
            {"id": slot.id, "study": slot.study_id, "scenario": slot.scenario_id}).mappings().one()
        attempts = connection.execute(text("SELECT operation_id, state FROM evaluation.usage_attempts "
            "WHERE scenario_scope_id = :scenario"), {"scenario": slot.scenario_id}).mappings().all()
        lease.check(connection)
    arm = next(a for a in study.arms if a.name == item.arm)
    if not (isinstance(arm, PolicyArm) and isinstance(arm.policy, CascadePolicy)):
        raise Refused("cascade_contract_binding")
    first_prefix = "qa/" + role_stage(study, item, "answer.first").name + "/"
    allowed = (first_prefix, "qa/" + role_stage(study, item, "embedding").name + "/")
    if (row["state"] != "running" or str(row["owner_token"]) != value.get("owner")
            or str(row["invocation_scope"]) != value.get("invocation")
            or not any(a["operation_id"].startswith(first_prefix) for a in attempts)
            or any(a["state"] not in {"settled", "released"}
                   or not a["operation_id"].startswith(allowed) for a in attempts)):
        return None
    raw = value["state"]
    ranking = tuple(raw["ranked_passage_ids"])
    if (not raw.get("ranking_complete") or len(ranking) > 100 or len(set(ranking)) != len(ranking)
            or any(p not in inputs.passage_text for p in ranking)
            or raw.get("route") != "fallback" or raw.get("escalation_reason") not in answers.ESCALATION_REASONS
            or type(raw.get("policy_started_at")) not in {int, float}
            or not 0 <= time.time() - raw["policy_started_at"] <= 604800):
        raise Refused("cascade_checkpoint_state")
    if time.time() - raw["policy_started_at"] >= study.execution.request_deadline_seconds:
        return None  # Restart does not reset the slot time budget.
    token = EvaluationClaimToken(slot.id, row["owner_token"],
        EvalBinding(slot.study_id, row["invocation_scope"], slot.scenario_id), lease.pid)
    state = AnswerState(ranking=ranking, ranking_complete=True,
        first_stage=tuple(raw["first_stage_passage_ids"]), audit=raw["audit"],
        stage_latency_ms=raw["stage_latency_ms"], stage_cost_usd=raw["stage_cost_usd"],
        rerank_metadata=raw["rerank_metadata"], route="fallback", escalation_reason=raw["escalation_reason"],
        policy_started_at=raw["policy_started_at"],
        policy_elapsed_offset_ms=int((time.time() - raw["policy_started_at"]) * 1000))
    return token, state


def run(study: QAStudy, inputs: Inputs, repository: EvaluationRepository, store: EvalLedgerStore,
        executor: ArmExecutor, *, allow_paid: bool, resume: bool,
        source: dict[str, Any] | None = None, boundary: Callable[[str], None] = lambda _: None,
        providers: Callable[[], Providers] | None = None, tokenizer: Tokenizer | None = None,
        selection_receipt: Path | None = None,
        cross_encoder: Callable[[CrossEncoder, float], CrossEncoderClient] | None = None) -> dict[str, Any]:
    study.validate_data()
    supported(study)
    arms = {arm.name: arm for arm in study.arms}
    judged = any(isinstance(a, (AnswerGeneration, PolicyArm)) or (isinstance(a, Rerank) and a.generator is not None)
                 for a in arms.values())
    judge = answers.selected_judge(study.judge, selection_receipt) if judged else None
    if study.example or not preflight(study)["within_caps"]:
        raise Refused("real_study_within_caps_required")
    if any(not isinstance(a, RetrievalOnly) or a.retrieval.method != "fts" for a in arms.values()) and not allow_paid:
        raise Refused("paid_opt_in_required_before_credentials")
    source = registration.source_provenance() if source is None else source
    registration.validate_source(study, source)
    order = schedule(study, inputs)
    cap = study.execution.cumulative_caps
    scope = store.ensure_study(str(study.study_id), study.digest(), cap_usd=cap.usd, cap_calls=cap.calls)
    # All QA runners share a DB advisory program lock. It outlives no process and requires no migration.
    program = uuid5(NAMESPACE_URL, "policyops-qa-program/" + study.execution.program_ledger_key)
    with repository.study_lock(program), repository.study_lock(scope) as lease:
        receipt = (None if study.purpose == "dev" and study.registration_sha256 is None
                   else registration.registered(study, repository, scope, source))
        if study.purpose == "sealed_test" and receipt is None:
            raise Refused("sealed_test_prior_registration_required")
        records = registration.run_records(study, scope, source)
        runs = {}
        for record, arm in zip(records, study.arms, strict=True):
            runs[arm.name] = record.id if receipt else repository.ensure_run(record)
            if repository.slots(record.id) and not resume:
                raise Refused("existing_study_requires_resume")
        directory = directory_for(study)
        shared = executor.preprocessing()
        external = [s for s in study.execution.stages if s.role == "embedding" and s.cohort is None]
        if shared.held or len(external) > 1:
            raise Refused("preprocessing_unsettled_or_stage_ambiguous")
        if shared.calls and (not external or not envelope_fits(external[0].caps,
                usd=shared.usd, calls=shared.calls, counts=shared.calls, inputs=shared.inputs, outputs=0,
                seconds=shared.seconds, next_usd=Decimal(0), next_inputs=0, next_seconds=0, paid=False)):
            raise Refused("preprocessing_stage_cap")
        frozen = {"study": study.model_dump(mode="json"), "source": source,
                  "execution_binding": executor.binding(),
                  "shared_preprocessing": {k: str(v) for k, v in asdict(shared).items()},
                  "schedule": [asdict(s) | {"id": str(s.id)} for s in order]}
        bundles.write(directory / "study.json", canonical_bytes(frozen), byte_limit=QA_BUNDLE_BYTES)
        boundary("frozen")
        lookup = {}
        for item in order:
            arm = arms[item.arm]
            role = "answer.first" if isinstance(arm, PolicyArm) else "answer"
            stage = stage_for(study, item, arm) if isinstance(arm, RetrievalOnly) else role_stage(study, item, role)
            config = configuration(study, stage) if isinstance(arm, RetrievalOnly) else composition_configuration(study)
            stage_id = uuid5(scope, "stage/" + stage.name if isinstance(arm, RetrievalOnly) else "qa-composition/v1")
            store.ensure_invocation(scope, stage_id, config.caps)
            scenario = store.ensure_scenario(scope, item.task, item.repetition,
                                             study.arm_digest(arms[item.arm]), config.caps)
            slot = Slot(item.id, runs[item.arm], scope, study.arm_digest(arms[item.arm]), item.task,
                        item.repetition, study.schedule.balanced_order_seed, scenario, "scheduled")
            repository.schedule(slot)
            lookup[item.id] = slot, stage, stage_id, config
        boundary("scheduled")
        existing = {s.id: s for run_id in runs.values() for s in repository.slots(run_id)}
        if existing.keys() != lookup.keys():
            raise Refused("persisted_schedule_bijection")
        recovering: dict[UUID, tuple[EvaluationClaimToken, AnswerState]] = {}
        scheduled_by_id = {item.id: item for item in order}
        for slot in existing.values():
            if slot.state == "running":
                arm = arms[scheduled_by_id[slot.id].arm]
                checkpoint = (resume_cascade(study, scheduled_by_id[slot.id], inputs, repository, slot, lease)
                              if isinstance(arm, PolicyArm) and isinstance(arm.policy, CascadePolicy) else None)
                if checkpoint is not None:
                    recovering[slot.id] = checkpoint
                    continue
                repository.abort(slot, lease)  # never reissue even a claim that crashed before reservation
        invocation = directory.parent.parent / str(uuid4())  # shared bounded inventory paths are benchmarks-relative
        invocation.mkdir()
        primary: BaseException | None = None
        try:
            for item in order:
                if existing[item.id].state != "scheduled" and item.id not in recovering:
                    continue
                slot, stage, stage_id, config = lookup[item.id]
                arm = arms[item.arm]
                paid = (not isinstance(arm, ClosedBook)
                        and executor.needs_embedding(retrieval_arm(arm), inputs.queries[item.question]))
                if isinstance(arm, RetrievalOnly) and not admit(study, item, stage, repository, scope, stage_id,
                                                               paid=paid, shared=shared):
                    break
                if not isinstance(arm, RetrievalOnly) and not admit_slot_time(study, repository, scope, shared):
                    break
                # The global evaluator total is a conservative parent cap, including other study families.
                with transaction(repository.engine) as connection:
                    program_usd = connection.execute(text("SELECT coalesce(sum(spent_usd + held_usd), 0) "
                        "FROM evaluation.budget_scopes WHERE kind = 'study'")).scalar_one()
                if program_usd + shared.usd + (config.reservation("embedding").worst_usd if paid else 0) > (
                        study.execution.program_cap_usd):
                    break
                token = recovering[item.id][0] if item.id in recovering else repository.claim(slot, stage_id, lease)
                if token is None:
                    raise Refused("claim_unavailable")
                boundary("claimed")
                started = time.monotonic()
                error: str | None = None
                ranking: tuple[str, ...] = ()
                state = recovering[item.id][1] if item.id in recovering else AnswerState(
                    policy_started_at=time.time(), policy_started_monotonic=started)
                slot_seconds = study.execution.request_deadline_seconds - state.policy_elapsed_offset_ms / 1000
                try:
                    boundary("before_execute")
                    if isinstance(arm, RetrievalOnly):
                        ledger = Ledger(EvalLedgerStore(repository.engine, env="evaluation", claim_token=token), config)
                        ranking = executor.execute(arm, inputs.queries[item.question], item, ledger,
                                                   started + study.execution.request_deadline_seconds)
                    else:
                        if not isinstance(arm, (AnswerGeneration, Rerank, ClosedBook, PolicyArm)):
                            raise Refused("unsupported_arm")
                        if providers is None:
                            raise Refused("answer_providers_required")
                        if cross_encoder is None:
                            def absent_ce(binding: CrossEncoder, deadline: float) -> CrossEncoderClient:
                                raise WorkerError("worker_not_configured")
                            ce: Callable[[CrossEncoder, float], CrossEncoderClient] = absent_ce
                        else:
                            ce = cross_encoder
                        composed = AnswerExecutor(study, repository, scope, token, item, shared, providers,
                                                  boundary, invocation)
                        composed.execute(arm, inputs.queries[item.question], executor, inputs.passage_text,
                            tokenizer or load_tokenizer(), state, judge, ce,
                            started + slot_seconds, resumed=item.id in recovering)
                        ranking = state.ranking
                    boundary("executed")
                    if time.monotonic() - started >= slot_seconds:
                        raise Refused("slot_deadline")
                except Exception as failure:
                    error = (str(failure) if isinstance(failure, (Refused, answers.AnswerError))
                             else "slot_execution_error")
                finally:
                    if not isinstance(arm, RetrievalOnly):
                        ranking = state.ranking if state.ranking_complete else ()
                        # Includes process-loss injection after any stage boundary. The outer
                        # inventory seals this private checkpoint even when finalization never ran.
                        bundles.write(invocation / (str(item.id) + "-answer.json"),
                                      canonical_bytes(private_answer(state)))
                usage = repository.usage(slot.scenario_id)
                known = not usage["held_usd"] and not usage["calls_held"]
                if not known:
                    error = "unresolved_billing"
                try:
                    metrics: dict[str, str | None] = (dict(metrics_for(ranking, inputs.gold[item.question],
                        failed=error is not None)) if isinstance(arm, RetrievalOnly) else answer_metrics(state, arm,
                        inputs.gold[item.question], inputs.references.get(item.question, ""), failed=error is not None))
                except Refused:
                    error = "lexical_metric_bound"
                    metrics = answer_metrics(state, arm, inputs.gold[item.question], "", failed=True)
                private = canonical_bytes({"slot_id": str(item.id), "ranked_passage_ids": ranking,
                                           "metrics": metrics, "failure_code": error})
                digest = sha256_bytes(private)
                bundles.write(invocation / (str(item.id) + ".json"), private)
                boundary("artifact")
                metric_failures = {key: (error is not None if isinstance(arm, RetrievalOnly)
                    or key in COMPOSITION_METRICS else not state.ranking_complete)
                    if key != "gold_citation" else state.policy_latency_ms is None
                    for key, value in metrics.items() if value is not None}
                components: dict[str, Any] = {"metrics": metrics, "metric_failures": metric_failures}
                if not isinstance(arm, RetrievalOnly):
                    components["citation_record"] = {
                        "answer": None if state.answer is None else state.answer.model_dump(),
                        "delivered_passage_ids": [p.id for p in state.delivery.passages],
                        "gold_passage_ids": inputs.gold[item.question].passage_ids}
                    components["policy_latency_ms"] = state.policy_latency_ms
                    components["route"], components["escalation_reason"] = state.route, state.escalation_reason
                    components["outcome_code"] = state.outcome_code if error is None else None
                    components["stages"] = {role: {"latency_ms": state.stage_latency_ms.get(role),
                        "cost_usd": state.stage_cost_usd.get(role)} for role in state.stage_latency_ms}
                repository.finalize(EvaluationTrial(id=slot.id, evaluation_run_id=slot.run_id,
                    task_id=slot.task_id, trial_index=slot.trial_index, seed=slot.seed,
                    outcome="success" if error is None else "error", reward=None,
                    components_json=json.dumps(components), error_class=error,
                    cost_status="known" if known else "unknown", cost_usd=usage["spent_usd"] if known else None,
                    latency_ms=int((time.monotonic() - started) * 1000), artifact_sha256=digest,
                    created_at=datetime.now(UTC)), token, lease)
                boundary("finalized")
                if not known or usage["overrun"] or usage["contract_block"]:
                    break
        except BaseException as failure:
            primary = failure
            raise
        finally:
            try:
                raw_inventory(directory, invocation)
                public = export(study, order, repository, runs, inputs)
                bundles.write(directory / ("export-" + sha256_bytes(canonical_bytes(public)) + ".json"),
                              canonical_bytes(public), byte_limit=QA_BUNDLE_BYTES)
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("private inventory or checkpoint export unconfirmed")
                raise primary from None
        for run_id in runs.values():
            repository.finish_run(run_id, lease)
        return {"scheduled": len(order), "recorded": sum(s["outcome"] != "missing" for s in public["slots"]),
                "failed": sum(s["outcome"] not in {"success", "missing"} for s in public["slots"]),
                "output": str(directory), "execution_complete": all(s["outcome"] != "missing" for s in public["slots"])}


def command(study: QAStudy, action: str, *, materialization: Path, app_dsn_file: Path,
            eval_dsn_file: Path, workspace: UUID, corpus: str, allow_paid: bool = False,
            resume: bool = False, selection_receipt: Path | None = None, judge_report: Path | None = None,
            ce_artifacts: Sequence[Path] = ()) -> dict[str, Any]:
    supported(study)
    if (action == "run" and not allow_paid
            and any(not isinstance(a, RetrievalOnly) or a.retrieval.method != "fts" for a in study.arms)):
        raise Refused("paid_opt_in_required_before_credentials")
    if action == "run" and any(isinstance(a, (AnswerGeneration, PolicyArm))
                               or (isinstance(a, Rerank) and a.generator is not None)
                               for a in study.arms):
        answers.selected_judge(study.judge, selection_receipt)
    gate = answers.judge_gate(study.judge, judge_report) if action == "report" else None
    inputs = load_inputs(study, materialization)
    source = registration.source_provenance()
    app = make_engine(lambda: psycopg.connect(app_dsn_file.read_text(encoding="utf-8"), connect_timeout=5,
                                             options=RUNTIME_CONNECT_OPTIONS))
    evaluation = make_engine(lambda: psycopg.connect(eval_dsn_file.read_text(encoding="utf-8"), connect_timeout=5,
                                                    options=RUNTIME_CONNECT_OPTIONS))
    try:
        repository = EvaluationRepository(evaluation)
        store = EvalLedgerStore(evaluation, env="evaluation")
        if action == "run":
            def providers() -> Providers:
                import httpx2
                from pydantic import SecretStr

                credentials = {}
                for provider, variable in (("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY")):
                    if key := os.environ.get(variable):
                        credentials[provider] = SecretStr(key)
                return Providers(credentials=credentials,
                                 transport=lambda _: httpx2.AsyncHTTPTransport(trust_env=False))
            with ExitStack() as workers:
                clients: dict[str, CrossEncoderClient] = {}
                def ce(binding: CrossEncoder, deadline: float) -> CrossEncoderClient:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise WorkerError("worker_deadline")
                    if binding.artifact_sha256 not in clients:
                        matches = []
                        for path in ce_artifacts:
                            for name in ("artifact-manifest.json", "download-manifest.json"):
                                manifest = path / name
                                if manifest.is_file() and manifest.stat().st_size <= 1_000_000:
                                    raw = manifest.read_bytes()
                                    if sha256_bytes(raw) == binding.artifact_sha256:
                                        value = json.loads(raw)
                                        if value["files"]["tokenizer.json"]["sha256"] != binding.tokenizer_sha256:
                                            raise WorkerError("worker_tokenizer_binding")
                                        if (binding.training_receipt_sha256 is not None and value["files"].get(
                                                "training-manifest.json", {}).get("sha256")
                                                != binding.training_receipt_sha256):
                                            raise WorkerError("worker_training_binding")
                                        matches.append(path)
                        if len(matches) != 1:
                            raise WorkerError("worker_artifact_binding")
                        clients[binding.artifact_sha256] = workers.enter_context(CrossEncoderClient(
                            matches[0], binding.artifact_sha256, threads=binding.threads, timeout=min(remaining, 600)))
                    client = clients[binding.artifact_sha256]
                    client.timeout = min(remaining, 600)
                    return client
                return run(study, inputs, repository, store,
                    RetrieverExecutor(app, workspace, corpus, providers=providers, expected_passages=inputs.passages),
                    allow_paid=allow_paid, resume=resume, source=source, providers=providers,
                    selection_receipt=selection_receipt, cross_encoder=ce)
        scope = store.study_by_key(str(study.study_id))
        if scope is None:
            raise Refused("study_not_started")
        if repository.study_manifest(scope.id) != study.digest():
            raise Refused("study_binding_changed")
        with repository.study_lock(scope.id):
            public = export(study, schedule(study, inputs), repository,
                            {a.name: registration.run_id(study, scope.id, a.name) for a in study.arms}, inputs)
            if action == "status":
                return public
            result = report(study, inputs, public, repository, scope.id, source, gate)
            raw = canonical_bytes(result)
            bundles.write(directory_for(study) / ("report-" + sha256_bytes(raw) + ".json"), raw)
            return result
    finally:
        app.dispose()
        evaluation.dispose()
