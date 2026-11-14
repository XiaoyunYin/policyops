"""Retrieval-only QA composition. Claims fence slots; the existing ledgers fence physical calls.

The app embedding ledger/cache remains authoritative for its workspace. A second,
claim-bound evaluator ledger reserves first and settles last, so a process loss
between databases keeps liability rather than permitting a replacement dispatch.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from decimal import Decimal
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

from policyops.budget.config import Actor, Configuration, EmbeddingActor
from policyops.budget.config import Caps as LedgerCaps
from policyops.budget.ledger import (
    Attempt,
    Binding,
    CountGranted,
    CountRefused,
    Diagnostic,
    DispatchGranted,
    DispatchRefused,
    Ledger,
    Reserved,
    Settled,
    Settlement,
)
from policyops.persistence.budget import AppLedgerStore, EvalLedgerStore
from policyops.persistence.database import RUNTIME_CONNECT_OPTIONS, make_engine, transaction, workspace_transaction
from policyops.persistence.embeddings import EmbeddingStore
from policyops.persistence.evaluation import EvaluationClaimToken, EvaluationRepository, EvaluationTrial, Slot
from policyops.persistence.retrieval import RetrievalStore
from policyops.providers.calls import Providers
from policyops.providers.embedding_calls import prepare_job, run_job_sync
from policyops.providers.tokenizer import Tokenizer
from policyops.providers.tokenizer import load as load_tokenizer
from policyops.retrieval.rank import fuse
from policyops_contracts.embedding import EmbeddingJob
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies import registration
from policyops_evals.qa_studies.config import ROOT, Arm, Caps, QAStudy, RetrievalOnly, Stage, preflight
from policyops_evals.qa_studies.metrics import Measurement, cost_per_question, latency_percentile, retrieval_metrics
from policyops_evals.qa_studies.statistics import QuestionObservation, comparison_result, paired_difference
from policyops_evals.studies import bundles
from policyops_evals.studies.runner_v2 import raw_inventory


class Refused(ValueError):
    pass


@dataclass(frozen=True)
class QueryInput:
    question_id: str
    dialogue_id: str
    history: str
    last_turn: str


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
    queries, gold = {}, {}
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
            queries[q] = QueryInput(q, row["domain"] + "/" + row["dialogue_id"], history, last)
    for row in gold_rows:
        q = row["query_id"]
        if q in wanted:
            ids = row["passage_ids"]
            if (q in gold or not isinstance(ids, list) or not ids or len(ids) > 5000
                    or any(not isinstance(p, str) or not p.startswith("md2d.p/") or len(p) > 100 for p in ids)):
                raise Refused("qrel_identity")
            gold[q] = Gold(tuple(ids), "clarification" if row["target_act"] == "query_condition" else "responding")
    if queries.keys() != wanted or gold.keys() != wanted:
        raise Refused("materialization_schedule_bijection")
    passage_manifest = json.loads((root / study.data.passages.path).read_bytes())
    passage_rows = read_private(directory / "passages.jsonl",
                                passage_manifest["materialization_sha256"]["passages.jsonl"])
    passages = {p["passage_id"]: sha256_bytes(canonical_bytes([p["heading"], p["body"]])) for p in passage_rows}
    if len(passages) != len(passage_rows) or not 1 <= len(passages) <= 5000:
        raise Refused("passage_bijection")
    return Inputs(queries, gold, cohorts, passages)


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
    if not isinstance(arm, RetrievalOnly):
        name = arm.policy.kind if arm.kind == "policy" else arm.kind
        raise Refused(f"{name}: not implemented in this slice")
    return arm


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
        snapshot = self.retrieval.snapshot(corpus_key=self.corpus,
            mode={"fts": "lexical", "dense": "dense", "rrf": "hybrid"}[arm.retrieval.method],
            query=value, query_vector=vector, document_ids=(), branch_documents=arm.retrieval.branch_limit,
            chunks_per_document=1, full_policy_max_chunks=1)
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


def sanitized_metrics(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise Refused("stored_metric_shape")
    names = asdict(retrieval_metrics((), ())).keys()
    selected = {}
    for name in names:
        if name not in value:
            continue
        raw = value[name]
        if not isinstance(raw, str) or len(raw) > 64 or not re.fullmatch(r"[0-9]+(?:/[1-9][0-9]*)?", raw):
            raise Refused("stored_metric_value")
        score = Fraction(raw)
        if not 0 <= score <= 1:
            raise Refused("stored_metric_value")
        selected[name] = str(score)
    return selected


def export(study: QAStudy, order: Sequence[Scheduled], repository: EvaluationRepository,
           runs: dict[str, UUID]) -> dict[str, Any]:
    rows = {row["id"]: row for run in runs.values() for row in repository.results(run)}
    claims = {s.id: s for run in runs.values() for s in repository.slots(run)}
    slots = []
    for item in order:
        row = rows.get(item.id)
        claim = claims.get(item.id)
        held = Decimal(0)
        if claim is not None and ((row is not None and row["cost_status"] != "known")
                                  or claim.state == "running"):
            held = repository.usage(claim.scenario_id)["held_usd"]
        slots.append({"slot_id": str(item.id), "cohort": item.cohort, "question_id": item.question,
            "arm": item.arm, "repetition": item.repetition, "outcome": "missing" if row is None else row["outcome"],
            "metrics": {} if row is None else sanitized_metrics(row["components"].get("metrics", {})),
            "cost_usd": None if row is None or row["cost_usd"] is None else str(row["cost_usd"]),
            "cost_status": "unknown" if row is None else row["cost_status"],
            "held_liability_usd": str(held),
            "latency_ms": None if row is None else row["latency_ms"],
            "failure_code": "missing" if row is None else row["error_class"]})
    return {"schema_version": "policyops.qa-export/v1", "study_id": str(study.study_id),
            "specification_sha256": study.digest(), "slots": slots}


def report(study: QAStudy, inputs: Inputs, public: dict[str, Any], repository: EvaluationRepository,
           scope: UUID, source: dict[str, Any]) -> dict[str, Any]:
    by_key = {(s["cohort"], s["question_id"], s["arm"], s["repetition"]): s for s in public["slots"]}
    aggregates = []
    for assignment in study.schedule.assignments:
        rows = [s for s in public["slots"] if (s["cohort"], s["arm"]) == (assignment.cohort, assignment.arm)]
        names = asdict(retrieval_metrics((), ())).keys()
        measurements = [Measurement(None if s["cost_usd"] is None else Decimal(s["cost_usd"]),
            None if s["latency_ms"] is None else Decimal(s["latency_ms"]) / 1000,
            "missing" if s["outcome"] == "missing" else "success" if s["outcome"] == "success" else "error",
            Decimal(s["held_liability_usd"])) for s in rows]
        aggregates.append({"cohort": assignment.cohort, "arm": assignment.arm, "scheduled": len(rows),
            "failed_or_missing": sum(s["outcome"] != "success" for s in rows),
            "cost": {k: str(v) if isinstance(v, Decimal) else v
                     for k, v in asdict(cost_per_question(measurements)).items()},
            "latency": {label: {k: str(v) if isinstance(v, Decimal) else v
                                for k, v in asdict(latency_percentile(measurements, probability)).items()}
                        for label, probability in (("p50", Fraction(1, 2)), ("p95", Fraction(19, 20)))},
            "metrics": {key: str(sum((Fraction(s["metrics"].get(key, "0")) if s["outcome"] == "success"
                                      else Fraction(0) for s in rows), Fraction(0)) / len(rows)) for key in names}})
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
                for arm, values in observations.items():
                    row = by_key[comparison.cohort, q, arm, repetition]
                    missing = row["outcome"] == "missing"
                    success = row["outcome"] == "success"
                    values.append(None if missing else QuestionObservation(
                        Fraction(row["metrics"].get(comparison.estimand, "0")) if success else None,
                        Measurement(None if row["cost_usd"] is None else Decimal(row["cost_usd"]),
                            None if row["latency_ms"] is None else Decimal(row["latency_ms"]) / 1000,
                            "success" if success else "error", Decimal(row["held_liability_usd"]))))
        candidate, reference = observations[comparison.candidate], observations[comparison.reference]
        result = comparison_result(study, comparison.name, ids, clusters, candidate, reference,
                                   registration_sha256=study.registration_sha256)
        estimate = paired_difference([o.value if o else None for o in candidate],
            [o.value if o else None for o in reference], clusters, seed=study.analysis.bootstrap_seed,
            alpha=Fraction(comparison.alpha))
        comparisons.append({"name": comparison.name, "result": result.model_dump(mode="json"),
            "ordinary_95": [str(estimate.low), str(estimate.high)], "point": str(estimate.point),
            "status": registration.comparison_status(study, result,
                DescriptiveView(repository.engine) if study.purpose == "dev" and study.registration_sha256 is None
                else repository, scope, source)})
    return {"schema_version": "policyops.qa-report/v1", "purpose": study.purpose,
            "aggregates": aggregates, "comparisons": comparisons}


class DescriptiveView(EvaluationRepository):
    """Unregistered dev runs are persisted, but cannot be mistaken for registration receipts."""
    def __init__(self, engine: Engine) -> None:
        self.engine = engine  # view only; caller already authenticated the repository

    def run_configuration(self, run_id: UUID) -> dict[str, Any] | None:
        return None


def run(study: QAStudy, inputs: Inputs, repository: EvaluationRepository, store: EvalLedgerStore,
        executor: ArmExecutor, *, allow_paid: bool, resume: bool,
        source: dict[str, Any] | None = None, boundary: Callable[[str], None] = lambda _: None) -> dict[str, Any]:
    study.validate_data()
    arms = {arm.name: retrieval_arm(arm) for arm in study.arms}
    if study.example or not preflight(study)["within_caps"]:
        raise Refused("real_study_within_caps_required")
    if any(a.retrieval.method != "fts" for a in arms.values()) and not allow_paid:
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
        bundles.write(directory / "study.json", canonical_bytes(frozen))
        boundary("frozen")
        lookup = {}
        for item in order:
            stage = stage_for(study, item, arms[item.arm])
            config = configuration(study, stage)
            stage_id = uuid5(scope, "stage/" + stage.name)
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
        for slot in existing.values():
            if slot.state == "running":
                repository.abort(slot, lease)  # never reissue even a claim that crashed before reservation
        invocation = directory.parent.parent / str(uuid4())  # shared bounded inventory paths are benchmarks-relative
        invocation.mkdir()
        primary: BaseException | None = None
        try:
            for item in order:
                if existing[item.id].state != "scheduled":
                    continue
                slot, stage, stage_id, config = lookup[item.id]
                paid = executor.needs_embedding(arms[item.arm], inputs.queries[item.question])
                if not admit(study, item, stage, repository, scope, stage_id, paid=paid, shared=shared):
                    break
                # The global evaluator total is a conservative parent cap, including other study families.
                with transaction(repository.engine) as connection:
                    program_usd = connection.execute(text("SELECT coalesce(sum(spent_usd + held_usd), 0) "
                        "FROM evaluation.budget_scopes WHERE kind = 'study'")).scalar_one()
                if program_usd + shared.usd + (config.reservation("embedding").worst_usd if paid else 0) > (
                        study.execution.program_cap_usd):
                    break
                token = repository.claim(slot, stage_id, lease)
                if token is None:
                    raise Refused("claim_unavailable")
                boundary("claimed")
                started = time.monotonic()
                error: str | None = None
                ranking: tuple[str, ...] = ()
                try:
                    ledger = Ledger(EvalLedgerStore(repository.engine, env="evaluation", claim_token=token), config)
                    boundary("before_execute")
                    ranking = executor.execute(arms[item.arm], inputs.queries[item.question], item, ledger,
                                               started + study.execution.request_deadline_seconds)
                    boundary("executed")
                    if time.monotonic() - started >= study.execution.request_deadline_seconds:
                        raise Refused("slot_deadline")
                except Exception as failure:
                    error = str(failure) if isinstance(failure, Refused) else "slot_execution_error"
                usage = repository.usage(slot.scenario_id)
                known = not usage["held_usd"] and not usage["calls_held"]
                if not known:
                    error = "unresolved_billing"
                metrics = metrics_for(ranking, inputs.gold[item.question], failed=error is not None)
                private = canonical_bytes({"slot_id": str(item.id), "ranked_passage_ids": ranking,
                                           "metrics": metrics, "failure_code": error})
                digest = sha256_bytes(private)
                bundles.write(invocation / (str(item.id) + ".json"), private)
                boundary("artifact")
                repository.finalize(EvaluationTrial(id=slot.id, evaluation_run_id=slot.run_id,
                    task_id=slot.task_id, trial_index=slot.trial_index, seed=slot.seed,
                    outcome="success" if error is None else "error", reward=None,
                    components_json=json.dumps({"metrics": metrics}), error_class=error,
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
                public = export(study, order, repository, runs)
                bundles.write(directory / ("export-" + sha256_bytes(canonical_bytes(public)) + ".json"),
                              canonical_bytes(public))
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("private inventory or checkpoint export unconfirmed")
                raise primary from None
        for run_id in runs.values():
            repository.finish_run(run_id, lease)
        return {"scheduled": len(order), "recorded": sum(s["outcome"] != "missing" for s in public["slots"]),
                "output": str(directory), "execution_complete": all(s["outcome"] != "missing" for s in public["slots"])}


def command(study: QAStudy, action: str, *, materialization: Path, app_dsn_file: Path,
            eval_dsn_file: Path, workspace: UUID, corpus: str, allow_paid: bool = False,
            resume: bool = False) -> dict[str, Any]:
    for arm in study.arms:
        retrieval_arm(arm)
    if (action == "run" and not allow_paid
            and any(a.retrieval.method != "fts" for a in study.arms if isinstance(a, RetrievalOnly))):
        raise Refused("paid_opt_in_required_before_credentials")
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

                key = os.environ.get("OPENAI_API_KEY")
                return Providers(credentials={"openai": SecretStr(key)} if key else {},
                                 transport=lambda _: httpx2.AsyncHTTPTransport())
            return run(study, inputs, repository, store,
                RetrieverExecutor(app, workspace, corpus, providers=providers, expected_passages=inputs.passages),
                allow_paid=allow_paid, resume=resume, source=source)
        scope = store.study_by_key(str(study.study_id))
        if scope is None:
            raise Refused("study_not_started")
        if repository.study_manifest(scope.id) != study.digest():
            raise Refused("study_binding_changed")
        with repository.study_lock(scope.id):
            public = export(study, schedule(study, inputs), repository,
                            {a.name: registration.run_id(study, scope.id, a.name) for a in study.arms})
            if action == "status":
                return public
            result = report(study, inputs, public, repository, scope.id, source)
            raw = canonical_bytes(result)
            bundles.write(directory_for(study) / ("report-" + sha256_bytes(raw) + ".json"), raw)
            return result
    finally:
        app.dispose()
        evaluation.dispose()
