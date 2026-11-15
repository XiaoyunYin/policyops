"""Frozen QA contract and offline, conservative admission arithmetic.

Manifests are byte-bound references, not imports of the dataset builder. The
runner expands their IDs later; optional cohorts are selected before registration.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints, field_validator, model_validator

from policyops.budget.prices import SNAPSHOT_2026_11_05
from policyops.budget.pricing import worst_case
from policyops_evals.canonical import canonical_bytes, sha256_bytes


ROOT = Path(__file__).resolve().parents[4]
PLACEHOLDER = "0" * 64
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Name = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,99}$")]
Text = Annotated[str, StringConstraints(min_length=1, max_length=500)]
Count = Annotated[int, Field(ge=0, le=1_000_000)]
Questions = Annotated[int, Field(ge=1, le=10_000)]
Tokens = Annotated[int, Field(ge=0, le=1_000_000_000_000)]
def exact_decimal(value: Any) -> Any:
    if not isinstance(value, (str, Decimal)):
        raise ValueError("exact decimal values require a decimal string or Decimal")
    if isinstance(value, str) and len(value) > 64:
        raise ValueError("decimal representation exceeds bound")
    try:
        return Decimal(value)
    except InvalidOperation as error:
        raise ValueError("invalid exact decimal") from error


Money = Annotated[Decimal, BeforeValidator(exact_decimal),
                  Field(ge=0, le=1_000_000, max_digits=21, decimal_places=12, allow_inf_nan=False)]
Probability = Annotated[Decimal, Field(ge=0, le=1, max_digits=12, decimal_places=10, allow_inf_nan=False)]


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ManifestRef(Frozen):
    path: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    sha256: Digest

    @field_validator("path")
    @classmethod
    def contained(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (path.is_absolute() or str(path) != value or ".." in path.parts or "\\" in value
                or ":" in value or not value.startswith("evals/")):
            raise ValueError("manifest path must be canonical and repository-relative under evals")
        return value


class ArchiveMember(Frozen):
    name: Text
    sha256: Digest


class Data(Frozen):
    dataset: Literal["multidoc2dial-v1"]
    archive_sha256: Digest
    revision: Text
    members: Annotated[tuple[ArchiveMember, ...], Field(min_length=1, max_length=16)]
    corpus: ManifestRef
    passages: ManifestRef
    queries: ManifestRef
    qrels: ManifestRef
    references: ManifestRef
    splits: ManifestRef
    sampling: ManifestRef
    eligibility_version: Name

    def manifests(self) -> tuple[ManifestRef, ...]:
        return (self.corpus, self.passages, self.queries, self.qrels,
                self.references, self.splits, self.sampling)


class ModelBinding(Frozen):
    model: Literal["gpt-6-luna", "claude-haiku-5-5"]
    effort: Literal["none", "minimal", "low", "medium", "high"]
    prompt_sha256: Digest
    schema_sha256: Digest
    max_input_tokens: Annotated[int, Field(ge=1, le=750_000)]
    max_output_tokens: Annotated[int, Field(ge=1, le=8192)]
    cache_policy: Literal["none", "30m", "12h", "5m", "1h"]

    @model_validator(mode="after")
    def priced(self) -> ModelBinding:
        worst_case(SNAPSHOT_2026_11_05.price(self.model), max_input=self.max_input_tokens,
                   max_output=self.max_output_tokens, cache_mode=self.cache_policy)
        return self


class JudgeBinding(ModelBinding):
    selection_receipt_sha256: Digest
    test_report_sha256: Digest | None = Field(default=None, exclude_if=lambda value: value is None)


def _all_terms(value: object) -> bool:
    return value == "all_terms"


class Retrieval(Frozen):
    method: Literal["fts", "dense", "rrf"]
    # Preserve historical specification/arm digests for omitted or explicit default modes.
    lexical_mode: Literal["all_terms", "any_terms", "bm25"] = Field(default="all_terms", exclude_if=_all_terms)
    query_profile: Literal["history-four-v1", "last-user-turn-v1"]
    candidate_count: Annotated[int, Field(ge=1, le=100)]
    branch_limit: Annotated[int, Field(ge=1, le=100)]
    rrf_k: Annotated[int, Field(ge=1, le=1000)]
    configuration_sha256: Digest


class Context(Frozen):
    max_passages: Annotated[int, Field(ge=1, le=5000)]
    evidence_tokens: Annotated[int, Field(ge=1, le=750_000)]
    policy: Literal["whole-passages-skip-overflow-v1", "complete-corpus-v1"]


class RetrievalOnly(Frozen):
    kind: Literal["retrieval_only"]
    name: Name
    retrieval: Retrieval


class AnswerGeneration(Frozen):
    kind: Literal["answer_generation"]
    name: Name
    retrieval: Retrieval
    generator: ModelBinding
    context: Context
    max_claims: Annotated[int, Field(ge=1, le=4)] = Field(default=4, exclude_if=lambda value: value == 4)


class LunaReranker(Frozen):
    kind: Literal["luna"]
    model: ModelBinding
    excerpt_policy_sha256: Digest

    @model_validator(mode="after")
    def luna(self) -> LunaReranker:
        if self.model.model != "gpt-6-luna":
            raise ValueError("Luna reranker requires Luna")
        return self


class CrossEncoder(Frozen):
    kind: Literal["cross_encoder"]
    artifact_sha256: Digest
    tokenizer_sha256: Digest
    runtime_sha256: Digest
    training_receipt_sha256: Digest | None
    candidate_pool_sha256: Digest
    truncation_policy_sha256: Digest
    max_length: Annotated[int, Field(ge=1, le=8192)]
    query_token_cap: Annotated[int, Field(ge=1, le=1024)]
    threads: Annotated[int, Field(ge=1, le=128)]


class Rerank(Frozen):
    kind: Literal["rerank"]
    name: Name
    retrieval: Retrieval
    reranker: Annotated[LunaReranker | CrossEncoder, Field(discriminator="kind")]
    generator: ModelBinding | None
    context: Context
    max_claims: Annotated[int, Field(ge=1, le=4)] = Field(default=4, exclude_if=lambda value: value == 4)


class CascadePolicy(Frozen):
    kind: Literal["cascade"]
    first: ModelBinding
    fallback: ModelBinding
    first_context: Context
    fallback_context: Context
    reranker: CrossEncoder | None = Field(default=None, exclude_if=lambda value: value is None)
    max_claims: Annotated[int, Field(ge=1, le=4)] = Field(default=4, exclude_if=lambda value: value == 4)
    confidence_threshold: Literal["0.6", "0.8", "1.0"]
    escalation_rule: Literal["invalid-or-abstain-or-request-or-low-confidence-v1"]


class SelectiveRerankPolicy(Frozen):
    kind: Literal["selective_rerank"]
    reranker: LunaReranker
    agreement_rule_sha256: Digest
    generator: ModelBinding
    context: Context


class PolicyArm(Frozen):
    kind: Literal["policy"]
    name: Name
    retrieval: Retrieval
    policy: Annotated[CascadePolicy | SelectiveRerankPolicy, Field(discriminator="kind")]
    selection_receipt_sha256: Digest | None = Field(default=None, exclude_if=lambda value: value is None)


class FullContext(Frozen):
    kind: Literal["full_context"]
    name: Name
    generator: ModelBinding
    corpus_render_sha256: Digest
    exact_count_receipt: ManifestRef
    context: Context

    @model_validator(mode="after")
    def complete(self) -> FullContext:
        if self.context.policy != "complete-corpus-v1":
            raise ValueError("full context must preserve the complete corpus")
        return self


class ClosedBook(Frozen):
    kind: Literal["closed_book"]
    name: Name
    generator: ModelBinding
    max_claims: Annotated[int, Field(ge=1, le=4)] = Field(default=4, exclude_if=lambda value: value == 4)


Arm = Annotated[RetrievalOnly | AnswerGeneration | Rerank | PolicyArm | FullContext | ClosedBook,
                Field(discriminator="kind")]


class Cohort(Frozen):
    name: Name
    manifest: ManifestRef
    manifest_cohort: Name
    split: Literal["train", "validation"]
    question_count: Questions
    dialogue_count: Questions
    optional: bool
    included: bool

    @model_validator(mode="after")
    def consistent(self) -> Cohort:
        if self.dialogue_count > self.question_count or (not self.optional and not self.included):
            raise ValueError("invalid cohort counts or omitted required cohort")
        return self


class ArmSchedule(Frozen):
    arm: Name
    cohort: Name


class Schedule(Frozen):
    cohorts: Annotated[tuple[Cohort, ...], Field(min_length=1, max_length=16)]
    assignments: Annotated[tuple[ArmSchedule, ...], Field(min_length=1, max_length=256)]
    repetitions: Annotated[int, Field(ge=1, le=32)]
    balanced_order_seed: Annotated[int, Field(ge=0, le=2147483647)]
    order_algorithm: Literal["sha256-rotation-v1"]
    slot_algorithm: Literal["uuid5-study-cohort-question-arm-repetition-v1"]


class JudgeGate(Frozen):
    min_kappa: Literal["0.6"]
    lower_kappa_exclusive: Literal["0.4"]
    max_false_pass: Literal["0.10"]
    require_complete: Literal[True]
    transfer_limitation: Literal["benchmark-agreement-not-domain-calibration"]


class CompoundMargins(Frozen):
    cost_ratio_upper: Literal["0.80"]
    latency_ratio_max: Literal["1.5"]
    latency_seconds_max: Literal["30"]


class Comparison(Frozen):
    name: Name
    candidate: Name
    reference: Name
    cohort: Name
    stratum: Literal["all", "responding", "clarification"]
    required_questions: Questions
    estimand: Literal["recall_at_5", "ndcg_at_10", "quality_q", "delivered_support", "gold_support", "gold_citation"]
    denominator: Literal["scheduled-questions-strict-non-success"]
    decision: Literal["superiority", "noninferior_and_cheaper"]
    margin: Annotated[Decimal, Field(ge=Decimal("-1"), le=1, allow_inf_nan=False)]
    direction: Literal["candidate-minus-reference"]
    alpha: Annotated[Decimal, Field(gt=0, le=Decimal("0.05"), decimal_places=10, allow_inf_nan=False)]
    compound: CompoundMargins | None

    @property
    def uses_judge(self) -> bool:
        return self.estimand in {"quality_q", "delivered_support", "gold_support"}

    @model_validator(mode="after")
    def margins(self) -> Comparison:
        if self.candidate == self.reference:
            raise ValueError("comparison requires distinct arms")
        if self.decision == "superiority":
            if self.margin != 0 or self.compound is not None:
                raise ValueError("superiority requires a strict positive improvement")
        elif (self.estimand not in {"quality_q", "gold_citation"} or self.margin != Decimal("-0.05")
              or self.compound is None):
            raise ValueError("compound adoption requires Q or gold_citation > -0.05 and frozen cost/latency margins")
        return self


class Analysis(Frozen):
    comparisons: Annotated[tuple[Comparison, ...], Field(min_length=1, max_length=16)]
    estimand_version: Name
    bootstrap_algorithm: Literal["sha256-whole-dialogue-question-weighted-ratio-v1"]
    bootstrap_seed: Annotated[int, Field(ge=0, le=2147483647)]
    bootstrap_replicates: Literal[10000]
    ordinary_interval: Literal["two-sided-95-percent"]
    multiplicity: Literal["bonferroni-directional-intersection-union-v1"]
    familywise_alpha: Literal["0.05"]
    missingness: Literal["strict-non-success"]
    judge_gate: JudgeGate

    @model_validator(mode="after")
    def allocation(self) -> Analysis:
        if sum((c.alpha for c in self.comparisons), Decimal(0)) > Decimal("0.05"):
            raise ValueError("familywise alpha allocation exceeds 0.05")
        if len({c.name for c in self.comparisons}) != len(self.comparisons):
            raise ValueError("duplicate comparison")
        return self


class Caps(Frozen):
    usd: Money
    calls: Count
    counts: Count
    input_tokens: Tokens
    output_tokens: Tokens
    seconds: Annotated[int, Field(ge=1, le=604800)]


class Stage(Frozen):
    name: Name
    arm: Name | None
    cohort: Name | None
    role: Literal["embedding", "answer", "answer.first", "answer.fallback",
                  "judge", "rerank", "policy", "local", "cache_probe"]
    model: Literal["gpt-6-luna", "claude-haiku-5-5", "text-embedding-3-small"] | None
    # Explicit ceilings include every scheduled question, repetition, failure,
    # possible escalation and cold cache write. No expected-hit discounts.
    planned_calls: Count
    planned_counts: Count
    max_input_tokens: Annotated[int, Field(ge=0, le=750_000)]
    max_output_tokens: Annotated[int, Field(ge=0, le=8192)]
    cache_policy: Literal["none", "30m", "12h", "5m", "1h"]
    caps: Caps

    @model_validator(mode="after")
    def request(self) -> Stage:
        if self.model is None:
            if (self.role != "local" or self.planned_calls or self.planned_counts
                    or self.max_input_tokens or self.max_output_tokens or self.cache_policy != "none"):
                raise ValueError("local stage cannot reserve provider work")
        else:
            if (self.role == "local" or self.max_input_tokens < 1 or self.planned_calls < 1
                    or self.planned_counts < self.planned_calls):
                raise ValueError("provider stage requires calls and an input envelope")
            price = SNAPSHOT_2026_11_05.price(self.model)
            if (price.kind == "embedding") != (self.role == "embedding"):
                raise ValueError("model kind/role mismatch")
            worst_case(price, max_input=self.max_input_tokens, max_output=self.max_output_tokens,
                       cache_mode=self.cache_policy)
        return self


class Execution(Frozen):
    price_snapshot_id: Literal["pricing.2026-11-05.v1"]
    stages: Annotated[tuple[Stage, ...], Field(min_length=1, max_length=256)]
    cumulative_caps: Caps
    program_ledger_key: Name
    program_cap_usd: Money
    retries: Literal[0]
    repairs: Literal[0]
    request_deadline_seconds: Annotated[int, Field(ge=1, le=300)]
    unresolved_liability_policy: Literal["hold-worst-case-block-decisions-and-resume-no-reissue"]
    artifact_max_observations: Annotated[int, Field(ge=1, le=1_000_000)]


class LockBinding(Frozen):
    path: Literal["uv.lock", "evals/uv.lock", "reranker/uv.lock"]
    sha256: Digest


class Provenance(Frozen):
    # None captures the actual value in the registration payload. Explicit
    # expectations are checked too; source/locks are never omitted from binding.
    source_revision: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")] | None
    dirty_sha256: Digest | None
    locks: Annotated[tuple[LockBinding, ...], Field(min_length=2, max_length=3)]
    machine: Text
    database: Text
    runtime: Text
    development_selection_receipts: Annotated[tuple[Digest, ...], Field(max_length=64)]


class QAStudy(Frozen):
    schema_version: Literal["policyops.qa-study/v1"]
    study_id: UUID
    name: Name
    purpose: Literal["dev", "sealed_test"]
    protocol_version: Name
    registration_sha256: Digest | None
    example: bool
    data: Data
    arms: Annotated[tuple[Arm, ...], Field(min_length=2, max_length=32)]
    judge: JudgeBinding | None
    schedule: Schedule
    analysis: Analysis
    execution: Execution
    provenance: Provenance

    def digest(self) -> str:
        return sha256_bytes(canonical_bytes(self.model_dump(mode="json", exclude={"registration_sha256"})))

    def slot_id(self, cohort: str, question: str, arm: str, repetition: int) -> UUID:
        if ((arm, cohort) not in {(a.arm, a.cohort) for a in self.schedule.assignments}
                or not 0 <= repetition < self.schedule.repetitions or not question or len(question) > 300):
            raise ValueError("slot outside declared schedule")
        return uuid5(self.study_id, canonical_bytes([cohort, question, arm, repetition]).decode())

    def arm_order(self, cohort: str, question_index: int, repetition: int) -> tuple[str, ...]:
        selected = next((c for c in self.schedule.cohorts if c.name == cohort and c.included), None)
        if (selected is None or not 0 <= question_index < selected.question_count
                or not 0 <= repetition < self.schedule.repetitions):
            raise ValueError("order outside declared schedule")
        names = tuple(a.name for a in self.arms
                      if (a.name, cohort) in {(s.arm, s.cohort) for s in self.schedule.assignments})
        if not names:
            raise ValueError("cohort has no scheduled arms")
        seed = sha256_bytes(canonical_bytes(["qa-order-v1", self.schedule.balanced_order_seed, cohort]))
        offset = (int(seed[:16], 16) + question_index * self.schedule.repetitions + repetition) % len(names)
        return names[offset:] + names[:offset]

    def arm_digest(self, arm: Arm) -> str:
        return sha256_bytes(canonical_bytes([self.digest(), arm.model_dump(mode="json")]))

    def manifests(self) -> tuple[ManifestRef, ...]:
        return (*self.data.manifests(), *(c.manifest for c in self.schedule.cohorts),
                *(a.exact_count_receipt for a in self.arms if isinstance(a, FullContext)))

    def validate_data(self, root: Path = ROOT) -> None:
        checked: dict[str, bytes] = {}
        for ref in self.manifests():
            target = (root / ref.path).resolve()
            if not target.is_relative_to(root.resolve()) or target.stat().st_size > 64_000_000:
                raise ValueError("manifest containment/size refusal")
            if ref.path not in checked:
                checked[ref.path] = target.read_bytes()
            if sha256_bytes(checked[ref.path]) != ref.sha256:
                raise ValueError("manifest byte binding mismatch")
        decoded: dict[str, Any] = {}
        corpus = json.loads(checked[self.data.corpus.path], object_pairs_hook=_unique_object)
        source = corpus.get("source", {}) if isinstance(corpus, dict) else {}
        if (not isinstance(source, dict) or source.get("archive_sha256") != self.data.archive_sha256
                or source.get("member_sha256") != {m.name: m.sha256 for m in self.data.members}):
            raise ValueError("dataset archive/member identity mismatch")
        decoded[self.data.corpus.path] = corpus
        for cohort in self.schedule.cohorts:
            path = cohort.manifest.path
            if path not in decoded:
                decoded[path] = json.loads(checked[path], object_pairs_hook=_unique_object)
            manifest = decoded[path]
            if not isinstance(manifest, dict) or manifest.get("schema") != "policyops.multidoc2dial/v1":
                raise ValueError("unsupported cohort manifest schema")
            entries = manifest.get("cohorts", {})
            selected = entries.get(cohort.manifest_cohort) if isinstance(entries, dict) else None
            if not isinstance(selected, dict):
                raise ValueError("cohort absent from bound manifest")
            questions, dialogues = selected.get("query_ids"), selected.get("dialogue_ids")
            if (not isinstance(questions, list) or not isinstance(dialogues, list)
                    or len(questions) != cohort.question_count or len(dialogues) != cohort.dialogue_count
                    or selected.get("queries") != cohort.question_count
                    or selected.get("dialogues") != cohort.dialogue_count
                    or any(not isinstance(q, str) or len(q) > 300
                           or not q.startswith("md2d.q/" + cohort.split + "/") for q in questions)
                    or any(not isinstance(d, str) or len(d) > 300 for d in dialogues)
                    or len(set(questions)) != len(questions) or len(set(dialogues)) != len(dialogues)):
                raise ValueError("cohort manifest identity/count mismatch")
            if (questions != sorted(questions)
                    or selected.get("query_ids_sha256") != sha256_bytes(
                        "".join(q + "\n" for q in questions).encode("utf-8"))):
                raise ValueError("cohort query IDs/hash mismatch")
            for comparison in self.analysis.comparisons:
                if (comparison.cohort == cohort.name and comparison.stratum != "all"
                        and selected.get("by_act_group", {}).get(comparison.stratum) != comparison.required_questions):
                    raise ValueError("stratum denominator differs from bound manifest")

    @model_validator(mode="after")
    def linked(self) -> QAStudy:
        arms = {a.name: a for a in self.arms}
        if len({m.name for m in self.data.members}) != len(self.data.members):
            raise ValueError("duplicate archive member identity")
        cohorts = {c.name: c for c in self.schedule.cohorts}
        assignments = {(a.arm, a.cohort) for a in self.schedule.assignments}
        if (len(arms) != len(self.arms) or len(cohorts) != len(self.schedule.cohorts)
                or len(assignments) != len(self.schedule.assignments)):
            raise ValueError("duplicate arm, cohort or assignment")
        if any(a not in arms or c not in cohorts or not cohorts[c].included for a, c in assignments):
            raise ValueError("assignment references unknown/excluded arm or cohort")
        if {a for a, _ in assignments} != set(arms):
            raise ValueError("every arm requires a schedule")
        if any(c.included and c.split != ("train" if self.purpose == "dev" else "validation")
               for c in cohorts.values()):
            raise ValueError("purpose/cohort split mismatch")
        if self.purpose != "dev" and any(isinstance(a, PolicyArm) and a.selection_receipt_sha256 is None
                                         for a in self.arms):
            raise ValueError("non-dev policy requires selection receipt")
        for comparison in self.analysis.comparisons:
            if any((a, comparison.cohort) not in assignments
                   for a in (comparison.candidate, comparison.reference)):
                raise ValueError("comparison arms must share a scheduled cohort")
            count = cohorts[comparison.cohort].question_count
            if (comparison.required_questions > count
                    or (comparison.stratum == "all" and comparison.required_questions != count)):
                raise ValueError("comparison denominator mismatch")
            if comparison.uses_judge and self.judge is None:
                raise ValueError("judged comparison requires frozen G6 judge binding")
            for name in (comparison.candidate, comparison.reference):
                arm = arms[name]
                if (comparison.uses_judge or comparison.estimand == "gold_citation") and (isinstance(arm, RetrievalOnly)
                                              or (isinstance(arm, Rerank) and arm.generator is None)):
                    raise ValueError("answer metric requires answer arms")
                if not comparison.uses_judge and isinstance(arm, (ClosedBook, FullContext)):
                    raise ValueError("retrieval metric requires retrieval arms")
        locks = self.provenance.locks
        if (len({lock.path for lock in locks}) != len(locks)
                or not {"uv.lock", "evals/uv.lock"} <= {lock.path for lock in locks}):
            raise ValueError("unique application and evaluator locks required")
        if (any((isinstance(a, Rerank) and isinstance(a.reranker, CrossEncoder))
                or (isinstance(a, PolicyArm) and isinstance(a.policy, CascadePolicy)
                    and a.policy.reranker is not None) for a in self.arms)
                and "reranker/uv.lock" not in {lock.path for lock in locks}):
            raise ValueError("cross-encoder runtime requires its isolated lock")
        if len({s.name for s in self.execution.stages}) != len(self.execution.stages):
            raise ValueError("duplicate stage")
        for stage in self.execution.stages:
            if ((stage.arm is not None and stage.arm not in arms)
                    or (stage.cohort is not None and (stage.cohort not in cohorts
                                                    or not cohorts[stage.cohort].included))):
                raise ValueError("stage references unknown/excluded arm or cohort")
        demands: list[tuple[str, str, str, ModelBinding, int]] = []
        for name, cohort in assignments:
            arm = arms[name]
            n = cohorts[cohort].question_count * self.schedule.repetitions
            models: list[tuple[str, ModelBinding]] = []
            if isinstance(arm, (AnswerGeneration, FullContext, ClosedBook)):
                models.append(("answer", arm.generator))
            elif isinstance(arm, Rerank):
                if isinstance(arm.reranker, LunaReranker):
                    models.append(("rerank", arm.reranker.model))
                if arm.generator is not None:
                    models.append(("answer", arm.generator))
            elif isinstance(arm, PolicyArm):
                if isinstance(arm.policy, CascadePolicy):
                    models.extend((("answer.first", arm.policy.first), ("answer.fallback", arm.policy.fallback)))
                else:
                    models.extend((("rerank", arm.policy.reranker.model), ("answer", arm.policy.generator)))
            if (any(role in {"answer", "answer.first", "answer.fallback", "policy"} for role, _ in models)
                    and self.judge is not None):
                models.append(("judge", self.judge))
            demands.extend((name, cohort, role, model,
                            n * (arm.max_claims if isinstance(arm, (AnswerGeneration, Rerank, ClosedBook))
                                 else arm.policy.max_claims if isinstance(arm, PolicyArm)
                                 and isinstance(arm.policy, CascadePolicy) else 1)
                            if role == "judge" else n)
                           for role, model in models if not (role == "judge" and isinstance(arm, ClosedBook)))
        # Demand is aggregated for identical stages (e.g. two cascade calls to
        # the same model); shared query embedding is separately declared.
        grouped: dict[tuple[str, str, str, str, str], tuple[int, int, int]] = {}
        for name, cohort, role, model, n in demands:
            key = (name, cohort, role, model.model, model.cache_policy)
            old_n, old_input, old_output = grouped.get(key, (0, 0, 0))
            grouped[key] = (old_n + n, max(old_input, model.max_input_tokens),
                            max(old_output, model.max_output_tokens))
        for (name, cohort, role, model_name, cache), (n, max_input, max_output) in grouped.items():
            available = sum(s.planned_calls for s in self.execution.stages
                if (s.arm, s.cohort, s.role, s.model, s.cache_policy) == (name, cohort, role, model_name, cache)
                and s.max_input_tokens >= max_input and s.max_output_tokens >= max_output)
            if available < n:
                raise ValueError("provider stage envelope does not cover the complete schedule")
        embedding_cohorts = set()
        for name, cohort in assignments:
            retrieval_arm = arms[name]
            if (isinstance(retrieval_arm, (RetrievalOnly, AnswerGeneration, Rerank, PolicyArm))
                    and retrieval_arm.retrieval.method in {"dense", "rrf"}):
                embedding_cohorts.add(cohort)
        for cohort in embedding_cohorts:
            available = sum(s.planned_calls for s in self.execution.stages if s.cohort == cohort
                            and s.role == "embedding" and s.max_input_tokens >= 1024)
            if available < cohorts[cohort].question_count:
                raise ValueError("shared query embedding envelope does not cover cohort")
        slots = sum(cohorts[c].question_count * self.schedule.repetitions for _, c in assignments)
        capacity = max(slots, sum(s.planned_calls + s.planned_counts for s in self.execution.stages))
        if capacity > self.execution.artifact_max_observations:
            raise ValueError("schedule exceeds declared artifact capacity")
        # Existing registration stores spec + payload in a 60,000-character
        # immutable record. Before registration the config is indented; the DB
        # receipt uses compact JSON. Reserve room for source and receipt fields
        # in both representations, including JSON's Unicode escapes.
        specification = self.model_dump(mode="json")
        if (len(canonical_bytes(specification)) > 50_000
                or 2 * len(json.dumps(specification)) + 4000 > 60_000):
            raise ValueError("QA specification exceeds existing registration record capacity")
        return self


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for key, value in pairs:
        if key in body:
            raise ValueError("duplicate JSON key")
        body[key] = value
    return body


def load_study(path: Path) -> QAStudy:
    if path.stat().st_size > 2_000_000:
        raise ValueError("QA specification size bound")
    raw = path.read_bytes()
    json.loads(raw, object_pairs_hook=_unique_object)
    return QAStudy.model_validate_json(raw)


def preflight(study: QAStudy) -> dict[str, Any]:
    """Worst-case paid calls, separate count calls, and exact Decimal money."""
    rows = []
    calls = counts = inputs = outputs = 0
    amount = Decimal(0)
    within = True
    for stage in study.execution.stages:
        usd = Decimal(0) if stage.model is None else stage.planned_calls * worst_case(
            SNAPSHOT_2026_11_05.price(stage.model), max_input=stage.max_input_tokens,
            max_output=stage.max_output_tokens, cache_mode=stage.cache_policy)
        input_tokens = stage.planned_calls * stage.max_input_tokens
        output_tokens = stage.planned_calls * stage.max_output_tokens
        caps = stage.caps
        ok = (usd <= caps.usd and stage.planned_calls <= caps.calls and stage.planned_counts <= caps.counts
              and input_tokens <= caps.input_tokens and output_tokens <= caps.output_tokens)
        rows.append({"stage": stage.name, "calls": stage.planned_calls, "counts": stage.planned_counts,
                     "input_tokens": input_tokens, "output_tokens": output_tokens,
                     "ceiling_usd": str(usd), "caps": caps.model_dump(mode="json"), "within_caps": ok})
        within = within and ok
        calls += stage.planned_calls
        counts += stage.planned_counts
        inputs += input_tokens
        outputs += output_tokens
        amount += usd
    cap = study.execution.cumulative_caps
    within = (within and amount <= cap.usd and calls <= cap.calls and counts <= cap.counts
              and inputs <= cap.input_tokens and outputs <= cap.output_tokens
              and cap.usd <= study.execution.program_cap_usd)
    return {"study_id": str(study.study_id), "price_snapshot_id": study.execution.price_snapshot_id,
            "stages": rows, "planned_calls": calls, "planned_counts": counts,
            "input_token_envelope": inputs, "output_token_envelope": outputs,
            "ceiling_usd": str(amount), "cumulative_caps": cap.model_dump(mode="json"),
            "within_caps": within, "authorizes_paid_execution": False}
