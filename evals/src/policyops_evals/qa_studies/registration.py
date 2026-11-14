"""QA registration on the existing evaluation repository; no QA runner here.

The source digest normalizes only the top-level QA registration value, retaining
all other bytes. Comparing normalized HEAD and worktree makes the committed
placeholder -> filled digest transition a fixed point even from a clean tree.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
import json
from pathlib import Path
import subprocess
from typing import Annotated, Any, Literal
from uuid import UUID, uuid5

from pydantic import Field, model_validator

from policyops.budget.prices import SNAPSHOT_2026_11_05
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository, EvaluationRun, StudyLock, environment_repository
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies.config import (
    PLACEHOLDER,
    ROOT,
    Count,
    Digest,
    Frozen,
    Money,
    Name,
    Probability,
    QAStudy,
    preflight,
)


def normalize_digest_field(data: bytes) -> bytes:
    """Normalize one top-level value, never JSON formatting or nested fields."""
    if len(data) > 2_000_000:
        return data
    try:
        text = data.decode("utf-8")
        body = json.loads(text)
        if not isinstance(body, dict) or body.get("schema_version") != "policyops.qa-study/v1":
            return data
        decoder = json.JSONDecoder()
        index = len(text) - len(text.lstrip()) + 1
        spans = []
        while True:
            while text[index].isspace():
                index += 1
            if text[index] == "}":
                break
            key, index = decoder.raw_decode(text, index)
            while text[index].isspace():
                index += 1
            if text[index] != ":":
                return data
            index += 1
            while text[index].isspace():
                index += 1
            start = index
            value, index = decoder.raw_decode(text, index)
            if key == "registration_sha256":
                if value is not None and (not isinstance(value, str) or len(value) != 64
                                          or any(c not in "0123456789abcdef" for c in value)):
                    return data
                spans.append((start, index))
            while text[index].isspace():
                index += 1
            if text[index] == "}":
                break
            if text[index] != ",":
                return data
            index += 1
        if len(spans) != 1:
            return data
        start, end = spans[0]
        return (text[:start] + "null" + text[end:]).encode("utf-8")
    except (ValueError, IndexError, UnicodeError):
        return data


def source_provenance(root: Path = ROOT) -> dict[str, Any]:
    def git(*args: str, required: bool = True) -> bytes | None:
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=30, check=required)
        return result.stdout if result.returncode == 0 else None

    head = git("rev-parse", "HEAD")
    changed = git("diff", "HEAD", "--name-only", "-z")
    untracked = git("ls-files", "--others", "--exclude-standard", "-z")
    if head is None or changed is None or untracked is None:
        raise ValueError("QA source inventory unavailable")
    inventory: list[tuple[str, str | None]] = []
    for raw in sorted((set(changed.split(b"\0")) | set(untracked.split(b"\0"))) - {b""}):
        path = raw.decode("utf-8")
        target = root / path
        if not target.exists():
            inventory.append((path, None))
            continue
        data = normalize_digest_field(target.read_bytes()) if path.endswith(".json") else target.read_bytes()
        before = git("show", "HEAD:" + path, required=False)
        if before is not None:
            before = normalize_digest_field(before) if path.endswith(".json") else before
        if data != before:
            inventory.append((path, sha256_bytes(data)))
    lock_paths = ["uv.lock", "evals/uv.lock"]
    if (root / "reranker/uv.lock").is_file():
        lock_paths.append("reranker/uv.lock")
    return {"source_head": head.decode().strip(), "dirty_sha256": sha256_bytes(canonical_bytes(inventory)),
            "lock_sha256": {path: sha256_bytes((root / path).read_bytes()) for path in lock_paths}}


def prices() -> dict[str, Any]:
    snapshot = SNAPSHOT_2026_11_05
    return {"revision": snapshot.revision, "checked_utc": snapshot.checked_utc,
            "models": [{"model": name, "provider": price.provider, "kind": price.kind,
                "tiers": [{"name": t.name, "max_prompt_tokens": t.max_prompt_tokens,
                    "input": str(t.input), "output": None if t.output is None else str(t.output),
                    "cache_read": None if t.cache_read is None else str(t.cache_read),
                    "cache_writes": {k: str(v) for k, v in t.cache_writes.items()}} for t in price.tiers]}
                for name, price in sorted(snapshot.models.items())]}


def registration_payload(study: QAStudy, source: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": "policyops.qa-study-registration/v1",
            "specification": study.model_dump(mode="json", exclude={"registration_sha256"}),
            "source": {k: source[k] for k in ("source_head", "dirty_sha256", "lock_sha256")},
            "schedule_sha256": sha256_bytes(canonical_bytes(study.schedule.model_dump(mode="json"))),
            "price_snapshot_sha256": sha256_bytes(canonical_bytes(prices()))}


def registration_digest(study: QAStudy, source: dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(registration_payload(study, source)))


def validate_source(study: QAStudy, source: dict[str, Any]) -> None:
    provenance = study.provenance
    if ((provenance.source_revision is not None and provenance.source_revision != source["source_head"])
            or (provenance.dirty_sha256 is not None and provenance.dirty_sha256 != source["dirty_sha256"])
            or any(source["lock_sha256"].get(lock.path) != lock.sha256 for lock in provenance.locks)):
        raise ValueError("QA source/lock binding mismatch")


def run_id(study: QAStudy, scope_id: UUID, arm_name: str) -> UUID:
    arm = next(a for a in study.arms if a.name == arm_name)
    return uuid5(scope_id, study.arm_digest(arm))


def run_records(study: QAStudy, scope_id: UUID, source: dict[str, Any]) -> list[EvaluationRun]:
    return [EvaluationRun(id=run_id(study, scope_id, arm.name), study_scope=scope_id,
        # This existing column is a Git identity: the derivation source, not an
        # invented upstream dataset commit. Archive/revision are in the spec.
        dataset="multidoc2dial-v1", dataset_revision=source["source_head"],
        split_id=study.purpose, config_sha256=study.arm_digest(arm),
        config_json=canonical_bytes({"study": study.model_dump(mode="json"), "arm": arm.name,
            "source": source}).decode(), created_at=datetime.now(UTC)) for arm in study.arms]


def validate_registration(study: QAStudy, source: dict[str, Any]) -> None:
    if study.example or study.registration_sha256 in {None, PLACEHOLDER}:
        raise ValueError("QA example/placeholder cannot be registered")
    study.validate_data()
    validate_source(study, source)
    if not preflight(study)["within_caps"]:
        raise ValueError("QA preflight exceeds caps")
    digest = registration_digest(study, source)
    if digest != study.registration_sha256:
        raise ValueError("QA declared registration digest mismatch")


def register(study: QAStudy, repository: EvaluationRepository, scope_id: UUID,
             source: dict[str, Any], lease: StudyLock) -> dict[str, Any]:
    validate_registration(study, source)
    digest = registration_digest(study, source)
    receipt = repository.register(run_records(study, scope_id, source),
                                  registration_payload(study, source), digest, lease)
    if not repository.registration_precedes_claims(scope_id, datetime.fromisoformat(receipt["created_at"])):
        raise ValueError("QA registration_after_claim")
    return receipt


def registered(study: QAStudy, repository: EvaluationRepository, scope_id: UUID,
               source: dict[str, Any]) -> dict[str, Any] | None:
    validate_source(study, source)
    digest = registration_digest(study, source)
    payload = registration_payload(study, source)
    configs = [repository.run_configuration(run_id(study, scope_id, a.name)) for a in study.arms]
    if all(config is None for config in configs):
        if study.registration_sha256 not in {None, PLACEHOLDER}:
            raise ValueError("QA committed registration required before claims")
        return None
    receipt: dict[str, Any] | None = None
    for config in configs:
        current = None if config is None else config.get("registration")
        if (not isinstance(current, dict) or digest != study.registration_sha256
                or current.get("sha256") != digest or current.get("payload") != payload
                or not current.get("created_at") or (receipt is not None and current != receipt)):
            raise ValueError("QA registration binding mismatch")
        receipt = current
    if receipt is None:
        raise ValueError("QA registration missing")
    at = datetime.fromisoformat(receipt["created_at"])
    if at.tzinfo is None or at.utcoffset() != timedelta(0):
        raise ValueError("QA registration requires UTC database timestamp")
    if not repository.registration_precedes_claims(scope_id, at):
        raise ValueError("QA registration_after_claim")
    return receipt


class JudgeResult(Frozen):
    selection_receipt_sha256: Digest
    complete: bool
    kappa: Annotated[Decimal, Field(ge=-1, le=1, allow_inf_nan=False)]
    kappa_lower: Annotated[Decimal, Field(ge=-1, le=1, allow_inf_nan=False)]
    false_pass: Probability

    @model_validator(mode="after")
    def interval(self) -> JudgeResult:
        if self.kappa_lower > self.kappa:
            raise ValueError("invalid kappa lower bound")
        return self

    def passed(self) -> bool:
        return (self.complete and self.kappa >= Decimal("0.6") and self.kappa_lower > Decimal("0.4")
                and self.false_pass <= Decimal("0.10"))


class ObservationSummary(Frozen):
    arm: Name
    scheduled: Count
    recorded: Count
    failed: Count
    missing: Count
    integrity: bool
    accounting_settled: bool
    held_liability_usd: Money

    @model_validator(mode="after")
    def counts(self) -> ObservationSummary:
        if self.recorded + self.missing != self.scheduled or self.failed > self.recorded:
            raise ValueError("invalid strict observation counts")
        if self.accounting_settled and self.held_liability_usd != 0:
            raise ValueError("settled accounting cannot contain held liability")
        return self


class ComparisonResult(Frozen):
    comparison: Name
    specification_sha256: Digest
    registration_sha256: Digest | None
    analysis_sha256: Digest
    missingness: Literal["strict-non-success"]
    adjusted_alpha: Annotated[Decimal, Field(gt=0, le=Decimal("0.05"), allow_inf_nan=False)]
    adjusted_lower: Annotated[Decimal, Field(ge=-1, le=1, allow_inf_nan=False)]
    cost_ratio_upper: Annotated[Decimal | None, Field(ge=0, le=1_000_000, allow_inf_nan=False)]
    candidate_p95_seconds: Annotated[Decimal | None, Field(ge=0, le=604800, allow_inf_nan=False)]
    reference_p95_seconds: Annotated[Decimal | None, Field(gt=0, le=604800, allow_inf_nan=False)]
    observations: Annotated[tuple[ObservationSummary, ...], Field(min_length=2, max_length=2)]
    judge: JudgeResult | None

    @model_validator(mode="after")
    def unique(self) -> ComparisonResult:
        if len({o.arm for o in self.observations}) != 2:
            raise ValueError("duplicate result arm")
        return self


Status = Literal["descriptive", "inconclusive", "candidate_superior", "candidate_noninferior_and_cheaper"]


def comparison_status(study: QAStudy, result: ComparisonResult, repository: EvaluationRepository,
                      scope_id: UUID, source: dict[str, Any]) -> Status:
    comparison = next((c for c in study.analysis.comparisons if c.name == result.comparison), None)
    if (comparison is None or result.specification_sha256 != study.digest()
            or result.analysis_sha256 != sha256_bytes(canonical_bytes(study.analysis.model_dump(mode="json")))
            or result.adjusted_alpha != comparison.alpha
            or {o.arm for o in result.observations} != {comparison.candidate, comparison.reference}):
        raise ValueError("QA result/specification binding mismatch")
    receipt = registered(study, repository, scope_id, source)
    if study.purpose == "dev" or study.example or receipt is None:
        return "descriptive"
    if result.registration_sha256 != receipt["sha256"]:
        raise ValueError("QA result/registration binding mismatch")
    expected = comparison.required_questions * study.schedule.repetitions
    if any(o.scheduled != expected or o.missing or not o.integrity or not o.accounting_settled
           or o.held_liability_usd for o in result.observations):
        return "inconclusive"
    if comparison.uses_judge and (result.judge is None or study.judge is None
            or result.judge.selection_receipt_sha256 != study.judge.selection_receipt_sha256
            or not result.judge.passed()):
        return "descriptive"
    if result.adjusted_lower <= comparison.margin:
        return "inconclusive"
    if comparison.decision == "superiority":
        return "candidate_superior"
    if (result.cost_ratio_upper is not None and result.cost_ratio_upper <= Decimal("0.80")
            and result.candidate_p95_seconds is not None and result.reference_p95_seconds is not None
            and result.candidate_p95_seconds <= Decimal("1.5") * result.reference_p95_seconds
            and result.candidate_p95_seconds <= Decimal("30")):
        return "candidate_noninferior_and_cheaper"
    return "inconclusive"


def command(study: QAStudy, *, register_requested: bool) -> dict[str, Any]:
    study.validate_data()
    source = source_provenance()
    result = preflight(study) | {"source": source, "registration_payload_sha256": registration_digest(study, source),
                                "prices": prices()}
    if not register_requested:
        return result
    if not result["within_caps"]:
        raise ValueError("QA preflight exceeds caps")
    validate_registration(study, source)
    repository = environment_repository()
    if repository is None:
        raise ValueError("QA evaluation database required")
    try:
        store = EvalLedgerStore(repository.engine, env="evaluation")
        cap = study.execution.cumulative_caps
        scope_id = store.ensure_study(str(study.study_id), study.digest(), cap_usd=cap.usd, cap_calls=cap.calls)
        with repository.study_lock(scope_id) as lease:
            receipt = register(study, repository, scope_id, source, lease)
        return result | {"registered": True, "receipt": receipt}
    finally:
        repository.engine.dispose()
