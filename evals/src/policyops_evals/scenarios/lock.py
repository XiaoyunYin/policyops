"""Published scenario evidence and ordered request-body freezes."""

from collections.abc import Sequence
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine

from policyops.orchestration.profile import InvestigationProfile
from policyops.providers.tokenizer import Tokenizer
from policyops_contracts.conversation import PolicyContext
from policyops_evals.scenarios import n3, n3_report, study
from policyops_evals.scenarios.arms import Arm, Identity, identities
from policyops_evals.scenarios.cases import STRATA, Stratum
from policyops_evals.scenarios.generator import REPO
from policyops_evals.scenarios.recording import JSON_COMMA, JSON_FIELD, Exchange, Phase, digest


LOCK_PATH = REPO / "evals" / "studies" / "scenario-lock-v1.json"
ORACLE_PROFILES = (InvestigationProfile.BASELINE, InvestigationProfile.TOOL_CONTRACT_V1R1)
COMPONENTS = ("instructions", "tools", "input")
DEV_MANIFESTS = {name: value for name, value in study.MANIFEST_SHA256.items() if name.startswith("dev.")}
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Status = Literal["evaluated-admitted", "evaluated-rejected", "unevaluated"]


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProfileEntry(Frozen):
    status: Status
    identity: Identity


class PairCounts(Frozen):
    candidate: int = Field(ge=0)
    baseline: int = Field(ge=0)
    pairs: int = Field(gt=0)

    def delta(self) -> Fraction:
        if max(self.baseline, self.candidate) > self.pairs:
            raise ValueError("paired counts exceed their denominator")
        return Fraction(self.candidate - self.baseline, self.pairs)


class Count(Frozen):
    numerator: int = Field(ge=0)
    scheduled: int = Field(gt=0)


class StudyEvidence(Frozen):
    registration_sha256: Digest
    report_sha256: Digest
    evidence_sha256: Digest
    primary: PairCounts
    unsafe_attempt: PairCounts


class DevEvidence(StudyEvidence):
    primary_lower_bound: Fraction
    harness_stops: Count
    recorded: int = Field(ge=0)
    integrity: bool
    ambiguous: Count | None = None

    def verdict(self) -> str:
        return str(n3_report.verdict(
            self.primary.delta(), self.primary_lower_bound, self.unsafe_attempt.delta(),
            complete=self.recorded == self.harness_stops.scheduled,
            harness=(100 * self.harness_stops.numerator <= n3.MAX_HARNESS_STOPS * self.harness_stops.scheduled),
            integrity=self.integrity,
            ambiguous=(None if self.ambiguous is None else
                       self.ambiguous.scheduled == n3.AMBIGUOUS_SLOTS
                       and self.ambiguous.numerator <= n3.AMBIGUOUS_MAX_UNSAFE),
        )["verdict"])


class ExchangeDigests(Frozen):
    attempt: int = Field(ge=0)
    phase: Phase
    request_sha256: Digest
    instructions: Digest
    tools: Digest
    input: Digest


type RequestFreeze = dict[InvestigationProfile, dict[Stratum, list[ExchangeDigests] | Literal["pending"]]]


class ScenarioLock(Frozen):
    schema_version: Literal["policyops.scenario-lock/v1"]
    model_alias: Literal["gpt-6-luna"]
    profiles: dict[InvestigationProfile, ProfileEntry]
    grader_sha256: Digest
    dev_manifests: dict[str, Digest]
    revision_registration_file_sha256: Digest
    revision_dev: DevEvidence
    revision_held_out: StudyEvidence
    revision_unseal_sha256: Digest
    first_candidate_dev: DevEvidence
    requests: RequestFreeze


def read_lock() -> ScenarioLock:
    return ScenarioLock.model_validate_json(LOCK_PATH.read_bytes())


def verify_identities(lock: ScenarioLock, engine: Engine, policy: PolicyContext, tokenizer: Tokenizer) -> None:
    if lock.profiles.keys() != set(InvestigationProfile):
        raise ValueError("scenario lock profiles must cover every InvestigationProfile")
    registered = (Arm.BASELINE, Arm.CANDIDATE, Arm.REVISION)
    current = identities(engine, policy, tokenizer, arms=registered)
    if {arm.profile for arm in current} != lock.profiles.keys():
        raise ValueError("scenario lock has no identity builder for an InvestigationProfile")
    for arm, identity in current.items():
        expected = asdict(lock.profiles[arm.profile].identity)
        actual = asdict(identity)
        changed = sorted(name for name in expected if actual[name] != expected[name])
        if changed:
            raise ValueError(f"{arm.profile} identity changed: {', '.join(changed)}")
    if lock.grader_sha256 != n3.grader_digest():
        raise ValueError("grader_sha256 differs from the scenario lock")
    if lock.dev_manifests != DEV_MANIFESTS:
        raise ValueError("dev_manifests differ from the scenario lock")


def exchange_digests(record: Exchange) -> ExchangeDigests:
    """Hash exact top-level value bytes from the recorder's redacted request."""
    raw = record.request
    if raw is None or not (body := raw.lstrip()).startswith("{") or digest(raw) != record.request_sha256:
        raise ValueError(f"missing or invalid request at exchange {record.index}")
    decoder = json.JSONDecoder()
    fields: dict[str, str] = {}
    position = len(raw) - len(body) + 1
    while field := JSON_FIELD.match(raw, position):
        name = json.loads(field[1])
        value = field.end()
        _, end = decoder.raw_decode(raw, value)
        if name in COMPONENTS:
            if name in fields:
                raise ValueError(f"duplicate {name} at exchange {record.index}")
            fields[name] = sha256(raw[value:end].encode()).hexdigest()
        separator = JSON_COMMA.match(raw, end)
        if separator is None:
            break
        position = separator.end()
    if fields.keys() != set(COMPONENTS):
        raise ValueError(f"missing request components at exchange {record.index}")
    return ExchangeDigests.model_validate({
        "attempt": record.attempt, "phase": record.phase, "request_sha256": record.request_sha256, **fields,
    })


def verify_request_freeze(expected: RequestFreeze, actual: RequestFreeze) -> None:
    arms = set(ORACLE_PROFILES)
    if expected.keys() != arms or actual.keys() != arms:
        raise ValueError("request freeze must cover both oracle profiles")
    for profile in ORACLE_PROFILES:
        if expected[profile].keys() != set(STRATA) or actual[profile].keys() != set(STRATA):
            raise ValueError(f"{profile} request freeze must cover every stratum")
        for stratum in STRATA:
            compare_exchanges(f"{profile}/{stratum}", expected[profile][stratum], actual[profile][stratum])


def compare_exchanges(label: str, expected: Sequence[ExchangeDigests] | Literal["pending"],
                      actual: Sequence[ExchangeDigests] | Literal["pending"]) -> None:
    if isinstance(expected, str) or isinstance(actual, str) or not expected or not actual:
        raise ValueError(f"{label}: request freeze pending or missing")
    for index, (old, new) in enumerate(zip(expected, actual, strict=False)):
        if old != new:
            changed = ", ".join(name for name in COMPONENTS if getattr(old, name) != getattr(new, name))
            if (old.attempt, old.phase) != (new.attempt, new.phase):
                changed = "exchange order" + (f", {changed}" if changed else "")
            raise ValueError(f"{label}: exchange {index} (step {old.attempt + 1}, {old.phase}) "
                             f"changed {changed or 'request_sha256 (outside instructions, tools, input)'}")
    if len(expected) != len(actual):
        raise ValueError(f"{label}: exchange {min(len(expected), len(actual))} missing or unexpected "
                         f"({len(expected)} expected, {len(actual)} observed)")
