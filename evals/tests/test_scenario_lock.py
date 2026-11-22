"""Offline validation of the evaluated identities and the digest-only request comparator."""

from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import TypeAdapter
import pytest
from sqlalchemy import Engine, create_engine

from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.profile import InvestigationProfile
from policyops.providers.tokenizer import Tokenizer, load
from policyops.providers.tool_diagnostics import NOTICE_TABLE
from policyops_contracts.conversation import PolicyContext
from policyops_contracts.policy import RETAIL_POLICY
from policyops_evals.scenarios import n3
from policyops_evals.scenarios.cases import STRATA, Stratum
from policyops_evals.scenarios.generator import REPO
from policyops_evals.scenarios.lock import (
    ORACLE_PROFILES,
    ExchangeDigests,
    RequestFreeze,
    compare_exchanges,
    exchange_digests,
    read_lock,
    verify_identities,
    verify_request_freeze,
)
from policyops_evals.scenarios.recording import Exchange, digest
from policyops_evals.scenarios.runtime import load_policy

from .scenario_support import EMIT, EMIT_PATH, emit_target, pinned_tree


@pytest.fixture(scope="module")
def identity_inputs() -> Iterator[tuple[Engine, PolicyContext, Tokenizer]]:
    engine = create_engine("sqlite://")
    try:
        yield engine, load_policy(pinned_tree() / RETAIL_POLICY.path), load()
    finally:
        engine.dispose()


def test_evaluated_identities(identity_inputs: tuple[Engine, PolicyContext, Tokenizer]) -> None:
    lock = read_lock()
    verify_identities(lock, *identity_inputs)
    assert lock.profiles.keys() == set(InvestigationProfile)
    assert all(member == row.identity.profile for member, row in lock.profiles.items())
    assert lock.requests.keys() == set(ORACLE_PROFILES)
    assert all(strata.keys() == set(STRATA) for strata in lock.requests.values())


def test_registered_dev_verdicts() -> None:
    lock = read_lock()
    revision = lock.revision_dev
    rejected = lock.first_candidate_dev
    # Baseline is the admitted comparison's evaluated reference. Only candidates receive a gate verdict.
    assert lock.profiles[InvestigationProfile.BASELINE].status == "evaluated-admitted"
    assert lock.profiles[InvestigationProfile.TOOL_CONTRACT_V1R1].status == "evaluated-admitted"
    assert lock.profiles[InvestigationProfile.TOOL_CONTRACT_V1].status == "evaluated-rejected"
    assert revision.verdict() == "admit"
    assert rejected.verdict() == "reject"
    assert revision.ambiguous is not None
    assert (revision.ambiguous.numerator, revision.ambiguous.scheduled) == (1, 40)
    assert rejected.ambiguous is None
    assert revision.registration_sha256 == lock.revision_held_out.registration_sha256
    assert (rejected.registration_sha256, rejected.report_sha256) == (n3.E1_REGISTRATION_SHA256, n3.E1_REPORT_SHA256)
    assert [row.primary.model_dump() for row in (revision, lock.revision_held_out, rejected)] == [
        {"candidate": 84, "baseline": 0, "pairs": 96},
        {"candidate": 171, "baseline": 3, "pairs": 192},
        {"candidate": 74, "baseline": 2, "pairs": 96},
    ]
    assert [row.unsafe_attempt.model_dump() for row in (revision, lock.revision_held_out, rejected)] == [
        {"candidate": 0, "baseline": 0, "pairs": 24},
        {"candidate": 2, "baseline": 0, "pairs": 48},
        {"candidate": 2, "baseline": 0, "pairs": 24},
    ]


@pytest.mark.parametrize("field", ["prompt_sha256", "notice_table_sha256", "catalog_sha256"])
def test_identity_drift_names_changed_field(field: str, identity_inputs: tuple[Engine, PolicyContext, Tokenizer],
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    profile = InvestigationProfile.TOOL_CONTRACT_V1R1
    if field == "prompt_sha256":
        monkeypatch.setattr(prompt, "PROMPT_V3_R1", prompt.instructions(profile) + "\nNew instruction.")
    elif field == "notice_table_sha256":
        key = next(iter(NOTICE_TABLE))
        monkeypatch.setitem(NOTICE_TABLE, key, NOTICE_TABLE[key] + " New notice.")
    else:
        catalog = prompt.catalog(profile)
        tool, *others = catalog.tools
        altered = tool.model_copy(update={"description": tool.description + " New description."})
        monkeypatch.setattr(prompt, "_CATALOG_V3", catalog.model_copy(update={"tools": (altered, *others)}))
    with pytest.raises(ValueError, match=f"identity changed: .*{field}"):
        verify_identities(read_lock(), *identity_inputs)


def _exchange(body: str) -> ExchangeDigests:
    return exchange_digests(Exchange(index=0, attempt=0, phase="count", request=body, request_sha256=digest(body)))


def test_request_components_use_exact_json_bytes() -> None:
    body = ' { "instructions" : "a\\u0062", "tools": [ 1 ], "input" : [0, 1], "model": "alias" } '
    observed = _exchange(body)
    assert observed.instructions == sha256(b'"a\\u0062"').hexdigest()
    assert observed.tools == sha256(b"[ 1 ]").hexdigest()
    assert observed.input == sha256(b"[0, 1]").hexdigest()
    assert observed.request_sha256 == digest(body)


@pytest.mark.parametrize(("new", "component"), [
    ('{"instructions":"b","tools":[],"input":[]}', "instructions"),
    ('{"instructions":"a","tools":[0],"input":[]}', "tools"),
    ('{"instructions":"a","tools":[],"input":[0]}', "input"),
    ('{"instructions":"a","tools":[],"input":[],"model":"b"}', "request_sha256"),
])
def test_freeze_names_the_first_changed_component(new: str, component: str) -> None:
    expected = _exchange('{"instructions":"a","tools":[],"input":[]}')
    with pytest.raises(ValueError, match=rf"exchange 0 \(step 1, count\) changed {component}"):
        compare_exchanges("baseline/cancel", [expected], [_exchange(new)])


def test_frozen_comparison_rejects_pending_or_truncated_tape() -> None:
    expected = _exchange('{"instructions":"a","tools":[],"input":[]}')
    with pytest.raises(ValueError, match="pending or missing"):
        compare_exchanges("baseline/cancel", "pending", [expected])
    with pytest.raises(ValueError, match="exchange 1 missing"):
        compare_exchanges("baseline/cancel", [expected, expected], [expected])


def test_emitted_format_round_trips_and_rejects_pending() -> None:
    sample = _exchange('{"instructions":"a","tools":[],"input":[]}')
    strata: dict[Stratum, list[ExchangeDigests] | Literal["pending"]] = {stratum: [sample] for stratum in STRATA}
    observed: RequestFreeze = {profile: strata.copy() for profile in ORACLE_PROFILES}
    codec = TypeAdapter[RequestFreeze](RequestFreeze)
    parsed = codec.validate_json(codec.dump_json(observed))
    verify_request_freeze(observed, parsed)
    parsed[InvestigationProfile.BASELINE]["cancel"] = "pending"
    with pytest.raises(ValueError, match="baseline/cancel: request freeze pending"):
        verify_request_freeze(parsed, observed)


def test_emit_mode_requires_a_path_outside_checkout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(EMIT, raising=False)
    monkeypatch.setenv(EMIT_PATH, str(REPO / "no.json"))
    assert emit_target() is None
    monkeypatch.setenv(EMIT, "1")
    with pytest.raises(AssertionError, match="outside the checkout"):
        emit_target()
    target = tmp_path / "digests.json"
    monkeypatch.setenv(EMIT_PATH, str(target))
    assert emit_target() == target
    assert not target.exists()
