"""Scripted controls for offline diagnosis, clause support and cache economics."""

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from policyops.domain.examples import World
from policyops.domain.retail_rules import propose
from policyops.providers.tool_diagnostics import NOTICE_TABLE
from policyops.services.run_reads import EvidenceView
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.proposal import ActionProposal, EvidenceRef
from policyops_contracts.retail import CancelPendingOrder, ToolName
from policyops_evals.scenarios import Refused
from policyops_evals.scenarios.arms import Arm
from policyops_evals.scenarios.batch import Result
from policyops_evals.scenarios.cases import Gold
from policyops_evals.scenarios.generator import _spans
from policyops_evals.scenarios.grading import grade_slot
from policyops_evals.scenarios.n7_report import Usage
from policyops_evals.scenarios.n18_cache import Tokens, fixed_workload
from policyops_evals.scenarios.n18_diagnosis import diagnose, read_sequence
from policyops_evals.scenarios.n18_evidence import exchanges
from policyops_evals.scenarios.proposal_grading import grade_proposal_clauses
from policyops_evals.scenarios.recording import MAX_EXCHANGES, Exchange

from .scenario_support import pinned_tree
from .test_scenario_grading import (
    ARGS,
    CANCEL_TOOL,
    HANDOFF,
    POSITIVE,
    REFUSAL,
    _call,
    _delivered,
    _exchange,
    _finish,
    _message,
    _observation,
    _reads,
)


def _result(gold: Gold, tape: list[Exchange], stop: str = "succeeded") -> Result:
    return Result(slot_id=uuid4(), run_id=uuid4(), registration_sha256="a" * 64,
                  recorded_at=datetime(2026, 11, 27, tzinfo=UTC), status="finalized",
                  ledger=None, grade=grade_slot(gold, tape, stop=stop), stop_reason=stop)


def test_invalid_cap_attributes_first_rejection_in_terminal_streak() -> None:
    notice = NOTICE_TABLE[(ToolName.GET_ORDER_DETAILS, "order_id", "pattern")]
    item: dict[str, object] = {"role": "user", "content": [{"type": "input_text", "text": notice}]}
    wrong = _call("get_order_details", {"order_id": "not-the-wire-id"})
    tape = [_exchange(_call("find_user_id_by_email", {}), history=[]), _exchange(wrong, index=1, history=_reads()[:2]),
            _exchange(wrong, index=2, history=[*_reads()[:2], item])]
    finding = diagnose(POSITIVE, _result(POSITIVE, tape, "invalid_cap"), tape)
    assert (finding.mechanism, finding.exchange, finding.constraint) == ("argument rejected: order_id", 1, "pattern")


def test_diagnosis_quotes_prose_and_transfer() -> None:
    tape = [_exchange(_finish(quote={"step": 0, "evidence_id": "E1", "quote": "Words absent from the chunk.",
                                     "start": None, "end": None}),
                      history=[*_reads("delivered"), *_delivered()])]
    assert diagnose(REFUSAL, _result(REFUSAL, tape), tape).mechanism == "finish failed quote validation"
    tape = [_exchange(_message("There is no action."))]
    assert diagnose(POSITIVE, _result(POSITIVE, tape), tape).mechanism == "prose reply with no tool call"
    tape = [_exchange(_call("transfer_to_human_agents", {"summary": "Needs a human."})),
            _exchange(_message("I will send a summary."), index=1)]
    assert diagnose(HANDOFF, _result(HANDOFF, tape, "invalid_cap"), tape).mechanism == (
        "transfer missing required follow-up"
    )


def test_sequence_deduplicates_history_and_ignores_reads_after_first_proposal() -> None:
    tape = [_exchange(_call("search_policy", {"query": "cancel"}), history=_reads()),
            _exchange(_call(CANCEL_TOOL, ARGS), index=1, history=[*_reads(), *_delivered()]),
            _exchange(_message("Done."), index=2, history=[*_reads(), *_delivered(),
                                                          *_observation("get_user_details", {})])]
    assert read_sequence(tape) == ("find_user_id_by_email", "get_order_details", "search_policy")


def test_tape_reader_bounds_file_count(tmp_path: Path) -> None:
    for index in range(MAX_EXCHANGES + 1):
        (tmp_path / f"{index:02}.json").touch()
    with pytest.raises(Refused, match="exchange limit"):
        exchanges(tmp_path, _result(POSITIVE, []))


@pytest.mark.parametrize("mode", ["supporting", "wrong clause", "partial", "wrong digest"])
def test_required_clause_uses_only_the_persisted_quote(mode: str) -> None:
    policy = (pinned_tree() / RETAIL_POLICY.path).read_bytes().decode()
    spans = _spans(policy.encode())
    span = spans["cancel.pending_only"]
    wrong = spans["cancel.order_and_reason"]
    gold = replace(POSITIVE, policy_sha256=RETAIL_POLICY.sha256, clause_spans=(span,))
    world = World()
    ref = EvidenceRef(evidence_id=uuid4(), document_version_id=uuid4(), content_sha256=RETAIL_POLICY.sha256)
    proposal = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(),
                       call=CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                       facts=world.facts(), evidence=(ref,), rationale="Scripted control", now=world.now)
    assert isinstance(proposal, ActionProposal)
    quote = wrong if mode == "wrong clause" else span
    end = quote.start + len(quote.text) - int(mode == "partial")
    evidence = EvidenceView(citation_id=ref.evidence_id, scope=proposal.scope, document_id=uuid4(),
                            document_version_id=ref.document_version_id, version="1",
                            version_sha256=ref.content_sha256, source_uri="tau2:retail/policy", span_start=quote.start,
                            span_end=end, excerpt_start=span.start - 1, excerpt_end=end + 1,
                            text=policy[span.start - 1:end + 1], quote_sha256=("0" * 64 if mode == "wrong digest"
                                else sha256(policy[quote.start:end].encode()).hexdigest()))
    score = grade_proposal_clauses(gold, proposal, [evidence], policy)
    assert score is not None
    assert score.provenance is (mode != "wrong digest")
    assert score.supported is (mode == "supporting")


def test_cache_model_break_even_and_observed_reconciliation() -> None:
    tokens = Tokens.from_usage(Usage(150, 25, 90, 0, 40, 7), Arm.A1)
    figures = fixed_workload(tokens)
    assert tokens.usd_parts() == {"uncached_input": Decimal("0.0000035"), "reads": Decimal("0.00000025"),
                                  "writes_30m": Decimal("0.00001125"), "output": Decimal("0.000020")}
    assert figures["observed_read_share"] == figures["break_even_read_share"] == Decimal(25) / 115
    assert figures["observed_mix_usd"] == figures["modelled_bypass_usd"] == tokens.settled
    assert figures["modelled_all_hit_usd"] < tokens.settled < figures["modelled_all_cold_usd"]
    with pytest.raises(Refused, match="cache mode"):
        Tokens.from_usage(Usage(150, 25, 90, 0, 40, 7), Arm.A0)
