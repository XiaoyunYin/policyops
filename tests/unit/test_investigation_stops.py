"""Stops authorize no later work, while the last permitted answer can finalize deterministically."""

import asyncio
import time
from typing import Any, cast
from uuid import uuid4

import pytest

from policyops.orchestration.graph import GraphEnvelope
from policyops.orchestration.state import InvestigationStopped, state_from_json
from policyops.orchestration.stops import InvestigationStop, stop_reason, stop_text
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.calls import AttemptRecord, CallReport
from policyops.providers.embedding_calls import BatchReport, JobReport
from policyops.retrieval.search import Retriever, _Unavailable
from policyops.runtime.investigation import InvestigationExecutor
from policyops.runtime.spec import StepContext, Stopped
from policyops_contracts.conversation import AgentLimits
from policyops_contracts.stops import StopDetails, StopReason
from policyops_testing.agent_fakes import ScriptedModel, calls
from tests.unit.test_investigation_graph import ABSTAIN, RecordingSaver, graph, initial, run


@pytest.mark.parametrize("reason", list(StopReason))
def test_each_closed_reason_and_no_later_steps(reason: StopReason) -> None:
    model = ScriptedModel([])
    build, actions = graph(model)
    build.resource_stop = lambda: reason
    envelope = GraphEnvelope.model_validate({"state": initial().model_dump(mode="json")})
    output = asyncio.run(build.node("investigate", envelope))
    terminal = output["state"]["terminal"]
    assert terminal["kind"] == "stopped" and terminal["details"]["reason"] == reason.value
    assert not model.keys and not actions.nodes


@pytest.mark.parametrize("reason,expected", [("usd_cap", "usd_cap"), ("call_cap", "call_cap"),
    ("count_cap", "count_cap"), ("count_rejected", "input_tokens"), ("count_not_admitted", "input_tokens"),
    ("blocked_by_overrun", "overrun"), ("blocked_by_contract", "contract_block")])
def test_provider_stop_reasons_survive(reason: str, expected: str) -> None:
    state, actions = run(ScriptedModel([CallReport(None, "budget", reason)]))
    assert isinstance(state.terminal, InvestigationStopped) and state.terminal.details.reason.value == expected
    assert not actions.nodes


def test_last_call_finalizes_but_no_tool_is_dispatched_after_cap() -> None:
    state, actions = run(ScriptedModel([calls("finish_answer", ABSTAIN)]), limits=AgentLimits(model_calls=1))
    assert state.terminal is not None and state.terminal.kind == "abstained"
    assert actions.nodes == ["finalize"]
    state, actions = run(ScriptedModel([calls("calculate", {"expression": "1"})]), limits=AgentLimits(model_calls=1))
    assert isinstance(state.terminal, InvestigationStopped) and state.terminal.details.reason == StopReason.CALL_CAP
    assert not actions.nodes


def test_tool_cap_stops_before_selected_action() -> None:
    model = ScriptedModel([calls("calculate", {"expression": "1"})])
    state, actions = run(model, initial(tool_steps=8))
    assert isinstance(state.terminal, InvestigationStopped) and state.terminal.details.reason == StopReason.TOOL_CAP
    assert not actions.nodes


def test_usage_unconfirmed_report_stays_reachable_and_message_is_truthful(monkeypatch: pytest.MonkeyPatch) -> None:
    report = CallReport(None, "failed", "accounting_unconfirmed", [AttemptRecord(uuid4(), "op", None)])

    async def execute(self: InvestigationExecutor, context: StepContext) -> Any:
        raise AccountingUnconfirmed(report)

    monkeypatch.setattr(InvestigationExecutor, "_execute", execute)
    outcome = object.__new__(InvestigationExecutor).execute(cast(StepContext, None))
    assert isinstance(outcome, Stopped) and outcome.report is report
    text = stop_text(outcome.details)
    assert "unconfirmed" in text and "reserved cost remains held" in text and "No further actions will run" in text
    assert "zero" not in text.lower() and "resume" not in text.lower()


@pytest.mark.parametrize("reason", ["usd_cap", "call_cap", "count_cap", "blocked_by_contract", "blocked_by_overrun"])
def test_embedding_budget_stops_investigation_but_standalone_fallback_is_explicit(reason: str) -> None:
    retriever = object.__new__(Retriever)
    retriever.stop_on_budget = True
    report = JobReport(uuid4(), "budget", reason)
    with pytest.raises(InvestigationStop) as error:
        retriever._interpret(report)
    assert error.value.details.reason == stop_reason(reason)
    retriever.stop_on_budget = False
    with pytest.raises(_Unavailable) as unavailable:
        retriever._interpret(report)
    assert unavailable.value.reason == "budget"


def test_stop_text_and_failure_classification_are_bounded() -> None:
    for reason in StopReason:
        details = StopDetails(reason=reason, usage_unconfirmed=reason == StopReason.USAGE_UNCONFIRMED)
        assert len(stop_text(details)) < 500
        assert details.failed == (reason in {StopReason.CONTEXT_LIMIT, StopReason.CONTRACT_BLOCK,
                                            StopReason.USAGE_UNCONFIRMED})


def test_accounting_failure_checkpoints_stop_and_keeps_report_until_finish() -> None:
    report = CallReport(None, "failed", "accounting_unconfirmed", [AttemptRecord(
        uuid4(), "op", None, cleanup_confirmed=False)])

    async def fail(request: Any) -> Any:
        raise AccountingUnconfirmed(report)

    async def execute() -> None:
        from langchain_core.runnables import RunnableConfig

        saver = RecordingSaver()
        config: RunnableConfig = {"configurable": {"thread_id": "accounting"}}
        first, actions = graph(ScriptedModel([fail]))
        result = await first.compile(saver).ainvoke({"state": initial().model_dump(mode="json")}, config,
                                                   durability="sync")
        state = state_from_json(result["state"])
        assert isinstance(state.terminal, InvestigationStopped)
        assert state.terminal.details.usage_unconfirmed and state.terminal.details.cleanup_unconfirmed
        assert first.accounting is not None and first.accounting.report is report
        model = ScriptedModel([])
        restarted, _ = graph(model)
        resumed = await restarted.compile(saver).ainvoke(None, config, durability="sync")
        assert resumed["state"] == result["state"] and not model.keys and not actions.nodes

    asyncio.run(execute())


@pytest.mark.parametrize("status", ["incomplete", "deadline"])
def test_embedding_unknown_usage_cannot_become_a_fallback_or_plain_deadline(status: Any) -> None:
    retriever = object.__new__(Retriever)
    retriever.stop_on_budget = True
    report = JobReport(uuid4(), status, "transport", [BatchReport(
        0, "sent", "unresolved", physical_request=True, cleanup_confirmed=False)])
    with pytest.raises(InvestigationStop) as error:
        retriever._interpret(report)
    assert error.value.details.usage_unconfirmed and error.value.details.cleanup_unconfirmed


@pytest.mark.parametrize("mode", ["retry", "repair"])
def test_retry_and_repair_share_the_cap_and_preserve_uncertainty(mode: str) -> None:
    from policyops.budget.ledger import BudgetExhausted, Reserved, RunBinding
    from policyops.providers.calls import CallLimits, call
    from policyops_testing.retrieval_fixtures import Scripted, count_reply, luna_reply, openai_json
    from tests.unit.test_provider_call_grants import REQUEST, Books

    class Capped(Books):
        def reserve(self, *args: Any, **kwargs: Any) -> Reserved:
            if self.log.count("begin_dispatch") == 1:
                raise BudgetExhausted("run", "call_cap")
            return super().reserve(*args, **kwargs)

    books = Capped()
    response = (openai_json({"error": {"type": "rate_limit_error"}}, 429) if mode == "retry" else
                luna_reply('{"decision":"invalid"}'))
    transport = Scripted(counts=[count_reply(1200)], creates=[response])
    report = asyncio.run(call(cast(Any, books), transport.providers()(), RunBinding(uuid4()), uuid4(), "cap", REQUEST,
                              "agent", deadline=time.monotonic() + 30,
                              limits=CallLimits(retries_per_request=1, repairs=1, backoff_seconds=0)))
    assert transport.seen == ["count", "create"] and report.status == "budget"
    state, actions = run(ScriptedModel([report]))
    assert isinstance(state.terminal, InvestigationStopped)
    assert state.terminal.details.reason == StopReason.CALL_CAP
    assert state.terminal.details.usage_unconfirmed == (mode == "retry")
    assert not actions.nodes
