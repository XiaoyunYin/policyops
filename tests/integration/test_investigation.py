"""T21 worker/executor/graph on real PostgreSQL; all customer/provider data is synthetic.

Boundary crash injections abandon the invocation and reclaim its lease; a separate case kills a real worker
process. None proves a hard SQL deadline. No Docker execution is attempted at collection.
"""

import asyncio
from dataclasses import dataclass, replace
from datetime import timedelta
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import ChannelVersions, Checkpoint, CheckpointMetadata
import pytest

from policyops.budget.config import Configuration
from policyops.domain.examples import World as RetailWorld
from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.state import InvestigationState
from policyops.persistence import repositories as repo
from policyops.persistence import runs
from policyops.persistence.checkpoints import InvestigationSaver
from policyops.persistence.database import workspace_transaction
from policyops.persistence.records import NewCase
from policyops.runtime import investigation as runtime
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.investigation import InvestigationExecutor, build_investigation_spec
from policyops.runtime.spec import AwaitingApproval, Failed, InvestigationCompleted, RuntimeCatalog, RuntimeSpec
from policyops.runtime.worker import Context, Worker
from policyops.services.proposals import ProposalService
from policyops_contracts.clock import FixedClock
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.retrieval import RetrievalConfig, RetrievalScope
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding
from policyops_testing import case_api
from policyops_testing.agent_fakes import ScriptedModel, calls, fictional_policy, says
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.case_api import START, CaseApi
from policyops_testing.gateway_cases import EMAIL, FakeRetail
from policyops_testing.gateway_cases import state as retail_state
from policyops_testing.retrieval_fixtures import TOKENIZER, Embeddings, World, documents


pytestmark = pytest.mark.postgres
TEXT = "Refunds go back to the original payment method within ten days."
ANSWER = {"v": "policyops.grounded-answer/v1", "outcome": "answer", "abstention": None,
          "assertions": [{"text": "Refunds take ten days.", "policy_dependent": False,
                          "citations": [{"step": 0, "evidence_id": "E1", "quote": TEXT,
                                         "start": None, "end": None}]}]}
ABSTAIN = {"v": "policyops.grounded-answer/v1", "outcome": "abstain", "assertions": [],
           "abstention": {"reason": "insufficient_evidence", "detail": None}}


class SimulatedCrash(BaseException):
    """Abandon an invocation without LangGraph reinterpreting node cancellation."""


@dataclass
class Scenario:
    api: CaseApi
    world: World
    spec: RuntimeSpec
    catalog: RuntimeCatalog
    model: ScriptedModel
    worker: Worker
    run_id: UUID
    case_id: UUID
    retail: FakeRetail

    @property
    def executor(self) -> InvestigationExecutor:
        assert isinstance(self.spec.executor, InvestigationExecutor)
        return self.spec.executor

    def claim(self) -> Context:
        candidates = self.worker.discover()
        assert len(candidates) == 1
        claimed = self.worker.claim(*candidates[0])
        assert claimed is not None
        token, case, spec = claimed
        return Context(self.worker, token, case, spec)

    def state(self) -> str:
        return str(self.api.scalar("SELECT state FROM app.runs WHERE id = %s", self.run_id))

    def agent_messages(self) -> int:
        return int(self.api.scalar("SELECT count(*) FROM app.case_messages WHERE case_id = %s AND source = 'agent'",
                                   self.case_id))

    def saver(self, context: Context) -> InvestigationSaver:
        return InvestigationSaver(engine=self.world.engine,
                                   scope=RunScope(workspace_id=context.workspace_id, case_id=context.case_id,
                                                   run_id=context.run_id),
                                   token=context.claim_token, graph_sha256=self.spec.graph_sha256,
                                   prompt_sha256=self.spec.prompt_sha256, config_sha256=self.spec.config_sha256,
                                   clock=self.executor.clock)

@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("investigation")


def scenario(db: AppDatabase, path: Path, mode: str = "answer", *, max_steps: int = 32) -> Scenario:
    world = World(db, path)
    world.publish(documents([("refunds", "Refund policy", TEXT)]))
    case = uuid4()
    with workspace_transaction(world.engine, world.ws) as connection:
        repo.create_case(connection, NewCase(id=case, workspace_id=world.ws, scenario="retail",
                                             customer_user_id=RetailWorld().user_id, created_by=None, created_at=START))
        repo.append_message(connection, message_id=uuid4(), scope=CaseScope(workspace_id=world.ws, case_id=case),
                            source="seeded", entered_by=None, text_value="Please help with my refund.",
                            created_at=START)
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=world.ws, case_id=case), seed_id="retail-demo-9999",
                                  user_id=RetailWorld().user_id, bound_at=START)
    script = ([calls("search_policy", {"query": "refunds"}), calls(prompt.FINISH, ANSWER)] if mode == "answer" else
              [calls("find_user_id_by_email", {"email": EMAIL}),
               calls("cancel_pending_order", {"order_id": RetailWorld().order_id, "reason": "no longer needed"})]
              if mode == "proposal" else [says("Uncited policy prose.")])
    model = ScriptedModel(list(script))
    retail = FakeRetail(retail_state(), tenant_id=world.ws, case_id=case)
    clock = FixedClock(START)
    spec = build_investigation_spec(env="test", engine=world.engine, configuration=Configuration(),
                                    policy=fictional_policy(),
                                    retrieval_scope=RetrievalScope(corpus_key="test-banking"),
                                    retrieval_config=RetrievalConfig(mode="lexical"), bindings=(binding,),
                                    fixture_sha256=FIXTURE_SHA256, retail=lambda scope: retail,
                                    providers=Embeddings().providers(), tokenizer=TOKENIZER,
                                    clock=FixedLeaseClock(clock), wall_clock=clock, max_steps=max_steps,
                                    test_model=lambda ledger, run: model)
    catalog = RuntimeCatalog.of([spec], default=spec.spec_id)
    api = case_api.build(db, catalog=catalog)
    # API and executor share the controlled lease clock, including reclaim/deadline observations.
    assert isinstance(spec.executor, InvestigationExecutor)
    api.clock = clock
    browser = api.member(f"investigator-{uuid4().hex}", world.ws, "analyst")
    started = api.start_run(browser, case, '"1"')
    assert started.status_code == 202
    return Scenario(api, world, spec, catalog, model, api.worker(catalog), UUID(started.json()["run_id"]), case, retail)


@pytest.mark.parametrize("mode,expected", [("answer", "succeeded"), ("abstain", "succeeded"),
                                           ("proposal", "waiting_approval")])
def test_worker_graph_terminal_paths(db: AppDatabase, tmp_path: Path, mode: str, expected: str) -> None:
    test = scenario(db, tmp_path, mode)
    assert test.worker.run_once() == 1
    assert test.state() == expected and test.agent_messages() == 1
    assert test.api.scalar("SELECT count(*) FROM app.run_events WHERE run_id = %s "
                           "AND event_type = 'case.message_posted'", test.run_id) == 1
    if mode == "answer":
        assert test.world.count("app.retrieval_traces") == 1
        text = test.api.scalar("SELECT text FROM app.case_messages WHERE case_id = %s AND source = 'agent'",
                               test.case_id)
        assert "Refunds take ten days. [" in text
    elif mode == "abstain":
        assert test.world.count("app.citations") == 0
    else:
        assert test.world.count("app.action_proposals") == 1
        assert test.world.count("app.proposal_presentations") == 1
        assert test.world.count("app.customer_consents") == 0


def test_final_message_lost_commit_acknowledgement_reconciles_without_reexecution(
        db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy.engine import RootTransaction

    from policyops.persistence.database import TransactionOutcomeUnknown

    test = scenario(db, tmp_path, "abstain")
    context = test.claim()
    outcome = test.executor.execute(context)
    commit = RootTransaction.commit

    def lose_ack(tx: RootTransaction) -> None:
        commit(tx)
        raise OSError("synthetic lost acknowledgement")

    with monkeypatch.context() as faults:
        faults.setattr(RootTransaction, "commit", lose_ack)
        with pytest.raises(TransactionOutcomeUnknown):
            test.worker.finish(context.claim_token, outcome)
    before = len(test.model.requests)
    assert not test.worker.process(context.claim_token.job_id, context.workspace_id)
    assert len(test.model.requests) == before and test.agent_messages() == 1 and test.state() == "succeeded"


@pytest.mark.parametrize("boundary", ["checkpoint", "proposal_commit", "terminal"])
def test_crash_reclaim_resumes_without_duplicate_proposal_or_message(
        db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str) -> None:
    test = scenario(db, tmp_path, "proposal")
    first = test.claim()
    original = InvestigationSaver.aput
    fired = False

    class CrashSaver(InvestigationSaver):
        async def aput(self, config: RunnableConfig, checkpoint: Checkpoint, metadata: CheckpointMetadata,
                       new_versions: ChannelVersions) -> RunnableConfig:
            nonlocal fired
            state = checkpoint["channel_values"].get("state")
            crash = (state is not None and not fired and
                     ((boundary == "checkpoint" and state["step_count"] == 2) or
                      (boundary in {"proposal_commit", "terminal"} and state["terminal"] is not None)))
            result = await original(self, config, checkpoint, metadata, new_versions)
            if crash and boundary != "proposal_commit":
                fired = True
                raise SimulatedCrash
            return result

    monkeypatch.setattr(runtime, "InvestigationSaver", CrashSaver)
    create_once = ProposalService.create_once
    def lost_preparation(*args: Any, **kwargs: Any) -> Any:
        nonlocal fired
        result = create_once(*args, **kwargs)
        if boundary == "proposal_commit" and not fired:
            fired = True
            raise SimulatedCrash
        return result
    monkeypatch.setattr(ProposalService, "create_once", lost_preparation)
    with pytest.raises(SimulatedCrash):
        test.executor.execute(first)
    assert fired
    calls_before = len(test.model.keys)
    retail_before = len(test.retail.calls)
    stale = test.saver(first)
    test.api.clock.advance(timedelta(minutes=1))
    second = test.claim()
    with pytest.raises(runs.Fenced):
        saved = asyncio.run(stale.aget_tuple(stale.config()))
        assert saved is not None
        asyncio.run(stale.aput(stale.config(), saved.checkpoint, saved.metadata, {}))
    monkeypatch.setattr(runtime, "InvestigationSaver", InvestigationSaver)
    monkeypatch.setattr(ProposalService, "create_once", create_once)
    # Rebuilding the executor discards every invocation-local adapter/session object.
    final = replace(test.executor).execute(second)
    assert isinstance(final, AwaitingApproval)
    test.worker.finish(second.claim_token, final)
    assert test.state() == "waiting_approval" and test.agent_messages() == 1
    assert test.world.count("app.action_proposals") == test.world.count("app.proposal_presentations") == 1
    assert len(test.model.keys) == (2 if boundary == "checkpoint" else calls_before)
    if boundary == "proposal_commit":
        assert len(test.retail.calls) == retail_before  # replay never recollects mutable facts


def test_terminal_checkpoint_short_circuits_then_finish_is_atomic(
        db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    test = scenario(db, tmp_path, "abstain")
    first = test.claim()
    terminal = test.executor.execute(first)
    assert isinstance(terminal, InvestigationCompleted)
    assert test.agent_messages() == 0
    test.api.clock.advance(timedelta(minutes=1))
    second = test.claim()
    # This path must not construct a provider, retriever or retail client.
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("terminal short-circuit performed fresh work")
    monkeypatch.setattr(runtime, "Retriever", forbidden)
    repeated = replace(test.executor, retail=forbidden).execute(second)
    assert repeated == terminal and len(test.model.keys) == 1
    end_job = runs.end_job
    monkeypatch.setattr(runs, "end_job", forbidden)
    with pytest.raises(AssertionError):
        test.worker.finish(second.claim_token, repeated)
    assert test.agent_messages() == 0 and test.state() == "running"
    monkeypatch.setattr(runs, "end_job", end_job)
    test.worker.finish(second.claim_token, repeated)
    test.worker.finish(second.claim_token, repeated)  # fenced; no second message/event
    assert test.agent_messages() == 1 and test.state() == "succeeded"


def test_executor_rejects_foreign_tenant_checkpoint_path(db: AppDatabase, tmp_path: Path) -> None:
    test = scenario(db, tmp_path, "abstain")
    context = test.claim()
    assert isinstance(test.executor.execute(context), InvestigationCompleted)
    snapshots = test.world.count("checkpoints.snapshots")
    assert snapshots > 0
    other = scenario(db, tmp_path / "other", "abstain")
    other_context = other.claim()
    foreign = replace(other_context.claim_token, run_id=context.run_id)
    rebound = Context(test.worker, foreign, context.case_id, context.spec)
    with pytest.raises(runs.Fenced):
        test.executor.execute(rebound)
    assert len(test.model.keys) == 1 and not other.model.keys
    assert test.world.count("checkpoints.snapshots") == snapshots
    assert other.world.count("checkpoints.snapshots") == 0


def test_forged_or_uncited_policy_answer_abstains(db: AppDatabase, tmp_path: Path) -> None:
    test = scenario(db, tmp_path, "answer")
    forged = json.loads(json.dumps(ANSWER))
    forged["assertions"][0]["citations"].append({"step": 0, "evidence_id": "E1", "quote": "Not delivered.",
                                               "start": None, "end": None})
    test.model.script[-1] = calls(prompt.FINISH, forged)
    assert test.worker.run_once() == 1 and test.state() == "succeeded"
    text = test.api.scalar("SELECT text FROM app.case_messages WHERE case_id = %s AND source = 'agent'", test.case_id)
    from policyops.orchestration.graph import ABSTENTION
    assert text == ABSTENTION


def test_persisted_step_ceiling_is_typed_failure(db: AppDatabase, tmp_path: Path) -> None:
    test = scenario(db, tmp_path, "answer", max_steps=1)
    assert test.worker.run_once() == 1 and test.state() == "failed"
    payload = test.api.scalar("SELECT payload->>'rule_id' FROM app.run_events WHERE run_id = %s "
                              "AND event_type = 'error.raised'", test.run_id)
    assert payload == "investigation.loop_ceiling"
    assert len(test.model.keys) == 1 and test.world.count("app.retrieval_traces") == 0


def test_os_killed_graph_worker_resumes_checkpoint(db: AppDatabase, tmp_path: Path) -> None:
    from policyops_testing import investigation_process, worker_process

    test = scenario(db, tmp_path, "abstain")
    process = investigation_process.start(db, test.executor)
    try:
        worker_process.wait_until_claimed(process, timeout=60)
        assert test.state() == "running"
        process.kill()
    finally:
        worker_process.stop(process)
    test.api.clock.advance(timedelta(minutes=1))
    context = test.claim()
    saver = test.saver(context)
    saved = asyncio.run(saver.aget_tuple(saver.config()))
    assert saved is not None
    state = InvestigationState.model_validate_json(json.dumps(saved.checkpoint["channel_values"]["state"]))
    assert state.step_count == 2 and state.model_calls == 1 and state.pending_tool is None
    final = test.executor.execute(context)
    assert isinstance(final, InvestigationCompleted)
    test.worker.finish(context.claim_token, final)
    assert test.state() == "succeeded" and test.agent_messages() == 1
    assert not test.retail.calls  # the checkpointed calculation was not reissued


def test_lost_billed_provider_result_keeps_key_and_never_redispatches(
        db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.budget.ledger import RunBinding
    from policyops.orchestration.ports import agent_model_port
    from policyops.providers.calls import CallReport
    from policyops_testing.retrieval_fixtures import Scripted, count_reply, luna_reply

    test = scenario(db, tmp_path, "abstain")
    context = test.claim()
    transport = Scripted(counts=[count_reply(900)], creates=[luna_reply("Lost model response.")])
    keys: list[UUID] = []

    class LoseResult:
        def __init__(self, ledger: Any) -> None:
            self.port = agent_model_port(ledger, RunBinding(test.run_id), transport.providers())

        async def complete(self, request: Any, *, key: UUID, operation: str, deadline: float) -> CallReport:
            keys.append(key)
            returned = await self.port.complete(request, key=key, operation=operation, deadline=deadline)
            if len(keys) == 1:
                assert returned.status == "result"
                raise SimulatedCrash
            return returned

    executor = replace(test.executor, test_model=lambda ledger, run: LoseResult(ledger))
    with pytest.raises(SimulatedCrash):
        executor.execute(context)
    test.api.clock.advance(timedelta(minutes=1))
    second = test.claim()
    final = executor.execute(second)
    assert isinstance(final, Failed) and final.rule_id == "investigation.provider_result_unavailable"
    assert len(keys) == 2 and keys[0] == keys[1]
    assert transport.kinds("create") == transport.kinds("count") == 1


@pytest.mark.parametrize("phase", ["count", "create"])
def test_composed_provider_cancellation_retains_liability_and_cleans_client(
        db: AppDatabase, tmp_path: Path, phase: str) -> None:
    from policyops_testing.retrieval_fixtures import Scripted, count_reply, luna_reply, slow

    test = scenario(db, tmp_path, "abstain")
    context = test.claim()

    async def exercise() -> None:
        entered = asyncio.Event()
        class Transport(Scripted):
            closed = False
            async def aclose(self) -> None:
                self.closed = True

        transport = Transport(counts=[slow(count_reply(900), 60, entered) if phase == "count" else count_reply(900)],
                              creates=[slow(luna_reply("never returned"), 60, entered)])
        executor = replace(test.executor, test_model=None, providers=transport.providers())
        task = asyncio.create_task(executor._execute(context))
        try:
            await asyncio.wait_for(entered.wait(), 10)
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 10)
        assert transport.closed
        assert transport.kinds("create") == (1 if phase == "create" else 0)
        states = test.api.rows("SELECT state FROM app.usage_attempts WHERE workspace_id = %s "
                               "AND operation_id LIKE 'agent.step%%'", test.world.ws)
        assert states == [("unresolved" if phase == "create" else "released",)]
        assert test.agent_messages() == 0 and test.state() == "running"

    asyncio.run(exercise())


def test_executor_rejects_old_checkpoint_version_without_fresh_work(db: AppDatabase, tmp_path: Path) -> None:
    test = scenario(db, tmp_path, "abstain")
    context = test.claim()
    assert isinstance(test.executor.execute(context), InvestigationCompleted)
    with db.superuser() as connection:
        connection.execute("UPDATE checkpoints.snapshots SET state_version = 0 WHERE workspace_id = %s",
                           (test.world.ws,))
    final = test.executor.execute(context)
    assert isinstance(final, Failed) and final.rule_id == "investigation.checkpoint_incompatible"
    assert len(test.model.keys) == 1 and test.agent_messages() == 0


def test_executor_maps_recursion_guard_to_persisted_failure(
        db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.orchestration.graph import InvestigationGraph

    test = scenario(db, tmp_path, "answer")
    compile_graph = InvestigationGraph.compile
    def limited_compile(*args: Any, **kwargs: Any) -> Any:
        compiled = compile_graph(*args, **kwargs)
        invoke = compiled.ainvoke
        async def limited(input: Any, config: Any, **options: Any) -> Any:
            return await invoke(input, config | {"recursion_limit": 1}, **options)
        monkeypatch.setattr(compiled, "ainvoke", limited)
        return compiled
    monkeypatch.setattr(InvestigationGraph, "compile", limited_compile)
    context = test.claim()
    result = test.executor.execute(context)
    assert isinstance(result, Failed) and result.rule_id == "investigation.loop_ceiling"
    saved = asyncio.run(test.saver(context).aget_tuple(test.saver(context).config()))
    assert saved is not None and saved.checkpoint["channel_values"]["state"]["terminal"]["kind"] == "loop_ceiling"
    async def updates() -> list[Any]:
        saver = test.saver(context)
        return [item async for item in saver.alist(saver.config(), filter={"source": "update"})]
    assert len(asyncio.run(updates())) == 1
    test.worker.finish(context.claim_token, result)
    assert test.state() == "failed" and len(test.model.keys) == 1


def test_budget_terminal_uses_budget_exceeded_run_state(db: AppDatabase, tmp_path: Path) -> None:
    from policyops.providers.calls import CallReport
    test = scenario(db, tmp_path, "abstain")
    test.model.script[:] = [CallReport(None, "budget", "cap")]
    assert test.worker.run_once() == 1 and test.state() == "budget_exceeded" and test.agent_messages() == 0


def test_owned_heartbeat_cancels_graph_and_preserves_fence_loss(db: AppDatabase, tmp_path: Path) -> None:
    test = scenario(db, tmp_path, "abstain")
    context = test.claim()
    async def exercise() -> None:
        cleaned = asyncio.Event()
        async def waiting(request: Any) -> Any:
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()
        test.model.script[:] = [waiting]
        context.heartbeat = lambda: False  # type: ignore[method-assign]
        with pytest.raises(runs.Fenced, match="heartbeat_lost"):
            await asyncio.wait_for(replace(test.executor, lease=timedelta(seconds=1))._execute(context), 10)
        assert cleaned.is_set()
    asyncio.run(exercise())
    assert test.state() == "running" and test.agent_messages() == 0
