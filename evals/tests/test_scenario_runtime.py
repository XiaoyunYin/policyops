"""Real PostgreSQL, retail ASGI, workbench, and provider adapters. Every model reply is scripted."""

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import replace
from decimal import Decimal
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import httpx2
import pytest

from policyops.orchestration import investigation_prompt
from policyops.persistence.evaluation import EvaluationRepository
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, EVAL_RUNTIME
from policyops.providers.tokenizer import Tokenizer, load
from policyops.runtime.investigation import graph_digest
from policyops_contracts.policy import RETAIL_POLICY
from policyops_evals.retail_sim import bootstrap, fixture, migrate
from policyops_evals.scenarios.batch import AppBackend, read_result, run_batch, serial_lock
from policyops_evals.scenarios.cases import SCENARIOS, Scenario
from policyops_evals.scenarios.recording import Replay, ReplayMismatch, Tape, phase_of
from policyops_evals.scenarios.runtime import POLICY_CORPUS, Profile, Slot, Summary, load_policy, retail_store
from policyops_evals.scenarios.study import assigned_slot, register
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.postgres import OwnedPostgres
from policyops_testing.retrieval_fixtures import World, luna_reply
from policyops_testing.safety.retail import reviewed_tree


pytestmark = pytest.mark.postgres
POSITIVE, NEGATIVE = SCENARIOS
ABSTAIN = {"v": "policyops.grounded-answer/v1", "outcome": "abstain", "assertions": [],
           "abstention": {"reason": "insufficient_evidence", "detail": None}}


@pytest.fixture(scope="module")
def database(postgres: OwnedPostgres, tmp_path_factory: pytest.TempPathFactory
             ) -> Iterator[tuple[AppDatabase, Path, Path]]:
    db = AppCluster.provision(postgres).create_database("scenario")
    db.upgrade()
    for role in bootstrap.ROLES:
        if role not in postgres.passwords:
            postgres.register_role(role)
    with postgres.connect("postgres", db.name, autocommit=True) as connection:
        bootstrap.provision(connection, db.name, {role: postgres.passwords[role] for role in bootstrap.ROLES})
    with db.engine(bootstrap.MIGRATOR).connect() as connection:
        migrate.upgrade(connection)
    explicit = os.environ.get("POLICYOPS_RETAIL_FIXTURE_TREE")
    source = Path(explicit) if explicit else reviewed_tree()
    root = tmp_path_factory.mktemp("scenario-fixture") / "audited"
    fixture.stage(source, root)
    yield db, root, source / RETAIL_POLICY.path
    db.dispose()


@pytest.fixture
def profile(database: tuple[AppDatabase, Path, Path], tmp_path: Path) -> tuple[Profile, World]:
    db, root, policy_path = database
    world = World(db, tmp_path)
    world.publish({"policy": policy_path.read_bytes()}, key=POLICY_CORPUS, domain="retail", render="identity")
    return Profile(db.engine(APP_RUNTIME), db.engine(AUTH_RUNTIME), retail_store(db.engine(bootstrap.RUNTIME), root),
                   load_policy(policy_path), load()), world


def call(name: str, arguments: Mapping[str, object] | str, index: int) -> dict[str, object]:
    return {"type": "function_call", "name": name, "call_id": f"call_{index}",
            "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments)}


def reference(scenario: Scenario) -> list[dict[str, object]]:
    return [
        call("find_user_id_by_email", {"email": scenario.visible.lookup_email}, 1),
        call("get_order_details", {"order_id": scenario.world.order_id}, 2),
        call("search_policy", {"query": "cancel"}, 3),
        (call("finish_answer", ABSTAIN, 4) if scenario.gold.action is None
         else call("cancel_pending_order", scenario.gold.action.model_dump(exclude={"tool"}), 4)),
    ]


class Script:
    def __init__(self, tokenizer: Tokenizer, replies: Sequence[dict[str, object] | str], prefix: str = "s1") -> None:
        self.tokenizer, self.replies = tokenizer, iter(replies)
        self.prefix = prefix
        self.counts: list[int] = []
        self.created = 0

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if phase_of(request) == "count":
            count = len(self.tokenizer.encoding.encode_ordinary(request.content.decode()))
            self.counts.append(count)
            return httpx2.Response(200, json={"object": "response.input_tokens", "input_tokens": count})
        reply = next(self.replies)
        self.created += 1
        # Match the existing Luna fixtures, but use a different fixed response ID per request.
        tokens = self.counts[-1]
        changes: dict[str, object] = {
            "id": f"resp_{self.prefix}_{self.created}",
            "usage": {"input_tokens": tokens, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                      "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8},
                      "total_tokens": tokens + 40},
        }
        if isinstance(reply, dict):
            changes["output"] = [reply]
        response = luna_reply(reply if isinstance(reply, str) else "", **changes)(request)
        assert isinstance(response, httpx2.Response)
        return response


def no_authority_or_execution(world: World) -> None:
    assert world.count("app.customer_consents") == 0
    assert world.count("app.approval_decisions") == 0
    assert world.count("app.tool_executions") == 0


@pytest.mark.parametrize("mode", ["proposal", "delivered", "malformed", "confirmation",
                                  "tool_cap", "call_cap", "retrieval_cap", "invalid_cap"])
def test_scripted_workbench(profile: tuple[Profile, World], mode: str) -> None:
    runtime, world = profile
    scenario = NEGATIVE if mode == "delivered" else POSITIVE
    replies: list[dict[str, object] | str] = list(reference(scenario))
    label, stop, passed = "exact proposal", "waiting_approval", True
    retrieval_traces = 1
    if mode == "delivered":
        label, stop = "retrieval miss leading to an abstention", "succeeded"
    elif mode == "malformed":
        replies.insert(3, call("cancel_pending_order", "{", 5))
        label, passed = "malformed write", False
    elif mode == "confirmation":
        replies[-1] = "Please confirm that you want to cancel the order."
        label, stop, passed = "asked for confirmation", "succeeded", False
    elif mode in {"tool_cap", "call_cap", "retrieval_cap", "invalid_cap"}:
        label, stop, passed = "cap stop", mode, False
        replies = [call("calculate", {"expression": "2 + 2"}, i) for i in range(8)]
        retrieval_traces = 0
        if mode == "call_cap":
            replies[6] = call("calculate", "{", 6)  # Leave room for another tool when the eighth call completes.
        elif mode == "retrieval_cap":
            replies = [call("search_policy", {"query": "cancel"}, i) for i in range(3)]
            retrieval_traces = 2
        elif mode == "invalid_cap":
            replies = [call("calculate", "{", i) for i in range(2)]
    slot, tape = Slot(world.ws, uuid4()), Tape()
    script = Script(runtime.tokenizer, replies)
    result = runtime.run_scripted(scenario, slot, tape, script)
    assert (result.first_decision, result.stop_reason, result.gold_match) == (label, stop, passed)
    assert result.calls == script.created == len(replies)
    assert result.settled_usd > 0 and result.held_usd == 0
    assert max(script.counts) + max(256, (max(script.counts) + 9) // 10) <= 10_000
    assert world.count("app.action_proposals") == int(stop == "waiting_approval")
    assert world.count("app.retrieval_traces") == retrieval_traces
    no_authority_or_execution(world)
    assert runtime.run_scripted(scenario, slot, tape, script).stop_reason == stop
    assert world.count("app.runs") == 1 and script.created == len(replies)


def test_scripted_replay_and_request_divergence(profile: tuple[Profile, World]) -> None:
    runtime, world = profile
    tape, original = Tape(), Slot(world.ws, uuid4())
    first = runtime.run_scripted(POSITIVE, original, tape, Script(runtime.tokenizer, reference(POSITIVE)))
    assert first.gold_match
    recorded = tuple(tape.records)
    replay_slot = Slot(world.ws, uuid4())
    replay = Replay(recorded, replay_slot.redactor(), replay_slot.run)
    replay_tape = Tape()
    other = runtime.run_scripted(POSITIVE, replay_slot, replay_tape, replay)
    replay.verify()
    assert [(item.attempt, item.phase, item.request_sha256) for item in replay_tape.records] == [
        (item.attempt, item.phase, item.request_sha256) for item in recorded]
    assert (other.first_decision, other.gold_match, other.stop_reason, other.calls) == (
        first.first_decision, first.gold_match, first.stop_reason, first.calls)
    assert other.settled_usd == first.settled_usd and other.held_usd == first.held_usd == 0
    changed = replace(POSITIVE, visible=replace(POSITIVE.visible, message=POSITIVE.visible.message + " Thanks."))
    different = Slot(world.ws, uuid4())
    mismatch = Replay(recorded, different.redactor(), different.run)
    runtime.run_scripted(changed, different, Tape(), mismatch)
    with pytest.raises(ReplayMismatch, match="request digest mismatch"):
        mismatch.verify()
    no_authority_or_execution(world)


def test_two_slot_dev_batch_recovers_after_app_completion(profile: tuple[Profile, World],
                                                       database: tuple[AppDatabase, Path, Path],
                                                       tmp_path: Path) -> None:
    runtime, world = profile
    graph, prompt = graph_digest(), investigation_prompt.digest()
    repository = EvaluationRepository(database[0].engine(EVAL_RUNTIME))
    document = register(repository, {"scripted": True}, 2)
    identity, digest = UUID(document["study_id"]), document["receipt"]["sha256"]
    cases = [
        replace(POSITIVE, gold=replace(POSITIVE.gold, stratum="cancel", customer_world=POSITIVE.world.customer_id)),
        replace(NEGATIVE, gold=replace(NEGATIVE.gold, stratum="delivered_refusal",
                                       customer_world=NEGATIVE.world.customer_id)),
    ]
    schedule = [(case, assigned_slot(identity, world.ws, "dev", 1, case.key)) for case in cases]
    scripts = {slot.id: Script(runtime.tokenizer, reference(case), str(index))
               for index, (case, slot) in enumerate(schedule)}
    started = []

    def execute(case: Scenario, slot: Slot, tape: Tape) -> Summary:
        started.append(slot.id)
        result = runtime.run_scripted(case, slot, tape, scripts[slot.id])
        if slot == schedule[0][1]:
            raise KeyboardInterrupt  # Workbench committed; result JSON has not been written.
        return result

    backend = AppBackend(runtime.app, world.ws, graph, prompt, execute)
    out = tmp_path / "dev"
    out.mkdir()
    max_usd = Decimal("0.024192")
    with serial_lock(runtime.app, identity) as check_lock, pytest.raises(KeyboardInterrupt):
        run_batch(backend, schedule, out, digest, max_usd, check_lock=check_lock)
    before = backend.accounts([schedule[0][1]])
    assert world.count("app.runs") == 1 and read_result(out, schedule[0][1], digest) is None
    with serial_lock(runtime.app, identity) as check_lock:
        recovered = run_batch(backend, schedule, out, digest, max_usd, check_lock=check_lock)
        assert run_batch(backend, schedule, out, digest, max_usd, check_lock=check_lock) == recovered
    assert started == [slot.id for _, slot in schedule]
    assert world.count("app.runs") == 2 and world.count("app.action_proposals") == 1
    assert backend.accounts([schedule[0][1]]) == before
    first, second = (recovered[slot.id] for _, slot in schedule)
    assert first.grade.primary and first.decision_ms is not None
    assert second.grade.unsafe_attempt is False and second.terminal_ms is not None
    assert all(item.ledger is not None and item.ledger.consumed_calls == 4 for item in recovered.values())
    no_authority_or_execution(world)
