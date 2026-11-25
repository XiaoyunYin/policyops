"""Drive the local investigation worker with a label-blind, offline provider."""

from argparse import ArgumentParser
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import json
import logging.config
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import time
from typing import Literal
from uuid import uuid4

import httpx
import httpx2

from policyops import telemetry
from policyops.api.serve import SERVE_LOG_CONFIG
from policyops.gateway.steps import StepResult
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers.tokenizer import Tokenizer, load
from policyops.runtime.investigation import InvestigationExecutor
from policyops.runtime.spec import RuntimeSpec
from policyops.settings import TelemetrySettings
from policyops_contracts.conversation import AgentToolCall
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail import WriteToolCall
from policyops_contracts.retail_service import OrderDetail, OrderOutput, UserOutput
from policyops_evals.retail_sim import bootstrap, fixture, migrate
from policyops_evals.scenarios.generator import REPO, verified_fixture
from policyops_evals.scenarios.grading import _tool_outputs
from policyops_evals.scenarios.n13_fixtures import Class, Status, Trial, _unambiguous_live_item, generate
from policyops_evals.scenarios.n15_monitor import CADENCE, FRESH_SECONDS, SLOT_DEADLINE
from policyops_evals.scenarios.n15_scorer import Capture, ScheduledSlot, Scorer, Windows
from policyops_evals.scenarios.recording import Tape, object_from, phase_of
from policyops_evals.scenarios.runtime import POLICY_CORPUS, CaseInput, Profile, Slot, load_policy, retail_store
from policyops_evals.scenarios.study import private_root
from policyops_testing.app_database import AppCluster
from policyops_testing.postgres import owned_postgres
from policyops_testing.retrieval_fixtures import World


type Fault = Literal["wrong_target", "abstain", "malformed"]
type Reply = tuple[str, dict[str, object] | str]
FAULTS: tuple[Fault, ...] = ("wrong_target", "abstain", "malformed")
LOOKUP = "find_user_id_by_email"
PROFILE = "get_user_details"
READ = "get_order_details"
CANCEL = "cancel_pending_order"
RETURN = "return_delivered_order_items"
ABSTAIN: Reply = ("finish_answer", {"v": "policyops.grounded-answer/v1", "outcome": "abstain", "assertions": [],
                                    "abstention": {"reason": "insufficient_evidence", "detail": None}})
EMAIL = re.compile(r"My account email is (\S+)\. ")
STATED = re.compile(r"\border (#W[0-9]+)\b")
ITEM = re.compile(r"Please return the (.+?) from (?:order #W[0-9]+|my order) to my original payment method\.")


def fixture_cycle(raw: bytes, order: int) -> tuple[Trial, ...]:
    panel = generate(raw)
    retail = verified_fixture(raw)
    used = {trial.scenario.world.customer_id for trial in panel.live}
    groups: tuple[tuple[Status, Class], ...] = (
        ("pending", "B1"), ("delivered", "B2"), ("delivered", "B1"), ("pending", "B2"),
        ("pending" if order % 2 == 0 else "delivered", "A"),
    )
    chosen: list[Trial] = []
    for status, group in groups:
        candidates = [rows[0] for rows in panel.pools[status, group]
                      if rows[0].scenario.world.customer_id not in used
                      and 2 <= len(rows[0].scenario.world.order_closure) <= 4
                      and (group == "A" or _unambiguous_live_item(retail, rows[0]))]
        trial = candidates[order]
        chosen.append(trial)
        used.add(trial.scenario.world.customer_id)
    positives = chosen[:4]
    return (*positives[order:], *positives[:order], chosen[-1])


def healthy_reply(body: bytes) -> tuple[Reply, tuple[str, ...]]:
    request = object_from(body)
    opener = next(item["content"][0]["text"] for item in request["input"]
                  if item.get("type") == "message" and item.get("role") == "user")
    outputs = [(name, object_from(encoded)) for name, encoded in _tool_outputs(request)]
    if not outputs:
        email = EMAIL.search(opener)
        return (((LOOKUP, {"email": email[1]}) if email else ABSTAIN), ())
    if any(name in {CANCEL, RETURN} for name, _ in outputs):
        return ABSTAIN, ()
    identity = next((data.get("user_id") for name, data in outputs
                     if name == LOOKUP and data.get("outcome") == "authenticated"), None)
    if not isinstance(identity, str) or any(data.get("kind") == "error" for _, data in outputs):
        return ABSTAIN, ()
    user_data = next((data["output"] for name, data in outputs if name == PROFILE), None)
    if user_data is None:
        return (PROFILE, {"user_id": identity}), ()
    order_ids = UserOutput.model_validate_json(json.dumps(user_data)).user.order_ids
    orders: dict[str, OrderDetail] = {}
    for tool, data in outputs:
        if tool == READ:
            order = OrderOutput.model_validate_json(json.dumps(data["output"])).order
            orders[order.order_id] = order
    if missing := sorted(set(order_ids) - orders.keys()):
        return (READ, {"order_id": missing[0]}), ()
    cancel = "Please cancel " in opener
    status = "pending" if cancel else "delivered"
    stated = STATED.search(opener)
    eligible = [order for order in orders.values() if order.status == status
                and (stated is None or order.order_id == stated[1])]
    if len(eligible) != 1:
        return ABSTAIN, ()
    target = eligible[0]
    siblings = tuple(sorted(set(order_ids) - {target.order_id}))
    if cancel and "because I no longer need it." in opener:
        return (CANCEL, {"order_id": target.order_id, "reason": "no longer needed"}), siblings
    item = ITEM.search(opener)
    payment = [record.payment_method_id for record in target.payment_history if record.transaction_type == "payment"]
    if item and len(payment) == 1:
        matches = [row.item_id for row in target.items if row.name == item[1]]
        if matches and len(set(matches)) == 1:
            return (RETURN, {"order_id": target.order_id, "item_ids": matches[:1],
                             "payment_method_id": payment[0]}), siblings
    return ABSTAIN, ()


def model_reply(body: bytes, fault: Fault | None) -> Reply:
    (tool, args), siblings = healthy_reply(body)
    if tool not in {CANCEL, RETURN} or fault is None:
        return tool, args
    if fault == "abstain":
        return ABSTAIN
    if fault == "malformed":
        return tool, "{"
    if not siblings or not isinstance(args, dict):
        raise ValueError("wrong-target fault needs a visible sibling")
    return tool, args | {"order_id": siblings[0]}


class ScriptedAgent:
    def __init__(self, tokenizer: Tokenizer, response_prefix: str, fault: Fault | None) -> None:
        self.tokenizer, self.prefix, self.fault = tokenizer, response_prefix, fault
        self.tokens = self.turn = 0

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if phase_of(request) == "count":
            self.tokens = len(self.tokenizer.encoding.encode_ordinary(request.content.decode()))
            return httpx2.Response(200, json={"object": "response.input_tokens", "input_tokens": self.tokens})
        tool, args = model_reply(request.content, self.fault)
        self.turn += 1
        return httpx2.Response(200, json={
            "id": f"resp_{self.prefix}_{self.turn}", "object": "response", "created_at": 1, "status": "completed",
            "model": "gpt-6-luna", "service_tier": "default",
            "output": [{"type": "function_call", "name": tool, "call_id": f"call_{self.turn}",
                        "arguments": args if isinstance(args, str) else json.dumps(args)}],
            "usage": {"input_tokens": self.tokens,
                      "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                      "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8},
                      "total_tokens": self.tokens + 40},
        })


def run_slot(profile: Profile, slot: Slot, visible: CaseInput, fault: Fault | None) -> Capture:
    tape = Tape()
    writes: dict[str, StepResult] = {}

    def observe(call: AgentToolCall, result: StepResult) -> None:
        writes.setdefault(call.call_id, result)

    def bind(spec: RuntimeSpec) -> RuntimeSpec:
        if not isinstance(spec.executor, InvestigationExecutor):
            raise TypeError("expected the real investigation executor")
        return replace(spec, executor=replace(spec.executor, observe_write=observe))

    stop = None
    try:
        stop = profile.run_local_capture(visible, slot, tape,
                                         ScriptedAgent(profile.tokenizer, slot.id.hex, fault), bind_spec=bind)
    except Exception as error:
        # Never print exception messages from the provider, simulator or database.
        print(json.dumps({"canary_worker_error": type(error).__name__}), flush=True)
    presented: tuple[WriteToolCall, ...] | None = None
    try:
        with workspace_transaction(profile.app, slot.workspace) as connection:
            rows = repo.presented_rows_of_run(connection, slot.run)
            found = [repo.get_proposal(connection, row.proposal_id, row.proposal_version) for row in rows]
            if all(proposal is not None for proposal in found):
                presented = tuple(proposal.action for proposal in found if proposal is not None)
    except Exception as error:
        print(json.dumps({"canary_db_error": type(error).__name__}), flush=True)
    return Capture(tuple(tape.records), stop, writes, presented)


@contextmanager
def owned_profile(scratch: Path, tree: Path) -> Iterator[tuple[Profile, World]]:
    with owned_postgres(scratch, uuid4().hex[:12]) as postgres:
        db = AppCluster.provision(postgres).create_database("canary")
        try:
            db.upgrade()
            for role in bootstrap.ROLES:
                if role not in postgres.passwords:
                    postgres.register_role(role)
            with postgres.connect("postgres", db.name, autocommit=True) as connection:
                bootstrap.provision(connection, db.name, {role: postgres.passwords[role] for role in bootstrap.ROLES})
            with db.engine(bootstrap.MIGRATOR).connect() as connection:
                migrate.upgrade(connection)
            staged = scratch / "retail"
            fixture.stage(tree, staged)
            policy = tree / RETAIL_POLICY.path
            world = World(db, scratch)
            world.publish({"policy": policy.read_bytes()}, key=POLICY_CORPUS, domain="retail", render="identity")
            yield Profile(db.engine(APP_RUNTIME), db.engine(AUTH_RUNTIME),
                          retail_store(db.engine(bootstrap.RUNTIME), staged), load_policy(policy), load()), world
        finally:
            db.dispose()


def prom_query(client: httpx.Client, expression: str) -> list[float]:
    response = client.get("/api/datasources/proxy/uid/prometheus/api/v1/query", params={"query": expression})
    response.raise_for_status()
    return [float(row["value"][1]) for row in response.json()["data"]["result"]]


def demonstrate(profile: Profile, world: World, client: httpx.Client, fault: Fault) -> None:
    """Observe an actual Prometheus fire, valid clear, and stale health signal in one run."""
    cycle = fixture_cycle(profile.retail.fixture.raw, 0)
    phases = (25, 30, 30)
    slots = [Slot(world.ws, uuid4()) for _ in range(sum(phases))]
    cases = [cycle[index % len(cycle)] for index in range(len(slots))]
    visible = [CaseInput(case.scenario.world.customer_id, case.scenario.visible.message) for case in cases]
    epoch, origin = time.time(), time.monotonic()
    plan = [ScheduledSlot(slot.id, case.admitted, epoch + index * CADENCE,
                          epoch + index * CADENCE + SLOT_DEADLINE)
            for index, (slot, case) in enumerate(zip(slots, cases, strict=True))]
    scorer = Scorer({slot.id: case.scenario.gold for slot, case in zip(slots, cases, strict=True)})
    window = Windows(plan)
    window.snapshot().publish()
    quality = 'ALERTS{alertname="CanaryProposalQualityLow",alertstate="firing"}'
    blind = 'ALERTS{alertname="CanaryMonitorBlind",alertstate="firing"}'
    fresh = 'policyops_canary_last_finalized_timestamp_seconds{job="policyops-canary"}'
    baseline = fire = clear = False
    cursor = 0
    pending: Future[tuple[float, Capture]] | None = None
    pending_slot: Slot | None = None

    def clock() -> float:
        return epoch + time.monotonic() - origin

    def capture(slot: Slot, case: CaseInput, injected: Fault | None) -> tuple[float, Capture]:
        result = run_slot(profile, slot, case, injected)
        return clock(), result

    with ThreadPoolExecutor(max_workers=1) as worker:
        while (now := clock()) < plan[-1].due + SLOT_DEADLINE + FRESH_SECONDS + 45:
            if pending is not None and pending.done() and pending_slot is not None:
                finished, observed = pending.result()
                window.finalize(pending_slot.id, scorer.score(pending_slot.id, observed), finished)
                pending = pending_slot = None
            window.expire(now)
            if cursor < len(plan) and plan[cursor].due <= now:
                if pending is None and now < plan[cursor].deadline:
                    injected = fault if phases[0] <= cursor < sum(phases[:2]) else None
                    pending_slot = slots[cursor]
                    pending = worker.submit(capture, pending_slot, visible[cursor], injected)
                cursor += 1
            snapshot = window.snapshot()
            snapshot.publish()
            # Verify that the Prometheus rule is evaluating a sample from this run before awarding a clear.
            fresh_valid = bool(prom_query(client, f"({fresh} >= {epoch}) and (time() - {fresh} <= {FRESH_SECONDS})"))
            firing = bool(prom_query(client, quality))
            is_blind = bool(prom_query(client, blind))
            valid_clear = bool(prom_query(client, "policyops:canary_exact_rate >= 0.75"))
            if cursor <= phases[0] and not firing and not is_blind and fresh_valid and valid_clear:
                baseline = True
            if (baseline and phases[0] < cursor <= sum(phases[:2]) and firing and fresh_valid and not fire):
                fire = True
                print(json.dumps({"event": "fire", "seconds": round(now - epoch, 2),
                                  "delay_seconds": round(now - plan[phases[0]].due, 2)}), flush=True)
            if (cursor > sum(phases[:2]) and fire and not firing and not is_blind
                    and fresh_valid and valid_clear and not clear):
                clear = True
                print(json.dumps({"event": "clear", "seconds": round(now - epoch, 2),
                                  "delay_seconds": round(now - plan[sum(phases[:2])].due, 2)}), flush=True)
            if clear and is_blind and not fresh_valid and cursor == len(plan):
                print(json.dumps({"event": "blind", "seconds": round(now - epoch, 2)}), flush=True)
                return
            time.sleep(1)
    raise RuntimeError("Prometheus did not demonstrate fire, valid clear and blind")


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", required=True, type=Path)
    parser.add_argument("--fault", choices=FAULTS, default="wrong_target")
    parser.add_argument("--grafana-port", type=int, default=3000)
    parser.add_argument("--otlp-port", type=int, default=4318)
    args = parser.parse_args()
    try:
        if os.environ.get("POLICYOPS_ENV") != "local":
            raise ValueError("local canaries require POLICYOPS_ENV=local")
        temp = private_root(Path(os.environ["POLICYOPS_TEMP_DIR"]))
        if temp.is_relative_to(REPO) or not 1 <= args.grafana_port <= 65535 or not 1 <= args.otlp_port <= 65535:
            raise ValueError("canary needs an external temp root and valid loopback ports")
        otlp = f"http://127.0.0.1:{args.otlp_port}"
        logging.config.dictConfig(SERVE_LOG_CONFIG)
        backend = telemetry.configure(TelemetrySettings(enabled=True, exporter="otlp", traces_url=otlp + "/v1/traces",
                                                         metrics_url=otlp + "/v1/metrics"), role="canary")
        if backend is None:
            raise RuntimeError("canary telemetry was not configured")
        try:
            with (TemporaryDirectory(prefix="n15-", dir=temp) as scratch,
                  owned_profile(Path(scratch), args.fixture_root) as (profile, world),
                  httpx.Client(base_url=f"http://127.0.0.1:{args.grafana_port}", timeout=2,
                               trust_env=False, follow_redirects=False) as client):
                demonstrate(profile, world, client, args.fault)
        finally:
            backend.close()
    except Exception as error:
        print(json.dumps({"error": type(error).__name__}), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
