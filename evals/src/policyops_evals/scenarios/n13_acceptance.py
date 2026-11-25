"""Run a bounded model-to-receipt slice against the signed, loopback retail simulator."""

from argparse import ArgumentParser
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from datetime import timedelta
from decimal import Decimal
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
import secrets
import socket
from threading import Thread
import time
from typing import Literal
from uuid import UUID, uuid4, uuid5

import httpx2
from sqlalchemy import Engine, text
import uvicorn

from policyops import telemetry
from policyops.adapters.retail_client import RetailClient, Unknown
from policyops.auth.service import Authorized, SessionContext
from policyops.domain.roles import Role
from policyops.orchestration.profile import InvestigationProfile
from policyops.persistence import executions, runs
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import ExecutionRecord, Membership, Principal
from policyops.providers.tokenizer import Tokenizer
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.runtime.review import build_review_runtime
from policyops.runtime.spec import RuntimeCatalog
from policyops.runtime.worker import Worker
from policyops.services.cases import CaseService
from policyops.services.decisions import DecisionService
from policyops.services.proposal_views import DecisionRequest
from policyops.settings import TelemetrySettings
from policyops.telemetry.sdk import MemorySpans
from policyops_contracts.clock import SystemClock
from policyops_contracts.events import ConsentRecorded, EventEnvelope, ReviewOutcome, ReviewReason
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import CancelPendingOrder, GetOrderDetails
from policyops_contracts.retail_service import FIXTURE_SHA256, CaseState, OrderOutput
from policyops_evals.retail_sim.app import create_app
from policyops_evals.retail_sim.auth import Key
from policyops_evals.retail_sim.store import Store
from policyops_evals.scenarios.batch import serial_lock
from policyops_evals.scenarios.cases import Scenario
from policyops_evals.scenarios.cli import _credential, _operator_profile, _require_paid
from policyops_evals.scenarios.grading import grade_slot
from policyops_evals.scenarios.n13_fixtures import LIVE_SLOTS, SEED, Trial, generate
from policyops_evals.scenarios.recording import Tape, phase_of
from policyops_evals.scenarios.runtime import Profile, Slot, Summary, configuration, usage
from policyops_evals.scenarios.study import private_root


PROFILE = InvestigationProfile.TOOL_CONTRACT_V1R1
MAX_USD = Decimal("0.25")
type FailureCategory = Literal["gateway_refusal", "model_wrong_or_abstained", "cap_stop", "infrastructure"]
FAILURE_CATEGORIES: tuple[FailureCategory, ...] = (
    "gateway_refusal", "model_wrong_or_abstained", "cap_stop", "infrastructure",
)
TRACE_ATTRIBUTES = frozenset({"run_id", "proposal_id", "operation_id", "attempt", "generation", "outcome", "tool",
                              "provider", "model", "access", "error_code", "receipt_sha256", "input_tokens",
                              "output_tokens", "cost_micro_usd", "node", "kind"})


@dataclass(frozen=True)
class Endpoint:
    origin: str
    key: bytes

    @contextmanager
    def client(self, _store: Store, slot: Slot, scenario: Scenario) -> Iterator[RetailClient]:
        with closing(RetailClient(self.origin, self.key, tenant_id=slot.workspace, case_id=slot.case,
                                  customer_id=scenario.world.customer_id)) as client:
            if not isinstance(client.initialize(), CaseState):
                raise ValueError("retail initialization unavailable")
            yield client


@dataclass(frozen=True)
class Failure:
    category: FailureCategory
    reason: str


@contextmanager
def loopback(store: Store) -> Iterator[Endpoint]:
    key = secrets.token_bytes(32)
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(create_app(store, Key(key)), access_log=False,
                                               lifespan="off", log_level="critical", ws="none"))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started:
                if not thread.is_alive() or time.monotonic() >= deadline:
                    raise RuntimeError("retail loopback server did not start")
                time.sleep(0.02)
            yield Endpoint(f"http://127.0.0.1:{port}", key)
        finally:
            server.should_exit = True
            thread.join(10)
        if thread.is_alive():
            raise RuntimeError("retail loopback server did not stop")


def presented(runtime: Profile, slot: Slot) -> ActionProposal | None:
    with workspace_transaction(runtime.app, slot.workspace) as connection:
        rows = repo.presented_rows_of_run(connection, slot.run)
        if not rows:
            return None
        [row] = rows
        proposal = repo.get_proposal(connection, row.proposal_id, row.proposal_version)
        if proposal is None or row.creation_step is None:
            raise ValueError("invalid investigation proposal")
        return proposal


def assent_and_approve(runtime: Profile, slot: Slot, proposal: ActionProposal) -> None:
    wall, clock = SystemClock(), DatabaseLeaseClock()
    with workspace_transaction(runtime.app, slot.workspace) as connection:
        case = repo.get_case(connection, slot.case)
    if case is None:
        raise ValueError("approval case missing")
    operator = runtime._operator(slot, wall)
    reply = CaseService(runtime.app, wall, clock).post_message(
        operator, key=f"reply-{slot.id.hex}", case_id=slot.case, expected_version=case.version,
        source="operator_entered_customer", text_value="Yes, please.")
    with workspace_transaction(runtime.app, slot.workspace) as connection:
        consent = repo.get_consent(connection, proposal.proposal_id, proposal.proposal_version)
    if reply.status != 201 or consent is None or consent.customer_message_id != reply.message_id:
        raise ValueError("scripted customer consent was not recorded")
    reviewer, now = uuid4(), wall.now()
    with transaction(runtime.auth) as connection:
        repo.create_principal(connection, Principal(id=reviewer, issuer="https://reviewer.invalid",
                                                    subject=str(reviewer), display_name="Acceptance reviewer",
                                                    created_at=now))
        repo.add_membership(connection, Membership(id=uuid4(), workspace_id=slot.workspace,
                                                    principal_id=reviewer, role="reviewer", created_at=now))
    authorized = Authorized(SessionContext(uuid4(), reviewer, slot.workspace, now + timedelta(minutes=5),
                                           "0" * 64), slot.workspace, frozenset({Role.REVIEWER}))
    decision = DecisionService(runtime.app, clock).decide(authorized, proposal.proposal_id, DecisionRequest(
        proposal_version=proposal.proposal_version, action_digest=proposal.action_digest,
        decision="approve", reason="Checked the customer consent and policy."))
    if decision.replayed or decision.decision.principal_id != reviewer or consent.entered_by == reviewer:
        raise ValueError("distinct fresh reviewer approval was not recorded")


def _review_job(worker: Worker, slot: Slot, trigger: Literal["decision", "outcome"]) -> None:
    with workspace_transaction(worker.app_engine, slot.workspace) as connection:
        job_id = connection.execute(text("SELECT id FROM app.jobs WHERE run_id = :run AND review_trigger = :trigger"),
                                    {"run": slot.run, "trigger": trigger}).scalar_one()
    if not worker.process(job_id, slot.workspace):
        raise ValueError("review job was not processed")


def advance(runtime: Profile, endpoint: Endpoint, trial: Trial, slot: Slot, *,
            before_dispatch: Callable[[], None] | None = None) -> ExecutionRecord | None:
    """Drive only this run's decision, dispatch and outcome. The dispatcher delegates to the same Executor.step."""
    clock = DatabaseLeaseClock()
    binding = runtime._seed(trial.scenario, slot, clock)
    review = build_review_runtime(env="local", app_engine=runtime.app, bindings=(binding,),
                                  fixture_sha256=FIXTURE_SHA256, retail_origin=endpoint.origin,
                                  retail_key=endpoint.key, clock=clock)
    # The jobs are already known and scoped to this run, so there is no cross-workspace discovery pass.
    worker = Worker(runtime.app, runtime.app, clock, RuntimeCatalog.of([]), review=review)
    _review_job(worker, slot, "decision")
    with workspace_transaction(runtime.app, slot.workspace) as connection:
        rows = executions.case_executions(connection, slot.case)
        if not rows:
            return None
        [execution] = rows
    if before_dispatch is not None:
        before_dispatch()
    step = review.executor.step(slot.workspace, execution.id)
    if step.state in {"succeeded", "failed", "reconciled"}:
        _review_job(worker, slot, "outcome")
    with workspace_transaction(runtime.app, slot.workspace) as connection:
        return executions.get(connection, execution.id)


def case_effects(runtime: Profile, slot: Slot) -> int:
    with transaction(runtime.retail.engine) as connection:
        connection.execute(text("SELECT set_config('retail.tenant_id', :tenant, true), "
                                "set_config('retail.case_id', :case, true)"),
                           {"tenant": str(slot.workspace), "case": str(slot.case)})
        return int(connection.execute(text("SELECT count(*) FROM retail.operations WHERE outcome = 'committed'"))
                   .scalar_one())


def verify_receipt(runtime: Profile, endpoint: Endpoint, trial: Trial, slot: Slot, proposal: ActionProposal,
                   execution: ExecutionRecord, *, effects: int = 1) -> str:
    receipt = execution.receipt
    if (execution.state != "succeeded" or receipt is None
            or (execution.proposal_id, execution.proposal_version, execution.request.call, receipt.actual_effect) != (
                proposal.proposal_id, proposal.proposal_version, trial.action, proposal.effect)):
        raise ValueError("execution receipt does not match the approved target and effect")
    digest = sha256(receipt.model_dump_json().encode()).hexdigest()
    with endpoint.client(runtime.retail, slot, trial.scenario) as client:
        operation = client.lookup(execution.operation_id, execution.request)
        order = client.read(GetOrderDetails(order_id=trial.action.order_id))
    expected = "cancelled" if isinstance(trial.action, CancelPendingOrder) else "return requested"
    if (isinstance(operation, Unknown) or operation.result is None or operation.result.receipt != receipt
            or isinstance(order, Unknown) or not isinstance(order.output, OrderOutput)
            or order.output.order.status != expected or case_effects(runtime, slot) != effects):
        raise ValueError("simulator receipt, target state or effect count did not verify")
    state, events = run_events(runtime.app, slot)
    if state != "succeeded" or not any(isinstance(event.payload, ReviewOutcome)
                                       and event.payload.receipt_sha256 == digest for event in events):
        raise ValueError("verified receipt was not delivered through the outcome worker")
    return digest


def run_events(engine: Engine, slot: Slot) -> tuple[str, tuple[EventEnvelope, ...]]:
    with workspace_transaction(engine, slot.workspace) as connection:
        run = runs.get_run(connection, slot.run)
        if run is None:
            return "missing", ()
        if run.event_highwater > 256:
            raise ValueError("acceptance event bound exceeded")
        events = runs.events_after(connection, run, 0, max(1, run.event_highwater))
        return run.state, tuple(event for event in events if isinstance(event, EventEnvelope))


def scripted(tokenizer: Tokenizer, trial: Trial, slot: Slot) -> Callable[[httpx2.Request], httpx2.Response]:
    """Provider-shaped replies that exercise the normal scenario path with zero paid calls."""
    case = trial.scenario
    replies: list[tuple[str, dict[str, object]]] = [
        ("find_user_id_by_email", {"email": case.visible.lookup_email}),
        ("get_user_details", {"user_id": case.world.customer_id}),
    ]
    reads = (case.world.order_closure if trial.admitted and case.gold.order_id_form == "absent"
             else (trial.action.order_id,))
    replies.extend(("get_order_details", {"order_id": oid}) for oid in reads)
    if len(reads) <= 3:
        query = "cancel order" if isinstance(trial.action, CancelPendingOrder) else "return item"
        replies.append(("search_policy", {"query": query}))
    replies.append((trial.action.tool, trial.action.model_dump(exclude={"tool"})))
    replies.append(("finish_answer", {"v": "policyops.grounded-answer/v1", "outcome": "abstain", "assertions": [],
                                      "abstention": {"reason": "insufficient_evidence", "detail": None}}))
    tokens = 0
    count = 0

    def respond(request: httpx2.Request) -> httpx2.Response:
        nonlocal tokens, count
        if phase_of(request) == "count":
            tokens = len(tokenizer.encoding.encode_ordinary(request.content.decode()))
            return httpx2.Response(200, json={"object": "response.input_tokens", "input_tokens": tokens})
        name, args = replies[count]
        count += 1
        return httpx2.Response(200, json={
            "id": f"resp_{slot.id.hex}_{count}", "object": "response", "created_at": 1, "status": "completed",
            "model": "gpt-6-luna", "service_tier": "default",
            "output": [{"type": "function_call", "name": name, "call_id": f"call_{count}",
                                                "arguments": json.dumps(args)}],
            "usage": {"input_tokens": tokens, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                      "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8},
                      "total_tokens": tokens + 40},
        })

    return respond


def preflight(trials: tuple[Trial, ...], maximum: Decimal) -> dict[str, object]:
    config = configuration()
    actor, caps = config.actors["agent"], config.caps
    worst = len(trials) * caps.run_usd
    if not maximum.is_finite() or not 0 < worst <= maximum <= MAX_USD or not 1 <= len(trials) <= LIVE_SLOTS:
        raise ValueError("acceptance USD cap does not cover the registered slots")
    return {"model": actor.model, "effort": "low", "cache_mode": "none", "profile": PROFILE,
            "fixture_sha256": FIXTURE_SHA256, "seed": SEED, "calls_per_slot": caps.run_calls,
            "input_per_call": caps.request_max_input, "output_per_call": caps.request_max_output,
            "seconds_per_slot": caps.active_seconds, "slots": len(trials), "worst_usd": worst, "max_usd": maximum,
            "cases": [trial.scenario.key for trial in trials]}


def _usage_tokens(engine: Engine, slot: Slot) -> dict[str, int]:
    with workspace_transaction(engine, slot.workspace) as connection:
        count, inputs, outputs = connection.execute(text(
            "SELECT count(*), coalesce(sum(uncached_input_tokens + cache_read_tokens + cache_write_tokens), 0), "
            "coalesce(sum(output_tokens), 0) FROM app.usage_events WHERE run_id = :run"
        ), {"run": slot.run}).one()
    return {"settled_events": int(count), "input_tokens": int(inputs), "output_tokens": int(outputs)}


def _emit(fields: dict[str, object], output: Path | None = None) -> None:
    line = json.dumps(fields, default=str, sort_keys=True)
    if output is not None:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
    print(line, flush=True)


def _investigation_failure(trial: Trial, summary: Summary, tape: Tape, *,
                           proposed: bool, gateway: object) -> Failure:
    if proposed:
        if not summary.gold_match:
            return Failure("model_wrong_or_abstained", summary.first_decision)
        return Failure("infrastructure", "presentation_without_waiting_approval")
    if summary.stop_reason == "waiting_approval":
        return Failure("infrastructure", "waiting_approval_without_presentation")
    grade = grade_slot(trial.scenario.gold, tape.records, stop=summary.stop_reason)
    if gateway == "error":
        return Failure("infrastructure", "gateway_write_unavailable")
    if gateway == "refused":
        return Failure("gateway_refusal", "gateway_write_refused")
    if grade.cap is not None:
        return Failure("cap_stop", grade.cap)
    if grade.failure == "provider failure" or summary.stop_reason.startswith("investigation."):
        return Failure("infrastructure", summary.stop_reason)
    if gateway == "completed":
        return Failure("gateway_refusal", "proposal_preparation_refused")
    return Failure("model_wrong_or_abstained", grade.failure or grade.decision)


def _complete(runtime: Profile, endpoint: Endpoint, trial: Trial, slot: Slot,
              proposal: ActionProposal) -> tuple[str | None, Failure | None]:
    if proposal.action != trial.action:
        return None, Failure("model_wrong_or_abstained", "presented_action_mismatch")
    phase = "consent_and_approval"
    try:
        assent_and_approve(runtime, slot, proposal)
        phase = "review_and_dispatch"
        execution = advance(runtime, endpoint, trial, slot)
        if execution is None:
            _, events = run_events(runtime.app, slot)
            if any(isinstance(event.payload, ReviewOutcome)
                   and event.payload.reason == ReviewReason.PRECHECK_REFUSED for event in events):
                return None, Failure("gateway_refusal", "reservation_precheck_refused")
            return None, Failure("infrastructure", "review_did_not_reserve_execution")
        if execution.outcome == "precheck_refused":
            return None, Failure("gateway_refusal", "dispatch_precheck_refused")
        phase = "receipt_verification"
        return verify_receipt(runtime, endpoint, trial, slot, proposal, execution), None
    except Exception as exc:
        return None, Failure("infrastructure", f"{phase}: {type(exc).__name__}")


def run(runtime: Profile, endpoint: Endpoint, workspace: UUID, trials: tuple[Trial, ...], *,
        maximum: Decimal, output: Path, credential: str | None = None, redactions: tuple[str, ...] = ()) -> int:
    registration = preflight(trials, maximum)
    study_id = uuid5(workspace, "policyops:n13/model-to-receipt/v1")
    slots = tuple(Slot(workspace, uuid5(study_id, trial.scenario.key)) for trial in trials)
    output = private_root(output)
    output.mkdir(parents=True, exist_ok=False)
    _emit(registration, output / "preflight.json")
    memory = MemorySpans()
    backend = telemetry.configure(TelemetrySettings(enabled=True, exporter="memory"), role="demo",
                                  span_exporter=memory)
    if backend is None:
        raise ValueError("acceptance trace was not configured")
    failures: Counter[FailureCategory] = Counter()
    verified = 0
    try:
        with serial_lock(runtime.app, study_id) as check:
            generation = runtime.corpus_generation(workspace)
            with workspace_transaction(runtime.app, workspace) as connection:
                if any(runs.get_run(connection, slot.run) is not None for slot in slots):
                    raise ValueError("a registered acceptance slot already has durable state")
            lock_lost = False
            for index, (trial, slot) in enumerate(zip(trials, slots, strict=True), start=1):
                tape = Tape()
                summary: Summary | None = None
                receipt_digest: str | None = None
                failure: Failure | None = None
                proposed = False
                phase = "batch_lock"
                with telemetry.span("investigation", run_id=slot.run):
                    trace = telemetry.correlation()["trace_id"]
                    try:
                        if lock_lost:
                            raise ValueError("batch lock already lost")
                        check()
                        phase = "budget_admission"
                        accounts = tuple(usage(runtime.app, item) for item in slots)
                        if any(row.blocked or row.held for row in accounts):
                            failure = Failure("infrastructure", "aggregate_usage_unreconciled")
                        elif sum(row.settled for row in accounts) + configuration().caps.run_usd > maximum:
                            failure = Failure("cap_stop", "aggregate_usd_cap")
                        else:
                            phase = "investigation"
                            if credential is None:
                                handler = scripted(runtime.tokenizer, trial, slot)
                                summary = runtime.run_scripted(trial.scenario, slot, tape, handler,
                                                               profile=PROFILE, retail_session=endpoint.client)
                            else:
                                tape = Tape(output / "private-provider" / str(index))
                                transport = partial(httpx2.AsyncHTTPTransport, trust_env=False, retries=0)
                                summary = runtime._run(
                                    trial.scenario, slot, tape, transport, env="local", credential=credential,
                                    redactor=slot.redactor((credential, *redactions)), expected_generation=generation,
                                    profile=PROFILE, retail_session=endpoint.client)
                            phase = "usage_reconciliation"
                            account = usage(runtime.app, slot)
                            if tape.write_failed or account.blocked or account.held:
                                raise ValueError("provider capture or usage did not reconcile")
                            phase = "presentation"
                            proposal = presented(runtime, slot)
                            proposed = proposal is not None
                            if (proposal is not None and summary.stop_reason == "waiting_approval"
                                    and summary.gold_match):
                                receipt_digest, failure = _complete(runtime, endpoint, trial, slot, proposal)
                    except Exception as exc:
                        # Driver, provider and database exceptions can carry private request text or credentials.
                        lock_lost = lock_lost or phase == "batch_lock"
                        failure = Failure("infrastructure", f"{phase}: {type(exc).__name__}")
                if not backend.flush(6):
                    failure = failure or Failure("infrastructure", "trace_flush_failed")
                state = "unavailable"
                events: tuple[EventEnvelope, ...] = ()
                accounting: dict[str, object] | None = None
                try:
                    state, events = run_events(runtime.app, slot)
                    accounting = asdict(usage(runtime.app, slot)) | _usage_tokens(runtime.app, slot)
                except Exception as exc:
                    failure = failure or Failure("infrastructure", f"reporting: {type(exc).__name__}")
                finished = [span for span in memory.get_finished_spans() if span.context is not None
                            and f"{span.context.trace_id:032x}" == trace]
                if failure is None and receipt_digest is None:
                    if summary is not None:
                        gateway = next((attrs.get("outcome") for span in reversed(finished)
                                        if span.name == "gateway.step" and (attrs := span.attributes)
                                        and attrs.get("access") == "write"), None)
                        failure = _investigation_failure(trial, summary, tape, proposed=proposed, gateway=gateway)
                    else:
                        failure = Failure("infrastructure", "missing_investigation_summary")
                spans = [{"name": span.name, "start_ns": span.start_time, "end_ns": span.end_time,
                          "span_id": f"{span.context.span_id:016x}",
                          "parent_id": f"{span.parent.span_id:016x}" if span.parent else None,
                          "attributes": {k: v for k, v in (span.attributes or {}).items() if k in TRACE_ATTRIBUTES}}
                         for span in finished if span.context is not None]
                if failure is None:
                    verified += 1
                else:
                    failures[failure.category] += 1
                _emit({"attempt": index, "case": trial.scenario.key, "run": slot.run, "trace": trace,
                       "scripted_assent": any(isinstance(event.payload, ConsentRecorded) for event in events),
                       "paid": credential is not None,
                       "investigation": asdict(summary) if summary is not None else None,
                       "usage": accounting,
                       "state": state, "events": [{"sequence": event.sequence, "type": event.payload.type,
                                                    "at": event.occurred_at} for event in events], "spans": spans,
                       "receipt_sha256": receipt_digest, "failure": asdict(failure) if failure else None},
                      output / f"attempt-{index}.json")
            _emit({"verified_receipts": verified, "registered_slots": len(slots),
                   "failures": {category: failures[category] for category in FAILURE_CATEGORIES}},
                  output / "summary.json")
            return verified
    finally:
        backend.close()


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--scripted", action="store_true")
    mode.add_argument("--allow-paid", action="store_true")
    parser.add_argument("--max-usd", type=Decimal, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--policy-file", type=Path)
    parser.add_argument("--dsn-file", type=Path)
    parser.add_argument("--workspace", type=UUID)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    from policyops_evals.retail_sim.fixture import DB_PATH

    try:
        panel = generate((args.fixture_root / DB_PATH).read_bytes())
        if args.preflight:
            _emit(preflight(panel.live, args.max_usd))
            return 0
        if any(value is None for value in (args.policy_file, args.dsn_file, args.workspace, args.out)):
            parser.error("run modes require --policy-file, --dsn-file, --workspace and --out")
        credential = None
        if args.allow_paid:
            _require_paid(True)
            credential = _credential()
        with _operator_profile(args) as (runtime, redactions), loopback(runtime.retail) as endpoint:
            verified = run(runtime, endpoint, args.workspace, panel.live, maximum=args.max_usd,
                           output=args.out, credential=credential, redactions=redactions)
            return int(verified < (1 if args.allow_paid else len(panel.live)))
    except Exception as exc:
        _emit({"error": type(exc).__name__})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
