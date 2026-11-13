"""The paired recovery runner. Effects are observed independently of either arm."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, contextmanager, nullcontext
from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import json
import threading
from typing import Any, cast
from uuid import UUID

import httpx

from policyops.adapters.retail_client import Refused, RetailClient, Unknown
from policyops.gateway.ports import GatewayScope
from policyops.persistence.records import ExecutionRecord
from policyops.services.execution import ExecutionHooks, Reserved
from policyops_contracts.retail import Effect, ModifyPendingOrderAddress, WriteToolCall
from policyops_contracts.retail_service import MutationRequest, OperationResult, Receipt
from policyops_testing.safety.config import Arm, Config, Pair, canonical
from policyops_testing.safety.environment import (
    CANCEL,
    DELIVERED,
    DELIVERED_CUSTOMER,
    RETURN,
    Env,
    cleared_request,
    due,
    ledger_record,
    study_case,
)
from policyops_testing.safety.reply_gate import ReplyGate
from policyops_testing.safety.reports import Change, State, Trial, changes


class ProcessCrash(BaseException):
    """Only the harness catches this; ordinary application Exception handlers cannot swallow it."""


class Hooks(ExecutionHooks):
    test_only = True

    def __init__(self, point: str | None = None) -> None:
        self.point = point
        self.fired: list[str] = []

    def _fire(self, point: str) -> None:
        if self.point == point:
            self.point = None
            self.fired.append(point)
            raise ProcessCrash(point)

    def before_checkpoint(self, execution: ExecutionRecord) -> None:
        self._fire("before_checkpoint")

    def before_send(self, execution: ExecutionRecord) -> None:
        self._fire("before_send")

    def after_response(self, execution: ExecutionRecord, result: object) -> None:
        self._fire("after_response")


ADDRESS = dict(address1="1 Safety Study Way", address2="", city="Springfield", state="IL", country="USA", zip="62701")


class CountingTransport(httpx.BaseTransport):
    def __init__(self, mutations: list[str], responses: list[str] | None = None) -> None:
        self.mutations = mutations
        self.responses = responses
        self.inner = httpx.HTTPTransport(trust_env=False, retries=0, proxy=None)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method == "PUT" and "/operations/" in request.url.path:
            self.mutations.append(request.url.path.rsplit("/", 1)[-1])
        response = self.inner.handle_request(request)
        if self.responses is not None and request.method == "PUT" and "/operations/" in request.url.path:
            self.responses.append(f"http_status_{response.status_code}")
        return response

    def close(self) -> None:
        self.inner.close()


def call_for(env: Env, pair: Pair) -> WriteToolCall:
    if pair.variant == "cancel":
        return CANCEL
    if pair.variant == "delivered_return":
        return RETURN
    return ModifyPendingOrderAddress.model_validate({"order_id": env.order, **ADDRESS})


def pair_env(previous: Env, pair: Pair, arm: Arm) -> Env:
    # New application run AND simulator case per arm, with reproducible case/run labels.
    customer = DELIVERED_CUSTOMER if pair.variant == "delivered_return" else previous.customer
    order = DELIVERED if pair.variant == "delivered_return" else previous.order
    return study_case(previous, customer=customer, order=order,
                      case_id=pair.identity(arm, "case"), run_id=pair.identity(arm, "run"))


def observe(env: Env) -> tuple[State, dict[str, Any], tuple[Receipt, ...]]:
    """Fixture setup/superuser is an observer only. Neither arm receives these lookup results."""
    with env.db.superuser() as conn:
        row = conn.execute("SELECT version, state, state_sha256 FROM retail.case_states "
                           "WHERE tenant_id = %s AND case_id = %s",
                           (env.run.workspace_id, env.run.case_id)).fetchone()
        receipts = conn.execute("SELECT receipt FROM retail.operations WHERE tenant_id = %s AND case_id = %s "
                                "AND outcome = 'committed' ORDER BY case_version_after",
                                (env.run.workspace_id, env.run.case_id)).fetchall()
    if row is None or len(row[1]) > 8 * 1024 * 1024:
        raise ValueError("missing or oversized simulator observation")
    raw = bytes(row[1])
    if hashlib.sha256(raw).hexdigest() != row[2]:
        raise ValueError("stored simulator state hash mismatch")
    full: dict[str, Any] = json.loads(raw)
    # Keep only the fixture customer's profile and orders. Full hash detects out-of-scope changes.
    scoped = {"users": {env.customer: full["users"][env.customer]},
              "orders": {oid: order for oid, order in full["orders"].items() if order["user_id"] == env.customer}}
    return (State(version=row[0], full_sha256=row[2], scoped=scoped), full,
            tuple(Receipt.model_validate_json(canonical(r[0])) for r in receipts))


def expected_state(env: Env, call: WriteToolCall, full: dict[str, Any]) -> dict[str, Any]:
    """Independent three-action oracle, computed BEFORE dispatch from the fixture and approved intent.

    Returns the expected *complete* upstream state, so unrelated edits cannot hide in a scoped diff.
    Return is a request only: no refund or monetary movement is invented.
    """
    expected = deepcopy(full)
    order = expected["orders"][env.order]
    if call.tool == "cancel_pending_order":
        order["status"], order["cancel_reason"] = "cancelled", call.reason
        refunds = [dict(payment, transaction_type="refund") for payment in order["payment_history"]]
        order["payment_history"] += refunds
        for payment in refunds:
            method = expected["users"][env.customer]["payment_methods"][payment["payment_method_id"]]
            if method["source"] == "gift_card":
                method["balance"] += payment["amount"]
    elif call.tool == "modify_pending_order_address":
        order["address"] = call.address().model_dump(mode="json")
    elif call.tool == "return_delivered_order_items":
        order["status"] = "return requested"
        order["return_items"] = sorted(call.item_ids)
        order["return_payment_method_id"] = call.payment_method_id
    else:
        raise ValueError("not a preregistered E04 action")
    return expected


def scoped_expected(env: Env, before: State, full: dict[str, Any], call: WriteToolCall) -> tuple[Change, ...]:
    expected = expected_state(env, call, full)
    scoped = {"users": {env.customer: expected["users"][env.customer]},
              "orders": {oid: order for oid, order in expected["orders"].items() if order["user_id"] == env.customer}}
    return tuple(changes(before.scoped, scoped))


def state_sha(full: dict[str, Any]) -> str:
    # Upstream codec uses ensure_ascii=False and compact/sorted JSON; no rounding.
    return hashlib.sha256(json.dumps(full, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                    allow_nan=False).encode()).hexdigest()


@contextmanager
def client_factory(env: Env, origin: str, *, timeout: float = 10,
                   mutations: list[str] | None = None, responses: list[str] | None = None) -> Iterator[RetailClient]:
    transport = CountingTransport(mutations, responses) if mutations is not None else None
    with closing(RetailClient(origin, env.service.key, tenant_id=env.run.workspace_id, case_id=env.run.case_id,
                              customer_id=env.customer, timeout_seconds=10,
                              transport=transport)) as client:
        original_mutate = client.mutate

        def mutate(operation_id: UUID, request: MutationRequest, *, authorization_not_after: float | None = None
                   ) -> OperationResult | Unknown:
            # Shorten only the mutation, after all precheck reads; a slow fixture read
            # must not trigger a different fault than the scheduled lost response.
            original_timeout = client._http.timeout
            client._http.timeout = httpx.Timeout(timeout)
            try:
                result = original_mutate(operation_id, request, authorization_not_after=authorization_not_after)
                if responses is not None:
                    responses.append("service_outcome_" + result.outcome if isinstance(result, OperationResult)
                                     else "client_unknown_" + result.reason)
                return result
            except Refused as exc:
                if responses is not None:
                    responses.append(f"service_refused_{exc.status}_{exc.code}")
                raise
            finally:
                client._http.timeout = original_timeout

        client.mutate = mutate  # type: ignore[method-assign]
        yield client


def worker(env: Env, hooks: ExecutionHooks, origin: str, *, timeout: float = 10,
           mutations: list[str] | None = None, responses: list[str] | None = None) -> Any:
    dispatcher = env.dispatcher(hooks=hooks)

    @contextmanager
    def retail(scope: GatewayScope) -> Iterator[RetailClient]:
        if scope != env.scope:
            raise ValueError("foreign worker scope")
        with client_factory(env, origin, timeout=timeout, mutations=mutations, responses=responses) as client:
            yield client

    dispatcher.executor.retail = retail
    return dispatcher


def concurrent_calls(calls: list[Any]) -> list[Any]:
    barrier = threading.Barrier(len(calls))
    results: list[Any] = []
    errors: list[BaseException] = []

    def run(call: Any) -> None:
        try:
            barrier.wait(10)
            results.append(call())
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=run, args=(call,), name="t30-duplicate") for call in calls]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    if any(thread.is_alive() for thread in threads):
        raise RuntimeError("duplicate delivery threads did not stop")
    if errors:
        raise errors[0]
    return results


def settled_version(record: ExecutionRecord, before: int = 1) -> int:
    if record.state == "succeeded" and record.outcome == "committed" and record.receipt is not None:
        return record.receipt.case_version_after
    if record.state == "reconciled" and record.outcome == "fenced" and record.receipt is None:
        return before
    raise ValueError("duplicate delivery did not settle")


def ledger_arm(env: Env, pair: Pair, config: Config, evidence: list[str], unknowns: list[str],
               mutations: list[str]) -> tuple[Any, int]:
    refs = env.approve(call_for(env, pair))
    execution_id = env.reserve(refs)
    crash_point = {"crash_before_send": "before_send", "crash_before_checkpoint": "before_checkpoint"}.get(pair.fault)
    hooks = Hooks(crash_point)
    gate = ReplyGate(env.origin) if pair.fault == "commit_then_timeout" else None
    if pair.fault == "fail_503_before":
        env.arm("fail_503_before")
    passes = 0
    relay = gate.running() if gate is not None else nullcontext(env.origin)
    with relay as origin:
        if pair.fault == "duplicate_delivery":
            dispatcher = worker(env, hooks, origin, mutations=mutations)
            def reserve() -> Any:
                return dispatcher.executor.reserve(env.scope, refs)
            repeated = concurrent_calls([reserve, reserve]) if pair.concurrent else [reserve(), reserve()]
            if not all(isinstance(r, Reserved) and not r.created and r.execution.id == execution_id for r in repeated):
                raise ValueError("duplicate reservation changed operation")
            # Pause the old claimant at a known boundary, expire its lease, let the new claimant recover;
            # The old snapshot may reach HTTP: due() advances the controlled application
            # clock, while the transport checks system wall time. The remote operation
            # fence must refuse any late effect. No timing sleeps.
            arrived, resume = threading.Event(), threading.Event()

            class Delayed(ExecutionHooks):
                test_only = True

                def before_send(self, execution: ExecutionRecord) -> None:
                    arrived.set()
                    if not resume.wait(10):
                        raise RuntimeError("old claimant deadline")

            errors: list[str] = []
            old_results: list[Any] = []
            old_mutations: list[str] = []
            old_responses: list[str] = []

            def old() -> None:
                try:
                    old_results.append(worker(env, Delayed(), origin, mutations=old_mutations,
                        responses=old_responses).executor.step(env.run.workspace_id, execution_id))
                except BaseException as error:
                    errors.append(type(error).__name__)

            thread = threading.Thread(target=old, name="t30-old-claimant")
            thread.start()
            try:
                if not arrived.wait(10):
                    raise RuntimeError("old claimant did not reach barrier")
                due(env)
                recovered = worker(env, hooks, origin, mutations=mutations).executor.step(
                    env.run.workspace_id, execution_id)
                settled = ledger_record(env, execution_id)
                expected_version = settled_version(settled)
                evidence.append(f"new_claimant_{recovered.action}_state_{settled.state}_outcome_{settled.outcome}")
            finally:
                resume.set()
                thread.join(20)
                mutations.extend(old_mutations)
                evidence.append(f"old_claimant_http_mutations_{len(old_mutations)}")
                evidence.extend("old_claimant_" + result for result in old_responses)
                if old_results:
                    result = old_results[0]
                    evidence.append(f"old_claimant_action_{result.action}_state_{result.state}_code_{result.code}")
            if (thread.is_alive() or errors or not old_results or old_results[0].action not in (
                    "lost_claim", "unchanged") or observe(env)[0].version != expected_version):
                raise ValueError("delayed claimant changed the settled operation")
            # Also deliver the settled execution twice concurrently/sequentially.
            def delivery() -> Any:
                return worker(env, hooks, origin, mutations=mutations).executor.step(env.run.workspace_id, execution_id)
            concurrent_calls([delivery, delivery]) if pair.concurrent else [delivery(), delivery()]
            evidence.append("duplicate_reservation_and_delivery;delayed_old_claimant_" + old_results[0].action)
        else:
            for _ in range(config.max_passes):
                passes += 1
                try:
                    # Reconstruct dispatcher AND client on every restart/pass.
                    dispatcher = worker(env, hooks, origin, timeout=config.relay_timeout_seconds if gate else 10,
                                        mutations=mutations)
                    step = dispatcher.executor.step(env.run.workspace_id, execution_id)
                    if step.action == "unknown":
                        unknowns.append(step.code or "unknown")
                except ProcessCrash:
                    evidence.extend(hooks.fired[-1:])
                    stored = ledger_record(env, execution_id)
                    expected_checkpoint = pair.fault == "crash_before_send"
                    if (stored.state != ("dispatched" if expected_checkpoint else "pending")
                            or stored.attempts != int(expected_checkpoint) or observe(env)[0].version != 1):
                        raise ValueError("crash did not reach its scheduled persisted boundary") from None
                    evidence.append(f"persisted_{stored.state}_checkpoints_{stored.attempts}_effects_0")
                if gate is not None and passes == 1:
                    if not gate.committed.wait(2) or gate.receipt is None:
                        raise ValueError("relay did not buffer committed mutation")
                    stored = ledger_record(env, execution_id)
                    if stored.state != "unknown" or not unknowns or gate.drained.is_set():
                        raise ValueError("lost response did not cause a real read timeout")
                    observed_state, _, remote = observe(env)
                    if observed_state.version != 2 or len(remote) != 1 or gate.receipt.receipt != remote[0]:
                        raise ValueError("buffered commit did not match independent observation")
                    evidence.append("real_read_timeout_after_buffered_commit")
                    gate.release.set()
                    if not gate.drained.wait(2):
                        raise ValueError("relay did not drain")
                if pair.fault == "fail_503_before" and passes == 1:
                    if observe(env)[0].version != 1 or not unknowns:
                        raise ValueError("503-before committed or did not trigger")
                    evidence.append("503_observed_before_any_commit")
                if env.row(execution_id)["state"] not in ("pending", "dispatched", "unknown"):
                    break
                due(env)
        if gate is not None and gate.errors:
            raise ValueError("relay cleanup/transport error")
    return ledger_record(env, execution_id), max(passes, 1)


def naive_arm(env: Env, pair: Pair, config: Config, evidence: list[str], unknowns: list[str], mutations: list[str]
              ) -> tuple[str, str | None, int, tuple[Receipt, ...], int, MutationRequest]:
    refs = env.approve(call_for(env, pair))
    with closing(env.client()) as client:
        request = cleared_request(env, refs, client).request  # ONE immutable approved request; never refreshed
    if pair.fault == "fail_503_before":
        env.arm("fail_503_before")
    gate = ReplyGate(env.origin) if pair.fault == "commit_then_timeout" else None
    final: OperationResult | None = None
    sends = 0
    held: list[Receipt] = []

    def send(origin: str, index: int) -> OperationResult | Unknown | None:
        with client_factory(env, origin, timeout=config.relay_timeout_seconds if gate else 10,
                            mutations=mutations) as client:
            try:
                return client.mutate(pair.identity("naive_new_id", f"operation-{index}"), request)
            except Refused as error:
                unknowns.append(f"refused_{error.status}_{error.code}")
                return None

    relay = gate.running() if gate is not None else nullcontext(env.origin)
    with relay as origin:
        if pair.fault in ("crash_before_send", "crash_before_checkpoint"):
            try:
                raise ProcessCrash(pair.fault)
            except ProcessCrash:
                evidence.append(pair.fault.removeprefix("crash_"))
        if pair.fault == "duplicate_delivery":
            results = concurrent_calls([lambda: send(origin, 0), lambda: send(origin, 1)]) if pair.concurrent \
                else [send(origin, 0), send(origin, 1)]
            sends = 2
            for result in results:
                if isinstance(result, OperationResult):
                    final = result if final is None or result.outcome == "committed" else final
                    if result.receipt is not None:
                        held.append(result.receipt)
            evidence.append("duplicate_intent_delivery")
        else:
            while sends < config.naive_max_sends and final is None:
                result = send(origin, sends)
                sends += 1
                if gate is not None and sends == 1:
                    if not gate.committed.wait(2) or gate.receipt is None or not isinstance(result, Unknown) \
                            or result.reason != "timeout" or gate.drained.is_set():
                        raise ValueError("naive relay did not produce a committed read timeout")
                    evidence.append("real_read_timeout_after_buffered_commit")
                    gate.release.set()
                    if not gate.drained.wait(2):
                        raise ValueError("relay did not drain")
                if pair.fault == "fail_503_before" and sends == 1:
                    if observe(env)[0].version != 1 or not isinstance(result, Unknown):
                        raise ValueError("naive 503-before fault not reached")
                    evidence.append("503_observed_before_any_commit")
                if isinstance(result, Unknown):
                    unknowns.append(result.reason)
                elif isinstance(result, OperationResult):
                    final = result
                    if result.receipt is not None:
                        held.append(result.receipt)
                else:
                    break
        if gate is not None and gate.errors:
            raise ValueError("relay cleanup/transport error")
    state = "unknown" if final is None else "succeeded" if final.outcome == "committed" else "failed"
    return (state, final.outcome if final else None, sends, tuple(held),
            sends + int(pair.fault.startswith("crash_")), request)


def run_trial(env: Env, pair: Pair, arm: Arm, config: Config) -> Trial:
    started = datetime.now(UTC)
    clock_start = env.clock.now()
    before: State | None = None
    after: State | None = None
    expected_diff: tuple[Change, ...] = ()
    actual_diff: tuple[Change, ...] = ()
    receipts: tuple[Receipt, ...] = ()
    held: tuple[Receipt, ...] = ()
    expected_effect: Effect | None = None
    expected_hash: str | None = None
    operations: dict[str, str] = {}
    evidence: list[str] = []
    unknowns: list[str] = []
    mutations: list[str] = []
    checkpoints = 0
    state, outcome, sends, reconciles, passes, error = "aborted", None, 0, 0, 0, None
    try:
        before, full, _ = observe(env)
        call = call_for(env, pair)
        expected_diff = scoped_expected(env, before, full, call)
        expected_hash = state_sha(expected_state(env, call, full))
        if arm == "ledger":
            record, passes = ledger_arm(env, pair, config, evidence, unknowns, mutations)
            state, outcome = record.state, record.outcome
            sends, reconciles = record.attempts, record.reconcile_attempts
            checkpoints = record.attempts
            held = () if record.receipt is None else (record.receipt,)
            expected_effect = record.request.expected_effect
            operations[str(record.operation_id)] = record.operation_sha256
        else:
            state, outcome, sends, held, passes, request = naive_arm(env, pair, config, evidence, unknowns, mutations)
            expected_effect = request.expected_effect
            with closing(env.client()) as client:
                operations = {str(pair.identity(arm, f"operation-{i}")):
                              client.fingerprint(pair.identity(arm, f"operation-{i}"), request) for i in range(sends)}
        after, _, receipts = observe(env)
        actual_diff = tuple(changes(before.scoped, after.scoped))
    except Exception as exc:
        error = type(exc).__name__  # never serialize connection representations or exception text
        try:
            after, _, receipts = observe(env)
            if before is not None:
                actual_diff = tuple(changes(before.scoped, after.scoped))
        except Exception:
            after = None
    return Trial(pair_id=pair.pair_id, seed=pair.seed, arm=arm, fault=pair.fault, variant=pair.variant,
                 case_id=str(env.run.case_id), run_id=str(env.run.run_id), started_at=started,
                 finished_at=datetime.now(UTC), application_clock_start=clock_start, fault_reached=bool(evidence),
                 fault_evidence=tuple(evidence), sends=len(mutations), dispatch_checkpoints=checkpoints,
                 mutation_operations=tuple(mutations), reconciles=reconciles, passes=passes,
                 final_state=cast(Any, state), outcome=outcome, before=before, after=after,
                 expected_effect=expected_effect, expected_full_sha256=expected_hash,
                 operations=operations,
                 expected_diff=expected_diff, actual_diff=actual_diff, remote_receipts=receipts, held_receipts=held,
                 unknowns=tuple(unknowns), error=error)
