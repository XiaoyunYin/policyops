"""Executed action/role/resource and retail-rule matrix, never a map of test links."""

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from datetime import timedelta
import json
from typing import Any
from uuid import uuid4

from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.auth.oidc import OidcClient
from policyops.auth.service import AuthError, Authorized, AuthService, ExpectedContext
from policyops.domain.case_status import CaseStatus
from policyops.domain.roles import Action
from policyops.gateway.ports import IncompleteHistory, PgMembership, PgSessionStore
from policyops.gateway.precheck import AuthorityRefs, Cleared, precheck
from policyops.gateway.steps import Gateway, StepResult, parse_result
from policyops.gateway.stores import PgDecisionStore, PgEvidencePort
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, Principal
from policyops.persistence.roles import AUTH_RUNTIME
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.spec import RuntimeCatalog, RuntimeSpec, Succeeded, binding
from policyops.services.cases import CaseService
from policyops.services.decisions import DecisionService
from policyops.services.execution import LedgerHistory
from policyops.services.proposal_views import DecisionRequest
from policyops.services.runs import RunService
from policyops.settings import AuthSettings
from policyops_contracts.gateway import ToolError
from policyops_contracts.model import ModelResult
from policyops_contracts.retail import ModifyPendingOrderAddress
from policyops_testing.gateway_cases import CASES, RuleCase, W, state
from policyops_testing.safety.config import canonical, digest
from policyops_testing.safety.e04 import observe, state_sha
from policyops_testing.safety.environment import (
    CANCEL,
    DELIVERED,
    DELIVERED_CUSTOMER,
    RETURN,
    ConsentNotRecorded,
    Env,
    next_run,
    study_case,
)
from policyops_testing.safety.reports import MatrixRow


# Explicit independent expectations; never read production PERMISSIONS to derive the oracle.
OPERATE = {"view_case", "create_case", "update_case_status", "post_staff_note", "enter_customer_turn",
           "start_run", "cancel_run"}
ROLE_ACTIONS = {
    "analyst": OPERATE,
    "reviewer": OPERATE | {"decide_proposal", "read_audit", "read_evaluations"},
    "admin": OPERATE | {"manage_membership", "read_audit", "read_evaluations"},
    "auditor": {"view_case", "read_audit", "read_evaluations"},
}
ACTORS = ("analyst", "reviewer", "admin", "auditor", "no_role", "revoked", "admin+reviewer")
RELATIONS = ("own", "other_case_same_workspace", "foreign_workspace", "missing_workspace", "mismatched_workspace")
RESOURCE_ACTIONS = {"view_case", "update_case_status", "post_staff_note", "enter_customer_turn", "start_run",
                    "cancel_run", "decide_proposal"}
BOUNDARIES = ("valid", "missing_approval", "forged_approval", "missing_consent", "expired", "revoked_reviewer",
              "changed_version", "changed_digest", "changed_policy", "changed_evidence", "changed_resource",
              "cancelled_run",
              "dead_run", "staff_note_is_not_consent", "self_entered_consent", "rejected_approval")


def applicable(action: Action, relation: str) -> bool:
    return relation not in ("other_case_same_workspace", "foreign_workspace") or action in RESOURCE_ACTIONS


def matrix_ids() -> tuple[str, ...]:
    return tuple([f"action/{action}/{actor}/{relation}" for action in Action for actor in ACTORS
                  for relation in RELATIONS if applicable(action, relation)]
                 + [f"rule/{case.case_id}" for case in CASES]
                 + [f"authority/{boundary}" for boundary in BOUNDARIES]
                 + [f"tool_execution/{tool}" for tool in WRITE_TOOLS]
                 + ["runtime/identities", "runtime/grants", "rls/customer_authentications", "rls/cases", "rls/runs",
                    "rls/proposals", "rls/consents", "rls/decisions", "rls/executions", "rls/messages",
                    "rls/memberships"])


WRITE_TOOLS = ("cancel_pending_order", "modify_pending_order_address", "modify_pending_order_payment",
               "modify_pending_order_items", "return_delivered_order_items", "exchange_delivered_order_items",
               "modify_user_address")


def roles_for(actor: str) -> tuple[str, ...]:
    if actor == "admin+reviewer":
        return ("admin", "reviewer")
    return () if actor == "no_role" else ("reviewer",) if actor == "revoked" else (actor,)


def allowed(action: Action, actor: str) -> bool:
    return actor != "revoked" and any(action in ROLE_ACTIONS.get(role, set()) for role in roles_for(actor))


def principal(env: Env, actor: str) -> Any:
    pid, now = uuid4(), env.clock.now()
    with transaction(env.db.engine(AUTH_RUNTIME)) as conn:
        repo.create_principal(conn, Principal(id=pid, issuer="https://safety.example.invalid", subject=str(pid),
                                              display_name="Synthetic matrix actor", created_at=now))
        for role in roles_for(actor):
            repo.add_membership(conn, Membership(id=uuid4(), workspace_id=env.run.workspace_id, principal_id=pid,
                role=role, created_at=now, revoked_at=now if actor == "revoked" else None))  # type: ignore[arg-type]
    return pid


class NeverExecute:
    def execute(self, context: Any) -> Succeeded:
        raise AssertionError("matrix starts persisted runs but does not run an agent")


def runtime_catalog() -> RuntimeCatalog:
    spec = RuntimeSpec(spec_id="t30-matrix", graph_sha256="a" * 64, prompt_sha256="b" * 64,
                       config_sha256="c" * 64, executor=NeverExecute(), test_only=True)
    return RuntimeCatalog(specs={binding(spec): spec}, default=spec.spec_id)


def operation(env: Env, target: Env, auth: Authorized, action: Action, refs: AuthorityRefs | None) -> str:
    cases = CaseService(env.app, target.clock, FixedLeaseClock(target.clock))
    runs = RunService(env.app, FixedLeaseClock(target.clock), runtime_catalog(), target.clock)
    with workspace_transaction(target.app, target.run.workspace_id) as conn:
        record = repo.get_case(conn, target.run.case_id)
    assert record is not None
    key = f"t30-{uuid4()}"
    if action == Action.VIEW_CASE:
        cases.get_case(auth, target.run.case_id)
    elif action == Action.CREATE_CASE:
        cases.create_case(auth, key=key)
    elif action == Action.UPDATE_CASE_STATUS:
        cases.change_status(auth, key=key, case_id=target.run.case_id, expected_version=record.version,
                            status=CaseStatus.IN_PROGRESS)
    elif action in (Action.POST_STAFF_NOTE, Action.ENTER_CUSTOMER_TURN):
        cases.post_message(auth, key=key, case_id=target.run.case_id, expected_version=record.version,
                           source="staff_note" if action == Action.POST_STAFF_NOTE else "operator_entered_customer",
                           text_value="Matrix synthetic turn")
    elif action == Action.START_RUN:
        runs.start(auth, key=key, case_id=target.run.case_id, expected_version=record.version)
    elif action == Action.CANCEL_RUN:
        runs.cancel(auth, key=key, run_id=target.run.run_id)
    elif action == Action.DECIDE_PROPOSAL:
        assert refs is not None
        with workspace_transaction(target.app, target.run.workspace_id) as conn:
            proposal = repo.get_proposal(conn, refs.proposal_id, refs.proposal_version)
        assert proposal is not None
        # Immutable decision replay still performs service role/scope checks.
        DecisionService(env.app, FixedLeaseClock(target.clock)).decide(auth, refs.proposal_id, DecisionRequest(
            proposal_version=refs.proposal_version, action_digest=proposal.action_digest,
            decision="approve", reason="Order and policy checked."))
    elif action == Action.MANAGE_MEMBERSHIP:
        with workspace_transaction(env.app, auth.workspace_id) as conn:
            repo.workspace_memberships(conn)
    else:
        return "auth_admission_only"
    return "service"


def application_state(env: Env) -> dict[str, Any]:
    with env.db.superuser() as conn:
        case = conn.execute("SELECT status, version FROM app.cases WHERE id = %s", (env.run.case_id,)).fetchone()
        run = conn.execute("SELECT state, version FROM app.runs WHERE id = %s", (env.run.run_id,)).fetchone()
        counts = {table: conn.execute(f"SELECT count(*) FROM app.{table} WHERE workspace_id = %s",  # noqa: S608
                                     (env.run.workspace_id,)).fetchone()[0] for table in (
            "cases", "case_messages", "runs", "approval_decisions", "audit_events")}
    return {"case": list(case), "run": list(run), "counts": counts}


def expected_application_change(action: Action, before: dict[str, Any], after: dict[str, Any], allowed: bool) -> bool:
    if not allowed or action in (Action.VIEW_CASE, Action.MANAGE_MEMBERSHIP,
                                 Action.READ_AUDIT, Action.READ_EVALUATIONS):
        return before == after
    changed = {Action.CREATE_CASE: "cases", Action.POST_STAFF_NOTE: "case_messages",
               Action.ENTER_CUSTOMER_TURN: "case_messages", Action.START_RUN: "runs",
               Action.DECIDE_PROPOSAL: "approval_decisions"}.get(action)
    if changed is not None and after["counts"][changed] != before["counts"][changed] + 1:
        return False
    if after["counts"]["audit_events"] != before["counts"]["audit_events"] + 1:
        return False
    if action == Action.UPDATE_CASE_STATUS:
        return bool(after["case"] == ["in_progress", before["case"][1] + 1])
    if action == Action.CANCEL_RUN:
        return bool(after["run"] == ["cancelled", before["run"][1] + 1])
    return True


def action_matrix(base: Env, rows: list[MatrixRow] | None = None) -> list[MatrixRow]:
    rows = [] if rows is None else rows
    settings = AuthSettings(env="test", public_origin="http://127.0.0.1:8000",
                            oidc_issuer="https://issuer.example.invalid", oidc_client_id="t30",
                            oidc_client_secret=SecretStr("synthetic-t30-client"))
    # No discovery/login/network calls: sessions and memberships are genuinely stored.
    oidc = OidcClient(settings, base.clock)
    try:
        for action in Action:
            for actor in ACTORS:
                env = study_case(base)
                pid = principal(env, actor)
                service = AuthService(settings, oidc, env.db.engine(AUTH_RUNTIME), env.clock)
                for relation in RELATIONS:
                    if not applicable(action, relation):
                        continue
                    target = env
                    if relation == "other_case_same_workspace":
                        target = study_case(env, customer=DELIVERED_CUSTOMER, order=DELIVERED)
                    elif relation == "foreign_workspace":
                        from policyops_testing.safety.environment import make_env
                        target = make_env((env.service, env.origin), env.db)
                    refs = target.approve(RETURN if target.customer == DELIVERED_CUSTOMER else CANCEL,
                                          decide=False) if action == Action.DECIDE_PROPOSAL else None
                    if action == Action.START_RUN:
                        target.cancel_run()  # fixture setup, before measuring any actor request
                    selected = None if relation == "missing_workspace" else env.run.workspace_id
                    expected_ws = uuid4() if relation == "mismatched_workspace" else env.run.workspace_id
                    service.clock = target.clock
                    with transaction(env.db.engine(AUTH_RUNTIME)) as conn:
                        issued = service._new_session(conn, principal_id=pid, workspace_id=selected,
                            now=target.clock.now(), expires_at=target.clock.now() + timedelta(hours=1),
                            rotated_from=None, return_to="/")
                    before = observe(target)[0]
                    app_before = application_state(target)
                    want_allow = allowed(action, actor) and relation not in (
                        "foreign_workspace", "missing_workspace", "mismatched_workspace")
                    expected_code, expected_rule = None, None
                    if relation in ("missing_workspace", "mismatched_workspace"):
                        expected_code, expected_rule = "context_changed", "auth.workspace_changed"
                    elif actor in ("no_role", "revoked"):
                        expected_code, expected_rule = "forbidden", "auth.membership"
                    elif not allowed(action, actor):
                        expected_code, expected_rule = "forbidden", "auth.role"
                    elif relation == "foreign_workspace":
                        expected_code = "not_found"
                    observed, code, rule, layer, error = "allow", None, None, "auth", None
                    try:
                        resolved = service.resolve(issued.cookie)
                        auth = service.authorize(resolved, action,
                            expected=ExpectedContext(principal_id=pid, workspace_id=expected_ws))
                        layer = "service"
                        layer = operation(env, target, auth, action, refs)
                    except AuthError as exc:
                        observed, code, rule = "deny", str(exc.code), exc.rule_id
                    except Exception as exc:
                        observed, error = "aborted", type(exc).__name__
                    after = observe(target)[0]
                    app_after = application_state(target)
                    rows.append(MatrixRow(cell_id=f"action/{action}/{actor}/{relation}", action=action,
                        roles=roles_for(actor), relationship=relation, expected="allow" if want_allow else "deny",
                        preconditions=(("different_case_and_customer",)
                                       if relation == "other_case_same_workspace" else ()),
                        expected_code=expected_code, expected_rule=expected_rule,
                        observed=observed, code=code, observed_rule=rule, layer=layer,
                        before_sha256=digest(before.scoped), after_sha256=digest(after.scoped),
                        database_evidence={"application_before": app_before, "application_after": app_after},
                        passed=(observed == ("allow" if want_allow else "deny") and before == after
                            and code == expected_code and (expected_rule is None or rule == expected_rule)
                            and expected_application_change(action, app_before, app_after, want_allow)), error=error))
                    # The next relation must get fresh mutable state and a fresh approval.
                    env = study_case(env)
    finally:
        oidc.close()
    return rows


def seed_rule_fixture(env: Env, case: RuleCase, *, execution: bool = False) -> Env:
    """Controlled synthetic preconditions, installed before measurement on one disposable simulator case.

    The upstream seed remains pinned; these deliberate case-state edits are not claimed to
    be an unmodified benchmark fixture. All reads after setup use the real HTTP service.
    """
    synthetic = state(status=case.setup.status, gift_balance=case.setup.gift_balance,
                      payments=case.setup.payments, item_c_available=case.setup.item_c_available)
    if execution and case.tool == "modify_pending_order_items":
        # The upstream computes a float price difference without rounding. 30 - 19.99
        # is 10.010000000000002 and is intentionally refused by the exact-money
        # projector. Use whole-dollar prices for the successful execution cell;
        # the rule-boundary fixtures keep their original 19.99 prices.
        from policyops_contracts.money import Money
        items = tuple(i.model_copy(update={"price": Money(amount_minor=2000)}) if i.item_id == W.item_a else i
                      for i in synthetic.order.items)
        total = Money(amount_minor=sum(i.price.amount_minor for i in items))
        synthetic.order = synthetic.order.model_copy(update={"items": items, "payment_history": tuple(
            p.model_copy(update={"amount": total}) for p in synthetic.order.payment_history)})
        synthetic.variants[W.item_a] = synthetic.variants[W.item_a].model_copy(
            update={"price": Money(amount_minor=2000)})
    _, full, _ = observe(env)
    user, order = synthetic.customer, synthetic.order
    profile = full["users"][env.customer]
    profile["email"] = "example.user@example.invalid"
    profile["name"] = {"first_name": "Example", "last_name": "User"}
    profile["address"] = user.address.model_dump(mode="json")
    profile["address"]["zip"] = "00001"
    profile["orders"] = [W.order_id]
    profile["payment_methods"] = {}
    for method in user.payment_methods:
        raw: dict[str, Any] = {"id": method.payment_method_id, "source": method.kind}
        if method.kind == "gift_card":
            assert method.gift_card_balance is not None
            raw["balance"] = method.gift_card_balance.amount_minor / 100
        elif method.kind == "credit_card":
            raw.update(brand="visa", last_four="4242")
        profile["payment_methods"][method.payment_method_id] = raw
    full["orders"][W.order_id] = {
        **{name: None for name in ("cancel_reason", "exchange_items", "exchange_new_items",
            "exchange_payment_method_id", "exchange_price_difference", "return_items", "return_payment_method_id")},
        "order_id": W.order_id, "user_id": env.customer, "address": order.address.model_dump(mode="json"),
        "status": order.status, "fulfillments": [],
        "items": [{"name": "Synthetic item", "item_id": i.item_id, "product_id": i.product_id,
                   "price": i.price.amount_minor / 100, "options": {"color": i.item_id}} for i in order.items],
        "payment_history": [{"transaction_type": p.transaction_type, "payment_method_id": p.payment_method_id,
                             "amount": p.amount.amount_minor / 100} for p in order.payment_history],
    }
    for variant in synthetic.variants.values():
        product = full["products"].setdefault(variant.product_id, {
            "name": "Synthetic product", "product_id": variant.product_id, "variants": {}})
        product["variants"][variant.item_id] = {"item_id": variant.item_id, "available": variant.available,
            "price": variant.price.amount_minor / 100, "options": {"color": variant.item_id}}
    raw_bytes = json.dumps(full, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    with env.db.superuser() as conn:
        conn.execute("UPDATE retail.case_states SET state = %s, state_sha256 = %s "
                     "WHERE tenant_id = %s AND case_id = %s",
                     (raw_bytes, state_sha(full), env.run.workspace_id, env.run.case_id))
        conn.execute("INSERT INTO retail.case_resources (tenant_id, case_id, kind, resource_id, version) "
                     "VALUES (%s, %s, 'order', %s, 1) ON CONFLICT DO NOTHING",
                     (env.run.workspace_id, env.run.case_id, W.order_id))
        if not case.setup.authenticated:
            conn.execute("DELETE FROM app.customer_authentications WHERE run_id = %s", (env.run.run_id,))
    env = replace(env, order=W.order_id)
    if case.setup.history:
        # A genuine prior successful HTTP execution establishes once-only history; no forged ledger rows.
        prior = ModifyPendingOrderAddress(order_id=W.order_id, address1="1 Previous Way", address2="",
                                          city="Example", state="IL", country="USA", zip="00001")
        env.reserve(env.approve(prior))
        assert env.dispatcher().dispatch_once()[0].state == "succeeded"
        env = next_run(env)
    return env


def remap_result(result: ModelResult, customer: str) -> ModelResult:
    raw = result.model_dump(mode="json")
    for call in raw["tool_calls"]:
        # Replace only a scalar user_id in parsed JSON, never arbitrary instruction text.
        args = json.loads(call["arguments_json"])
        if args.get("user_id") == W.user_id:
            args["user_id"] = customer
        call["arguments_json"] = json.dumps(args)
    return ModelResult.model_validate_json(canonical(raw))


def rule_matrix(base: Env, rows: list[MatrixRow] | None = None) -> list[MatrixRow]:
    rows = [] if rows is None else rows
    for case in CASES:
        env = study_case(base)
        before = observe(env)[0]
        error, code, rule, observed = None, None, None, "aborted"
        try:
            env = seed_rule_fixture(env, case)
            before = observe(env)[0]
            with closing(env.client()) as client:
                gateway = Gateway(env.scope, retail=client, sessions=PgSessionStore(env.app), clock=env.clock,
                    history=IncompleteHistory() if case.setup.history is None else LedgerHistory(env.app, env.run))
                previous = None
                observations = []
                for sequence, raw in enumerate(case.steps, 2):
                    parsed = parse_result(remap_result(raw, env.customer))
                    result = StepResult(parsed) if isinstance(parsed, ToolError) else gateway.step(
                        parsed, previous=previous, sequence=sequence)
                    if not isinstance(parsed, ToolError):
                        previous = parsed
                    observation = result.observation
                    observed = "message" if observation is None else (
                        "preview" if observation.kind == "proposal_preview" else observation.kind)
                    code = str(observation.code) if isinstance(observation, ToolError) else None
                    rule = observation.rule_id if isinstance(observation, ToolError) else None
                    observations.append((observed, code, rule))
            expected = (case.expect.kind, None if case.expect.code is None else str(case.expect.code),
                        case.expect.rule_id)
            passed = observations[-1] == expected and (not case.same_each_step or all(
                o == expected for o in observations))
        except Exception as exc:
            error, passed = type(exc).__name__, False
        after = observe(env)[0]
        rows.append(MatrixRow(cell_id=f"rule/{case.case_id}", tool=case.tool, rule=case.rule_id,
            relationship="bound_customer", preconditions=(f"status={case.setup.status}",
                "synthetic_case_state_setup;real_HTTP;persisted_auth;ledger_history"),
            expected=case.expect.kind, expected_code=None if case.expect.code is None else str(case.expect.code),
            expected_rule=case.expect.rule_id, observed=observed, code=code, observed_rule=rule,
            layer="parser+gateway+postgres+HTTP", before_sha256=digest(before.scoped),
            after_sha256=digest(after.scoped), passed=passed and before == after, error=error))
    return rows


def authority_matrix(base: Env, rows: list[MatrixRow] | None = None) -> list[MatrixRow]:
    rows = [] if rows is None else rows
    for boundary in BOUNDARIES:
        env = study_case(base)
        if boundary == "revoked_reviewer":
            from policyops_testing.safety.environment import make_env
            env = make_env((base.service, base.origin), base.db)
        if boundary == "staff_note_is_not_consent":
            before = observe(env)[0]
            try:
                env.approve(source="staff_note", entered_by=env.reviewer)
            except ConsentNotRecorded as exc:
                # record_customer_reply returned the actual non-Consented result.
                rows.append(MatrixRow(cell_id=f"authority/{boundary}", relationship="bound_customer",
                    expected="deny", observed="deny", code="no_customer_consent", layer="customer_reply_service",
                    before_sha256=digest(before.scoped), after_sha256=digest(observe(env)[0].scoped),
                    passed=exc.args == ("NotConsent",)))
                continue
            raise ValueError("staff note was accepted as customer consent")
        if boundary == "self_entered_consent":
            before = observe(env)[0]
            try:
                env.approve(source="operator_entered_customer", entered_by=env.reviewer)
            except AuthError as exc:
                rows.append(MatrixRow(cell_id=f"authority/{boundary}", relationship="bound_customer",
                    expected="deny", observed="deny", code=str(exc.code), observed_rule=exc.rule_id,
                    layer="decision_service", before_sha256=digest(before.scoped),
                    after_sha256=digest(observe(env)[0].scoped), passed=True))
                continue
            raise ValueError("reviewer approved their own entered consent")
        refs = env.approve(decision_kind="reject" if boundary == "rejected_approval" else "approve")
        before = observe(env)[0]
        if boundary == "missing_approval" or boundary == "forged_approval":
            refs = replace(refs, approval_id=uuid4())
        elif boundary == "missing_consent":
            refs = replace(refs, consent_id=uuid4())
        elif boundary == "changed_version":
            refs = replace(refs, proposal_version=refs.proposal_version + 1)
        elif boundary == "expired":
            env.clock.advance(timedelta(hours=3))
        elif boundary == "revoked_reviewer":
            with transaction(env.db.engine(AUTH_RUNTIME)) as conn:
                repo.revoke_membership(conn, env.membership, env.clock.now())
        elif boundary in ("cancelled_run", "dead_run"):
            if boundary == "cancelled_run":
                env.cancel_run()
            else:
                env.clock.advance(timedelta(hours=3))
        elif boundary in ("changed_digest", "changed_policy", "changed_evidence"):
            column = {"changed_digest": "action_digest", "changed_policy": "policy_sha256",
                      "changed_evidence": "body"}[boundary]
            expression = ("jsonb_set(body, '{evidence}', '[{}]'::jsonb)"
                          if boundary == "changed_evidence" else ":changed")
            try:
                with workspace_transaction(env.app, env.run.workspace_id) as conn:
                    conn.execute(text(f"UPDATE app.action_proposals SET {column} = {expression} "  # noqa: S608
                                      "WHERE proposal_id = :pid"), {"changed": "f" * 64, "pid": refs.proposal_id})
            except DBAPIError as exc:
                rows.append(MatrixRow(cell_id=f"authority/{boundary}", relationship="bound_customer",
                    expected="deny", observed="deny", code=str(getattr(exc.orig, "sqlstate", "unknown")),
                    layer="immutable_database_authority", before_sha256=digest(before.scoped),
                    after_sha256=digest(observe(env)[0].scoped), passed=True))
                continue
            raise ValueError("immutable authority accepted a changed digest/policy")
        elif boundary == "changed_resource":
            with closing(env.client()) as client:
                from policyops_testing.safety.environment import cleared_request
                request = cleared_request(env, refs, client).request
                result = client.mutate(uuid4(), request)
                if not hasattr(result, "receipt") or result.receipt is None:
                    raise ValueError("resource-change setup did not commit")
            before = observe(env)[0]
        observed, code, error, passed = "deny", None, None, False
        try:
            with closing(env.client()) as client:
                checked = precheck(env.scope, refs, retail=client, sessions=PgSessionStore(env.app),
                    membership=PgMembership(env.app), clock=env.clock, decisions=PgDecisionStore(env.app),
                    history=LedgerHistory(env.app, env.run), evidence=PgEvidencePort(env.app))
            observed = "allow" if isinstance(checked, Cleared) else "deny"
            if not isinstance(checked, Cleared):
                code = str(checked.code)
            if boundary in ("cancelled_run", "dead_run"):
                reservation = env.dispatcher().executor.reserve(env.scope, refs)
                observed = "deny" if not hasattr(reservation, "execution") else "allow"
            passed = observed == ("allow" if boundary == "valid" else "deny")
        except Exception as exc:
            error = type(exc).__name__
        after = observe(env)[0]
        rows.append(MatrixRow(cell_id=f"authority/{boundary}", rule="consent.explicit_yes" if boundary in (
            "valid", "missing_consent", "expired") else None,
            relationship="bound_customer", expected=(
            "allow" if boundary == "valid" else "deny"), observed=observed, code=code, layer="persisted_precheck",
            before_sha256=digest(before.scoped), after_sha256=digest(after.scoped), passed=passed, error=error))
    return rows


def tool_matrix(base: Env, rows: list[MatrixRow] | None = None) -> list[MatrixRow]:
    from pydantic import TypeAdapter

    from policyops_contracts.retail import ToolCall
    from policyops_testing.safety.environment import ledger_record
    rows = [] if rows is None else rows
    for tool in WRITE_TOOLS:
        case = next(c for c in CASES if c.tool == tool and c.expect.kind == "preview")
        env = seed_rule_fixture(study_case(base), case, execution=True)
        raw = remap_result(case.steps[-1], env.customer).tool_calls[0]
        call = TypeAdapter(ToolCall).validate_json(canonical({"tool": tool, **json.loads(raw.arguments_json)}))
        before, _, _ = observe(env)
        error, passed, observed = None, False, "aborted"
        evidence: dict[str, Any] = {"steps": [], "state": None, "outcome": None, "last_code": None}
        execution_id = None
        try:
            execution_id = env.reserve(env.approve(call))
            step = env.dispatcher().executor.step(env.run.workspace_id, execution_id)
            evidence["steps"].append({"action": step.action, "state": step.state, "code": step.code})
            record = ledger_record(env, execution_id)
            evidence.update(state=record.state, outcome=record.outcome, last_code=record.last_code)
            after, _, receipts = observe(env)
            passed = (record.state == "succeeded" and after.version - before.version == 1 and len(receipts) == 1
                      and record.receipt == receipts[0] and receipts[0].actual_effect == record.request.expected_effect)
            observed = "one_approved_effect_and_receipt" if passed else "incorrect"
            from policyops_testing.safety.reports import changes
            evidence.update({"actual_diff": [c.model_dump(mode="json") for c in changes(before.scoped, after.scoped)],
                        "expected_effect": record.request.expected_effect.model_dump(mode="json"),
                        "receipts": [r.model_dump(mode="json") for r in receipts]})
        except Exception as exc:
            error = type(exc).__name__
            if execution_id is not None:
                record = ledger_record(env, execution_id)
                evidence.update(state=record.state, outcome=record.outcome, last_code=record.last_code)
        after = observe(env)[0]
        rows.append(MatrixRow(cell_id=f"tool_execution/{tool}", tool=tool, relationship="bound_customer",
            expected="one_approved_effect_and_receipt", observed=observed, layer="persisted_authority+dispatcher+HTTP",
            before_sha256=digest(before.scoped), after_sha256=digest(after.scoped), database_evidence=evidence,
            passed=passed, error=error))
    return rows
