"""Durable customer authentication (T17, revision 0008) on real PostgreSQL, as the actual runtime LOGIN role.

Covers:
- first write wins, and a conflicting customer or case is refused;
- composite run/case/customer keys and workspace RLS;
- SELECT and INSERT only;
- concurrent first writes and restart persistence;
- the migration from a populated 0007 database (old rows, roles and grants kept), the populated-downgrade refusal,
  and a safe empty downgrade;
- the gateway on an old 0007 schema, which fails closed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import threading
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import DBAPIError

from policyops.gateway.ports import GatewayScope, PgSessionStore, ScopeMismatch, load_scope
from policyops.gateway.steps import Gateway, parse_result
from policyops.persistence import customer_authentications as auth_rows
from policyops.persistence import repositories as repo
from policyops.persistence.customer_authentications import AuthenticationConflict
from policyops.persistence.database import transaction, verify_runtime_role, workspace_transaction
from policyops.persistence.migrate import DataLossRefused
from policyops.persistence.records import Membership, NewCase, NewRun, Principal, Workspace
from policyops.persistence.roles import APP_MIGRATOR, APP_RUNTIME, AUTH_RUNTIME
from policyops_contracts.agent import ToolCallStep
from policyops_contracts.clock import FixedClock
from policyops_contracts.digest import text_sha256
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.gateway_cases import EMAIL, FakeRetail, state, tool


pytestmark = pytest.mark.postgres
NOW = datetime.now(UTC).replace(microsecond=0)
CUSTOMER, OTHER = "example_user_0001", "other_user_0002"
TABLE = "app.customer_authentications"


def workspace(db: AppDatabase) -> UUID:
    ws = uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=ws, slug=f"ws-{ws.hex[:12]}", name="Gateway test",
                                              created_at=NOW))
    return ws


def case_and_run(db: AppDatabase, ws: UUID, customer: str | None = CUSTOMER) -> RunScope:
    case, run = uuid4(), uuid4()
    with workspace_transaction(db.engine(APP_RUNTIME), ws) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=ws, scenario="retail",
                                                customer_user_id=customer, created_by=None, created_at=NOW))
        repo.create_run(conn, NewRun(id=run, workspace_id=ws, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=NOW + timedelta(hours=1),
                                     created_at=NOW))
    return RunScope(workspace_id=ws, case_id=case, run_id=run)


def another_run(db: AppDatabase, scope: RunScope) -> RunScope:
    run = uuid4()
    with workspace_transaction(db.engine(APP_RUNTIME), scope.workspace_id) as conn:
        case = repo.get_case(conn, scope.case_id)
        assert case is not None
        repo.create_run(conn, NewRun(id=run, workspace_id=scope.workspace_id, case_id=scope.case_id,
                                     case_version=case.version, mode="evaluation", graph_sha256=text_sha256("g"),
                                     prompt_sha256=text_sha256("p"), config_sha256=text_sha256("c"),
                                     deadline_at=NOW + timedelta(hours=1), created_at=NOW))
    return RunScope(workspace_id=scope.workspace_id, case_id=scope.case_id, run_id=run)


def authentication(scope: RunScope, user_id: str = CUSTOMER, step: int = 1) -> CustomerAuthentication:
    return CustomerAuthentication(scope=scope, user_id=user_id, lookup_tool="find_user_id_by_email",
                                  lookup_call_sha256=hashlib.sha256(f"{scope.run_id}/{step}".encode()).hexdigest(),
                                  step_sequence=step, authenticated_at=NOW)


def binding(scope: RunScope, user_id: str = CUSTOMER) -> CaseCustomerBinding:
    return CaseCustomerBinding(scope=CaseScope(workspace_id=scope.workspace_id, case_id=scope.case_id),
                               seed_id="retail-demo-9999", user_id=user_id, bound_at=NOW)


@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("gateway_auth")


def test_the_runtime_is_the_restricted_login_with_select_insert_only(db: AppDatabase) -> None:
    runtime = db.engine(APP_RUNTIME)
    verify_runtime_role(runtime, APP_RUNTIME)
    with runtime.connect() as conn:
        row = conn.exec_driver_sql("SELECT current_user, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles "
                                   "WHERE rolname = current_user").one()
    assert tuple(row) == (APP_RUNTIME, False, False, True)
    with db.superuser() as conn:
        granted = {privilege: conn.execute("SELECT has_table_privilege(%s, %s, %s)",
                                           (APP_RUNTIME, TABLE, privilege)).fetchone()[0]
                   for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")}
        forced = conn.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass",
                              (TABLE,)).fetchone()
    assert granted == {"SELECT": True, "INSERT": True, "UPDATE": False, "DELETE": False, "TRUNCATE": False,
                       "REFERENCES": False, "TRIGGER": False}
    assert forced == (True, True)


def test_first_write_wins_and_a_conflicting_identity_is_refused(db: AppDatabase) -> None:
    scope = case_and_run(db, workspace(db))
    store = PgSessionStore(db.engine(APP_RUNTIME))
    first = store.record(authentication(scope, step=3))
    assert store.record(authentication(scope, step=3)) == first  # identical replay
    assert store.record(authentication(scope, step=8)) == first  # a later successful lookup keeps the first record
    with pytest.raises(AuthenticationConflict):
        store.record(authentication(scope, user_id=OTHER))
    assert store.load(scope) == first
    with workspace_transaction(db.engine(APP_RUNTIME), scope.workspace_id) as conn:
        assert auth_rows.run_ids(conn) == [scope.run_id]


def test_the_keys_tie_a_record_to_its_own_run_case_and_bound_customer(db: AppDatabase) -> None:
    ws = workspace(db)
    bound, other_case = case_and_run(db, ws), case_and_run(db, ws, customer=OTHER)
    unbound = case_and_run(db, ws, customer=None)
    store = PgSessionStore(db.engine(APP_RUNTIME))
    refused = {
        "run of another case": authentication(RunScope(workspace_id=ws, case_id=bound.case_id,
                                                       run_id=other_case.run_id)),
        "customer the case is not bound to": authentication(another_run(db, bound), user_id=OTHER),
        "case without a bound customer": authentication(unbound),
        "run that does not exist": authentication(RunScope(workspace_id=ws, case_id=bound.case_id, run_id=uuid4())),
    }
    for label, record in refused.items():
        with pytest.raises(AuthenticationConflict):
            store.record(record)
        assert store.load(record.scope) is None, label
    with db.superuser() as conn:
        assert conn.execute(f"SELECT count(*) FROM {TABLE}").fetchone() == (0,)  # noqa: S608


def test_workspace_rls_hides_and_refuses_other_tenants_records(db: AppDatabase) -> None:
    a, b = workspace(db), workspace(db)
    scope_a, scope_b = case_and_run(db, a), case_and_run(db, b)
    runtime = db.engine(APP_RUNTIME)
    PgSessionStore(runtime).record(authentication(scope_a))
    with workspace_transaction(runtime, b) as conn:
        assert auth_rows.run_ids(conn) == []
        assert auth_rows.load(conn, scope_a) is None
    # A fully valid row of workspace A (its own unused run, case and bound customer): under B only the policy's
    # WITH CHECK can refuse it (42501), never a missing key or a duplicate. The same row then inserts under A.
    unused = authentication(another_run(db, scope_a))
    insert = (f"INSERT INTO {TABLE} (workspace_id, case_id, run_id, user_id, lookup_tool, "  # noqa: S608
              "lookup_call_sha256, step_sequence, authenticated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
    row = (a, unused.scope.case_id, unused.scope.run_id, CUSTOMER, unused.lookup_tool, unused.lookup_call_sha256,
           unused.step_sequence, NOW)
    with pytest.raises(DBAPIError) as refused, workspace_transaction(runtime, b) as conn:
        conn.exec_driver_sql(insert, row)
    assert refused.value.orig.sqlstate == "42501"  # type: ignore[union-attr]
    with workspace_transaction(runtime, a) as conn:  # positive control: the identical payload is valid for A
        conn.exec_driver_sql(insert, row)
    assert PgSessionStore(runtime).load(unused.scope) == unused
    with pytest.raises(AuthenticationConflict):  # b's own run, but a's case: the composite key refuses it
        PgSessionStore(runtime).record(authentication(RunScope(workspace_id=b, case_id=scope_a.case_id,
                                                               run_id=scope_b.run_id)))


@pytest.mark.parametrize("statement", [f"UPDATE {TABLE} SET user_id = 'other_user_0002'",  # noqa: S608
                                       f"DELETE FROM {TABLE}",  # noqa: S608
                                       f"TRUNCATE {TABLE}"])
def test_the_runtime_cannot_rewrite_or_remove_an_authentication(db: AppDatabase, statement: str) -> None:
    scope = case_and_run(db, workspace(db))
    PgSessionStore(db.engine(APP_RUNTIME)).record(authentication(scope))
    with pytest.raises(DBAPIError, match="permission denied"), \
            workspace_transaction(db.engine(APP_RUNTIME), scope.workspace_id) as conn:
        conn.exec_driver_sql(statement)
    assert PgSessionStore(db.engine(APP_RUNTIME)).load(scope) == authentication(scope)


def test_a_case_cannot_be_rebound_while_one_of_its_runs_is_authenticated(db: AppDatabase) -> None:
    scope = case_and_run(db, workspace(db))
    PgSessionStore(db.engine(APP_RUNTIME)).record(authentication(scope))
    with pytest.raises(Exception, match="customer_authentications_bound_customer"), db.superuser() as conn:
        conn.execute("UPDATE app.cases SET customer_user_id = %s WHERE id = %s", (OTHER, scope.case_id))


def test_concurrent_first_writes_keep_exactly_one_record(db: AppDatabase) -> None:
    scope = case_and_run(db, workspace(db))
    store = PgSessionStore(db.engine(APP_RUNTIME, pool_size=4))
    barrier, results, errors = threading.Barrier(4), [], []

    def write(step: int) -> None:
        barrier.wait(10)
        try:
            results.append(store.record(authentication(scope, step=step)))
        except BaseException as error:  # pragma: no cover - reported below
            errors.append(type(error).__name__)

    threads = [threading.Thread(target=write, args=(step,)) for step in (2, 3, 4, 5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert errors == [] and len(results) == 4 and not any(thread.is_alive() for thread in threads)
    stored = store.load(scope)
    assert stored is not None and all(result == stored for result in results)
    with db.superuser() as conn:
        assert conn.execute(f"SELECT count(*) FROM {TABLE}").fetchone() == (1,)  # noqa: S608


def test_the_authentication_survives_a_restart_and_the_gateway_uses_it(db: AppDatabase) -> None:
    scope = case_and_run(db, workspace(db))
    gateway_scope = load_scope(db.engine(APP_RUNTIME), workspace_id=scope.workspace_id, run_id=scope.run_id,
                               binding=binding(scope), fixture_sha256=FIXTURE_SHA256)
    retail = FakeRetail(state(), tenant_id=scope.workspace_id, case_id=scope.case_id)
    gateway = Gateway(gateway_scope, retail=retail, sessions=PgSessionStore(db.engine(APP_RUNTIME)),
                      clock=FixedClock(NOW))
    lookup = parse_result(tool("find_user_id_by_email", email=EMAIL))
    assert isinstance(lookup, ToolCallStep)
    assert gateway.step(lookup, previous=None, sequence=2).observation.outcome == "authenticated"  # type: ignore[union-attr]
    db.dispose()  # a worker restart: new connections, nothing cached in the process
    restarted = Gateway(gateway_scope, retail=retail, sessions=PgSessionStore(db.engine(APP_RUNTIME)),
                        clock=FixedClock(NOW))
    session = restarted.session()
    assert session.authentication is not None and session.authentication.step_sequence == 2


def test_the_scope_is_loaded_from_the_persisted_run_and_case(db: AppDatabase) -> None:
    ws = workspace(db)
    scope, other = case_and_run(db, ws), case_and_run(db, ws, customer=OTHER)
    runtime = db.engine(APP_RUNTIME)
    loaded = load_scope(runtime, workspace_id=ws, run_id=scope.run_id, binding=binding(scope),
                        fixture_sha256=FIXTURE_SHA256)
    assert loaded == GatewayScope(run=scope, binding=binding(scope), fixture_sha256=FIXTURE_SHA256)
    for run_id, wrong in ((scope.run_id, binding(other, OTHER)),  # another case's binding
                          (scope.run_id, binding(scope, OTHER)),  # a customer the case is not bound to
                          (uuid4(), binding(scope))):  # a run that does not exist
        with pytest.raises(ScopeMismatch):
            load_scope(runtime, workspace_id=ws, run_id=run_id, binding=wrong, fixture_sha256=FIXTURE_SHA256)
    with pytest.raises(ScopeMismatch):  # another tenant cannot see the run at all
        load_scope(runtime, workspace_id=workspace(db), run_id=scope.run_id, binding=binding(scope),
                   fixture_sha256=FIXTURE_SHA256)


# -- migration 0008 ---------------------------------------------------------------------------------------------

def table_digests(db: AppDatabase) -> dict[str, str]:
    with db.superuser() as conn:
        tables = [row[0] for row in conn.execute(
            "SELECT format('%I.%I', schemaname, tablename) FROM pg_tables WHERE schemaname IN "
            "('app', 'identity', 'evaluation') ORDER BY 1").fetchall()]
        digests = {}
        for table in tables:
            rows = conn.execute(f"SELECT coalesce(string_agg(t::text, E'\\n' ORDER BY t::text), '') "  # noqa: S608
                                f"FROM {table} t").fetchone()[0]
            digests[table] = hashlib.sha256(rows.encode()).hexdigest()
        return digests


def grants(db: AppDatabase) -> set[tuple[Any, ...]]:
    with db.superuser() as conn:
        return {tuple(row) for row in conn.execute(
            "SELECT grantee, table_schema, table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE table_schema IN ('app', 'identity', 'evaluation') AND grantee LIKE 'policyops_%'").fetchall()}


def populate_0007(db: AppDatabase) -> RunScope:
    ws = workspace(db)
    principal = Principal(id=uuid4(), issuer="https://issuer.example.invalid", subject=f"s-{uuid4().hex}",
                          display_name="Synthetic Reviewer", created_at=NOW)
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_principal(conn, principal)
        repo.add_membership(conn, Membership(id=uuid4(), workspace_id=ws, principal_id=principal.id,
                                             role="reviewer", created_at=NOW))
    scope = case_and_run(db, ws)
    case_and_run(db, ws, customer=None)
    with workspace_transaction(db.engine(APP_RUNTIME), ws) as conn:
        repo.append_message(conn, message_id=uuid4(), scope=CaseScope(workspace_id=ws, case_id=scope.case_id),
                            source="operator_entered_customer", entered_by=principal.id, text_value="Hello",
                            created_at=NOW)
    return scope


def test_0008_upgrades_a_populated_0007_database_keeping_rows_and_grants(new_app_database: NewDatabase) -> None:
    db = new_app_database("gateway_0007_upgrade", revision="0007")
    scope = populate_0007(db)
    before, granted_before = table_digests(db), grants(db)
    assert TABLE not in before
    db.upgrade("0008")
    assert db.current() == "0008"
    after = table_digests(db)
    assert {table: digest for table, digest in after.items() if table != TABLE} == before
    with db.superuser() as conn:
        owner = conn.execute("SELECT tableowner FROM pg_tables WHERE schemaname = 'app' "
                             "AND tablename = 'customer_authentications'").fetchone()[0]
    assert owner == APP_MIGRATOR
    new_grants = {grant for grant in grants(db) - granted_before if grant[0] != owner}  # the owner holds all
    assert granted_before <= grants(db)
    assert new_grants == {(APP_RUNTIME, "app", "customer_authentications", "SELECT"),
                          (APP_RUNTIME, "app", "customer_authentications", "INSERT")}
    assert PgSessionStore(db.engine(APP_RUNTIME)).record(authentication(scope)) == authentication(scope)


def test_a_populated_0008_downgrade_is_refused_and_an_empty_one_is_reversible(new_app_database: NewDatabase) -> None:
    db = new_app_database("gateway_0008_downgrade", revision="0007")
    scope = populate_0007(db)
    before = table_digests(db)
    db.upgrade("0008")
    PgSessionStore(db.engine(APP_RUNTIME)).record(authentication(scope))
    with pytest.raises(DataLossRefused):
        db.downgrade("0007")
    assert db.current() == "0008" and PgSessionStore(db.engine(APP_RUNTIME)).load(scope) == authentication(scope)
    with db.superuser() as conn:
        conn.execute(f"DELETE FROM {TABLE}")  # noqa: S608 - test setup: empty it as the owner would
    db.downgrade("0007")
    assert db.current() == "0007" and table_digests(db) == before
    with db.superuser() as conn:
        assert conn.execute("SELECT to_regclass(%s)", (TABLE,)).fetchone() == (None,)
        assert conn.execute("SELECT count(*) FROM pg_constraint WHERE conname = 'cases_customer_binding_unique'"
                            ).fetchone() == (0,)
    db.upgrade("0008")
    assert db.current() == "0008"


def test_the_gateway_on_an_old_0007_schema_fails_closed(new_app_database: NewDatabase) -> None:
    db = new_app_database("gateway_old_schema", revision="0007")
    scope = case_and_run(db, workspace(db))
    retail = FakeRetail(state(), tenant_id=scope.workspace_id, case_id=scope.case_id)
    gateway = Gateway(GatewayScope(run=scope, binding=binding(scope), fixture_sha256=FIXTURE_SHA256),
                      retail=retail, sessions=PgSessionStore(db.engine(APP_RUNTIME)), clock=FixedClock(NOW))
    lookup = parse_result(tool("find_user_id_by_email", email=EMAIL))
    assert isinstance(lookup, ToolCallStep)
    with pytest.raises(DBAPIError):
        gateway.step(lookup, previous=None, sequence=2)
    assert retail.calls == []  # the session load failed before any retail contact
