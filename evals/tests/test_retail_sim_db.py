"""retail-simulator on real PostgreSQL, as the restricted retail roles (the owned test server; no application
import). Store protocol, concurrency, fences, row-level security and column grants, migrations, and the HTTP
authentication and limit matrix through the in-process ASGI app."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import psycopg
import pytest
from sqlalchemy import create_engine, text

from policyops_contracts.money import Money
from policyops_contracts.retail import (
    GetOrderDetails,
    ItemChangeLine,
    ItemsEffect,
    ModifyPendingOrderItems,
    ResourceVersion,
)
from policyops_contracts.retail_service import (
    FIXTURE_ID,
    FIXTURE_SHA256,
    CaseInitialization,
    FenceRequest,
    MutationRequest,
    ReadRequest,
    ServiceContext,
)
from policyops_evals.retail_sim import auth, bootstrap, codec, fixture, migrate
from policyops_evals.retail_sim.app import create_app
from policyops_evals.retail_sim.schema import DataLossRefused
from policyops_evals.retail_sim.store import (
    CaseNotFound,
    Conflict,
    Expired,
    InvalidRequest,
    NotFound,
    Replayed,
    Store,
)
from policyops_testing.postgres import OwnedPostgres


pytestmark = pytest.mark.postgres
CUSTOMER, ORDER, CARD = "james_johnson_9321", "#W1006327", "credit_card_4998749"


def source_tree() -> Path:
    explicit = os.environ.get("POLICYOPS_RETAIL_FIXTURE_TREE")
    found = Path(explicit) if explicit else fixture.find_reviewed_tree(Path(os.environ.get("UV_CACHE_DIR", "")))
    if found is None:
        pytest.fail("no verified tau2 checkout: run through scripts/devenv.py after `uv sync`")
    return found
TENANT = UUID("00000000-0000-4000-8000-000000000001")
TABLES = ("case_states", "case_resources", "operations", "token_uses", "fault_plans")


# -- databases ---------------------------------------------------------------------------------------------------

def new_database(server: OwnedPostgres, *, revision: str = "head") -> str:
    name = f"retail_{secrets.token_hex(4)}"
    server.register_database(name)
    for role in bootstrap.ROLES:
        if role not in server.passwords:
            server.register_role(role)
    with server.connect("postgres", "postgres", autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    with server.connect("postgres", name, autocommit=True) as conn:
        bootstrap.provision(conn, name, {role: server.passwords[role] for role in bootstrap.ROLES})
    migrator = create_engine("postgresql+psycopg://", creator=lambda: server.connect(bootstrap.MIGRATOR, name))
    with migrator.connect() as connection:
        migrate.upgrade(connection, revision)
    migrator.dispose()
    return name


@pytest.fixture(scope="module")
def staged(tmp_path_factory: pytest.TempPathFactory) -> tuple[fixture.Fixture, fixture.Upstream]:
    item = fixture.stage(source_tree(), tmp_path_factory.mktemp("fixture") / "root")
    return item, fixture.upstream(item)


@pytest.fixture(scope="module")
def store(postgres: OwnedPostgres, staged: Any) -> Iterator[Store]:
    name = new_database(postgres)
    engine = create_engine("postgresql+psycopg://", creator=lambda: postgres.connect(bootstrap.RUNTIME, name),
                           pool_size=8, max_overflow=0)
    item, upstream = staged
    value = Store(engine, item, upstream)
    value.require_head()
    value.name = name  # type: ignore[attr-defined]
    yield value
    engine.dispose()


def context(case_id: UUID, *, scope: str = "write", method: str = "PUT", path: str | None = None,
            body: bytes = b"", customer: str = CUSTOMER, now: int | None = None) -> ServiceContext:
    issued = int(time.time()) if now is None else now
    return ServiceContext(v="policyops.retail-auth/v1", iss="policyops-gateway", aud="retail-simulator",
                          tenant_id=TENANT, case_id=case_id, customer_id=customer, fixture_sha256=FIXTURE_SHA256,
                          scope=scope, method=method, path=path or f"/v1/cases/{case_id}",  # type: ignore[arg-type]
                          body_sha256=hashlib.sha256(body).hexdigest(), iat=issued, exp=issued + 30, jti=uuid4())


def initialized(store: Store, customer: str = CUSTOMER) -> UUID:
    case_id = uuid4()
    store.initialize(context(case_id, customer=customer),
                     CaseInitialization(fixture_id=FIXTURE_ID, fixture_sha256=FIXTURE_SHA256, customer_id=customer))
    return case_id


def single_item(order_version: int = 1, user_version: int = 1, *, price_after: int = 5201,
                intent: str = "a" * 64) -> MutationRequest:
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                   payment_method_id=CARD)
    change = ItemChangeLine(item_id="5172162216", new_item_id="4068787148", product_id="1808611083",
                            price_before=Money(amount_minor=4851), price_after=Money(amount_minor=price_after))
    effect = ItemsEffect(kind="modify_pending_order_items", order_id=ORDER, changes=(change,),
                         price_difference=Money(amount_minor=price_after - 4851), payment_method_id=CARD,
                         status_before="pending", status_after="pending (item modified)")
    return MutationRequest(call=call, expected_effect=effect, intent_sha256=intent, expected_versions=(
        ResourceVersion(kind="order", resource_id=ORDER, version=order_version),
        ResourceVersion(kind="user", resource_id=CUSTOMER, version=user_version),
        ResourceVersion(kind="product", resource_id="1808611083", version=1)))


def inventory(store: Store, case_id: UUID) -> dict[str, Any]:
    with store._tx(TENANT, case_id) as c:
        return {"state": c.execute(text("SELECT version, state_sha256 FROM retail.case_states")).all(),
                "resources": c.execute(text("SELECT kind, resource_id, version FROM retail.case_resources "
                                            "ORDER BY 1, 2")).all(),
                "operations": c.execute(text("SELECT operation_id, outcome FROM retail.operations ORDER BY 1")).all()}


# -- initialization ----------------------------------------------------------------------------------------------

def test_initialization_replays_and_never_resets_or_rebinds(store: Store) -> None:
    case_id = initialized(store)
    init = CaseInitialization(fixture_id=FIXTURE_ID, fixture_sha256=FIXTURE_SHA256, customer_id=CUSTOMER)
    again = store.initialize(context(case_id), init)
    assert (again.created, again.case_version) == (False, 1)
    other = CaseInitialization(fixture_id=FIXTURE_ID, fixture_sha256=FIXTURE_SHA256, customer_id="raj_sanchez_2970")
    with pytest.raises(Conflict):
        store.initialize(context(case_id, customer="raj_sanchez_2970"), other)


@pytest.mark.parametrize("customers", [(CUSTOMER, CUSTOMER), (CUSTOMER, "raj_sanchez_2970")])
def test_concurrent_initialization_of_a_missing_case_has_one_winner(store: Store, customers: tuple[str, str]) -> None:
    case_id, barrier = uuid4(), threading.Barrier(2)
    results: list[Any] = []

    def run(customer: str) -> None:
        barrier.wait()
        try:
            results.append(store.initialize(context(case_id, customer=customer), CaseInitialization(
                fixture_id=FIXTURE_ID, fixture_sha256=FIXTURE_SHA256, customer_id=customer)).created)
        except Conflict:
            results.append("conflict")
    threads = [threading.Thread(target=run, args=(c,)) for c in customers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    expected = [False, True] if customers[0] == customers[1] else ["conflict", True]
    assert sorted(results, key=str) == sorted(expected, key=str)
    assert len(inventory(store, case_id)["state"]) == 1


# -- reads -------------------------------------------------------------------------------------------------------

def test_reads_are_exact_scoped_and_persist_nothing(store: Store) -> None:
    case_id = initialized(store)
    before = inventory(store, case_id)
    result = store.read(context(case_id, scope="read"), ReadRequest(call=GetOrderDetails(order_id=ORDER)))
    assert result.output.kind == "order" and result.case_version == 1
    assert [(v.kind, v.resource_id, v.version) for v in result.resource_versions] == [("order", ORDER, 1)]
    with pytest.raises(NotFound):
        store.read(context(case_id, scope="read"), ReadRequest(call=GetOrderDetails(order_id="#W1067251")))
    assert inventory(store, case_id) == before
    with pytest.raises(CaseNotFound):
        store.read(context(uuid4(), scope="read"), ReadRequest(call=GetOrderDetails(order_id=ORDER)))


# -- mutations ---------------------------------------------------------------------------------------------------

def test_a_mutation_commits_once_and_replays_its_receipt(store: Store) -> None:
    case_id, op = initialized(store), uuid4()
    first = store.mutate(context(case_id), op, single_item())
    assert first.outcome == "committed" and first.receipt is not None and not first.replayed
    assert first.receipt.case_version_after == 2
    after = {(v.kind, v.resource_id): v.version for v in first.receipt.resource_versions_after}
    assert after == {("order", ORDER): 2, ("user", CUSTOMER): 1, ("product", "1808611083"): 1}
    replay = store.mutate(context(case_id), op, single_item())
    assert replay.replayed and replay.receipt == first.receipt
    with pytest.raises(Conflict):
        store.mutate(context(case_id), op, single_item(intent="b" * 64))  # same arguments, another intent
    state = inventory(store, case_id)
    assert state["state"][0][0] == 2 and [o[1] for o in state["operations"]] == ["committed"]


def test_rejections_are_terminal_rows_that_change_nothing_else(store: Store) -> None:
    case_id = initialized(store)
    before = inventory(store, case_id)
    wrong = uuid4()
    result = store.mutate(context(case_id), wrong, single_item(price_after=5202))
    assert (result.outcome, result.receipt) == ("effect_mismatch", None)
    after = inventory(store, case_id)
    assert (after["state"], after["resources"]) == (before["state"], before["resources"])
    assert after["operations"] == [(wrong, "effect_mismatch")]  # exactly the declared failure record
    assert store.mutate(context(case_id), wrong, single_item(price_after=5202)).replayed


def test_an_upstream_change_outside_the_approved_fields_rolls_back(store: Store, staged: Any) -> None:
    """F4 regression through the store and PostgreSQL: an upstream tool that also renames the target item (simulated by
    wrapping the real tool) is an effect mismatch; only the failure record is written."""
    item, upstream = staged

    class Renaming:
        def __init__(self, db: Any) -> None:
            self.real = upstream.retail_tools(db)
            self.db = db

        def modify_pending_order_items(self, **arguments: Any) -> Any:
            result = self.real.modify_pending_order_items(**arguments)
            for line in self.db.orders[arguments["order_id"]].items:
                if line.item_id in arguments["new_item_ids"]:
                    line.name = "UNAPPROVED-ITEM-RENAME"
            return result
    renaming = Store(store.engine, item, fixture.Upstream(upstream.retail_db, Renaming))
    case_id = initialized(renaming)
    before = inventory(renaming, case_id)
    op = uuid4()
    result = renaming.mutate(context(case_id), op, single_item())
    assert (result.outcome, result.receipt) == ("effect_mismatch", None)
    after = inventory(renaming, case_id)
    assert (after["state"], after["resources"]) == (before["state"], before["resources"])
    assert after["operations"] == [(op, "effect_mismatch")]
    with renaming._tx(TENANT, case_id) as c:
        assert c.execute(text("SELECT code FROM retail.operations")).scalar() == "unexpected_change"


def test_a_stale_version_is_a_terminal_version_conflict(store: Store) -> None:
    case_id = initialized(store)
    store.mutate(context(case_id), uuid4(), single_item())  # order is now version 2
    stale = uuid4()
    result = store.mutate(context(case_id), stale, single_item())
    assert result.outcome == "version_conflict" and result.receipt is None
    again = store.mutate(context(case_id), stale, single_item())
    assert again.replayed and again.outcome == "version_conflict"  # matching retry: the same rejection
    with pytest.raises(Conflict):
        store.mutate(context(case_id), stale, single_item(order_version=2))  # changed payload, same accepted ID


def test_version_coverage_must_be_exact_and_scope_is_enforced(store: Store) -> None:
    case_id = initialized(store)
    request = single_item()
    for versions in (request.expected_versions[:2], request.expected_versions[1:]):
        with pytest.raises(InvalidRequest):
            store.mutate(context(case_id), uuid4(), request.model_copy(update={"expected_versions": versions}))
    foreign = initialized(store, customer="raj_sanchez_2970")
    with pytest.raises(NotFound):
        store.mutate(context(foreign, customer="raj_sanchez_2970"), uuid4(), request)
    assert inventory(store, case_id)["operations"] == []


def test_concurrent_identical_requests_commit_once(store: Store) -> None:
    case_id, op, barrier, results = initialized(store), uuid4(), threading.Barrier(2), []

    def run() -> None:
        barrier.wait()
        results.append(store.mutate(context(case_id), op, single_item()))
    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert sorted(r.replayed for r in results) == [False, True]
    assert results[0].receipt == results[1].receipt and inventory(store, case_id)["state"][0][0] == 2


# -- fences and lookups ------------------------------------------------------------------------------------------

def test_a_lookup_never_fences_and_a_fence_blocks_a_late_original(store: Store) -> None:
    case_id = initialized(store)
    request, op = single_item(), uuid4()
    assert store.lookup(context(case_id, scope="read"), op).state == "unknown"
    assert store.mutate(context(case_id), op, request).outcome == "committed"  # the lookup did not suppress it
    late = uuid4()
    fingerprint = store.fingerprint(context(case_id), late, single_item(order_version=2))
    fenced = store.fence(context(case_id), late, FenceRequest(operation_sha256=fingerprint))
    assert fenced.outcome == "fenced" and fenced.receipt is None
    replayed = store.mutate(context(case_id), late, single_item(order_version=2))
    assert replayed.replayed and replayed.outcome == "fenced"
    with pytest.raises(Conflict):
        store.fence(context(case_id), op, FenceRequest(operation_sha256="c" * 64))
    assert store.fence(context(case_id), op, FenceRequest(operation_sha256=store.fingerprint(
        context(case_id), op, request))).outcome == "committed"


def test_a_context_that_expires_while_waiting_for_the_case_lock_applies_nothing(
        postgres: OwnedPostgres, staged: Any) -> None:
    """Controlled clock: the context is valid at entry, the case lock is held by another transaction, the clock is
    advanced past `exp` during the wait, then the lock is released. No row, state or version may change."""
    name = new_database(postgres)
    engine_ = create_engine("postgresql+psycopg://", creator=lambda: postgres.connect(bootstrap.RUNTIME, name),
                            pool_size=4, max_overflow=0)
    offset = [0.0]
    item, upstream = staged
    timed = Store(engine_, item, upstream, clock=lambda: datetime.fromtimestamp(time.time() + offset[0], UTC))
    try:
        case_id = initialized(timed)
        before = inventory(timed, case_id)
        outcome: list[Any] = []
        holder = postgres.connect(bootstrap.RUNTIME, name)
        try:
            holder.execute("SELECT set_config('retail.tenant_id', %s, true), set_config('retail.case_id', %s, true)",
                           (str(TENANT), str(case_id)))
            holder.execute("SELECT 1 FROM retail.case_states FOR UPDATE")

            def run() -> None:
                try:
                    outcome.append(timed.mutate(context(case_id), uuid4(), single_item()))
                except Exception as error:
                    outcome.append(error)
            waiter = threading.Thread(target=run)
            waiter.start()
            time.sleep(0.5)  # the mutation is now blocked on the case lock (lock_timeout is 2 s)
            offset[0] = 120.0  # the context's 30 s lifetime has passed while it waited
            holder.rollback()
            waiter.join(30)
        finally:
            holder.close()
        assert len(outcome) == 1 and isinstance(outcome[0], Expired)
        assert inventory(timed, case_id) == before  # no effect, no success receipt, no failure record
    finally:
        engine_.dispose()


def test_a_nonce_is_single_use(store: Store) -> None:
    case_id = initialized(store)
    used = context(case_id)
    store.use_nonce(used)
    with pytest.raises(Replayed):
        store.use_nonce(used)


# -- row-level security and grants as the actual runtime role ---------------------------------------------------

def test_the_runtime_role_sees_only_its_scope_and_cannot_rewrite_identity_or_outcomes(
        store: Store, postgres: OwnedPostgres) -> None:
    case_id = initialized(store)
    store.mutate(context(case_id), uuid4(), single_item())
    with postgres.connect(bootstrap.RUNTIME, store.name) as conn:  # type: ignore[attr-defined]
        conn.execute("SELECT set_config('retail.tenant_id', %s, true), set_config('retail.case_id', %s, true)",
                     (str(TENANT), str(uuid4())))
        assert all((conn.execute(f"SELECT count(*) FROM retail.{t}").fetchone() or [None])[0] == 0  # noqa: S608
                   for t in TABLES)  # fixed table names
        conn.rollback()
        conn.execute("SELECT set_config('retail.tenant_id', %s, true), set_config('retail.case_id', %s, true)",
                     (str(TENANT), str(case_id)))
        for statement in ("UPDATE retail.case_states SET customer_id = 'raj_sanchez_2970'",
                          "UPDATE retail.case_states SET fixture_sha256 = repeat('0', 64)",
                          "UPDATE retail.operations SET outcome = 'fenced'", "DELETE FROM retail.operations",
                          "DELETE FROM retail.case_states", "CREATE TABLE retail.extra (x int)"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
            conn.rollback()
            conn.execute("SELECT set_config('retail.tenant_id', %s, true), set_config('retail.case_id', %s, true)",
                         (str(TENANT), str(case_id)))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # RLS WITH CHECK: another tenant's row
            conn.execute("INSERT INTO retail.token_uses VALUES (%s, %s, %s, now() + interval '1 minute')",
                         (str(uuid4()), str(case_id), str(uuid4())))
        conn.rollback()


# -- migrations --------------------------------------------------------------------------------------------------

def test_populated_first_revision_upgrades_and_downgrades_are_refused(postgres: OwnedPostgres, staged: Any) -> None:
    name = new_database(postgres, revision="r0001")
    runtime = create_engine("postgresql+psycopg://", creator=lambda: postgres.connect(bootstrap.RUNTIME, name))
    migrator = create_engine("postgresql+psycopg://", creator=lambda: postgres.connect(bootstrap.MIGRATOR, name))
    item, upstream = staged
    try:
        early = Store(runtime, item, upstream)
        with pytest.raises(RuntimeError):
            early.require_head()  # the runtime refuses a non-head schema
        case_id = uuid4()
        raw = codec.encode(codec.decode(item.raw, upstream.retail_db))
        with early._tx(TENANT, case_id) as c:
            c.execute(text("INSERT INTO retail.case_states VALUES (:t, :c, :u, :f, :s, 'retail-state/v1', 1, :raw, "
                           ":h, now(), now())"), {"t": TENANT, "c": case_id, "u": CUSTOMER, "f": FIXTURE_ID,
                                                  "s": FIXTURE_SHA256, "raw": raw, "h": codec.digest(raw)})
            c.execute(text("INSERT INTO retail.case_resources VALUES (:t, :c, 'user', :u, 1), "
                           "(:t, :c, 'order', :o, 1)"),
                      {"t": TENANT, "c": case_id, "u": CUSTOMER, "o": ORDER})
        with migrator.connect() as connection:
            migrate.upgrade(connection)
            assert migrate.current(connection) == migrate.head() == "r0002"
        upgraded = Store(runtime, item, upstream)
        upgraded.require_head()
        assert upgraded.mutate(context(case_id), uuid4(), single_item()).outcome == "committed"  # r0001 data works
        with migrator.connect() as connection:
            with pytest.raises(DataLossRefused):
                migrate.downgrade(connection, "base")  # r0002 now holds an operation: refused before any drop
            assert migrate.current(connection) == "r0002"
        with early._tx(TENANT, case_id) as c:
            assert c.execute(text("SELECT version FROM retail.case_states")).scalar() == 2
    finally:
        migrator.dispose()
        runtime.dispose()


# -- HTTP: authentication, limits and faults through the ASGI app -----------------------------------------------

KEY = auth.Key(b"k" * 32)


@pytest.fixture
def client(store: Store) -> Iterator[Callable[..., Any]]:
    app = TestClient(create_app(store, KEY, faults_enabled=True))

    def call(method: str, url: str, body: Any = None, *, scope: str = "write", sign: bool = True,
             token: ServiceContext | None = None, headers: dict[str, str] | None = None, raw: bytes | None = None,
             **changes: Any) -> Any:
        path = url
        data = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        case_id = UUID(path.split("/")[3])
        signed = token or context(case_id, scope=scope, method=method, path=path, body=data).model_copy(
            update=changes)
        sent = dict(headers or {})
        if sign:
            sent["authorization"] = f"Bearer {auth.sign(signed, KEY)}"
        return app.request(method, path, content=data, headers=sent)
    yield call
    app.close()


def test_http_initialize_read_mutate_and_reconcile_after_a_lost_commit(client: Callable[..., Any]) -> None:
    case_id = uuid4()
    base = f"/v1/cases/{case_id}"
    init = {"fixture_id": FIXTURE_ID, "fixture_sha256": FIXTURE_SHA256, "customer_id": CUSTOMER}
    assert client("PUT", base, init).status_code == 201 and client("PUT", base, init).status_code == 200
    assert client("POST", f"{base}/reads", {"call": {"tool": "get_order_details", "order_id": ORDER}},
                  scope="read").status_code == 200
    assert client("PUT", f"{base}/faults", {"fault": "commit_then_503", "count": 1}).status_code == 204
    op = uuid4()
    lost = client("PUT", f"{base}/operations/{op}", json.loads(single_item().model_dump_json()))
    assert lost.status_code == 503 and lost.headers["x-policyops-fault"] == "commit_then_503"
    found = client("GET", f"{base}/operations/{op}", scope="read").json()
    assert found["state"] == "found" and found["result"]["outcome"] == "committed"
    again = client("PUT", f"{base}/operations/{op}", json.loads(single_item().model_dump_json())).json()
    assert again["replayed"] and again["receipt"] == found["result"]["receipt"]


@pytest.mark.parametrize("variant", ["none", "two_headers", "bad_signature", "expired", "future", "wrong_path",
                                     "wrong_body", "query", "read_scope", "replayed", "duplicate_key", "too_large",
                                     "chunked_too_large", "calculator_power"])
def test_http_refuses_unauthenticated_uncovered_or_unbounded_requests(store: Store, client: Callable[..., Any],
                                                                      variant: str) -> None:
    case_id = initialized(store)
    base = f"/v1/cases/{case_id}/reads"
    body = {"call": {"tool": "get_order_details", "order_id": ORDER}}
    now = int(time.time())
    status = {"none": 401, "two_headers": 401, "bad_signature": 401, "expired": 401, "future": 401,
              "wrong_path": 403, "wrong_body": 403, "query": 403, "read_scope": 403, "replayed": 401,
              "duplicate_key": 400, "too_large": 413, "chunked_too_large": 413, "calculator_power": 400}[variant]
    if variant == "none":
        response = client("POST", base, body, sign=False)
    elif variant == "two_headers":
        token = auth.sign(context(case_id, scope="read", method="POST", path=base,
                                  body=json.dumps(body).encode()), KEY)
        response = TestClient(create_app(store, KEY)).request(
            "POST", base, content=json.dumps(body).encode(),
            headers=[("authorization", f"Bearer {token}"), ("authorization", f"Bearer {token}")])
    elif variant == "bad_signature":
        response = TestClient(create_app(store, auth.Key(b"x" * 32))).request(
            "POST", base, content=json.dumps(body).encode(), headers={"authorization": "Bearer e30.AAAA"})
    elif variant == "expired":
        response = client("POST", base, body, scope="read", iat=now - 120, exp=now - 60)
    elif variant == "future":
        response = client("POST", base, body, scope="read", iat=now + 30, exp=now + 60)
    elif variant == "wrong_path":
        response = client("POST", base, body, scope="read", path=f"/v1/cases/{case_id}")
    elif variant == "wrong_body":
        response = client("POST", base, body, scope="read", body_sha256="0" * 64)
    elif variant == "query":
        signed = context(case_id, scope="read", method="POST", path=base, body=json.dumps(body).encode())
        response = TestClient(create_app(store, KEY)).request(
            "POST", base + "?x=1", content=json.dumps(body).encode(),
            headers={"authorization": f"Bearer {auth.sign(signed, KEY)}"})
    elif variant == "read_scope":
        response = client("PUT", f"/v1/cases/{case_id}/operations/{uuid4()}",
                          json.loads(single_item().model_dump_json()), scope="read")
    elif variant == "replayed":
        signed = context(case_id, scope="read", method="POST", path=base, body=json.dumps(body).encode())
        assert client("POST", base, body, token=signed).status_code == 200
        response = client("POST", base, body, token=signed)
    elif variant == "duplicate_key":
        raw = b'{"call": {"tool": "get_order_details", "order_id": "#W1006327", "order_id": "#W1006327"}}'
        response = client("POST", base, raw=raw, scope="read")
    elif variant == "too_large":
        response = client("POST", base, raw=b" " * (70 * 1024), scope="read")
    elif variant == "chunked_too_large":
        def chunks() -> Iterator[bytes]:
            for _ in range(70):
                yield b" " * 1024
        signed = context(case_id, scope="read", method="POST", path=base, body=b" " * 70 * 1024)
        response = TestClient(create_app(store, KEY)).request(
            "POST", base, content=chunks(), headers={"authorization": f"Bearer {auth.sign(signed, KEY)}"})
    else:
        response = client("POST", base, {"call": {"tool": "calculate", "expression": "9 ** 9 ** 9"}}, scope="read")
    assert response.status_code == status, (variant, response.status_code)
    assert set(response.json()) == {"schema_version", "code", "detail", "rule_id", "correlation_id", "retryable"}


def test_the_fault_endpoint_does_not_exist_by_default(store: Store) -> None:
    case_id = initialized(store)
    path = f"/v1/cases/{case_id}/faults"
    data = json.dumps({"fault": "fail_503_before", "count": 1}).encode()
    token = auth.sign(context(case_id, method="PUT", path=path, body=data), KEY)
    response = TestClient(create_app(store, KEY)).request("PUT", path, content=data,
                                                          headers={"authorization": f"Bearer {token}"})
    assert response.status_code in (404, 405)


# -- acceptance interleavings and restore (G1) -------------------------------------------------------------------

class Gate:
    """Hold one thread at a chosen point until released; the other thread is then provably waiting on the lock."""

    def __init__(self) -> None:
        self.reached, self.release = threading.Event(), threading.Event()

    def hold(self) -> None:
        self.reached.set()
        assert self.release.wait(30)


def run_in_thread(target: Callable[[], Any]) -> tuple[threading.Thread, list[Any]]:
    out: list[Any] = []

    def run() -> None:
        try:
            out.append(target())
        except Exception as error:
            out.append(error)
    thread = threading.Thread(target=run)
    thread.start()
    return thread, out


def test_a_read_is_coherent_while_a_writer_waits(store: Store, monkeypatch: pytest.MonkeyPatch) -> None:
    """D6: the read holds FOR SHARE on the case between its state and version SELECTs; a writer blocks until the
    read ends, so the read's state and versions are one snapshot."""
    case_id, gate, mine = initialized(store), Gate(), threading.local()
    real_versions = Store._versions

    def versions(c: Any) -> dict[Any, int]:
        if getattr(mine, "reader", False):
            gate.hold()  # between the state SELECT and the versions SELECT
        return real_versions(c)
    monkeypatch.setattr(Store, "_versions", staticmethod(versions))

    def read() -> Any:
        mine.reader = True
        return store.read(context(case_id, scope="read"), ReadRequest(call=GetOrderDetails(order_id=ORDER)))
    reader, read_out = run_in_thread(read)
    assert gate.reached.wait(30)
    writer, write_out = run_in_thread(lambda: store.mutate(context(case_id), uuid4(), single_item()))
    time.sleep(0.5)
    assert not write_out  # the writer is waiting for the reader's share lock
    gate.release.set()
    reader.join(30)
    writer.join(30)
    result = read_out[0]
    assert result.case_version == 1 and result.output.order.version == 1  # one consistent pre-write snapshot
    assert [(v.kind, v.version) for v in result.resource_versions] == [("order", 1)]
    assert write_out[0].outcome == "committed" and write_out[0].receipt.case_version_after == 2


@pytest.mark.parametrize("first", ["mutation", "fence"])
def test_a_mutation_and_a_fence_for_one_operation_serialize_either_way(store: Store, first: str,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    """D1/D2: whichever holds the case lock first wins; the other then replays that outcome. Exactly one of commit
    or fence takes effect, never both."""
    case_id, op, gate, mine = initialized(store), uuid4(), Gate(), threading.local()
    request = single_item()
    fingerprint = store.fingerprint(context(case_id), op, request)
    real_existing = Store._existing

    def existing(self: Store, c: Any, operation_id: UUID) -> Any:
        if getattr(mine, "first", False):
            gate.hold()  # the first caller holds the case lock here, before its lookup
        return real_existing(self, c, operation_id)
    monkeypatch.setattr(Store, "_existing", existing)

    def mutation() -> Any:
        mine.first = first == "mutation"
        return store.mutate(context(case_id), op, request)

    def fence() -> Any:
        mine.first = first == "fence"
        return store.fence(context(case_id), op, FenceRequest(operation_sha256=fingerprint))
    leader, follower = (mutation, fence) if first == "mutation" else (fence, mutation)
    lead, lead_out = run_in_thread(leader)
    assert gate.reached.wait(30)
    follow, follow_out = run_in_thread(follower)
    time.sleep(0.5)
    assert not follow_out  # blocked on the case lock
    gate.release.set()
    lead.join(30)
    follow.join(30)
    winner = "committed" if first == "mutation" else "fenced"
    assert lead_out[0].outcome == winner and not lead_out[0].replayed
    assert follow_out[0].outcome == winner and follow_out[0].replayed
    state = inventory(store, case_id)
    assert state["operations"] == [(op, winner)] and state["state"][0][0] == (2 if winner == "committed" else 1)


def test_a_dump_restores_into_a_separate_database_with_state_resources_and_outcomes(
        postgres: OwnedPostgres, staged: Any) -> None:
    """D11: a consistent dump of a populated retail database restores into a separate, empty database; identity,
    state, versions, outcomes and receipts are unchanged there, a replay returns the original receipt, and new work
    continues."""
    source = new_database(postgres)
    item, upstream = staged
    engines = []

    def store_for(name: str) -> Store:
        engines.append(create_engine("postgresql+psycopg://",
                                     creator=lambda: postgres.connect(bootstrap.RUNTIME, name)))
        value = Store(engines[-1], item, upstream)
        value.require_head()
        return value
    try:
        original = store_for(source)
        case_id, op = initialized(original), uuid4()
        committed = original.mutate(context(case_id), op, single_item())
        rejected_op = uuid4()
        original.mutate(context(case_id), rejected_op, single_item(order_version=2, price_after=5202))
        fenced_op = uuid4()
        fenced_sha = original.fingerprint(context(case_id), fenced_op, single_item(order_version=2))
        assert original.fence(context(case_id), fenced_op, FenceRequest(operation_sha256=fenced_sha)).outcome == \
            "fenced"
        before = inventory(original, case_id)
        # The second request names the item the first commit replaced: upstream rejects it (a terminal row).
        assert {o[1] for o in before["operations"]} == {"committed", "upstream_rejected", "fenced"}
        target = f"retail_restore_{secrets.token_hex(3)}"
        postgres.register_database(target)
        with postgres.connect("postgres", "postgres", autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{target}"')
        postgres.dump_and_restore(source, target)
        with postgres.connect("postgres", target, autocommit=True) as conn:  # database-level grants; isolation check
            bootstrap.provision(conn, target, {role: postgres.passwords[role] for role in bootstrap.ROLES})
        restored = store_for(target)
        assert inventory(restored, case_id) == before
        replay = restored.mutate(context(case_id), op, single_item())
        assert replay.replayed and replay.receipt == committed.receipt
        assert restored.mutate(context(case_id), rejected_op, single_item(order_version=2, price_after=5202)).replayed
        late = restored.mutate(context(case_id), fenced_op, single_item(order_version=2))
        assert late.replayed and late.outcome == "fenced"  # the late original stays fenced after the restore
        later = restored.mutate(context(case_id), uuid4(), single_item(order_version=2))  # new work: item gone now
        assert later.outcome == "upstream_rejected" and inventory(restored, case_id)["state"] == before["state"]
    finally:
        for engine_ in engines:
            engine_.dispose()
