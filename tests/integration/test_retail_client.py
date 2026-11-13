"""End to end: the application's retail client against the real evals-owned retail-simulator process and real
PostgreSQL, plus the application/retail role cross-denial in one shared database.

The service runs as an owned child process of the evals interpreter (no import across the two projects): staged
from the reviewed fixture, bootstrapped and migrated by its own CLI, listening on one registered loopback port. It
is stopped with a bounded terminate/kill whose exit is confirmed; a restart reuses the same database.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any
from uuid import uuid4

import httpx
import psycopg
from pydantic import BaseModel
import pytest

from policyops.adapters.retail_client import RetailClient, Unknown
from policyops.persistence.roles import APP_RUNTIME, EVAL_RUNTIME
from policyops_contracts.money import Money
from policyops_contracts.retail import (
    Address,
    GetOrderDetails,
    GetUserDetails,
    ItemChangeLine,
    ItemsEffect,
    ModifyPendingOrderItems,
    ModifyUserAddress,
    ResourceVersion,
    UserAddressEffect,
)
from policyops_contracts.retail_service import CaseState, LookupResult, MutationRequest, OperationResult, ReadResult
from policyops_testing.app_database import NewDatabase
from policyops_testing.postgres import OwnedPostgres
from policyops_testing.safety.retail import (
    CARD as CARD,
)
from policyops_testing.safety.retail import (
    CUSTOMER as CUSTOMER,
)
from policyops_testing.safety.retail import (
    ORDER as ORDER,
)
from policyops_testing.safety.retail import (
    RETAIL_ROLES as RETAIL_ROLES,
)
from policyops_testing.safety.retail import (
    Service as Service,
)
from policyops_testing.safety.retail import (
    cli as cli,
)
from policyops_testing.safety.retail import (
    evals_environment as evals_environment,
)
from policyops_testing.safety.retail import (
    evals_python as evals_python,
)
from policyops_testing.safety.retail import (
    free_port as free_port,
)
from policyops_testing.safety.retail import (
    reviewed_tree as reviewed_tree,
)
from policyops_testing.safety.retail import (
    stop as stop,
)


pytestmark = pytest.mark.postgres



@pytest.fixture
def service(postgres: OwnedPostgres, new_app_database: NewDatabase, tmp_path: Path) -> Service:
    return Service(postgres, new_app_database("retail"), tmp_path)


TENANT = uuid4()


def client(service: Service, origin: str, case_id: Any) -> RetailClient:
    return RetailClient(origin, service.key, tenant_id=TENANT, case_id=case_id, customer_id=CUSTOMER)


def single_item(order_version: int = 1) -> MutationRequest:
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                   payment_method_id=CARD)
    effect = ItemsEffect(kind="modify_pending_order_items", order_id=ORDER, changes=(ItemChangeLine(
        item_id="5172162216", new_item_id="4068787148", product_id="1808611083",
        price_before=Money(amount_minor=4851), price_after=Money(amount_minor=5201)),),
        price_difference=Money(amount_minor=350), payment_method_id=CARD, status_before="pending",
        status_after="pending (item modified)")
    return MutationRequest(call=call, expected_effect=effect, intent_sha256="a" * 64, expected_versions=(
        ResourceVersion(kind="order", resource_id=ORDER, version=order_version),
        ResourceVersion(kind="user", resource_id=CUSTOMER, version=1),
        ResourceVersion(kind="product", resource_id="1808611083", version=1)))


def new_address(before: Address) -> MutationRequest:
    after = Address(address1="1 Test Way", address2="", city="Springfield", state="IL", country="USA", zip="62701")
    return MutationRequest(call=ModifyUserAddress(user_id=CUSTOMER, **after.model_dump()),
                           expected_effect=UserAddressEffect(user_id=CUSTOMER, address_before=before,
                                                             address_after=after),
                           intent_sha256="b" * 64,
                           expected_versions=(ResourceVersion(kind="user", resource_id=CUSTOMER, version=1),))


class Fault(BaseModel):
    fault: str
    count: int


def test_client_and_service_commit_reconcile_restart_replay_and_fence(service: Service) -> None:
    case_id, committed, lost, fenced = uuid4(), uuid4(), uuid4(), uuid4()
    with service.running() as origin:
        retail = client(service, origin, case_id)
        try:
            state = retail.initialize()
            assert isinstance(state, CaseState) and state.created and state.case_version == 1
            read = retail.read(GetOrderDetails(order_id=ORDER))
            assert isinstance(read, ReadResult) and read.output.kind == "order"
            first = retail.mutate(committed, single_item())
            assert isinstance(first, OperationResult) and first.outcome == "committed" and first.receipt
            sent = retail._send("PUT", retail._path("faults"), "write",
                                Fault(fault="commit_then_503", count=1))
            assert not isinstance(sent, Unknown) and sent.status_code == 204
            user = retail.read(GetUserDetails(user_id=CUSTOMER))
            assert isinstance(user, ReadResult) and user.output.kind == "user"
            address = new_address(user.output.user.address)
            fenced_request = single_item(order_version=2)
            assert retail.mutate(lost, address) == Unknown("http_503")  # committed, reply lost
            found = retail.lookup(lost, address)
            assert isinstance(found, LookupResult) and found.result is not None
            assert found.result.outcome == "committed"
        finally:
            retail.close()
    with service.running() as origin:  # a restarted process, the same database
        retail = client(service, origin, case_id)
        try:
            replay = retail.mutate(committed, single_item())
            assert isinstance(replay, OperationResult) and replay.replayed and replay.receipt == first.receipt
            fence = retail.fence(fenced, fenced_request)
            assert isinstance(fence, OperationResult) and fence.outcome == "fenced"
            late = retail.mutate(fenced, fenced_request)
            assert isinstance(late, OperationResult) and late.replayed and late.outcome == "fenced"
            final = retail.read(GetOrderDetails(order_id=ORDER))
            assert isinstance(final, ReadResult) and final.case_version == 3  # exactly two committed effects
        finally:
            retail.close()


def test_application_and_retail_roles_cannot_reach_each_others_schemas(service: Service) -> None:
    server, name = service.server, service.database.name
    for role, statement in ((APP_RUNTIME, "SELECT count(*) FROM retail.case_states"),
                            (EVAL_RUNTIME, "SELECT count(*) FROM retail.operations"),
                            ("retail_runtime", "SELECT count(*) FROM app.cases"),
                            ("retail_migrator", "SELECT count(*) FROM app.cases")):
        with server.connect(role, name) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement)


def test_service_cleanup_owns_acquisition_and_preserves_the_setup_error(tmp_path: Path,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    """N1 regression with fake processes (no service, database or network): a spawn failure still closes the log and
    surfaces its own error; a readiness failure still stops the process and closes the log."""
    opened: list[Any] = []
    real_open = Path.open

    def tracking_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = real_open(self, *args, **kwargs)
        opened.append(handle)
        return handle
    monkeypatch.setattr(Path, "open", tracking_open)
    service = object.__new__(Service)
    service.root, service.db, service.port = tmp_path, ["--db-port", "1", "--db-name", "x"], 9
    monkeypatch.setitem(globals(), "evals_python", lambda: Path("python"))  # restored after the test

    def spawn_fails(*args: Any, **kwargs: Any) -> Any:
        raise OSError("spawn failed")
    monkeypatch.setattr(subprocess, "Popen", spawn_fails)
    with pytest.raises(OSError, match="spawn failed"), service.running():
        pass
    assert opened and all(handle.closed for handle in opened)

    class Exits:
        returncode = 3
        stopped = False

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.stopped = True

        def wait(self, timeout: float) -> int:
            return self.returncode

        def kill(self) -> None:
            self.stopped = True
    fake = Exits()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake)
    # The original readiness error, not cleanup's.
    with pytest.raises(pytest.fail.Exception, match="exited early"), service.running():
        pass
    assert fake.stopped and all(handle.closed for handle in opened)


def test_a_setup_error_keeps_unconfirmed_cleanup_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """N1 (C5 diagnostic branch) with fake processes: readiness fails and the child cannot be confirmed stopped. The
    original error propagates unchanged and carries the cleanup problem as a note; the log is still closed."""
    opened: list[Any] = []
    real_open = Path.open

    def tracking_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = real_open(self, *args, **kwargs)
        opened.append(handle)
        return handle
    monkeypatch.setattr(Path, "open", tracking_open)
    service = object.__new__(Service)
    service.root, service.db, service.port = tmp_path, ["--db-port", "1", "--db-name", "x"], 9
    monkeypatch.setitem(globals(), "evals_python", lambda: Path("python"))

    class Unstoppable:
        returncode = None

        def poll(self) -> int | None:
            return None  # never confirmed stopped

        def terminate(self) -> None:
            raise OSError("controlled stop failure")

        def wait(self, timeout: float) -> int:
            raise subprocess.TimeoutExpired("python", timeout)

        def kill(self) -> None:
            raise OSError("controlled kill failure")

    class SetupFailure(Exception):
        pass
    original = SetupFailure("controlled readiness failure")

    def not_ready(*args: Any, **kwargs: Any) -> Any:
        raise original
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Unstoppable())
    monkeypatch.setattr(httpx, "get", not_ready)
    with pytest.raises(SetupFailure) as raised, service.running():
        pass
    assert raised.value is original
    notes = getattr(raised.value, "__notes__", [])
    assert notes == ["service cleanup: the service process did not stop; the service process is still running"]
    assert opened and all(handle.closed for handle in opened)
