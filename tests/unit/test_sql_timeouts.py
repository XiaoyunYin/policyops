"""Phase classification and transaction ownership without sockets; PostgreSQL behavior is tested separately."""

import asyncio
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import errors
import pytest
from sqlalchemy.exc import DBAPIError

from policyops.persistence.database import (
    DatabaseUnavailable,
    SqlTimeouts,
    TransactionCommitCancelled,
    TransactionOutcomeUnknown,
    classify_sql_failure,
    transaction,
)


@pytest.mark.parametrize("original,state,reconcile", [
    (errors.LockNotAvailable(), "55P03", False), (errors.QueryCanceled(), "57014", False),
    (errors.IdleInTransactionSessionTimeout(), "25P03", True),
    (errors.ConnectionFailure(), "08006", True),
])
def test_transient_sqlstates_are_safe_phase_metadata(original: Exception, state: str, reconcile: bool) -> None:
    error = DBAPIError("private SQL", {"private": "values"}, original)
    classified = classify_sql_failure(error, "body")
    assert isinstance(classified, DatabaseUnavailable)
    assert (classified.phase, classified.sqlstate, classified.reconcile) == ("body", state, reconcile)
    assert "private" not in str(classified)
    assert isinstance(classify_sql_failure(error, "commit"), TransactionOutcomeUnknown)


@pytest.mark.parametrize("original", [errors.InvalidPassword(), errors.InsufficientPrivilege(),
                                      errors.UndefinedTable(), errors.CheckViolation()])
def test_configuration_and_integrity_errors_are_not_transient(original: Exception) -> None:
    assert classify_sql_failure(DBAPIError("", {}, original), "body") is None


def test_libpq_connection_failure_does_not_make_bad_credentials_transient() -> None:
    denied = DBAPIError("private", {}, psycopg.OperationalError("password authentication failed for user synthetic"))
    assert classify_sql_failure(denied, "acquire") is None
    refused = DBAPIError("private", {}, psycopg.OperationalError("connection refused"))
    result = classify_sql_failure(refused, "acquire")
    assert isinstance(result, DatabaseUnavailable) and result.phase == "acquire"


@pytest.mark.parametrize("values", [(0, 1, 1), (500, 500, 500), (500, 100, 60001), (True, 1, 2)])
def test_sql_timeout_validation(values: tuple[Any, ...]) -> None:
    with pytest.raises(ValueError):
        SqlTimeouts(*values)


class FakeConnection:
    def __init__(self, phase: str, error: BaseException) -> None:
        self.phase, self.error = phase, error
        self.closed = self.rolled_back = False

    def begin(self) -> Any:
        return self

    def execute(self, *args: Any, **kwargs: Any) -> None:
        if self.phase == "setup":
            raise self.error

    def commit(self) -> None:
        if self.phase == "commit":
            raise self.error

    def rollback(self) -> None:
        self.rolled_back = True
        raise RuntimeError("secondary rollback error")

    def close(self) -> None:
        self.closed = True
        raise RuntimeError("secondary close error")


@contextmanager
def failing_transaction(phase: str, error: BaseException) -> Any:
    from types import SimpleNamespace

    connection = FakeConnection(phase, error)
    yield connection, SimpleNamespace(connect=lambda: connection)


@pytest.mark.parametrize("phase", ["setup", "body", "commit"])
def test_setup_body_and_commit_failures_own_cleanup_and_preserve_primary(phase: str) -> None:
    primary = ValueError("primary")
    with failing_transaction(phase, primary) as (connection, engine):
        expected = TransactionOutcomeUnknown if phase == "commit" else ValueError
        with pytest.raises(expected) as caught, transaction(engine):
            if phase == "body":
                raise primary
        assert connection.closed and connection.rolled_back
        if phase != "commit":
            assert caught.value is primary
        else:
            assert caught.value.__cause__ is primary
        assert any("close" in note for note in caught.value.__notes__)


def test_commit_cancellation_stays_cancellation_and_is_outcome_unknown() -> None:
    with failing_transaction("commit", asyncio.CancelledError()) as (connection, engine):
        with pytest.raises(asyncio.CancelledError) as caught, transaction(engine):
            pass
        assert isinstance(caught.value, TransactionCommitCancelled)
        assert isinstance(caught.value, TransactionOutcomeUnknown)
        assert connection.closed


@pytest.mark.parametrize("error,rule", [(DatabaseUnavailable("body", "55P03"), "api.database_unavailable"),
                                       (TransactionOutcomeUnknown(), "api.transaction_outcome_unknown")])
def test_api_preserves_safe_retry_and_unknown_outcome_semantics(error: Exception, rule: str) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from policyops.api.auth import install_error_boundary

    app = FastAPI()
    install_error_boundary(app)

    @app.get("/api/v1/probe")
    def probe() -> None:
        raise error

    with TestClient(app) as client:
        response = client.get("/api/v1/probe")
    assert response.status_code == 503 and response.json()["rule_id"] == rule
    assert response.json()["retryable"] and response.headers["cache-control"] == "no-store"
