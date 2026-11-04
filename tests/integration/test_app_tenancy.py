"""Tenant isolation as the actual runtime roles: forced RLS, composite foreign keys, pooled scope reset and the
auth/evaluation role boundaries (PLAN D1/D5)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
from psycopg import errors
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from policyops.persistence import repositories as repo
from policyops.persistence.database import NotFound, transaction, workspace_transaction
from policyops.persistence.records import (
    EvaluationRun,
    EvaluationTrial,
    Membership,
    NewCase,
    Principal,
    Workspace,
)
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, EVAL_RUNTIME
from policyops_contracts.digest import text_sha256
from policyops_testing.app_database import AppDatabase


pytestmark = pytest.mark.postgres
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _workspace(db: AppDatabase, label: str) -> UUID:
    workspace_id = uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=workspace_id, slug=f"{label}-{workspace_id.hex[:8]}",
                                              name=label.title(), created_at=NOW))
    return workspace_id


def _case(db: AppDatabase, workspace_id: UUID) -> UUID:
    case_id = uuid4()
    with workspace_transaction(db.engine(APP_RUNTIME), workspace_id) as conn:
        repo.create_case(conn, NewCase(id=case_id, workspace_id=workspace_id, scenario="retail",
                                       customer_user_id=None, created_by=None, created_at=NOW))
    return case_id


@pytest.fixture
def two_tenants(shared_db: AppDatabase) -> Iterator[tuple[UUID, UUID, UUID, UUID]]:
    a, b = _workspace(shared_db, "alpha"), _workspace(shared_db, "beta")
    yield a, _case(shared_db, a), b, _case(shared_db, b)


def test_runtime_sees_and_writes_only_its_scope(shared_db: AppDatabase, two_tenants: tuple[UUID, ...]) -> None:
    a, case_a, b, case_b = two_tenants
    app = shared_db.engine(APP_RUNTIME)
    with workspace_transaction(app, a) as conn:
        assert repo.get_case(conn, case_a) is not None and repo.get_case(conn, case_b) is None
        ids = {row[0] for row in conn.execute(text("SELECT id FROM app.cases"))}
        assert case_a in ids and case_b not in ids
        workspaces = conn.execute(text("SELECT id FROM identity.workspaces")).scalars().all()
        assert workspaces == [a]
    with pytest.raises(ProgrammingError, match="row-level security"), workspace_transaction(app, a) as conn:
        repo.create_case(conn, NewCase(id=uuid4(), workspace_id=b, scenario="retail", customer_user_id=None,
                                       created_by=None, created_at=NOW))
    with pytest.raises(NotFound), workspace_transaction(app, a) as conn:  # cannot touch B's row by its ID
        repo.set_case_status(conn, case_b, expected_version=1, status="closed", now=NOW)


def test_no_scope_means_no_rows_and_no_writes(shared_db: AppDatabase, two_tenants: tuple[UUID, ...]) -> None:
    a, case_a, *_ = two_tenants
    app = shared_db.engine(APP_RUNTIME)
    with transaction(app) as conn:
        assert conn.execute(text("SELECT count(*) FROM app.cases")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM identity.memberships")).scalar_one() == 0
    with pytest.raises(ProgrammingError, match="row-level security"), transaction(app) as conn:
        repo.create_case(conn, NewCase(id=uuid4(), workspace_id=a, scenario="retail", customer_user_id=None,
                                       created_by=None, created_at=NOW))
    with transaction(app) as conn:  # an empty setting is also "no scope"
        conn.execute(text("SELECT set_config('policyops.workspace_id', '', true)"))
        assert repo.get_case(conn, case_a) is None


def test_pooled_connection_never_keeps_a_scope(shared_db: AppDatabase, two_tenants: tuple[UUID, ...]) -> None:
    a, case_a, *_ = two_tenants
    engine = shared_db.engine(APP_RUNTIME, pool_size=1)  # every transaction reuses the same server connection

    def backend_and_visible() -> tuple[int, int, str | None]:
        with transaction(engine) as conn:
            return (conn.execute(text("SELECT pg_backend_pid()")).scalar_one(),
                    conn.execute(text("SELECT count(*) FROM app.cases")).scalar_one(),
                    conn.execute(text("SELECT current_setting('policyops.workspace_id', true)")).scalar_one())

    with workspace_transaction(engine, a) as conn:  # commit
        pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
        assert repo.get_case(conn, case_a) is not None
    assert backend_and_visible()[:2] == (pid, 0)
    with pytest.raises(RuntimeError, match="boom"), workspace_transaction(engine, a):  # rollback by exception
        raise RuntimeError("boom")
    assert backend_and_visible()[:2] == (pid, 0)
    with pytest.raises(DBAPIError), workspace_transaction(engine, a) as conn:  # rollback after a database error
        conn.execute(text("SELECT 1 / 0"))
    pid_after, visible, setting = backend_and_visible()
    assert (pid_after, visible) == (pid, 0) and setting in ("", None)


def test_composite_foreign_keys_reject_cross_tenant_links(shared_db: AppDatabase,
                                                         two_tenants: tuple[UUID, ...]) -> None:
    a, case_a, b, case_b = two_tenants
    app = shared_db.engine(APP_RUNTIME)
    with pytest.raises(DBAPIError) as raised, workspace_transaction(app, a) as conn:
        # Valid UUID of B's case, own workspace column: the composite key (a, case_b) does not exist.
        conn.execute(text("INSERT INTO app.case_messages (id, workspace_id, case_id, sequence, source, text, "
                          "text_sha256, created_at) VALUES (:id, :w, :c, 1, 'seeded', 'x', :d, :t)"),
                     {"id": uuid4(), "w": a, "c": case_b, "d": text_sha256("x"), "t": NOW})
    assert isinstance(raised.value.orig, errors.ForeignKeyViolation)
    # Even a superuser (no RLS) cannot link across workspaces.
    with shared_db.superuser() as conn, pytest.raises(errors.ForeignKeyViolation):
        conn.execute("INSERT INTO app.case_messages (id, workspace_id, case_id, sequence, source, text, "
                     "text_sha256, created_at) VALUES (%s, %s, %s, 1, 'seeded', 'x', %s, %s)",
                     (uuid4(), b, case_a, text_sha256("x"), NOW))


def test_optional_links_are_null_or_checked(shared_db: AppDatabase, two_tenants: tuple[UUID, ...]) -> None:
    a, _, b, case_b = two_tenants
    app = shared_db.engine(APP_RUNTIME)
    insert = text("INSERT INTO app.outbox_events (id, workspace_id, run_id, dedupe_key, topic, payload, created_at) "
                  "VALUES (:id, :w, :r, :k, 'case.updated', CAST('{}' AS jsonb), :t)")
    with workspace_transaction(app, a) as conn:  # MATCH SIMPLE: a NULL optional link is simply no link
        conn.execute(insert, {"id": uuid4(), "w": a, "r": None, "k": f"k-{uuid4()}", "t": NOW})
    run_b = uuid4()
    with workspace_transaction(app, b) as conn:
        conn.execute(text("INSERT INTO app.runs (id, workspace_id, case_id, case_version, mode, graph_sha256, "
                          "prompt_sha256, config_sha256, state, deadline_at, created_at, updated_at) VALUES (:id, :w, "
                          ":c, 1, 'workbench', :h, :h, :h, 'queued', :d, :t, :t)"),
                     {"id": run_b, "w": b, "c": case_b, "h": "0" * 64, "d": NOW + timedelta(hours=1), "t": NOW})
    with pytest.raises(DBAPIError) as raised, workspace_transaction(app, a) as conn:
        conn.execute(insert, {"id": uuid4(), "w": a, "r": run_b, "k": f"k-{uuid4()}", "t": NOW})
    assert isinstance(raised.value.orig, errors.ForeignKeyViolation)


def test_auth_role_is_confined_to_identity(shared_db: AppDatabase, two_tenants: tuple[UUID, ...]) -> None:
    a, _, b, _ = two_tenants
    principal = Principal(id=uuid4(), issuer="https://issuer.example.invalid", subject=f"s-{uuid4().hex}",
                          display_name="Synthetic Person", created_at=NOW)
    with transaction(shared_db.engine(AUTH_RUNTIME)) as conn:
        repo.create_principal(conn, principal)
        for workspace_id, role in ((a, "analyst"), (b, "reviewer")):
            repo.add_membership(conn, Membership(id=uuid4(), workspace_id=workspace_id, principal_id=principal.id,
                                                 role=role, created_at=NOW))  # type: ignore[arg-type]
    with transaction(shared_db.engine(AUTH_RUNTIME)) as conn:  # pre-workspace lookup across workspaces
        assert repo.find_principal(conn, principal.issuer, principal.subject) == principal
        assert {m.workspace_id for m in repo.active_memberships(conn, principal.id)} == {a, b}
    for statement in ("SELECT 1 FROM app.cases", "SELECT 1 FROM evaluation.evaluation_runs",
                      "SELECT app.current_workspace()"):
        with pytest.raises(ProgrammingError, match="permission denied"), \
                transaction(shared_db.engine(AUTH_RUNTIME)) as conn:
            conn.execute(text(statement))
    with workspace_transaction(shared_db.engine(APP_RUNTIME), a) as conn:  # app sees only scope memberships
        rows = conn.execute(text("SELECT workspace_id FROM identity.memberships WHERE principal_id = :p"),
                            {"p": principal.id}).scalars().all()
        assert rows == [a]
    for statement in ("SELECT 1 FROM identity.principals", "SELECT 1 FROM identity.sessions"):
        with pytest.raises(ProgrammingError, match="permission denied"), \
                workspace_transaction(shared_db.engine(APP_RUNTIME), a) as conn:
            conn.execute(text(statement))


def test_evaluation_role_is_confined_to_evaluation(shared_db: AppDatabase) -> None:
    run = EvaluationRun(id=uuid4(), dataset="tau2-retail", dataset_revision="1" * 40, split_id="dev",
                        config_sha256="2" * 64, config_json='{"model": "fake"}', created_at=NOW)
    from decimal import Decimal

    with transaction(shared_db.engine(EVAL_RUNTIME)) as conn:
        repo.create_evaluation_run(conn, run)
        repo.add_trial(conn, EvaluationTrial(
            id=uuid4(), evaluation_run_id=run.id, task_id="7", trial_index=0, seed=20261104, outcome="success",
            reward=Decimal("1"), components_json='{"db": 1}', cost_status="known",
            cost_usd=Decimal("0.000000000000000123"), created_at=NOW))
    with transaction(shared_db.engine(EVAL_RUNTIME)) as conn:
        stored = conn.execute(text("SELECT cost_usd FROM evaluation.evaluation_trials WHERE evaluation_run_id = :r"),
                              {"r": run.id}).scalar_one()
        assert stored == Decimal("0.000000000000000123") and str(stored) == "1.23E-16"
    for statement in ("SELECT 1 FROM app.cases", "SELECT 1 FROM identity.workspaces"):
        with pytest.raises(ProgrammingError, match="permission denied"), \
                transaction(shared_db.engine(EVAL_RUNTIME)) as conn:
            conn.execute(text(statement))
    with pytest.raises(ProgrammingError, match="permission denied"), \
            transaction(shared_db.engine(APP_RUNTIME)) as conn:
        conn.execute(text("SELECT 1 FROM evaluation.evaluation_runs"))


def test_only_ready_index_generations_are_retrievable(shared_db: AppDatabase, two_tenants: tuple[UUID, ...]) -> None:
    a, *_ = two_tenants
    app = shared_db.engine(APP_RUNTIME)
    document, version, generation, chunk = uuid4(), uuid4(), uuid4(), uuid4()
    with workspace_transaction(app, a) as conn:
        conn.execute(text("INSERT INTO app.documents (id, workspace_id, domain, publisher, source_uri, license, "
                          "created_at) VALUES (:id, :w, 'retail', 'Synthetic', 'urn:example:policy', 'CC0', :t)"),
                     {"id": document, "w": a, "t": NOW})
        conn.execute(text("INSERT INTO app.document_versions (id, workspace_id, document_id, version, sha256, body, "
                          "status, effective_from, created_at) VALUES (:id, :w, :d, 1, :s, 'Body.', 'active', :t, :t)"),
                     {"id": version, "w": a, "d": document, "s": text_sha256("Body."), "t": NOW})
        conn.execute(text("INSERT INTO app.index_generations (id, workspace_id, policy_sha256, parser_version, "
                          "embedding_model, dimension, status, created_at) VALUES (:id, :w, :s, 'p1', 'fake-embed', "
                          "1536, 'building', :t)"), {"id": generation, "w": a, "s": "3" * 64, "t": NOW})
        conn.execute(text("INSERT INTO app.chunks (id, workspace_id, generation_id, document_version_id, heading, "
                          "start_offset, end_offset, text, sha256, embedding, created_at) VALUES (:id, :w, :g, :v, "
                          "'Returns', 0, 5, 'Body.', :s, CAST(:e AS public.vector), :t)"),
                     {"id": chunk, "w": a, "g": generation, "v": version, "s": text_sha256("Body."),
                      "e": "[" + ",".join(["0"] * 1535 + ["1"]) + "]", "t": NOW})
        assert conn.execute(text("SELECT count(*) FROM app.chunks WHERE id = :id"), {"id": chunk}).scalar_one() == 0
        conn.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = :t WHERE id = :id"),
                     {"id": generation, "t": NOW})
        row = conn.execute(text("SELECT tsv @@ to_tsquery('english', 'body') FROM app.chunks WHERE id = :id"),
                           {"id": chunk}).one()
        assert row == (True,)


def test_a_direct_runtime_connection_cannot_escalate(shared_db: AppDatabase) -> None:
    with shared_db.server.connect(APP_RUNTIME, shared_db.name) as conn:
        for statement in ("SET ROLE policyops_app_migrator", "SET SESSION AUTHORIZATION policyops_app_migrator",
                          "ALTER TABLE app.cases NO FORCE ROW LEVEL SECURITY", "SET row_security = off"):
            with pytest.raises(psycopg.Error):
                conn.execute(statement)
                # row_security=off is accepted as a setting but then fails any query that RLS would filter
                conn.execute("SELECT count(*) FROM app.cases")
            conn.rollback()
