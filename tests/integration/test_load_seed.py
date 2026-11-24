"""Exercise the load fixture repositories against scoped PostgreSQL (coordinator-run)."""

from datetime import UTC, datetime
import os
from pathlib import Path
import sys
from uuid import UUID, uuid5

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from infra.compose import load_identity, loadseed, runtime
from policyops.domain.examples import World
from policyops.domain.retail_rules import RetailFacts
from policyops.persistence import identity
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, NewCase, Principal, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_testing.app_database import NewDatabase


pytestmark = pytest.mark.postgres
ISSUER = "https://issuer.example.invalid/dex"


def bootstrap_identity(auth: Engine, default: UUID, now: datetime) -> None:
    with transaction(auth) as conn:
        repo.create_workspace(conn, Workspace(id=default, slug="compose-demo", name="Fictional demo", created_at=now))
        for user in runtime.demo()["users"]:
            principal = uuid5(default, user["name"])
            repo.create_principal(
                conn,
                Principal(
                    id=principal,
                    issuer=ISSUER,
                    subject=user["subject"],
                    display_name=user["name"],
                    created_at=now,
                ),
            )
            repo.add_membership(
                conn,
                Membership(
                    id=uuid5(principal, "membership"),
                    workspace_id=default,
                    principal_id=principal,
                    role=user["role"],
                    created_at=now,
                ),
            )


def test_history_manifest_separates_workspaces_and_preserves_fixture_bindings(
    new_app_database: NewDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = new_app_database("n10fixture")
    auth, app = db.engine(AUTH_RUNTIME), db.engine(APP_RUNTIME)
    seed = 10
    default, second, foreign = loadseed.workspaces(seed)
    now = datetime.now(UTC)
    bootstrap_identity(auth, default, now)
    loadseed.membership(auth, default, second, foreign, now)
    customer = World().customer(user_id=runtime.demo()["customer_id"])
    for workspace, count in ((default, 3), (second, 2), (foreign, 1)):
        loadseed.seed_history(
            app, workspace, seed, count, RetailFacts(customer), "a" * 64, foreign=workspace == foreign
        )
    monkeypatch.setitem(os.environ, "POLICYOPS_ENV", "local")
    evidence = loadseed.manifest(app, seed, [], run_id="n10-fixture")
    assert evidence["counts"][str(default)]["cases"] == 3
    assert evidence["counts"][str(second)]["cases"] == 2
    assert evidence["counts"][str(foreign)]["cases"] == 1
    assert len(evidence["workspaces"][str(default)]["hold"]) == 3
    assert len(evidence["workspaces"][str(second)]["browse_proposals"]) == 2
    assert evidence["canary"]["workspace_id"] == str(foreign)
    assert set(evidence["workspaces"][str(default)]["cases"]).isdisjoint(evidence["workspaces"][str(second)]["cases"])
    with transaction(auth) as conn:
        assert identity.active_roles(conn, uuid5(default, "bob"), second) == {"reviewer"}
        assert not identity.active_roles(conn, uuid5(default, "bob"), foreign)


def test_load_identity_enrollment_and_volume_lock(new_app_database: NewDatabase) -> None:
    db = new_app_database("n10identity")
    auth, app, postgres = db.engine(AUTH_RUNTIME), db.engine(APP_RUNTIME), db.engine("postgres")
    config = runtime.demo()
    workspace, case = UUID(config["workspace_id"]), UUID(config["case_id"])
    now = datetime.now(UTC)
    enrolled = load_identity.LoadIdentity("n10-integration", "ab" * 32, ISSUER)
    bootstrap_identity(auth, workspace, now)
    with pytest.raises(load_identity.SeedError, match="volume marker"), postgres.begin() as conn:
        load_identity.initialize(conn, enrolled)
    with postgres.begin() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        # Exercise the same catalog marker written by the initdb hook, on the test cluster only.
        marker = (enrolled.volume_marker + " " + database).replace("'", "''")
        conn.exec_driver_sql(f"COMMENT ON DATABASE postgres IS '{marker}'")
    with pytest.raises(load_identity.SeedError, match="beyond the bootstrap"), postgres.begin() as conn:
        load_identity.initialize(conn, enrolled)
    with pytest.raises(load_identity.SeedError, match="unavailable"):
        load_identity.verify_identity(app, enrolled)
    with workspace_transaction(app, workspace) as conn:
        repo.create_case(conn, NewCase(
            id=case, workspace_id=workspace, scenario="retail", customer_user_id=config["customer_id"],
            created_by=uuid5(workspace, "alice"), created_at=now,
        ))
    with postgres.begin() as conn:
        conn.execute(text("UPDATE identity.principals SET issuer='https://protected.example.invalid/dex'"))
    with pytest.raises(load_identity.SeedError, match="stored issuer"), postgres.begin() as conn:
        load_identity.initialize(conn, enrolled)
    with postgres.begin() as conn:
        conn.execute(text("UPDATE identity.principals SET issuer=:issuer"), {"issuer": ISSUER})
    with postgres.begin() as conn:
        load_identity.initialize(conn, enrolled)
    for engine in (app, auth):
        load_identity.verify_identity(engine, enrolled)
        with pytest.raises(ProgrammingError), engine.begin() as conn:
            conn.execute(text("DELETE FROM n10_load.identity"))
    with pytest.raises(load_identity.SeedError, match="already has load identity"), postgres.begin() as conn:
        load_identity.initialize(conn, enrolled)
    with (
        load_identity.wave_admission(app),
        pytest.raises(load_identity.SeedError, match="volume lock"),
        load_identity.wave_admission(app),
    ):
        pytest.fail("a second connection acquired the volume lock")
    with load_identity.wave_admission(app):
        load_identity.verify_identity(auth, enrolled)
