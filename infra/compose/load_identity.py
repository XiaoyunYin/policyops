"""One-time enrollment of an empty N10 volume, followed by read-only runtime checks."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from hmac import compare_digest
import os
import re
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import SQLAlchemyError

from infra.compose import runtime


LOCK_KEY = 1401260010


class SeedError(ValueError):
    """Fixed diagnostics with no connection details."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SeedError(message)


@dataclass(frozen=True)
class LoadIdentity:
    run_id: str
    token_sha256: str
    issuer: str

    @property
    def volume_marker(self) -> str:
        return f"n10-volume-v1 {self.run_id} {self.token_sha256} {self.issuer}"


def load_config() -> LoadIdentity:
    require(os.environ.get("POLICYOPS_ENV") == "local", "requires the disposable overlay")
    token = runtime.secret("n10_load_token")
    run_id = os.environ.get("POLICYOPS_N10_RUN_ID", "")
    denied = {
        line.strip().lower().rstrip(".")
        for line in (runtime.SECRETS / "n10_deny_hosts").read_text(encoding="ascii").splitlines()
        if line.strip()
    }
    require(bool(denied) and "" not in denied, "requires private denied hostnames")
    public_host = os.environ.get("POLICYOPS_N10_PUBLIC_HOST", "")
    issuer = os.environ.get("POLICYOPS_N10_ISSUER", "")
    origin = urlsplit(issuer)
    app_origin = os.environ.get("POLICYOPS_PUBLIC_ORIGIN", issuer.removesuffix("/dex"))
    app_issuer = os.environ.get("POLICYOPS_OIDC_ISSUER", issuer)
    hosts = (public_host, *(urlsplit(value).hostname or "" for value in (issuer, app_origin, app_issuer)))
    for host in hosts:
        normalized = host.lower().rstrip(".")
        require(
            not any(normalized == denied_host or normalized.endswith("." + denied_host) for denied_host in denied),
            "public hostname denied",
        )
    require(bool(re.fullmatch(r"n10-[a-z0-9-]{1,59}", run_id)), "requires a unique n10 run ID")
    require(bool(re.fullmatch(r"[0-9a-f]{64}", token)), "invalid disposable run token")
    expected = f"https://{public_host}/dex" if public_host else f"http://127.0.0.1:{origin.port}/dex"
    require(
        issuer == expected and app_issuer == issuer and app_origin + "/dex" == issuer
        and (origin.hostname == public_host if public_host else bool(origin.port)),
        "disposable issuer does not match the host",
    )
    return LoadIdentity(run_id, hashlib.sha256(token.encode("ascii")).hexdigest(), issuer)


def require_issuer(conn: Connection, identity: LoadIdentity) -> None:
    issuers = conn.execute(text("SELECT DISTINCT issuer FROM identity.principals")).scalars().all()
    require(issuers == [identity.issuer], "stored issuer does not match the disposable host")


def require_fresh(conn: Connection, identity: LoadIdentity) -> None:
    config = runtime.demo()
    workspace = UUID(config["workspace_id"])
    principals = {uuid5(workspace, user["name"]) for user in config["users"]}
    expected = {
        "app.cases": {UUID(config["case_id"])},
        "identity.workspaces": {workspace},
        "identity.principals": principals,
        "identity.memberships": {uuid5(principal, "membership") for principal in principals},
    }
    tables = (
        conn.execute(
            text(
                "SELECT format('%I.%I', n.nspname, c.relname) FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname IN ('app','identity','checkpoints','retail','evaluation') AND c.relkind IN ('r','p') "
                "AND c.relname <> 'alembic_version' ORDER BY 1"
            )
        )
        .scalars()
        .all()
    )
    require(expected.keys() <= set(tables), "bootstrap fixture tables are missing")
    # The superuser sees across tenant RLS. Hold off concurrent mutations through enrollment.
    conn.exec_driver_sql("LOCK TABLE " + ", ".join(tables) + " IN SHARE ROW EXCLUSIVE MODE")
    require_issuer(conn, identity)
    for table in tables:
        if table in expected:
            rows = conn.exec_driver_sql(
                f"SELECT id FROM {table} LIMIT {len(expected[table]) + 1}"  # noqa: S608 - catalog-quoted identifier
            ).scalars()
            fresh = set(rows) == expected[table]
        else:
            fresh = (
                conn.exec_driver_sql(
                    f"SELECT 1 FROM {table} LIMIT 1"  # noqa: S608 - catalog-quoted identifier
                ).first()
                is None
            )
        require(fresh, "database contains state beyond the bootstrap fixture")
    require(
        conn.execute(text("SELECT 1 FROM app.cases WHERE status='open' AND version=1")).first() is not None,
        "bootstrap case has been modified",
    )


def initialize(conn: Connection, identity: LoadIdentity) -> None:
    # This shared catalog entry is written by initdb on the fresh volume, before app bootstrap.
    marker_matches = conn.execute(text(
        "SELECT pg_catalog.shobj_description(oid, 'pg_database') = :marker || ' ' || current_database() "
        "FROM pg_catalog.pg_database WHERE datname = 'postgres'"
    ), {"marker": identity.volume_marker}).scalar_one()
    require(marker_matches is True, "disposable volume marker mismatch")
    require_issuer(conn, identity)
    require(
        conn.execute(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": LOCK_KEY}).scalar_one(),
        "another load operation holds the volume lock",
    )
    require(
        conn.execute(text("SELECT to_regnamespace('n10_load') IS NULL")).scalar_one(),
        "database already has load identity state",
    )
    require_fresh(conn, identity)
    conn.exec_driver_sql("CREATE SCHEMA n10_load")
    conn.exec_driver_sql(
        "CREATE TABLE n10_load.identity (singleton boolean PRIMARY KEY CHECK (singleton),"
        " run_id text NOT NULL, token_sha256 text NOT NULL)"
    )
    conn.execute(
        text("INSERT INTO n10_load.identity VALUES (true, :run, :digest)"),
        {"run": identity.run_id, "digest": identity.token_sha256},
    )
    conn.exec_driver_sql("GRANT USAGE ON SCHEMA n10_load TO policyops_app_runtime, policyops_auth_runtime")
    conn.exec_driver_sql("GRANT SELECT ON n10_load.identity TO policyops_app_runtime, policyops_auth_runtime")


def verify_identity(engine: Engine, identity: LoadIdentity) -> None:
    try:
        with engine.connect() as conn:
            row = conn.execute(text("SELECT run_id, token_sha256 FROM n10_load.identity WHERE singleton")).one_or_none()
    except SQLAlchemyError:
        raise SeedError("database load identity unavailable") from None
    require(
        row is not None and row.run_id == identity.run_id and compare_digest(row.token_sha256, identity.token_sha256),
        "database load identity mismatch",
    )


@contextmanager
def wave_admission(app: Engine) -> Iterator[None]:
    # Seeding and the manifest use separate scoped transactions. Hold one session lock across them.
    with app.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        require(
            conn.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK_KEY}).scalar_one(),
            "another load operation holds the volume lock",
        )
        try:
            yield
        finally:
            try:
                conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK_KEY})
            except SQLAlchemyError:
                conn.invalidate()
                raise
