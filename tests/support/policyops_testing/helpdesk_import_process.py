"""Pause a real importer process at a known boundary for the PostgreSQL kill test."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Event
from typing import Any
from unittest.mock import patch
from uuid import UUID

import psycopg
from sqlalchemy import Connection

from policyops.persistence import helpdesk_imports as store
from policyops.persistence.database import (
    RUNTIME_CONNECT_OPTIONS,
    connection_transaction,
    make_engine,
    verify_runtime_role,
)
from policyops.persistence.helpdesk_imports import Checkpoint, Outcome
from policyops.persistence.roles import APP_RUNTIME
from policyops.services import helpdesk_import as service
from policyops.services.helpdesk_export import VerifiedExport
from policyops_testing.app_database import AppDatabase
from policyops_testing.postgres import SESSION_OPTIONS
from policyops_testing.zammad import settings


def start(db: AppDatabase, *, workspace: UUID, exported_at: datetime, source: Path, sha256: str,
          ready: Path, after: int, mid_batch: bool) -> subprocess.Popen[str]:
    server = db.server
    support = str(Path(__file__).resolve().parents[1])
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, (support, os.environ.get("PYTHONPATH"))))}
    config = {"port": server.port, "database": db.name, "password": server.passwords[APP_RUNTIME],
              "passfile": str(server.root / "client" / "no-passfile"), "workspace": str(workspace),
              "exported_at": exported_at.isoformat(), "source": str(source), "sha256": sha256,
              "ready": str(ready), "after": after, "mid_batch": mid_batch}
    process = subprocess.Popen(
        [sys.executable, "-B", "-m", "policyops_testing.helpdesk_import_process"], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, env=env)
    try:
        assert process.stdin is not None
        with process.stdin as stream:
            stream.write(json.dumps(config) + "\n")
    except BaseException:
        process.kill()
        process.wait(30)
        raise
    return process


def main() -> None:
    config = json.loads(sys.stdin.readline())

    def connect() -> psycopg.Connection[Any]:
        return psycopg.connect(
            host="127.0.0.1", hostaddr="127.0.0.1", port=config["port"], user=APP_RUNTIME, dbname=config["database"],
            password=config["password"], sslmode="disable", gssencmode="disable", passfile=config["passfile"],
            connect_timeout=5, options=SESSION_OPTIONS + " " + RUNTIME_CONNECT_OPTIONS, client_encoding="UTF8",
            application_name="policyops-helpdesk-import-test")

    def pause() -> None:
        Path(config["ready"]).write_bytes(b"ready")
        Event().wait(30)

    real_advance, real_save = store.advance, store.save_outcome
    advanced = 0

    def advance(connection: Connection, workspace: UUID, run: Checkpoint, outcomes: list[Outcome]) -> Checkpoint:
        nonlocal advanced
        checkpoint = real_advance(connection, workspace, run, outcomes)
        advanced = checkpoint.next_record
        return checkpoint

    def save(connection: Connection, workspace: UUID, run: UUID, outcome: Outcome, sha: str) -> None:
        real_save(connection, workspace, run, outcome, sha)
        if config["mid_batch"] and outcome.record_no == config["after"]:
            pause()

    @contextmanager
    def transaction(connection: Connection, workspace: UUID) -> Iterator[Connection]:
        with connection_transaction(connection, workspace) as transaction_connection:
            yield transaction_connection
        if not config["mid_batch"] and advanced == config["after"]:
            pause()

    engine = make_engine(connect, pool_size=1)
    try:
        verify_runtime_role(engine, APP_RUNTIME)
        endpoint = settings(UUID(config["workspace"]), enabled=False).connections[0]
        source = VerifiedExport.read(Path(config["source"]), expected_sha256=config["sha256"])
        with (patch.object(store, "save_outcome", save), patch.object(store, "advance", advance),
              patch.object(service, "connection_transaction", transaction)):
            service.TicketImport(engine, endpoint).run(source, datetime.fromisoformat(config["exported_at"]))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
