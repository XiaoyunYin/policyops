"""The ingestion CLI on real PostgreSQL: the read-only default plan, explicit execute and paid gating with JSON
outcomes and exit codes, the runtime-role check, and a crash inside publication: a real CLI subprocess (libpq
environment, no provider work) is blocked mid-transaction by a test lock, killed and reaped, and the previous
generation stays active with nothing written."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any
from uuid import UUID, uuid4

import pytest

from policyops.persistence import repositories as repo
from policyops.persistence.database import SCOPE_SETTING, transaction
from policyops.persistence.records import Workspace
from policyops.persistence.roles import APP_MIGRATOR, APP_RUNTIME, AUTH_RUNTIME
from policyops.providers import tokenizer as tk
from policyops.retrieval.cli import main
from policyops_testing.app_database import AppDatabase
from policyops_testing.corpus_fixtures import CredentialReads, FixtureCorpus, ScriptedEmbeddings, banking, write


pytestmark = pytest.mark.postgres
TOKENIZER = tk.load()
PAID = ["--paid", "--model", "text-embedding-3-small", "--dimensions", "1536", "--max-usd", "0.01", "--max-calls",
        "20", "--max-input-tokens", "100000", "--max-seconds", "900"]


class Cli:
    def __init__(self, db: AppDatabase, root: Path) -> None:
        self.db, self.root, self.ws, self.n = db, root, uuid4(), 0
        with transaction(db.engine(AUTH_RUNTIME)) as conn:
            repo.create_workspace(conn, Workspace(id=self.ws, slug=f"ws-{self.ws.hex[:12]}", name="CLI",
                                                  created_at=datetime.now(UTC)))
        self.provider = ScriptedEmbeddings()
        self.credentials = CredentialReads(self.provider)

    def files(self, content: str, *, key: str = "cli-corpus", domain: str = "banking_knowledge") -> list[str]:
        self.n += 1
        root = self.root / f"acq-{self.n}"
        documents = {"a": banking("a", "Policy", content), "b": banking("b", "Other", "Stable second rule.")}
        raw, digest = write(root, [FixtureCorpus(key, domain, "tau2-banking/v1", documents)])
        manifest = self.root / f"manifest-{self.n}.json"
        manifest.write_bytes(raw)
        return ["ingest", "--workspace", str(self.ws), "--corpus-key", key, "--manifest", str(manifest),
                "--manifest-sha256", digest, "--acquisition-root", str(root)]

    def run(self, argv: list[str], *, role: str = APP_RUNTIME) -> tuple[int, dict[str, Any]]:
        out = io.StringIO()
        code = main(argv, connect=lambda: self.db.server.connect(role, self.db.name), providers=self.credentials,
                    tokenizer=TOKENIZER, env="test", stdout=out)
        return code, json.loads(out.getvalue())

    def counts(self) -> dict[str, int]:
        with self.db.superuser() as conn:
            return {t: conn.execute(f"SELECT count(*) FROM {t} WHERE workspace_id = %s",  # noqa: S608 - fixed names
                                    (self.ws,)).fetchone()[0]
                    for t in ("app.corpora", "app.documents", "app.document_versions", "app.index_generations",
                              "app.generation_documents", "app.chunks", "app.embedding_jobs", "app.usage_attempts")}


@pytest.fixture
def cli(shared_db: AppDatabase, tmp_path: Path) -> Cli:
    return Cli(shared_db, tmp_path)


def test_plan_is_the_read_only_default_and_execute_needs_paid(cli: Cli) -> None:
    before = cli.counts()
    code, plan = cli.run(cli.files("Rule one."))
    assert (code, plan["outcome"], plan["mode"]) == (0, "planned", "plan") and plan["estimate"]["batches"] == 1
    code, refused = cli.run([*cli.files("Rule one."), "--execute"])
    assert (code, refused["outcome"], refused["reason"]) == (2, "refused", "paid_execution_not_authorized")
    assert cli.counts() == before and cli.credentials.reads == 0 and cli.provider.requests == []


def test_execute_paid_activates_then_a_repeat_is_unchanged(cli: Cli) -> None:
    code, activated = cli.run([*cli.files("Rule one."), "--execute", *PAID])
    assert (code, activated["outcome"]) == (0, "activated"), activated
    assert activated["paid"]["max_usd"] == "0.01" and activated["physical_requests"] == 1
    assert "Rule one." not in json.dumps(activated)  # no document text in the output
    before = cli.counts()
    code, repeat = cli.run([*cli.files("Rule one."), "--execute", *PAID])
    assert (code, repeat["outcome"]) == (0, "unchanged") and cli.counts() == before


def test_a_connection_that_is_not_the_app_runtime_is_refused(cli: Cli) -> None:
    code, failed = cli.run(cli.files("Rule one."), role=APP_MIGRATOR)
    assert (code, failed["outcome"], failed["error"]) == (1, "failed", "RuntimeRoleError")


class OwnedCleanup:
    """Attempts every registered cleanup, in reverse order, even when some fail. A cleanup failure never replaces
    the primary failure: it is attached to it as a note (type name only: connection errors can carry connection
    details). With no primary failure, the cleanup failures are raised together, so uncertainty is never a pass."""

    def __init__(self) -> None:
        self._callbacks: list[tuple[Callable[..., object], tuple[object, ...], dict[str, object]]] = []

    def register(self, callback: Callable[..., object], *args: object, **kwargs: object) -> None:
        self._callbacks.append((callback, args, kwargs))

    def __enter__(self) -> OwnedCleanup:
        return self

    def __exit__(self, kind: type[BaseException] | None, primary: BaseException | None, trace: object) -> None:
        failures: list[BaseException] = []
        for callback, args, kwargs in reversed(self._callbacks):
            try:
                callback(*args, **kwargs)
            except BaseException as error:  # every owned cleanup must still be attempted
                failures.append(error)
        if failures and primary is not None:
            for item in failures:
                primary.add_note(f"owned cleanup also failed: {type(item).__name__}")
        elif failures:
            raise BaseExceptionGroup("owned cleanup failed", failures)


def _write_owned_secret(path: Path, content: str) -> None:
    """Write a transient secret file (restricted where POSIX permissions exist). If writing or restricting fails,
    removal is attempted and the original failure is kept; a removal failure becomes a type-only note on it."""
    try:
        path.write_text(content, encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
    except BaseException as primary:
        try:
            path.unlink(missing_ok=True)
        except BaseException as cleanup:  # the primary failure is what the caller must see
            primary.add_note(f"owned cleanup also failed: {type(cleanup).__name__}")
        raise


def _owned_pgpass(db: AppDatabase, directory: Path) -> Path:
    """A transient pgpass file for the child (the caller registers its removal right after it exists)."""
    path = directory / "pgpass"
    password = db.server.passwords[APP_RUNTIME]
    _write_owned_secret(path, f"127.0.0.1:{db.server.port}:{db.name}:{APP_RUNTIME}:{password}\n")
    return path


def _blocked_backend(db: AppDatabase, seconds: float = 60.0) -> int | None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with db.superuser() as conn:
            row = conn.execute("SELECT pid FROM pg_stat_activity WHERE datname = %s AND usename = %s AND "
                               "wait_event_type = 'Lock' AND query LIKE 'UPDATE app.index_generations%%'",
                               (db.name, APP_RUNTIME)).fetchone()
        if row is not None:
            return int(row[0])
        time.sleep(0.1)
    return None


def _reap(process: subprocess.Popen[bytes]) -> None:
    """Kill the child if it still runs, then wait for it, bounded."""
    if process.poll() is None:
        process.kill()
    process.wait(timeout=30)


def _gone(db: AppDatabase, pid: int, seconds: float = 30.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with db.superuser() as conn:
            if conn.execute("SELECT count(*) FROM pg_stat_activity WHERE pid = %s", (pid,)).fetchone() == (0,):
                return True
        time.sleep(0.1)
    return False


def test_a_killed_cli_inside_publication_leaves_the_previous_generation_active(cli: Cli, tmp_path: Path) -> None:
    code, first = cli.run([*cli.files("Original rule."), "--execute", *PAID])
    assert code == 0 and first["outcome"] == "activated"
    old = UUID(first["generation_id"])
    # Cache the edited content's vectors through another corpus, so the subprocess needs no provider at all.
    code, cached = cli.run([*cli.files("Edited rule.", key="cache-corpus", domain="cache_domain"), "--execute", *PAID])
    assert code == 0 and cached["outcome"] == "activated"
    argv = [*cli.files("Edited rule."), "--execute"]
    before = cli.counts()
    pid: int | None = None
    # Every owned resource registers its cleanup as soon as it exists; all are attempted in reverse order (reap the
    # child, close its log, release the lock, close the connection, remove the pgpass file) and a cleanup failure
    # is attached to, never substituted for, a primary failure.
    with OwnedCleanup() as owned:
        pgpass = _owned_pgpass(cli.db, tmp_path)
        owned.register(pgpass.unlink, missing_ok=True)
        blocker = cli.db.server.connect(APP_RUNTIME, cli.db.name)
        owned.register(blocker.close)
        owned.register(blocker.rollback)  # the lock goes; an orphaned backend finds its client gone and rolls back
        blocker.execute("SELECT set_config(%s, %s, true)", (SCOPE_SETTING, str(cli.ws)))
        # FOR SHARE on the active generation: the subprocess's retirement UPDATE (FOR NO KEY UPDATE) must wait,
        # after it has inserted its documents, generation, membership and chunks.
        assert blocker.execute("SELECT 1 FROM app.index_generations WHERE id = %s FOR SHARE", (old,)).fetchone()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PG", "OPENAI_"))}
        env |= {"PGHOST": "127.0.0.1", "PGPORT": str(cli.db.server.port), "PGDATABASE": cli.db.name,
                "PGUSER": APP_RUNTIME, "PGPASSFILE": str(pgpass), "PGCONNECT_TIMEOUT": "10"}
        log = (tmp_path / "cli-child.log").open("wb")
        owned.register(log.close)
        process = subprocess.Popen([sys.executable, "-B", "-m", "policyops.retrieval.cli", *argv], env=env,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        owned.register(_reap, process)
        pid = _blocked_backend(cli.db)
        assert pid is not None, "the subprocess never blocked inside publication"
        process.kill()
        process.wait(timeout=30)
    assert process.returncode != 0
    assert not pgpass.exists() and pid is not None
    assert _gone(cli.db, pid), "the killed client's backend did not end"
    assert cli.counts() == before
    with cli.db.superuser() as conn:
        pointer = conn.execute("SELECT active_generation_id FROM app.corpora WHERE workspace_id = %s AND "
                               "corpus_key = 'cli-corpus'", (cli.ws,)).fetchone()
        statuses = conn.execute("SELECT status FROM app.index_generations WHERE id = %s", (old,)).fetchone()
    assert pointer == (old,) and statuses == ("ready",)
    code, resumed = cli.run(argv)  # the same import afterwards: all cached, publishes locally
    assert (code, resumed["outcome"]) == (0, "activated")


def test_owned_cleanup_keeps_the_primary_failure_and_attempts_every_cleanup() -> None:
    """Injected setup and cleanup failures (no database needed): every cleanup runs, the primary error survives
    with notes, and cleanup failures alone are raised rather than passing silently."""
    ran: list[str] = []

    def failing(name: str) -> None:
        ran.append(name)
        raise OSError(f"{name} failed")

    with pytest.raises(ValueError, match="primary") as primary, OwnedCleanup() as owned:
        owned.register(failing, "first")
        owned.register(ran.append, "second")
        owned.register(failing, "third")
        raise ValueError("primary setup failure")
    assert ran == ["third", "second", "first"]
    assert primary.value.__notes__ == ["owned cleanup also failed: OSError"] * 2
    ran.clear()
    with pytest.raises(BaseExceptionGroup) as group, OwnedCleanup() as owned:
        owned.register(failing, "only")
        owned.register(ran.append, "after")
    assert ran == ["after", "only"] and len(group.value.exceptions) == 1


class FailingFile:
    """A stand-in path whose write fails and whose removal may fail too (injected, no file system)."""

    def __init__(self, *, unlink_fails: bool) -> None:
        self.unlink_fails, self.unlinked = unlink_fails, False

    def write_text(self, content: str, encoding: str) -> None:
        raise ValueError("injected write failure")

    def chmod(self, mode: int) -> None:  # pragma: no cover - never reached after the failed write
        raise AssertionError("unreachable")

    def unlink(self, missing_ok: bool = False) -> None:
        self.unlinked = True
        if self.unlink_fails:
            raise PermissionError("injected removal failure")


def test_a_failed_secret_write_keeps_its_own_failure_even_when_removal_fails() -> None:
    for unlink_fails in (False, True):
        target = FailingFile(unlink_fails=unlink_fails)
        with pytest.raises(ValueError, match="injected write failure") as caught:
            _write_owned_secret(target, "secret")  # type: ignore[arg-type]
        assert target.unlinked
        notes = getattr(caught.value, "__notes__", [])
        assert notes == (["owned cleanup also failed: PermissionError"] if unlink_fails else [])
