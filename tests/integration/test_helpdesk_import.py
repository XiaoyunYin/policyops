"""N14 acceptance on real PostgreSQL, app runtime credentials and signed fake-Zammad snapshots."""

from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict
from datetime import timedelta
import hashlib
from itertools import permutations
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Barrier, Event, current_thread
from time import monotonic, perf_counter, sleep
from typing import Any
from uuid import UUID, uuid5

import httpx
import pytest
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError

from policyops.persistence import helpdesk as helpdesk_store
from policyops.persistence import helpdesk_imports as import_store
from policyops.persistence.database import (
    TransactionOutcomeUnknown,
    connection_transaction,
    sqlstate,
    workspace_transaction,
)
from policyops.persistence.helpdesk_imports import Checkpoint, ImportKey, Outcome
from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import DatabaseLeaseClock, FixedLeaseClock
from policyops.runtime.helpdesk import HelpdeskWorker
from policyops.services import helpdesk_import as service
from policyops.services.helpdesk_export import BATCH_BYTES, BATCH_RECORDS, ImportRefused, VerifiedExport, utc_timestamp
from policyops.services.helpdesk_import import Report, TicketImport
from policyops.services.helpdesk_inbound import Inbound
from policyops.settings import HelpdeskSettings
from policyops_contracts.clock import FixedClock
from policyops_testing import helpdesk_import_process, worker_process
from policyops_testing.app_database import AppDatabase
from policyops_testing.helpdesk_export import CUSTOMER, EXPORTED_AT, archive, snapshot
from policyops_testing.plugin import _temp_root
from policyops_testing.zammad import NOW, FakeZammad, settings, webhook
from tests.integration.test_helpdesk_contract import bind, ids, signed, state, workspace


pytestmark = pytest.mark.postgres
ARTICLE_NAMESPACE = UUID("e2de4574-ded7-5764-817b-ed269571fe6e")
GENERATOR = Path(__file__).resolve().parents[2] / "evals" / "helpdesk_export.py"


def make_importer(db: AppDatabase) -> tuple[TicketImport, HelpdeskSettings]:
    app = db.engine(APP_RUNTIME, pool_size=5)
    config = settings(workspace(db), enabled=False)
    bind(app, config, customer=CUSTOMER)
    return TicketImport(app, config.connections[0]), config


def project_state(importer: TicketImport) -> tuple[list[dict[str, Any]], set[UUID]]:
    tenant = importer.config.workspace_id
    with workspace_transaction(importer.engine, tenant) as connection:
        links = connection.execute(text("""
            SELECT l.ticket_id, l.group_id, l.requester_id, l.customer_user_id, l.state_id, l.ticket_updated_at,
                   l.max_article_id, l.case_id, c.status, c.customer_user_id AS case_customer
            FROM app.helpdesk_ticket_links l JOIN app.cases c ON (l.workspace_id, l.case_id) = (c.workspace_id, c.id)
            ORDER BY l.ticket_id
        """)).mappings().all()
        rows = connection.execute(text("""
            SELECT case_id, id, source, sequence, text_sha256 FROM app.case_messages ORDER BY case_id, sequence
        """)).all()
        cases = connection.execute(text("SELECT id FROM app.cases")).scalars().all()
    messages: dict[UUID, list[tuple[UUID, str]]] = {case: [] for case in cases}
    for row in rows:
        bucket = messages[row.case_id]
        assert row.sequence == len(bucket) + 1 and row.source == "helpdesk_ticket"
        bucket.append((row.id, row.text_sha256))
    result = []
    for link in links:
        assert link.status == "open" and link.case_customer == link.customer_user_id
        entry = dict(link)
        del entry["status"], entry["case_customer"], entry["case_id"]
        entry["ticket_updated_at"] = link.ticket_updated_at.isoformat().replace("+00:00", "Z")
        namespace = uuid5(ARTICLE_NAMESPACE, str(tenant))
        source_ids = {uuid5(namespace, f"{importer.config.connection_id}:{link.ticket_id}:{article_id}"): article_id
                      for article_id in range(1, link.max_article_id + 1)}
        entry["messages"] = [{"article_id": source_ids[identity], "text_sha256": sha}
                             for identity, sha in messages[link.case_id]]
        result.append(entry)
    assert len(links) == len(cases)
    return result, set(cases)


def assert_effects(importer: TicketImport, records: int, *, events: int = 0, runs: int = 1) -> None:
    with workspace_transaction(importer.engine, importer.config.workspace_id) as connection:
        row = connection.execute(text("""
            SELECT
                (SELECT count(*) FROM app.audit_events WHERE action = 'helpdesk.import') AS audits,
                (SELECT count(*) FROM app.helpdesk_imports) AS runs,
                (SELECT coalesce(sum(next_record), 0) FROM app.helpdesk_imports) AS committed,
                (SELECT count(*) FROM app.helpdesk_import_records) AS ledger,
                (SELECT count(*) FROM app.helpdesk_events) AS events,
                (SELECT count(*) FROM app.helpdesk_writebacks) AS writebacks,
                (SELECT count(*) FROM app.customer_consents) AS consents
        """)).one()
        assert tuple(row) == (runs, runs, records, records, events, 0, 0)


def ledger(importer: TicketImport) -> list[tuple[Any, ...]]:
    with workspace_transaction(importer.engine, importer.config.workspace_id) as connection:
        rows = connection.execute(text("""
            SELECT record_no, ticket_id, record_sha256, disposition, reason
            FROM app.helpdesk_import_records ORDER BY record_no
        """))
        return [tuple(row) for row in rows]


def test_pinned_retail_fixture_matches_independent_oracle(
    shared_db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    git_cache = _temp_root() / "cache/uv-evals-raw-v1/git-v1/checkouts"
    fixtures = sorted(git_cache.glob("*/19f13ea/data/tau2/domains/retail/db.json"))
    assert fixtures, "sync the frozen evaluator environment before the PostgreSQL lane"
    output = tmp_path / "retail"
    workstation = os.environ.get("POLICYOPS_N14_WORKSTATION_HARDWARE")
    subprocess.run([sys.executable, "-B", str(GENERATOR), "--db", str(fixtures[0]), "--output", str(output),
                    "--orders", "1000" if workstation else "48"], check=True)
    expected = json.loads((output / "expected.json").read_bytes())
    bindings = json.loads((output / "bindings.json").read_bytes())
    importer, _ = make_importer(shared_db)
    with workspace_transaction(importer.engine, importer.config.workspace_id) as connection:
        for item in bindings:
            helpdesk_store.seed_binding(connection, workspace=importer.config.workspace_id,
                connection_id=importer.config.connection_id, requester_id=item["requester_id"],
                customer=item["customer_user_id"], seed_id=item["seed_id"], now=NOW)

    def no_http(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("historical import attempted HTTP")

    monkeypatch.setattr(httpx.Client, "send", no_http)
    monkeypatch.setattr(httpx.AsyncClient, "send", no_http)
    archive_path = output / "tickets.csv"
    source = VerifiedExport.read(archive_path)
    exported_at = utc_timestamp(expected["exported_at"])
    plan = importer.plan(source, exported_at)
    assert plan["records_total"] == len(expected["outcomes"])
    assert plan["valid"] == sum(row["disposition"] != "rejected" for row in expected["outcomes"])
    assert_effects(importer, 0, runs=0)

    started = perf_counter()
    report = importer.run(source, exported_at)
    elapsed = perf_counter() - started
    assert report.state == "completed" and report.next_record == report.records_total
    assert [asdict(item) for item in report.outcomes] == expected["outcomes"]
    assert Counter(row.reason for row in report.outcomes) == expected["counts_by_reason"]
    assert report.counts == Counter(row["disposition"] for row in expected["outcomes"])
    assert report.counts["quarantined"] > 0
    assert Counter(row.reason for row in report.outcomes)["snapshot_conflict"] == 1
    assert Counter(row.reason for row in report.outcomes)["incompatible_history"] == 1
    links, _ = project_state(importer)
    assert links == expected["links"]
    assert_effects(importer, source.records_total)
    if workstation:
        print(json.dumps({"workstation_hardware": workstation, "file_sha256": source.sha256, "file_bytes": source.size,
                          "batch_records": BATCH_RECORDS, "batch_bytes": BATCH_BYTES, "elapsed_s": elapsed,
                          "committed_records": report.next_record, "records_per_s": report.next_record / elapsed}))


def test_kill_after_each_batch_and_inside_batch(shared_db: AppDatabase, tmp_path: Path) -> None:
    path = tmp_path / "history.csv"
    source = archive(path, *(snapshot(1 + (i % 3), ticket_id=42 + i) for i in range(2 * BATCH_RECORDS + 3)))
    uninterrupted, _ = make_importer(shared_db)
    expected = uninterrupted.run(source, EXPORTED_AT)
    expected_state, _ = project_state(uninterrupted)
    for after, mid_batch, durable in (
        (BATCH_RECORDS, False, BATCH_RECORDS),
        (2 * BATCH_RECORDS, False, 2 * BATCH_RECORDS),
        (source.records_total, False, source.records_total),
        (BATCH_RECORDS + 2, True, BATCH_RECORDS),
    ):
        importer, _ = make_importer(shared_db)
        ready = tmp_path / f"paused-{after}"
        process = helpdesk_import_process.start(shared_db, workspace=importer.config.workspace_id, source=path,
            sha256=source.sha256, exported_at=EXPORTED_AT, ready=ready, after=after, mid_batch=mid_batch)
        try:
            deadline = monotonic() + 30
            while not ready.is_file():
                assert process.poll() is None, f"import process exited before pause ({process.returncode})"
                assert monotonic() < deadline, "import process never reached its pause"
                sleep(0.02)
            assert process.poll() is None
            process.kill()
        finally:
            worker_process.stop(process)
        assert importer.report(source.sha256).next_record == durable
        assert_effects(importer, durable)
        assert importer.run(VerifiedExport.read(path, expected_sha256=source.sha256), EXPORTED_AT) == expected
        assert project_state(importer)[0] == expected_state
        assert ledger(importer) == ledger(uninterrupted)
        assert_effects(importer, source.records_total)


class Crash(RuntimeError):
    pass


def test_precommit_crash_concurrent_resume_changed_file_and_completed_rerun(
    shared_db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer, _ = make_importer(shared_db)
    path = tmp_path / "history.csv"
    source = archive(path, *(snapshot(1, ticket_id=42 + i) for i in range(BATCH_RECORDS + 2)))
    real_advance = import_store.advance

    def crash(connection: Connection, tenant: UUID, run: Checkpoint, outcomes: list[Outcome]) -> Checkpoint:
        result = real_advance(connection, tenant, run, outcomes)
        if result.state == "completed":
            raise Crash
        return result

    with monkeypatch.context() as fault:
        fault.setattr(import_store, "advance", crash)
        with pytest.raises(Crash):
            importer.run(source, EXPORTED_AT)
    assert importer.report(source.sha256).next_record == BATCH_RECORDS
    assert_effects(importer, BATCH_RECORDS)
    assert len(project_state(importer)[0]) == BATCH_RECORDS

    changed_path = tmp_path / "changed.csv"
    changed = archive(changed_path, snapshot(3))
    with pytest.raises(ImportRefused, match=r"^input_sha256_mismatch$"):
        VerifiedExport.read(changed_path, expected_sha256=source.sha256)
    with pytest.raises(ImportRefused, match=r"^run_parameters_changed$"):
        importer.run(source, EXPORTED_AT + timedelta(seconds=1))
    with pytest.raises(ImportRefused, match=r"^run_parameters_changed$"):
        TicketImport(importer.engine, importer.config.model_copy(
            update={"allowed_group_ids": frozenset({7, 8})})).run(source, EXPORTED_AT)
    with pytest.raises(ImportRefused, match=r"^run_parameters_changed$"):
        TicketImport(importer.engine, importer.config.model_copy(
            update={"api_origin": "https://changed.example.invalid"})).run(source, EXPORTED_AT)
    assert_effects(importer, BATCH_RECORDS)

    real_lock = import_store.try_lock_connection
    first_locked, second_refused = Event(), Event()
    gate = Barrier(2)

    def lock(connection: Connection, key: ImportKey) -> bool:
        result = real_lock(connection, key)
        if result and not first_locked.is_set():
            first_locked.set()
            assert second_refused.wait(3)
        if not result:
            second_refused.set()
        return result

    def resume() -> Report:
        gate.wait(3)
        return importer.run(VerifiedExport.read(path, expected_sha256=source.sha256), EXPORTED_AT)

    with monkeypatch.context() as race:
        race.setattr(import_store, "try_lock_connection", lock)
        with ThreadPoolExecutor(2) as pool:
            first, second = pool.submit(resume), pool.submit(resume)
            completed = first.result(10)
            assert completed == second.result(10)
    assert second_refused.is_set() and completed.next_record == source.records_total
    assert importer.run(source, EXPORTED_AT) == importer.report(source.sha256) == completed
    assert ledger(importer) == [(row.number, row.ticket_id, row.sha256, "accepted", "case_created")
                                for batch in source.batches(EXPORTED_AT) for row in batch]
    assert_effects(importer, source.records_total)
    importer.run(changed, EXPORTED_AT)
    assert_effects(importer, source.records_total + 1, runs=2)


def test_lost_commit_acknowledgement_rereads_durable_cursor(
    shared_db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer, _ = make_importer(shared_db)
    source = archive(tmp_path / "history.csv", *(snapshot(1, ticket_id=42 + i) for i in range(BATCH_RECORDS + 1)))
    original_advance, original_read = import_store.advance, import_store.checkpoint
    advanced, lost = False, False
    reads = []

    def advance(connection: Connection, tenant: UUID, run: Checkpoint, outcomes: list[Outcome]) -> Checkpoint:
        nonlocal advanced
        result = original_advance(connection, tenant, run, outcomes)
        advanced = True
        return result

    @contextmanager
    def lose_ack(connection: Connection, tenant: UUID) -> Iterator[Connection]:
        nonlocal lost
        with connection_transaction(connection, tenant) as active:
            yield active
        if advanced and not lost:
            lost = True
            raise TransactionOutcomeUnknown()

    def read(connection: Connection, key: ImportKey) -> Checkpoint | None:
        result = original_read(connection, key)
        reads.append(None if result is None else result.next_record)
        return result

    monkeypatch.setattr(import_store, "advance", advance)
    monkeypatch.setattr(import_store, "checkpoint", read)
    monkeypatch.setattr(service, "connection_transaction", lose_ack)
    report = importer.run(source, EXPORTED_AT)
    assert lost and reads == [None, BATCH_RECORDS]
    assert report.next_record == source.records_total and report.counts["accepted"] == source.records_total
    assert_effects(importer, source.records_total)


def deliver(worker: HelpdeskWorker, inbound: Inbound, fake: FakeZammad, step: int) -> tuple[str, str | None]:
    raw = webhook(updated_at=NOW + timedelta(milliseconds=step))
    assert signed(inbound, raw) == 202
    tenant = fake.config.workspace_id
    event = ids(inbound.engine, tenant, helpdesk_store.Queue.EVENTS)[-1]
    # All fixture event timestamps are distinct via the lease clock used in the tests.
    assert worker.process_event(tenant, event)
    return state(inbound.engine, tenant, helpdesk_store.Queue.EVENTS, event)


def harness(db: AppDatabase, importer: TicketImport, settings: HelpdeskSettings,
            step: int) -> tuple[HelpdeskWorker, Inbound, FakeZammad]:
    lease = FixedLeaseClock(FixedClock(NOW + timedelta(seconds=step)))
    fake = FakeZammad(importer.config)
    worker = HelpdeskWorker(env="test", app=importer.engine, discovery=db.engine(WORKER_DISCOVERY),
                            settings=settings, clock=lease, transport=fake.transport)
    return worker, Inbound(settings, importer.engine, lease), fake


def test_all_mixed_snapshot_orders_converge(shared_db: AppDatabase, tmp_path: Path) -> None:
    snapshots = {n: snapshot(n) for n in range(1, 6)}
    sources = {n: archive(tmp_path / f"r{n}.csv", snapshots[n]) for n in (1, 3, 5)}
    digests = set()
    for order in permutations(snapshots):
        importer, config = make_importer(shared_db)
        for step, revision in enumerate(order, 1):
            if revision in sources:
                importer.run(sources[revision], EXPORTED_AT)
            else:
                worker, inbound, fake = harness(shared_db, importer, config, step)
                fake.ticket, fake.articles = snapshots[revision]
                outcome, _ = deliver(worker, inbound, fake, step)
                assert outcome in {"applied", "stale"}
        links, _ = project_state(importer)
        [link] = links
        assert link["state_id"] == 6 and link["max_article_id"] == 6 and len(link["messages"]) == 5
        digests.add(hashlib.sha256(json.dumps(links, sort_keys=True).encode()).hexdigest())
        assert_effects(importer, 3, events=2, runs=3)
    assert len(digests) == 1


@pytest.mark.parametrize("leader", ["import", "webhook"])
def test_first_creation_race_in_both_lock_orders(
    shared_db: AppDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leader: str,
) -> None:
    importer, config = make_importer(shared_db)
    source = archive(tmp_path / "r1.csv", snapshot(1))
    worker, inbound, fake = harness(shared_db, importer, config, 1)
    fake.ticket, fake.articles = snapshot(2)
    locked, entered = Event(), Event()
    original_lock = helpdesk_store.lock_ticket

    def lock(connection: Connection, tenant: UUID, connection_id: str, ticket_id: int) -> helpdesk_store.Link | None:
        if current_thread().name.startswith(leader):
            link = original_lock(connection, tenant, connection_id, ticket_id)
            assert link is None
            locked.set()
            assert entered.wait(2)
            return link
        assert locked.wait(2)
        entered.set()
        return original_lock(connection, tenant, connection_id, ticket_id)

    with monkeypatch.context() as race:
        race.setattr(helpdesk_store, "lock_ticket", lock)
        with ThreadPoolExecutor(1, thread_name_prefix="import") as migration, ThreadPoolExecutor(
                1, thread_name_prefix="webhook") as live:
            if leader == "import":
                imported = migration.submit(importer.run, source, EXPORTED_AT)
                assert locked.wait(2)
                delivered = live.submit(deliver, worker, inbound, fake, 1)
            else:
                delivered = live.submit(deliver, worker, inbound, fake, 1)
                assert locked.wait(2)
                imported = migration.submit(importer.run, source, EXPORTED_AT)
            result = imported.result(10)
            assert delivered.result(10) == ("applied", None)
    assert result.outcomes[0].disposition == ("accepted" if leader == "import" else "skipped_stale")
    [link], _ = project_state(importer)
    assert link["state_id"] == 3 and [m["article_id"] for m in link["messages"]] == [1, 3]
    assert_effects(importer, 1, events=1)


def test_future_record_and_export_refused_then_newer_webhook_applies(shared_db: AppDatabase, tmp_path: Path) -> None:
    importer, config = make_importer(shared_db)
    ticket, articles = snapshot(2)
    future = ticket | {"updated_at": (EXPORTED_AT + timedelta(seconds=1)).isoformat()}
    source = archive(tmp_path / "mixed.csv", snapshot(1), (future, articles))
    with workspace_transaction(importer.engine, importer.config.workspace_id) as connection:
        exported_in_future = DatabaseLeaseClock().now(connection) + timedelta(minutes=6)
    for invoke in (importer.plan, importer.run):
        with pytest.raises(ImportRefused, match=r"^exported_at_in_future$"):
            invoke(source, exported_in_future)
    assert_effects(importer, 0, runs=0)
    report = importer.run(source, EXPORTED_AT)
    assert report.outcomes[1].reason == "future_ticket"
    worker, inbound, fake = harness(shared_db, importer, config, 1)
    fake.ticket, fake.articles = snapshot(3)
    assert deliver(worker, inbound, fake, 1) == ("applied", None)
    [link], _ = project_state(importer)
    assert link["state_id"] == 4
    assert_effects(importer, 2, events=1)


def test_import_preserves_existing_webhook_projection_on_conflict(
    shared_db: AppDatabase, tmp_path: Path,
) -> None:
    importer, config = make_importer(shared_db)
    worker, inbound, fake = harness(shared_db, importer, config, 1)
    ticket, articles = snapshot(2)
    fake.ticket, fake.articles = ticket, articles
    assert deliver(worker, inbound, fake, 1) == ("applied", None)
    before = project_state(importer)
    changed = [articles[0] | {"body": "edited"}, *articles[1:]]
    higher = ticket | {"updated_at": (NOW + timedelta(seconds=3)).isoformat()}
    source = archive(tmp_path / "existing.csv", (ticket, articles), (ticket | {"state_id": 8}, articles),
                     (ticket, changed), (higher, changed), (higher, articles[1:]))
    report = importer.run(source, EXPORTED_AT)
    assert [row.reason for row in report.outcomes] == [
        "same_snapshot", "snapshot_conflict", "snapshot_conflict", "incompatible_history", "incompatible_history",
    ]
    assert project_state(importer) == before
    assert_effects(importer, 5, events=1)


def test_header_only_import_has_one_audit_and_no_outcomes(shared_db: AppDatabase, tmp_path: Path) -> None:
    importer, _ = make_importer(shared_db)
    source = archive(tmp_path / "empty.csv")
    assert importer.plan(source, EXPORTED_AT)["valid"] == 0
    assert_effects(importer, 0, runs=0)
    result = importer.run(source, EXPORTED_AT)
    assert result.state == "completed" and result.next_record == 0 and result.outcomes == ()
    assert importer.run(source, EXPORTED_AT) == importer.report(source.sha256) == result
    assert_effects(importer, 0)


def test_runtime_tenant_isolation_and_scoped_foreign_key(shared_db: AppDatabase, tmp_path: Path) -> None:
    first, _ = make_importer(shared_db)
    second, _ = make_importer(shared_db)
    source = archive(tmp_path / "history.csv", snapshot(1), snapshot(2))
    expected = first.run(source, EXPORTED_AT)
    with workspace_transaction(first.engine, first.config.workspace_id) as connection:
        foreign = connection.execute(text("SELECT id FROM app.helpdesk_imports")).scalar_one()
        with pytest.raises(DBAPIError) as invalid, connection.begin_nested():
            connection.execute(text("UPDATE app.helpdesk_imports SET accepted = 0"))
        assert sqlstate(invalid.value) == "23514"
    assert_effects(second, 0, runs=0)
    with pytest.raises(ImportRefused, match=r"^run_not_found$"):
        second.report(source.sha256)
    with workspace_transaction(second.engine, second.config.workspace_id) as connection:
        with pytest.raises(DBAPIError) as foreign_key, connection.begin_nested():
            connection.execute(text("""
                INSERT INTO app.helpdesk_import_records
                    (workspace_id, import_id, record_no, ticket_id, record_sha256, disposition, reason)
                VALUES (:workspace, :run, 1, 42, :sha, 'accepted', 'case_created')
            """), {"workspace": second.config.workspace_id, "run": foreign, "sha": source.sha256})
        assert sqlstate(foreign_key.value) == "23503"
        assert connection.execute(text("SELECT count(*) FROM app.helpdesk_import_records")).scalar_one() == 0

    assert second.run(source, EXPORTED_AT) == expected
    first_links, first_cases = project_state(first)
    second_links, second_cases = project_state(second)
    assert first_links == second_links and first_cases.isdisjoint(second_cases)
    assert_effects(first, 2)
    assert_effects(second, 2)
