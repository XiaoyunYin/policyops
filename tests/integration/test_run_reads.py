"""G1-G4 through the served API, on head and as the real RLS runtime role.

Synthetic ingested corpora, controlled time; no Docker execution is implied by collection.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from policyops.persistence import migrate
from policyops.persistence import repositories as repo
from policyops.persistence import runs as store
from policyops.persistence.database import workspace_transaction
from policyops.persistence.roles import APP_RUNTIME
from policyops.providers import tokenizer as tk
from policyops.retrieval.ingest import PaidCaps, Request, ingest
from policyops.runtime.spec import RuntimeCatalog
from policyops_contracts.digest import text_sha256
from policyops_contracts.events import EscalationRequested, ExecutionChanged, ReviewOutcome, ReviewReason, RunStopped
from policyops_contracts.retail import ToolName
from policyops_contracts.stops import StopDetails, StopReason
from policyops_testing import case_api
from policyops_testing.app_database import AppDatabase
from policyops_testing.case_api import CaseApi
from policyops_testing.corpus_fixtures import CredentialReads, FixtureCorpus, ScriptedEmbeddings, banking, write
from policyops_testing.scripted import ScriptedExecutor, scripted_spec


pytestmark = pytest.mark.postgres


@dataclass
class Reads:
    api: CaseApi
    ws: UUID
    browser: Any
    case: UUID
    run: UUID
    root: Path
    activations: int = 0

    def get(self, path: str, template: str, **params: Any) -> Any:
        return self.api.get(self.browser, path, template, **params)

    def snapshot(self, **params: Any) -> Any:
        return self.get(f"/api/v1/runs/{self.run}/snapshot", "/api/v1/runs/{run_id}/snapshot", **params)

    def activate(self, body: str) -> UUID:
        self.activations += 1
        root = self.root / f"acquisition-{self.activations}"
        raw, digest = write(root, [FixtureCorpus("ui-sources", "banking_knowledge", "tau2-banking/v1",
                                                {"p": banking("p", "Historical policy", body)})])
        result = ingest(Request(self.ws, "ui-sources", raw, digest, root, "execute",
            PaidCaps("text-embedding-3-small", 1536, Decimal("0.01"), 64, 1000000, 3600)),
            engine=self.api.runtime.app_engine, tokenizer=tk.load(),
            providers=CredentialReads(ScriptedEmbeddings()), env="test")
        assert result.outcome == "activated", result.outcome
        return UUID(result.details["generation_id"])

    def cite(self, generation: UUID, quote: str) -> UUID:
        citation, trace = uuid4(), uuid4()
        with workspace_transaction(self.api.runtime.app_engine, self.ws) as conn:
            row = conn.execute(text("SELECT id, document_version_id, start_offset, text FROM app.chunks "
                "WHERE generation_id=:g AND position(:quote IN text)>0 ORDER BY start_offset LIMIT 1"),
                {"g": generation, "quote": quote}).one()
            start = row.start_offset + row.text.index(quote)
            conn.execute(text("INSERT INTO app.retrieval_traces (id,workspace_id,run_id,generation_id,query_sha256,"
                "authorized_scope,candidates,final_chunk_ids,created_at) VALUES "
                "(:id,:w,:r,:g,:sha,'{}','[]','{}',:now)"), {"id": trace, "w": self.ws, "r": self.run,
                "g": generation, "sha": "f" * 64, "now": self.api.clock.now()})
            conn.execute(text("INSERT INTO app.citations (id,workspace_id,trace_id,chunk_id,document_version_id,"
                "span_start,span_end,created_at) VALUES (:id,:w,:t,:k,:v,:s,:e,:now)"),
                {"id": citation, "w": self.ws, "t": trace, "k": row.id, "v": row.document_version_id,
                 "s": start, "e": start + len(quote), "now": self.api.clock.now()})
        return citation

    def evidence(self, citation: UUID, run: UUID | None = None) -> Any:
        return self.get(f"/api/v1/evidence/{citation}", "/api/v1/evidence/{citation_id}", run_id=str(run or self.run))


@pytest.fixture
def reads(shared_db: AppDatabase, tmp_path: Path) -> Reads:
    assert shared_db.current() == migrate.head()
    spec = scripted_spec(ScriptedExecutor())
    api = case_api.build(shared_db, catalog=RuntimeCatalog.of([spec], default=spec.spec_id), pool_size=6)
    ws = api.workspace("ui-read")
    browser = api.member(f"ui-{uuid4().hex}", ws, "analyst")
    case = UUID(api.create(browser).json()["case_id"])
    run = UUID(api.start_run(browser, case, '"1"').json()["run_id"])
    return Reads(api, ws, browser, case, run, tmp_path)


def test_runtime_identity_and_run_page_cursor_is_bound_to_case(reads: Reads) -> None:
    api = reads.api
    with workspace_transaction(api.runtime.app_engine, reads.ws) as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == APP_RUNTIME
        assert conn.execute(text("SHOW statement_timeout")).scalar_one() == "5s"
        assert conn.execute(text("SHOW lock_timeout")).scalar_one() == "1s"
    api.cancel_run(reads.browser, reads.run)
    second = api.start_run(reads.browser, reads.case, '"1"').json()["run_id"]
    path, template = f"/api/v1/cases/{reads.case}/runs", "/api/v1/cases/{case_id}/runs"
    first = reads.get(path, template, limit=1)
    assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
    cursor = first.json()["next_cursor"]
    assert cursor is not None
    next_page = reads.get(path, template, limit=1, cursor=cursor)
    assert {first.json()["items"][0]["run_id"], next_page.json()["items"][0]["run_id"]} == {str(reads.run), second}
    assert next_page.json()["next_cursor"] is None
    other = api.create(reads.browser).json()["case_id"]
    assert reads.get(f"/api/v1/cases/{other}/runs", template, cursor=cursor).status_code == 422
    assert reads.get(path, template, cursor="!" * 401).status_code == 422
    assert reads.get(path, template, limit=101).status_code == 422
    assert reads.get(f"/api/v1/cases/{uuid4()}/runs", template).status_code == 404
    assert reads.get(f"/api/v1/cases/{other}/runs", template).json()["items"] == []


def test_snapshot_keeps_latest_typed_projections_outside_tail_and_reports_retention(reads: Reads) -> None:
    with workspace_transaction(reads.api.runtime.app_engine, reads.ws) as conn:
        run = store.get_run(conn, reads.run, lock=True)
        assert run is not None
        now = reads.api.clock.now()
        store.append_event(conn, run, ReviewOutcome(proposal_id=uuid4(), proposal_version=1, outcome="refused",
            reason=ReviewReason.REVIEW_REJECTED, message_id=uuid4()), now)
        store.append_event(conn, run, RunStopped(message_id=uuid4(),
            details=StopDetails(reason=StopReason.CALL_CAP)), now)
        store.append_event(conn, run, ExecutionChanged(execution_id=uuid4(), operation_id=uuid4(),
            tool=ToolName.CANCEL_PENDING_ORDER, state="unknown", attempt=1), now)
        for _ in range(105):
            store.append_event(conn, run, EscalationRequested(rule_id="test.activity"), now)
    response = reads.snapshot(tail=2)
    assert response.status_code == 200
    s = response.json()
    assert s["highwater"] == s["run"]["event_highwater"] == 109
    assert [e["sequence"] for e in s["events"]] == [108, 109]
    assert [s[k]["sequence"] for k in ("latest_review", "latest_stop", "latest_execution")] == [2, 3, 4]
    assert s["projections_complete"]
    assert reads.snapshot(tail=0).json()["events"] == []
    assert reads.snapshot(tail=101).status_code == 422
    with reads.api.db.superuser() as conn:  # simulate a future operator retention purge, not a runtime privilege
        conn.execute("DELETE FROM app.run_events WHERE run_id=%s AND sequence<=3", (reads.run,))
        conn.execute("UPDATE app.runs SET event_retention_floor=3 WHERE id=%s", (reads.run,))
    s = reads.snapshot(tail=0).json()
    assert not s["projections_complete"] and s["retention_floor"] == 3
    assert s["latest_review"] is None and s["latest_execution"]["sequence"] == 4


def test_snapshot_has_one_database_snapshot_during_a_concurrent_append(reads: Reads, monkeypatch: pytest.MonkeyPatch
                                                                      ) -> None:
    original = store.events_after
    injected = False

    def events(*args: Any, **kwargs: Any) -> Any:
        nonlocal injected
        if not injected:
            injected = True
            with workspace_transaction(reads.api.runtime.app_engine, reads.ws) as conn:
                run = store.get_run(conn, reads.run, lock=True)
                assert run is not None
                store.append_event(conn, run, EscalationRequested(rule_id="test.concurrent"), reads.api.clock.now())
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "events_after", events)
    s = reads.snapshot().json()
    assert s["highwater"] == 1 and [e["sequence"] for e in s["events"]] == [1]
    assert reads.snapshot().json()["highwater"] == 2


def test_snapshot_unsupported_positions_are_identifier_only_and_holes_refuse(reads: Reads) -> None:
    with reads.api.db.superuser() as conn:  # corrupt/forward-version row, never emitted by this app
        conn.execute("UPDATE app.run_events SET schema_version='policyops.run-event/v99',payload='{}' WHERE run_id=%s", (reads.run,))
    s = reads.snapshot().json()
    assert set(s["events"][0]) == {"event_id", "sequence", "event_type", "schema_version"}
    assert not s["projections_complete"]
    with reads.api.db.superuser() as conn:
        conn.execute("DELETE FROM app.run_events WHERE run_id=%s", (reads.run,))
    assert reads.snapshot().status_code == 409


def test_historical_unicode_excerpt_and_citation_pagination_survive_reindex(reads: Reads) -> None:
    quote = "😀 Cafe\u0301 refunds return to the original method."
    generation = reads.activate("Prefix. " + quote + " Suffix.")
    ids = {reads.cite(generation, quote), reads.cite(generation, "refunds")}
    path, template = f"/api/v1/runs/{reads.run}/citations", "/api/v1/runs/{run_id}/citations"
    page = reads.get(path, template, limit=1).json()
    next_page = reads.get(path, template, limit=1, cursor=page["next_cursor"]).json()
    assert {UUID(page["items"][0]["citation_id"]), UUID(next_page["items"][0]["citation_id"])} == ids
    assert next_page["next_cursor"] is None
    resolved = {c: reads.evidence(c).json() for c in ids}
    chosen = next(c for c, e in resolved.items() if e["span_end"] - e["span_start"] == len(quote))
    before = reads.evidence(chosen).json()
    reads.activate("A newer policy says something different.")
    after = reads.evidence(chosen)
    assert after.status_code == 200 and after.json() == before
    e = after.json()
    assert e["text"][e["span_start"] - e["excerpt_start"]:e["span_end"] - e["excerpt_start"]] == quote
    assert e["quote_sha256"] == text_sha256(quote)
    assert len(e["text"]) <= 20512 and e["span_start"] - e["excerpt_start"] <= 256
    assert e["excerpt_end"] - e["span_end"] <= 256
    other = UUID(reads.api.create(reads.browser).json()["case_id"])
    other_run = UUID(reads.api.start_run(reads.browser, other, '"1"').json()["run_id"])
    assert reads.get(f"/api/v1/runs/{other_run}/citations", template, cursor=page["next_cursor"]).status_code == 422
    mismatch = reads.evidence(chosen, other_run)
    assert mismatch.status_code == 404 and mismatch.json()["rule_id"] == reads.evidence(uuid4()).json()["rule_id"]


@pytest.mark.parametrize("resource", ["runs", "snapshot", "citations", "evidence"])
def test_every_read_hides_foreign_ids_and_refuses_revoked_membership(reads: Reads, resource: str) -> None:
    generation = reads.activate("Synthetic refunds are permitted.")
    citation = reads.cite(generation, "refunds")
    paths = {
        "runs": (f"/api/v1/cases/{reads.case}/runs", "/api/v1/cases/{case_id}/runs", {}),
        "snapshot": (f"/api/v1/runs/{reads.run}/snapshot", "/api/v1/runs/{run_id}/snapshot", {}),
        "citations": (f"/api/v1/runs/{reads.run}/citations", "/api/v1/runs/{run_id}/citations", {}),
        "evidence": (f"/api/v1/evidence/{citation}", "/api/v1/evidence/{citation_id}", {"run_id": str(reads.run)}),
    }
    path, template, params = paths[resource]
    assert reads.get(path, template, **params).status_code == 200
    stranger = reads.api.member(f"stranger-{uuid4().hex}", reads.api.workspace("other"), "auditor")
    assert reads.api.get(stranger, path, template, **params).status_code == 404
    who = f"revoked-{uuid4().hex}"
    viewer = reads.api.member(who, reads.ws, "auditor")
    assert reads.api.get(viewer, path, template, **params).status_code == 200
    with workspace_transaction(reads.api.runtime.app_engine, reads.ws) as conn:
        membership = conn.execute(text("SELECT id FROM identity.memberships WHERE principal_id=:p "
                                       "AND revoked_at IS NULL"), {"p": reads.api.principal(who)}).scalar_one()
        assert repo.revoke_membership(conn, membership, reads.api.clock.now())
    assert reads.api.get(viewer, path, template, **params).status_code == 403


def test_evidence_digest_corruption_is_an_integrity_conflict(reads: Reads) -> None:
    citation = reads.cite(reads.activate("A recorded refund rule."), "refund")
    version = UUID(reads.evidence(citation).json()["document_version_id"])
    with reads.api.db.superuser() as conn:  # damage immutable historical bytes, explicitly outside runtime grants
        conn.execute("SET session_replication_role=replica")
        conn.execute("UPDATE app.document_versions SET body='damaged' WHERE id=%s", (version,))
        conn.execute("SET session_replication_role=DEFAULT")
    assert reads.evidence(citation).status_code == 409
