"""Bounded workbench reads. Every read rechecks membership under the runtime role.

Snapshots use repeatable-read, including the clock, run bounds and projections. No
purger exists today; after physical retention, missing historical truth is explicit.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Literal, get_args
from uuid import UUID

from pydantic import Field, ValidationError
from sqlalchemy import Connection, Engine, text

from policyops.auth.service import AuthError, Authorized
from policyops.domain.roles import Action
from policyops.persistence import repositories as repo
from policyops.persistence import runs as store
from policyops.persistence.database import workspace_transaction
from policyops.runtime.clock import LeaseClock
from policyops.services.runs import RunView, run_view
from policyops.services.writes import not_found, recheck
from policyops_contracts.base import WireModel
from policyops_contracts.digest import text_sha256
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import EventEnvelope
from policyops_contracts.scalars import RunScope, Sha256Hex, UtcDatetime


SafePosition = Annotated[int, Field(ge=0, le=2**53 - 1)]
SafeVersion = Annotated[int, Field(ge=1, le=2**53 - 1)]
# Derive the stored discriminator inventory from the closed contract, avoiding another hand-maintained allowlist.
EVENT_TYPES = tuple(t.model_fields["type"].default for t in get_args(EventEnvelope.model_fields["payload"].annotation))


class UnsupportedEventView(WireModel):
    event_id: UUID
    sequence: SafeVersion
    event_type: Annotated[str, Field(max_length=256)]
    schema_version: Annotated[str, Field(max_length=256)]


ReplayItem = EventEnvelope | UnsupportedEventView


class ProposalRef(WireModel):
    proposal_id: UUID
    proposal_version: SafeVersion


class RunPage(WireModel):
    items: Annotated[list[RunView], Field(max_length=100)]
    next_cursor: Annotated[str, Field(max_length=400)] | None


class RunSnapshot(WireModel):
    run: RunView
    retention_floor: SafePosition
    highwater: SafePosition
    proposal_ref: ProposalRef | None
    events: Annotated[list[ReplayItem], Field(max_length=100)]
    latest_review: EventEnvelope | None
    latest_stop: EventEnvelope | None
    latest_execution: EventEnvelope | None
    latest_investigation: EventEnvelope | None = None
    projections_complete: bool
    server_time: UtcDatetime


class CitationSummary(WireModel):
    citation_id: UUID
    scope: RunScope
    document_id: UUID
    document_version_id: UUID
    version_sha256: Sha256Hex
    source_uri: Annotated[str, Field(max_length=2000)]
    span_start: SafePosition
    span_end: SafeVersion


class CitationPage(WireModel):
    items: Annotated[list[CitationSummary], Field(max_length=100)]
    next_cursor: Annotated[str, Field(max_length=400)] | None


class EvidenceView(CitationSummary):
    version: Annotated[str, Field(max_length=200)]
    excerpt_start: SafePosition
    excerpt_end: SafePosition
    text: Annotated[str, Field(max_length=20512)]
    quote_sha256: Sha256Hex


class ReadCursor(WireModel):
    v: Literal["ui1"] = "ui1"
    w: UUID
    resource: UUID
    kind: Literal["runs", "citations"]
    at: UtcDatetime
    id: UUID


def encode(cursor: ReadCursor) -> str:
    return base64.urlsafe_b64encode(cursor.model_dump_json().encode()).rstrip(b"=").decode()


def invalid() -> AuthError:
    return AuthError(422, ErrorCode.INVALID_INPUT, "Invalid page bounds or cursor.", "api.invalid_cursor")


def conflict() -> AuthError:
    return AuthError(409, ErrorCode.CONFLICT, "Stored evidence or activity could not be verified.",
                     "api.read_integrity_conflict")


def position(cursor: str | None, w: UUID, resource: UUID, kind: Literal["runs", "citations"], limit: int
             ) -> tuple[datetime, UUID] | None:
    if not 1 <= limit <= 100:
        raise invalid()
    if cursor is None:
        return None
    try:
        if not 1 <= len(cursor) <= 400 or not cursor.isascii():
            raise ValueError
        decoded = ReadCursor.model_validate_json(base64.b64decode(
            cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True))
        if encode(decoded) != cursor or (decoded.w, decoded.resource, decoded.kind) != (w, resource, kind):
            raise ValueError
        return decoded.at, decoded.id
    except (ValueError, binascii.Error):
        raise invalid() from None


def replay(item: store.StoredEvent) -> ReplayItem:
    if isinstance(item, store.UnsupportedEvent):
        return UnsupportedEventView(event_id=item.event_id, sequence=item.sequence,
                                    event_type=item.event_type, schema_version=item.schema_version)
    return item


CITATION_FROM = (
    "FROM app.citations c JOIN app.retrieval_traces t ON t.workspace_id=c.workspace_id AND t.id=c.trace_id "
    "JOIN app.document_versions v ON v.workspace_id=c.workspace_id AND v.id=c.document_version_id "
    "JOIN app.documents d ON d.workspace_id=v.workspace_id AND d.id=v.document_id "
    "JOIN app.index_generations g ON g.workspace_id=t.workspace_id AND g.id=t.generation_id ")
CITATION_COLUMNS = ("c.id AS citation_id, c.created_at, c.span_start, c.span_end, v.document_id, "
                    "c.document_version_id, v.sha256 AS version_sha256, d.source_uri ")


def citation(row: object, run: store.Run) -> CitationSummary:
    # SQLAlchemy RowMapping is consumed only at this persistence boundary.
    data = dict(row)  # type: ignore[call-overload]
    data.pop("created_at", None)
    return CitationSummary.model_validate({**data, "scope": run.scope}, strict=False)


@dataclass
class RunReads:
    engine: Engine
    clock: LeaseClock

    def _run(self, connection: Connection, authorized: Authorized, run_id: UUID) -> store.Run:
        recheck(connection, authorized, Action.VIEW_CASE)
        run = store.get_run(connection, run_id)
        if run is None:
            raise not_found("run")
        return run

    def runs(self, authorized: Authorized, case_id: UUID, *, cursor: str | None, limit: int) -> RunPage:
        before = position(cursor, authorized.workspace_id, case_id, "runs", limit)
        with workspace_transaction(self.engine, authorized.workspace_id) as conn:
            recheck(conn, authorized, Action.VIEW_CASE)
            if repo.get_case(conn, case_id) is None:
                raise not_found()
            clause = "AND (created_at, id) < (:at, :id) " if before else ""
            rows = conn.execute(text(
                f"SELECT {store.RUN_COLUMNS} FROM app.runs WHERE case_id=:case AND mode='workbench' "  # noqa: S608
                f"{clause}ORDER BY created_at DESC, id DESC LIMIT :limit"),
                {"case": case_id, "limit": limit + 1, "at": before[0] if before else None,
                 "id": before[1] if before else None}).mappings().all()
            items = [run_view(store.Run.model_validate(dict(row), strict=False)) for row in rows[:limit]]
        next_cursor = encode(ReadCursor(w=authorized.workspace_id, resource=case_id, kind="runs",
                                        at=items[-1].created_at, id=items[-1].run_id)) if len(rows) > limit else None
        return RunPage(items=items, next_cursor=next_cursor)

    def snapshot(self, authorized: Authorized, run_id: UUID, *, tail: int) -> RunSnapshot:
        if not 0 <= tail <= 100:
            raise invalid()
        with workspace_transaction(self.engine.execution_options(isolation_level="REPEATABLE READ"),
                                   authorized.workspace_id) as conn:
            run = self._run(conn, authorized, run_id)
            # One investigation ends with one proposal identity (versions may differ).
            refs = conn.execute(text("SELECT proposal_id, max(proposal_version) AS version "
                                     "FROM app.action_proposals WHERE run_id=:r GROUP BY proposal_id LIMIT 2"),
                                {"r": run_id}).all()
            executions = conn.execute(text("SELECT id FROM app.tool_executions WHERE run_id=:r LIMIT 2"),
                                      {"r": run_id}).all()
            if len(refs) > 1 or len(executions) > 1:
                raise conflict()
            start = max(run.event_retention_floor, run.event_highwater - tail)
            events = store.events_after(conn, run, start, tail) if tail else []
            if len(events) != min(tail, run.event_highwater - run.event_retention_floor):
                raise conflict()
            if any(e.sequence != start + i + 1 for i, e in enumerate(events)):
                raise conflict()
            latest: list[EventEnvelope | None] = []
            complete = run.event_retention_floor == 0 and not any(isinstance(e, store.UnsupportedEvent) for e in events)
            for kind in ("review.outcome", "run.stopped", "execution.changed", "investigation.outcome"):
                row = conn.execute(text(
                    "SELECT id, sequence, event_type, schema_version, payload::text AS payload, occurred_at "
                    "FROM app.run_events WHERE run_id=:r AND sequence<=:h AND event_type=:kind "
                    "ORDER BY sequence DESC LIMIT 1"), {"r": run_id, "h": run.event_highwater, "kind": kind}).first()
                item = store.decode_event(run, row) if row else None
                if isinstance(item, store.UnsupportedEvent):
                    complete = False
                    item = None
                latest.append(item)
            if conn.execute(text("SELECT EXISTS(SELECT 1 FROM app.run_events WHERE run_id=:r "
                                 "AND (schema_version<>:schema OR event_type<>ALL(:types)) AND sequence<=:h)"),
                            {"r": run_id, "schema": store.SUPPORTED_EVENT_SCHEMA,
                             "types": list(EVENT_TYPES),
                             "h": run.event_highwater}).scalar_one():
                complete = False
            try:
                return RunSnapshot(run=run_view(run), retention_floor=run.event_retention_floor,
                    highwater=run.event_highwater,
                    proposal_ref=ProposalRef(proposal_id=refs[0].proposal_id,
                                             proposal_version=refs[0].version) if refs else None,
                    events=[replay(e) for e in events], latest_review=latest[0], latest_stop=latest[1],
                    latest_execution=latest[2], latest_investigation=latest[3],
                    projections_complete=complete, server_time=self.clock.now(conn))
            except ValidationError:
                raise conflict() from None

    def citations(self, authorized: Authorized, run_id: UUID, *, cursor: str | None, limit: int) -> CitationPage:
        after = position(cursor, authorized.workspace_id, run_id, "citations", limit)
        with workspace_transaction(self.engine, authorized.workspace_id) as conn:
            run = self._run(conn, authorized, run_id)
            clause = "AND (c.created_at,c.id) > (:at,:id) " if after else ""
            rows = conn.execute(text("SELECT " + CITATION_COLUMNS + CITATION_FROM +
                "WHERE t.run_id=:r " + clause + "ORDER BY c.created_at,c.id LIMIT :limit"),
                {"r": run_id, "at": after[0] if after else None, "id": after[1] if after else None,
                 "limit": limit + 1}).mappings().all()
            items = [citation(row, run) for row in rows[:limit]]
        next_cursor = encode(ReadCursor(w=authorized.workspace_id, resource=run_id, kind="citations",
            at=rows[limit - 1]["created_at"], id=items[-1].citation_id)) if len(rows) > limit else None
        return CitationPage(items=items, next_cursor=next_cursor)

    def evidence(self, authorized: Authorized, run_id: UUID, citation_id: UUID) -> EvidenceView:
        with workspace_transaction(self.engine, authorized.workspace_id) as conn:
            recheck(conn, authorized, Action.VIEW_CASE)
            run = store.get_run(conn, run_id)
            if run is None:
                raise not_found("evidence")
            row = conn.execute(text("SELECT " + CITATION_COLUMNS +  # noqa: S608
                ", v.version::text AS version, char_length(v.body) AS body_length, "
                "encode(sha256(convert_to(v.body,'UTF8')),'hex') AS actual, "
                "greatest(0,c.span_start-256) AS excerpt_start, "
                "least(char_length(v.body),c.span_end+256) AS excerpt_end, "
                "CASE WHEN c.span_end-c.span_start<=20000 THEN substring(v.body FROM "
                "greatest(0,c.span_start-256)+1 FOR least(char_length(v.body),c.span_end+256)"
                "-greatest(0,c.span_start-256)) END AS text, "
                "g.corpus_key IS NOT NULL AS corpus_generation, EXISTS(SELECT 1 FROM app.generation_documents m "
                "WHERE m.workspace_id=c.workspace_id AND m.generation_id=t.generation_id "
                "AND m.document_version_id=c.document_version_id) AS member " + CITATION_FROM +
                "WHERE c.id=:c AND t.run_id=:r"), {"c": citation_id, "r": run_id}).mappings().first()
            if row is None:
                raise not_found("evidence")
            if (row["actual"] != row["version_sha256"] or row["span_end"] > row["body_length"]
                    or row["text"] is None or (row["corpus_generation"] and not row["member"])):
                raise conflict()
            data = {key: row[key] for key in CitationSummary.model_fields if key != "scope"}
            quote = row["text"][row["span_start"] - row["excerpt_start"]:row["span_end"] - row["excerpt_start"]]
            try:
                return EvidenceView.model_validate({**data, "scope": run.scope, "version": row["version"],
                    "excerpt_start": row["excerpt_start"], "excerpt_end": row["excerpt_end"], "text": row["text"],
                    "quote_sha256": text_sha256(quote)}, strict=False)
            except ValidationError:
                raise conflict() from None
