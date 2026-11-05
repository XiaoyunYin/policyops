"""Durable request idempotency (app runtime, workspace scope; table from revision 0004).

Intent: each write has an immutable, operation-specific typed intent (`CreateCaseIntent`, `StatusIntent`,
`MessageIntent`) whose `operation` is a fixed literal field, so it cannot be shadowed. Its digest is the SHA-256 of
the intent's JSON-mode dump serialized with sorted keys and no coercive fallbacks. Every intent carries the explicit
`schema_version` literal (a string, which strict validation cannot confuse with `true` or `1.0`); changing an
intent's fields or canonical form needs a new version.

Concurrency: `lock` takes a transaction-scoped advisory lock on the key's scope (workspace, principal, operation,
key), so concurrent requests with the same key serialize. The first commits its mutation and the stored response
together; later ones then find that record and replay it. A failed or rolled-back attempt stores nothing, so the
key stays usable. Only successful responses are stored, and they are never updated or expired here. Each record
links to its case, and a message write to the message of that case, by composite workspace foreign keys.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, StringConstraints
from sqlalchemy import Connection, text

from policyops_contracts.base import WireModel
from policyops_contracts.scalars import MessageText, PositiveVersion, Sha256Hex, UtcDatetime


Operation = Literal["case.create", "case.status", "case.message"]
IdempotencyKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._~-]{8,128}$")]


class CreateCaseIntent(WireModel):
    schema_version: Literal["policyops.idempotency-intent/v1"] = "policyops.idempotency-intent/v1"
    operation: Literal["case.create"] = "case.create"
    scenario: Literal["retail"]


class StatusIntent(WireModel):
    schema_version: Literal["policyops.idempotency-intent/v1"] = "policyops.idempotency-intent/v1"
    operation: Literal["case.status"] = "case.status"
    case_id: UUID
    expected_version: PositiveVersion
    status: Literal["open", "in_progress", "resolved", "closed"]


class MessageIntent(WireModel):
    schema_version: Literal["policyops.idempotency-intent/v1"] = "policyops.idempotency-intent/v1"
    operation: Literal["case.message"] = "case.message"
    case_id: UUID
    expected_version: PositiveVersion
    source: Literal["staff_note", "operator_entered_customer"]
    text: MessageText


Intent = CreateCaseIntent | StatusIntent | MessageIntent


def intent_sha256(intent: Intent) -> str:
    canonical = json.dumps(intent.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class StoredResponse(WireModel):
    request_sha256: Sha256Hex
    case_id: UUID
    message_id: UUID | None
    status: Annotated[int, Field(ge=200, le=299)]
    body_json: str
    etag: str | None


class NewRecord(WireModel):
    workspace_id: UUID
    principal_id: UUID
    operation: Operation
    idempotency_key: IdempotencyKey
    request_sha256: Sha256Hex
    case_id: UUID
    message_id: UUID | None
    status: Annotated[int, Field(ge=200, le=299)]
    body_json: str
    etag: str | None
    created_at: UtcDatetime


def lock(connection: Connection, *, workspace_id: UUID, principal_id: UUID, operation: Operation,
         key: str) -> None:
    connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                       {"scope": f"idempotency:{workspace_id}:{principal_id}:{operation}:{key}"})


def find(connection: Connection, *, principal_id: UUID, operation: Operation, key: str) -> StoredResponse | None:
    row = connection.execute(text(
        "SELECT request_sha256, case_id, message_id, response_status, response_body::text AS body, response_etag "
        "FROM app.request_idempotency WHERE principal_id = :p AND operation = :op AND idempotency_key = :k"),
        {"p": principal_id, "op": operation, "k": key}).mappings().first()
    if row is None:
        return None
    return StoredResponse(request_sha256=row["request_sha256"], case_id=row["case_id"], message_id=row["message_id"],
                          status=row["response_status"], body_json=row["body"], etag=row["response_etag"])


def store(connection: Connection, record: NewRecord) -> None:
    connection.execute(text(
        "INSERT INTO app.request_idempotency (workspace_id, principal_id, operation, idempotency_key, request_sha256, "
        "case_id, message_id, response_status, response_body, response_etag, created_at) VALUES (:workspace_id, "
        ":principal_id, :operation, :idempotency_key, :request_sha256, :case_id, :message_id, :status, "
        "CAST(:body_json AS jsonb), :etag, :created_at)"), record.model_dump())


def body(stored: StoredResponse) -> Any:
    return json.loads(stored.body_json)
