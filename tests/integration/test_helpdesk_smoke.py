"""Opt-in assertions for an independently owned, disposable local Zammad smoke."""

import base64
from contextlib import closing
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from policyops.adapters.zammad_client import ZammadClient
from policyops.domain.helpdesk_rules import digest, matching_notes, note_body
from policyops.settings import HelpdeskConnection, HelpdeskSettings
from policyops_contracts.helpdesk import TicketWakeup
from policyops_testing import network


pytestmark = pytest.mark.helpdesk


def artifact(name: str) -> dict[str, Any]:
    value = os.environ[f"POLICYOPS_HELPDESK_SMOKE_{name}"]
    decoded: dict[str, Any] = json.loads(Path(value).read_text(encoding="utf-8-sig"))
    return decoded


def endpoint() -> HelpdeskConnection:
    if os.environ.get("POLICYOPS_HELPDESK_SMOKE") != "1":
        pytest.fail("real help desk smoke requires explicit opt-in and the disposable fixture files")
    settings = HelpdeskSettings.from_secret_file(Path(os.environ["POLICYOPS_HELPDESK_SMOKE_SETTINGS"]))
    config = settings.connection(os.environ["POLICYOPS_HELPDESK_SMOKE_CONNECTION"])
    assert config is not None
    return config


def loopback(value: str) -> tuple[str, int]:
    address = httpx.URL(value)
    assert address.scheme in {"http", "https"} and address.host in {"127.0.0.1", "::1"}
    assert address.port is not None
    return address.host, address.port


def test_real_trigger_replay_and_forgery() -> None:
    config = endpoint()
    captured = artifact("CAPTURE")
    before = artifact("BEFORE")
    [accepted] = before["events"]
    assert accepted["state"] == "applied" and before["imported_messages"] == 1 and before["case_id"]
    body = base64.b64decode(captured["body_base64"], validate=True)
    assert hashlib.sha256(body).hexdigest() == captured["body_sha256"] == accepted["body_sha256"]
    TicketWakeup.model_validate_json(body)
    signature = "sha1=" + hmac.digest(config.signing_secret.get_secret_value().encode(), body, "sha1").hex()
    origin = os.environ["POLICYOPS_HELPDESK_SMOKE_POLICYOPS_ORIGIN"]
    route = f"/api/v1/integrations/zammad/{config.connection_id}/events"
    with network.allow(*loopback(origin)), httpx.Client(base_url=origin, trust_env=False, timeout=5) as client:
        response = client.post(route, content=body, headers={
            "X-Hub-Signature": signature, "X-Zammad-Delivery": str(uuid4())})
        assert response.status_code == 202
        forged = client.post(route, content=body + b" ", headers={"X-Hub-Signature": signature})
        assert forged.status_code == 401


def test_real_replay_did_not_add_rows_and_disallowed_group_was_audited() -> None:
    endpoint()
    before, after = artifact("BEFORE"), artifact("AFTER_REPLAY")
    assert before == after
    rejected = artifact("REJECTED")
    assert rejected["case_id"] is None and rejected["imported_messages"] == 0
    assert rejected["rejected_mapping_audits"] == 1
    [event] = rejected["events"]
    assert (event["state"], event["reason"]) == ("rejected_mapping", "disallowed_group")


def test_real_internal_note_after_outage_recovery() -> None:
    config = endpoint()
    captured = artifact("CAPTURE")
    body = base64.b64decode(captured["body_base64"], validate=True)
    ticket_id = TicketWakeup.model_validate_json(body).ticket_id
    final = artifact("AFTER_OUTCOME")
    before = artifact("BEFORE")
    assert final["case_id"] == before["case_id"] and final["imported_messages"] == before["imported_messages"]
    [receipt] = final["writebacks"]
    [during] = artifact("OUTAGE")["writebacks"]
    assert receipt["id"] == during["id"] and during["state"] == "pending" and during["attempts"] >= 1
    assert receipt["state"] == "succeeded" and not receipt["duplicate_article_ids"]
    operation = UUID(receipt["id"])
    remote = os.environ["POLICYOPS_HELPDESK_SMOKE_ZAMMAD_ORIGIN"]
    host_config = config.model_copy(update={"api_origin": remote})
    with network.allow(*loopback(remote)), closing(ZammadClient(host_config)) as client:
        articles = client.articles(ticket_id)
    [article] = matching_notes(articles, ticket_id=ticket_id, author=config.integration_user_id,
                              operation_id=operation, body_sha256=digest(note_body(operation, 1).encode()))
    assert article.id == receipt["article_id"] and article.created_at == datetime.fromisoformat(
        receipt["article_created_at"])
