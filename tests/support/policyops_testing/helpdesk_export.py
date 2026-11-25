"""Small authored ticket histories for the application suites."""

import csv
from datetime import timedelta
import json
from pathlib import Path
from typing import Any

from policyops.services.helpdesk_export import HEADER, VerifiedExport
from policyops_testing.zammad import NOW


EXPORTED_AT = NOW + timedelta(minutes=1)
CUSTOMER = "fictional_customer_1"


def article(ticket: int, number: int, text: str, **fields: Any) -> dict[str, Any]:
    return {"id": number, "ticket_id": ticket, "internal": False, "sender": "Customer", "created_by_id": 11,
            "content_type": "text/plain", "body": text, "created_at": NOW.isoformat(), **fields}


def snapshot(revision: int, *, ticket_id: int = 42) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    ticket = {"id": ticket_id, "group_id": 7, "customer_id": 11, "state_id": revision + 1,
              "updated_at": (NOW + timedelta(seconds=revision)).isoformat()}
    articles = [article(ticket_id, 1, "yes"), article(ticket_id, 2, "hidden", internal=True)]
    articles.extend(article(ticket_id, n + 2, f"Article {n}") for n in range(1, revision))
    return ticket, articles


def archive(path: Path, *rows: tuple[dict[str, Any], list[dict[str, Any]]],
            newline: str = "\n") -> VerifiedExport:
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file, lineterminator=newline)
        writer.writerow(HEADER.decode().split(","))
        for ticket, articles in rows:
            writer.writerow([*(ticket[key] for key in ("id", "group_id", "customer_id", "state_id", "updated_at")),
                             json.dumps(articles, ensure_ascii=False)])
    return VerifiedExport.read(path)
