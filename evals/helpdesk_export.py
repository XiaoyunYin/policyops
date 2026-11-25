"""Generate a private N14 CSV, bindings and independent expected projection from the pinned retail database."""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
from typing import Any


PIN = "413a65160adbdb5fde0ffc0015c49b6d70250b10c18128de169b597af7766765"
HEADER = ("policyops_helpdesk_v1_ticket_id", "group_id", "customer_id", "state_id", "updated_at", "articles_json")
EXPORTED = "2026-11-01T00:00:00Z"
EARLY = "2026-10-30T00:00:00Z"
LATE = "2026-10-31T00:00:00Z"
ADVANCE = "2026-10-31T01:00:00Z"
FUTURE = "2026-11-01T00:00:01Z"
STATES = {"pending": 1, "processed": 2, "delivered": 3, "cancelled": 4}
HTML = "[Help desk article omitted because it contains HTML.]"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def article(ticket: int, identity: int, body: str, **fields: Any) -> dict[str, Any]:
    return {"id": identity, "ticket_id": ticket, "internal": False, "sender": "Customer",
            "created_by_id": 11, "content_type": "text/plain", "body": body, "created_at": EARLY, **fields}


def generate(database: Path, output: Path, limit: int) -> None:
    with database.open("rb") as file:
        raw = file.read(8 * 1024 * 1024 + 1)
    if sha(raw) != PIN:
        raise ValueError("retail db.json digest does not match the pinned fixture")
    orders = json.loads(raw)["orders"]
    ordered = [(order_id, order["user_id"], order["status"]) for order_id, order in sorted(orders.items())
               if re.fullmatch(r"[a-z]+(?:_[a-z]+)*_[0-9]{1,6}", order["user_id"])
               and len(order["user_id"]) <= 64][:limit]
    if not ordered or not 1 <= limit <= 1000:
        raise ValueError("select 1 to 1000 retail orders")

    owner_ids = {owner: index for index, owner in enumerate(sorted({item[1] for item in ordered}), 100)}
    bindings = [{"requester_id": identity, "customer_user_id": owner, "seed_id": f"retail-demo-{9999 - offset}"}
                for offset, (owner, identity) in enumerate(owner_ids.items())]
    schedule: list[tuple[tuple[Any, ...], str, str]] = []
    links = []

    for ticket, (order_id, owner, status) in enumerate(ordered, 1):
        state = STATES[status]
        requester = owner_ids[owner] if ticket % 11 else 100_000 + ticket
        first = f"Can you check order {order_id}?"
        current = f"Status on {order_id} is {status}."
        history = [article(ticket, 1, first), article(ticket, 2, "internal", internal=True),
                   article(ticket, 3, "yes")]
        final = [*history, article(ticket, 4, "<b>order</b>", content_type="text/html"),
                 article(ticket, 5, current), article(ticket, 6, "echo", created_by_id=19)]
        old = (ticket, 7, requester, 5, EARLY, history)
        new = (ticket, 7, requester, state, LATE, final)
        if ticket % 11 == 0:
            schedule.append((new, "quarantined", "unmapped_requester"))
            continue
        schedule.extend(((old, "accepted", "case_created"), (new, "updated", "snapshot_advanced")))
        links.append({"ticket_id": ticket, "group_id": 7, "requester_id": requester, "customer_user_id": owner,
                      "state_id": state, "ticket_updated_at": LATE, "max_article_id": 6,
                      "messages": [{"article_id": identity, "text_sha256": sha(body.encode())}
                                   for identity, body in [(1, first), (3, "yes"), (4, HTML), (5, current)]]})
        if ticket % 7 == 1:
            schedule.extend(((new, "duplicate", "same_snapshot"), (old, "skipped_stale", "older_snapshot")))
        if ticket == 1:
            changed = [final[0] | {"body": "different projected text"}, *final[1:]]
            schedule.extend((
                ((ticket, 7, requester, state, LATE, changed), "quarantined", "snapshot_conflict"),
                ((ticket, 7, requester, state, ADVANCE, final[1:]), "quarantined", "incompatible_history"),
                ((ticket, 7, 99_999, state, ADVANCE, final), "quarantined", "requester_changed"),
                ((ticket, 9, requester, state, ADVANCE, final), "quarantined", "disallowed_group"),
                ((ticket, 7, requester, state, ADVANCE, [article(ticket, n, "cap") for n in range(1, 202)]),
                 "rejected", "too_many_articles"),
                ((ticket, 7, requester, state, ADVANCE, [article(ticket, 1, "x" * (256 * 1024))]),
                 "rejected", "articles_too_large"),
                ((ticket, 7, requester, state, ADVANCE, [article(ticket, 1, "x" * (1024 * 1024))]),
                 "rejected", "record_too_large"),
                ((ticket, 7, requester, state, ADVANCE, [final[0], final[0]]), "rejected", "duplicate_article_id"),
                ((ticket, 7, requester, state, FUTURE, final), "rejected", "future_ticket"),
                ((ticket, "bad", requester, state, ADVANCE, final), "rejected", "invalid_ticket"),
            ))

    outcomes = [{"record_no": index, "ticket_id": None if reason == "record_too_large" else row[0],
                 "disposition": outcome, "reason": reason}
                for index, (row, outcome, reason) in enumerate(schedule, 1)]
    expected = {"exported_at": EXPORTED, "links": links, "outcomes": outcomes,
                "counts_by_reason": dict(Counter(row["reason"] for row in outcomes))}

    if Path(__file__).resolve().parents[1] in output.resolve().parents:
        raise ValueError("use a private output directory outside the repository")
    output.mkdir(parents=True, exist_ok=False)
    with (output / "tickets.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file, lineterminator="\n")
        writer.writerow(HEADER)
        for (*fields, articles), _, _ in schedule:
            writer.writerow((*fields, json.dumps(articles, ensure_ascii=True, separators=(",", ":"))))
    for name, payload in (("expected.json", expected), ("bindings.json", bindings)):
        (output / name).write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--orders", type=int, default=1000)
    args = parser.parse_args()
    generate(args.db, args.output, args.orders)


if __name__ == "__main__":
    main()
