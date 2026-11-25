"""Bounded, immutable input for the v1 historical ticket export."""

import codecs
from collections.abc import Iterator
import csv
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
from threading import Lock
from typing import Any

from pydantic import TypeAdapter

from policyops.adapters.zammad_client import MAX_ARTICLES, MAX_RESPONSE_BYTES
from policyops.domain.helpdesk_rules import RejectReason, digest
from policyops_contracts.helpdesk import Article, Ticket


FORMAT_VERSION = 1
HEADER = b"policyops_helpdesk_v1_ticket_id,group_id,customer_id,state_id,updated_at,articles_json"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 50_000
MAX_RECORD_BYTES = 1024 * 1024
BATCH_RECORDS = 16
BATCH_BYTES = 2 * 1024 * 1024
_articles = TypeAdapter(list[Article])
_csv_limit_lock = Lock()

class ImportRefused(ValueError):
    """Safe, typed operator-facing import failure."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Record:
    number: int
    sha256: str
    ticket_id: int | None
    ticket: Ticket | None = None
    articles: tuple[Article, ...] = ()
    reason: RejectReason | None = None


def utc_timestamp(value: str) -> datetime:
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                        r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)", value):
        raise ValueError("invalid UTC timestamp")
    return datetime.fromisoformat(value).astimezone(UTC)


def _external_id(value: str) -> int | None:
    if re.fullmatch(r"[1-9][0-9]{0,15}", value):
        number = int(value)
        if number <= 2**53 - 1:
            return number
    return None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate JSON field")
    return obj


def _parse_record(number: int, raw: memoryview, exported_at: datetime) -> Record:
    sha = hashlib.sha256(raw).hexdigest()
    ticket_id = None

    def rejected(reason: RejectReason) -> Record:
        return Record(number, sha, ticket_id, reason=reason)

    if len(raw) > MAX_RECORD_BYTES:
        return rejected("record_too_large")
    encoded_line = raw.tobytes()
    if encoded_line.endswith(b"\r\n"):
        encoded_line = encoded_line[:-2]
    line = encoded_line.removesuffix(b"\n").decode("utf-8")
    if "\r" in line or "\x00" in line:
        return rejected("invalid_csv")
    try:
        # field_size_limit is process-global. Do not leave a changed parser limit behind.
        with _csv_limit_lock:
            previous = csv.field_size_limit(MAX_RECORD_BYTES)
            try:
                fields = next(csv.reader([line], strict=True))
            finally:
                csv.field_size_limit(previous)
    except csv.Error:
        return rejected("invalid_csv")
    if fields:
        ticket_id = _external_id(fields[0])
    if len(fields) != 6:
        return rejected("invalid_csv")
    group, customer, state = map(_external_id, fields[1:4])
    if ticket_id is None or group is None or customer is None or state is None:
        return rejected("invalid_ticket")
    try:
        updated_at = utc_timestamp(fields[4])
    except ValueError:
        return rejected("invalid_ticket")
    if updated_at > exported_at:
        return rejected("future_ticket")
    ticket = Ticket(id=ticket_id, group_id=group, customer_id=customer, state_id=state, updated_at=updated_at)

    encoded = fields[5].encode()
    if len(encoded) > MAX_RESPONSE_BYTES:
        return rejected("articles_too_large")
    try:
        array = json.loads(encoded, object_pairs_hook=_unique_object)
        if not isinstance(array, list):
            return rejected("invalid_articles")
        if len(array) > MAX_ARTICLES:
            return rejected("too_many_articles")
        if any(not isinstance(item, dict) or not isinstance(item.get("created_at"), str) for item in array):
            return rejected("invalid_articles")
        articles = tuple(_articles.validate_json(encoded))
    except (ValueError, RecursionError):
        return rejected("invalid_articles")
    if len({article.id for article in articles}) != len(articles):
        return rejected("duplicate_article_id")
    if any(article.ticket_id != ticket_id for article in articles):
        return rejected("article_ticket_mismatch")
    return Record(number, sha, ticket_id, ticket, articles)


@dataclass(frozen=True)
class VerifiedExport:
    sha256: str
    size: int
    _data: bytes
    _spans: tuple[tuple[int, int], ...]

    @classmethod
    def read(cls, path: Path, *, expected_sha256: str | None = None) -> "VerifiedExport":
        if not path.is_file():
            raise ImportRefused("input_unavailable")
        with path.open("rb") as source:
            data = source.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise ImportRefused("file_too_large")
        sha = digest(data)
        if expected_sha256 is not None and sha != expected_sha256:
            raise ImportRefused("input_sha256_mismatch")
        try:
            decoder = codecs.getincrementaldecoder("utf-8")()
            for start in range(0, len(data), 64 * 1024):
                decoder.decode(data[start:start + 64 * 1024])
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            raise ImportRefused("invalid_utf8") from None
        end = data.find(b"\n", 0, len(HEADER) + 3)
        if end >= 0:
            header, cursor = data[:end].removesuffix(b"\r"), end + 1
        else:
            header, cursor = data[:len(HEADER) + 1], len(data)
        if header != HEADER:
            raise ImportRefused("invalid_header")
        spans = []
        while cursor < len(data):
            end = data.find(b"\n", cursor)
            end = len(data) if end < 0 else end + 1
            spans.append((cursor, end))
            if len(spans) > MAX_RECORDS:
                raise ImportRefused("too_many_records")
            cursor = end
        return cls(sha, len(data), data, tuple(spans))

    @property
    def records_total(self) -> int:
        return len(self._spans)

    def batches(self, exported_at: datetime, *, start: int = 0) -> Iterator[tuple[Record, ...]]:
        view = memoryview(self._data)
        batch: list[Record] = []
        size = 0
        for index in range(start, self.records_total):
            left, right = self._spans[index]
            # Oversized records are alone if necessary and only consume a hash and a rejection entry.
            length = right - left
            if batch and (len(batch) == BATCH_RECORDS or size + length > BATCH_BYTES):
                yield tuple(batch)
                batch, size = [], 0
            batch.append(_parse_record(index + 1, view[left:right], exported_at))
            size += length
        if batch:
            yield tuple(batch)
