"""Offline format, validation bounds and trusted input identity tests."""

import csv
from datetime import timedelta
import hashlib
from pathlib import Path
from typing import Any

import pytest

from policyops.services import helpdesk_export as export
from policyops_testing.helpdesk_export import EXPORTED_AT, archive, article, snapshot


def test_strict_header_utf8_and_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "test.csv"
    for data, reason in [(b"\xef\xbb\xbf" + export.HEADER, "invalid_header"), (b"ticket_id", "invalid_header"),
                         (export.HEADER + b"\n\x80", "invalid_utf8")]:
        path.write_bytes(data)
        with pytest.raises(export.ImportRefused, match=f"^{reason}$"):
            export.VerifiedExport.read(path)
    source = archive(path, snapshot(1), snapshot(2), newline="\r\n")
    monkeypatch.setattr(export, "MAX_FILE_BYTES", source.size - 1)
    with pytest.raises(export.ImportRefused, match=r"^file_too_large$"):
        export.VerifiedExport.read(path)
    monkeypatch.setattr(export, "MAX_FILE_BYTES", source.size)
    monkeypatch.setattr(export, "MAX_RECORDS", 1)
    with pytest.raises(export.ImportRefused, match=r"^too_many_records$"):
        export.VerifiedExport.read(path)
    path.write_bytes(export.HEADER)
    assert export.VerifiedExport.read(path).records_total == 0


def test_exact_bytes_verified_and_preserved_after_source_changes(tmp_path: Path) -> None:
    path = tmp_path / "test.csv"
    original = archive(path, snapshot(1), newline="\r\n")
    raw = path.read_bytes()
    assert original.sha256 == hashlib.sha256(raw).hexdigest()
    other = archive(path, snapshot(2))
    with pytest.raises(export.ImportRefused, match=r"^input_sha256_mismatch$"):
        export.VerifiedExport.read(path, expected_sha256=original.sha256)
    assert export.VerifiedExport.read(path, expected_sha256=other.sha256).sha256 != original.sha256
    [(record,)] = list(original.batches(EXPORTED_AT))
    assert (record.number, record.ticket_id, record.reason) == (1, 42, None)
    assert record.sha256 == hashlib.sha256(raw[raw.index(b"\n") + 1:]).hexdigest()


def test_typed_invalid_rows_and_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ticket, articles = snapshot(1)
    multiline = article(42, 5, 'escaped "quoted" body\nwith unicode ☃')
    too_many = [article(42, n, "x") for n in range(1, 202)]
    large = [article(42, 5, "x" * (256 * 1024))]
    oversized = [article(42, 5, "x" * (1024 * 1024))]
    rows: list[tuple[dict[str, Any], list[dict[str, Any]]]] = [
        (ticket, [multiline]), (ticket, [*articles, articles[0]]), (ticket, [article(43, 1, "wrong")]),
        (ticket, [multiline | {"internal": 1}]), (ticket | {"group_id": "2.0"}, articles),
        (ticket | {"updated_at": (EXPORTED_AT + timedelta(microseconds=1)).isoformat()}, articles),
        (ticket, too_many), (ticket, large), (ticket, oversized),
    ]
    source = archive(tmp_path / "test.csv", *rows)
    monkeypatch.setattr(export, "BATCH_RECORDS", 3)
    monkeypatch.setattr(export, "BATCH_BYTES", 1024 * 1024)
    limit = csv.field_size_limit()
    batches = list(source.batches(EXPORTED_AT))
    assert csv.field_size_limit() == limit
    assert list(map(len, batches)) == [3, 3, 2, 1]
    records = [record for batch in batches for record in batch]
    assert records[0].articles[0].body == multiline["body"]
    assert [record.reason for record in records] == [
        None, "duplicate_article_id", "article_ticket_mismatch", "invalid_articles", "invalid_ticket",
        "future_ticket", "too_many_articles", "articles_too_large", "record_too_large",
    ]
    assert records[-1].ticket_id is None


def test_malformed_physical_lines_are_separate_redacted_records(tmp_path: Path) -> None:
    path = tmp_path / "test.csv"
    path.write_bytes(export.HEADER + b'\n42,7,11,2,not-a-timestamp,"open\n'
                     b'continued"\n42,7,11,2,2026-11-01T00:00:00Z,[]')
    source = export.VerifiedExport.read(path)
    [batch] = list(source.batches(EXPORTED_AT))
    assert [(record.ticket_id, record.reason) for record in batch] == [(None, "invalid_csv"), (None, "invalid_csv"),
                                                                      (42, None)]


@pytest.mark.parametrize("value", ["2026-01-01T00:00:00-08:00", "2026-01-01 00:00:00Z", "1750000000",
                                  "2026-01-01T00:00:00.1234567Z", "2026-02-30T00:00:00Z"])
def test_export_timestamp_requires_unambiguous_utc(value: str) -> None:
    with pytest.raises(ValueError, match=r"timestamp|day"):
        export.utc_timestamp(value)
