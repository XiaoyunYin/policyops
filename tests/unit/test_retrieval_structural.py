"""Structural acquisition, intact passages, provenance and offline cap arithmetic."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import io
import json
from pathlib import Path
import time
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import create_engine

from policyops.providers import tokenizer as tk
from policyops.retrieval.archive_sources import load_manifest, read_corpus
from policyops.retrieval.cli import main
from policyops.retrieval.corpus import build_expected
from policyops.retrieval.ingest import PaidCaps, Request, ingest
from policyops.retrieval.parse import ParseRefused
from policyops.retrieval.sources import MAX_DOCUMENTS, ManifestCorpus, SourceRefused, sha256_hex
from policyops.retrieval.structural import CHUNK_CONFIG, PARSER_VERSION, chunk_passage
from policyops_testing.structural_fixtures import KEY, passage, write


TOKENIZER = tk.load()
CAPS = PaidCaps("text-embedding-3-small", 1536, Decimal("1"), 90, 600_000, 3600)


def test_mapping_heading_only_and_intact_markdown(tmp_path: Path) -> None:
    body = "## This stays literal\r\n\nUnicode: é 🦊"
    raw, digest = write(tmp_path, [passage(0, body=body), passage(1, body="Only title", heading_only=True)])
    source = read_corpus(raw, digest, KEY, tmp_path)
    expected = build_expected(source, TOKENIZER, tokenizer_sha256=TOKENIZER.identity_sha256,
                              model=CAPS.model, dimensions=1536, deadline=time.monotonic() + 60)
    assert len(expected.documents) == len(expected.chunks) == 2
    assert all(d.chunk_count == 1 for d in expected.documents)
    first = next(d.source for d in expected.documents if d.source.body == body)
    assert first.document_key == passage()["passage_id"]
    assert first.source_uri == f"md2d:dmv/{first.document_key}"
    assert json.loads(first.path) == {"domain": "dmv", "document_id": "Original document:#1", "start": 17,
                                     "end": 17 + len(body), "heading_only": False}
    chunk = next(c for c in expected.chunks if c.text == body)
    assert chunk.start == 0 and chunk.end == len(body) and first.body[chunk.start:chunk.end] == body
    assert chunk.embed_input == "Refunds\n\n" + body
    assert expected.header["parser"] == PARSER_VERSION and expected.header["chunk_config"] == CHUNK_CONFIG
    assert expected.header["archive_sha256"] == "a" * 64
    assert source.revision.commit == "a" * 40  # derivation fixture, not the archive digest


@pytest.mark.parametrize("field,value", [("passage_count", 0), ("passage_count", 5001),
    ("passages_bytes", 16 * 1_048_576 + 1), ("derivation_version", "unknown")])
def test_manifest_bounds(tmp_path: Path, field: str, value: Any) -> None:
    raw, digest = write(tmp_path, [passage()], **{field: value})
    with pytest.raises(SourceRefused):
        load_manifest(raw, digest)


def test_structural_limit_does_not_widen_markdown(tmp_path: Path) -> None:
    raw, digest = write(tmp_path, [passage()], passage_count=5000)
    assert load_manifest(raw, digest).passage_count == 5000
    assert MAX_DOCUMENTS == 2000
    schema = ManifestCorpus.model_json_schema()
    assert schema["properties"]["documents"]["maxItems"] == 2000


@pytest.mark.parametrize("change,code", [("manifest", "manifest_sha256_mismatch"),
    ("file_hash", "passages_sha256_mismatch"), ("file_size", "source_size_mismatch"),
    ("count", "passage_count_mismatch"), ("path", "path_unsafe")])
def test_hash_size_and_path_refusal(tmp_path: Path, change: str, code: str) -> None:
    options: dict[str, dict[str, Any]] = {"file_hash": {"passages_sha256": "0" * 64},
        "file_size": {"passages_bytes": 1}, "count": {"passage_count": 2},
        "path": {"passages_path": "../passages.jsonl"}}
    overrides = options.get(change, {})
    raw, digest = write(tmp_path, [passage()], **overrides)
    with pytest.raises(SourceRefused, match=code):
        read_corpus(raw, "0" * 64 if change == "manifest" else digest, KEY, tmp_path)


@pytest.mark.parametrize("changes", [{"body": "x" * 20001, "end": 20018}, {"heading": "h" * 501},
    {"end": 18}, {"body": "\x00", "end": 18}, {"body": "\ud800", "end": 18},
    {"passage_id": "unsafe"}, {"start": -1}, {"heading_only": "true"}, {"extra": "refused"}])
def test_passage_refusals(tmp_path: Path, changes: dict[str, Any]) -> None:
    # JSON escapes allow testing lone surrogates without encoding one as raw UTF-8.
    raw, _ = write(tmp_path, [passage()])
    row = passage() | changes
    data = json.dumps(row, ensure_ascii=True).encode() + b"\n"
    (tmp_path / "passages.jsonl").write_bytes(data)
    manifest = json.loads(raw) | {"passages_bytes": len(data), "passages_sha256": sha256_hex(data)}
    raw = json.dumps(manifest).encode()
    with pytest.raises(SourceRefused):
        read_corpus(raw, sha256_hex(raw), KEY, tmp_path)


def test_duplicate_passages_refuse(tmp_path: Path) -> None:
    raw, digest = write(tmp_path, [passage(), passage()])
    with pytest.raises(SourceRefused, match="passage_duplicate_id"):
        read_corpus(raw, digest, KEY, tmp_path)


def test_complete_passage_token_and_codepoint_bounds(tmp_path: Path) -> None:
    class Counter:
        def __init__(self, tokens: int) -> None:
            self.tokens = tokens

        def count(self, text: str) -> int:
            return self.tokens

    raw, digest = write(tmp_path, [passage(body="x" * 20000)])
    source = read_corpus(raw, digest, KEY, tmp_path).documents[0]
    assert len(chunk_passage(source, Counter(8192), deadline=time.monotonic() + 10)) == 1
    with pytest.raises(ParseRefused, match="structural_token_bound"):
        chunk_passage(source, Counter(8193), deadline=time.monotonic() + 10)
    with pytest.raises(ParseRefused, match="structural_chunk_too_large"):
        chunk_passage(replace(source, body=source.body + "x"), Counter(1), deadline=time.monotonic() + 10)
    with pytest.raises(ParseRefused, match="parse_deadline"):
        chunk_passage(source, Counter(1), deadline=0)


def test_offline_preflight_uses_real_packer_and_caps_without_io(tmp_path: Path) -> None:
    raw, digest = write(tmp_path, [passage(0), passage(1), passage(2, body="Different text.")])
    engine = create_engine("postgresql+psycopg://", creator=lambda: pytest.fail("database connection"))
    try:
        req = Request(uuid4(), KEY, raw, digest, tmp_path, "preflight", CAPS, "structural")
        out = ingest(req, engine=engine, tokenizer=TOKENIZER, providers=lambda: pytest.fail("provider credentials"))
        assert out.outcome == "planned", out.to_json()
        assert out.details["documents"] == 3 and out.details["distinct_inputs"] == 2
        tokens = TOKENIZER.count("Refunds\n\nRefunds return to the original card.")
        other = TOKENIZER.count("Refunds\n\nDifferent text.")
        assert out.details["all_passage_tokens"] == 2 * tokens + other
        assert out.details["estimate"]["local_tokens"] == tokens + other
        assert (Decimal(out.details["estimate"]["local_estimated_usd"])
                == Decimal(tokens + other) * Decimal("0.00000002"))
        assert all(out.details["within_caps"].values())
        for caps in (replace(CAPS, max_input_tokens=1), replace(CAPS, max_usd=Decimal("0.00000001")),
                     replace(CAPS, max_seconds=1)):
            refused = ingest(replace(req, paid=caps), engine=engine, tokenizer=TOKENIZER,
                             providers=lambda: pytest.fail("provider credentials"))
            assert refused.reason == "preflight_exceeds_caps"
    finally:
        engine.dispose()


def test_offline_cli(tmp_path: Path) -> None:
    raw, digest = write(tmp_path, [passage()])
    manifest = tmp_path / "ingest.json"
    manifest.write_bytes(raw)
    output = io.StringIO()
    code = main(["ingest", "--workspace", str(uuid4()), "--corpus-key", KEY, "--manifest", str(manifest),
        "--manifest-sha256", digest, "--acquisition-root", str(tmp_path), "--profile", "structural",
        "--offline-preflight", "--paid", "--model", CAPS.model, "--dimensions", "1536", "--max-usd", "1",
        "--max-calls", "90", "--max-input-tokens", "600000", "--max-seconds", "3600"],
        stdout=output, tokenizer=TOKENIZER, connect=lambda: pytest.fail("database"),
        providers=lambda: pytest.fail("provider"))
    assert code == 0 and json.loads(output.getvalue())["offline"] is True
