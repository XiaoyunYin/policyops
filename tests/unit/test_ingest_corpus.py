"""The exact expected generation (T12): composite chunk identity versus plain text digest, the expected-set
multiset (duplicates and documents without chunks included), keys, distinct embedding inputs and bounds. Offline."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import time

import pytest

from policyops.providers import tokenizer as tk
from policyops.retrieval import corpus as corpus_module
from policyops.retrieval.cli import main
from policyops.retrieval.corpus import CorpusRefused, Expected, build_expected, chunk_identity
from policyops.retrieval.sources import read_corpus
from policyops_testing.corpus_fixtures import FixtureCorpus, banking, write


TOKENIZER = tk.load()


def expected_for(tmp_path: Path, documents: dict[str, bytes], *, render: str = "tau2-banking/v1",
                 key: str = "test-banking") -> Expected:
    raw, digest = write(tmp_path, [FixtureCorpus(key, "banking_knowledge", render, documents)])
    source = read_corpus(raw, digest, key, tmp_path)
    return build_expected(source, TOKENIZER, tokenizer_sha256=TOKENIZER.identity_sha256,
                          model="text-embedding-3-small", dimensions=1536, deadline=time.monotonic() + 30)


def test_composite_identity_is_not_the_text_digest_and_binds_position(tmp_path: Path) -> None:
    repeated = "### X\nSame.\n### X\nSame."  # two sections with the same path and text in one document
    expected = expected_for(tmp_path, {"a": banking("a", "T", repeated), "b": banking("b", "T", repeated)})
    texts = [c for c in expected.chunks if c.text == "Same."]
    assert len(texts) == 4  # one per position, duplicates kept
    assert len({c.sha256 for c in texts}) == 4 and len({c.text_sha256 for c in texts}) == 1
    for chunk in texts:
        assert chunk.text_sha256 == hashlib.sha256(b"Same.").hexdigest() != chunk.sha256
        assert chunk.sha256 == chunk_identity(chunk.source_uri, chunk.version_sha256, chunk.start, chunk.end,
                                              chunk.heading, chunk.section_ordinal, chunk.section_start,
                                              chunk.section_end, chunk.text_sha256)
    assert expected.inputs == ("T > X\n\nSame.",)  # one distinct exact embedding input for all four positions


def test_documents_without_chunks_are_part_of_the_expected_set(tmp_path: Path) -> None:
    with_empty = expected_for(tmp_path / "1", {"a": banking("a", "T", "Text."), "b": banking("b", "T", " \n ")})
    without = expected_for(tmp_path / "2", {"a": banking("a", "T", "Text.")})
    assert [d.chunk_count for d in with_empty.documents] == [1, 0]
    assert [c.sha256 for c in with_empty.chunks] == [c.sha256 for c in without.chunks]
    assert with_empty.expected_set_sha256 != without.expected_set_sha256


def test_keys_are_deterministic_and_change_with_content_render_or_corpus(tmp_path: Path) -> None:
    docs = {"a": banking("a", "T", "Text one."), "b": banking("b", "U", "Text two.")}
    first, again = expected_for(tmp_path / "1", docs), expected_for(tmp_path / "2", docs)
    assert (first.expected_set_sha256, first.generation_key_sha256) == (again.expected_set_sha256,
                                                                       again.generation_key_sha256)
    edited = expected_for(tmp_path / "3", docs | {"b": banking("b", "U", "Text two, edited.")})
    other_key = expected_for(tmp_path / "4", docs, key="test-banking-2")
    assert len({first.generation_key_sha256, edited.generation_key_sha256, other_key.generation_key_sha256}) == 3
    assert first.subject_key == f"ingest.test-banking.{first.expected_set_sha256}" and len(first.subject_key) <= 200
    assert first.header["model"] == "text-embedding-3-small" and first.header["dimensions"] == 1536
    assert first.request_config_sha256 == first.header["request_config_sha256"]


def test_chunks_are_sorted_by_identity_and_position(tmp_path: Path) -> None:
    expected = expected_for(tmp_path, {"b": banking("b", "T", "B1.\n\nB2."), "a": banking("a", "T", "A1.")})
    assert [(c.source_uri, c.start) for c in expected.chunks] == sorted((c.source_uri, c.start)
                                                                       for c in expected.chunks)


def test_the_single_transaction_chunk_bound_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(corpus_module, "MAX_CHUNKS", 2)
    with pytest.raises(CorpusRefused, match="corpus_exceeds_single_transaction_bounds"):
        expected_for(tmp_path, {"a": banking("a", "T", "One.\n\n" + "x" * 3000 + "\n\nThree.")})


def never_connect() -> object:
    raise AssertionError("a usage refusal must not open a database connection")


@pytest.mark.parametrize(("extra", "detail"), [
    (["--paid", "--model", "text-embedding-3-small"], "--paid requires --execute"),
    (["--execute", "--paid"], "missing model"),
    (["--max-usd", "0.01"], "only accepted with --paid"),
    (["--execute", "--paid", "--model", "m", "--dimensions", "1536", "--max-usd", "x", "--max-calls", "1",
      "--max-input-tokens", "1", "--max-seconds", "1"], "not a decimal"),
    (["--execute", "--paid", "--model", "m", "--dimensions", "1536", "--max-usd", "5", "--max-calls", "1",
      "--max-input-tokens", "1", "--max-seconds", "1"], "max_usd"),
    (["--execute", "--paid", "--model", "m", "--dimensions", "1536", "--max-usd", "0.01", "--max-calls", "1",
      "--max-input-tokens", "1", "--max-seconds", "99999"], "max_seconds exceeds"),
    (["--execute", "--paid", "--model", "m", "--dimensions", "1536", "--max-usd", "0.0000000000000000001",
      "--max-calls", "1", "--max-input-tokens", "1", "--max-seconds", "1"], "max_usd"),
])
def test_cli_usage_refusals_happen_before_any_connection(tmp_path: Path, extra: list[str], detail: str) -> None:
    argv = ["ingest", "--workspace", "00000000-0000-4000-8000-000000000001", "--corpus-key", "k", "--manifest",
            str(tmp_path / "m.json"), "--manifest-sha256", "0" * 64, "--acquisition-root", str(tmp_path), *extra]
    stream = io.StringIO()
    assert main(argv, connect=never_connect, stdout=stream) == 2  # type: ignore[arg-type]
    result = json.loads(stream.getvalue())
    assert result["outcome"] == "refused" and result["reason"] == "usage" and detail in result["detail"]
