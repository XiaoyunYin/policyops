"""Ingestion sources (T12): the committed manifest, strict manifest validation, containment and verified reading
of synthetic files. No database, provider or network; real files only in the test's own temporary root."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from policyops.retrieval import sources
from policyops.retrieval.sources import SourceRefused, load_manifest, read_corpus
from policyops_testing.corpus_fixtures import FixtureCorpus, banking, write


REPO = Path(__file__).resolve().parents[2]
COMMITTED = REPO / "evals/manifests/tau2-19f13ea3/ingest-corpora.json"


def link_directory(link: Path, target: Path) -> None:
    """A real junction on Windows (no privilege needed), a symlink elsewhere."""
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def bank(**documents: bytes) -> FixtureCorpus:
    return FixtureCorpus("test-banking", "banking_knowledge", "tau2-banking/v1", documents)


def test_the_committed_manifest_loads_strictly_and_matches_t03() -> None:
    raw = COMMITTED.read_bytes()
    manifest = load_manifest(raw, hashlib.sha256(raw).hexdigest())
    banking_corpus = manifest.corpus("tau2-banking-knowledge")
    retail = manifest.corpus("tau2-retail-policy")
    assert len(banking_corpus.documents) == 698 and len(retail.documents) == 1
    assert banking_corpus.rendered_list_sha256 == "762ad8e0c6c7016c8d5d361fe39fb73574a361754fadfa39262287e002312679"
    assert sum(d.size for d in banking_corpus.documents) == 932122
    assert manifest.source.commit == "19f13ea3f5fba8b4c4d272d1353590f29dc53062"
    assert banking_corpus.render == "tau2-banking/v1" and retail.render == "identity"


def test_an_ordinary_serialized_manifest_loads_and_round_trips_its_files(tmp_path: Path) -> None:
    """Regression (draft finding: strict validation refused JSON arrays for tuple fields)."""
    raw, digest = write(tmp_path, [bank(a=banking("a", "Refunds", "Back to the original method.\r\nNo cash."))])
    corpus = read_corpus(raw, digest, "test-banking", tmp_path)
    assert [d.document_key for d in corpus.documents] == ["a"]
    document = corpus.documents[0]
    assert document.body == "## Refunds\n\nBack to the original method.\r\nNo cash."  # CRLF preserved
    assert document.source_uri == "tau2:banking_knowledge/a"
    reserialized = corpus.corpus.model_dump_json().encode()
    assert json.loads(reserialized)["documents"][0]["document_key"] == "a"


def mutate(raw: bytes, change: object) -> tuple[bytes, str]:
    data = json.loads(raw)
    change(data)  # type: ignore[operator]
    out = json.dumps(data).encode()
    return out, hashlib.sha256(out).hexdigest()


@pytest.mark.parametrize(("change", "code"), [
    (lambda d: d.update(extra=1), "manifest_invalid"),
    (lambda d: d["corpora"][0].update(render="html"), "manifest_invalid"),
    (lambda d: d["corpora"][0]["documents"][0].update(size="12"), "manifest_invalid"),
    (lambda d: d["corpora"][0]["documents"][0].update(size=True), "manifest_invalid"),
    (lambda d: d["corpora"][0]["documents"].reverse(), "manifest_invalid"),
    (lambda d: d["corpora"][0]["documents"][0].update(document_key="../x"), "manifest_invalid"),
    (lambda d: d["source"].update(commit="ABC"), "manifest_invalid"),
    (lambda d: d.update(schema="policyops.ingest-manifest/v2"), "manifest_invalid"),
])
def test_manifest_validation_is_strict(tmp_path: Path, change: object, code: str) -> None:
    raw, _ = write(tmp_path, [bank(a=banking("a", "T", "x"), b=banking("b", "T", "y"))])
    changed, digest = mutate(raw, change)
    with pytest.raises(SourceRefused) as caught:
        load_manifest(changed, digest)
    assert caught.value.code == code


def test_duplicate_keys_non_finite_constants_and_digest_binding_are_refused(tmp_path: Path) -> None:
    raw, digest = write(tmp_path, [bank(a=banking("a", "T", "x"))])
    duplicated = raw.replace(b'"schema":', b'"schema": "x", "schema":', 1)
    for bad, code in ((duplicated, "manifest_malformed"), (raw.replace(b'"size": ', b'"size": NaN, "s": ', 1),
                                                           "manifest_malformed")):
        with pytest.raises(SourceRefused, match=code):
            load_manifest(bad, hashlib.sha256(bad).hexdigest())
    with pytest.raises(SourceRefused, match="manifest_sha256_mismatch"):
        load_manifest(raw, "0" * 64)
    with pytest.raises(SourceRefused, match="manifest_sha256_malformed"):
        load_manifest(raw, digest.upper())
    with pytest.raises(SourceRefused, match="manifest_too_large"):
        load_manifest(b" " * (sources.MAX_MANIFEST_BYTES + 1), digest)


def test_one_source_identity_cannot_belong_to_two_corpora(tmp_path: Path) -> None:
    first = FixtureCorpus("corpus-a", "banking_knowledge", "tau2-banking/v1", {"a": banking("a", "T", "x")},
                          directory="one")
    second = FixtureCorpus("corpus-b", "banking_knowledge", "tau2-banking/v1", {"a": banking("a", "T", "x")},
                           directory="two")
    raw, digest = write(tmp_path, [first, second])
    with pytest.raises(SourceRefused, match="manifest_invalid"):
        load_manifest(raw, digest)


@pytest.mark.parametrize("path", ["./docs/a.json", "docs/./a.json", ".", "docs/../docs/a.json", "/docs/a.json",
                                  "docs//a.json", "docs\\a.json", "C:docs/a.json", "docs/a.json/"])
def test_dot_aliases_traversal_and_absolute_paths_are_refused_before_any_open(path: str, tmp_path: Path) -> None:
    """Regression (draft finding: raw `.` components were normalized away before validation)."""
    with pytest.raises(SourceRefused, match="path_unsafe"):
        sources.contained_file(tmp_path.resolve(), path)


def test_a_valid_nested_relative_path_is_accepted(tmp_path: Path) -> None:
    target = tmp_path / "data" / "a(1)+b.json"
    target.parent.mkdir()
    target.write_bytes(b"{}")
    assert sources.contained_file(tmp_path.resolve(), "data/a(1)+b.json") == target.resolve()


def test_a_link_on_any_component_or_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    raw, digest = write(root, [bank(a=banking("a", "T", "x"))])
    outside = tmp_path / "outside"
    (outside / "docs").mkdir(parents=True)
    (outside / "docs" / "a.json").write_bytes(banking("a", "T", "x"))
    (root / "docs" / "a.json").unlink()
    (root / "docs").rmdir()
    link_directory(root / "docs", outside / "docs")
    with pytest.raises(SourceRefused, match="path_link"):
        read_corpus(raw, digest, "test-banking", root)
    link_directory(tmp_path / "linked-root", outside)
    with pytest.raises(SourceRefused, match=r"acquisition_root_link|acquisition_root_not_canonical"):
        read_corpus(raw, digest, "test-banking", tmp_path / "linked-root")
    with pytest.raises(SourceRefused, match="acquisition_root_missing"):
        read_corpus(raw, digest, "test-banking", tmp_path / "missing")


@pytest.mark.parametrize(("edit", "code"), [
    (lambda p: p.write_bytes(p.read_bytes() + b" "), "source_size_mismatch"),
    (lambda p: p.write_bytes(p.read_bytes()[:-1] + b"X"), "source_sha256_mismatch"),
    (lambda p: p.unlink(), "source_missing"),
])
def test_changed_or_missing_files_are_refused(tmp_path: Path, edit: object, code: str) -> None:
    raw, digest = write(tmp_path, [bank(a=banking("a", "T", "content"))])
    edit(tmp_path / "docs" / "a.json")  # type: ignore[operator]
    with pytest.raises(SourceRefused, match=code):
        read_corpus(raw, digest, "test-banking", tmp_path)


def test_a_wrong_git_blob_is_refused_even_when_the_sha256_matches(tmp_path: Path) -> None:
    raw, _ = write(tmp_path, [bank(a=banking("a", "T", "content"))])
    changed, digest = mutate(raw, lambda d: d["corpora"][0]["documents"][0].update(git_blob="f" * 40))
    with pytest.raises(SourceRefused, match="source_git_blob_mismatch"):
        read_corpus(changed, digest, "test-banking", tmp_path)


@pytest.mark.parametrize(("raw_document", "code"), [
    (b"\xef\xbb\xbf" + banking("a", "T", "x"), "source_bom"),
    (b'{"id": "a", "title": "T", "content": "\xff"}', "source_not_utf8"),
    (b'{"id": "a", "title": "T", "content": "x\\u0000"}', "body_nul"),
    (b'{"id": "a", "title": "T", "content": "\\ud800"}', "body_lone_surrogate"),
    (b'{"id": "a", "title": "T"}', "source_json_shape"),
    (b'{"id": "a", "title": "T", "content": "x", "extra": "y"}', "source_json_shape"),
    (b'{"id": "a", "title": 1, "content": "x"}', "source_json_shape"),
    (b'{"id": "b", "title": "T", "content": "x"}', "source_json_id_mismatch"),
    (b'{"id": "a", "id": "a", "title": "T", "content": "x"}', "source_json_malformed"),
    (b"[1, 2", "source_json_malformed"),
])
def test_invalid_source_content_refuses_the_corpus(tmp_path: Path, raw_document: bytes, code: str) -> None:
    raw, digest = write(tmp_path, [bank(a=raw_document)])
    with pytest.raises(SourceRefused) as caught:
        read_corpus(raw, digest, "test-banking", tmp_path)
    assert caught.value.code == code and caught.value.detail in ("a", "")


def test_identity_render_keeps_the_exact_file_text(tmp_path: Path) -> None:
    text = "# Policy\r\n\r\nRésumé \u2013 東京 \U0001f600\n\tTabbed\u2028same line\n"
    corpus = FixtureCorpus("test-retail", "retail", "identity", {"policy": text.encode()})
    raw, digest = write(tmp_path, [corpus])
    document = read_corpus(raw, digest, "test-retail", tmp_path).documents[0]
    assert document.body == text and document.version_sha256 == hashlib.sha256(text.encode()).hexdigest()
    bom = FixtureCorpus("test-retail", "retail", "identity", {"policy": b"\xef\xbb\xbf# x"})
    raw, digest = write(tmp_path / "bom", [bom])
    with pytest.raises(SourceRefused, match="source_bom"):
        read_corpus(raw, digest, "test-retail", tmp_path / "bom")


def test_the_rendered_list_digest_is_verified(tmp_path: Path) -> None:
    raw, _ = write(tmp_path, [bank(a=banking("a", "T", "x"))])
    changed, digest = mutate(raw, lambda d: d["corpora"][0].update(rendered_list_sha256="0" * 64))
    with pytest.raises(SourceRefused, match="rendered_list_mismatch"):
        read_corpus(changed, digest, "test-banking", tmp_path)


def test_an_unknown_corpus_is_refused(tmp_path: Path) -> None:
    raw, digest = write(tmp_path, [bank(a=banking("a", "T", "x"))])
    with pytest.raises(SourceRefused, match="corpus_not_in_manifest"):
        read_corpus(raw, digest, "other", tmp_path)


def test_body_bounds(tmp_path: Path) -> None:
    sources.check_body("x" * 10, "k")
    with pytest.raises(SourceRefused, match="body_too_large"):
        sources.check_body("é" * (sources.MAX_BODY_BYTES // 2 + 1), "k")
    with pytest.raises(SourceRefused, match="body_empty"):
        sources.check_body("", "k")
