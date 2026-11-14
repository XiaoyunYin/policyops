"""Bounded, hash-bound private title-run JSONL acquisition. No archive extraction or fetching.

Generation Git fields name the derivation implementation, never an upstream dataset revision.
Membership source_path is canonical JSON mapping local body offsets to the original document.
Membership blob/digest/size describe the canonical passage record, not a claimed upstream Git object.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, ValidationError, model_validator

from policyops.retrieval.sources import (
    MAX_CORPUS_RAW_BYTES,
    MAX_MANIFEST_BYTES,
    ArchiveMetadata,
    Hex64,
    Slug,
    SourceCorpus,
    SourceDocument,
    SourceRefused,
    SourceRevision,
    StructuralOrigin,
    Text200,
    Text2000,
    _read_exact,
    _Strict,
    _strict_json,
    canonical_json,
    check_body,
    checked_root,
    contained_file,
    git_blob_sha1,
    sha256_hex,
)
from policyops.retrieval.structural import CHUNK_CONFIG, PARSER_VERSION


MANIFEST_SCHEMA = "policyops.structural-ingest/v1"
MAX_DOCUMENTS = 5000
MAX_LINE_BYTES = 262_144


class ArchiveManifest(_Strict):
    schema_: Literal["policyops.structural-ingest/v1"] = Field(alias="schema")
    corpus_key: Slug
    domain: Slug
    publisher: Text200
    license: Text200
    license_scope: Text2000
    derivation: SourceRevision
    derivation_version: Literal["md2d.title-runs/v1"]
    archive_sha256: Hex64
    passages_path: Annotated[str, StringConstraints(min_length=1, max_length=1000)]
    passages_sha256: Hex64
    passages_bytes: Annotated[int, Field(ge=1, le=MAX_CORPUS_RAW_BYTES)]
    passage_count: Annotated[int, Field(ge=1, le=MAX_DOCUMENTS)]


class Passage(_Strict):
    passage_id: Annotated[str, StringConstraints(pattern=r"^md2d\.p/[0-9a-f]{64}$")]
    domain: Slug
    document_id: Text200
    heading: Annotated[str, StringConstraints(max_length=500)]
    body: Annotated[str, StringConstraints(min_length=1, max_length=20_000)]
    start: Annotated[int, Field(ge=0, le=4_194_304)]
    end: Annotated[int, Field(ge=1, le=4_194_304)]
    span_ids: Annotated[tuple[Text200, ...], Field(min_length=1, max_length=5000)]
    heading_only: bool
    run_ordinal: Annotated[int, Field(ge=0, le=5000)]

    @model_validator(mode="after")
    def _offsets(self) -> Passage:
        if self.end - self.start != len(self.body):
            raise ValueError("body length must equal original offset span")
        if len(set(self.span_ids)) != len(self.span_ids):
            raise ValueError("duplicate span IDs")
        return self


def load_manifest(raw: bytes, expected_sha256: str) -> ArchiveManifest:
    if len(raw) > MAX_MANIFEST_BYTES:
        raise SourceRefused("manifest_too_large")
    if sha256_hex(raw) != expected_sha256:
        raise SourceRefused("manifest_sha256_mismatch")
    try:
        decoded = raw.decode("utf-8", errors="strict")
        _strict_json(decoded, "manifest_malformed")
        return ArchiveManifest.model_validate_json(decoded)
    except (UnicodeError, ValidationError):
        raise SourceRefused("structural_manifest_invalid") from None


def read_corpus(raw: bytes, digest: str, corpus_key: str, acquisition_root: Path) -> SourceCorpus:
    manifest = load_manifest(raw, digest)
    if manifest.corpus_key != corpus_key:
        raise SourceRefused("corpus_not_in_manifest", corpus_key)
    root = checked_root(acquisition_root)
    data = _read_exact(contained_file(root, manifest.passages_path), manifest.passages_bytes, "passages")
    if sha256_hex(data) != manifest.passages_sha256:
        raise SourceRefused("passages_sha256_mismatch")
    # Split only LF (str.splitlines also accepts Unicode separators inside JSON strings).
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    if len(lines) != manifest.passage_count:
        raise SourceRefused("passage_count_mismatch")
    documents = []
    seen: set[str] = set()
    for line in lines:
        if len(line) > MAX_LINE_BYTES:
            raise SourceRefused("passage_record_too_large")
        try:
            decoded = line.decode("utf-8", errors="strict")
            _strict_json(decoded, "passage_malformed")
            passage = Passage.model_validate_json(decoded)
            check_body(passage.body, passage.passage_id)
            if passage.heading:
                check_body(passage.heading, passage.passage_id)
            record = canonical_json(passage.model_dump(mode="json"))
        except (UnicodeError, ValidationError):
            raise SourceRefused("passage_invalid") from None
        if passage.passage_id in seen:
            raise SourceRefused("passage_duplicate_id")
        seen.add(passage.passage_id)
        origin = StructuralOrigin(passage.domain, passage.document_id, passage.start, passage.end,
                                  passage.heading, passage.heading_only)
        mapping = canonical_json({"domain": origin.domain, "document_id": origin.document_id,
                                  "start": origin.start, "end": origin.end,
                                  "heading_only": origin.heading_only}).decode("utf-8")
        documents.append(SourceDocument(
            passage.passage_id, f"md2d:{passage.domain}/{passage.passage_id}", mapping, git_blob_sha1(record),
            sha256_hex(record), len(record), passage.body, sha256_hex(passage.body.encode("utf-8")), origin))
    documents.sort(key=lambda d: d.document_key)
    metadata = ArchiveMetadata(corpus_key=manifest.corpus_key, domain=manifest.domain, publisher=manifest.publisher,
                               license=manifest.license, license_scope=manifest.license_scope)
    return SourceCorpus(digest, sha256_hex(canonical_json(manifest.model_dump(mode="json"))), manifest.derivation,
                        metadata, tuple(documents), PARSER_VERSION, CHUNK_CONFIG, manifest.archive_sha256)
