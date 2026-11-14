"""The exact expected generation of one corpus import (T12): documents, chunks, digests and keys.

Everything here is a pure function of the verified sources, the parser and chunk versions, the tokenizer identity
and the embedding request configuration.

- **Chunk identity** `chunks.sha256` is the SHA-256 of canonical JSON over the parser and chunk versions, the
  stable source identity, the version digest, the offsets, the heading path, the section metadata and the chunk
  text's own digest. It is a composite identity, never the plain text digest; the two are stored and verified
  separately. Repeated text at different positions or in different documents (even byte-identical ones) keeps
  distinct identities.
- **Embedding input** is `policyops.embed-input/v1` (heading path, blank line, text); its digest is the cache key and
  is independent of document and offsets, so an unchanged exact input is reused.
- **Expected set** `expected_set_sha256` is the SHA-256 of canonical JSON of the header, the per-document list
  (including documents with no chunk) and the sorted chunk list (duplicates included). `generation_key_sha256` binds
  the header and the expected set; an import whose key equals the active generation's is a repeat.
- **Embedding inputs** of the job are the distinct exact inputs in first-occurrence order of the sorted chunk list.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import time
from typing import Any

from policyops.providers.embedding_contract import request_config_sha256
from policyops.providers.embeddings import input_sha256
from policyops.retrieval.parse import (
    CHUNK_CONFIG,
    EMBED_INPUT_FORMAT,
    PARSER_VERSION,
    TokenCounter,
    chunk_document,
    embed_input,
)
from policyops.retrieval.sources import SourceCorpus, SourceDocument, canonical_json, sha256_hex
from policyops.retrieval.structural import chunk_passage


MAX_CHUNKS = 10_000  # the embedding job's input limit; also bounds the single publish transaction
MAX_BODY_TOTAL_BYTES = 64 * 1_048_576
SET_VERSION = "policyops.expected-set/v1"


class CorpusRefused(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


@dataclass(frozen=True)
class ExpectedChunk:
    source_uri: str
    version_sha256: str
    start: int
    end: int
    heading: str
    section_ordinal: int
    section_start: int
    section_end: int
    text: str
    text_sha256: str
    sha256: str  # the composite identity
    embed_input: str
    embed_input_sha256: str
    tokens: int


@dataclass(frozen=True)
class ExpectedDocument:
    source: SourceDocument
    ordinal: int
    chunk_count: int


@dataclass(frozen=True)
class Expected:
    corpus: SourceCorpus
    header: dict[str, Any]
    documents: tuple[ExpectedDocument, ...]
    chunks: tuple[ExpectedChunk, ...]
    inputs: tuple[str, ...]  # distinct embedding inputs, first occurrence order
    expected_set_sha256: str
    generation_key_sha256: str
    request_config_sha256: str
    tokenizer_sha256: str

    @property
    def subject_key(self) -> str:
        return f"ingest.{self.corpus.corpus.corpus_key}.{self.expected_set_sha256}"


def chunk_identity(source_uri: str, version_sha256: str, start: int, end: int, heading: str, section_ordinal: int,
                   section_start: int, section_end: int, text_sha256: str, *, parser: str = PARSER_VERSION,
                   chunk_config: str = CHUNK_CONFIG) -> str:
    return sha256_hex(canonical_json({
        "v": "policyops.chunk/v1", "parser": parser, "chunk_config": chunk_config,
        "source_uri": source_uri, "version_sha256": version_sha256, "start": start, "end": end, "heading": heading,
        "section_ordinal": section_ordinal, "section_start": section_start, "section_end": section_end,
        "text_sha256": text_sha256}))


def chunk_entry(chunk: ExpectedChunk) -> list[Any]:
    return [chunk.source_uri, chunk.version_sha256, chunk.start, chunk.end, chunk.sha256, chunk.text_sha256,
            chunk.heading, chunk.section_ordinal, chunk.section_start, chunk.section_end, chunk.embed_input_sha256]


def document_entry(document: ExpectedDocument) -> list[Any]:
    source = document.source
    return [document.ordinal, source.source_uri, source.version_sha256, source.path, source.git_blob,
            source.raw_sha256, source.raw_bytes, document.chunk_count]


def set_digest(header: dict[str, Any], documents: Sequence[list[Any]], chunks: Sequence[list[Any]]) -> str:
    return sha256_hex(canonical_json({"v": SET_VERSION, "header": header, "documents": list(documents),
                                      "chunks": sorted(chunks, key=lambda c: (c[0], c[2], c[3]))}))


def generation_key(header: dict[str, Any], expected_set_sha256: str) -> str:
    return sha256_hex(canonical_json({"v": "policyops.generation-key/v1", "header": header,
                                      "expected_set_sha256": expected_set_sha256}))


def build_expected(corpus: SourceCorpus, counter: TokenCounter, *, tokenizer_sha256: str, model: str,
                   dimensions: int, deadline: float, clock: Callable[[], float] = time.monotonic) -> Expected:
    if sum(len(d.body.encode("utf-8")) for d in corpus.documents) > MAX_BODY_TOTAL_BYTES:
        raise CorpusRefused("corpus_exceeds_single_transaction_bounds", "bodies")
    config = request_config_sha256(model, dimensions)
    spec = corpus.corpus
    header = {"corpus_key": spec.corpus_key, "domain": spec.domain, "render": spec.render,
              "corpus_manifest_sha256": corpus.corpus_manifest_sha256,
              "source": corpus.revision.model_dump(mode="json"), "parser": corpus.parser_version,
              "chunk_config": corpus.chunk_config, "embed_input": EMBED_INPUT_FORMAT,
              "tokenizer_sha256": tokenizer_sha256,
              "request_config_sha256": config, "model": model, "dimensions": dimensions}
    if corpus.archive_sha256 is not None:
        header["archive_sha256"] = corpus.archive_sha256
    documents: list[ExpectedDocument] = []
    chunks: list[ExpectedChunk] = []
    for ordinal, source in enumerate(corpus.documents):
        found = (chunk_passage(source, counter, deadline=deadline, clock=clock) if source.origin is not None
                 else chunk_document(source.body, counter, deadline=deadline, clock=clock))
        for chunk in found:
            text_digest = sha256_hex(chunk.text.encode("utf-8"))
            submitted = embed_input(chunk.heading, chunk.text)
            chunks.append(ExpectedChunk(
                source.source_uri, source.version_sha256, chunk.start, chunk.end, chunk.heading,
                chunk.section_ordinal, chunk.section_start, chunk.section_end, chunk.text, text_digest,
                chunk_identity(source.source_uri, source.version_sha256, chunk.start, chunk.end, chunk.heading,
                               chunk.section_ordinal, chunk.section_start, chunk.section_end, text_digest,
                               parser=corpus.parser_version, chunk_config=corpus.chunk_config),
                submitted, input_sha256(submitted), chunk.tokens))
            if len(chunks) > MAX_CHUNKS:
                raise CorpusRefused("corpus_exceeds_single_transaction_bounds", "chunks")
        documents.append(ExpectedDocument(source, ordinal, len(found)))
    chunks.sort(key=lambda c: (c.source_uri, c.start, c.end))
    seen: dict[str, None] = {}
    for entry in chunks:
        seen.setdefault(entry.embed_input, None)
    expected_set = set_digest(header, [document_entry(d) for d in documents], [chunk_entry(c) for c in chunks])
    return Expected(corpus, header, tuple(documents), tuple(chunks), tuple(seen), expected_set,
                    generation_key(header, expected_set), config, tokenizer_sha256)
