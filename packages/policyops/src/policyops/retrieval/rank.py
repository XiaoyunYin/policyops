"""Pure retrieval ranking (T13): reciprocal-rank fusion, evidence delivery and the evidence format. No I/O.

**Fusion.** A document's RRF value is `sum(1 / (rrf_k + rank))` over the branches it appears in (1-based ranks),
computed with `fractions.Fraction`, so ties are exact. Order: RRF descending, then the best single-branch rank, then
`source_uri` (code-point order, which equals the database's `COLLATE "C"` byte order for UTF-8), then the document
ID. A lexical score is never compared with a dense distance: only ranks enter fusion.

**Delivery** (ranked modes), greedy per step:
- per document (in fused order) the chunk list is the better-ranked branch's chunks in that branch's order, then the
  other branch's; **on an equal rank, lexical first**. Duplicates are dropped by chunk ID;
- a first pass takes at most `chunks_per_document` chunks per document, a second pass the remainder, in the same
  order;
- each admission counts the **whole** assembled evidence string with the candidate block appended (headers and
  separators included; BPE counts are not additive). A block is admitted only if that count is at most
  `max_evidence_tokens` and fewer than `max_chunks` are delivered; otherwise it is skipped, never truncated;
- at most `max_admission_attempts` blocks are tried.

**Full policy** delivers every chunk in `(source_uri, start, end, chunk ID)` order if the whole string fits, or
refuses.

**Evidence format** `policyops.evidence-format/v1`: blocks `[E{n}] {source_uri} version {v} | {heading} | chars
{start}-{end}` + LF + the verbatim chunk text, joined by a blank line. Source URIs, headings and texts are untrusted
data and may contain URLs, instructions or fake `[E9]` markers; the `E{n}` map is the delivery list, never parsed from
text. The delimiter is not prompt-injection-proof.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Protocol
from uuid import UUID

from policyops_contracts.retrieval import RetrievalConfig


EVIDENCE_FORMAT = "policyops.evidence-format/v1"
SEPARATOR = "\n\n"
_MISSING = 10**9


class Counter(Protocol):
    def count(self, text: str) -> int: ...


class CountRefused(Exception):
    """A counter refusal for one candidate assembly (treated as a non-fit, never truncated)."""


@dataclass(frozen=True)
class Hit:
    """One branch's document entry: its rank, decimal score text and ordered chunk IDs."""

    document_id: UUID
    source_uri: str
    rank: int
    score: str
    chunk_ids: tuple[UUID, ...]


@dataclass(frozen=True)
class Fused:
    document_id: UUID
    source_uri: str
    rank: int
    rrf: Fraction
    lexical_rank: int | None
    dense_rank: int | None
    chunk_ids: tuple[UUID, ...]  # the delivery order of this document's chunks


@dataclass(frozen=True)
class ChunkRow:
    chunk_id: UUID
    document_id: UUID
    document_version_id: UUID
    source_uri: str
    version_number: int
    heading: str
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class Delivery:
    chunks: tuple[ChunkRow, ...]
    evidence_text: str
    evidence_tokens: int
    admission_attempts: int
    count_refused: int = 0  # candidate assemblies the counter refused (skipped, reported, never truncated)


class FullPolicyRefused(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def fraction_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def fuse(lexical: Sequence[Hit], dense: Sequence[Hit], rrf_k: int) -> list[Fused]:
    by_document: dict[UUID, dict[str, Hit]] = {}
    for branch, hits in (("lexical", lexical), ("dense", dense)):
        for hit in hits:
            by_document.setdefault(hit.document_id, {})[branch] = hit
    entries = []
    for document_id, branches in by_document.items():
        rrf = sum((Fraction(1, rrf_k + hit.rank) for hit in branches.values()), Fraction(0))
        lexical_hit, dense_hit = branches.get("lexical"), branches.get("dense")
        lexical_rank = lexical_hit.rank if lexical_hit else None
        dense_rank = dense_hit.rank if dense_hit else None
        order = [lexical_hit, dense_hit] if (lexical_rank or _MISSING) <= (dense_rank or _MISSING) \
            else [dense_hit, lexical_hit]
        chunks: list[UUID] = []
        for branch_hit in order:
            for chunk_id in branch_hit.chunk_ids if branch_hit else ():
                if chunk_id not in chunks:
                    chunks.append(chunk_id)
        source_uri = next(iter(branches.values())).source_uri
        entries.append((rrf, min(lexical_rank or _MISSING, dense_rank or _MISSING), source_uri, document_id,
                        lexical_rank, dense_rank, tuple(chunks)))
    entries.sort(key=lambda e: (-e[0], e[1], e[2], str(e[3])))
    return [Fused(e[3], e[2], position, e[0], e[4], e[5], e[6]) for position, e in enumerate(entries, start=1)]


def block(number: int, chunk: ChunkRow) -> str:
    return (f"[E{number}] {chunk.source_uri} version {chunk.version_number} | {chunk.heading} | "
            f"chars {chunk.start}-{chunk.end}\n{chunk.text}")


def assemble(chunks: Sequence[ChunkRow]) -> str:
    return SEPARATOR.join(block(number, chunk) for number, chunk in enumerate(chunks, start=1))


def _try(counter: Counter, text: str) -> int | None:
    try:
        return counter.count(text)
    except CountRefused:
        return None


def deliver(fused: Sequence[Fused], rows: dict[UUID, ChunkRow], config: RetrievalConfig, counter: Counter) -> Delivery:
    """Greedy, skip-not-truncate delivery under the whole-string token budget (see the module docstring)."""
    first: list[UUID] = []
    second: list[UUID] = []
    for document in fused:
        available = [c for c in document.chunk_ids if c in rows]
        first.extend(available[:config.chunks_per_document])
        second.extend(available[config.chunks_per_document:])
    delivered: list[ChunkRow] = []
    assembled, tokens, attempts, refused = "", 0, 0, 0
    for chunk_id in first + second:
        if len(delivered) >= config.max_chunks or attempts >= config.max_admission_attempts:
            break
        attempts += 1
        chunk = rows[chunk_id]
        candidate_block = block(len(delivered) + 1, chunk)
        candidate = candidate_block if not assembled else assembled + SEPARATOR + candidate_block
        counted = _try(counter, candidate)
        if counted is None:
            refused += 1
        elif counted <= config.max_evidence_tokens:
            delivered.append(chunk)
            assembled, tokens = candidate, counted
    return Delivery(tuple(delivered), assembled, tokens, attempts, refused)


def deliver_full_policy(rows: Sequence[ChunkRow], config: RetrievalConfig, counter: Counter) -> Delivery:
    """Every chunk in stable order, or a refusal (never truncation)."""
    if len(rows) > config.full_policy_max_chunks:
        raise FullPolicyRefused("full_policy_too_many_chunks")
    ordered = sorted(rows, key=lambda c: (c.source_uri, c.start, c.end, str(c.chunk_id)))
    text = assemble(ordered)
    counted = _try(counter, text) if text else 0
    if counted is None:  # a computational guard (for example an over-long regex piece), not a token overflow
        raise FullPolicyRefused("evidence_uncountable")
    if counted > config.max_evidence_tokens:
        raise FullPolicyRefused("full_policy_exceeds_budget")
    return Delivery(tuple(ordered), text, counted, 1 if text else 0)
