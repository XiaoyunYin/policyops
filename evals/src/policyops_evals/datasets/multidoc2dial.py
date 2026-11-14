"""Pinned MultiDoc2Dial derivation, without extraction, network access or model calls.

    python -m policyops_evals.datasets.multidoc2dial build --archive ZIP --out PRIVATE_DIR

Only cohort dialogue/query identities, hashes and counts belong in the committed manifest. Human
replies/references are separate from model inputs in the private JSONL files.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import io
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any, Literal
import zipfile
import zlib

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from policyops.providers import tokenizer


SCHEMA = "policyops.multidoc2dial/v1"
PASSAGE_RULE = "md2d.title-runs/v1"
ARCHIVE_SHA256 = "f0c034c249663d7b3cb08b19cf2cc2c3d101372485be982621d4711931a1ce00"
ARCHIVE_BYTES = 6_868_509
PREFIX = "multidoc2dial/"
DOC = PREFIX + "multidoc2dial_doc.json"
TRAIN = PREFIX + "multidoc2dial_dial_train.json"
VALIDATION = PREFIX + "multidoc2dial_dial_validation.json"
MEMBER_SHA256 = {
    DOC: "7205be05b7c260fd3c0eda4d98a4abddf7af66c364238f1be509aa139414012d",
    TRAIN: "c9a6ef2e0be22306429e0affa51c2ca164b2808a89a999e7756700170ed15d96",
    VALIDATION: "ce063938b53d96f6128275d76c0ba967a435e3d865d011aaeb6461c2538b2ce4",
}
ALLOWED_MEMBERS = frozenset((*MEMBER_SHA256, PREFIX, PREFIX + "README.md",
                             PREFIX + "multidoc2dial_dial_test.json"))
MAX_ARCHIVE_BYTES = 8 << 20
MAX_MEMBER_BYTES = 48 << 20
MAX_TOTAL_BYTES = 104 << 20
MAX_MEMBERS = 32
MAX_COMPRESSION_RATIO = 128
MAX_QUERY_TOKENS = 1024
COHORT_HASHES = {
    "dev": "ca78f1ca0f2cddc5fde0565b8b43fa4a4da56950ac00ad07ff9889ffb7579041",
    "retrieval": "64c91b39aea999f4a24c94cdb4ea692383f12e4adc7cfacf7397645bd4c36438",
    "answers": "fc12977b997cf8801c319c6db77b67fe5f68de5a14d8bb1e0572334bbfd8bda8",
    "full_context": "58915c5b141aa6a89398a1bfa9c47ea028701adbbac324e13e96438605ca7e5b",
}


class DatasetError(ValueError):
    """Invalid input, pin mismatch or a changed derivation. Does not echo source text."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def text_hash(text: str) -> str:
    return digest(text.encode("utf-8"))


def ids_hash(ids: Sequence[str]) -> str:
    return text_hash("".join(item + "\n" for item in sorted(ids)))


def jsonl(rows: Iterable[Mapping[str, Any]]) -> Iterator[bytes]:
    for row in rows:
        yield canonical(row) + b"\n"


def stream_hash(chunks: Iterable[bytes]) -> str:
    result = hashlib.sha256()
    for chunk in chunks:
        result.update(chunk)
    return result.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DatasetError("duplicate JSON key")
        result[key] = value
    return result


@dataclass(frozen=True)
class ArchivePins:
    sha256: str
    size: int
    members: Mapping[str, str]


PINS = ArchivePins(ARCHIVE_SHA256, ARCHIVE_BYTES, MEMBER_SHA256)


def read_archive(source: Path | bytes, *, pins: ArchivePins = PINS) -> dict[str, Any]:
    """Bound before parsing/decompression; verify pins before consuming JSON.

    Bytes input and explicit pins support small offline fixtures. Production uses
    the immutable default pins. Even ignored resource forks undergo path/size checks.
    """
    if isinstance(source, Path):
        with source.open("rb") as handle:
            data = handle.read(MAX_ARCHIVE_BYTES + 1)
    else:
        data = source
    if len(data) > MAX_ARCHIVE_BYTES:
        raise DatasetError("archive size limit")
    if len(data) != pins.size or digest(data) != pins.sha256:
        raise DatasetError("archive pin mismatch")
    result: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                raise DatasetError("archive member count limit")
            names: set[str] = set()
            total = 0
            for info in infos:
                name = info.filename
                path = PurePosixPath(name)
                if (not name or "\\" in name or "\x00" in info.orig_filename or ":" in name
                        or path.is_absolute() or any(p in {".", "..", ""} for p in name.rstrip("/").split("/"))):
                    raise DatasetError("unsafe archive path")
                if name in names:
                    raise DatasetError("duplicate archive member")
                names.add(name)
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise DatasetError("nonregular archive member")
                total += info.file_size
                if (info.file_size > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES
                        or info.file_size > max(1, info.compress_size) * MAX_COMPRESSION_RATIO):
                    raise DatasetError("archive member size limit")
                if info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise DatasetError("unsupported archive encoding")
                if path.parts[0] == "__MACOSX":
                    continue
                if name not in ALLOWED_MEMBERS:
                    raise DatasetError("archive member outside allowlist")
                if name not in pins.members:
                    continue
                with archive.open(info) as member:
                    body = member.read(MAX_MEMBER_BYTES + 1)
                if len(body) != info.file_size or digest(body) != pins.members[name]:
                    raise DatasetError("archive member pin mismatch")
                result[name] = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
            if set(result) != set(pins.members) or set(pins.members) != set(MEMBER_SHA256):
                raise DatasetError("missing required archive member")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, UnicodeError, RecursionError,
            json.JSONDecodeError, EOFError, zlib.error):
        raise DatasetError("malformed archive or JSON") from None
    return result


class InputModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")


class ParentTitle(InputModel):
    text: str = Field(max_length=20_000)


class Span(InputModel):
    id_sp: str = Field(pattern=r"^[0-9]{1,8}$")
    start_sp: int = Field(ge=0)
    end_sp: int = Field(ge=0)
    text_sp: str = Field(max_length=100_000)
    title: str = Field(max_length=20_000)
    parent_titles: list[ParentTitle] = Field(max_length=100)
    tag: str = Field(max_length=100)


class Document(InputModel):
    doc_id: str = Field(min_length=1, max_length=2000)
    domain: str = Field(min_length=1, max_length=100)
    doc_text: str = Field(max_length=200_000)
    spans: dict[str, Span] = Field(min_length=1, max_length=20_000)


class Documents(InputModel):
    doc_data: dict[str, dict[str, Document]]


class Reference(InputModel):
    doc_id: str = Field(min_length=1, max_length=2000)
    id_sp: str = Field(pattern=r"^[0-9]{1,8}$")
    domain: str | None = Field(default=None, max_length=100)


class Turn(InputModel):
    turn_id: int = Field(ge=0)
    role: Literal["user", "agent"]
    utterance: str = Field(min_length=1, max_length=20_000)
    da: str = Field(max_length=100)
    references: list[Reference] = Field(max_length=1000)


class Dialogue(InputModel):
    dial_id: str = Field(min_length=1, max_length=200)
    turns: list[Turn] = Field(max_length=1000)


class Dialogues(InputModel):
    dial_data: dict[str, list[Dialogue]]


@dataclass(frozen=True)
class Passage:
    passage_id: str
    domain: str
    document_id: str
    run_ordinal: int
    span_ids: tuple[str, ...]
    start: int
    end: int
    heading: str
    body: str
    heading_only: bool

    @property
    def rendered(self) -> str:
        return self.heading + "\n\n" + self.body


@dataclass(frozen=True)
class Query:
    query_id: str
    split: str
    domain: str
    dialogue_id: str
    turn_id: int
    retrieval: str
    generation_history: str
    last_turn: str
    history_turn_ids: tuple[int, ...]  # chronological, including current user
    dropped_history_turns: int
    reference_answer: str
    target_act: str
    passage_ids: tuple[str, ...]

    @property
    def dialogue_key(self) -> str:
        return self.domain + "/" + self.dialogue_id


@dataclass(frozen=True)
class Dataset:
    passages: tuple[Passage, ...]
    queries: tuple[Query, ...]
    dialogues: Mapping[str, tuple[str, ...]]
    excluded_no_solution: Mapping[str, int]


def build_passages(documents: Documents) -> tuple[tuple[Passage, ...], dict[tuple[str, str, str], str]]:
    passages: list[Passage] = []
    index: dict[tuple[str, str, str], str] = {}
    for domain, docs in sorted(documents.doc_data.items()):
        for doc_id, doc in sorted(docs.items()):
            if (domain, doc_id) != (doc.domain, doc.doc_id):
                raise DatasetError("document identity mismatch")
            spans = sorted(doc.spans.values(), key=lambda s: (s.start_sp, s.end_sp, int(s.id_sp)))
            for key, span in doc.spans.items():
                if (key != span.id_sp or not 0 <= span.start_sp < span.end_sp <= len(doc.doc_text)
                        or doc.doc_text[span.start_sp:span.end_sp] != span.text_sp):
                    raise DatasetError("invalid span identity or slice")
            if any(a.end_sp > b.start_sp for a, b in itertools.pairwise(spans)):
                raise DatasetError("overlapping spans")
            for ordinal, (_, group) in enumerate(itertools.groupby(spans, key=lambda s: s.title), 1):
                run = list(group)
                if any(a.end_sp != b.start_sp for a, b in itertools.pairwise(run)):
                    raise DatasetError("noncontiguous title run")
                first, last = run[0], run[-1]
                passage_id = "md2d.p/" + digest(canonical([domain, doc_id, ordinal]))
                passage = Passage(
                    passage_id, domain, doc_id, ordinal, tuple(s.id_sp for s in run), first.start_sp, last.end_sp,
                    " > ".join([p.text for p in first.parent_titles] + [first.title]),
                    doc.doc_text[first.start_sp:last.end_sp], all(s.tag in {"h1", "h2", "h3", "h4", "h5", "h6"}
                                                               for s in run),
                )
                passages.append(passage)
                for span in run:
                    index[domain, doc_id, span.id_sp] = passage_id
    return tuple(passages), index


def render_query(turns: Sequence[Turn], count: Callable[[str], int], *, limit: int = MAX_QUERY_TOKENS
                 ) -> tuple[str, str, str, tuple[int, ...], int]:
    """The caller supplies turns through the current user, never the target."""
    if not turns or turns[-1].role != "user":
        raise DatasetError("query must end with a user turn")
    available = list(turns[-5:])
    initial = len(available)

    def render(items: Sequence[Turn]) -> str:
        return " [SEP] ".join(f"{t.role}: {t.utterance}" for t in items)

    last = render(available[-1:])
    if count(last) > limit:
        raise DatasetError("current user turn exceeds query token bound")
    while True:
        retrieval = render(available[::-1])
        if count(retrieval) <= limit:
            break
        available.pop(0)
    return retrieval, render(available), last, tuple(t.turn_id for t in available), initial - len(available)


def build_dataset(members: Mapping[str, Any], count: Callable[[str], int]) -> Dataset:
    try:
        documents = Documents.model_validate(members[DOC])
        splits = {"train": Dialogues.model_validate(members[TRAIN]),
                  "validation": Dialogues.model_validate(members[VALIDATION])}
    except (ValidationError, KeyError):
        raise DatasetError("invalid dataset schema") from None
    passages, index = build_passages(documents)
    queries: list[Query] = []
    dialogue_keys: dict[str, tuple[str, ...]] = {}
    excluded: dict[str, int] = {}
    for split, data in splits.items():
        keys: set[str] = set()
        excluded[split] = 0
        for domain, dialogues in sorted(data.dial_data.items()):
            if domain not in documents.doc_data:
                raise DatasetError("unknown dialogue domain")
            for dialogue in sorted(dialogues, key=lambda d: d.dial_id):
                key = domain + "/" + dialogue.dial_id
                if key in keys or len({t.turn_id for t in dialogue.turns}) != len(dialogue.turns):
                    raise DatasetError("duplicate dialogue or turn identity")
                keys.add(key)
                if any(a.turn_id >= b.turn_id for a, b in itertools.pairwise(dialogue.turns)):
                    raise DatasetError("turn order mismatch")
                # Validate even excluded/user references, not just qrels that happen to be selected.
                for turn in dialogue.turns:
                    for ref in turn.references:
                        if (ref.domain or domain, ref.doc_id, ref.id_sp) not in index:
                            raise DatasetError("unknown reference")
                for position, target in enumerate(dialogue.turns):
                    if target.role != "agent" or position == 0 or dialogue.turns[position - 1].role != "user":
                        continue
                    if target.da == "respond_no_solution":
                        excluded[split] += 1
                        continue
                    retrieval, history, last, history_ids, dropped = render_query(dialogue.turns[:position], count)
                    qrels = tuple(sorted({index[ref.domain or domain, ref.doc_id, ref.id_sp]
                                          for ref in target.references}))
                    queries.append(Query(
                        f"md2d.q/{split}/{domain}/{dialogue.dial_id}/{target.turn_id}", split, domain,
                        dialogue.dial_id, target.turn_id, retrieval, history, last, history_ids, dropped,
                        target.utterance, target.da, qrels,
                    ))
        dialogue_keys[split] = tuple(sorted(keys))
    return Dataset(passages, tuple(queries), dialogue_keys, excluded)


def rank_dialogues(keys: Sequence[str], prefix: str = "g0/v1") -> list[str]:
    def rank(key: str) -> tuple[str, str]:
        domain, dial_id = key.split("/", 1)
        return text_hash(f"{prefix}|20261114|{domain}|{dial_id}"), key
    return sorted(keys, key=rank)


def cohorts(dataset: Dataset) -> dict[str, list[str]]:
    train = rank_dialogues(dataset.dialogues["train"])
    retrieval = rank_dialogues(dataset.dialogues["validation"])[:300]
    answers = rank_dialogues(retrieval, "g0/answers/v1")[:200]
    return {"dev": sorted(train[:80]), "g8_pool": sorted(train[80:]), "retrieval": sorted(retrieval),
            "answers": sorted(answers), "full_context": sorted(rank_dialogues(answers, "g0/full/v1")[:6])}


def _duplicate_groups(items: Sequence[tuple[str, str, str]]) -> list[dict[str, Any]]:
    """Exact UTF-8 hash groups spanning partitions; values never leave this function."""
    groups: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for partition, identity, value in items:
        groups[text_hash(value)][partition].append(identity)
    return [{"sha256": h, "partitions": {p: sorted(ids) for p, ids in sorted(parts.items())}}
            for h, parts in sorted(groups.items()) if len(parts) > 1]


def audit(dataset: Dataset, selected: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    dev = set(selected["dev"])
    partition = {q.query_id: ("validation" if q.split == "validation" else
                            "dev" if q.dialogue_key in dev else "g8_pool") for q in dataset.queries}
    # Last-turn matches are conservatively excluded from training even when history differs.
    query_duplicates = {
        field: _duplicate_groups([(partition[q.query_id], q.query_id, getattr(q, field)) for q in dataset.queries])
        for field in ("retrieval", "last_turn")
    }
    excluded: set[str] = set()
    for groups in query_duplicates.values():
        for group in groups:
            excluded.update(group["partitions"].get("g8_pool", []))
    used: dict[str, set[str]] = defaultdict(set)
    for q in dataset.queries:
        used[partition[q.query_id]].update(q.passage_ids)
    passage_duplicates = {
        field: _duplicate_groups([(part, p.passage_id, getattr(p, field))
                                  for part, ids in sorted(used.items())
                                  for p in dataset.passages if p.passage_id in ids])
        for field in ("body", "rendered")
    }
    # Shared source passages are intentional retrieval corpus reuse, not dialogue leakage.
    return {"query_duplicates": query_duplicates, "passage_duplicates": passage_duplicates,
            "g8_excluded_query_ids": sorted(excluded),
            "g8_exclusion_rule": "exact retrieval or last-turn hash shared with dev or any validation query",
            "passage_overlap_treatment": "shared corpus permitted; no G8 exclusion solely for passage overlap"}


def _query_counts(queries: Sequence[Query]) -> dict[str, Any]:
    def act_group(act: str) -> str:
        if act == "query_condition":
            return "clarification"
        return "responding" if act in {"respond_solution", "respond_solution_positive",
                                       "respond_solution_negative"} else "other"

    return {"queries": len(queries), "by_domain": dict(sorted(Counter(q.domain for q in queries).items())),
            "by_act": dict(sorted(Counter(q.target_act for q in queries).items())),
            "by_act_group": dict(sorted(Counter(act_group(q.target_act) for q in queries).items())),
            "empty_qrels": sum(not q.passage_ids for q in queries),
            "multi_passage_qrels": sum(len(q.passage_ids) > 1 for q in queries),
            "dropped_history_turns": sum(q.dropped_history_turns for q in queries)}


def passage_records(dataset: Dataset) -> list[dict[str, Any]]:
    """Full ID/span/content identity derivation, hashed rather than published."""
    return [{"passage_id": p.passage_id, "domain": p.domain, "document_id": p.document_id,
             "run_ordinal": p.run_ordinal, "span_ids": list(p.span_ids), "start": p.start, "end": p.end,
             "heading_only": p.heading_only, "body_sha256": text_hash(p.body),
             "heading_sha256": text_hash(p.heading), "rendered_sha256": text_hash(p.rendered)}
            for p in sorted(dataset.passages, key=lambda p: p.passage_id)]


def materialization_rows(dataset: Dataset, name: str) -> Iterator[dict[str, Any]]:
    """One serialization contract for private-file hashes and actual output bytes."""
    if name == "passages.jsonl":
        for passage in dataset.passages:
            yield asdict(passage)
    elif name == "queries.jsonl":
        for query in dataset.queries:
            yield {key: val for key, val in asdict(query).items()
                   if key not in {"reference_answer", "target_act", "passage_ids"}}
    elif name == "references.jsonl":
        for query in dataset.queries:
            yield {"query_id": query.query_id, "answer": query.reference_answer,
                   "target_act": query.target_act, "passage_ids": query.passage_ids}
    else:
        raise DatasetError("unknown materialization file")


MATERIALIZATION_FILES = ("passages.jsonl", "queries.jsonl", "references.jsonl")


def manifest(dataset: Dataset, tokenizer_identity: str) -> dict[str, Any]:
    """Deterministic public projection. Never serialize utterances, headings or bodies."""
    selected = cohorts(dataset)
    audits = audit(dataset, selected)
    excluded = set(audits["g8_excluded_query_ids"])
    cohort_records: dict[str, Any] = {}
    for name, keys in selected.items():
        split = "train" if name in {"dev", "g8_pool"} else "validation"
        key_set = set(keys)
        queries = [q for q in dataset.queries if q.split == split and q.dialogue_key in key_set]
        cohort_records[name] = {"dialogues": len(keys), "sha256": ids_hash(keys),
                                "query_ids_sha256": ids_hash([q.query_id for q in queries]),
                                **_query_counts(queries)}
        if name != "g8_pool":
            cohort_records[name]["dialogue_ids"] = keys
            cohort_records[name]["query_ids"] = sorted(q.query_id for q in queries)
    eligible_g8 = [q for q in dataset.queries if q.split == "train" and q.dialogue_key in set(selected["g8_pool"])
                   and q.query_id not in excluded]
    return {
        "schema": SCHEMA,
        "source": {"dataset": "MultiDoc2Dial v1.0", "archive_sha256": ARCHIVE_SHA256,
                   "archive_bytes": ARCHIVE_BYTES, "member_sha256": MEMBER_SHA256,
                   "homepage": "https://doc2dial.github.io/multidoc2dial/", "archive_host": "doc2dial.github.io",
                   "upstream_git_revision": None, "acquired_utc_date": "2026-11-14"},
        "algorithms": {
            "passages": PASSAGE_RULE,
            "passage_identity": "md2d.p/ + sha256(canonical JSON [domain, doc_id, 1-based run])",
            "content_hash": "sha256 exact UTF-8; rendered = heading + LF LF + body",
            "spans": "sort (start_sp,end_sp,integer id_sp); maximal consecutive identical-title runs; exact slice",
            "heading": "first span parent_titles texts then title, joined with ' > '",
            "heading_only": "all run span tags in h1..h6; retained",
            "eligibility": "agent immediately after user; target da != respond_no_solution",
            "act_groups": "query_condition = clarification; respond_solution{,_positive,_negative} = responding",
            "retrieval": "current user then previous four individual turns newest first; role: utterance; ' [SEP] '",
            "truncation": "drop oldest history until <=1024 cl100k tokens; overlong current user fails",
            "generation": "same retained turns chronologically, identical role labels and separator",
            "last_turn": "user: current utterance, no history",
            "qrels": "union of target agent references across domains/documents/spans, sorted deduplicated passage IDs",
            "ranking": "sha256 UTF-8 {prefix}|20261114|{domain}|{dial_id}; ties domain/dial_id",
            "cohort_prefixes": {"dev": "g0/v1", "retrieval": "g0/v1", "answers": "g0/answers/v1",
                                "full_context": "g0/full/v1"},
            "cohort_rules": "dev first80 train; G8 remainder; retrieval first300 validation; "
                            "answers first200 retrieval; full first6 answers",
            "id_list_hash": "sorted domain/dial_id, LF-separated, trailing LF",
            "query_id_list_hash": "sorted query IDs, LF-separated, trailing LF",
            "derivation_hashes": "SHA-256; canonical JSON uses sorted keys, ASCII escaping, compact separators; "
                                 "passage list sorted by passage_id without trailing LF; "
                                 "qrels canonical JSONL sorted by query_id with sorted passage_ids and trailing LF; "
                                 "duplicate-group lists canonical JSON without trailing LF",
            "materialization_hashes": "SHA-256 of exact private canonical JSONL bytes, including trailing LF; "
                                      "source domain/document/dialogue/turn order, as in the builder",
        },
        "tokenizer": {"encoding": tokenizer.ENCODING_NAME, "tiktoken": tokenizer.TIKTOKEN_VERSION,
                      "vocabulary_sha256": tokenizer.VOCABULARY_SHA256, "identity_sha256": tokenizer_identity,
                      "query_token_bound": MAX_QUERY_TOKENS, "provider_count": False},
        "counts": {
            "documents": len({(p.domain, p.document_id) for p in dataset.passages}),
            "passages": len(dataset.passages), "heading_only": sum(p.heading_only for p in dataset.passages),
            "passages_by_domain": dict(sorted(Counter(p.domain for p in dataset.passages).items())),
            "splits": {split: {"dialogues": len(dataset.dialogues[split]),
                               **_query_counts([q for q in dataset.queries if q.split == split])}
                       for split in ("train", "validation")},
            "excluded_respond_no_solution": dict(dataset.excluded_no_solution),
            "g8_after_duplicate_exclusions": _query_counts(eligible_g8),
        },
        "cohorts": cohort_records,
        "audits": {
            kind: {field: {"groups": len(groups), "sha256": digest(canonical(groups))}
                   for field, groups in audits[kind].items()}
            for kind in ("query_duplicates", "passage_duplicates")
        } | {"g8_excluded_queries": len(excluded), "g8_excluded_query_ids_sha256": ids_hash(sorted(excluded)),
             "g8_exclusion_rule": audits["g8_exclusion_rule"],
             "passage_overlap_treatment": audits["passage_overlap_treatment"],
             "notes": "Coordinator's independent 200-random-query probe: 0 gold spans missing from qrel passage "
                      "bodies. Three target replies also occurred in inputs because the human agent had said "
                      "the same text earlier in the dialogue; natural repetition, not pipeline target leakage. "
                      "These probe observations are not an exhaustive corpus audit."},
        "derivations": {
            "passages_sha256": digest(canonical(passage_records(dataset))),
            "qrels_sha256": stream_hash(jsonl(
                {"query_id": q.query_id, "passage_ids": sorted(q.passage_ids)}
                for q in sorted(dataset.queries, key=lambda q: q.query_id))),
        },
        "materialization_sha256": {name: stream_hash(jsonl(materialization_rows(dataset, name)))
                                   for name in MATERIALIZATION_FILES},
        "rights": {
            "attribution": "MultiDoc2Dial v1.0, IBM; Song Feng, Siva Sankalp Patel, Hui Wan, Sachindra Joshi (2021)",
            "citation": "MultiDoc2Dial: Modeling Dialogues Grounded in Multiple Documents. "
                        "EMNLP 2021. https://arxiv.org/abs/2109.12595",
            "homepage": "https://doc2dial.github.io/multidoc2dial/",
            "license": "CC BY 3.0", "license_url": "https://creativecommons.org/licenses/by/3.0/",
            "conflict": "HF YAML tag says Apache-2.0; HF licensing section and Doc2Dial card say CC BY 3.0. "
                        "Treat as CC BY 3.0.",
            "changes": "title-run passages, rendered history, mapped qrels, hash-ranked cohorts and duplicate audits",
            "publication": "registerable cohort dialogue/query IDs, hashes, counts and audit summaries only; "
                           "archive, derived text, replies and traces remain private",
            "limitations": "Official test is dummy; validation is sealed test. "
                           "Train denominator differs from paper by 2. "
                           "No natural unanswerables; abstention accuracy N/A. Shared documents and incomplete qrels; "
                           "public benchmark contamination cannot be excluded. "
                           "Matching passage count does not prove upstream preprocessing.",
        },
    }


def verify_design(value: Mapping[str, Any]) -> None:
    expected = {"dev": (80, 500), "g8_pool": (3394, 20951), "retrieval": (300, 1940),
                "answers": (200, 1302), "full_context": (6, 42)}
    if (value["counts"]["documents"], value["counts"]["passages"], value["counts"]["heading_only"]) != (488, 4110, 537):
        raise DatasetError("design passage counts mismatch")
    if [value["counts"]["splits"][s]["queries"] for s in ("train", "validation")] != [21451, 4201]:
        raise DatasetError("design query counts mismatch")
    for name, sizes in expected.items():
        cohort = value["cohorts"][name]
        if (cohort["dialogues"], cohort["queries"]) != sizes:
            raise DatasetError(f"design cohort count mismatch: {name}")
        if name in COHORT_HASHES and cohort["sha256"] != COHORT_HASHES[name]:
            raise DatasetError(f"design cohort hash mismatch: {name}")
        if name == "g8_pool":
            if "query_ids" in cohort:
                raise DatasetError("design G8 query IDs must remain hash-only")
        else:
            questions = cohort.get("query_ids")
            if (not isinstance(questions, list) or len(questions) != sizes[1]
                    or any(not isinstance(q, str) for q in questions)
                    or questions != sorted(questions) or len(set(questions)) != len(questions)
                    or cohort.get("query_ids_sha256") != ids_hash(questions)):
                raise DatasetError(f"design cohort query IDs/hash mismatch: {name}")
    if value["cohorts"]["answers"]["by_act_group"] != {"responding": 1038, "clarification": 264}:
        raise DatasetError("design answer acts mismatch")


def default_manifest() -> Path:
    return Path(__file__).resolve().parents[3] / "manifests/multidoc2dial-v1/manifest.json"


def verify_manifest(actual: Mapping[str, Any], path: Path | None = None) -> None:
    verify_design(actual)
    expected = json.loads((path or default_manifest()).read_text(encoding="utf-8"))
    if canonical(actual) != canonical(expected):
        raise DatasetError("committed manifest mismatch")


def private_output(path: Path) -> Path:
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "")
    if not raw or not Path(raw).is_absolute():
        raise DatasetError("POLICYOPS_TEMP_DIR must be absolute")
    root = Path(raw).resolve()
    out = path.resolve()
    checkout = Path(__file__).resolve().parents[4]
    if (out in (root, checkout) or root not in out.parents or checkout in out.parents
            or root == checkout or checkout in root.parents):
        raise DatasetError("output must be below private temp root and outside repository")
    if out.exists():
        raise DatasetError("output must be a new directory")
    return out


def materialize(dataset: Dataset, value: Mapping[str, Any], out: Path) -> None:
    """Verify everything before creating output; exclusive files prevent overwrites."""
    out = private_output(out)
    if canonical(value) != canonical(manifest(dataset, value["tokenizer"]["identity_sha256"])):
        raise DatasetError("materialization derivation mismatch")
    verify_manifest(value)
    out.mkdir(parents=True)
    for name in MATERIALIZATION_FILES:
        with (out / name).open("xb") as handle:
            for line in jsonl(materialization_rows(dataset, name)):
                handle.write(line)
    (out / "manifest.json").write_bytes(canonical(value) + b"\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="verify pin and manifest, then write private JSONL")
    build.add_argument("--archive", type=Path, required=True)
    build.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        out = private_output(args.out)
        counter = tokenizer.load()
        dataset = build_dataset(read_archive(args.archive), counter.count)
        value = manifest(dataset, counter.identity_sha256)
        materialize(dataset, value, out)
    except (DatasetError, OSError, tokenizer.TokenizerUnavailable, tokenizer.InputRefused) as error:
        # Validation diagnostics contain no source text. OS errors can contain paths,
        # so expose only their class; do not print Pydantic's input-bearing errors.
        reason = type(error).__name__ if isinstance(error, OSError) else str(error)
        print(f"MultiDoc2Dial build refused: {reason}", file=sys.stderr)
        return 1
    print(json.dumps({"schema": SCHEMA, "passages": len(dataset.passages), "queries": len(dataset.queries),
                      "manifest_sha256": digest(canonical(value))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
