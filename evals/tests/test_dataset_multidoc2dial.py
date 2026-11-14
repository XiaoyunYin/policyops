"""Synthetic corruption/derivation tests and opt-in exact pinned-archive rebuild."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from typing import Any
import zipfile

import pytest

from policyops.providers import tokenizer
from policyops_evals.datasets import multidoc2dial as m


def document(doc_id: str = "doc", *, domain: str = "d") -> dict[str, Any]:
    # A/body A, heading-only B, repeated A in a separate run, heading-only C.
    pieces = [("A", "A", "h1"), ("body", "A", "u"), ("B", "B", "h2"),
              ("again", "A", "u"), ("C", "C", "h3")]
    text = "".join(p[0] for p in pieces)
    spans = {}
    offset = 0
    for number, (body, title, tag) in enumerate(pieces, 1):
        spans[str(number)] = {"id_sp": str(number), "start_sp": offset, "end_sp": offset + len(body),
                              "text_sp": body, "title": title, "parent_titles": [{"text": "Root"}], "tag": tag}
        offset += len(body)
    return {"doc_id": doc_id, "domain": domain, "doc_text": text, "spans": spans}


def turn(number: int, role: str, utterance: str, *, act: str = "respond_solution",
         references: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {"turn_id": number, "role": role, "utterance": utterance, "da": act,
            "references": [] if references is None else references}


def members() -> dict[str, Any]:
    refs = [{"doc_id": "doc", "id_sp": s} for s in ("1", "2", "3", "1")]
    refs += [{"doc_id": "second", "id_sp": "4"}, {"domain": "e", "doc_id": "third", "id_sp": "5"}]
    turns = [turn(1, "user", "current question"), turn(2, "agent", "secret target", references=refs),
             turn(3, "user", "excluded question"), turn(4, "agent", "excluded target", act="respond_no_solution"),
             turn(5, "user", "clarification question"), turn(6, "agent", "clarify", act="query_condition")]
    return {m.DOC: {"doc_data": {"d": {"doc": document(), "second": document("second")},
                                "e": {"third": document("third", domain="e")}}},
            m.TRAIN: {"dial_data": {"d": [{"dial_id": "train-dialogue", "turns": turns}]}},
            m.VALIDATION: {"dial_data": {"d": [{"dial_id": "validation-dialogue", "turns": turns[:2]}]}}}


def archive(values: dict[str, Any] | None = None, *, extras: dict[str, bytes] | None = None,
            missing: str | None = None) -> tuple[bytes, m.ArchivePins]:
    bodies = {name: m.canonical(value) for name, value in (values or members()).items()}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, body in bodies.items():
            if name != missing:
                z.writestr(name, body)
        for name, body in (extras or {}).items():
            z.writestr(name, body)
    data = stream.getvalue()
    return data, m.ArchivePins(m.digest(data), len(data), {name: m.digest(body) for name, body in bodies.items()})


def synthetic(values: dict[str, Any] | None = None) -> m.Dataset:
    data, pins = archive(values)
    return m.build_dataset(m.read_archive(data, pins=pins), len)


def test_title_runs_and_stable_identity() -> None:
    dataset = synthetic()
    passages = [p for p in dataset.passages if p.document_id == "doc"]
    assert [p.body for p in passages] == ["Abody", "B", "again", "C"]
    assert [p.heading for p in passages] == ["Root > A", "Root > B", "Root > A", "Root > C"]
    assert [p.heading_only for p in passages] == [False, True, False, True]
    assert [p.run_ordinal for p in passages] == [1, 2, 3, 4]
    assert passages[0].passage_id != passages[2].passage_id
    assert passages[0].span_ids == ("1", "2")
    values = members()
    changed = values[m.DOC]["doc_data"]["d"]["doc"]
    changed["doc_text"] = changed["doc_text"].replace("body", "BODY")
    changed["spans"]["2"]["text_sp"] = "BODY"
    altered = next(p for p in synthetic(values).passages if p.document_id == "doc")
    assert altered.passage_id == passages[0].passage_id
    assert m.text_hash(altered.rendered) != m.text_hash(passages[0].rendered)


def test_qrels_union_across_spans_documents_and_domains() -> None:
    dataset = synthetic()
    query = dataset.queries[0]
    assert len(query.passage_ids) == 4
    assert query.passage_ids == tuple(sorted(set(query.passage_ids)))
    selected = [p for p in dataset.passages if p.passage_id in query.passage_ids]
    assert {(p.domain, p.document_id) for p in selected} == {("d", "doc"), ("d", "second"), ("e", "third")}
    assert query.reference_answer == "secret target"
    assert "secret target" not in query.retrieval
    assert "secret target" not in query.generation_history


def test_eligibility_retains_clarification_and_empty_qrels() -> None:
    dataset = synthetic()
    assert len([q for q in dataset.queries if q.split == "train"]) == 2
    assert dataset.excluded_no_solution == {"train": 1, "validation": 0}
    assert dataset.queries[1].target_act == "query_condition"
    assert dataset.queries[1].passage_ids == ()
    values = members()
    values[m.TRAIN]["dial_data"]["d"][0]["turns"] = [turn(1, "agent", "opening"), turn(2, "agent", "another")]
    assert not [q for q in synthetic(values).queries if q.split == "train"]


@pytest.mark.parametrize("location", ["eligible", "excluded", "user"])
def test_unknown_reference_is_fatal(location: str) -> None:
    values = members()
    turns = values[m.TRAIN]["dial_data"]["d"][0]["turns"]
    position = {"eligible": 1, "excluded": 3, "user": 0}[location]
    turns[position]["references"] = [{"doc_id": "missing", "id_sp": "1"}]
    with pytest.raises(m.DatasetError, match="unknown reference"):
        synthetic(values)


@pytest.mark.parametrize("change", ["slice", "overlap", "gap", "identity"])
def test_invalid_spans_refused(change: str) -> None:
    values = members()
    doc = values[m.DOC]["doc_data"]["d"]["doc"]
    if change == "slice":
        doc["spans"]["1"]["text_sp"] = "wrong"
    elif change == "overlap":
        doc["spans"]["2"].update(start_sp=0, text_sp="Abody")
    elif change == "gap":
        doc["spans"]["2"].update(start_sp=2, text_sp="ody")
    else:
        doc["spans"]["2"]["id_sp"] = "10"
    with pytest.raises(m.DatasetError):
        synthetic(values)


def test_query_rendering_and_oldest_first_truncation() -> None:
    turns = [m.Turn.model_validate(turn(i, "user" if i % 2 else "agent", f"text{i}")) for i in range(1, 8)]
    retrieval, generation, last, ids, dropped = m.render_query(turns, len)
    assert retrieval == "user: text7 [SEP] agent: text6 [SEP] user: text5 [SEP] agent: text4 [SEP] user: text3"
    assert generation == "user: text3 [SEP] agent: text4 [SEP] user: text5 [SEP] agent: text6 [SEP] user: text7"
    assert last == "user: text7"
    assert ids == (3, 4, 5, 6, 7)
    assert dropped == 0
    bounded = m.render_query(turns, len, limit=len("user: text7 [SEP] agent: text6"))
    assert bounded == ("user: text7 [SEP] agent: text6", "agent: text6 [SEP] user: text7", last, (6, 7), 3)
    with pytest.raises(m.DatasetError, match="current user"):
        m.render_query(turns, len, limit=len(last) - 1)
    with pytest.raises(m.DatasetError):
        m.render_query(turns[:-1], len)


def test_hash_ranking_and_audits_are_deterministic() -> None:
    keys = ["d/a", "e/a", "d/b"]
    expected = sorted(keys, key=lambda k: (m.text_hash("g0/v1|20261114|" + k.replace("/", "|")), k))
    assert m.rank_dialogues(keys) == m.rank_dialogues(keys[::-1]) == expected
    assert m.ids_hash(keys) == m.text_hash("d/a\nd/b\ne/a\n")
    dataset = synthetic()
    # Put the identical train question into the G8 pool, not the dev partition.
    result = m.audit(dataset, {"dev": []})
    assert dataset.queries[0].query_id in result["g8_excluded_query_ids"]
    assert result["query_duplicates"]["last_turn"]
    assert result["passage_duplicates"]["body"]
    assert "current question" not in json.dumps(result)
    assert result == m.audit(dataset, {"dev": []})


def test_last_turn_leakage_excluded_but_shared_corpus_permitted() -> None:
    dataset = synthetic()
    train = dataset.queries[0]
    validation = replace(dataset.queries[-1], retrieval="different history", last_turn=train.last_turn)
    sample = replace(dataset, queries=(train, validation))
    result = m.audit(sample, {"dev": []})
    assert result["query_duplicates"]["retrieval"] == []
    assert result["g8_excluded_query_ids"] == [train.query_id]
    sample = replace(sample, queries=(train, replace(validation, last_turn="different user")))
    result = m.audit(sample, {"dev": []})
    assert result["g8_excluded_query_ids"] == []
    assert result["passage_duplicates"]["rendered"]


def test_archive_and_member_pins() -> None:
    data, pins = archive()
    assert set(m.read_archive(data, pins=pins)) == set(m.MEMBER_SHA256)
    with pytest.raises(m.DatasetError, match="archive pin"):
        m.read_archive(data)
    changed = dict(pins.members)
    changed[m.DOC] = "0" * 64
    with pytest.raises(m.DatasetError, match="member pin"):
        m.read_archive(data, pins=replace(pins, members=changed))
    data, pins = archive(missing=m.TRAIN)
    with pytest.raises(m.DatasetError, match="missing"):
        m.read_archive(data, pins=pins)


@pytest.mark.parametrize("path", ["../escape", "/absolute", "C:/absolute", "a\\escape", "a/./b", "a//b",
                                  "__MACOSX/../escape", "unlisted.json"])
def test_traversal_and_allowlist(path: str) -> None:
    data, pins = archive(extras={path: b"x"})
    with pytest.raises(m.DatasetError):
        m.read_archive(data, pins=pins)


def test_macos_resource_forks_ignored() -> None:
    data, pins = archive(extras={"__MACOSX/ignored": b"not JSON or executable code"})
    assert set(m.read_archive(data, pins=pins)) == set(m.MEMBER_SHA256)


def test_malformed_zip_and_json() -> None:
    data = b"not a zip"
    with pytest.raises(m.DatasetError, match="malformed"):
        m.read_archive(data, pins=m.ArchivePins(m.digest(data), len(data), m.MEMBER_SHA256))
    for body in (b"{", b'{"doc_data":{},"doc_data":{}}'):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as z:
            z.writestr(m.DOC, body)
        data = stream.getvalue()
        with pytest.raises(m.DatasetError):
            m.read_archive(data, pins=m.ArchivePins(m.digest(data), len(data), {m.DOC: m.digest(body)}))


def test_archive_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    data, pins = archive()
    with monkeypatch.context() as patch:
        patch.setattr(m, "MAX_ARCHIVE_BYTES", len(data) - 1)
        with pytest.raises(m.DatasetError, match="archive size"):
            m.read_archive(data, pins=pins)
    for bound in ("MAX_MEMBER_BYTES", "MAX_TOTAL_BYTES", "MAX_MEMBERS"):
        with monkeypatch.context() as patch:
            patch.setattr(m, bound, 1)
            with pytest.raises(m.DatasetError, match="limit"):
                m.read_archive(data, pins=pins)
    data, pins = archive(extras={"__MACOSX/bomb": b"0" * 100_000})
    with pytest.raises(m.DatasetError, match="size limit"):
        m.read_archive(data, pins=pins)


def test_symlink_and_duplicate_zip_members_refused() -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        entry = zipfile.ZipInfo("__MACOSX/link")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(entry, b"outside")
    data = stream.getvalue()
    with pytest.raises(m.DatasetError, match="nonregular"):
        m.read_archive(data, pins=m.ArchivePins(m.digest(data), len(data), m.MEMBER_SHA256))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        z.writestr(m.DOC, b"{}")
        with pytest.warns(UserWarning, match="Duplicate"):
            z.writestr(m.DOC, b"{}")
    data = stream.getvalue()
    with pytest.raises(m.DatasetError, match="duplicate archive"):
        m.read_archive(data, pins=m.ArchivePins(m.digest(data), len(data), {m.DOC: m.digest(b"{}")}))


def test_private_output_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    assert m.private_output(tmp_path / "new") == (tmp_path / "new").resolve()
    for invalid in (tmp_path, tmp_path.parent / "elsewhere", m.default_manifest().parent / "raw"):
        with pytest.raises(m.DatasetError):
            m.private_output(invalid)
    (tmp_path / "existing").mkdir()
    with pytest.raises(m.DatasetError):
        m.private_output(tmp_path / "existing")
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(m.default_manifest().parents[3]))
    with pytest.raises(m.DatasetError):
        m.private_output(m.default_manifest().parent / "new")


def test_public_projection_has_no_text_or_answers() -> None:
    dataset = synthetic()
    value = m.manifest(dataset, "synthetic-tokenizer")
    encoded = m.canonical(value)
    for q in dataset.queries:
        assert q.reference_answer.encode() not in encoded
        assert q.retrieval.encode() not in encoded
    assert b"Root > A" not in encoded
    assert b"Abody" not in encoded
    assert "passages" not in value
    assert "qrels" not in value
    for name, cohort in value["cohorts"].items():
        assert ("query_ids" in cohort) == (name != "g8_pool")
        assert ("dialogue_ids" in cohort) == (name != "g8_pool")
        if name != "g8_pool":
            assert cohort["dialogue_ids"] == sorted(cohort["dialogue_ids"])
            assert cohort["query_ids"] == sorted(cohort["query_ids"])
            assert len(cohort["query_ids"]) == cohort["queries"]
            assert cohort["query_ids_sha256"] == m.ids_hash(cohort["query_ids"])
    assert "g8_excluded_query_ids" not in value["audits"]
    assert len(encoded) < 300_000
    with pytest.raises(m.DatasetError, match="design"):
        m.verify_design(value)


@pytest.mark.parametrize("corruption", ["hash", "query", "order", "missing", "duplicate", "g8"])
def test_design_rejects_corrupt_public_query_ids(corruption: str) -> None:
    value = deepcopy(json.loads(m.default_manifest().read_bytes()))
    cohort = value["cohorts"]["dev"]
    if corruption == "hash":
        cohort["query_ids_sha256"] = "0" * 64
    elif corruption == "query":
        cohort["query_ids"][-1] += "-changed"
    elif corruption == "order":
        cohort["query_ids"].reverse()
    elif corruption == "missing":
        del cohort["query_ids"]
    elif corruption == "duplicate":
        cohort["query_ids"][0] = cohort["query_ids"][1]
        cohort["query_ids_sha256"] = m.ids_hash(cohort["query_ids"])
    else:
        value["cohorts"]["g8_pool"]["query_ids"] = []
    with pytest.raises(m.DatasetError, match="query IDs"):
        m.verify_design(value)


def test_hashes_bind_changed_passages_qrels_inputs_and_answers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dataset = synthetic()
    original = m.manifest(dataset, "synthetic")
    passage = dataset.passages[0]
    changed = replace(dataset, passages=(replace(passage, span_ids=("changed",)), *dataset.passages[1:]))
    changed_hash = m.manifest(changed, "synthetic")["derivations"]["passages_sha256"]
    assert changed_hash != original["derivations"]["passages_sha256"]
    query = dataset.queries[0]
    for changed_query, file in ((replace(query, passage_ids=()), "references.jsonl"),
                                (replace(query, reference_answer="changed"), "references.jsonl"),
                                (replace(query, retrieval="changed"), "queries.jsonl")):
        changed = replace(dataset, queries=(changed_query, *dataset.queries[1:]))
        actual = m.manifest(changed, "synthetic")
        assert actual["materialization_sha256"][file] != original["materialization_sha256"][file]
        if changed_query.passage_ids != query.passage_ids:
            assert actual["derivations"]["qrels_sha256"] != original["derivations"]["qrels_sha256"]
        monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
        with pytest.raises(m.DatasetError, match="derivation mismatch"):
            m.materialize(changed, original, tmp_path / "must-not-exist")
        assert not (tmp_path / "must-not-exist").exists()


def test_failed_verification_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    dataset = synthetic()
    out = tmp_path / "must-not-exist"
    with pytest.raises(m.DatasetError, match="design"):
        m.materialize(dataset, m.manifest(dataset, "synthetic"), out)
    assert not out.exists()


@pytest.mark.skipif(not os.environ.get("POLICYOPS_MD2D_ARCHIVE"), reason="set POLICYOPS_MD2D_ARCHIVE for pinned ZIP")
def test_real_pinned_archive_matches_every_manifest_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    counter = tokenizer.load()
    dataset = m.build_dataset(m.read_archive(Path(os.environ["POLICYOPS_MD2D_ARCHIVE"])), counter.count)
    value = m.manifest(dataset, counter.identity_sha256)
    m.verify_manifest(value)
    assert len(dataset.passages) == 4110
    assert sum(p.heading_only for p in dataset.passages) == 537
    assert max(counter.count(q.retrieval) for q in dataset.queries) <= 1024
    assert value["cohorts"]["answers"]["by_act_group"] == {"responding": 1038, "clarification": 264}
    assert value["counts"]["g8_after_duplicate_exclusions"]["queries"] == 19238
    for name, expected in m.COHORT_HASHES.items():
        assert value["cohorts"][name]["sha256"] == expected
    public_bytes = m.default_manifest().read_bytes()
    assert public_bytes == m.canonical(value) + b"\n"
    assert len(public_bytes) < 1_000_000
    assert len(public_bytes) <= 300_000
    assert "passages" not in value and "qrels" not in value
    assert "dialogue_ids" not in value["cohorts"]["g8_pool"]
    assert "query_ids" not in value["cohorts"]["g8_pool"]
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    out = tmp_path / "rebuilt"
    m.materialize(dataset, value, out)
    for file, expected in value["materialization_sha256"].items():
        assert hashlib.sha256((out / file).read_bytes()).hexdigest() == expected
    references = [json.loads(line) for line in (out / "references.jsonl").read_bytes().splitlines()]
    qrels = b"".join(m.canonical({"query_id": row["query_id"], "passage_ids": sorted(row["passage_ids"])}) + b"\n"
                     for row in sorted(references, key=lambda row: row["query_id"]))
    assert hashlib.sha256(qrels).hexdigest() == value["derivations"]["qrels_sha256"]
    passages = [json.loads(line) for line in (out / "passages.jsonl").read_bytes().splitlines()]
    passage_records = []
    for row in sorted(passages, key=lambda row: row["passage_id"]):
        record = {key: val for key, val in row.items() if key not in {"body", "heading"}}
        for field, text in (("body", row["body"]), ("heading", row["heading"]),
                            ("rendered", row["heading"] + "\n\n" + row["body"])):
            record[field + "_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        passage_records.append(record)
    assert hashlib.sha256(m.canonical(passage_records)).hexdigest() == value["derivations"]["passages_sha256"]
    selected = m.cohorts(dataset)
    for name, keys in selected.items():
        split = "train" if name in {"dev", "g8_pool"} else "validation"
        ids = sorted(q.query_id for q in dataset.queries if q.split == split and q.dialogue_key in keys)
        expected_hash = hashlib.sha256("".join(i + "\n" for i in ids).encode()).hexdigest()
        assert expected_hash == value["cohorts"][name]["query_ids_sha256"]
        if name != "g8_pool":
            assert value["cohorts"][name]["query_ids"] == ids
    audit = m.audit(dataset, selected)
    excluded = audit["g8_excluded_query_ids"]
    assert value["audits"]["g8_excluded_queries"] == len(excluded) == 1713
    expected_hash = hashlib.sha256("".join(i + "\n" for i in sorted(excluded)).encode()).hexdigest()
    assert expected_hash == value["audits"]["g8_excluded_query_ids_sha256"]
    # Each public hash must be checked, including hashes outside the design's count checks.
    hash_records = [value["derivations"], value["materialization_sha256"],
                    *value["cohorts"].values(), value["audits"]]
    hash_records += [record for kind in ("query_duplicates", "passage_duplicates")
                     for record in value["audits"][kind].values()]
    for record in hash_records:
        for key in record:
            if "sha256" in key or record is value["materialization_sha256"]:
                with monkeypatch.context() as patch:
                    patch.setitem(record, key, "0" * 64)
                    with pytest.raises(m.DatasetError, match="mismatch"):
                        m.verify_manifest(value)
