"""Runtime projection, split guard, rights scanning, token reporting and upstream comparison helpers."""

import argparse
from collections.abc import Callable, Iterator, Mapping
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

from pydantic import ValidationError
import pytest

from policyops_evals import cli, rights, upstream
from policyops_evals.build import BANKING_SPLIT, RETAIL_SPLIT, default_manifest_dir, load_committed
from policyops_evals.canonical import ManifestError
from policyops_evals.corpus import (
    DOCUMENT_SEPARATOR,
    OutputPathError,
    render_corpus,
    render_document,
    write_contained,
    write_extracted,
)
from policyops_evals.projection import (
    HiddenStateError,
    Purpose,
    RuntimeTaskView,
    SplitGuard,
    SplitViolation,
    project_task,
)
from policyops_evals.sources import SourceTree
from policyops_evals.upstream_runtime import compare_labels, package_parity, record_sha256


CANARY = "CANARY-7f3a-hidden"
HIDDEN = ("user_scenario", "evaluation_criteria", "required_documents", "user_tools", "description", "annotations",
          "issues")


class PoisonTask(Mapping[str, Any]):
    """Raises if projection touches anything but id and initial_state.message_history."""

    def __init__(self, task_id: str, initial: Mapping[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = {key: {"secret": CANARY} for key in HIDDEN}
        self._data.update(id=task_id, initial_state=initial)
        self.accessed: list[str] = []

    def __getitem__(self, key: str) -> Any:
        if key in HIDDEN:
            raise AssertionError(f"projection read hidden field {key}")
        self.accessed.append(key)
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("projection iterated the task record")

    def __len__(self) -> int:
        raise AssertionError("projection sized the task record")

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __repr__(self) -> str:
        raise AssertionError("projection rendered the task record")


class PoisonInitialState(PoisonTask):
    def __init__(self) -> None:
        super().__init__("unused")
        self._data = {"initialization_data": {"agent_data": CANARY}, "initialization_actions": [CANARY],
                      "message_history": None}

    def __getitem__(self, key: str) -> Any:
        if key != "message_history":
            raise AssertionError(f"projection read initial_state.{key}")
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self[key] if key in self._data else default


@pytest.fixture(scope="module")
def guard() -> SplitGuard:
    committed = load_committed(default_manifest_dir())
    return SplitGuard({"retail": committed[RETAIL_SPLIT], "banking_knowledge": committed[BANKING_SPLIT]})


@pytest.fixture(scope="module")
def splits() -> dict[str, dict[str, Any]]:
    committed = load_committed(default_manifest_dir())
    return {"retail": committed[RETAIL_SPLIT]["splits"], "banking_knowledge": committed[BANKING_SPLIT]["splits"]}


def test_projection_reads_only_allowlisted_fields(guard: SplitGuard, splits: dict[str, dict[str, Any]]) -> None:
    dev_id = splits["banking_knowledge"]["dev"]["task_ids"][0]
    task = PoisonTask(dev_id, PoisonInitialState())
    view = project_task(task, domain="banking_knowledge", guard=guard, purpose=Purpose.TUNING)
    assert task.accessed == ["id", "initial_state"]
    assert CANARY not in view.model_dump_json()
    assert set(RuntimeTaskView.model_fields) == {"schema_version", "domain", "task_id", "split", "purpose"}


def test_runtime_view_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        RuntimeTaskView.model_validate({"domain": "retail", "task_id": "1", "split": "dev",
                                        "purpose": Purpose.DEMO, "required_documents": ["x"]})


@pytest.mark.parametrize("purpose", [Purpose.DEMO, Purpose.SMOKE, Purpose.TUNING, Purpose.DEV_EVALUATION])
def test_no_holdout_task_serves_demos_or_tuning(guard: SplitGuard, splits: dict[str, dict[str, Any]],
                                                purpose: Purpose) -> None:
    for domain, held in (("retail", "holdout"), ("banking_knowledge", "test")):
        for task_id in splits[domain][held]["task_ids"]:
            with pytest.raises(SplitViolation):
                guard.require(domain, task_id, purpose)
        for task_id in splits[domain]["dev"]["task_ids"]:
            assert guard.require(domain, task_id, purpose) == "dev"


def test_holdout_evaluation_refuses_dev_and_unknown_tasks(guard: SplitGuard, splits: dict[str, dict[str, Any]]) -> None:
    with pytest.raises(SplitViolation):
        guard.require("retail", splits["retail"]["dev"]["task_ids"][0], Purpose.HOLDOUT_EVALUATION)
    with pytest.raises(SplitViolation):
        guard.require("retail", "999", Purpose.DEMO)
    assert guard.require("retail", splits["retail"]["holdout"]["task_ids"][0], Purpose.HOLDOUT_EVALUATION) == "holdout"


def test_prefilled_conversations_are_refused(guard: SplitGuard, splits: dict[str, dict[str, Any]]) -> None:
    task = {"id": splits["retail"]["dev"]["task_ids"][0], "initial_state": {"message_history": [{"role": "user"}]}}
    with pytest.raises(HiddenStateError):
        project_task(task, domain="retail", guard=guard, purpose=Purpose.DEMO)


def test_duplicate_membership_is_rejected() -> None:
    manifest = {"domain": "retail", "splits": {"dev": {"task_ids": ["1"]}, "holdout": {"task_ids": ["1"]}}}
    with pytest.raises(ValueError, match="more than one split"):
        SplitGuard({"retail": manifest})


def test_rights_scan_counts_markers_without_copying_text() -> None:
    result = rights.scan(b"Copyright (c) 2024 Someone. Licensed under the Apache License. mail me@example.org "
                         b"https://example.org")
    assert result["markers"] == {"copyright": 2, "license_word": 2, "named_license": 1, "url": 1, "email": 1}
    assert rights.scan(b"\0binary")["binary"] is True


@pytest.mark.parametrize("payload", [b"A" * 400_000, b"A" * 400_000 + b"@", b"A" * 200_000 + b"@" + b"B" * 200_000,
                                     b"(c) " * 100_000, b"x" * 400_000 + b"@a."])
def test_rights_scan_is_linear_on_adversarial_text(payload: bytes) -> None:
    started = time.perf_counter()
    rights.scan(payload)
    assert time.perf_counter() - started < 2.0


def test_unconsumed_files_get_bounded_header_scan_only() -> None:
    late = b"x" * (rights.HEADER_BYTES + 10) + b"Copyright 2020 Late Notice"
    inventory = {"files": [{"path": upstream.LICENSE, "sha256": "l"}, {"path": "web/a.js", "sha256": "a"},
                           {"path": "web/LICENSE.txt", "sha256": "b"}], "unmaterialized": []}
    audit = rights.build_rights_audit(inventory, [(upstream.LICENSE, b"MIT"), ("web/a.js", late),
                                                  ("web/LICENSE.txt", b"Copyright 2021 Other")])
    flagged = {item["path"] for item in audit["whole_tree"]["files_with_license_markers_other_than_root_license"]}
    assert flagged == {"web/LICENSE.txt"}
    assert audit["whole_tree"]["notice_like_file_names"] == [upstream.LICENSE, "web/LICENSE.txt"]
    assert audit["method"]["unconsumed_files_header_scanned"] == 2


class FakeCounter:
    name = "fake-words"

    def count(self, text: str) -> int:
        return len(text.split())


def test_document_rendering_matches_upstream_format() -> None:
    documents = {"b": {"id": "b", "title": "B", "content": "two"}, "a": {"id": "a", "title": "A", "content": "one"}}
    assert render_document(documents["a"]) == "## A\n\none"
    assert render_corpus(documents) == "## A\n\none" + DOCUMENT_SEPARATOR + "## B\n\ntwo"
    assert FakeCounter().count(render_corpus(documents)) == 7


def test_package_parity_hashes_actual_bytes() -> None:
    commit = {"src/tau2/a.py": "11", "src/tau2/b.py": "22"}
    assert package_parity([("tau2/a.py", "11", "11"), ("tau2/b.py", "22", "22")], commit)["installed_files_hashed"] == 2
    for entries in ([("tau2/a.py", "11", "99")],          # edited after install: RECORD still matches commit
                    [("tau2/a.py", "99", "99")],          # consistent wheel built from different bytes (e.g. CRLF)
                    [("tau2/c.py", "33", "33")],          # file not in the commit
                    [("tau2/a.py", None, "11")],          # no RECORD hash
                    []):
        with pytest.raises(ManifestError):
            package_parity(entries, commit)


def test_record_hash_decoding() -> None:
    assert record_sha256("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


def test_label_comparison_detects_swaps_that_preserve_global_counts() -> None:
    source = {"task_001": ["doc_a", "doc_b"], "task_002": ["doc_c"]}
    assert compare_labels(dict(source), source)["per_task_ordered_equal"]
    for loader in ({"task_001": ["doc_c"], "task_002": ["doc_a", "doc_b"]},
                   {"task_001": ["doc_b", "doc_a"], "task_002": ["doc_c"]},
                   {"task_002": ["doc_c"], "task_001": ["doc_a", "doc_b"]}):
        with pytest.raises(ManifestError):
            compare_labels(loader, source)


def test_cli_refuses_repository_paths_and_validates_committed_manifests(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["data", "verify", "--acquired", str(Path(__file__).parent)])
    assert cli.main(["data", "check-manifests"]) == 0
    assert json.loads(capsys.readouterr().out)["retail"]["holdout"] == 50


def directory_link(link: Path, target: Path) -> None:
    """A directory alias: a junction on Windows (no privilege needed), a symlink elsewhere."""
    # sys.platform (not os.name) lets mypy skip the Windows-only _winapi branch on other platforms.
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


@pytest.fixture
def corpus_tree(synthetic_tree: Callable[[dict[str, bytes]], SourceTree]) -> SourceTree:
    files = {f"{upstream.BANKING_DOCUMENTS_DIR}/doc_{i}.json": json.dumps(
        {"id": f"doc_{i}", "title": f"T{i}", "content": "c"}).encode() for i in range(3)}
    files[upstream.RETAIL_POLICY] = b"# Retail policy\n"
    return synthetic_tree(files)


def test_extracted_outputs_can_be_regenerated_in_place(corpus_tree: SourceTree, tmp_path: Path) -> None:
    out = tmp_path / "out"
    first = write_extracted(corpus_tree, out)
    assert write_extracted(corpus_tree, out) == first
    assert (out / "retail-policy.md").read_bytes() == b"# Retail policy\n"
    assert json.loads((out / "extracted-sha256.json").read_bytes()) == first
    assert sorted(path.name for path in (out / "banking").iterdir()) == ["doc_0.md", "doc_1.md", "doc_2.md"]


@pytest.mark.parametrize("aliased", ["root", "banking"])
def test_directory_aliases_are_refused_and_their_targets_untouched(corpus_tree: SourceTree, tmp_path: Path,
                                                                   aliased: str) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "sentinel.txt").write_bytes(b"SENTINEL")
    out = tmp_path / "out"
    if aliased == "root":
        directory_link(out, elsewhere)
    else:
        out.mkdir()
        directory_link(out / "banking", elsewhere)
    with pytest.raises(OutputPathError):
        write_extracted(corpus_tree, out)
    assert sorted(path.name for path in elsewhere.iterdir()) == ["sentinel.txt"]
    assert (elsewhere / "sentinel.txt").read_bytes() == b"SENTINEL"


def test_hardlinked_existing_output_is_replaced_not_written_through(corpus_tree: SourceTree, tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel.md"
    sentinel.write_bytes(b"SENTINEL")
    out = tmp_path / "out"
    out.mkdir()
    os.link(sentinel, out / "retail-policy.md")
    write_extracted(corpus_tree, out)
    assert sentinel.read_bytes() == b"SENTINEL"
    assert (out / "retail-policy.md").read_bytes() == b"# Retail policy\n"


def test_output_names_that_are_directories_are_refused(tmp_path: Path) -> None:
    (tmp_path / "out" / "banking-corpus.md").mkdir(parents=True)
    with pytest.raises(OutputPathError):
        write_contained(tmp_path / "out", "banking-corpus.md", b"x")
    with pytest.raises(ValueError):
        write_contained(tmp_path / "out", "../escape.md", b"x")


def test_cli_rejects_links_into_the_checkout_and_keeps_other_links_visible(tmp_path: Path) -> None:
    into_repo = tmp_path / "into-repo"
    directory_link(into_repo, Path(cli.__file__).parent)
    with pytest.raises(argparse.ArgumentTypeError):
        cli.outside_repository(str(into_repo))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    alias = tmp_path / "alias"
    directory_link(alias, elsewhere)
    assert cli.outside_repository(str(alias)) == alias.absolute()
