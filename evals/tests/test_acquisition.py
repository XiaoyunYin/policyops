"""Git object verification and byte-exact acquisition from a local repository (no network)."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Any

import pytest

from policyops_evals import gitobjects
from policyops_evals.acquire import AcquisitionError, acquire, inventory_digest, materialize, verify_materialized
from policyops_evals.canonical import ManifestError, canonical_bytes, sha256_bytes


def git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(cwd / ".no-global"), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}
    result = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, check=True, text=True)
    return result.stdout.strip()


@pytest.fixture
def upstream_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "upstream"
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "core.autocrlf", "false")
    git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    (repo / "data" / "docs").mkdir(parents=True)
    (repo / "LICENSE").write_bytes(b"MIT\n")
    (repo / "data" / "lf.txt").write_bytes(b"line one\nline two\n")
    (repo / "data" / "crlf.txt").write_bytes(b"line one\r\nline two\r\n")
    (repo / "data" / "docs" / "a (1).json").write_bytes(b'{"id": "a"}')
    git(repo, "add", "-A")
    # A symlink entry without needing symlink privileges on Windows.
    target = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, input=b"lf.txt",
                            capture_output=True, check=True).stdout.decode().strip()
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{target},data/link")
    git(repo, "commit", "--quiet", "-m", "fixture")
    commit = git(repo, "rev-parse", "HEAD")
    return repo, commit, git(repo, "rev-parse", "HEAD^{tree}")


def test_object_id_matches_git() -> None:
    assert gitobjects.object_id("blob", b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert gitobjects.object_id("blob", b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_acquisition_is_byte_exact_and_reproducible(tmp_path: Path, upstream_repo: tuple[Path, str, str]) -> None:
    repo, commit, tree = upstream_repo
    url = repo.resolve().as_uri()
    first = acquire(tmp_path / "a", repository=url, commit=commit, expected_tree=tree, allow_file_protocol=True)
    second = acquire(tmp_path / "b", repository=url, commit=commit, expected_tree=tree, allow_file_protocol=True)
    assert first["inventory_sha256"] == second["inventory_sha256"]
    assert (tmp_path / "a" / "tree" / "data" / "crlf.txt").read_bytes() == b"line one\r\nline two\r\n"
    assert (tmp_path / "a" / "tree" / "data" / "lf.txt").read_bytes() == b"line one\nline two\n"
    assert verify_materialized(tmp_path / "a", commit=commit, tree=tree)["commit"] == commit


def test_file_protocol_is_refused_by_default(tmp_path: Path, upstream_repo: tuple[Path, str, str]) -> None:
    repo, commit, tree = upstream_repo
    with pytest.raises(AcquisitionError):
        acquire(tmp_path / "a", repository=repo.resolve().as_uri(), commit=commit, expected_tree=tree)


def test_wrong_tree_and_non_empty_destination_are_refused(tmp_path: Path,
                                                          upstream_repo: tuple[Path, str, str]) -> None:
    repo, commit, _ = upstream_repo
    with pytest.raises(AcquisitionError, match="expected"):
        acquire(tmp_path / "a", repository=repo.resolve().as_uri(), commit=commit, expected_tree="0" * 40,
                allow_file_protocol=True)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "x").write_text("x", encoding="utf-8")
    with pytest.raises(AcquisitionError, match="not empty"):
        acquire(occupied, repository=repo.resolve().as_uri(), commit=commit, expected_tree="0" * 40)


@pytest.mark.parametrize("mutation", ["modify", "extra", "missing"])
def test_materialized_tree_tampering_is_detected(tmp_path: Path, upstream_repo: tuple[Path, str, str],
                                                 mutation: str) -> None:
    repo, commit, tree = upstream_repo
    acquire(tmp_path / "a", repository=repo.resolve().as_uri(), commit=commit, expected_tree=tree,
            allow_file_protocol=True)
    root = tmp_path / "a" / "tree" / "data"
    if mutation == "modify":
        (root / "lf.txt").write_bytes(b"line one\r\nline two\r\n")
    elif mutation == "extra":
        (root / "docs" / "injected.json").write_bytes(b"{}")
    else:
        (root / "docs" / "a (1).json").unlink()
    with pytest.raises(ManifestError):
        verify_materialized(tmp_path / "a", commit=commit, tree=tree)


def forge_consistently(dest: Path, path: str, data: bytes) -> None:
    """Replace one file and rewrite its inventory entry and digest so the inventory is self-consistent."""
    inventory = json.loads((dest / "inventory.json").read_bytes())
    (dest / "tree").joinpath(*path.split("/")).write_bytes(data)
    for item in inventory["files"]:
        if item["path"] == path:
            item.update(size=len(data), sha256=sha256_bytes(data), git_blob=gitobjects.object_id("blob", data))
    inventory["inventory_sha256"] = inventory_digest(inventory["files"])
    (dest / "inventory.json").write_bytes(canonical_bytes(inventory))


def test_coherently_forged_inventory_cannot_claim_the_pin(tmp_path: Path, upstream_repo: tuple[Path, str, str]) -> None:
    repo, commit, tree = upstream_repo
    dest = tmp_path / "a"
    acquire(dest, repository=repo.resolve().as_uri(), commit=commit, expected_tree=tree, allow_file_protocol=True)
    # Git writes read-only pack files; clear the bit so Windows can delete them.
    def writable_then_remove(remove: Any, path: str, _: object) -> None:
        Path(path).chmod(stat.S_IWRITE)
        remove(path)

    shutil.rmtree(dest / "repo.git", onexc=writable_then_remove)
    verify_materialized(dest, commit=commit, tree=tree)  # no object store needed for an honest tree
    forge_consistently(dest, "data/docs/a (1).json", b'{"id": "forged"}')
    with pytest.raises(ManifestError, match="root tree"):
        verify_materialized(dest, commit=commit, tree=tree)


@pytest.mark.parametrize("damage", ["missing", "altered", "other-tree"])
def test_commit_object_must_hash_to_the_pin(tmp_path: Path, upstream_repo: tuple[Path, str, str], damage: str) -> None:
    repo, commit, tree = upstream_repo
    dest = tmp_path / "a"
    acquire(dest, repository=repo.resolve().as_uri(), commit=commit, expected_tree=tree, allow_file_protocol=True)
    if damage == "missing":
        (dest / "commit.object").unlink()
    elif damage == "altered":
        (dest / "commit.object").write_bytes((dest / "commit.object").read_bytes() + b"x")
    with pytest.raises((ManifestError, gitobjects.ObjectError)):
        verify_materialized(dest, commit=commit, tree="1" * 40 if damage == "other-tree" else tree)


def test_tree_rebuild_matches_git_ordering() -> None:
    blob = gitobjects.object_id("blob", b"x")
    # "a.b" sorts before the subtree "a" (compared as "a/"), and "a-" before both.
    entries = [("a/x", "100644", blob), ("a.b", "100644", blob), ("a-", "100755", blob)]
    sub = gitobjects.object_id("tree", b"100644 x\0" + bytes.fromhex(blob))
    expected = gitobjects.object_id("tree", b"".join(
        f"{mode} {name}".encode() + b"\0" + bytes.fromhex(oid)
        for mode, name, oid in [("100755", "a-", blob), ("100644", "a.b", blob), ("40000", "a", sub)]))
    assert gitobjects.build_tree_id(entries) == expected


def fake_store(objects: dict[str, tuple[str, bytes]]) -> gitobjects.ReadObject:
    def read(oid: str) -> tuple[str, bytes]:
        return objects[oid]
    return read


def tree_body(entries: list[tuple[str, str, str]]) -> bytes:
    return b"".join(f"{mode} {name}".encode() + b"\0" + bytes.fromhex(oid) for mode, name, oid in entries)


def store_with(name: str, blob: bytes, tamper: bytes | None = None) -> tuple[dict[str, tuple[str, bytes]], str, str]:
    blob_id = gitobjects.object_id("blob", blob)
    tree = tree_body([("100644", name, blob_id)])
    tree_id = gitobjects.object_id("tree", tree)
    commit = f"tree {tree_id}\nauthor x\n\nmsg\n".encode()
    commit_id = gitobjects.object_id("commit", commit)
    objects = {blob_id: ("blob", tamper if tamper is not None else blob), tree_id: ("tree", tree),
               commit_id: ("commit", commit)}
    return objects, commit_id, tree_id


def test_substituted_blob_is_rejected(tmp_path: Path) -> None:
    objects, commit, tree = store_with("a.txt", b"original", tamper=b"substituted")
    with pytest.raises(gitobjects.ObjectError, match="does not hash"):
        materialize(fake_store(objects), commit, tree, tmp_path / "out")


@pytest.mark.parametrize("name", ["..", "CON", "nul.txt", "a:b", "trailing.", ".git", "a\\b"])
def test_unsafe_path_components_are_rejected(tmp_path: Path, name: str) -> None:
    objects, commit, tree = store_with(name, b"x")
    with pytest.raises(gitobjects.ObjectError, match="unsafe"):
        materialize(fake_store(objects), commit, tree, tmp_path / "out")


def test_case_insensitive_collisions_are_rejected(tmp_path: Path) -> None:
    blob_id = gitobjects.object_id("blob", b"x")
    tree = tree_body([("100644", "A.txt", blob_id), ("100644", "a.txt", blob_id)])
    tree_id = gitobjects.object_id("tree", tree)
    commit = f"tree {tree_id}\n\nmsg\n".encode()
    commit_id = gitobjects.object_id("commit", commit)
    objects = {blob_id: ("blob", b"x"), tree_id: ("tree", tree), commit_id: ("commit", commit)}
    with pytest.raises(AcquisitionError, match="collide"):
        materialize(fake_store(objects), commit_id, tree_id, tmp_path / "out")


def edit_inventory(dest: Path, edit: Any) -> None:
    inventory = json.loads((dest / "inventory.json").read_bytes())
    edit(inventory)
    inventory["inventory_sha256"] = inventory_digest(inventory["files"])
    (dest / "inventory.json").write_bytes(canonical_bytes(inventory))


def regular_declared_as_symlink(inventory: dict[str, Any]) -> None:
    item = next(item for item in inventory["files"] if item["path"] == "data/lf.txt")
    item.update(sha256="0" * 64)
    inventory["unmaterialized"].append({"path": item["path"], "mode": "100644", "oid": item["git_blob"],
                                        "reason": "symlink"})


def regular_relabelled_symlink(inventory: dict[str, Any]) -> None:
    item = next(item for item in inventory["files"] if item["path"] == "data/lf.txt")
    inventory["unmaterialized"].append({"path": item["path"], "mode": "120000", "oid": item["git_blob"],
                                        "reason": "symlink", "target_hex": ""})


def symlink_hash_forged(inventory: dict[str, Any]) -> None:
    next(item for item in inventory["files"] if item["path"] == "data/link")["sha256"] = "0" * 64


def symlink_declaration_dropped(inventory: dict[str, Any]) -> None:
    inventory["unmaterialized"] = []


def duplicate_declaration(inventory: dict[str, Any]) -> None:
    inventory["unmaterialized"].append(dict(inventory["unmaterialized"][0]))


@pytest.mark.parametrize("edit", [regular_declared_as_symlink, regular_relabelled_symlink, symlink_hash_forged,
                                  symlink_declaration_dropped, duplicate_declaration])
def test_unmaterialized_declarations_are_derived_from_modes(tmp_path: Path, upstream_repo: tuple[Path, str, str],
                                                            edit: Any) -> None:
    repo, commit, tree = upstream_repo
    dest = tmp_path / "a"
    acquire(dest, repository=repo.resolve().as_uri(), commit=commit, expected_tree=tree, allow_file_protocol=True)
    assert not (dest / "tree" / "data" / "link").exists()
    verify_materialized(dest, commit=commit, tree=tree)
    if edit in (regular_declared_as_symlink, regular_relabelled_symlink):
        (dest / "tree" / "data" / "lf.txt").unlink()  # the regular file is genuinely missing
    edit_inventory(dest, edit)
    with pytest.raises(ManifestError):
        verify_materialized(dest, commit=commit, tree=tree)
