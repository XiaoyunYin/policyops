"""Fetch the pinned upstream commit and materialize its exact file bytes.

Live network use is limited to `git fetch` of one commit, run only by the explicit
`policyops-evals data fetch` command. Fetched content is untrusted data: no
checkout, hooks, filters, submodules or upstream code run. Objects are read from
the object store and verified by `gitobjects`; files are written byte-for-byte
(no line-ending conversion) below `<dest>/tree/`, with an inventory recording
each file's mode, size, Git blob ID and SHA-256.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import datetime
import json
import os
from pathlib import Path
import subprocess
from typing import IO, Any

from policyops_evals import gitobjects
from policyops_evals.canonical import ManifestError, canonical_bytes, sha256_bytes


INVENTORY = "inventory.json"
LOG = "acquisition-log.json"
# Raw body of the fetched commit object; verification re-hashes it to the pin.
COMMIT_OBJECT = "commit.object"
TREE_DIR = "tree"
GIT_DIR = "repo.git"
# Variables that could redirect git to another repository or configuration.
GIT_ENV_DROP = {
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_SSH", "GIT_SSH_COMMAND",
    "GIT_PROXY_COMMAND", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
}


class AcquisitionError(RuntimeError):
    """The fetched objects are not exactly the pinned commit."""


@dataclass
class GitRunner:
    """Run git against one bare repository with an isolated, minimal configuration."""

    git_dir: Path
    scratch: Path
    allow_file_protocol: bool = False
    executable: str = "git"
    log: list[dict[str, Any]] = field(default_factory=list)

    def environment(self) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items() if key not in GIT_ENV_DROP}
        empty = self.scratch / "empty-gitconfig"
        empty.touch()
        hooks = self.scratch / "no-hooks"
        hooks.mkdir(exist_ok=True)
        env.update(
            GIT_CONFIG_GLOBAL=str(empty), GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", SSH_ASKPASS="",
            GIT_LFS_SKIP_SMUDGE="1",
        )
        return env

    def options(self) -> list[str]:
        protocols = ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
        if self.allow_file_protocol:
            protocols += ["-c", "protocol.file.allow=always"]
        return [
            "-c", f"core.hooksPath={self.scratch / 'no-hooks'}", "-c", "core.autocrlf=false",
            "-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true", "-c", "submodule.recurse=false",
            *protocols, f"--git-dir={self.git_dir}",
        ]

    def run(self, *args: str, timeout: float = 600) -> str:
        command = [self.executable, *self.options(), *args]
        started = datetime.datetime.now(datetime.UTC)
        result = subprocess.run(
            command, env=self.environment(), capture_output=True, timeout=timeout, check=False,
        )
        self.log.append({
            "args": list(args), "exit_code": result.returncode,
            "started_utc": started.isoformat(timespec="seconds"),
            "stderr_tail": result.stderr.decode("utf-8", errors="replace")[-2000:],
        })
        if result.returncode != 0:
            raise AcquisitionError(f"git {args[0]} failed with exit code {result.returncode}")
        return result.stdout.decode("utf-8", errors="replace")


class BatchReader:
    """Read raw objects through one `git cat-file --batch` process."""

    def __init__(self, runner: GitRunner) -> None:
        self._process = subprocess.Popen(
            [runner.executable, *runner.options(), "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=runner.environment(),
        )

    def __call__(self, oid: str) -> tuple[str, bytes]:
        stdin: IO[bytes] | None = self._process.stdin
        stdout: IO[bytes] | None = self._process.stdout
        if stdin is None or stdout is None:
            raise AcquisitionError("git cat-file pipes are not available")
        stdin.write(oid.encode("ascii") + b"\n")
        stdin.flush()
        header = stdout.readline().decode("ascii").split()
        if len(header) != 3 or header[0] != oid:
            raise gitobjects.ObjectError(f"{oid}: object missing from the fetched store")
        body = stdout.read(int(header[2]))
        stdout.read(1)
        return header[1], body

    def close(self) -> None:
        if self._process.stdin:
            self._process.stdin.close()
        if self._process.stdout:
            self._process.stdout.close()
        self._process.wait(timeout=60)


def safe_target(root: Path, path: str) -> Path:
    for part in path.split("/"):
        gitobjects.check_component(part)
    target = root.joinpath(*path.split("/"))
    if root.resolve() not in target.resolve().parents:
        raise AcquisitionError(f"{path!r} escapes the materialization root")
    return target


def inventory_digest(files: Sequence[Mapping[str, Any]]) -> str:
    return sha256_bytes(canonical_bytes(list(files)))


def materialize(read: gitobjects.ReadObject, commit: str, expected_tree: str, root: Path) -> dict[str, Any]:
    """Verify commit -> tree -> blobs and write every regular file below root."""
    kind, body = read(commit)
    gitobjects.check_object(commit, kind, body, "commit")
    tree = gitobjects.commit_tree(body)
    if tree != expected_tree:
        raise AcquisitionError(f"commit {commit} has tree {tree}, expected {expected_tree}")
    entries = sorted(gitobjects.walk_tree(read, tree), key=lambda entry: entry.path)
    folded: dict[str, str] = {}
    for entry in entries:
        other = folded.setdefault(entry.path.casefold(), entry.path)
        if other != entry.path:
            raise AcquisitionError(f"paths {other!r} and {entry.path!r} collide on case-insensitive filesystems")
    files, unmaterialized = [], []
    for entry in entries:
        if entry.mode == gitobjects.GITLINK_MODE:
            unmaterialized.append({"path": entry.path, "mode": entry.mode, "oid": entry.oid, "reason": "submodule"})
            continue
        kind, blob = read(entry.oid)
        gitobjects.check_object(entry.oid, kind, blob, "blob")
        record = {"path": entry.path, "mode": entry.mode, "size": len(blob), "git_blob": entry.oid,
                  "sha256": sha256_bytes(blob)}
        files.append(record)
        if entry.mode == gitobjects.SYMLINK_MODE:
            unmaterialized.append({"path": entry.path, "mode": entry.mode, "oid": entry.oid, "reason": "symlink",
                                   "target_hex": blob.hex()})
            continue
        target = safe_target(root, entry.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(blob)
        if sha256_bytes(target.read_bytes()) != record["sha256"]:
            raise AcquisitionError(f"{entry.path}: written bytes differ from the verified blob")
    return {"commit": commit, "tree": tree, "files": files, "unmaterialized": unmaterialized,
            "inventory_sha256": inventory_digest(files), "commit_object": body}


def acquire(
    dest: Path, *, repository: str, commit: str, expected_tree: str, allow_file_protocol: bool = False,
) -> dict[str, Any]:
    """Fetch `commit` into a new directory and return the verified inventory."""
    if dest.exists() and any(dest.iterdir()):
        raise AcquisitionError(f"{dest} is not empty; acquire into a new directory")
    dest.mkdir(parents=True, exist_ok=True)
    scratch = dest / "git-scratch"
    scratch.mkdir()
    runner = GitRunner(dest / GIT_DIR, scratch, allow_file_protocol=allow_file_protocol)
    subprocess.run(["git", "init", "--quiet", "--bare", str(dest / GIT_DIR)], env=runner.environment(),
                   check=True, capture_output=True)
    runner.log.append({"args": ["init", "--bare"], "exit_code": 0})
    try:
        runner.run("fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", repository, commit)
        fetched = runner.run("rev-parse", "--verify", "FETCH_HEAD^{commit}").strip()
        if fetched != commit:
            raise AcquisitionError(f"FETCH_HEAD is {fetched}, expected {commit}")
        reader = BatchReader(runner)
        try:
            inventory = materialize(reader, commit, expected_tree, dest / TREE_DIR)
        finally:
            reader.close()
    finally:
        (dest / LOG).write_bytes(canonical_bytes({"repository": repository, "commit": commit, "git": runner.log}))
    (dest / COMMIT_OBJECT).write_bytes(inventory.pop("commit_object"))
    inventory["repository"] = repository
    (dest / INVENTORY).write_bytes(canonical_bytes(inventory))
    return inventory


def verify_materialized(dest: Path, *, commit: str, tree: str) -> dict[str, Any]:
    """Prove an acquisition is exactly `commit`, without trusting its inventory or any object store.

    The saved commit object must hash to `commit` and name `tree`. Every file is
    re-hashed (SHA-256 and Git blob ID from its actual bytes), the tree objects
    are rebuilt from those blob IDs and the inventory's modes, and the rebuilt
    root must equal `tree`. A file changed together with its recorded hashes
    therefore fails, because no consistent edit can preserve the root tree ID.
    Regular files must all be present; only symlinks (whose saved target bytes are
    re-hashed) and submodules may be unmaterialized, and that set is derived
    from entry modes, not trusted from the declaration.
    """
    commit_path = dest / COMMIT_OBJECT
    if not commit_path.is_file():
        raise ManifestError("acquisition has no saved commit object; fetch it again")
    body = commit_path.read_bytes()
    gitobjects.check_object(commit, "commit", body, "commit")
    if gitobjects.commit_tree(body) != tree:
        raise ManifestError("saved commit object does not name the pinned tree")
    inventory: dict[str, Any] = json.loads((dest / INVENTORY).read_bytes())
    if inventory.get("commit") != commit or inventory.get("tree") != tree:
        raise ManifestError("inventory does not describe the pinned commit/tree")
    if inventory_digest(inventory["files"]) != inventory["inventory_sha256"]:
        raise ManifestError("inventory digest does not match its file list")
    files = {item["path"]: item for item in inventory["files"]}
    if len(files) != len(inventory["files"]):
        raise ManifestError("inventory lists a path twice")
    # Only symlinks (recorded in files, target bytes saved) and submodules (not in
    # files) may be unmaterialized; the declaration must be exactly derivable.
    expected_skips = {path: item for path, item in files.items() if item["mode"] == gitobjects.SYMLINK_MODE}
    declared = {}
    for item in inventory["unmaterialized"]:
        if item["path"] in declared:
            raise ManifestError(f"{item['path']}: declared unmaterialized twice")
        declared[item["path"]] = item
        if item["mode"] == gitobjects.SYMLINK_MODE:
            listed = files.get(item["path"])
            target = bytes.fromhex(item.get("target_hex", ""))
            if (listed is None or listed["mode"] != item["mode"] or listed["git_blob"] != item["oid"]
                    or gitobjects.object_id("blob", target) != item["oid"] or sha256_bytes(target) != listed["sha256"]
                    or len(target) != listed["size"] or item.get("reason") != "symlink"):
                raise ManifestError(f"{item['path']}: symlink declaration does not verify")
        elif item["mode"] == gitobjects.GITLINK_MODE:
            if item["path"] in files or item.get("reason") != "submodule":
                raise ManifestError(f"{item['path']}: submodule declaration conflicts with the file list")
        else:
            raise ManifestError(f"{item['path']}: mode {item['mode']} may not be left unmaterialized")
    if {path for path, item in declared.items() if item["mode"] == gitobjects.SYMLINK_MODE} != set(expected_skips):
        raise ManifestError("unmaterialized declarations do not match the symlink entries")
    regular = {path: item for path, item in files.items() if item["mode"] in gitobjects.REGULAR_MODES}
    if len(regular) + len(expected_skips) != len(files):
        raise ManifestError("inventory contains an entry mode that cannot be materialized")
    root = dest / TREE_DIR
    present = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if present != set(regular):
        extra, missing = sorted(present - set(regular)), sorted(set(regular) - present)
        raise ManifestError(f"materialized tree differs: {len(extra)} extra, {len(missing)} missing files")
    entries = [(path, item["mode"], item["git_blob"]) for path, item in expected_skips.items()]
    for path, item in regular.items():
        data = safe_target(root, path).read_bytes()
        blob = gitobjects.object_id("blob", data)
        if sha256_bytes(data) != item["sha256"] or blob != item["git_blob"] or len(data) != item["size"]:
            raise ManifestError(f"{path}: content does not match the inventory")
        entries.append((path, item["mode"], blob))
    entries += [(item["path"], item["mode"], item["oid"]) for item in declared.values()
                if item["mode"] == gitobjects.GITLINK_MODE]
    if gitobjects.build_tree_id(entries) != tree:
        raise ManifestError("files do not rebuild the pinned root tree")
    return inventory
