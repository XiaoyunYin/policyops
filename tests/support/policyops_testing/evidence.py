"""Evidence recorder: contained artifacts, redacted command capture, failure inclusion and re-verification.

Every artifact lives below the recorder's root, itself below POLICYOPS_TEMP_DIR. The root is checked before
anything is created, and created one component at a time without following links. The identity (device and
inode/file ID) of every directory from POLICYOPS_TEMP_DIR down to the root is frozen at construction and re-checked
before every read, write and parent creation, so a root or ancestor later replaced by a link or another directory
is refused. (A replacement racing between that check and the write itself is not prevented.) Paths are relative POSIX
paths; absolute, traversal and link-escaping paths (symlinks or Windows junctions on any component) are refused.
Files are written through a fresh, exclusively created temporary file in the verified directory and then renamed,
so a pre-planted link is never written through.

Secrets: command output is redacted before it is persisted, using the credential patterns, registered values and
the values of secret-named flags in that command's argv (and of secret-named variables in an explicitly supplied
`env`). Any other artifact that contains such a value or pattern is refused (raw data is never silently altered),
and `finish()` re-checks every artifact against the values known by then. Unknown secret formats can still pass.

A non-zero
exit, a timeout or a failure to start the command automatically adds a failure record, so failures cannot be
silently dropped. `finish()` re-hashes every artifact and refuses to write the manifest if any changed after it
was recorded.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
from typing import Any

from policyops_contracts.clock import Clock, SystemClock
from policyops_contracts.evidence import ArtifactRole, CodeIdentity, EvidenceManifest
from policyops_testing import redaction


VOLATILE = ("run_id", "started_at", "finished_at")
TIMEOUT_EXIT = -1  # recorded exit code of a timed-out command; the failure kind says which it was
LAUNCH_ERROR_EXIT = -2  # the command could not be started (missing executable, permission, bad argv)


class EvidenceError(ValueError):
    """An artifact path escapes the root, is a link, or changed after it was recorded."""


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    """Write `data` to `path` via an exclusively created temporary sibling (never an existing file or link)."""
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        Path(temporary).replace(path)  # replaces a directory entry; does not follow a link at `path`
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _directory_identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    return info.st_dev, info.st_ino


Chain = tuple[tuple[Path, tuple[int, int]], ...]


def _contained_root(root: Path) -> tuple[Path, Chain]:
    """Create `root` below POLICYOPS_TEMP_DIR, refusing outside paths and links before creating anything.

    Returns the root and the identities of every directory from POLICYOPS_TEMP_DIR down to it.
    """
    # abspath is lexical on purpose: resolve() would follow the links this function must refuse.
    configured = Path(os.path.abspath(os.environ["POLICYOPS_TEMP_DIR"]))  # noqa: PTH100
    temp_root = configured.resolve()
    if not temp_root.is_dir():
        raise EvidenceError("POLICYOPS_TEMP_DIR is not an existing directory")
    candidate = Path(os.path.abspath(root))  # noqa: PTH100 - normalizes "..", so traversal is caught here
    for base in (configured, temp_root):
        if candidate == base or base in candidate.parents:
            parts = candidate.relative_to(base).parts
            break
    else:
        raise EvidenceError(f"{root} is not below POLICYOPS_TEMP_DIR")
    current = temp_root
    chain = [(temp_root, _directory_identity(temp_root))]
    for part in parts:
        current = current / part
        if _is_link(current):
            raise EvidenceError(f"{current} is a link")
        if not current.exists():
            current.mkdir()
        if _is_link(current) or not current.is_dir():
            raise EvidenceError(f"{current} is not a directory")
        chain.append((current, _directory_identity(current)))
    if current.resolve() != current:
        raise EvidenceError(f"{root} does not resolve to itself below POLICYOPS_TEMP_DIR")
    return current, tuple(chain)


def git_identity(repository: Path) -> CodeIdentity:
    """HEAD commit and tree; the digest of `git diff --binary HEAD` when tracked files differ (untracked files are
    not included)."""
    def git(*args: str) -> bytes:
        return subprocess.run(["git", "-C", str(repository), *args], capture_output=True, check=True).stdout

    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    patch = git("diff", "--binary", "HEAD")
    return CodeIdentity(git_head=head, git_tree=tree,
                        dirty_patch_sha256=hashlib.sha256(patch).hexdigest() if patch else None)


class EvidenceRecorder:
    def __init__(self, root: Path, *, run_id: str, task_id: str, purpose: str, seed: int | None = None,
                 clock: Clock | None = None) -> None:
        self.root, self._chain = _contained_root(root)
        self._clock = clock or SystemClock()
        self._identity = {"run_id": run_id, "task_id": task_id, "purpose": purpose, "seed": seed}
        self._started = self._clock.now()
        self._artifacts: dict[str, dict[str, Any]] = {}
        self._commands: list[dict[str, Any]] = []
        self._failures: list[dict[str, Any]] = []
        self._metrics: list[dict[str, Any]] = []
        self._secrets: set[str] = set()  # values learned from commands' argv/env; never persisted

    # -- paths ---------------------------------------------------------------------------------------------

    def _check_root(self) -> None:
        for path, identity in self._chain:
            try:
                unchanged = not _is_link(path) and path.is_dir() and _directory_identity(path) == identity
            except OSError:
                unchanged = False
            if not unchanged:
                raise EvidenceError(f"{path} was replaced or removed after the recorder was created")

    def _contained(self, relative: str, *, create_parents: bool = False) -> Path:
        self._check_root()
        pure = PurePosixPath(relative)
        if (not relative or "\\" in relative or pure.is_absolute() or (len(relative) > 1 and relative[1] == ":")
                or any(part in ("", ".", "..") for part in relative.split("/"))):
            raise EvidenceError(f"{relative!r} is not a contained relative path")
        current = self.root
        for part in pure.parts[:-1]:
            current = current / part
            if _is_link(current):
                raise EvidenceError(f"{relative!r} passes through a link")
            if create_parents:
                current.mkdir(exist_ok=True)
        target = current / pure.parts[-1]
        if _is_link(target):
            raise EvidenceError(f"{relative!r} is a link")
        if self.root not in target.resolve().parents:  # the frozen canonical root, not a re-resolved one
            raise EvidenceError(f"{relative!r} resolves outside the evidence root")
        return target

    # -- recording -----------------------------------------------------------------------------------------

    def _refuse_secrets(self, relative: str, data: bytes) -> None:
        if redaction.contains_secret(data.decode("utf-8", errors="replace"), self._secrets):
            raise EvidenceError(f"{relative!r} contains a known secret or credential pattern; refusing to record it")

    def add_artifact(self, relative: str, role: ArtifactRole) -> str:
        path = self._contained(relative)
        if not path.is_file():
            raise EvidenceError(f"{relative!r} is not a regular file")
        self._refuse_secrets(relative, path.read_bytes())
        self._artifacts[relative] = {"path": relative, "role": role, "sha256": _sha256(path),
                                     "size": path.stat().st_size}
        return str(self._artifacts[relative]["sha256"])

    def write_artifact(self, relative: str, data: bytes, role: ArtifactRole) -> str:
        self._refuse_secrets(relative, data)  # before anything is written
        _atomic_write(self._contained(relative, create_parents=True), data)
        return self.add_artifact(relative, role)

    def run(self, step: str, argv: Sequence[str], *, timeout: float = 600, cwd: Path | None = None,
            env: Mapping[str, str] | None = None) -> int:
        values = redaction.secret_values_in_argv(argv)
        env_values = redaction.secret_values_in_environment(env) if env is not None else ()
        try:  # refused before anything runs or is written: a value this short could not be masked safely
            redaction.require_maskable(values, "a secret-named flag value")
            redaction.require_maskable(env_values, "a secret-named environment value")
        except ValueError as exc:
            raise EvidenceError(f"step {step!r}: {exc}") from None
        self._secrets.update(value for value in (*values, *env_values) if value)
        self._check_root()  # before the command runs, not only when its output is written
        started, launch_error, timed_out = self._clock.now(), "", False
        try:
            completed = subprocess.run(list(argv), capture_output=True, timeout=timeout, cwd=cwd, env=env,
                                       check=False)
            code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True  # the kind comes from this flag: a child killed by SIGHUP also returns -1
            code, stdout, stderr = TIMEOUT_EXIT, exc.stdout or b"", exc.stderr or b""
        except (OSError, ValueError) as exc:  # could not start: recorded, never silently dropped
            launch_error = f"could not start: {type(exc).__name__}: {getattr(exc, 'strerror', None) or exc}"
            code, stdout, stderr = LAUNCH_ERROR_EXIT, b"", launch_error.encode("utf-8")
        finished = self._clock.now()
        outputs = []
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            relative = f"commands/{step}.{name}.txt"
            text = redaction.redact_text(data.decode("utf-8", errors="replace"), self._secrets)
            self.write_artifact(relative, text.encode("utf-8"), "log")
            outputs.append(relative)
        self._commands.append({"step": step, "argv": redaction.redact_argv(argv, self._secrets),
                               "exit_code": code,
                               "started_at": started, "finished_at": finished, "outputs": tuple(outputs)})
        if launch_error:
            self.failure(step, "launch_error", launch_error, outputs)
        elif timed_out:
            self.failure(step, "timeout", f"timed out after {timeout} s", outputs)
        elif code != 0:
            self.failure(step, "nonzero_exit", f"exited with code {code}", outputs)
        return code

    def failure(self, step: str, kind: str, detail: str, artifacts: Iterable[str] = ()) -> None:
        detail = redaction.redact_text(detail, self._secrets)[:500]
        self._failures.append({"step": step, "kind": kind, "detail": detail,
                               "artifacts": tuple(artifacts)})

    def metric(self, name: str, value: Decimal | int | str, unit: str, derivation: str,
               sources: Iterable[str]) -> None:
        if isinstance(value, (bool, float)):
            raise EvidenceError("metric values must be exact (Decimal, int or decimal text)")
        digests = []
        for relative in sources:
            if relative not in self._artifacts:
                raise EvidenceError(f"metric source {relative!r} is not a recorded artifact")
            digests.append(self._artifacts[relative]["sha256"])
        self._metrics.append({"name": name, "value": str(value), "unit": unit, "derivation": derivation,
                              "sources": tuple(digests)})

    # -- output --------------------------------------------------------------------------------------------

    def verify(self) -> None:
        """Re-hash every artifact and re-check it against the secrets known now (values may be registered later)."""
        for relative, record in self._artifacts.items():
            path = self._contained(relative)
            if not path.is_file() or _sha256(path) != record["sha256"]:
                raise EvidenceError(f"artifact {relative!r} changed after it was recorded")
            self._refuse_secrets(relative, path.read_bytes())

    def finish(self, code: CodeIdentity, *, environment: Iterable[str] = (),
               manifest_name: str = "evidence-manifest.json") -> EvidenceManifest:
        target = self._contained(manifest_name, create_parents=True)
        # The manifest must not replace a file it describes (or any existing file): its hashes would then be stale.
        if any(self._contained(relative) == target for relative in self._artifacts) or target.exists():
            raise EvidenceError(f"manifest path {manifest_name!r} collides with a recorded or existing file")
        self.verify()
        env = redaction.redact_environment(os.environ, environment)
        manifest = EvidenceManifest.model_validate({
            **self._identity, "started_at": self._started, "finished_at": self._clock.now(),
            "code": code.model_dump(), "environment": tuple({"name": n, "value": v} for n, v in env),
            "artifacts": tuple(self._artifacts[key] for key in sorted(self._artifacts)),
            "commands": tuple(self._commands), "failures": tuple(self._failures), "metrics": tuple(self._metrics),
        })
        text = json.dumps(json.loads(manifest.model_dump_json()), indent=2, sort_keys=True) + "\n"
        # Fields were redacted when recorded; never rewrite serialized JSON, refuse instead if anything still looks
        # like a secret.
        if redaction.contains_secret(text, self._secrets):
            raise EvidenceError("the manifest still contains secret-like content; refusing to persist it")
        _atomic_write(target, text.encode("utf-8"))
        return manifest


def deterministic_digest(manifest: EvidenceManifest) -> str:
    """SHA-256 of the manifest without run IDs and timestamps, for comparing reruns of the same inputs."""
    data = json.loads(manifest.model_dump_json())
    for key in VOLATILE:
        data.pop(key, None)
    for command in data["commands"]:
        command.pop("started_at", None)
        command.pop("finished_at", None)
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
