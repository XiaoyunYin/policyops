"""Evidence manifest for test, benchmark and review runs.

A manifest records what ran (redacted argv, exit codes, UTC times), on which code
(Git head/tree, optional dirty-patch digest), with which locks/configs/inputs,
what it produced (artifacts by path relative to the run's root and SHA-256),
every failure, and how derived metrics trace to raw artifacts.

Schema validation enforces structure only:
- relative POSIX paths without traversal;
- chronology;
- a failure record for every non-zero exit;
- metrics and failures that reference recorded artifacts.

It cannot prove the hashes match the files or that nothing was omitted; the recorder (tests/support) hashes
contained files and re-verifies them before writing.
"""

from typing import Annotated, Literal, Self

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.scalars import GitObjectId, SafeDetail, Sha256Hex, ShortText, Slug, UtcDatetime


def _relative_posix(value: str) -> str:
    """Relative POSIX path: no leading slash, drive, backslash, empty, "." or ".." component."""
    parts = value.split("/")
    if (value.startswith("/") or (len(value) > 1 and value[1] == ":") or "\\" in value
            or any(part in ("", ".", "..") for part in parts)):
        raise ValueError("artifact paths must be relative POSIX paths without traversal")
    return value


RelativePath = Annotated[str, StringConstraints(min_length=1, max_length=400, pattern=r"^[^\x00-\x1f]+$"),
                         AfterValidator(_relative_posix)]
ArgText = Annotated[str, StringConstraints(max_length=2000, pattern=r"^[^\x00-\x08\x0b-\x1f\x7f]*$")]
EnvName = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
DecimalText = Annotated[str, StringConstraints(pattern=r"^-?(?:0|[1-9]\d{0,30})(?:\.\d{1,12})?$")]
ArtifactRole = Literal["input", "output", "log", "report", "config", "lock"]


class ArtifactRef(WireModel):
    path: RelativePath
    role: ArtifactRole
    sha256: Sha256Hex
    size: Annotated[int, Field(ge=0)]


class CommandRecord(WireModel):
    step: Slug
    argv: Annotated[tuple[ArgText, ...], Field(min_length=1, max_length=64)]
    exit_code: int
    started_at: UtcDatetime
    finished_at: UtcDatetime
    outputs: Annotated[tuple[RelativePath, ...], Field(max_length=16)] = ()


class CodeIdentity(WireModel):
    git_head: GitObjectId
    git_tree: GitObjectId
    dirty_patch_sha256: Sha256Hex | None = None


class FailureRecord(WireModel):
    step: Slug
    kind: Literal["nonzero_exit", "launch_error", "test_failure", "error", "timeout", "skipped_required"]
    detail: SafeDetail
    artifacts: Annotated[tuple[RelativePath, ...], Field(max_length=16)] = ()


class DerivedMetric(WireModel):
    name: Slug
    value: DecimalText
    unit: ShortText
    derivation: ShortText
    sources: Annotated[tuple[Sha256Hex, ...], Field(min_length=1, max_length=64)]


class EnvironmentEntry(WireModel):
    name: EnvName
    value: Annotated[str, StringConstraints(max_length=400, pattern=r"^[^\x00-\x1f\x7f]*$")]


class EvidenceManifest(WireModel):
    schema_version: Literal["policyops.evidence-manifest/v1"] = "policyops.evidence-manifest/v1"
    run_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")]
    task_id: Annotated[str, StringConstraints(pattern=r"^[A-Z][0-9]{2}$")]
    purpose: ShortText
    seed: int | None = None
    started_at: UtcDatetime
    finished_at: UtcDatetime
    code: CodeIdentity
    environment: Annotated[tuple[EnvironmentEntry, ...], Field(max_length=64)] = ()
    artifacts: Annotated[tuple[ArtifactRef, ...], Field(max_length=4096)] = ()
    commands: Annotated[tuple[CommandRecord, ...], Field(max_length=512)] = ()
    failures: Annotated[tuple[FailureRecord, ...], Field(max_length=512)] = ()
    metrics: Annotated[tuple[DerivedMetric, ...], Field(max_length=512)] = ()

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("run finished before it started")
        paths = [artifact.path for artifact in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError("artifact paths must be unique")
        known_paths, known_digests = set(paths), {artifact.sha256 for artifact in self.artifacts}
        names = [entry.name for entry in self.environment]
        if len(names) != len(set(names)):
            raise ValueError("environment names must be unique")
        steps = [command.step for command in self.commands]
        if len(steps) != len(set(steps)):
            raise ValueError("command steps must be unique")
        failed_steps = {failure.step for failure in self.failures}
        for command in self.commands:
            if not self.started_at <= command.started_at <= command.finished_at <= self.finished_at:
                raise ValueError(f"command {command.step} lies outside the run's time span")
            if not set(command.outputs) <= known_paths:
                raise ValueError(f"command {command.step} names outputs that are not recorded artifacts")
            if command.exit_code != 0 and command.step not in failed_steps:
                raise ValueError(f"command {command.step} exited {command.exit_code} without a failure record")
        for failure in self.failures:
            if not set(failure.artifacts) <= known_paths:
                raise ValueError(f"failure {failure.step} names unrecorded artifacts")
        for metric in self.metrics:
            if not set(metric.sources) <= known_digests:
                raise ValueError(f"metric {metric.name} derives from artifacts that are not recorded")
        return self
