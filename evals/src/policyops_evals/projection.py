"""Runtime projection of evaluator task data and the split-purpose guard.

The application runtime may learn which public task it is working on, its domain
and split, and nothing else from a task record. Projection reads only `id` and
the presence of `initial_state.message_history` (any prefilled conversation is
refused until T29 defines a visible-message contract). User-scenario
instructions, evaluation criteria, reference actions, NL assertions, required
documents, user tools, initialization data/actions, descriptions, annotations
and issue records never cross. This is an allowlist: unknown fields are ignored,
not copied.

`SplitGuard` enforces the split rules: demos, smoke runs and tuning use dev tasks
only; held-out tasks are available solely for an explicit holdout evaluation.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field

from policyops_contracts import WireModel


VIEW_SCHEMA: Literal["policyops.runtime-task-view/v1"] = "policyops.runtime-task-view/v1"


class Purpose(StrEnum):
    DEMO = "demo"
    SMOKE = "smoke"
    TUNING = "tuning"
    DEV_EVALUATION = "dev_evaluation"
    HOLDOUT_EVALUATION = "holdout_evaluation"


DEV_ONLY = {Purpose.DEMO, Purpose.SMOKE, Purpose.TUNING, Purpose.DEV_EVALUATION}


class SplitViolation(PermissionError):
    """A task was requested for a purpose its split does not allow."""


class HiddenStateError(ValueError):
    """The task carries state the runtime contract cannot represent safely."""


class RuntimeTaskView(WireModel):
    """Everything from a task record that the application runtime may receive."""

    schema_version: Literal["policyops.runtime-task-view/v1"] = VIEW_SCHEMA
    domain: Literal["retail", "banking_knowledge"]
    task_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    split: Literal["dev", "holdout", "test"]
    purpose: Purpose


class SplitGuard:
    """Membership from reviewed split manifests; decides which purposes a task may serve."""

    def __init__(self, manifests: Mapping[str, Mapping[str, Any]]) -> None:
        self._membership: dict[tuple[str, str], str] = {}
        for domain, manifest in manifests.items():
            if manifest.get("domain") != domain:
                raise ValueError(f"manifest for {domain} declares domain {manifest.get('domain')!r}")
            for split, section in manifest["splits"].items():
                for task_id in section["task_ids"]:
                    key = (domain, str(task_id))
                    if key in self._membership:
                        raise ValueError(f"{domain}/{task_id} appears in more than one split")
                    self._membership[key] = split

    def split_of(self, domain: str, task_id: str) -> str:
        try:
            return self._membership[(domain, task_id)]
        except KeyError:
            raise SplitViolation(f"{domain}/{task_id} is not in a reviewed split") from None

    def require(self, domain: str, task_id: str, purpose: Purpose) -> str:
        split = self.split_of(domain, task_id)
        allowed = split == "dev" if purpose in DEV_ONLY else split in {"holdout", "test"}
        if not allowed:
            raise SplitViolation(f"{domain}/{task_id} is a {split} task; not allowed for {purpose.value}")
        return split


def project_task(task: Mapping[str, Any], *, domain: str, guard: SplitGuard, purpose: Purpose) -> RuntimeTaskView:
    task_id = task["id"]
    if not isinstance(task_id, str):
        raise HiddenStateError("task id must be a string")
    split = guard.require(domain, task_id, purpose)
    if "initial_state" in task:
        initial = task["initial_state"]
        if initial is not None and initial.get("message_history"):
            raise HiddenStateError(f"{domain}/{task_id} has a prefilled conversation; no visible-message contract yet")
    return RuntimeTaskView.model_validate(
        {"domain": domain, "task_id": task_id, "split": split, "purpose": purpose})
