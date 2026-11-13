"""Offline codes/counts from sealed slots and hash-linked private evidence.

The snapshot anchors each result hash, and each result anchors its agent hash.
Private inventories locate bytes; they are never an alternative trust anchor.
No transcript field is copied into the output.
"""

from collections import Counter
from pathlib import Path
import re
from typing import Any

from policyops_contracts.conversation import ConversationSnapshot
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.studies import bundles
from policyops_evals.studies.reports import validate


ERRORS = frozenset({"trial_failed", "scoring_unavailable", "trial_deadline", "study_interrupted",
    "abandoned_claim", "unclaimed_closed", "cleanup_unconfirmed", "actor_limit_or_contract", "agent_limit",
    "trial_setup_or_artifact", "judge_unavailable", "simulator_failed"})
OUTCOMES = frozenset({"success", "failure", "error", "aborted", "budget_exceeded"})
type ArtifactIndex = dict[tuple[str, str], list[Path]]


def inventory(directory: Path) -> ArtifactIndex:
    """Verify all declared private bytes, with bounded discovery and no alias traversal."""
    found: ArtifactIndex = {}
    seen: set[str] = set()
    base = directory.parent.parent  # benchmarks/studies/<study-id>
    inventories = []
    for path in directory.glob("private-inventory-*.json"):
        inventories.append(path)
        if len(inventories) > 1000:
            raise bundles.BundleRefused("private_inventory_count")
    aggregate_bytes = 0
    for path in sorted(inventories):
        body, _ = bundles.read(path)
        if (not isinstance(body, dict) or set(body) != {"schema_version", "base", "files"}
                or body["schema_version"] != "policyops.private-inventory/v1" or body["base"] != "benchmarks"
                or not isinstance(body["files"], list) or len(body["files"]) > 16384):
            raise bundles.BundleRefused("private_inventory_schema")
        total = 0
        for item in body["files"]:
            if (not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}
                    or not isinstance(item["path"], str) or item["path"] in seen
                    or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= bundles.MAX_FILE
                    or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
                raise bundles.BundleRefused("private_inventory_entry")
            total += item["bytes"]
            aggregate_bytes += item["bytes"]
            if total > bundles.MAX_BYTES or aggregate_bytes > 16 * bundles.MAX_BYTES or len(seen) >= 131072:
                raise bundles.BundleRefused("private_inventory_bound")
            target = bundles.child(base, item["path"])
            # Check ancestors too: a junction above the invocation is not allowed.
            if any(p.is_symlink() or p.is_junction() for p in target.parents):
                raise bundles.BundleRefused("private_inventory_alias")
            try:
                with target.open("rb") as handle:
                    raw = handle.read(bundles.MAX_FILE + 1)
            except OSError:
                raise bundles.BundleRefused("private_artifact_missing") from None
            if len(raw) != item["bytes"] or sha256_bytes(raw) != item["sha256"]:
                raise bundles.BundleRefused("private_artifact_integrity")
            seen.add(item["path"])
            found.setdefault((target.name, item["sha256"]), []).append(target)
    return found


def linked(found: ArtifactIndex, filename: str, digest: str,
           *, invocation: Path | None = None) -> tuple[Any, Path]:
    matches = [p for p in found.get((filename, digest), ()) if invocation is None or p.parent == invocation]
    if len(matches) != 1:
        raise bundles.BundleRefused("private_artifact_link")
    path = matches[0]
    body, raw = bundles.read(path)
    if sha256_bytes(raw) != digest:  # recheck the exact parsed bytes
        raise bundles.BundleRefused("private_artifact_integrity")
    return body, path


def render(path: Path, *, snapshot: str, out: Path) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot):
        raise bundles.BundleRefused("snapshot_digest")
    study, frozen, study_hash, snapshot_hash = bundles.load(path, snapshot)
    validate(study, frozen)  # includes schedule, identity and stratum checks
    found = inventory(path.parent)
    counts: Counter[tuple[str, str, str, str]] = Counter()
    tasks: Counter[tuple[str, str, str, str, str]] = Counter()
    for row in frozen.trials:
        outcome: str = row.status
        terminal = "unavailable"
        error: str = row.failure_class or "none"
        if row.artifact_sha256 is not None:
            raw_result, result_path = linked(found, f"{row.slot_id}-result.json", row.artifact_sha256)
            if not isinstance(raw_result, dict) or raw_result.get("outcome") not in OUTCOMES:
                raise bundles.BundleRefused("private_result_schema")
            outcome = raw_result["outcome"]
            normalized = "error" if outcome == "budget_exceeded" else outcome
            # Normalization may convert an invalid scored result to error; it
            # may never turn one into success. Keep both codes in the taxonomy.
            if normalized != row.status and row.status != "error":
                raise bundles.BundleRefused("private_result_outcome")
            code = raw_result.get("error_class")
            error = "none" if code is None else code if isinstance(code, str) and code in ERRORS else "unknown_error"
            agent_hash = raw_result.get("agent_snapshot_sha256")
            if agent_hash is not None:
                if not isinstance(agent_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", agent_hash):
                    raise bundles.BundleRefused("private_agent_digest")
                agent, _ = linked(found, f"{row.slot_id}-agent.json", agent_hash, invocation=result_path.parent)
                try:
                    checked = ConversationSnapshot.model_validate_json(canonical_bytes(agent))
                except ValueError:
                    raise bundles.BundleRefused("private_agent_schema") from None
                terminal = checked.terminal or "none"
        group_key = (row.variant, outcome, terminal, error)
        counts[group_key] += 1
        tasks[(row.task_id, *group_key)] += 1

    def rows(counter: Counter[Any], fields: tuple[str, ...]) -> list[dict[str, Any]]:
        return [dict(zip(fields, key, strict=True)) | {"count": count} for key, count in sorted(counter.items())]

    fields = ("variant", "outcome", "agent_terminal_reason", "error_class")
    result: dict[str, Any] = {"schema_version": "policyops.study-taxonomy/v1", "study_sha256": study_hash,
        "snapshot_sha256": snapshot_hash, "scheduled_trials": len(frozen.trials),
        "counts": rows(counts, fields), "per_task": rows(tasks, ("task_id", *fields))}
    lines = ["# Study failure taxonomy", "", f"Snapshot: {snapshot_hash}", "",
             "Outcome is the raw result code when available; absent artifacts use the sealed slot status.",
             "Terminal `none` means observed without a terminal; `unavailable` means no linked agent artifact.",
             "Unknown error strings map to `unknown_error`. Counts include every scheduled trial.", ""]
    for title, key, columns in (("Counts", "counts", fields), ("Per-task matrix", "per_task", ("task_id", *fields))):
        lines.extend([f"## {title}", "", "| " + " | ".join((*columns, "count")) + " |",
                      "| " + " | ".join("---" for _ in (*columns, "count")) + " |"])
        lines.extend("| " + " | ".join(str(row[c]) for c in (*columns, "count")) + " |" for row in result[key])
        lines.append("")
    # Only write after every integrity check has passed.
    bundles.write(out / "taxonomy.json", canonical_bytes(result))
    bundles.write(out / "taxonomy.md", ("\n".join(lines) + "\n").encode("utf-8"), byte_limit=bundles.MAX_BYTES)
    return result
