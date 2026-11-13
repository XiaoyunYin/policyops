"""Bounded private receipts around entire logical calls, including settlement."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
import time
from typing import Any
from uuid import UUID

from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.corpus import write_contained


class CallTimings:
    def __init__(self, directory: Path, slot_id: UUID) -> None:
        self.directory, self.slot_id = directory, slot_id
        self.rows: list[dict[str, Any]] = []
        self.inventory: list[dict[str, Any]] = []

    def index(self) -> None:
        write_contained(self.directory, f"{self.slot_id}-timings.json", canonical_bytes(self.inventory))

    @contextmanager
    def observe(self, actor: str, key: UUID) -> Iterator[None]:
        if actor not in {"agent", "simulator", "judge"} or len(self.rows) >= 256:
            raise ValueError("timing bounds")
        row: dict[str, Any] = {"slot_id": str(self.slot_id), "call_id": str(key), "actor": actor,
            "started_at": datetime.now(UTC).isoformat(), "finished_at": None, "wall_ms": None}
        start = time.monotonic_ns()
        raw = canonical_bytes(row)
        write_contained(self.directory, f"{key}-timing-start.json", raw)
        entry = {"call_id": str(key), "start_sha256": sha256_bytes(raw), "end_sha256": None}
        self.inventory.append(entry)
        self.index()  # committed receipt identity before count/inference begins
        self.rows.append(row)
        try:
            yield
        finally:
            row.update(finished_at=datetime.now(UTC).isoformat(), wall_ms=(time.monotonic_ns() - start) // 1_000_000)
            raw = canonical_bytes(row)
            write_contained(self.directory, f"{key}-timing-end.json", raw)
            entry["end_sha256"] = sha256_bytes(raw)
            self.index()


def receipts(directory: Path, slot_id: UUID) -> list[dict[str, Any]]:
    """Read only the claim-bound per-slot inventory, including start-only calls."""
    from policyops_evals.studies.bundles import BundleRefused, read

    path = directory / f"{slot_id}-timings.json"
    if not path.exists():
        return []  # legacy/never-started observer; do not reconstruct durations
    entries, _ = read(path)
    if not isinstance(entries, list) or len(entries) > 256:
        raise BundleRefused("timing_inventory_bounds")
    rows = []
    seen = set()
    for entry in entries:
        call_id = UUID(entry["call_id"])
        if str(call_id) in seen:
            raise BundleRefused("duplicate_timing_receipt")
        seen.add(str(call_id))
        row, raw = read(directory / f"{call_id}-timing-start.json")
        if sha256_bytes(raw) != entry["start_sha256"]:
            raise BundleRefused("timing_receipt_integrity")
        if entry["end_sha256"] is not None:
            row, raw = read(directory / f"{call_id}-timing-end.json")
            if sha256_bytes(raw) != entry["end_sha256"]:
                raise BundleRefused("timing_receipt_integrity")
        if row.get("slot_id") != str(slot_id) or row.get("call_id") != str(call_id):
            raise BundleRefused("timing_receipt_binding")
        rows.append(row)
    return rows
