"""Derive N16 tables from retained query, plan and build JSONL evidence."""
from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from hashlib import file_digest
import json
import math
from pathlib import Path
from statistics import median
import sys
from typing import Any

from scripts.bm25_latency_probe import output_path, percentile
from scripts.n16_ann_benchmark import digest
from scripts.n16_ann_data import K
from scripts.n16_ann_postgres import plan_summary


def recall_at_10(actual: Collection[str], expected: Collection[str]) -> float:
    return len(set(actual).intersection(expected)) / K


def spread(values: Sequence[float | int | None], decimals: int) -> str:
    samples = [value for value in values if value is not None]
    if not samples:
        return "—"
    return (
        f"{median(samples):.{decimals}f} "
        f"[{min(samples):.{decimals}f}, {max(samples):.{decimals}f}]"
    )


Key = tuple[str, int, int, str]


@dataclass
class Attempt:
    scheduled_queries: list[str] | None = None
    plan_digest: str | None = None
    observed: str = "unverified"
    node: str = "—"
    recorded: int = 0
    latency: list[float] = field(default_factory=list)
    recall_sum: float = 0
    short: int = 0
    errors: int = 0
    warmup_errors: int = 0


class Evidence:
    def __init__(self) -> None:
        self.run: dict[str, Any] = {}
        self.source: dict[str, Any] = {}
        self.database: dict[str, Any] = {}
        self.versions: dict[str, Any] = {}
        self.finish: dict[str, Any] = {}
        self.attempts: dict[Key, Attempt] = {}
        self.cells: dict[tuple[str, str], dict[str, Any]] = {}
        self.builds: dict[tuple[str, int], dict[str, Any]] = {}
        self.started_builds: set[tuple[str, int]] = set()
        self.truth: dict[tuple[str, str, str], list[str]] = {}
        self.ties: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
        self.checks: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self.truncated = False

    def accept(self, row: dict[str, Any]) -> None:
        kind = row.pop("kind")
        if self.finish:
            raise ValueError("record_after_finish")
        if kind == "run":
            if self.run:
                raise ValueError("duplicate_run")
            self.run = row
            for layout in row["schedule"]:
                layout_id = layout["layout"]
                for number, parameters in enumerate(layout["builds"], 1):
                    self.builds[layout_id, number] = {"m": parameters[0], "ef_construction": parameters[1]}
                    for cell in layout["cells"]:
                        self.cells[layout_id, cell["id"]] = cell | {"size": layout["size"]}
                        for repeat in range(1, self.run["passes"] + 1):
                            self.attempts[layout_id, number, repeat, cell["id"]] = Attempt()
            return
        if not self.run:
            raise ValueError("missing_run_header")
        if kind in ("finish", "versions", "database", "corpus"):
            attribute = "source" if kind == "corpus" else kind
            if getattr(self, attribute):
                raise ValueError("duplicate_run_record")
            setattr(self, attribute, row)
        elif kind in ("build", "build_start"):
            build_id = (row["layout"], row["build"])
            expected = self.builds[build_id]
            if any(row[key] != expected[key] for key in ("m", "ef_construction")):
                raise ValueError("build_parameters_mismatch")
            if kind == "build_start":
                if build_id in self.started_builds:
                    raise ValueError("duplicate_build_start")
                self.started_builds.add(build_id)
            else:
                if "layout" in expected or build_id not in self.started_builds:
                    raise ValueError("unexpected_build_result")
                self.builds[build_id] = row
        elif kind == "truth":
            key = row["layout"], row["scope"], row["query"]
            if key in self.truth:
                raise ValueError("duplicate_truth")
            self.truth[key] = [source_id for source_id, _ in row["rows"][:K]]
            ties = self.ties[key[:2]]
            ties[0] += int(row["cutoff_tie"])
            ties[1] += int(row["crossing_tie"])
        elif kind == "crosscheck":
            scope = row["layout"], row["scope"]
            if scope in self.checks:
                raise ValueError("duplicate_crosscheck")
            self.checks[scope] = row["rows"]
        elif kind in ("cell", "plan", "plan_error", "sample", "warmup_error"):
            self.accept_cell(kind, row)
        else:
            raise ValueError("unknown_record")

    def accept_cell(self, kind: str, row: dict[str, Any]) -> None:
        layout, cell_id = row["layout"], row["cell"]
        cell = self.cells[layout, cell_id]
        attempt = self.attempts[layout, row["build"], row["pass"], cell_id]
        if kind == "cell":
            order: list[str] = row["query_order"]
            if attempt.scheduled_queries is not None or sorted(order) != sorted(self.source["query_ids"]):
                raise ValueError("cell_query_schedule_mismatch")
            attempt.scheduled_queries = order
        elif attempt.scheduled_queries is None:
            raise ValueError("missing_cell_header")
        elif kind in ("plan", "plan_error"):
            if attempt.observed != "unverified" or row["query"] != attempt.scheduled_queries[0]:
                raise ValueError("unexpected_plan")
            if kind == "plan_error":
                attempt.observed = "plan error"
            else:
                observed, node = plan_summary(row["plan"], cell["method"])
                if row["digest"] != digest(row["plan"]) or (observed, node) != (row["observed"], row["node"]):
                    raise ValueError("plan_digest_or_classification_mismatch")
                attempt.plan_digest, attempt.observed, attempt.node = row["digest"], observed, node
        elif kind == "warmup_error":
            attempt.warmup_errors += 1
        else:
            query, index = row["query"], attempt.recorded
            if (
                index >= len(attempt.scheduled_queries)
                or query != attempt.scheduled_queries[index]
                or row["plan_digest"] != attempt.plan_digest
                or attempt.observed == "unverified"
            ):
                raise ValueError("sample_schedule_or_plan_mismatch")
            ids = [source_id for source_id, _ in row["rows"]]
            elapsed = row["elapsed_ms"]
            if len(ids) != len(set(ids)) or len(ids) > K or (
                elapsed is not None and (not math.isfinite(elapsed) or elapsed < 0)
            ):
                raise ValueError("sample_shape")
            attempt.recorded += 1
            attempt.short += len(ids) < K and row["error"] is None
            if row["error"] is None:
                if elapsed is None:
                    raise ValueError("missing_sample_latency")
                attempt.latency.append(elapsed)
                attempt.recall_sum += recall_at_10(ids, self.truth[layout, cell["scope"], query])
            else:
                attempt.errors += 1

    def complete(self) -> bool:
        if not (self.finish.get("status") == "completed" and self.versions and self.database and self.source):
            return False
        queries = self.source["query_ids"]
        scopes = {(layout, cell["scope"]) for (layout, _), cell in self.cells.items()}
        return (
            not self.truncated
            and len(queries) == len(set(queries)) == self.run["queries"]
            and set(self.truth) == {(layout, scope, query) for layout, scope in scopes for query in queries}
            and set(self.checks) == scopes
            and all(
                len({row["query"] for row in checks}) == len(checks) == self.run["config"]["crosscheck_count"]
                and all(row["ok"] and row["query"] in queries for row in checks)
                for checks in self.checks.values()
            )
            and all(
                row.get("index_bytes") and row.get("memory_samples", 0) >= 2
                and row["memory_sample_failures"] == 0 and "error" not in row for row in self.builds.values()
            )
            and all(
                attempt.recorded == self.run["queries"] and attempt.plan_digest
                and attempt.errors == attempt.warmup_errors == 0
                for attempt in self.attempts.values()
            )
        )


def read(path: Path) -> Evidence:
    evidence = Evidence()
    with path.open("rb") as input_file:
        for line in input_file:
            if not line.endswith(b"\n"):
                evidence.truncated = True
                break
            evidence.accept(json.loads(line))
    if not evidence.run:
        raise ValueError("missing_run_header")
    return evidence


def table_row(*columns: object) -> str:
    return "| " + " | ".join(str(value) if value is not None else "—" for value in columns) + " |"


def render(evidence: Evidence, artifact_hash: str) -> str:
    run = evidence.run
    query_count = run["queries"]
    mode = run["mode"]
    lines = [
        f"# N16 {mode} evidence", "",
        f"Evidence {'complete' if evidence.complete() else 'incomplete or failed'}. Raw SHA-256 `{artifact_hash}`.", "",
        "Latency is execute through fetch for successful samples. Recall divides by ten per scheduled query. "
        "Short counts are successful queries returning fewer than ten. Errors and missing slots also contribute zero "
        "recall. Each aggregate shows the median and min-max across started passes of the same observed plan, "
        "with no confidence interval. The repeat table includes unstarted passes.", "",
        f"Optional MultiDoc2Dial comparison is {run['real_corpus']}.",
    ]
    if evidence.finish.get("error"):
        lines.extend(["", f"Run stopped with `{evidence.finish['error']}`."])
    if evidence.truncated:
        lines.extend(["", "The final raw record was truncated."])

    lines.extend([
        "", "## Builds", "",
        "| Layout | Build | m | ef construction | Maintenance mem | Parallel worker cap | Seconds | Index bytes "
        "| Heap bytes | TOAST bytes | Sampled peak bytes | Container lifetime high water bytes "
        "| Memory samples / failures | Graph spill | Status |",
        table_row(*(["---"] * 15)),
    ])
    for key, row in sorted(evidence.builds.items()):
        status = row.get("error", "built" if "index_bytes" in row else
                         "unfinished" if key in evidence.started_builds else "unstarted")
        seconds = row.get("build_seconds")
        lines.append(table_row(
            *key, row["m"], row["ef_construction"], row.get("maintenance_work_mem"),
            row.get("maintenance_workers"), f"{seconds:.3f}" if seconds is not None else None, row.get("index_bytes"),
            row.get("heap_bytes"), row.get("toast_bytes"), row.get("peak_container_memory_bytes"),
            row.get("container_lifetime_high_water_bytes"),
            f"{row['memory_samples']} / {row['memory_sample_failures']}" if "memory_samples" in row else None,
            len(row["spill_notices"]) if "spill_notices" in row else None, status,
        ))

    if evidence.cells:
        grouped: dict[tuple[str, str, int, int, str, str], list[Attempt]] = defaultdict(list)
        repeat_rows = []
        for (layout, build, repeat, cell_id), attempt in sorted(evidence.attempts.items()):
            build_row = evidence.builds[layout, build]
            status = attempt.observed if attempt.scheduled_queries is not None else "unstarted"
            grouped[layout, cell_id, build_row["m"], build_row["ef_construction"], status, attempt.node].append(attempt)
            repeat_rows.append(table_row(
                layout, build, repeat, cell_id, status, attempt.recorded, query_count, attempt.short,
                attempt.errors, attempt.warmup_errors, spread([attempt.recall_sum / query_count], 3)
                if attempt.scheduled_queries is not None else "—",
                spread([percentile(attempt.latency, 0.50)], 3), spread([percentile(attempt.latency, 0.95)], 3),
            ))
        lines.extend([
            "", "## Search", "",
            "| N | Visible rows / share | Scope | Method | Planner settings | ef search | m / ef construction "
            "| Passes | Recall@10 | Short | Errors / missing | p50 ms | p95 ms | Observed plan | Plan nodes |",
            table_row(*(["---"] * 15)),
        ])
        for (layout, cell_id, m, construction, observed, node), attempts in sorted(grouped.items()):
            cell = evidence.cells[layout, cell_id]
            started = [attempt for attempt in attempts if attempt.scheduled_queries is not None]
            lines.append(table_row(
                cell["size"], f"{cell['visible']} / {cell['per_mille'] / 10:g}%", cell["scope"], cell["method"],
                cell["planner"], cell["ef"], f"{m} / {construction}", len(attempts),
                spread([attempt.recall_sum / query_count for attempt in started], 3),
                spread([attempt.short for attempt in started], 1),
                f"{sum(attempt.errors for attempt in attempts)} / "
                f"{query_count * len(attempts) - sum(attempt.recorded for attempt in attempts)}",
                spread([percentile(attempt.latency, 0.50) for attempt in started], 3),
                spread([percentile(attempt.latency, 0.95) for attempt in started], 3),
                observed, node,
            ))
        lines.extend([
            "", "## Exact truth checks", "",
            "| Layout | Scope | Ties touching rank 10 | Ties crossing rank 10 | NumPy passed / checked |",
            table_row(*(["---"] * 5)),
        ])
        for (layout, scope), (touch, cross) in sorted(evidence.ties.items()):
            checks = evidence.checks.get((layout, scope), [])
            passed = sum(bool(row["ok"]) for row in checks)
            lines.append(table_row(layout, scope, touch, cross, f"{passed} / {len(checks)}"))
        lines.extend([
            "", "## Passes", "",
            "| Layout | Build | Pass | Cell | Plan | Recorded | Scheduled | Short | Errors | Warmup errors "
            "| Recall@10 | p50 ms | p95 ms |", table_row(*(["---"] * 13)), *repeat_rows,
        ])
    settings = {
        key: value for key, value in run["config"].items()
        if key in ("work_mem", "max_scan_tuples", "scan_mem_multiplier", "shared_buffers")
    }
    lines.extend([
        "", "## Run metadata", "", "```json",
        json.dumps({"revision": run["revision"], "dirty": run["dirty"], "hardware": run["hardware"],
                    "dataset": evidence.source.get("source"), "database": evidence.database,
                    "versions": evidence.versions, "settings": settings,
                    "status": evidence.finish}, indent=2, sort_keys=True), "```", "",
    ])
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        source = output_path(args.raw)
        evidence = read(source)
        with source.open("rb") as handle:
            artifact_hash = file_digest(handle, "sha256").hexdigest()
        with output_path(args.out).open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(render(evidence, artifact_hash))
        return 0 if evidence.complete() else 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"N16 report failed ({type(error).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
