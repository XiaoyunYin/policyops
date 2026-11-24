"""Linux SUT sampler for one explicitly named disposable Compose project. Standard library only."""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any


SERVICES = {"api", "worker", "postgres", "retail", "caddy", "dex"}
SAMPLE_CADENCE = {"host": 1, "postgres": 1, "containers": 5}
APPLICATION_NAMES = frozenset({"policyops-api-app", "policyops-api-auth", "policyops-compose"})
# One bounded read-only probe per second through the disposable project's PostgreSQL socket.
ACTIVITY = """
SELECT json_build_object(
 'activity', (SELECT coalesce(json_agg(q),'[]'::json) FROM (
  SELECT application_name,state,wait_event_type,wait_event,count(*) FROM pg_stat_activity
  WHERE datname=current_database() AND pid<>pg_backend_pid()
  GROUP BY application_name,state,wait_event_type,wait_event) q),
 'due', (SELECT json_build_object('count',count(*),'oldest_s',
    coalesce(extract(epoch FROM clock_timestamp()-min(available_at)),0)) FROM app.jobs
    WHERE (state='queued' AND available_at<=clock_timestamp()) OR
          (state='leased' AND lease_expires_at<=clock_timestamp()))
)
"""
COUNTERS = """
SELECT json_build_object(
 'database', (SELECT row_to_json(q) FROM (
 SELECT xact_commit,xact_rollback,blks_read,blks_hit,tup_returned,tup_fetched,tup_inserted,tup_updated,tup_deleted,
        conflicts,temp_files,temp_bytes,deadlocks,blk_read_time,blk_write_time,stats_reset
 FROM pg_stat_database WHERE datname=current_database()) q),
 'tables', (SELECT coalesce(json_agg(q),'[]'::json) FROM (
 SELECT schemaname||'.'||relname AS name,seq_scan,seq_tup_read,idx_scan,idx_tup_fetch,n_tup_ins,n_tup_upd,
        n_tup_del,n_tup_hot_upd,n_live_tup,n_dead_tup
 FROM pg_stat_user_tables ORDER BY schemaname,relname) q)
)
"""


def run(*args: str, timeout: float = 4) -> str:
    return subprocess.run(
        args, check=True, capture_output=True, text=True, encoding="utf-8", timeout=timeout
    ).stdout.strip()


def services(project: str) -> dict[str, str]:
    selected = run(
        "docker",
        "ps",
        "--no-trunc",
        "--filter",
        f"label=com.docker.compose.project={project}",
        "--format",
        '{{.ID}} {{.Label "com.docker.compose.service"}}',
    )
    result: dict[str, str] = {}
    for line in selected.splitlines():
        identifier, service = line.split()
        if service not in SERVICES:
            continue
        if service in result or not re.fullmatch(r"[a-f0-9]{64}", identifier):
            raise ValueError("invalid service inventory")
        result[service] = identifier
    if result.keys() != SERVICES:
        raise ValueError("missing SUT services")
    return result


def containers(project: str) -> dict[str, Any]:
    current = services(project)
    service_by_id = {identifier: service for service, identifier in current.items()}
    inspected = json.loads(run("docker", "inspect", *current.values(), timeout=2))
    stats = [
        json.loads(line)
        for line in run(
            "docker", "stats", "--no-stream", "--no-trunc", "--format", "{{json .}}", *current.values()
        ).splitlines()
    ]
    return {
        "inspect": {
            service_by_id[item["Id"]]: {
                "id": item["Id"],
                "image": item["Image"],
                "status": item["State"]["Status"],
                "oom": item["State"]["OOMKilled"],
                "restarts": item["RestartCount"],
                "memory_limit": item["HostConfig"]["Memory"],
                "health": item["State"].get("Health", {}).get("Status"),
            }
            for item in inspected
        },
        "stats": {
            service_by_id[item["ID"]]: {
                key: item[key] for key in ("CPUPerc", "MemUsage", "MemPerc", "NetIO", "BlockIO", "PIDs")
            }
            for item in stats
        },
    }


def postgres(identifier: str, database: str, sql: str) -> Any:
    raw = run(
        "docker",
        "exec",
        "--env",
        "PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=750 -c lock_timeout=250",
        identifier,
        "psql",
        "-XAtw",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "postgres",
        "-d",
        database,
        "-c",
        sql,
        timeout=1.5,
    )
    data = json.loads(raw)
    if sql == ACTIVITY:
        for row in data["activity"]:
            if row["application_name"] not in APPLICATION_NAMES:
                row["application_name"] = "other"
    return data


def host(previous: list[int] | None) -> tuple[list[int], dict[str, Any]]:
    with Path("/proc/stat").open(encoding="ascii") as source:
        ticks = [int(value) for value in source.readline().split()[1:9]]
    delta = [a - b for a, b in zip(ticks, previous, strict=True)] if previous is not None else []
    total = sum(delta)
    cpu = (
        dict(
            zip(
                ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"),
                (100 * value / total for value in delta),
                strict=True,
            )
        )
        if total > 0
        else {}
    )
    wanted = {"MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached", "SwapTotal", "SwapFree"}
    mem = {
        key.rstrip(":"): int(value)
        for key, value, *_ in (line.split() for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines())
        if key.rstrip(":") in wanted
    }
    swap_io = {
        key: int(value)
        for key, value in (line.split() for line in Path("/proc/vmstat").read_text(encoding="ascii").splitlines())
        if key in {"pswpin", "pswpout"}
    }
    return ticks, {"cpu_percent": cpu, "memory_kib": mem, "swap_pages": swap_io}


def safety(current: dict[str, Any], baseline: dict[str, Any] | None) -> str | None:
    for service, row in current.items():
        if row["oom"]:
            return f"{service}_oom"
        if row["status"] != "running":
            return f"{service}_status"
        if baseline is not None and (row["id"], row["restarts"]) != (
            baseline[service]["id"],
            baseline[service]["restarts"],
        ):
            return f"{service}_restarted"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--database", default="policyops")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    args = parser.parse_args()
    if (
        not re.fullmatch(r"(?:n10-[a-z0-9-]+|policyops-public)", args.project)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,62}", args.database)
        or not 1 <= args.seconds <= 3600
    ):
        parser.error("expected the disposable project and a bounded sample duration")
    try:
        token = args.token_file.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[a-f0-9]{64}", token):
            raise ValueError("invalid load token")
        with args.output.open("x", encoding="utf-8", buffering=1) as output, ThreadPoolExecutor(2) as pool:
            start = time.monotonic()

            def write(kind: str, **values: Any) -> None:
                output.write(
                    json.dumps({"kind": kind, "utc": datetime.now(UTC).isoformat(), **values}, separators=(",", ":"))
                    + "\n"
                )

            ids = services(args.project)
            marker = json.loads(run("docker", "inspect", "--format", "{{json .Mounts}}", ids["api"]))
            if not any(
                row["Source"] == str(args.token_file.resolve())
                and row["Destination"] == "/run/secrets/n10_load_token"
                and not row["RW"]
                for row in marker
            ):
                raise ValueError("the selected API has no disposable overlay token mount")
            # The postgres ID is fixed for this sampler. If it disappears the sampler stops.
            pg_id = ids["postgres"]
            write("sampler_meta", cadence_s=SAMPLE_CADENCE)
            baseline = None
            pending: Future[dict[str, Any]] | None = pool.submit(containers, args.project)
            ticks = None
            unhealthy = 0
            for second in range(args.seconds + 1):
                time.sleep(max(0, start + second * SAMPLE_CADENCE["host"] - time.monotonic()))
                try:
                    activity = pool.submit(postgres, pg_id, args.database, ACTIVITY)
                    ticks, data = host(ticks)
                    write("host", **data)
                    write("postgres", **activity.result())
                    if pending is not None and (pending.done() or second == args.seconds):
                        sample = pending.result()
                        pending = None
                        failure = safety(sample["inspect"], baseline)
                        baseline = baseline or sample["inspect"]
                        unhealthy = (
                            unhealthy + 1
                            if any(row["health"] == "unhealthy" for row in sample["inspect"].values())
                            else 0
                        )
                        write("containers", **sample)
                        if failure or unhealthy >= 2:
                            write("abort", reason=failure or "repeated_container_unhealthy")
                            return 1
                    if second % SAMPLE_CADENCE["containers"] == 0 or second == args.seconds:
                        write("pg_counters", **postgres(pg_id, args.database, COUNTERS))
                        if second != args.seconds and pending is None:
                            pending = pool.submit(containers, args.project)
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    write("abort", reason=type(error).__name__)
                    return 1
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
