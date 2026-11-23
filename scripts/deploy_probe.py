"""Sample the public PolicyOps release and readiness during a deployment drill."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
import json
import os
import re
import subprocess
import time
from typing import TypedDict


PATHS = {"release": "/release", "readiness": "/api/v1/health/ready"}
INTERVALS = {"release": 1, "readiness": 2}


class Sample(TypedDict):
    at: str
    endpoint: str
    slot: int
    status: int | None
    latency_ms: float
    release: str | None
    error: str | None


def hostname(raw: str) -> str:
    if len(raw) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}", raw):
        raise ValueError("expected a DNS hostname without scheme or port")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in raw.split(".")):
        raise ValueError("invalid DNS label")
    return raw


def probe(host: str, endpoint: str, slot: int) -> Sample:
    at = datetime.now(UTC).isoformat()
    start = time.monotonic()
    status, release, error = None, None, None
    args = ["curl", "--disable", "--silent", "--noproxy", "*", "--proto", "=https", "--connect-timeout", "1",
            "--max-time", "2", "--write-out", "\n%{http_code}"]
    if endpoint == "release":
        args += ["--max-filesize", "40"]
    else:
        args += ["--output", os.devnull]
    try:
        result = subprocess.run([*args, f"https://{host}{PATHS[endpoint]}"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=3, check=False)
        body, _, code = result.stdout.rpartition(b"\n")
        if re.fullmatch(rb"[1-5][0-9]{2}", code):
            status = int(code)
        if result.returncode:
            error = f"curl_{result.returncode}"
        elif status != 200:
            error = "http_status"
        elif endpoint == "release":
            if re.fullmatch(rb"[0-9a-f]{40}", body):
                release = body.decode("ascii")
            else:
                error = "invalid_release"
    except subprocess.TimeoutExpired:
        error = "timeout"
    except OSError:
        error = "curl_unavailable"
    return {"at": at, "endpoint": endpoint, "slot": slot, "status": status, "release": release,
            "error": error, "latency_ms": round((time.monotonic() - start) * 1000, 3)}


def summarize(samples: Iterable[Sample], duration: int) -> dict[str, object]:
    ordered = sorted(samples, key=lambda sample: sample["slot"])
    endpoints = {}
    releases: dict[str, dict[str, str]] = {}
    windows = []
    for endpoint, interval in INTERVALS.items():
        by_slot = {sample["slot"]: sample for sample in ordered if sample["endpoint"] == endpoint}
        gaps, failed = [], []
        start, end = None, None
        for slot in range(0, duration, interval):
            sample = by_slot.get(slot)
            if sample is None:
                gaps.append(slot)
            if sample is not None and sample["error"] is not None:
                start = sample if start is None else start
                end = sample
            elif start is not None and end is not None:
                failed.append((start, end))
                start, end = None, None
            if sample is not None and (release := sample["release"]) is not None:
                seen = releases.setdefault(release, {"first": sample["at"], "last": sample["at"]})
                seen["last"] = sample["at"]
        if start is not None and end is not None:
            failed.append((start, end))
        longest = max(failed, key=lambda pair: pair[1]["slot"] - pair[0]["slot"], default=None)
        window = None
        if longest is not None:
            first, last = longest
            span = last["slot"] - first["slot"]
            window = {"endpoint": endpoint, "first": first["at"], "last": last["at"],
                      "sample_span_seconds": span, "samples": 1 + span // interval}
            windows.append((span, window))
        endpoints[endpoint] = {"samples": len(by_slot), "gap_slots": gaps, "longest_failing_window": window}
    longest_window = max(windows, key=lambda pair: pair[0], default=(0, None))[1]
    return {"at": datetime.now(UTC).isoformat(), "type": "summary", "sample_count": len(ordered),
            "longest_failing_window": longest_window, "endpoints": endpoints, "releases": releases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", type=hostname)
    parser.add_argument("--duration", type=int, default=900, help="sampling duration in seconds (1 to 3600)")
    args = parser.parse_args()
    if not 1 <= args.duration <= 3600:
        parser.error("--duration must be between 1 and 3600 seconds")
    start = time.monotonic()
    samples: list[Sample] = []
    pending: set[Future[Sample]] = set()
    with ThreadPoolExecutor(max_workers=5) as workers:
        for slot in range(args.duration):
            time.sleep(max(0, start + slot - time.monotonic()))
            complete = {future for future in pending if future.done()}
            for future in complete:
                sample = future.result()
                samples.append(sample)
                print(json.dumps({"type": "sample", **sample}), flush=True)
            pending -= complete
            # Never catch up missed slots with a burst of requests.
            if time.monotonic() < start + slot + 0.5:
                for endpoint, interval in INTERVALS.items():
                    if slot % interval == 0 and len(pending) < 5:
                        pending.add(workers.submit(probe, args.hostname, endpoint, slot))
        for future in pending:
            sample = future.result()
            samples.append(sample)
            print(json.dumps({"type": "sample", **sample}), flush=True)
    print(json.dumps(summarize(samples, args.duration)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
