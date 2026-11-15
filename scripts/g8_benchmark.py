"""G8 CPU benchmark. Run in the routed reranker venv; writes only private results.

    python scripts/devenv.py uv --project reranker run --offline --frozen python -B \
        scripts/g8_benchmark.py --artifact DIR --expected-sha256 SHA --threads 4 --out PRIVATE_JSON

Latency uses synthetic fixed top-20 inputs, not an accuracy dataset. Cold model
load excludes Python/library import time; process wall time includes those imports.
"""
from __future__ import annotations

import argparse
import ctypes
import importlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Any


def peak_ram_bytes() -> int:
    if os.name == "nt":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        *[(name, ctypes.c_size_t) for name in (
                            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
                            "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage",
                            "PeakPagefileUsage")]]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise OSError("process_memory_unavailable")
        return int(counters.PeakWorkingSetSize)
    resource = importlib.import_module("resource")

    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * (1 if sys.platform == "darwin" else 1024)


def percentile(values: list[float], probability: float) -> float | None:
    return sorted(values)[max(0, math.ceil(len(values) * probability) - 1)] if values else None


def child(args: argparse.Namespace) -> dict[str, Any]:
    load = importlib.import_module("policyops_reranker.model").load
    scores = importlib.import_module("policyops_reranker.score").scores

    started = time.perf_counter()
    model, tokenizer, identity = load(args.artifact, threads=args.threads, expected_sha256=args.expected_sha256)
    cold = time.perf_counter() - started
    query = "What documents do I need to renew my benefits?"
    passages = [(f"p{i:02}", "Required documents\n\n" + ("Bring your identity and income documents. " * 80))
                for i in range(20)]
    warm = []
    scores(model, tokenizer, query, passages)  # explicit untimed warm-up
    for _ in range(args.repeats):
        started = time.perf_counter()
        scores(model, tokenizer, query, passages)
        warm.append(time.perf_counter() - started)
    return {"artifact_sha256": identity, "cold_load_seconds": cold, "warm_top20_seconds": warm,
            "peak_process_ram_bytes": peak_ram_bytes(),
            "torch": importlib.import_module("torch").__version__,
            "transformers": importlib.import_module("transformers").__version__}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--cold-runs", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1 <= args.cold_runs <= 10 or not 1 <= args.repeats <= 100 or not 1 <= args.threads <= 32:
        parser.error("benchmark caps exceeded")
    if args.child:
        print(json.dumps(child(args)))
        return 0
    runtime = importlib.import_module("policyops_reranker.model")

    if args.out is None:
        parser.error("--out is required")
    runtime.private_output(args.out)
    runtime.verify(args.artifact, args.expected_sha256)
    runs, failures = [], []
    for index in range(args.cold_runs):
        started = time.perf_counter()
        try:
            result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--child",
                "--artifact", str(args.artifact), "--expected-sha256", args.expected_sha256,
                "--threads", str(args.threads), "--repeats", str(args.repeats)],
                capture_output=True, timeout=1800, check=True)
            run = json.loads(result.stdout)
            run["process_wall_seconds"] = time.perf_counter() - started
            runs.append(run)
        except (subprocess.SubprocessError, ValueError) as error:
            failures.append({"cold_run": index, "error": type(error).__name__,
                             "censored_seconds": time.perf_counter() - started})
    cold = [r["cold_load_seconds"] for r in runs]
    warm = [v for r in runs for v in r["warm_top20_seconds"]]
    output = {"schema": "policyops.g8-cpu-benchmark/v1", "artifact_sha256": args.expected_sha256,
        "script_sha256": runtime.sha256(Path(__file__)), "threads": args.threads, "logical_cpus": os.cpu_count(),
        "processor": platform.processor(), "platform": platform.platform(), "python": platform.python_version(),
        "requested_cold_runs": args.cold_runs, "warm_repeats_per_run": args.repeats, "interop_threads": 1,
        "max_length": 384, "query_token_cap": 128,
        "runs": runs, "failures": failures, "warmup": "one untimed top20 per process",
        "percentile": "nearest rank", "synthetic_query_tokens": "wordpiece measured by shared scorer",
        "cold_load_p50_seconds": percentile(cold, .5), "cold_load_p95_seconds": percentile(cold, .95),
        "warm_top20_p50_seconds": percentile(warm, .5), "warm_top20_p95_seconds": percentile(warm, .95)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("xb") as handle:
        handle.write(runtime.canonical(output))
    print(json.dumps({"out": str(args.out), "successful_cold_runs": len(runs), "failures": len(failures)}))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
