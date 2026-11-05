"""Type-check recorded HTTP response bodies against the generated TypeScript API types (T08).

Each recorded JSON body becomes `const sampleN: Body<"operationId", status> = <body>;` in a temporary file next to
a copy of `apps/web/src/api/schema.d.ts`, compiled with the web app's own TypeScript in strict mode. Object
literals get excess-property checks, and a status without a JSON body type resolves to `never`, so a body the
generated types do not describe fails to compile.
"""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
import shutil
import subprocess

from policyops_testing.case_api import Recorded


ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "apps" / "web" / "src" / "api" / "schema.d.ts"
TSC = ROOT / "apps" / "web" / "node_modules" / "typescript" / "bin" / "tsc"
HEADER = """import type { operations } from "./schema";

type Responses<O extends keyof operations> = operations[O]["responses"];
type Body<O extends keyof operations, S extends keyof Responses<O>> =
    Responses<O>[S] extends { content: { "application/json": infer B } } ? B : never;
"""
FLAGS = ["--noEmit", "--strict", "--exactOptionalPropertyTypes", "--noUncheckedIndexedAccess", "--target", "ES2023",
         "--module", "ESNext", "--moduleResolution", "bundler", "--verbatimModuleSyntax", "--isolatedModules"]


class ToolchainMissing(RuntimeError):
    pass


def compile_samples(samples: Iterable[Recorded], work: Path) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    if node is None or not TSC.is_file():
        raise ToolchainMissing("needs node on PATH and apps/web/node_modules (npm ci in apps/web)")
    work.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SCHEMA, work / "schema.d.ts")
    lines = [HEADER]
    for index, sample in enumerate(samples):
        if sample.body is not None:
            lines.append(f"export const sample{index}: Body<{json.dumps(sample.operation_id)}, {sample.status}> = "
                         f"{json.dumps(sample.body)};")
    (work / "samples.ts").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    return subprocess.run([node, str(TSC), *FLAGS, str(work / "samples.ts")], cwd=work, capture_output=True,
                          text=True, check=False, timeout=300)
