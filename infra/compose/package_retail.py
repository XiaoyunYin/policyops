"""Build-stage fixture/metadata staging; never copy the VCS cache into the runtime image."""

from __future__ import annotations

import base64
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path


# URL-safe, unpadded SHA-256 values from the pinned tau2 wheel's RECORD.
# These are judge configuration, not benchmark tasks, labels or data.
JUDGE_CONFIG_SHA256 = {
    "tau2/judges/nativeness_authoring_catalog.json": "RTXtzbE8g99e3C_Fy8wfFQLf9jZKPJVJN84VikuElVo",
    "tau2/judges/production_judges.json": "6qEw5ztN1nVyrvo5mPvZquuBr0Ofrv6eqMZK-oGMoO0",
}


def audit_payloads(tau: metadata.Distribution) -> None:
    if not tau.files:
        raise RuntimeError("installed tau2 file inventory missing")
    for relative in tau.files:
        name = str(relative).replace("\\", "/")
        if name in JUDGE_CONFIG_SHA256:
            expected = JUDGE_CONFIG_SHA256[name]
            recorded = relative.hash
            actual = base64.urlsafe_b64encode(hashlib.sha256(Path(relative.locate()).read_bytes()).digest())
            if (recorded is None or recorded.mode != "sha256" or recorded.value != expected
                    or actual.decode("ascii").rstrip("=") != expected):
                raise RuntimeError("installed tau2 judge configuration hash mismatch")
        elif name.startswith("tau2/") and ("/data/" in name or name.endswith((".json", ".jsonl", ".yaml", ".yml"))):
            raise RuntimeError("unexpected task/data payload in installed tau2 package")


def main() -> None:
    from policyops_evals.retail_sim import fixture

    tree = fixture.find_reviewed_tree(Path(os.environ["UV_CACHE_DIR"]))
    if tree is None:
        raise RuntimeError("frozen tau2 checkout missing")
    fixture.stage(tree, Path("/opt/fixture"))
    manifest = fixture.SOURCE_MANIFEST
    source = json.loads(manifest.read_bytes())
    # Only the fixture and its license are required by fixture.load(). No task IDs/labels.
    minimal = {"consumed": [row for row in source["consumed"] if row["path"] in fixture.STAGED]}
    manifest.write_text(json.dumps(minimal, indent=2) + "\n", encoding="utf-8")
    fixture.load(Path("/opt/fixture"))
    tau = metadata.distribution("tau2")
    # Audit the installed wheel too. Code and documentation are retained, hidden task/data payloads refuse build.
    audit_payloads(tau)


if __name__ == "__main__":
    main()
