"""Evaluator environment: pinned upstream, isolated from the application stack."""

from importlib import metadata, util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from policyops_contracts import CONTRACTS_SCHEMA_VERSION, WireModel
from policyops_evals import TAU2_COMMIT


PROBE = """
import json, os, sys
import tau2
from litellm.litellm_core_utils.get_model_cost_map import get_model_cost_map_source_info
print(json.dumps({"canary": os.environ.get("POLICYOPS_DOTENV_CANARY"),
                  "cost_map": get_model_cost_map_source_info()["source"]}))
"""


def test_tau2_installed_from_exact_pinned_commit() -> None:
    direct_url = json.loads(metadata.distribution("tau2").read_text("direct_url.json") or "{}")
    assert direct_url["url"] == "https://github.com/sierra-research/tau2-bench"
    assert direct_url["vcs_info"]["commit_id"] == TAU2_COMMIT


def test_installed_tau2_sources_keep_upstream_line_endings() -> None:
    # The pinned commit's src/tau2 files contain no CR bytes. Git for Windows'
    # core.autocrlf=true once made uv's checkout install CRLF copies, which changed
    # upstream's runtime_rules digest and the English retail binding revision.
    files = [file for file in metadata.distribution("tau2").files or [] if file.suffix == ".py"]
    assert files
    converted = [str(file) for file in files if b"\r" in Path(str(file.locate())).read_bytes()]
    assert converted == []


def test_knowledge_extra_only() -> None:
    for module in ("rank_bm25", "openai"):
        assert util.find_spec(module) is not None, module
    for module in ("elevenlabs", "deepgram", "pyaudio", "livekit", "aiortc"):
        assert util.find_spec(module) is None, module


def test_local_application_is_installed_for_narrow_composition() -> None:
    for module in ("policyops", "langgraph", "pydantic_settings"):
        assert util.find_spec(module) is not None, module
    direct = json.loads(metadata.distribution("policyops").read_text("direct_url.json") or "{}")
    assert direct["dir_info"]["editable"] is True


def test_litellm_below_upstream_cap() -> None:
    major, minor, patch = (int(part) for part in metadata.version("litellm").split(".")[:3])
    assert (major, minor, patch) < (1, 82, 7)


def test_shared_contracts_behave_identically() -> None:
    class Probe(WireModel):
        count: int

    assert CONTRACTS_SCHEMA_VERSION == "0.3.0"
    assert Probe.model_validate_json('{"count": 1}').count == 1
    for payload in ('{"count": "1"}', '{"count": 1, "extra": true}'):
        with pytest.raises(ValueError):
            Probe.model_validate_json(payload)


def run_probe(cwd: Path, *, dotenv_disabled: bool) -> dict[str, str | None]:
    env = dict(os.environ)
    if not dotenv_disabled:
        env.pop("PYTHON_DOTENV_DISABLED", None)
    result = subprocess.run(
        [sys.executable, "-c", PROBE], cwd=cwd, env=env, capture_output=True, text=True,
        check=True, timeout=300,
    )
    parsed: dict[str, str | None] = json.loads(result.stdout.strip().splitlines()[-1])
    return parsed


def test_tau2_import_does_not_load_dotenv_or_fetch_pricing(tmp_path: Path) -> None:
    # `python -c` makes python-dotenv search the working directory, as an
    # interactive evaluator session would.
    (tmp_path / ".env").write_text("POLICYOPS_DOTENV_CANARY=loaded\n", encoding="utf-8")
    assert run_probe(tmp_path, dotenv_disabled=False)["canary"] == "loaded"
    guarded = run_probe(tmp_path, dotenv_disabled=True)
    assert guarded == {"canary": None, "cost_map": "local"}
