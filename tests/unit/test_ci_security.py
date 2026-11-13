"""Parse CI and reject privilege, credential, provider and output-routing regressions."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]


CI = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"


def parse_workflow(text: str) -> dict[str, Any]:
    # BaseLoader keeps GitHub's `on` as a string (YAML 1.1 SafeLoader makes it
    # boolean). Compose nodes only: no constructors/custom tags can execute.
    def value(node: Any) -> Any:
        if node.id == "mapping":
            result = {}
            for key, child in node.value:
                assert key.id == "scalar" and key.value not in result, "duplicate/non-scalar workflow key"
                result[key.value] = value(child)
            return result
        if node.id == "sequence":
            return [value(child) for child in node.value]
        assert node.id == "scalar"
        return node.value

    result = value(yaml.compose(text, Loader=yaml.BaseLoader))
    assert isinstance(result, dict)
    return result


def enforce(workflow: dict[str, Any]) -> None:
    assert set(workflow["on"]) == {"push", "pull_request"}, "untrusted event boundary changed"
    assert workflow["permissions"] == {"contents": "read"}, "default permissions must be read-only"
    text = repr(workflow)
    assert not re.search(r"secrets\s*[.\[]|secrets['\"]?\s*:", text, re.I), "secret context/inheritance in CI"
    assert not re.search(r"OPENAI_|ANTHROPIC_|POLICYOPS_\w*(?:API_KEY|PASSWORD|SECRET)", text, re.I)
    assert not re.search(r"pull_request_target|--live\b|--paid\b|--allow-paid\b|--provider-smoke\b", text)
    assert "policyops_testing" in (CI.parents[2] / "tests/conftest.py").read_text(encoding="utf-8")
    jobs = workflow["jobs"]
    assert {"publication", "python", "postgres", "web"} <= jobs.keys()
    for job in jobs.values():
        assert "uses" not in job and "environment" not in job, "unreviewed reusable/deployment job"
        assert job.get("permissions", {}) in ({}, {"contents": "read"}), "job permissions widened"
        steps = job["steps"]
        routed = False
        for step in steps:
            assert "env" not in step or all("secrets" not in str(v) for v in step["env"].values())
            if "uses" in step:
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", step["uses"]), "action must be SHA pinned"
                if step["uses"].startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] == "false"
                    continue
            command = step.get("run", "")
            if 'root="$RUNNER_TEMP/policyops"' in command:
                assert not routed
                for assignment in ("POLICYOPS_TEMP_DIR=$root", "TEMP=$root/tmp", "TMP=$root/tmp",
                                   "TMPDIR=$root/tmp", "PYTHONDONTWRITEBYTECODE=1"):
                    assert assignment in command
                assert '>> "$GITHUB_ENV"' in command
                routed = True
            else:
                assert routed, "tool ran before temporary routing"
        assert routed
    all_commands = "\n".join(step.get("run", "") for job in jobs.values() for step in job["steps"])
    for required in ("check_publication.py --history", "gitleaks_gate.py history", "check_build_context.py",
                     "check_bundle.py", "check_repo_artifacts.py", "uv run --frozen pytest"):
        assert required in all_commands
    for job in (jobs["python"], jobs["postgres"]):
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        assert "scripts/devenv.py uv run --frozen pytest" in commands
        assert "fetch_tokenizer_vocab.py" in commands  # no tokenizer fetch by a test
    checkout = jobs["publication"]["steps"][0]
    assert checkout["with"]["fetch-depth"] == "0", "history scan must fetch all history"


def test_current_workflow_enforces_the_security_contract() -> None:
    enforce(parse_workflow(CI.read_text(encoding="utf-8")))


@pytest.mark.parametrize("attack", ["write", "job-write", "tag", "credential", "secret", "target", "paid",
                                  "routing", "late-routing", "history", "bundle"])
def test_workflow_policy_detects_unsafe_mutations(attack: str) -> None:
    config = deepcopy(parse_workflow(CI.read_text(encoding="utf-8")))
    steps = config["jobs"]["publication"]["steps"]
    if attack == "write":
        config["permissions"] = "write-all"
    elif attack == "job-write":
        config["jobs"]["python"]["permissions"] = {"id-token": "write"}
    elif attack == "tag":
        steps[0]["uses"] = "actions/checkout@v7"
    elif attack == "credential":
        steps[0]["with"]["persist-credentials"] = "true"
    elif attack == "secret":
        steps[-1]["env"] = {"KEY": "${{ secrets.PROVIDER }}"}
    elif attack == "target":
        config["on"]["pull_request_target"] = ""
    elif attack == "paid":
        steps[-1]["run"] += " --live"
    elif attack == "routing":
        steps[1]["run"] = steps[1]["run"].replace("TMP=$root/tmp", "TMP=/tmp")
    elif attack == "late-routing":
        steps[1], steps[2] = steps[2], steps[1]
    elif attack == "history":
        steps[0]["with"]["fetch-depth"] = "1"
    else:
        for step in config["jobs"]["web"]["steps"]:
            step["run"] = step.get("run", "").replace("check_bundle.py", "no_bundle_check.py")
    with pytest.raises(AssertionError):
        enforce(config)


def test_duplicate_yaml_keys_are_rejected() -> None:
    with pytest.raises(AssertionError, match="duplicate"):
        parse_workflow("permissions: {}\npermissions: write-all\n")
