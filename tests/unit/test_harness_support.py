"""Fake provider, clocks, seeds, redaction and evidence recording."""

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
from typing import Any

from pydantic import ValidationError
import pytest

from policyops_contracts.clock import FixedClock, SteppingClock, SystemClock
from policyops_contracts.evidence import CodeIdentity, EvidenceManifest
from policyops_contracts.timing import MAX_UTC
from policyops_testing import network, redaction
from policyops_testing.evidence import LAUNCH_ERROR_EXIT, EvidenceError, EvidenceRecorder, deterministic_digest
from policyops_testing.fake_provider import (
    FakeProvider,
    FakeProviderTimeout,
    FakeRequest,
    FakeResponse,
    Step,
    Timeout,
    UnexpectedRequest,
    Usage,
)
from policyops_testing.plugin import DEFAULT_SEED
from policyops_testing.postgres import (
    DATABASE,
    MIGRATOR,
    RUNTIME,
    SESSION_OPTIONS,
    CleanupUncertain,
    OwnedPostgres,
    PostgresUnavailable,
)


CODE = CodeIdentity(git_head="1" * 40, git_tree="2" * 40)
T0 = datetime(2026, 1, 1, tzinfo=UTC)
# Synthetic values are assembled at runtime so that neither source scanner (the publication guard, gitleaks)
# reports the test inputs themselves.
CANARY = "sk-" + "proj-SYNTHETICcanary" + "0" * 16


def synthetic(label: str) -> str:
    """A synthetic secret-like value, assembled at runtime so source scanners do not report the test input."""
    return f"{label}-SYNTHETIC"


def request(text: str) -> FakeRequest:
    return FakeRequest(model="fake-small", messages=(text,), max_output_tokens=64)


def reply(text: str) -> FakeResponse:
    return FakeResponse(kind="text", text=text, usage=Usage(input_tokens=10, output_tokens=3))


# ---- fake provider ----------------------------------------------------------------------------------


def test_fake_provider_answers_the_exact_scripted_sequence(
        fake_provider: Callable[[Sequence[Step]], FakeProvider]) -> None:
    tool = FakeResponse(kind="tool_call", tool_name="get_order_details",
                        tool_arguments_json='{"order_id": "#W0000001"}',
                        usage=Usage(input_tokens=20, output_tokens=8, cached_input_tokens=5, reasoning_tokens=2))
    provider = fake_provider([Step(request("hi"), reply("hello")), Step(request("look up"), tool),
                              Step(request("refuse?"), FakeResponse(kind="refusal", usage=Usage(5, 1))),
                              Step(request("long"), FakeResponse(kind="truncated", text="...", usage=Usage(5, 64)))])
    assert provider.complete(request("hi")).text == "hello"
    assert provider.complete(request("look up")).tool_name == "get_order_details"
    assert provider.complete(request("refuse?")).kind == "refusal"
    assert provider.complete(request("long")).kind == "truncated"
    assert provider.calls == [request("hi"), request("look up"), request("refuse?"), request("long")]


def test_unexpected_extra_and_leftover_requests_fail() -> None:
    mismatch = FakeProvider(script=(Step(request("a"), reply("x")),))
    with pytest.raises(UnexpectedRequest, match="differs"):
        mismatch.complete(request("b"))
    extra = FakeProvider(script=(Step(request("a"), reply("x")),))
    extra.complete(request("a"))
    with pytest.raises(UnexpectedRequest, match="not scripted"):
        extra.complete(request("a"))
    leftover = FakeProvider(script=(Step(request("a"), reply("x")), Step(request("b"), reply("y"))))
    leftover.complete(request("a"))
    with pytest.raises(UnexpectedRequest, match="never sent"):
        leftover.assert_exhausted()


def test_a_caught_mismatch_still_fails_exhaustion() -> None:
    provider = FakeProvider(script=(Step(request("a"), reply("x")),))
    with pytest.raises(UnexpectedRequest):
        provider.complete(request("b"))  # e.g. swallowed by the code under test
    assert provider.calls == [request("b")] and provider.consumed == 0 and provider.remaining == 1
    with pytest.raises(UnexpectedRequest, match="1 unexpected request"):
        provider.assert_exhausted()
    assert provider.complete(request("a")).text == "x"  # the script did not advance on the mismatch
    assert provider.remaining == 0
    with pytest.raises(UnexpectedRequest, match="differs from script step #1"):
        provider.assert_exhausted()  # still fails: the mismatch is never forgotten


def test_fixture_teardown_fails_after_a_caught_mismatch() -> None:
    from policyops_testing.plugin import fake_provider as fixture

    generator = fixture.__wrapped__()  # type: ignore[attr-defined]
    make = next(generator)
    provider = make([Step(request("a"), reply("x"))])
    with pytest.raises(UnexpectedRequest):
        provider.complete(request("b"))
    with pytest.raises(UnexpectedRequest, match="unexpected request"):
        next(generator)


def test_timeouts_are_raised_once_without_retry_and_carry_billed_usage() -> None:
    provider = FakeProvider(script=(Step(request("a"), Timeout(billed=Usage(10, 0))),
                                    Step(request("b"), Timeout())))
    with pytest.raises(FakeProviderTimeout) as billed:
        provider.complete(request("a"))
    assert billed.value.billed == Usage(10, 0)
    with pytest.raises(FakeProviderTimeout) as unknown:
        provider.complete(request("b"))
    assert unknown.value.billed is None
    assert len(provider.calls) == 2 and provider.remaining == 0
    provider.assert_exhausted()


@pytest.mark.parametrize("bad", [dict(input_tokens=-1, output_tokens=0), dict(input_tokens=True, output_tokens=0),
                                 dict(input_tokens=5, output_tokens=1, cached_input_tokens=6),
                                 dict(input_tokens=5, output_tokens=1, reasoning_tokens=2)])
def test_usage_is_validated(bad: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        Usage(**bad)


def test_tool_call_shape_is_validated() -> None:
    with pytest.raises(ValueError):
        FakeResponse(kind="tool_call", usage=Usage(1, 1))
    with pytest.raises(ValueError):
        FakeResponse(kind="text", tool_name="x", tool_arguments_json="{}", usage=Usage(1, 1))


# ---- clocks and seeds ---------------------------------------------------------------------------------


def test_clocks_are_utc_and_only_move_forward() -> None:
    clock = FixedClock(T0)
    assert clock.now() == T0 and clock.advance(timedelta(seconds=5)) == T0 + timedelta(seconds=5)
    for bad in (datetime(2026, 1, 1), datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1)))):
        with pytest.raises(ValueError):
            FixedClock(bad)
    for step in (timedelta(0), timedelta(seconds=-1)):
        with pytest.raises(ValueError):
            clock.advance(step)
        with pytest.raises(ValueError):
            SteppingClock(T0, step)
    with pytest.raises(OverflowError):
        FixedClock(MAX_UTC - timedelta(seconds=1)).advance(timedelta(seconds=2))
    stepping = SteppingClock(T0, timedelta(milliseconds=10))
    assert [stepping.now() for _ in range(3)] == [T0 + timedelta(milliseconds=10 * i) for i in range(3)]
    assert SystemClock().now().tzinfo is UTC


class _SeasonalZone(tzinfo):
    """Offset 0 in January, +1 h from April: a zero offset at construction does not make a zone UTC."""

    def utcoffset(self, dt: datetime | None) -> timedelta:
        return timedelta(hours=1) if dt is not None and dt.month >= 4 else timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str:
        return "SEASONAL"


def test_zero_offset_zones_are_normalized_to_utc() -> None:
    start = datetime(2026, 1, 1, tzinfo=_SeasonalZone())
    fixed, stepping = FixedClock(start), SteppingClock(start, timedelta(days=90))
    assert fixed.now().tzinfo is UTC and fixed.now() == T0
    later = fixed.advance(timedelta(days=180))
    assert later.tzinfo is UTC and later.utcoffset() == timedelta(0) and later == T0 + timedelta(days=180)
    readings = [stepping.now() for _ in range(3)]
    assert all(reading.tzinfo is UTC for reading in readings)
    assert readings == [T0 + timedelta(days=90 * i) for i in range(3)]


def test_seed_is_deterministic_and_applied_before_each_test(seed: int) -> None:
    assert seed == int(os.environ.get("POLICYOPS_TEST_SEED", DEFAULT_SEED))
    # Determinism of test data, not cryptography.
    expected = random.Random(seed)  # noqa: S311
    assert [random.random() for _ in range(3)] == [expected.random() for _ in range(3)]  # noqa: S311


# ---- redaction -------------------------------------------------------------------------------------------


def test_argv_and_text_redaction_on_synthetic_values() -> None:
    argv = ["tool", "--password=" + synthetic("hunter2"), "--api-key", synthetic("abc123"),
            "--token", synthetic("t0k3n"), "--name=visible", f"--model-key-like={CANARY}"]
    redacted = redaction.redact_argv(argv)
    assert redacted[:7] == ("tool", "--password=[REDACTED]", "--api-key", "[REDACTED]", "--token", "[REDACTED]",
                            "--name=visible")
    assert CANARY not in " ".join(redacted)
    text = ("Authorization: Bearer abcdefghijklmnop-SYNTHETIC\npostgresql://app:" + synthetic("pw")
            + "@127.0.0.1:5/db\n" + "ghp_" + "A" * 36 + " AKIA" + "B" * 16 + " password=topsecret-SYNTHETIC " + CANARY)
    cleaned = redaction.redact_text(text)
    for secret in ("abcdefghijklmnop-SYNTHETIC", synthetic("pw"), "ghp_" + "A" * 36, "AKIA" + "B" * 16,
                   "topsecret-SYNTHETIC", CANARY):
        assert secret not in cleaned
    assert "postgresql://app:" + redaction.MASK + "@127.0.0.1:5/db" in cleaned


def test_registered_values_and_environment_names_are_masked() -> None:
    redaction.register("fixture-pass-SYNTHETIC-1234")
    try:
        assert redaction.redact_text("pw is fixture-pass-SYNTHETIC-1234!") == "pw is [REDACTED]!"
    finally:
        redaction.forget("fixture-pass-SYNTHETIC-1234")
    env = {"OPENAI_API_KEY": "x", "DB_PASSWORD": "y", "PATH_HINT": f"a {CANARY}", "POLICYOPS_TEST_SEED": "1"}
    assert dict(redaction.redact_environment(env, env)) == {
        "DB_PASSWORD": "[REDACTED]", "OPENAI_API_KEY": "[REDACTED]", "PATH_HINT": "a [REDACTED]",
        "POLICYOPS_TEST_SEED": "1"}


# ---- evidence ---------------------------------------------------------------------------------------------


def recorder(root: Path, run_id: str = "run-1") -> EvidenceRecorder:
    return EvidenceRecorder(root, run_id=run_id, task_id="T05", purpose="harness test", seed=7,
                            clock=SteppingClock(T0, timedelta(seconds=1)))


def test_recorder_captures_failures_redacts_output_and_traces_metrics(tmp_path: Path) -> None:
    rec = recorder(tmp_path / "ev")
    assert rec.run("ok", [sys.executable, "-c", f"print('{CANARY}'); print(42)"]) == 0
    failing = [sys.executable, "-c", "import sys; sys.exit(3)", "--password=" + synthetic("hunter2")]
    assert rec.run("fails", failing) == 3
    assert rec.run("slow", [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5) != 0
    rec.write_artifact("raw/counts.json", b'{"passed": 2}', "output")
    rec.metric("passed_tests", 2, "tests", "raw/counts.json:passed", ["raw/counts.json"])
    manifest = rec.finish(CODE, environment=["POLICYOPS_TEST_SEED", "DB_PASSWORD"])
    assert [(f.step, f.kind) for f in manifest.failures] == [("fails", "nonzero_exit"), ("slow", "timeout")]
    assert "--password=[REDACTED]" in manifest.commands[1].argv
    stdout = (tmp_path / "ev" / "commands" / "ok.stdout.txt").read_text(encoding="utf-8")
    assert CANARY not in stdout and "42" in stdout
    persisted = (tmp_path / "ev" / "evidence-manifest.json").read_text(encoding="utf-8")
    assert CANARY not in persisted and "hunter2" not in persisted
    EvidenceManifest.model_validate_json(persisted)


def test_manifest_with_secret_like_content_is_refused(tmp_path: Path) -> None:
    rec = EvidenceRecorder(tmp_path / "ev", run_id="r", task_id="T05", purpose=f"leaks {CANARY}", seed=None)
    with pytest.raises(EvidenceError, match="secret-like"):
        rec.finish(CODE)
    assert not (tmp_path / "ev" / "evidence-manifest.json").exists()
    cleaned = redaction.redact_text('{"h": "Authorization: Bearer abcdefgh123", "n": 1}')
    assert "abcdefgh123" not in cleaned and json.loads(cleaned)["n"] == 1  # still valid JSON


def _files_under(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_secret_flag_and_env_values_never_reach_persisted_output(tmp_path: Path) -> None:
    opaque, env_value = synthetic("opaque0token"), synthetic("env0value")  # no recognizable credential format
    rec = recorder(tmp_path / "ev")
    rec.run("echo", [sys.executable, "-c", "import sys; print(sys.argv[-1])", "--token", opaque])
    rec.run("inline", [sys.executable, "-c", "import sys; print(sys.argv[-1].split('=')[1])", f"--api-key={opaque}"])
    minimal = {name: os.environ[name] for name in ("SYSTEMROOT", "PATH") if name in os.environ}
    rec.run("env", [sys.executable, "-c", "import os; print(os.environ['POLICYOPS_SYNTHETIC_TOKEN'])"],
            env={**minimal, "POLICYOPS_SYNTHETIC_TOKEN": env_value})
    rec.finish(CODE)
    files = _files_under(tmp_path / "ev")
    assert files["commands/echo.stdout.txt"].strip() == redaction.MASK.encode()
    assert files["commands/inline.stdout.txt"].strip() == redaction.MASK.encode()
    assert files["commands/env.stdout.txt"].strip() == redaction.MASK.encode()
    for name, data in files.items():  # every persisted file, the manifest included
        assert opaque.encode() not in data and env_value.encode() not in data, name


def test_secret_bearing_artifacts_are_refused_not_altered(tmp_path: Path) -> None:
    known = synthetic("registered0canary")
    rec = recorder(tmp_path / "ev")
    redaction.register(known)
    try:
        with pytest.raises(EvidenceError, match="known secret"):
            rec.write_artifact("reports/result.txt", f"value: {known}\n".encode(), "report")
        assert not (tmp_path / "ev" / "reports" / "result.txt").exists()
        with pytest.raises(EvidenceError, match="known secret"):
            rec.write_artifact("reports/auth.txt", b"Authorization: Bearer " + synthetic("bearer0value").encode(),
                               "report")
        raw = tmp_path / "ev" / "inputs" / "raw.bin"
        raw.parent.mkdir()
        raw.write_bytes(b"\x00\x01" + known.encode() + b"\xff")
        with pytest.raises(EvidenceError, match="known secret"):
            rec.add_artifact("inputs/raw.bin", "input")
        assert raw.read_bytes() == b"\x00\x01" + known.encode() + b"\xff"  # raw data is never rewritten
        rec.write_artifact("reports/clean.txt", b"later-registered-value-123\n", "report")
        redaction.register("later-registered-value-123")
        with pytest.raises(EvidenceError, match="known secret"):
            rec.finish(CODE)  # re-checked against values registered after recording
        assert not (tmp_path / "ev" / "evidence-manifest.json").exists()
    finally:
        redaction.forget(known, "later-registered-value-123")


@pytest.mark.parametrize("manifest_name", ["evidence-manifest.json", "outputs/out.txt", "Outputs/OUT.txt"])
def test_manifest_never_replaces_a_recorded_artifact(tmp_path: Path, manifest_name: str) -> None:
    rec = recorder(tmp_path / "ev")
    rec.write_artifact("evidence-manifest.json", b"recorded input", "input")
    rec.write_artifact("outputs/out.txt", b"recorded output", "output")
    before = _files_under(tmp_path / "ev")
    if manifest_name == "Outputs/OUT.txt" and sys.platform != "win32":
        manifest_name = "outputs/out.txt"  # case-insensitive aliasing only exists on Windows filesystems
    with pytest.raises(EvidenceError, match="collides"):
        rec.finish(CODE, manifest_name=manifest_name)
    assert _files_under(tmp_path / "ev") == before


def test_every_emitted_reference_matches_the_final_files(tmp_path: Path) -> None:
    rec = recorder(tmp_path / "ev")
    rec.write_artifact("evidence-manifest-input.json", b"{}", "input")
    rec.run("ok", [sys.executable, "-c", "print('done')"])
    manifest = rec.finish(CODE, manifest_name="reports/manifest.json")
    on_disk = EvidenceManifest.model_validate_json((tmp_path / "ev" / "reports" / "manifest.json").read_bytes())
    assert on_disk == manifest
    for artifact in on_disk.artifacts:
        data = (tmp_path / "ev" / artifact.path).read_bytes()
        assert (hashlib.sha256(data).hexdigest(), len(data)) == (artifact.sha256, artifact.size), artifact.path
    rec.verify()  # still consistent after the manifest was written


def test_artifact_changed_after_hashing_is_detected(tmp_path: Path) -> None:
    rec = recorder(tmp_path / "ev")
    rec.write_artifact("a.txt", b"one", "output")
    (tmp_path / "ev" / "a.txt").write_bytes(b"two")
    with pytest.raises(EvidenceError, match="changed"):
        rec.finish(CODE)


@pytest.mark.parametrize("path", ["/abs/file", "../escape", "a/../b", "C:/x", "a\\b", "./a", "a//b", ""])
def test_recorder_rejects_uncontained_paths(tmp_path: Path, path: str) -> None:
    with pytest.raises(EvidenceError):
        recorder(tmp_path / "ev").write_artifact(path, b"x", "output")


def _directory_link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def test_recorder_rejects_link_escapes(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"outside")
    rec = recorder(tmp_path / "ev")
    _directory_link(tmp_path / "ev" / "alias", outside)
    with pytest.raises(EvidenceError):
        rec.add_artifact("alias/secret.txt", "input")
    with pytest.raises(EvidenceError):
        rec.write_artifact("alias/new.txt", b"x", "output")
    assert sorted(path.name for path in outside.iterdir()) == ["secret.txt"]
    with pytest.raises(EvidenceError):
        EvidenceRecorder(tmp_path / "ev" / "alias", run_id="r", task_id="T05", purpose="p")


def test_recorder_root_is_checked_before_anything_is_created(tmp_path: Path,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    configured = tmp_path / "configured"
    configured.mkdir()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(configured))
    outside = tmp_path / "outside"
    outside.mkdir()
    _directory_link(configured / "alias", outside)
    for root in (tmp_path / "sibling" / "ev", configured / ".." / "traversal" / "ev", configured / "alias" / "ev"):
        with pytest.raises(EvidenceError):
            EvidenceRecorder(root, run_id="r", task_id="T05", purpose="p")
    assert not (tmp_path / "sibling").exists() and not (tmp_path / "traversal").exists()
    assert list(outside.iterdir()) == []
    rec = EvidenceRecorder(configured / "a" / "b", run_id="r", task_id="T05", purpose="p")
    assert rec.root.is_dir() and not rec.root.is_symlink()


@pytest.mark.parametrize("replace", ["root-with-link", "ancestor-with-link", "root-with-directory"])
def test_root_or_ancestor_replaced_after_construction_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                 replace: str) -> None:
    configured = tmp_path / "configured"
    configured.mkdir()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(configured))
    outside = tmp_path / "outside"
    (outside / "ev").mkdir(parents=True)
    rec = EvidenceRecorder(configured / "a" / "ev", run_id="r", task_id="T05", purpose="p")
    rec.write_artifact("before.txt", b"recorded", "output")
    if replace == "root-with-link":
        (configured / "a" / "ev").rename(configured / "a" / "ev-moved")
        _directory_link(configured / "a" / "ev", outside / "ev")
    elif replace == "ancestor-with-link":
        (configured / "a").rename(configured / "a-moved")
        _directory_link(configured / "a", outside)
    else:  # a different, real directory at the same path
        (configured / "a" / "ev").rename(configured / "a" / "ev-moved")
        (configured / "a" / "ev").mkdir()
    for attempt in (lambda: rec.write_artifact("escaped.txt", b"x", "output"),
                    lambda: rec.write_artifact("sub/escaped.txt", b"x", "output"),
                    lambda: rec.add_artifact("before.txt", "output"),
                    lambda: rec.run("cmd", [sys.executable, "-c", f"open({str(tmp_path / 'ran')!r}, 'w')"]),
                    lambda: rec.finish(CODE)):
        with pytest.raises(EvidenceError, match="replaced or removed"):
            attempt()
    assert [p.name for p in (outside / "ev").iterdir()] == [] and sorted(p.name for p in outside.iterdir()) == ["ev"]
    assert not (tmp_path / "ran").exists()  # the command never ran
    if replace == "root-with-directory":
        assert list((configured / "a" / "ev").iterdir()) == []


def test_explicitly_known_short_secrets_are_refused_without_side_effects(tmp_path: Path) -> None:
    short = "k" + "3y9q"  # 5 characters: too short to mask in ordinary output
    with pytest.raises(ValueError) as registered:
        redaction.register(short)
    assert short not in str(registered.value)
    assert redaction.redact_text(f"value {short}") == f"value {short}"  # nothing was registered
    rec = recorder(tmp_path / "ev")
    marker = tmp_path / "ran.txt"
    program = f"open({str(marker)!r}, 'w').write('ran')"
    minimal = {name: os.environ[name] for name in ("SYSTEMROOT", "PATH") if name in os.environ}
    for step, argv, env in (("flag", [sys.executable, "-c", program, "--token", short], None),
                            ("inline", [sys.executable, "-c", program, f"--api-key={short}"], None),
                            ("env", [sys.executable, "-c", program], {**minimal, "POLICYOPS_SYNTHETIC_TOKEN": short})):
        with pytest.raises(EvidenceError) as refused:
            rec.run(step, argv, env=env)
        assert short not in str(refused.value)
    assert not marker.exists()  # never executed
    assert not (tmp_path / "ev" / "commands").exists()  # nothing written
    rec.run("empty", [sys.executable, "-c", "print('ok')", "--token="])  # an empty value is not a secret to mask
    manifest = rec.finish(CODE)
    assert [c.step for c in manifest.commands] == ["empty"]
    for name, data in _files_under(tmp_path / "ev").items():
        assert short.encode() not in data, name


def test_writes_never_go_through_a_planted_temporary_sibling(tmp_path: Path) -> None:
    # The C1 recorder wrote to the predictable ".<name>.tmp" first; a hard link (no privilege needed) or a symlink
    # planted there would have redirected that write to a file outside the evidence root.
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    rec = recorder(tmp_path / "ev")
    planted = [tmp_path / "ev" / ".report.txt.tmp", tmp_path / "ev" / ".evidence-manifest.json.tmp"]
    for link in planted:
        os.link(outside, link)
    rec.write_artifact("report.txt", b"inside", "report")
    if sys.platform != "win32":
        (tmp_path / "ev" / ".other.txt.tmp").symlink_to(outside)
        rec.write_artifact("other.txt", b"inside", "report")
    rec.finish(CODE)
    assert outside.read_bytes() == b"outside"
    assert (tmp_path / "ev" / "report.txt").read_bytes() == b"inside"
    assert all(link.read_bytes() == b"outside" for link in planted)  # untouched, not reused
    leftovers = [p.name for p in (tmp_path / "ev").iterdir() if p.name.endswith(".tmp")]
    assert sorted(leftovers) == sorted([p.name for p in planted] + ([] if sys.platform == "win32"
                                                                     else [".other.txt.tmp"]))


def test_commands_that_cannot_start_are_recorded_as_failures(tmp_path: Path) -> None:
    rec = recorder(tmp_path / "ev")
    missing = str(tmp_path / "no-such-policyops-executable")
    assert rec.run("missing", [missing, "--password=" + synthetic("hunter2")]) == LAUNCH_ERROR_EXIT
    assert rec.run("directory", [str(tmp_path)]) == LAUNCH_ERROR_EXIT  # not executable: permission/start error
    manifest = rec.finish(CODE)
    assert [(c.step, c.exit_code) for c in manifest.commands] == [("missing", LAUNCH_ERROR_EXIT),
                                                                    ("directory", LAUNCH_ERROR_EXIT)]
    assert manifest.commands[0].argv == (missing, "--password=[REDACTED]")
    assert [(f.step, f.kind) for f in manifest.failures] == [("missing", "launch_error"),
                                                             ("directory", "launch_error")]
    assert manifest.failures[0].detail.startswith("could not start: FileNotFoundError")
    stderr = (tmp_path / "ev" / "commands" / "missing.stderr.txt").read_text(encoding="utf-8")
    assert stderr.startswith("could not start: FileNotFoundError") and "hunter2" not in stderr


def test_exit_code_minus_one_without_a_timeout_is_not_labelled_timeout(tmp_path: Path,
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    rec = recorder(tmp_path / "ev")
    if sys.platform != "win32":  # a real child killed by SIGHUP: subprocess reports -1, no TimeoutExpired
        assert rec.run("sighup", [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGHUP)"]) == -1
    assert rec.run("slow", [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5) == -1
    real_run = subprocess.run
    monkeypatch.setattr("policyops_testing.evidence.subprocess.run",
                        lambda argv, **kwargs: subprocess.CompletedProcess(argv, -1, b"", b""))
    assert rec.run("minus-one", [sys.executable, "-c", "pass"]) == -1  # the same code, reported by the child
    monkeypatch.setattr("policyops_testing.evidence.subprocess.run", real_run)
    kinds = {failure.step: failure.kind for failure in rec.finish(CODE).failures}
    expected = {"slow": "timeout", "minus-one": "nonzero_exit"}
    if sys.platform != "win32":
        expected["sighup"] = "nonzero_exit"
    assert kinds == expected


def test_metrics_must_be_exact_and_sourced(tmp_path: Path) -> None:
    rec = recorder(tmp_path / "ev")
    rec.write_artifact("raw.txt", b"1", "output")
    with pytest.raises(EvidenceError):
        rec.metric("m", 0.5, "ratio", "d", ["raw.txt"])  # type: ignore[arg-type]
    with pytest.raises(EvidenceError):
        rec.metric("m", Decimal("0.5"), "ratio", "d", ["missing.txt"])
    rec.metric("m", Decimal("0.5"), "ratio", "d", ["raw.txt"])


def test_deterministic_digest_ignores_run_ids_and_timestamps(tmp_path: Path) -> None:
    def build(name: str, start: datetime) -> EvidenceManifest:
        rec = EvidenceRecorder(tmp_path / name, run_id=name, task_id="T05", purpose="p", seed=7,
                               clock=SteppingClock(start, timedelta(seconds=1)))
        rec.write_artifact("out.txt", b"same", "output")
        rec.run("echo", [sys.executable, "-c", "print('same')"])
        return rec.finish(CODE)

    first, second = build("first", T0), build("second", T0 + timedelta(days=1))
    assert first.run_id != second.run_id and first.started_at != second.started_at
    assert deterministic_digest(first) == deterministic_digest(second)


def _manifest(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "run_id": "r1", "task_id": "T05", "purpose": "p", "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:01:00Z", "code": {"git_head": "1" * 40, "git_tree": "2" * 40},
        "artifacts": [{"path": "out/a.txt", "role": "output", "sha256": "a" * 64, "size": 1}],
        "commands": [{"step": "build", "argv": ["x"], "exit_code": 0, "started_at": "2026-01-01T00:00:10Z",
                      "finished_at": "2026-01-01T00:00:20Z", "outputs": ["out/a.txt"]}],
        "metrics": [{"name": "m", "value": "1.5", "unit": "u", "derivation": "d", "sources": ["a" * 64]}],
    }
    base.update(changes)
    return base


@pytest.mark.parametrize("edit", [
    lambda m: m["commands"][0].update(exit_code=1),
    lambda m: m.update(finished_at="2025-12-31T00:00:00Z"),
    lambda m: m["commands"][0].update(started_at="2025-12-31T00:00:00Z"),
    lambda m: m["artifacts"][0].update(path="/etc/passwd"),
    lambda m: m["artifacts"][0].update(path="../x"),
    lambda m: m["metrics"][0].update(sources=["b" * 64]),
    lambda m: m["metrics"][0].update(value="1e3"),
    lambda m: m["commands"][0].update(outputs=["out/missing.txt"]),
    lambda m: m.update(started_at="2026-01-01T00:00:00"),
])
def test_manifest_schema_rejects_inconsistent_records(edit: Any) -> None:
    EvidenceManifest.model_validate_json(json.dumps(_manifest()))
    data = _manifest()
    edit(data)
    with pytest.raises(ValidationError):
        EvidenceManifest.model_validate_json(json.dumps(data))


def test_startup_error_log_tails_are_redacted(tmp_path: Path) -> None:
    server = OwnedPostgres(root=tmp_path, run_id="tails", image="unused")
    (tmp_path / "log").mkdir()
    registered = "registered-canary-H6J2Z8"
    redaction.register(registered)
    try:
        (tmp_path / "log" / "initdb.log").write_text(f"initdb: problem near {registered}\n", encoding="utf-8")
        message = str(server._startup_error(f"failed with {registered}"))
    finally:
        redaction.forget(registered)
    assert registered not in message and message.count(redaction.MASK) == 2
    assert "<postgresql.log missing>" in message


class _NoLibpq:
    """Stands in for psycopg.connect: records calls and never opens a connection."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **params: Any) -> Any:
        self.calls.append(params)
        return self  # stands in for the connection; try_password() only closes it

    def close(self) -> None:
        pass


@pytest.fixture
def fake_libpq(monkeypatch: pytest.MonkeyPatch) -> _NoLibpq:
    fake = _NoLibpq()
    monkeypatch.setattr("policyops_testing.postgres.psycopg.connect", fake)
    return fake


@pytest.fixture
def unstarted_server(tmp_path: Path) -> Iterator[OwnedPostgres]:
    server = OwnedPostgres(root=tmp_path, run_id="target", image="unused", port=24123,
                           passwords={"postgres": "p", MIGRATOR: "m", RUNTIME: "r"})
    with network.allow("127.0.0.1", 24123):
        yield server


@pytest.mark.parametrize("override", [
    {"host": "192.0.2.123"}, {"port": 24224}, {"hostaddr": "192.0.2.123"}, {"service": "elsewhere"},
    {"user": "postgres"}, {"password": "x"}, {"options": "-c search_path=x"}, {"sslmode": "require"},
])
def test_connect_rejects_libpq_overrides_before_libpq(unstarted_server: OwnedPostgres, fake_libpq: _NoLibpq,
                                                      override: dict[str, Any]) -> None:
    with pytest.raises(TypeError):
        unstarted_server.connect(RUNTIME, **override)
    assert fake_libpq.calls == []


@pytest.mark.parametrize("dbname", ["host=192.0.2.123 port=24224 dbname=x", "postgresql://192.0.2.123:24224/x",
                                    "other_database"])
def test_connect_rejects_connection_strings_as_database_names(unstarted_server: OwnedPostgres,
                                                              fake_libpq: _NoLibpq, dbname: str) -> None:
    with pytest.raises(ValueError):
        unstarted_server.connect(RUNTIME, dbname)
    with pytest.raises(ValueError):
        unstarted_server.connect("intruder")
    with pytest.raises(ValueError):
        unstarted_server.connect(RUNTIME, connect_timeout=0)
    assert fake_libpq.calls == []


def test_connect_pins_startup_options_over_ambient_environment(unstarted_server: OwnedPostgres,
                                                               fake_libpq: _NoLibpq,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PGOPTIONS", "-c log_statement=all")
    monkeypatch.setenv("PGCLIENTENCODING", "LATIN1")
    monkeypatch.setenv("PGGSSENCMODE", "require")
    unstarted_server.connect("postgres", "postgres", autocommit=True)
    unstarted_server.try_password(RUNTIME, "wrong")
    for call in fake_libpq.calls:
        assert (call["options"], call["client_encoding"], call["gssencmode"], call["sslmode"]) == (
            SESSION_OPTIONS, "UTF8", "disable", "disable")
    assert "log_statement" not in SESSION_OPTIONS


def test_connect_targets_only_the_registered_endpoint(unstarted_server: OwnedPostgres, fake_libpq: _NoLibpq,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PGHOSTADDR", "192.0.2.123")  # libpq would use it if hostaddr were not pinned
    unstarted_server.connect(RUNTIME, autocommit=True)
    unstarted_server.try_password(RUNTIME, "wrong")
    for call, password in zip(fake_libpq.calls, ("r", "wrong"), strict=True):
        assert (call["host"], call["hostaddr"], call["port"], call["user"], call["dbname"], call["password"]) == (
            "127.0.0.1", "127.0.0.1", 24123, RUNTIME, DATABASE, password)
    unstarted_server.port = 24224  # not registered
    with pytest.raises(network.NetworkBlocked):
        unstarted_server.connect(RUNTIME)
    with pytest.raises(network.NetworkBlocked):
        unstarted_server.try_password(RUNTIME, "wrong")
    assert len(fake_libpq.calls) == 2


CONTAINER = "c" * 64


class _FakeDocker:
    """Stands in for the fixture's Docker CLI wrapper: scripted results, every call recorded, nothing executed."""

    def __init__(self, present: bool, *, unreachable: bool = False, timeout: bool = False) -> None:
        self.present, self.unreachable, self.timeout = present, unreachable, timeout
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        if self.timeout:
            raise subprocess.TimeoutExpired(["docker", *args], timeout)
        if self.unreachable:
            return subprocess.CompletedProcess(["docker", *args], 1, "", "Cannot connect to the Docker daemon")
        if args[0] == "ps":
            return subprocess.CompletedProcess(["docker", *args], 0, f"{CONTAINER}\n" if self.present else "", "")
        if args[0] == "inspect":
            labels = "policyops-tests cleanup /policyops-test-pg-cleanup\n"
            return subprocess.CompletedProcess(["docker", *args], 0, labels, "")
        if args[0] == "rm":
            self.present = False
            return subprocess.CompletedProcess(["docker", *args], 0, CONTAINER, "")
        raise AssertionError(f"unexpected docker call {args}")


def _server_with_container(tmp_path: Path) -> OwnedPostgres:
    return OwnedPostgres(root=tmp_path, run_id="cleanup", image="unused", container_id=CONTAINER)


@pytest.mark.parametrize("docker", [_FakeDocker(True, unreachable=True), _FakeDocker(True, timeout=True)],
                         ids=["daemon-unreachable", "timed-out"])
def test_unobservable_docker_keeps_the_container_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                    docker: _FakeDocker) -> None:
    monkeypatch.setattr("policyops_testing.postgres._docker", docker)
    server = _server_with_container(tmp_path)
    with pytest.raises(CleanupUncertain):
        server.stop()
    assert server.container_id == CONTAINER  # not reported as removed
    assert not [call for call in docker.calls if call[0] == "rm"]


def test_confirmed_absence_and_verified_removal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gone = _FakeDocker(False)
    monkeypatch.setattr("policyops_testing.postgres._docker", gone)
    server = _server_with_container(tmp_path)
    server.stop()
    assert server.container_id == "" and [call[0] for call in gone.calls] == ["ps"]
    running = _FakeDocker(True)
    monkeypatch.setattr("policyops_testing.postgres._docker", running)
    server = _server_with_container(tmp_path)
    server.stop()
    assert server.container_id == ""
    assert [call[0] for call in running.calls] == ["ps", "inspect", "rm", "ps"]
    assert ("rm", "-f", "-v", CONTAINER) in running.calls


class _PgpassDocker:
    """Scripted Docker for _exec_with_pgpass: each step returns an exit code or raises; every call is recorded."""

    def __init__(self, **outcomes: int | type[BaseException]) -> None:
        self.outcomes = {"write": 0, "tool": 0, "rm": 0, "test": 1, **outcomes}
        self.calls: list[tuple[tuple[str, ...], str | None]] = []

    def __call__(self, *args: str, timeout: float = 120, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        self.calls.append((args, stdin))
        step = _pgpass_step(args)
        outcome = self.outcomes[step]
        if isinstance(outcome, type):
            raise subprocess.TimeoutExpired(["docker", *args], timeout) if outcome is subprocess.TimeoutExpired \
                else outcome("synthetic")
        return subprocess.CompletedProcess(["docker", *args], outcome, "", "synthetic stderr")

    def steps(self) -> list[str]:
        return [_pgpass_step(args) for args, _ in self.calls]


def _pgpass_step(args: tuple[str, ...]) -> str:
    # ("exec", "-i", id, "sh", ...) writes; ("exec", id, "rm"|"test", ...) cleans up; ("exec", "-e", ...) runs the tool.
    return "write" if args[1] == "-i" else args[2] if args[2] in ("rm", "test") else "tool"


PGPASS_PASSWORD = "superuser-" + "SYNTHETIC0password"


@pytest.mark.parametrize(("outcomes", "raised", "steps"), [
    ({}, None, ["write", "tool", "rm", "test"]),
    ({"write": subprocess.TimeoutExpired}, subprocess.TimeoutExpired, ["write", "rm", "test"]),
    ({"write": 1}, PostgresUnavailable, ["write", "rm", "test"]),
    ({"tool": 1}, PostgresUnavailable, ["write", "tool", "rm", "test"]),
    ({"rm": 1}, CleanupUncertain, ["write", "tool", "rm"]),
    ({"rm": subprocess.TimeoutExpired}, CleanupUncertain, ["write", "tool", "rm"]),
    ({"rm": OSError}, CleanupUncertain, ["write", "tool", "rm"]),
    ({"test": 0}, CleanupUncertain, ["write", "tool", "rm", "test"]),  # still exists after rm
    ({"test": 125}, CleanupUncertain, ["write", "tool", "rm", "test"]),  # existence unknown
    ({"write": subprocess.TimeoutExpired, "rm": 1}, CleanupUncertain, ["write", "rm"]),
    ({"tool": 1, "test": 0}, CleanupUncertain, ["write", "tool", "rm", "test"]),
], ids=["ok", "write-timeout", "write-fails", "tool-fails", "rm-fails", "rm-timeout", "rm-oserror", "still-present",
        "check-unknown", "write-timeout-and-rm-fails", "tool-fails-and-still-present"])
def test_pgpass_cleanup_is_always_attempted_and_confirmed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                         outcomes: dict[str, Any], raised: type[BaseException] | None,
                                                         steps: list[str]) -> None:
    """C1 finding F3: the transient credential file is removed and its absence confirmed on every path; an
    unconfirmed removal is never reported as success, and a primary failure stays attached as context."""
    docker = _PgpassDocker(**outcomes)
    monkeypatch.setattr("policyops_testing.postgres._docker", docker)
    server = OwnedPostgres(root=tmp_path, run_id="pgpass", image="unused", container_id=CONTAINER,
                           passwords={"postgres": PGPASS_PASSWORD})
    if raised is None:
        server._exec_with_pgpass("pg_dump", "--version")
    else:
        with pytest.raises(raised) as error:
            server._exec_with_pgpass("pg_dump", "--version")
        assert PGPASS_PASSWORD not in str(error.value)
        primary_failed = outcomes.get("write", 0) != 0 or outcomes.get("tool", 0) != 0
        if raised is CleanupUncertain and primary_failed:
            assert error.value.__context__ is not None and "already failed" in str(error.value)
    assert docker.steps() == steps
    paths = {args[-1] for args, _ in docker.calls if "rm" in args or "test" in args}
    assert len(paths) == 1 and next(iter(paths)).startswith("/var/lib/postgresql/data/secrets/pgpass-")
    assert all(PGPASS_PASSWORD not in " ".join(args) for args, _ in docker.calls)  # never in argv
    assert [stdin for _, stdin in docker.calls if stdin] == [f"127.0.0.1:5432:*:postgres:{PGPASS_PASSWORD}\n"]


# -- Dex fixture secret cleanup (T07 review F1) ----------------------------------------------------------------

@dataclass
class FakeDocker:
    """Docker as the Dex fixture sees it: a registry of containers by ID, with labels and names."""

    run_error: str = "synthetic run failure"
    run_fails: bool = False
    run_creates: bool = False          # a failed run still created this run's container (a partial create)
    rm_fails: bool = False
    inspect_error: str | None = None   # a name lookup that fails for another reason than "no such container"
    containers: dict[str, dict[str, str]] = field(default_factory=dict)
    removed: list[str] = field(default_factory=list)
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def add(self, name: str, owner: str = "", run: str = "") -> str:
        container_id = f"{len(self.containers) + 1:064x}"
        self.containers[container_id] = {"name": f"/{name}", "owner": owner or "<no value>", "run": run or "<no value>"}
        return container_id

    def by_name(self, name: str) -> str | None:
        return next((cid for cid, c in self.containers.items() if c["name"] == f"/{name}"), None)

    def __call__(self, *args: str, timeout: float = 120, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)

        def done(code: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(["docker", *args], code, out, err)

        if args[:2] == ("image", "inspect"):
            return done()
        if args[0] == "run" and self.run_fails:
            name = args[args.index("--name") + 1]
            run_label = next(a for a in args if a.startswith("policyops.run="))
            if self.run_creates and self.by_name(name) is None:
                self.add(name, "policyops-tests", run_label.split("=", 1)[1])
            return done(125, err=self.run_error)
        if args[:2] == ("container", "inspect"):
            if self.inspect_error is not None:
                return done(1, err=self.inspect_error)
            cid = self.by_name(args[-1])
            if cid is None:
                return done(1, err=f"Error: No such container: {args[-1]}")
            c = self.containers[cid]
            return done(out=f"{cid} {c['owner']} {c['run']} {c['name']}\n")
        if args[:2] == ("ps", "-a"):
            wanted = args[-1].split("=", 1)[1]
            return done(out="\n".join(cid for cid in self.containers if cid == wanted))
        if args[0] == "inspect" and args[1] == "-f":
            labelled = self.containers.get(args[-1])
            if labelled is None:
                return done(1, err="No such object")
            return done(out=f"{labelled['owner']} {labelled['run']} {labelled['name']}")
        if args[:3] == ("rm", "-f", "-v"):
            if not self.rm_fails:
                self.containers.pop(args[3], None)
                self.removed.append(args[3])
            return done(1 if self.rm_fails else 0)
        raise AssertionError(f"unexpected docker call {args[:2]}")


def _dex_without_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, run_fails: bool = False,
                        **behaviour: Any) -> Any:
    from policyops_testing import dex as dex_module
    from policyops_testing import postgres as postgres_module

    fake = FakeDocker(run_fails=run_fails, **behaviour)
    monkeypatch.setattr(dex_module, "_docker", fake)
    monkeypatch.setattr(postgres_module, "_docker", fake)  # `_observe` / `_container_exists` (the guarded removal)
    root = tmp_path / "dex"
    root.mkdir()
    server = dex_module.OwnedDex(root=root, run_id="cleanup", redirect_uri="http://127.0.0.1:8000/cb",
                                 image="unused")
    server.fake = fake  # type: ignore[attr-defined]
    return server


@pytest.mark.parametrize("wording", ["Bind for 127.0.0.1:1234 failed: port is already allocated",
                                     "failed to bind host port 127.0.0.1:1234/tcp: address already in use"])
def test_a_dex_port_collision_is_retried_and_each_owned_partial_create_removed_by_id(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wording: str) -> None:
    """Both Docker wordings of a lost port race (Linux, Docker Desktop on Windows) are retried; the container each
    failed run created for this run is removed by its ID through the guarded removal."""
    from policyops_testing.dex import DexUnavailable

    server = _dex_without_docker(tmp_path, monkeypatch, run_fails=True, run_error=wording, run_creates=True)
    with pytest.raises(DexUnavailable, match="no free loopback port"):
        server.start()
    assert len(server.fake.removed) == 3 and server.fake.containers == {}
    assert not any(call[:2] == ("rm", "-f") and server.name in call for call in server.fake.calls)  # never by name


def test_a_failed_run_that_created_nothing_removes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops_testing.dex import DexUnavailable

    server = _dex_without_docker(tmp_path, monkeypatch, run_fails=True)
    with pytest.raises(DexUnavailable, match="synthetic run failure"):
        server.start()
    assert server.fake.removed == []


@pytest.mark.parametrize(("owner", "run"), [("", ""), ("someone-else", "cleanup"), ("policyops-tests", "other-run")])
def test_a_foreign_or_mismatched_container_under_our_name_is_never_removed(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner: str, run: str) -> None:
    from policyops_testing.dex import DexUnavailable

    server = _dex_without_docker(tmp_path, monkeypatch, run_fails=True,
                                 run_error="Conflict. The container name is already in use")
    foreign = server.fake.add(server.name, owner, run)
    with pytest.raises(DexUnavailable, match="not this run's"):
        server.start()
    assert foreign in server.fake.containers and server.fake.removed == []
    assert not any(call[0] == "rm" for call in server.fake.calls)


def test_failed_cleanup_of_an_owned_partial_create_is_reported(tmp_path: Path,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops_testing.dex import DexUnavailable
    from policyops_testing.postgres import CleanupUncertain

    server = _dex_without_docker(tmp_path, monkeypatch, run_fails=True, run_creates=True, rm_fails=True)
    with pytest.raises(DexUnavailable, match="was not removed"):
        server.start()
    assert len(server.fake.containers) == 1  # reported, not assumed gone
    (tmp_path / "second").mkdir()
    unclear = _dex_without_docker(tmp_path / "second", monkeypatch, run_fails=True,
                                  inspect_error="Cannot connect to the Docker daemon")
    with pytest.raises(CleanupUncertain, match="cannot inspect"):
        unclear.start()
    assert unclear.fake.removed == []


def test_a_failed_dex_secret_write_leaves_no_secret_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = _dex_without_docker(tmp_path, monkeypatch)
    real_write = Path.write_text

    def failing_write(self: Path, data: str, *args: Any, **kwargs: Any) -> int:
        if self.name == "bob":
            raise OSError("synthetic write failure")
        return real_write(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", failing_write)
    with pytest.raises(OSError, match="synthetic write failure"):
        server.start()
    assert list((server.root / "secrets").iterdir()) == [] and not (server.root / "data" / "config.yaml").exists()
    assert server.client_secret and redaction.redact_text(server.client_secret) == server.client_secret  # forgotten


def test_a_failed_dex_start_removes_written_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops_testing.dex import DexUnavailable

    server = _dex_without_docker(tmp_path, monkeypatch, run_fails=True)
    with pytest.raises(DexUnavailable, match="synthetic run failure"):
        server.start()
    assert list((server.root / "secrets").iterdir()) == []


def test_unconfirmed_dex_secret_cleanup_is_reported_with_the_primary_error(tmp_path: Path,
                                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops_testing.dex import DexUnavailable

    server = _dex_without_docker(tmp_path, monkeypatch, run_fails=True)
    real_unlink = Path.unlink

    def stuck_unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name == "alice":
            raise PermissionError("synthetic: cannot remove")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", stuck_unlink)
    with pytest.raises(CleanupUncertain, match="secrets/alice") as raised:
        server.start()
    assert isinstance(raised.value.__context__, DexUnavailable)  # the primary failure is kept
    assert server.passwords["alice"] not in str(raised.value)
    monkeypatch.setattr(Path, "unlink", real_unlink)
    (server.root / "secrets" / "alice").unlink()  # the test's own synthetic leftover
