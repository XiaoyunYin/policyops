"""Pinned gitleaks gate and hook ordering, exercised in isolated repositories.

Synthetic secrets are generated at run time, so the scanner configuration needs
no allowlist for test fixtures; its only allowlist is the reviewed exact corpus-key
exception, tested here in both directions. Hook tests require the verified scanner
(`python -B scripts/gitleaks_gate.py install`); they fail rather than skip.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import string
import subprocess
import sys
import tempfile
import tomllib
from typing import Any
import unittest
from unittest import mock
import zipfile


REPO = Path(__file__).resolve().parents[2]
GATE = REPO / "scripts" / "gitleaks_gate.py"
HOOKS = REPO / ".githooks"
_spec = importlib.util.spec_from_file_location("policyops_gitleaks_gate", GATE)
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

ALNUM = string.ascii_letters + string.digits
# The reviewed allowlist's two public identifiers and two files, assembled at run time so this
# source file's own assignments cannot match generic-api-key when the repository is scanned.
CORPUS_KEYS = tuple("tau2-" + name for name in ("banking-knowledge", "retail-policy"))
CORPUS_KEY_PATHS = ("evals/src/policyops_evals/ingest_manifest.py", "evals/manifests/tau2-19f13ea3/ingest-corpora.json")
# Runs the gate and records, through audit hooks, every directory it creates and
# the TEMP/TMP/TMPDIR handed to each child process, whichever API created them.
RECORDING_DRIVER = r'''
import json, os, runpy, sys
record, script = sys.argv[1], sys.argv[2]
made, children = [], []
def audit(event, args):
    if event == "os.mkdir":
        made.append(os.fsdecode(args[0]))
    elif event == "subprocess.Popen":
        env = args[3]
        children.append(None if env is None else {k: env.get(k) for k in ("TEMP", "TMP", "TMPDIR")})
sys.addaudithook(audit)
sys.argv = [script, *sys.argv[3:]]
try:
    runpy.run_path(script, run_name="__main__")
    code = 0
except SystemExit as exc:
    code = exc.code
with open(record, "w", encoding="utf-8") as handle:
    json.dump({"made": made, "children": children}, handle)
raise SystemExit(code)
'''


def random_text(length: int) -> str:
    return "".join(secrets.choice(ALNUM) for _ in range(length))


def stripe_like_key() -> str:
    # Detected by gitleaks' default rules but not by check_publication.py's
    # patterns, so a block proves the scanner ran after the guard passed.
    return "sk_" + "live_" + random_text(32)


class TempRepo:
    def __init__(self, test: unittest.TestCase) -> None:
        self._temp = tempfile.TemporaryDirectory(
            prefix="policyops-gitleaks-", dir=os.environ.get("POLICYOPS_TEMP_DIR"),
        )
        test.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name) / "work"
        self.root.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GITLEAKS_"))}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "-q")
        self.git("config", "user.email", "gate-test@example.invalid")
        self.git("config", "user.name", "Gate test")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "core.hooksPath", HOOKS.as_posix())

    def run(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(args), cwd=self.root, env=env or self.env, text=True, capture_output=True,
        )

    def git(self, *args: str) -> str:
        result = self.run("git", *args)
        if result.returncode != 0:
            raise AssertionError(f"git {args} failed: {result.stderr}")
        return result.stdout

    def write(self, name: str, content: str) -> None:
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def stage(self, name: str, content: str) -> None:
        self.write(name, content)
        self.git("add", "--", name)

    def commit(self, message: str = "fixture", env: dict[str, str] | None = None,
               verify: bool = True) -> subprocess.CompletedProcess[str]:
        args = ["git", "commit", "-qm", message] + ([] if verify else ["--no-verify"])
        return self.run(*args, env=env)


class GitleaksHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            gate.resolve_binary(gate.platform_key())
        except gate.GateError as exc:
            raise AssertionError(f"verified gitleaks unavailable: {exc}") from exc

    def assert_blocked_by_scanner(self, result: subprocess.CompletedProcess[str], secret: str) -> None:
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("Publication boundary passed", output)
        self.assertIn("rule=stripe-access-token", output)
        self.assertNotIn(secret, output)

    def test_clean_commit_runs_guard_then_scanner(self) -> None:
        repo = TempRepo(self)
        repo.stage("apps/readme.txt", "safe content\n")
        result = repo.commit()
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertLess(output.index("Publication boundary passed"),
                        output.index("gitleaks 8.30.1 staged scan passed"))

    def test_scanner_blocks_secret_the_guard_does_not_know(self) -> None:
        repo = TempRepo(self)
        secret = stripe_like_key()
        repo.stage("apps/config.txt", f'payment_key = "{secret}"\n')
        self.assert_blocked_by_scanner(repo.commit(), secret)
        self.assertEqual(repo.run("git", "rev-list", "--all").stdout, "")

    def test_guard_failure_stops_before_scanner(self) -> None:
        repo = TempRepo(self)
        repo.stage("PLAN.md", "private\n")
        result = repo.commit()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private path", result.stderr)
        self.assertNotIn("gitleaks", result.stdout + result.stderr)

    def test_missing_or_unverified_scanner_fails_closed(self) -> None:
        missing = Path(os.environ["POLICYOPS_TEMP_DIR"]) / "missing-gitleaks.exe"
        for binary in (str(missing), sys.executable):
            with self.subTest(binary=binary):
                repo = TempRepo(self)
                repo.stage("apps/readme.txt", "safe content\n")
                result = repo.commit(env={**repo.env, "POLICYOPS_GITLEAKS": binary})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("gitleaks gate failed closed", result.stderr)

    def test_inline_allow_and_env_config_cannot_suppress(self) -> None:
        repo = TempRepo(self)
        secret = stripe_like_key()
        permissive = Path(repo.root.parent / "permissive.toml")
        permissive.write_text('[allowlist]\npaths = [""".*"""]\n', encoding="utf-8")
        repo.stage("apps/config.txt", f'payment_key = "{secret}"  # gitleaks:allow\n')
        env = {**repo.env, "GITLEAKS_CONFIG": str(permissive),
               "GITLEAKS_CONFIG_TOML": permissive.read_text(encoding="utf-8")}
        self.assert_blocked_by_scanner(repo.commit(env=env), secret)

    def test_repository_ignore_file_fails_closed(self) -> None:
        # Regression: gitleaks reads <repo>/.gitleaksignore regardless of
        # --gitleaks-ignore-path, so a fingerprint there silently passed a secret.
        repo = TempRepo(self)
        secret = stripe_like_key()
        repo.write(".gitleaksignore", "apps/config.txt:stripe-access-token:1\n")
        repo.stage("apps/config.txt", f'payment_key = "{secret}"\n')
        result = repo.commit()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(".gitleaksignore", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_pre_push_scans_all_history_after_guard(self) -> None:
        repo = TempRepo(self)
        remote = repo.root.parent / "remote.git"
        repo.run("git", "init", "-q", "--bare", str(remote))
        repo.git("remote", "add", "origin", remote.as_posix())
        repo.stage("apps/readme.txt", "safe content\n")
        self.assertEqual(repo.commit().returncode, 0)
        clean_push = repo.run("git", "push", "-q", "origin", "HEAD:refs/heads/clean")
        self.assertEqual(clean_push.returncode, 0, clean_push.stderr)
        self.assertIn("gitleaks 8.30.1 history scan passed", clean_push.stdout + clean_push.stderr)

        secret = stripe_like_key()
        repo.stage("apps/config.txt", f'payment_key = "{secret}"\n')
        repo.commit("fixture: secret", verify=False)
        repo.stage("apps/config.txt", "payment_key = removed\n")
        repo.commit("fixture: remove secret", verify=False)
        result = repo.run("git", "push", "-q", "origin", "HEAD:refs/heads/main")
        self.assert_blocked_by_scanner(result, secret)
        self.assertIn("commit=", result.stderr)
        remote_refs = repo.run("git", "--git-dir", str(remote), "for-each-ref", "--format=%(refname)").stdout
        self.assertNotIn("refs/heads/main", remote_refs)

    def test_project_rule_flags_assignments_but_not_empty_placeholders(self) -> None:
        repo = TempRepo(self)
        # Assemble names at run time: a literal "NAME=\n..." in this source file
        # would itself match the rule when the repository is scanned.
        key = "POLICYOPS_SESSION_" + "SECRET="
        repo.stage(".env.example", "\n".join([key, "POLICYOPS_BUSINESS_API_URL=", ""]))
        clean = repo.run(sys.executable, "-B", str(GATE), "staged")
        self.assertEqual(clean.returncode, 0, clean.stderr)
        secret = random_text(40)
        repo.stage("apps/settings.env", key + secret + "\n")
        found = repo.run(sys.executable, "-B", str(GATE), "staged")
        self.assertEqual(found.returncode, 1)
        self.assertIn("rule=policyops-secret-assignment", found.stderr)
        self.assertNotIn(secret, found.stdout + found.stderr)

    def test_corpus_key_exception_admits_only_the_two_exact_identifiers_in_the_two_files(self) -> None:
        # The reviewed allowlist (.gitleaks.toml): public corpus_key values that generic-api-key misreads.
        legit = "".join(f'{{"corpus_key": "{key}", "domain": "d"}},\n' for key in CORPUS_KEYS)
        repo = TempRepo(self)
        for path in CORPUS_KEY_PATHS:
            repo.stage(path, legit)
        clean = repo.run(sys.executable, "-B", str(GATE), "staged")
        self.assertEqual(clean.returncode, 0, clean.stderr)
        blocked: list[tuple[str, str, str | None]] = [("apps/other_manifest.py", legit, None)]  # elsewhere
        for path in CORPUS_KEY_PATHS:
            secret = random_text(32)
            blocked.append((path, legit + f'api_key = "{secret}"\n', secret))  # a real secret beside them
            lookalike = f"{CORPUS_KEYS[0]}-{random_text(20)}"
            blocked.append((path, f'{{"corpus_key": "{lookalike}"}}\n', lookalike))  # not an exact identifier
        for case, (path, content, generated) in enumerate(blocked):  # labels never carry generated values
            with self.subTest(case=case, path=path):
                repo = TempRepo(self)
                repo.stage(path, content)
                found = repo.run(sys.executable, "-B", str(GATE), "staged")
                self.assertEqual(found.returncode, 1, found.stdout + found.stderr)
                self.assertIn(f"{path}:", found.stderr)
                self.assertIn("rule=generic-api-key", found.stderr)
                if generated is not None:
                    self.assertNotIn(generated, found.stdout + found.stderr)
        repo = TempRepo(self)
        secret = stripe_like_key()
        repo.stage(CORPUS_KEY_PATHS[0], legit + f'payment_key = "{secret}"\n')  # other rules are not allowlisted
        self.assert_blocked_by_scanner(repo.commit(), secret)

    def test_non_ascii_history_metadata_is_reported_not_crashed(self) -> None:
        # Regression: scanner JSON (UTF-8, including commit author names) was
        # decoded with the locale code page, e.g. cp936, instead of UTF-8.
        repo = TempRepo(self)
        repo.git("config", "user.name", "Zoë 测试 ✓")
        secret = stripe_like_key()
        repo.stage("apps/config.txt", f'payment_key = "{secret}"\n')
        repo.commit("fixture: secret", verify=False)
        result = repo.run(sys.executable, "-B", str(GATE), "history")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("rule=stripe-access-token", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_history_of_empty_repository_passes(self) -> None:
        repo = TempRepo(self)
        result = repo.run(sys.executable, "-B", str(GATE), "history")
        self.assertEqual(result.returncode, 0, result.stderr)


class GitleaksTempRootTests(unittest.TestCase):
    """Regression: scanner scratch followed the caller's TEMP/TMP, and a configured
    POLICYOPS_GITLEAKS let scans run without any validated temporary root."""

    binary: str

    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.binary = str(gate.resolve_binary(gate.platform_key()))
        except gate.GateError as exc:
            raise AssertionError(f"verified gitleaks unavailable: {exc}") from exc

    def setUp(self) -> None:
        self.repo = TempRepo(self)
        self.repo.stage("apps/readme.txt", "safe content\n")
        self.declared = self.repo.root.parent / "declared-root"
        self.inherited = self.repo.root.parent / "inherited-temp"
        self.inherited.mkdir()
        # The scanner is configured explicitly, so only the temp root is missing.
        self.env = {k: v for k, v in self.repo.env.items() if k != "POLICYOPS_TEMP_DIR"}
        self.env.update(POLICYOPS_GITLEAKS=self.binary, TEMP=str(self.inherited), TMP=str(self.inherited),
                        TMPDIR=str(self.inherited))

    def run_recorded(self, env: dict[str, str], mode: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        record = self.repo.root.parent / "record.json"
        result = self.repo.run(sys.executable, "-B", "-c", RECORDING_DRIVER, str(record), str(GATE), mode, env=env)
        recorded: dict[str, Any] = json.loads(record.read_text(encoding="utf-8"))
        return result, recorded

    def test_scratch_and_child_temp_use_declared_root_not_inherited_temp(self) -> None:
        env = {**self.env, "POLICYOPS_TEMP_DIR": str(self.declared)}
        scratch = self.declared.resolve() / "tmp"
        for mode in ("staged", "history"):
            with self.subTest(mode=mode):
                if mode == "history":
                    self.assertEqual(self.repo.commit(verify=False).returncode, 0)
                result, record = self.run_recorded(env, mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"{mode} scan passed", result.stdout)
                made = [Path(p) for p in record["made"]]
                self.assertTrue(any(p.name.startswith("gitleaks-noignore-") for p in made), made)
                for path in made:
                    self.assertTrue(path.is_relative_to(self.declared.resolve()), path)
                self.assertTrue(record["children"])
                for child in record["children"]:
                    self.assertIsNotNone(child, "child process inherited the caller's temp settings")
                    for value in child.values():
                        self.assertEqual(Path(value), scratch)
                self.assertEqual(list(self.inherited.iterdir()), [])
                self.assertEqual(list(scratch.iterdir()), [])

    def test_missing_or_invalid_root_fails_closed_even_with_configured_scanner(self) -> None:
        for value in (None, "", "relative/root", str(REPO), str(REPO / "tmp"), str(self.repo.root),
                      str(self.repo.root / "nested")):
            with self.subTest(value=value):
                env = dict(self.env) if value is None else {**self.env, "POLICYOPS_TEMP_DIR": value}
                result, record = self.run_recorded(env, "staged")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("POLICYOPS_TEMP_DIR", result.stderr)
                self.assertNotIn("scan passed", result.stdout)
                self.assertEqual(record["made"], [])

    def test_hooks_fail_closed_without_temp_root(self) -> None:
        commit = self.repo.commit(env=self.env)
        self.assertNotEqual(commit.returncode, 0)
        self.assertIn("Publication boundary passed", commit.stdout + commit.stderr)
        self.assertIn("POLICYOPS_TEMP_DIR is not set", commit.stderr)
        self.assertEqual(self.repo.run("git", "rev-list", "--all").stdout, "")

        remote = self.repo.root.parent / "remote.git"
        self.repo.run("git", "init", "-q", "--bare", str(remote))
        self.repo.git("remote", "add", "origin", remote.as_posix())
        self.assertEqual(self.repo.commit(verify=False).returncode, 0)
        push = self.repo.run("git", "push", "-q", "origin", "HEAD:refs/heads/main", env=self.env)
        self.assertNotEqual(push.returncode, 0)
        self.assertIn("POLICYOPS_TEMP_DIR is not set", push.stderr)
        remote_refs = self.repo.run("git", "--git-dir", str(remote), "for-each-ref").stdout
        self.assertEqual(remote_refs, "")


class GitleaksInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="policyops-gitleaks-install-", dir=os.environ.get("POLICYOPS_TEMP_DIR"),
        )
        self.addCleanup(self.temp.cleanup)
        self.dest = Path(self.temp.name) / "bin"

    def fake_archive(self) -> Path:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            bundle.writestr("gitleaks.exe", b"not the pinned scanner")
        path = Path(self.temp.name) / "gitleaks_8.30.1_windows_x64.zip"
        path.write_bytes(buffer.getvalue())
        return path

    def test_archive_checksum_mismatch_installs_nothing(self) -> None:
        with self.assertRaises(gate.GateError):
            gate.install(self.dest, self.fake_archive(), "windows_x64")
        self.assertFalse(self.dest.exists())

    def test_cli_install_failure_exits_two(self) -> None:
        result = subprocess.run(
            [sys.executable, "-B", str(GATE), "install", "--dest", str(self.dest),
             "--archive", str(self.fake_archive())],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.dest.exists())
        self.assertIn("failed closed", result.stderr)

    def test_install_into_repository_is_rejected(self) -> None:
        dest = REPO / "gitleaks-install-test"
        result = subprocess.run(
            [sys.executable, "-B", str(GATE), "install", "--dest", str(dest), "--archive", str(self.fake_archive())],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside the repository", result.stderr)
        self.assertFalse(dest.exists())

    def test_unknown_platform_is_rejected(self) -> None:
        with mock.patch.object(gate.platform, "system", return_value="Plan9"), \
                mock.patch.object(gate.platform, "machine", return_value="mips"), \
                self.assertRaises(gate.GateError):
            gate.platform_key()

    def test_pins_cover_supported_platforms_with_sha256_values(self) -> None:
        self.assertEqual(set(gate.PINS), {"windows_x64", "linux_x64", "linux_arm64",
                                          "darwin_x64", "darwin_arm64"})
        for asset, archive_sha, member, binary_sha in gate.PINS.values():
            self.assertTrue(asset.startswith(f"gitleaks_{gate.VERSION}_"))
            self.assertIn(member, {"gitleaks", "gitleaks.exe"})
            for digest in (archive_sha, binary_sha):
                self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_config_extends_defaults_with_only_the_reviewed_exact_allowlist(self) -> None:
        config = tomllib.loads((REPO / ".gitleaks.toml").read_text(encoding="utf-8"))
        self.assertEqual(config["extend"], {"useDefault": True})
        self.assertNotIn("allowlist", config)
        for rule in config.get("rules", []):
            self.assertNotIn("allowlist", rule)
            self.assertNotIn("allowlists", rule)
        (exception,) = config["allowlists"]
        self.assertEqual(exception["targetRules"], ["generic-api-key"])
        self.assertEqual(exception["condition"], "AND")
        self.assertEqual(exception["regexes"], [rf"\A{key}\z" for key in CORPUS_KEYS])
        self.assertEqual(exception["paths"], [r"\Aevals/src/policyops_evals/ingest_manifest\.py\z",
                                              r"\Aevals/manifests/tau2-19f13ea3/ingest-corpora\.json\z"])
        self.assertEqual(set(exception) - {"description"},
                         {"targetRules", "condition", "regexes", "paths"})  # no stopwords, commits or regexTarget
        self.assertFalse((REPO / ".gitleaksignore").exists())


if __name__ == "__main__":
    unittest.main()
