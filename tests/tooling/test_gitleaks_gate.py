"""Pinned gitleaks gate and hook ordering, exercised in isolated repositories.

Synthetic secrets are generated at run time, so the scanner configuration needs
no allowlist for test fixtures; its only allowlists are the reviewed exact corpus-key
and tokenizer-digest exceptions, each tested here in both directions. Hook tests require the verified scanner
(`python -B scripts/gitleaks_gate.py install`); they fail rather than skip.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
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
# The second reviewed exception: the public MiniLM cross-encoder tokenizer digest pinned by the
# committed G1 QA study configs, read from the config rather than repeated as a literal here.
TOKENIZER_DIGEST = json.loads((Path(__file__).resolve().parents[2] / "evals" / "qa_studies"
                               / "g1-dev-answers-v2.json").read_text(encoding="utf-8"))["arms"][3]["reranker"][
    "tokenizer_sha256"]
# Empirically measured with pinned 8.30.1 and git log -p -U0 <commit>^!.
# Merge resolution lines are absent from its default log diff, too.
COMMIT_COVERAGE = {
    "root": 1, "normal-add": 1, "deletion-only": 0, "rename-only": 0,
    "mode-only": 0, "binary-only-add": 0, "allow-empty": 0,
    "merge-clean": 0, "merge-resolution-add": 0,
    "empty-file": 0, "blank-line": 1, "no-newline": 1,
}
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
            prefix="policyops-gitleaks-", dir=os.environ.get("TEMP"),
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
            # Random keys can hit upstream stopwords/the letters-only allowlist.
            # Fixed synthetic digests keep this exception-boundary test reproducible.
            secret = hashlib.sha256(("generic:" + path).encode()).hexdigest()
            blocked.append((path, legit + f'api_key = "{secret}"\n', secret))  # a real secret beside them
            suffix = hashlib.sha256(("lookalike:" + path).encode()).hexdigest()[:20]
            lookalike = f"{CORPUS_KEYS[0]}-{suffix}"
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

    def test_tokenizer_digest_exception_admits_only_the_exact_digest_in_g1_study_configs(self) -> None:
        legit = f'{{"tokenizer_sha256": "{TOKENIZER_DIGEST}"}}\n'
        path = "evals/qa_studies/g1-sealed-example.json"
        repo = TempRepo(self)
        repo.stage(path, legit)
        clean = repo.run(sys.executable, "-B", str(GATE), "staged")
        self.assertEqual(clean.returncode, 0, clean.stderr)
        other = hashlib.sha256(b"tokenizer-lookalike").hexdigest()
        blocked = [("apps/other_config.json", legit, None),  # same digest outside the G1 study configs
                   (path, f'{{"tokenizer_sha256": "{other}"}}\n', other)]  # any other digest in a G1 config
        for case, (target, content, generated) in enumerate(blocked):
            with self.subTest(case=case, path=target):
                repo = TempRepo(self)
                repo.stage(target, content)
                found = repo.run(sys.executable, "-B", str(GATE), "staged")
                self.assertEqual(found.returncode, 1, found.stdout + found.stderr)
                self.assertIn("rule=generic-api-key", found.stderr)
                if generated is not None:
                    self.assertNotIn(generated, found.stdout + found.stderr)

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

    def test_clean_history_with_additions_passes(self) -> None:
        repo = TempRepo(self)
        for number in range(2):
            repo.stage("apps/readme.txt", f"safe content {number}\n")
            self.assertEqual(repo.commit(verify=False).returncode, 0)
        result = repo.run(sys.executable, "-B", str(GATE), "history")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("history scan passed", result.stdout)

    def test_clean_staged_scan_with_kilobytes_passes(self) -> None:
        repo = TempRepo(self)
        repo.stage("apps/readme.txt", "safe content\n" * 1000)
        result = repo.run(sys.executable, "-B", str(GATE), "staged")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("staged scan passed", result.stdout)


class GitleaksCommitKindTests(unittest.TestCase):
    """Real repositories + pinned binary: the commit-count fixture is executable."""

    def test_clean_commit_kind_matrix_and_secret_history(self) -> None:
        binary = gate.resolve_binary(gate.platform_key())
        repo = TempRepo(self)
        scratch = repo.root.parent / "scanner-tmp"
        scratch.mkdir()
        total = 0

        def scan(mode: str) -> tuple[int, str]:
            output = io.StringIO()
            with mock.patch.dict(os.environ, repo.env, clear=True), redirect_stdout(output), redirect_stderr(output):
                result = gate.scan(binary, mode, repo.root, scratch)
            return result, output.getvalue()

        def record(kind: str) -> None:
            nonlocal total
            with self.subTest(kind=kind):
                if kind == "binary-only-add":
                    # The pinned scanner cannot read binary patches. The explicit
                    # staged-content rule refuses zero-byte coverage for additions.
                    with self.assertRaisesRegex(gate.GateError, "staged additions.*zero scanned"):
                        scan("staged")
                else:
                    result, output = scan("staged")
                    self.assertEqual(result, 0, output)
                repo.git("-c", "core.hooksPath=", "commit", "--allow-empty", "-qm", kind)
                revision = repo.git("rev-parse", "HEAD").strip()
                measured = repo.run(
                    str(binary), "git", "--config", str(gate.CONFIG), "--no-banner", "--no-color", "--redact",
                    "--ignore-gitleaks-allow", f"--log-opts={revision}^!", "--report-format=json", "--report-path=-",
                )
                self.assertEqual(measured.returncode, 0, measured.stderr)
                self.assertEqual(json.loads(measured.stdout), [])
                observed, _ = gate.scan_coverage(measured.stderr, 0)
                self.assertEqual(observed, COMMIT_COVERAGE[kind], measured.stderr)
                stats = repo.git("log", f"{revision}^!", "--format=%H", "--numstat", "-z", "--")
                self.assertEqual(gate.numstat_coverage(stats, "history"), observed)
                total += COMMIT_COVERAGE[kind]
                self.assertEqual(gate.expected_coverage(repo.root, "history", repo.env), total)
                result, output = scan("history")
                self.assertEqual(result, 0, output)

        repo.stage("apps/a.txt", "base\n")
        repo.stage("apps/b.txt", "spare\n")
        record("root")
        repo.git("rm", "apps/b.txt")
        record("deletion-only")
        repo.git("mv", "apps/a.txt", "apps/renamed.txt")
        record("rename-only")
        repo.git("update-index", "--chmod=+x", "apps/renamed.txt")
        record("mode-only")
        (repo.root / "apps/binary.dat").write_bytes(b"\0binary\0data\n")
        repo.git("add", "apps/binary.dat")
        record("binary-only-add")
        record("allow-empty")
        repo.stage("apps/normal.txt", "normal\n")
        record("normal-add")
        repo.stage("apps/empty.txt", "")
        record("empty-file")
        repo.stage("apps/blank.txt", "\n")
        record("blank-line")
        repo.stage("apps/no-newline.txt", "text")
        record("no-newline")
        main = repo.git("branch", "--show-current").strip()
        repo.git("checkout", "-qb", "side")
        repo.stage("apps/side.txt", "side\n")
        record("normal-add")
        repo.git("checkout", main)
        repo.stage("apps/main.txt", "main\n")
        record("normal-add")
        repo.git("merge", "--no-ff", "--no-commit", "side")
        record("merge-clean")
        repo.git("checkout", "-qb", "conflict")
        repo.stage("apps/normal.txt", "side conflict\n")
        record("normal-add")
        repo.git("checkout", main)
        repo.stage("apps/normal.txt", "main conflict\n")
        record("normal-add")
        self.assertEqual(repo.run("git", "merge", "--no-ff", "--no-commit", "conflict").returncode, 1)
        repo.stage("apps/normal.txt", "new resolution content\n")
        record("merge-resolution-add")
        # Binary deletions contain no additions and must pass the staged gate.
        repo.git("rm", "apps/binary.dat")
        result, output = scan("staged")
        self.assertEqual(result, 0, output)
        record("deletion-only")
        secret = stripe_like_key()
        repo.stage("apps/config.txt", f'payment_key = "{secret}"\n')
        self.assertEqual(repo.commit(verify=False).returncode, 0)
        result, output = scan("history")
        self.assertEqual(result, 1, output)
        self.assertIn("rule=stripe-access-token", output)
        self.assertNotIn(secret, output)


class GitleaksCoverageTests(unittest.TestCase):
    """Fake both processes to reproduce misleading successful scanner responses."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="policyops-coverage-", dir=os.environ["TEMP"])
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.scratch = Path(self.temp.name) / "scratch"
        self.scratch.mkdir()
        self.binary = Path(self.temp.name) / "scanner"
        self.output = io.StringIO()

    @staticmethod
    def summaries(commits: int = 0, size: int = 12, findings: int = 0) -> str:
        outcome = f"WRN leaks found: {findings}" if findings else "INF no leaks found"
        return (f"7:51PM INF {commits} commits scanned.\n"
                f"7:51PM INF scanned ~{size} bytes ({size} bytes) in 269ms\n7:51PM {outcome}\n")

    def run_scan(self, *, mode: str = "staged", stats: str = "1\t0\tapps/readme.txt\0", expected_commits: int = 2,
                 stderr: str | None = None, findings: list[dict[str, object]] | None = None,
                 git_stderr: str = "", git_exit: int = 0, scanner_exit: int | None = None,
                 after_stats: str | None = None, after_commits: int | None = None) -> int:
        report = [] if findings is None else findings
        observations = 0

        def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            nonlocal observations
            if args[0] == "git":
                self.assertEqual(args[1:3], ["-C", str(self.repo)])
                if mode == "history":
                    self.assertEqual(args[3:], ["log", "--all", "--format=%H", "--numstat", "-z", "--"])
                    count = after_commits if observations and after_commits is not None else expected_commits
                    stdout = "".join(f"{n:040x}\0\n1\t0\tfile.txt\0" for n in range(count))
                else:
                    self.assertEqual(args[3:], ["diff", "--cached", "--numstat", "-z",
                                               "--diff-filter=ACMRTUXB", "--"])
                    stdout = after_stats if observations and after_stats is not None else stats
                observations += 1
                return subprocess.CompletedProcess(args, git_exit, stdout, git_stderr)
            self.assertEqual(args[0], str(self.binary))
            self.assertIn("--no-color", args)
            self.assertEqual(args[args.index("--log-level") + 1], "info")
            for flag in (["--pre-commit", "--staged"] if mode == "staged" else ["--log-opts=--all"]):
                self.assertIn(flag, args)
            return subprocess.CompletedProcess(args, int(bool(report)) if scanner_exit is None else scanner_exit,
                                               json.dumps(report), self.summaries() if stderr is None else stderr)

        with mock.patch.object(gate.subprocess, "run", side_effect=run), \
                redirect_stdout(self.output), redirect_stderr(self.output):
            return int(gate.scan(self.binary, mode, self.repo, self.scratch))

    def test_git_warning_and_empty_success_fails_closed(self) -> None:
        warning = "7:51PM ERR [git] warning: unable to access config: Permission denied\n"
        with self.assertRaisesRegex(gate.GateError, "Git diagnostic.*aborted/partial"):
            self.run_scan(stderr=warning + self.summaries(size=0))
        self.assertNotIn("scan passed", self.output.getvalue())

    def test_unknown_stderr_on_success_fails_without_echoing_it(self) -> None:
        sensitive = random_text(40)
        for diagnostic in (f"7:51PM WRN skipped file {sensitive}\n", f"unexpected {sensitive}\n",
                           "7:51PM ERR error=\"stderr is not empty\"\n"):
            with self.subTest(diagnostic=diagnostic[:10]), \
                    self.assertRaisesRegex(gate.GateError, "unknown scanner diagnostic") as caught:
                self.run_scan(stderr=self.summaries() + diagnostic)
            self.assertNotIn(sensitive, str(caught.exception))

    def test_nonempty_staged_diff_with_empty_scan_fails_closed(self) -> None:
        for stats in ("1\t0\tfile.txt\0", "-\t-\tbinary.dat\0"):
            with self.subTest(stats=stats), self.assertRaisesRegex(gate.GateError, "staged additions.*zero scanned"):
                self.run_scan(stats=stats, stderr=self.summaries(size=0))

    def test_clean_scan_with_coverage_passes(self) -> None:
        self.assertEqual(self.run_scan(), 0)
        self.assertIn("staged scan passed", self.output.getvalue())

    def test_clean_scan_accepts_pinned_human_readable_byte_units(self) -> None:
        for size in ("14 KB", "192.58 KB", "8.80 MB", "1 GB", "1.2 TB"):
            with self.subTest(size=size):
                stderr = self.summaries(size=192584).replace("192584 bytes)", f"{size})")
                self.assertEqual(self.run_scan(stderr=stderr), 0)

    def test_empty_staged_diff_with_empty_scan_passes(self) -> None:
        for stats in ("", "0\t1\tfile.txt\0", "0\t0\t\0old\0new\0", "0\t0\tfile.txt\0"):
            with self.subTest(stats=stats):
                self.assertEqual(self.run_scan(stats=stats, stderr=self.summaries(size=0)), 0)

    def test_zero_eligible_history_still_runs_scanner_and_validates_diagnostics(self) -> None:
        self.assertEqual(self.run_scan(mode="history", expected_commits=0, stderr=self.summaries(size=0)), 0)
        with self.assertRaisesRegex(gate.GateError, "Git diagnostic"):
            self.run_scan(mode="history", expected_commits=0,
                          stderr=self.summaries(size=0) + "7:51PM ERR [git] read aborted\n")

    def test_numstat_rejects_malformed_and_truncated_records(self) -> None:
        for mode, stats in (("staged", "1\t0\tpath"), ("staged", "1\t-\tpath\0"),
                            ("staged", "1\t0\t\0old\0"), ("staged", "junk\0"),
                            ("history", "1\t0\tpath\0"), ("history", "x" * 40 + "\0"),
                            ("history", ("a" * 40 + "\0") * 2)):
            with self.subTest(mode=mode, stats=stats), self.assertRaises(gate.GateError):
                gate.numstat_coverage(stats, mode)

    def test_numstat_treats_rename_paths_as_opaque_and_counts_commits_once(self) -> None:
        stats = "0\t0\t\0" + "a" * 40 + "\0\n1\t0\tpath\0"
        self.assertEqual(gate.numstat_coverage(stats, "staged"), 0)
        history = "a" * 40 + "\0\n" + stats + "2\t1\ta\tb\nfile\0-\t-\tbinary\0"
        history += "b" * 40 + "\0\n0\t9\tdeleted\0"
        self.assertEqual(gate.numstat_coverage(history, "history"), 1)

    def test_exact_link_only_notice_for_local_remote_is_benign(self) -> None:
        notice = "7:51PM INF Unknown SCM platform. Use --platform to include links in findings. host=\n"
        self.assertEqual(self.run_scan(stderr=notice + self.summaries()), 0)
        with self.assertRaisesRegex(gate.GateError, "unknown scanner diagnostic"):
            self.run_scan(stderr=notice.rstrip() + "unrecognized-host\n" + self.summaries())

    def test_finding_fails_and_redacts_values(self) -> None:
        sensitive = stripe_like_key()
        report = [{"File": "apps/config.txt", "StartLine": 1, "RuleID": "stripe-access-token", "Secret": sensitive}]
        self.assertEqual(self.run_scan(findings=report, stderr=self.summaries(findings=1)), 1)
        self.assertIn("rule=stripe-access-token", self.output.getvalue())
        self.assertNotIn(sensitive, self.output.getvalue())

    def test_partial_history_count_fails_closed(self) -> None:
        with self.assertRaisesRegex(gate.GateError, "history coverage mismatch.*2.*1"):
            self.run_scan(mode="history", stderr=self.summaries(commits=1))

    def test_clean_history_with_matching_count_passes(self) -> None:
        self.assertEqual(self.run_scan(mode="history", stderr=self.summaries(commits=2)), 0)

    def test_independent_coverage_changes_during_scan_fail_closed(self) -> None:
        with self.assertRaisesRegex(gate.GateError, "staged coverage changed"):
            self.run_scan(after_stats="1\t0\tfirst\0" + "1\t0\tsecond\0")
        with self.assertRaisesRegex(gate.GateError, "history coverage changed"):
            self.run_scan(mode="history", stderr=self.summaries(commits=2), after_commits=3)

    def test_missing_or_duplicate_summaries_fail_closed(self) -> None:
        for stderr in ("", "7:51PM INF no leaks found\n", self.summaries() * 2):
            with self.subTest(stderr=stderr), self.assertRaisesRegex(gate.GateError, "coverage/result summaries"):
                self.run_scan(stderr=stderr)

    def test_result_summary_must_agree_with_report(self) -> None:
        with self.assertRaisesRegex(gate.GateError, "coverage/result summaries"):
            self.run_scan(stderr=self.summaries(findings=1))

    def test_independent_git_warning_or_failure_fails_closed(self) -> None:
        for stderr, code in (("warning: partial read", 0), ("", 128)):
            with self.subTest(code=code), self.assertRaisesRegex(gate.GateError, "Git staged coverage check failed"):
                self.run_scan(git_stderr=stderr, git_exit=code)

    def test_exit_report_inconsistency_fails_closed(self) -> None:
        with self.assertRaisesRegex(gate.GateError, "invalid report/exit consistency"):
            self.run_scan(scanner_exit=1)


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
            prefix="policyops-gitleaks-install-", dir=os.environ.get("TEMP"),
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
        corpus, tokenizer = config["allowlists"]
        self.assertEqual(corpus["regexes"], [rf"\A{key}\z" for key in CORPUS_KEYS])
        self.assertEqual(corpus["paths"], [r"\Aevals/src/policyops_evals/ingest_manifest\.py\z",
                                           r"\Aevals/manifests/tau2-19f13ea3/ingest-corpora\.json\z"])
        self.assertRegex(TOKENIZER_DIGEST, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(tokenizer["regexes"], [rf"\A{TOKENIZER_DIGEST}\z"])
        self.assertEqual(tokenizer["paths"], [r"\Aevals/qa_studies/g1-[a-z0-9-]+\.json\z"])
        for exception in (corpus, tokenizer):
            self.assertEqual(exception["targetRules"], ["generic-api-key"])
            self.assertEqual(exception["condition"], "AND")
            self.assertEqual(set(exception) - {"description"},
                             {"targetRules", "condition", "regexes", "paths"})  # no stopwords, commits or regexTarget
        self.assertFalse((REPO / ".gitleaksignore").exists())


if __name__ == "__main__":
    unittest.main()
