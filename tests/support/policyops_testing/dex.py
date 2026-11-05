"""An owned, contained Dex (pinned image) for OIDC integration tests, using infra/dex/config.yaml.tmpl.

Containment and ownership follow the PostgreSQL fixture: unique name plus `policyops.owner`/`policyops.run` labels,
read-only root filesystem, `--log-driver none`, exactly one bind mount (a unique directory under POLICYOPS_TEMP_DIR
at /work), and a 127.0.0.1-only published port that is registered with the network guard for the server's lifetime.
The issuer URL contains the host port, so a free loopback port is chosen before start (a tiny race, retried).

Secrets: the client secret and the fictional users' passwords are generated per run, registered for redaction,
written to files in the bind mount (never argv or environment), rendered into Dex's config by the image's own
gomplate (bcrypt), and those files plus the rendered config are deleted as soon as Dex is ready. Dex keeps its state
in memory. Its log goes to /work/log/dex.log.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import time
from typing import Any

import httpx

from policyops_testing import network, redaction
from policyops_testing.postgres import REPO, CleanupUncertain, _container_exists, _docker, _observe, _tail


TEMPLATE = REPO / "infra" / "dex" / "config.yaml.tmpl"
USERS = ("alice", "bob", "carol")
CLIENT_ID = "policyops-local"
OWNER_LABEL = "policyops.owner=policyops-tests"
SCRIPT = ('set -eu; gomplate -f /work/config.yaml.tmpl -o /work/data/config.yaml; '
          'exec dex serve /work/data/config.yaml >/work/log/dex.log 2>&1')


class DexUnavailable(RuntimeError):
    """Docker or the pinned Dex image is missing, or Dex did not become ready (log tail attached)."""


def pinned_dex_image() -> str:
    pins = json.loads((REPO / "infra" / "images.json").read_text(encoding="utf-8"))["images"]["oidc"]
    return f"{pins['image']}@{pins['digest']}"


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


@dataclass
class OwnedDex:
    root: Path
    run_id: str
    redirect_uri: str
    image: str = field(default_factory=pinned_dex_image)
    container_id: str = ""
    port: int = 0
    client_secret: str = ""
    passwords: dict[str, str] = field(default_factory=dict)
    _allowance: contextlib.ExitStack = field(default_factory=contextlib.ExitStack)

    @property
    def name(self) -> str:
        return f"policyops-test-dex-{self.run_id}"

    @property
    def issuer(self) -> str:
        return f"http://127.0.0.1:{self.port}/dex"

    def _secret_paths(self) -> list[Path]:
        return [self.root / "secrets" / name for name in ("client_secret", *USERS)] + [
            self.root / "data" / "config.yaml"]

    def start(self, *, deadline_seconds: float = 60) -> None:
        if _docker("image", "inspect", self.image).returncode != 0:
            raise DexUnavailable(f"pinned image {self.image} is not installed; pull it by digest first")
        for sub in ("secrets", "log", "data"):
            (self.root / sub).mkdir(parents=True, exist_ok=False)
        shutil.copyfile(TEMPLATE, self.root / "config.yaml.tmpl")
        if os.name != "nt":  # the image's dex user must read the inputs and write data/log
            for path in (self.root, self.root / "secrets", self.root / "log", self.root / "data"):
                path.chmod(0o777)
        try:  # everything from secret generation to readiness is covered by the cleanup below
            self.client_secret = secrets.token_urlsafe(32)
            self.passwords = {user: f"{user}-{secrets.token_urlsafe(18)}" for user in USERS}
            redaction.register(self.client_secret, *self.passwords.values())
            (self.root / "secrets" / "client_secret").write_text(self.client_secret, encoding="utf-8")
            for user, password in self.passwords.items():
                (self.root / "secrets" / user).write_text(password, encoding="utf-8")
            self._run_container()
            self._verify_containment()
            self._allowance.enter_context(network.allow("127.0.0.1", self.port))
            self._wait_ready(deadline_seconds)
        except BaseException:
            try:
                self._remove_secret_files()
            finally:
                self.stop()
            raise
        self._remove_secret_files()  # Dex has read its configuration; nothing secret stays on disk

    def _run_container(self) -> None:
        for _attempt in range(3):
            self.port = _free_loopback_port()
            run = _docker("run", "-d", "--name", self.name, "--label", OWNER_LABEL,
                          "--label", f"policyops.run={self.run_id}", "--read-only", "--log-driver", "none",
                          "-p", f"127.0.0.1:{self.port}:5556",
                          "--mount", f"type=bind,source={self.root},target=/work",
                          "-e", f"DEX_ISSUER={self.issuer}", "-e", f"POLICYOPS_REDIRECT_URI={self.redirect_uri}",
                          "--entrypoint", "sh", self.image, "-c", SCRIPT)
            if run.returncode == 0:
                self.container_id = run.stdout.strip()
                return
            self._remove_failed_create()  # a failed run can leave this run's created container behind
            # The free port can be taken between choosing and binding it; Docker reports that in two wordings
            # (Linux: "port is already allocated"; Docker Desktop on Windows: "address already in use").
            if not any(text in run.stderr for text in ("port is already allocated", "address already in use")):
                raise DexUnavailable(f"docker run failed: {redaction.redact_text(run.stderr.strip())[-500:]}")
        raise DexUnavailable("no free loopback port after 3 attempts")

    def _remove_failed_create(self) -> None:
        """A failed `docker run` may still have created the named container. It is removed only if it is exactly
        this run's (the owner label, this run's label and this name), by its ID through the guarded `_remove`. A
        foreign or mismatched container under the name (for example the cause of a name conflict) is never
        touched, and a state that cannot be determined is reported, not assumed."""
        found = _observe("container", "inspect", "-f", '{{.Id}} {{index .Config.Labels "policyops.owner"}} '
                         '{{index .Config.Labels "policyops.run"}} {{.Name}}', self.name)
        if found.returncode != 0:
            if "No such container" in found.stderr or "No such object" in found.stderr:
                return  # the failed run created nothing
            raise CleanupUncertain(f"cannot inspect a container named {self.name}: {found.stderr.strip()[:300]}")
        fields = found.stdout.split()
        if len(fields) != 4 or fields[1:] != ["policyops-tests", self.run_id, f"/{self.name}"]:
            raise DexUnavailable(f"refusing to remove the container named {self.name}: it is not this run's")
        self.container_id = fields[0]
        self._remove()

    def _remove_secret_files(self) -> None:
        """Remove every owned secret path (generated inputs and the rendered config) and confirm; never silent."""
        remaining = []
        for path in self._secret_paths():
            with contextlib.suppress(OSError):  # verified just below; a failure is reported, not ignored
                path.unlink(missing_ok=True)
            if path.exists():
                remaining.append(path.relative_to(self.root).as_posix())
        if remaining:
            raise CleanupUncertain(f"Dex secret files may remain under {self.root}: {', '.join(remaining)}")

    def _verify_containment(self) -> None:
        found = _docker("inspect", self.container_id)
        if found.returncode != 0:
            raise DexUnavailable("container disappeared")
        info: dict[str, Any] = json.loads(found.stdout)[0]
        problems = []
        if [(m.get("Type"), m.get("Destination")) for m in info.get("Mounts", [])] != [("bind", "/work")]:
            problems.append("mounts are not exactly one bind at /work")
        if not info["HostConfig"].get("ReadonlyRootfs"):
            problems.append("root filesystem is writable")
        if info["HostConfig"]["LogConfig"]["Type"] != "none":
            problems.append("Docker log storage is enabled")
        bindings = info["HostConfig"]["PortBindings"].get("5556/tcp") or []
        if [(b.get("HostIp"), b.get("HostPort")) for b in bindings] != [("127.0.0.1", str(self.port))]:
            problems.append(f"port bindings {bindings} are not exactly 127.0.0.1:{self.port}")
        if problems:
            raise DexUnavailable("; ".join(problems))

    def _wait_ready(self, deadline_seconds: float) -> None:
        deadline = time.monotonic() + deadline_seconds
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=2) as client:
            while time.monotonic() < deadline:
                if _docker("inspect", "-f", "{{.State.Running}}", self.container_id).stdout.strip() != "true":
                    break
                try:
                    if client.get(self.issuer + "/.well-known/openid-configuration").status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(0.25)
        raise DexUnavailable(f"Dex did not become ready\n--- dex.log ---\n{_tail(self.root / 'log' / 'dex.log')}")

    def stop(self) -> None:
        self._allowance.close()
        try:
            if self.container_id:
                self._remove()
        finally:
            redaction.forget(self.client_secret, *self.passwords.values())

    def _remove(self) -> None:
        if not _container_exists(self.container_id):
            self.container_id = ""
            return
        found = _observe("inspect", "-f", '{{index .Config.Labels "policyops.owner"}} '
                         '{{index .Config.Labels "policyops.run"}} {{.Name}}', self.container_id)
        if found.returncode != 0:
            raise CleanupUncertain(f"cannot inspect container {self.container_id}")
        if found.stdout.split() != ["policyops-tests", self.run_id, f"/{self.name}"]:
            raise DexUnavailable(f"refusing to remove {self.container_id}: not this run's container")
        removed = _observe("rm", "-f", "-v", self.container_id)
        if _container_exists(self.container_id):
            raise DexUnavailable(f"container {self.container_id} was not removed: {removed.stderr.strip()[:300]}")
        self.container_id = ""


@contextlib.contextmanager
def owned_dex(base: Path, run_id: str, redirect_uri: str) -> Any:
    server = OwnedDex(root=base / run_id, run_id=run_id, redirect_uri=redirect_uri)
    server.root.mkdir(parents=True, exist_ok=False)
    try:
        server.start()
        yield server
    finally:
        server.stop()
