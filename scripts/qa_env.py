"""Persistent, explicitly owned local QA PostgreSQL. Output contains paths, never credentials."""
from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from typing import Any
from uuid import UUID, uuid4, uuid5


REPO = Path(__file__).resolve().parents[1]
OWNER = "policyops-qa-env-v1"
DATABASE = "policyops_qa"
DESTINATION = "/var/lib/postgresql/data"
DEFAULT_PROJECT = "policyops-qa"
Docker = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def bind_source_matches(source: str, expected: Path) -> bool:
    """Exact host-path match for a bind mount. Docker Desktop on Windows reports a drive path such as `D:/a b/c` as
    `/run/desktop/mnt/host/d/a b/c`; accept only that exact translation of the expected path, nothing broader."""
    target = expected.resolve()
    if source and Path(source).resolve() == target:
        return True
    drive, rest = target.drive, target.as_posix()[len(target.drive):]
    if len(drive) == 2 and drive[1] == ":" and drive[0].isalpha():
        return source == f"/run/desktop/mnt/host/{drive[0].lower()}{rest}"
    return False

class Refused(RuntimeError):
    pass


def docker(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120, check=False)


def restrict(path: Path, *, directory: bool = False) -> None:
    if os.name == "nt":
        # Restrict the DACL before creating secret children; inherited broad ACLs are removed.
        who = subprocess.run(["whoami"], capture_output=True, text=True, check=True).stdout.strip()
        grant = f"{who}:(OI)(CI)F" if directory else f"{who}:F"
        result = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", grant],
                                capture_output=True, text=True, check=False)
        if result.returncode:
            raise Refused("secret_permissions_unconfirmed")
    else:
        path.chmod(0o700 if directory else 0o600)


def private_root(project: str) -> Path:
    value = os.environ.get("POLICYOPS_TEMP_DIR")
    if not value or not Path(value).is_absolute():
        raise Refused("absolute_POLICYOPS_TEMP_DIR_required")
    root = Path(value).resolve()
    if root.is_relative_to(REPO) or REPO.is_relative_to(root):
        raise Refused("temporary_root_must_be_outside_checkout")
    target = root / "qa-env" / project
    if any(p.is_symlink() or p.is_junction() for p in (target, *target.parents)):
        raise Refused("environment_path_link")
    return target


class Environment:
    def __init__(self, project: str, root: Path, runner: Docker = docker) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", project):
            raise Refused("invalid_project")
        self.project, self.root, self.docker = project, root, runner
        self.name, self.volume = project + "-postgres", project + "-pgdata"
        pin = json.loads((REPO / "infra/images.json").read_bytes())["images"]["postgres"]
        self.image = pin["image"] + "@" + pin["digest"]

    def call(self, *args: str) -> str:
        result = self.docker(args)
        if result.returncode:
            raise Refused("docker_" + args[0] + "_failed")  # Docker stderr may contain credentials.
        return result.stdout.strip()

    def file(self, name: str) -> Path:
        target = self.root / name
        if (not target.resolve().is_relative_to(self.root.resolve())
                or any(p.is_symlink() or p.is_junction() for p in (target, *target.parents))):
            raise Refused("environment_path_link")
        return target

    def state(self, *, create: bool = False) -> dict[str, str]:
        path = self.file("owner.json")
        if not path.exists():
            if not create:
                raise Refused("environment_not_initialized")
            self.root.mkdir(parents=True, exist_ok=True)
            restrict(self.root, directory=True)
            state = {"owner": OWNER, "project": self.project, "run": str(uuid4())}
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(state))
        value: dict[str, str] = json.loads(path.read_bytes())
        if value.get("owner") != OWNER or value.get("project") != self.project:
            raise Refused("owner_record_mismatch")
        UUID(value["run"])
        return value

    def labels(self, state: dict[str, str]) -> dict[str, str]:
        return {"policyops.owner": OWNER, "policyops.run": state["run"],
                "com.docker.compose.project": self.project}

    def inspect(self) -> dict[str, Any] | None:
        # Absence is established by a successful enumeration, never a failed inspect/start.
        names = self.call("ps", "-a", "--format", "{{.Names}}" ).splitlines()
        if self.name not in names:
            return None
        info: dict[str, Any] = json.loads(self.call("inspect", self.name))[0]
        self.verify(info)
        return info

    def verify_volume(self) -> bool:
        if self.volume not in self.call("volume", "ls", "--format", "{{.Name}}").splitlines():
            return False
        info = json.loads(self.call("volume", "inspect", self.volume))[0]
        if (info.get("Name") != self.volume
                or any(info.get("Labels", {}).get(k) != v for k, v in self.labels(self.state()).items())):
            raise Refused("volume_owner_mismatch")
        return True

    def verify(self, info: dict[str, Any]) -> None:
        labels = info.get("Config", {}).get("Labels") or {}
        mounts = info.get("Mounts", [])
        bindings = info.get("HostConfig", {}).get("PortBindings", {})
        if (info.get("Name") != "/" + self.name or not re.fullmatch(r"[0-9a-f]{64}", info.get("Id", ""))
                or any(labels.get(k) != v for k, v in self.labels(self.state()).items())
                or info.get("Config", {}).get("Image") != self.image
                or len(mounts) != 2
                or not any(m.get("Type") == "volume" and m.get("Name") == self.volume
                           and m.get("Destination") == DESTINATION for m in mounts)
                or not any(m.get("Type") == "bind" and m.get("Destination") == "/qa-secrets"
                           and m.get("RW") is False
                           and bind_source_matches(m.get("Source", ""), self.root / "secrets")
                           for m in mounts)
                or set(bindings) != {"5432/tcp"} or len(bindings["5432/tcp"]) != 1
                or bindings["5432/tcp"][0].get("HostIp") != "127.0.0.1"
                or info.get("HostConfig", {}).get("LogConfig", {}).get("Type") != "none"):
            raise Refused("container_owner_or_containment_mismatch")
        if not self.verify_volume():
            raise Refused("owned_volume_missing")

    def secret(self, role: str) -> str:
        directory = self.file("secrets")
        directory.mkdir(exist_ok=True)
        restrict(directory, directory=True)
        path = self.file("secrets/" + role)
        if not path.exists():
            with path.open("x", encoding="ascii") as handle:
                handle.write(secrets.token_urlsafe(32))
        restrict(path)
        return path.read_text(encoding="ascii")

    def up(self) -> dict[str, Any]:
        state = self.state(create=True)
        info = self.inspect()
        if info is None:
            self.call("image", "inspect", self.image)  # never pull implicitly
            self.secret("postgres")
            flags = [s for k, v in self.labels(state).items() for s in ("--label", k + "=" + v)]
            if not self.verify_volume():
                self.call("volume", "create", *flags, self.volume)
            self.call("create", "--name", self.name, *flags, "--log-driver", "none",
                      "-p", "127.0.0.1::5432", "--mount", f"type=volume,source={self.volume},target={DESTINATION}",
                      "--mount", f"type=bind,source={self.root / 'secrets'},target=/qa-secrets,readonly",
                      "-e", "POSTGRES_PASSWORD_FILE=/qa-secrets/postgres",
                      "-e", "POSTGRES_INITDB_ARGS=--auth=scram-sha-256",
                      self.image, "postgres", "-c", "log_min_messages=panic", "-c", "log_min_error_statement=panic")
            info = self.inspect()
        if info is None:
            raise Refused("container_creation_unconfirmed")
        # No automatic removal on failure; only destroy verifies/removes an exact ID.
        if not info["State"]["Running"]:
            self.call("start", info["Id"])
        info = self.inspect()
        if info is None:
            raise Refused("container_start_unconfirmed")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with self.connect("postgres", database="postgres", info=info):
                    break
            except Exception:
                time.sleep(0.25)
        else:
            raise Refused("postgres_readiness_timeout")
        return self.status()

    def connect(self, role: str, *, database: str = DATABASE, info: dict[str, Any] | None = None,
                autocommit: bool = True) -> Any:
        import psycopg

        info = self.inspect() if info is None else info
        if info is None or not info["State"]["Running"]:
            raise Refused("environment_not_running")
        ports = info["NetworkSettings"]["Ports"]["5432/tcp"]
        if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
            raise Refused("port_containment_mismatch")
        return psycopg.connect(host="127.0.0.1", hostaddr="127.0.0.1", port=int(ports[0]["HostPort"]),
                               dbname=database, user=role,
                               password=self.secret(role), options="-c timezone=UTC", connect_timeout=5,
                               autocommit=autocommit)

    def paths(self, info: dict[str, Any]) -> dict[str, str]:
        from psycopg.conninfo import make_conninfo

        from policyops.persistence.roles import ALL_ROLES

        result = {}
        services = []
        port = info["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
        for role in ALL_ROLES:
            path = self.file("secrets/" + role + ".dsn")
            raw = make_conninfo(host="127.0.0.1", port=port, dbname=DATABASE, user=role,
                                hostaddr="127.0.0.1", password=self.secret(role), options="-c timezone=UTC")
            path.write_text(raw, encoding="utf-8")
            restrict(path)
            result[role] = str(path)
            services.append(f"[{role}]\nhost=127.0.0.1\nhostaddr=127.0.0.1\nport={port}\n"
                            f"dbname={DATABASE}\nuser={role}\npassword={self.secret(role)}\n")
        service = self.file("secrets/pg_service.conf")
        service.write_text("\n".join(services), encoding="utf-8")
        restrict(service)
        return result

    def status(self) -> dict[str, Any]:
        info = self.inspect()
        running = info is not None and info["State"]["Running"]
        return {"project": self.project, "running": running, "image": self.image,
                "service_file": str(self.root / "secrets/pg_service.conf") if running else None,
                "dsn_files": self.paths(info) if running and info is not None else {}}

    def migrate(self) -> dict[str, Any]:
        from policyops.persistence import bootstrap, migrate
        from policyops.persistence.database import make_engine
        from policyops.persistence.roles import ALL_ROLES, APP_MIGRATOR, RolePassword

        with self.connect("postgres", database="postgres") as connection:
            bootstrap.provision_roles(connection, [RolePassword(r, self.secret(r)) for r in ALL_ROLES])
            bootstrap.provision_database(connection, DATABASE)
        with self.connect("postgres") as connection:
            bootstrap.provision_extensions(connection, DATABASE)
        engine = make_engine(lambda: self.connect(APP_MIGRATOR, autocommit=False))
        try:
            with engine.connect() as connection:
                migrate.upgrade(connection, "head")  # app migration chain includes the evaluation schema
        finally:
            engine.dispose()
        return self.status() | {"migrated": "head"}

    def bootstrap(self) -> dict[str, Any]:
        state = self.state()
        workspace = uuid5(UUID(state["run"]), "fictional-qa-workspace-v1")
        principal = uuid5(workspace, "fictional-qa-operator-v1")
        # Trusted local provisioning only; app work continues as the RLS runtime.
        with self.connect("postgres") as connection, connection.transaction():
            connection.execute("INSERT INTO identity.workspaces (id, slug, name, created_at) "
                "VALUES (%s, %s, %s, now()) ON CONFLICT (id) DO NOTHING",
                (workspace, "fictional-qa", "Fictional QA evaluation"))
            connection.execute("INSERT INTO identity.principals (id, issuer, subject, display_name, created_at) "
                "VALUES (%s, %s, %s, %s, now()) ON CONFLICT (id) DO NOTHING",
                (principal, "https://fictional.qa.invalid", "qa-operator", "Fictional QA operator"))
            for role in ("analyst", "reviewer", "admin", "auditor"):
                connection.execute("INSERT INTO identity.memberships "
                    "(id, workspace_id, principal_id, role, created_at) "
                    "VALUES (%s, %s, %s, %s, now()) ON CONFLICT DO NOTHING",
                    (uuid5(workspace, role), workspace, principal, role))
        self.file("workspace.txt").write_text(str(workspace) + "\n", encoding="ascii")
        return {"workspace_id": str(workspace), "workspace_file": str(self.root / "workspace.txt")}

    def down(self) -> dict[str, Any]:
        info = self.inspect()
        if info is not None:
            self.call("stop", "--time", "10", info["Id"])
        return self.status()

    def destroy(self, confirmation: str) -> dict[str, Any]:
        if confirmation != self.project:
            raise Refused("destroy_confirmation_mismatch")
        info = self.inspect()
        volume = self.verify_volume()  # verify both before the first mutation
        if info is not None:
            self.call("rm", "-f", info["Id"])
            if self.inspect() is not None:
                raise Refused("container_removal_unconfirmed")
        if volume:
            if not self.verify_volume():
                raise Refused("volume_disappeared_before_removal")
            self.call("volume", "rm", self.volume)
            if self.verify_volume():
                raise Refused("volume_removal_unconfirmed")
        return {"destroyed": self.project, "retained_private_directory": str(self.root)}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--project", default=DEFAULT_PROJECT)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("up", "status", "migrate", "bootstrap", "down", "destroy"):
        command = commands.add_parser(name)
        if name == "destroy":
            command.add_argument("--confirm", required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        environment = Environment(args.project, private_root(args.project))
        result = (environment.destroy(args.confirm) if args.command == "destroy"
                  else getattr(environment, args.command)())
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"refused": str(error) if isinstance(error, Refused) else type(error).__name__}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
