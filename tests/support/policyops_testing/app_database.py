"""Application databases on the owned test server: bootstrap, migrate and per-role engines.

Application suite only (imports the policyops package); the evaluator never imports this module."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import secrets
from typing import Any

from sqlalchemy import Engine

from policyops.persistence import bootstrap, migrate
from policyops.persistence.database import make_engine
from policyops.persistence.roles import ALL_ROLES, APP_MIGRATOR, RolePassword
from policyops_testing.postgres import OwnedPostgres


@dataclass
class AppCluster:
    """The four application roles, provisioned once on the session server with registered passwords."""

    server: OwnedPostgres
    _counter: int = 0

    @classmethod
    def provision(cls, server: OwnedPostgres) -> AppCluster:
        passwords = [RolePassword(role, server.passwords[role] if role in server.passwords
                                  else server.register_role(role)) for role in ALL_ROLES]
        with server.connect("postgres", "postgres", autocommit=True) as conn:
            bootstrap.provision_roles(conn, passwords)
        return cls(server)

    def new_name(self, label: str) -> str:
        self._counter += 1
        return f"app_{label}_{self._counter}_{secrets.token_hex(3)}"

    def create_database(self, label: str, *, extensions: bool = True) -> AppDatabase:
        name = self.new_name(label)
        self.server.register_database(name)
        with self.server.connect("postgres", "postgres", autocommit=True) as conn:
            bootstrap.provision_database(conn, name)
        database = AppDatabase(self.server, name)
        if extensions:
            database.report = database.provision_extensions()
        return database


@dataclass
class AppDatabase:
    server: OwnedPostgres
    name: str
    report: bootstrap.ExtensionReport | None = None
    _engines: dict[str, Engine] = field(default_factory=dict)

    def provision_extensions(self) -> bootstrap.ExtensionReport:
        with self.server.connect("postgres", self.name, autocommit=True) as conn:
            return bootstrap.provision_extensions(conn, self.name)

    def engine(self, role: str, *, pool_size: int = 2) -> Engine:
        key = f"{role}/{pool_size}"
        if key not in self._engines:
            self._engines[key] = make_engine(lambda: self.server.connect(role, self.name), pool_size=pool_size)
        return self._engines[key]

    def upgrade(self, revision: str = "head") -> None:
        with self.engine(APP_MIGRATOR).connect() as connection:
            migrate.upgrade(connection, revision)

    def downgrade(self, revision: str, *, allow_data_loss: bool = False) -> None:
        with self.engine(APP_MIGRATOR).connect() as connection:
            migrate.downgrade(connection, revision, allow_data_loss=allow_data_loss)

    def current(self) -> str | None:
        with self.engine(APP_MIGRATOR).connect() as connection:
            return migrate.current(connection)

    @contextmanager
    def superuser(self) -> Iterator[Any]:
        """An autocommit superuser psycopg connection to this database (inspection and test setup only)."""
        with self.server.connect("postgres", self.name, autocommit=True) as conn:
            yield conn

    def dispose(self) -> None:
        for engine in self._engines.values():
            engine.dispose()
        self._engines.clear()


NewDatabase = Callable[..., AppDatabase]
