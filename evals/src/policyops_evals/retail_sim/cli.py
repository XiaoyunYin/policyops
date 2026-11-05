"""`policyops-retail-simulator`: stage the audited fixture, bootstrap the retail roles, migrate, or serve.

    stage     --source-tree TREE --fixture-root ROOT
    bootstrap --db-host H --db-port P --db-name D --db-password-file SUPERUSER_FILE
              --migrator-password-file F --runtime-password-file F                (as the superuser)
    migrate --db-host H --db-port P --db-name D --db-password-file F          (as retail_migrator)
    serve   --db-host H --db-port P --db-name D --db-password-file F --fixture-root ROOT --key-file K
            [--port N] [--faults]                                              (as retail_runtime, 127.0.0.1 only)

Passwords and the service key are read from files and never printed. The server listens on 127.0.0.1 only; the
container/deployment wiring is T38's. `--faults` enables the one-shot test fault endpoint (default off).
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import psycopg
from sqlalchemy import Engine, create_engine

from policyops_evals.retail_sim import auth, bootstrap, fixture, migrate
from policyops_evals.retail_sim.store import Store


def connector(host: str, port: int, database: str, role: str, password: str) -> Any:
    def connect() -> psycopg.Connection[Any]:
        return psycopg.connect(host=host, hostaddr=host, port=port, dbname=database, user=role, password=password,
                               sslmode="disable", gssencmode="disable", connect_timeout=5,
                               options="-c timezone=UTC", application_name="policyops-retail-simulator")
    return connect


def make_engine(host: str, port: int, database: str, role: str, password: str, *, pool_size: int = 8) -> Engine:
    return create_engine("postgresql+psycopg://", creator=connector(host, port, database, role, password),
                         pool_size=pool_size, max_overflow=0, pool_reset_on_return="rollback")


def _database(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db-host", default="127.0.0.1")
    parser.add_argument("--db-port", type=int, required=True)
    parser.add_argument("--db-name", required=True)
    parser.add_argument("--db-password-file", type=Path, required=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="policyops-retail-simulator")
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--source-tree", type=Path, required=True)
    stage.add_argument("--fixture-root", type=Path, required=True)
    for name in ("bootstrap", "migrate", "serve"):
        _database(sub := commands.add_parser(name))
        if name == "bootstrap":
            sub.add_argument("--migrator-password-file", type=Path, required=True)
            sub.add_argument("--runtime-password-file", type=Path, required=True)
        if name == "serve":
            sub.add_argument("--fixture-root", type=Path, required=True)
            sub.add_argument("--key-file", type=Path, required=True)
            sub.add_argument("--port", type=int, default=0)
            sub.add_argument("--faults", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "stage":
        fixture.stage(args.source_tree, args.fixture_root)
        print('{"staged": true}')
        return 0
    password = args.db_password_file.read_text(encoding="utf-8").strip()
    if args.command == "bootstrap":
        passwords = {bootstrap.MIGRATOR: args.migrator_password_file.read_text(encoding="utf-8").strip(),
                     bootstrap.RUNTIME: args.runtime_password_file.read_text(encoding="utf-8").strip()}
        with connector(args.db_host, args.db_port, args.db_name, "postgres", password)() as conn:
            conn.autocommit = True
            bootstrap.provision(conn, args.db_name, passwords)
        print('{"bootstrapped": true}')
        return 0
    role = bootstrap.MIGRATOR if args.command == "migrate" else bootstrap.RUNTIME
    engine = make_engine(args.db_host, args.db_port, args.db_name, role, password)
    if args.command == "migrate":
        with engine.connect() as connection:
            migrate.upgrade(connection)
        engine.dispose()
        print('{"migrated": true}')
        return 0
    import uvicorn

    from policyops_evals.retail_sim.app import create_app

    loaded = fixture.load(args.fixture_root)
    store = Store(engine, loaded, fixture.upstream(loaded))
    store.require_head()
    key = auth.Key(args.key_file.read_bytes())  # raw bytes: never strip a binary key
    uvicorn.run(create_app(store, key, faults_enabled=args.faults), host="127.0.0.1", port=args.port,
                log_level="warning", access_log=False, server_header=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
