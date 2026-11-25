"""Plan, run or report a historical ticket import in a disposable local workspace."""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import sys

from runtime import helpdesk_settings, own_engine

from policyops.persistence.database import verify_runtime_role
from policyops.persistence.roles import APP_RUNTIME
from policyops.services.helpdesk_export import ImportRefused, VerifiedExport, utc_timestamp
from policyops.services.helpdesk_import import TicketImport


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run", "report"):
        command = commands.add_parser(name)
        command.add_argument("--connection", required=True)
        if name != "report":
            command.add_argument("--file", required=True, type=Path)
            command.add_argument("--exported-at", required=True)
        if name != "plan":
            command.add_argument("--sha256", required=True, help="SHA-256 from plan")
    args = parser.parse_args()
    try:
        if os.environ.get("POLICYOPS_ENV") != "local":
            raise ImportRefused("local_environment_required")
        configured = helpdesk_settings()
        config = configured.connection(args.connection) if configured is not None else None
        if config is None:
            raise ImportRefused("unknown_connection")
        if config.writeback_enabled:
            raise ImportRefused("writeback_enabled")
        sha = getattr(args, "sha256", None)
        if sha is not None and re.fullmatch(r"[0-9a-f]{64}", sha) is None:
            raise ImportRefused("invalid_sha256")
        if args.command != "report":
            try:
                exported_at = utc_timestamp(args.exported_at)
            except ValueError:
                raise ImportRefused("invalid_exported_at") from None
            source = VerifiedExport.read(args.file, expected_sha256=sha)

        with own_engine(APP_RUNTIME) as engine:
            verify_runtime_role(engine, APP_RUNTIME)
            importer = TicketImport(engine, config)
            if args.command == "plan":
                output = importer.plan(source, exported_at)
            elif args.command == "run":
                output = asdict(importer.run(source, exported_at))
            else:
                output = asdict(importer.report(sha))
        print(json.dumps(output))
    except Exception as error:
        reason = error.reason if isinstance(error, ImportRefused) else type(error).__name__
        print(json.dumps({"error": reason}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
