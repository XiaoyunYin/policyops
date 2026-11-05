"""`python -m policyops.retrieval.cli ingest`: import one corpus into one workspace (T12).

Workspace-bound and operator-run: the process holds database credentials, so there is no principal or membership
check (like the synthetic importer). There is no HTTP endpoint and no worker.

    python -m policyops.retrieval.cli ingest --workspace UUID --corpus-key KEY --manifest PATH
        --manifest-sha256 HEX --acquisition-root PATH
        [--execute [--paid --model M --dimensions D --max-usd USD --max-calls N --max-input-tokens T
                    --max-seconds S]]

- Without `--execute` the run is a read-only plan (no write, reservation, credential read or request).
- `--execute` allows writes; any provider work also needs `--paid` with every cap given explicitly (no defaults),
  each within the ingestion ceilings. An all-cached import needs no `--paid`.
- The database connection uses the standard libpq environment (`PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`,
  `PGPASSFILE`); the role must be `policyops_app_runtime`, which is verified after argument, manifest and source
  preparation and before any database write or provider work. The OpenAI key is read from `OPENAI_API_KEY` only
  after a paid preflight passed.
- Output: one JSON object on stdout with the outcome and counts, digests, estimate and caps; never document text or
  secrets. Exit codes: 0 planned, unchanged or activated; 2 refused; 3 embedding incomplete (the previous generation
  stays active); 4 stale activation; 1 verification failure or unexpected error (type only).
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import sys
from typing import Any, TextIO
from uuid import UUID

import psycopg

from policyops.persistence.database import make_engine
from policyops.providers import tokenizer as tokenizers
from policyops.providers.calls import Providers
from policyops.retrieval.ingest import Outcome, PaidCaps, Request, ingest
from policyops.retrieval.sources import MAX_MANIFEST_BYTES
from policyops.runtime.clock import LeaseClock


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:  # a usage error is a refusal (exit 2), reported as JSON
        raise _Usage(message)


class _Usage(Exception):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="policyops.retrieval.cli", description="Versioned policy corpus ingestion.")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("ingest")
    run.add_argument("--workspace", required=True, type=UUID)
    run.add_argument("--corpus-key", required=True)
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--manifest-sha256", required=True)
    run.add_argument("--acquisition-root", required=True, type=Path)
    run.add_argument("--execute", action="store_true")
    run.add_argument("--paid", action="store_true")
    run.add_argument("--model")
    run.add_argument("--dimensions", type=int)
    run.add_argument("--max-usd")
    run.add_argument("--max-calls", type=int)
    run.add_argument("--max-input-tokens", type=int)
    run.add_argument("--max-seconds", type=int)
    return parser


PAID_FLAGS = ("model", "dimensions", "max_usd", "max_calls", "max_input_tokens", "max_seconds")


def _paid(args: argparse.Namespace) -> PaidCaps | None:
    given = [name for name in PAID_FLAGS if getattr(args, name) is not None]
    if not args.paid:
        if given:
            raise _Usage("caps are only accepted with --paid")
        return None
    if not args.execute:
        raise _Usage("--paid requires --execute")
    missing = [name for name in PAID_FLAGS if getattr(args, name) is None]
    if missing:
        raise _Usage(f"--paid requires every cap explicitly: missing {', '.join(missing)}")
    try:
        usd = Decimal(args.max_usd)
    except InvalidOperation:
        raise _Usage("--max-usd is not a decimal") from None
    try:
        return PaidCaps(args.model, args.dimensions, usd, args.max_calls, args.max_input_tokens, args.max_seconds)
    except ValueError as exc:
        raise _Usage(str(exc)) from None


def _read_manifest(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(MAX_MANIFEST_BYTES + 1)


def _production_providers() -> Providers:
    """Read only after a paid preflight passed; the key never appears in output."""
    import httpx2
    from pydantic import SecretStr

    key = os.environ.get("OPENAI_API_KEY")
    return Providers(credentials={"openai": SecretStr(key)} if key else {},
                     transport=lambda name: httpx2.AsyncHTTPTransport())


def main(argv: Sequence[str] | None = None, *, connect: Callable[[], psycopg.Connection[Any]] | None = None,
         providers: Callable[[], Providers] = _production_providers, tokenizer: tokenizers.Tokenizer | None = None,
         env: str | None = None, clock: LeaseClock | None = None, stdout: TextIO | None = None) -> int:
    out = stdout or sys.stdout
    try:
        args = _parser().parse_args(argv)
        paid = _paid(args)
    except _Usage as exc:
        return _emit(out, Outcome("refused", "usage", {"detail": str(exc)}))
    try:
        manifest = _read_manifest(args.manifest)
    except OSError:
        return _emit(out, Outcome("refused", "manifest_unreadable"))
    request = Request(args.workspace, args.corpus_key, manifest, args.manifest_sha256, args.acquisition_root,
                      "execute" if args.execute else "plan", paid)
    engine = make_engine(connect or (lambda: psycopg.connect(connect_timeout=10)), pool_size=4)
    try:
        outcome = ingest(request, engine=engine, tokenizer=tokenizer or tokenizers.load(), providers=providers,
                         env=env or os.environ.get("POLICYOPS_ENV", "production"), clock=clock)
    except Exception as exc:
        return _emit(out, Outcome("failed", "unexpected_error", {"error": type(exc).__name__}))
    finally:
        engine.dispose()
    return _emit(out, outcome)


def _emit(out: TextIO, outcome: Outcome) -> int:
    out.write(json.dumps(outcome.to_json(), sort_keys=True, default=str) + "\n")
    out.flush()
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
