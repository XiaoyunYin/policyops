"""Generate the committed OpenAPI document of the served API (T08).

    python -m policyops.api.openapi --out FILE     write FILE
    python -m policyops.api.openapi --check FILE   exit 1 if FILE differs from a fresh export

The document is built from the same route composition `create_app(auth)` serves (`include_api_routes`), on an
app without a runtime: no settings, environment, keys, database or identity provider are read, and that app is
not servable (every authenticated route fails closed, as there is no runtime to resolve). Requirements our own
dependencies enforce are documented by `policyops.api.docs`; the export refuses a document that still carries
FastAPI's default validation-error body. Output is canonical (sorted keys, two-space indent, LF, trailing newline)
and depends only on the code, so regeneration is reproducible. The checked TypeScript types are generated from
this file (`scripts/api_types.py`).
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys
from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from policyops.api import docs
from policyops.api.app import create_app, include_api_routes


DEFAULT_VALIDATION_SCHEMAS = ("HTTPValidationError", "ValidationError")


class UndocumentedError(ValueError):
    """An operation documents a response body the API never returns."""


def schema_app() -> FastAPI:
    app = create_app()
    include_api_routes(app)
    return app


def document(app: FastAPI) -> dict[str, Any]:
    result = get_openapi(title=app.title, version=app.version, openapi_version=app.openapi_version,
                         routes=app.routes)
    result.setdefault("components", {})["securitySchemes"] = docs.SECURITY_SCHEMES
    leaked = [name for name in DEFAULT_VALIDATION_SCHEMAS if name in result["components"].get("schemas", {})]
    if leaked:
        raise UndocumentedError(f"FastAPI default schemas {leaked} are documented; declare 422 via docs.operation")
    return result


def export() -> bytes:
    return (json.dumps(document(schema_app()), indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    generated = export()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(generated)
        return 0
    if not args.check.is_file() or args.check.read_bytes() != generated:
        print(f"{args.check} differs from a fresh OpenAPI export", file=sys.stderr)
        return 1
    print("OpenAPI document matches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
