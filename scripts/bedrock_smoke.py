"""Coordinator-only paid smoke: one tiny structured request, a persisted PostgreSQL ledger, <=4 calls / $0.05.

Use a migrated local app database with an existing workspace and libpq PG* settings for its app-runtime login.
Uses us.anthropic.claude-haiku-5-5 (US residency across three regions).
Repeated runs share the named operation scope, including unresolved liability. No paid execution without --execute.
"""

from __future__ import annotations

import argparse
import asyncio
from decimal import Decimal
import json
import time
from uuid import UUID, uuid4

import httpx2
import psycopg

from policyops.budget.config import DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.budget.ledger import OperationBinding
from policyops.budget.pricing import worst_case
from policyops.budget.registry import BEDROCK_REGISTRY
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.database import RUNTIME_CONNECT_OPTIONS, make_engine
from policyops.persistence.roles import APP_RUNTIME
from policyops.providers.bedrock_auth import MODEL, REGISTRY_MODEL, BedrockAccess, BedrockSettings
from policyops.providers.calls import CallLimits, Providers, call
from policyops_contracts.model import Message, ModelRequest, OutputSpec, TextPart


def configuration() -> Configuration:
    return Configuration(registry=BEDROCK_REGISTRY,
                         actors={**DEFAULT_ACTORS, "judge": ChatActor("judge", REGISTRY_MODEL, "low",
                                 max_input=4096, max_output=64, count_headroom_percent=0, count_headroom_min=0)},
                         caps=Caps(operation_calls=4, operation_usd=Decimal("0.05")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--workspace", required=True, type=UUID)
    parser.add_argument("--operation-key", default="bedrock-haiku-smoke-v1",
                        help="Persisted budget key; reuse across repeats, including after changing the model profile")
    args = parser.parse_args()
    if not args.execute:
        return 2
    summary: dict[str, object] = {"effective_model": MODEL, "usage": None, "cost_usd": None, "request_id": None}
    result_code = 1
    engine = None
    try:
        config = configuration()
        assert worst_case(config.price("judge"), max_input=4096, max_output=64) * 4 <= Decimal("0.05")  # noqa: S101
        access = BedrockAccess.from_settings(BedrockSettings())
        engine = make_engine(lambda: psycopg.connect(user=APP_RUNTIME, connect_timeout=5,
                                                      options=RUNTIME_CONNECT_OPTIONS), pool_size=1)
        ledger = build_app_ledger(env="local", engine=engine, workspace_id=args.workspace, configuration=config)
        providers = Providers({}, lambda _: httpx2.AsyncHTTPTransport(retries=0), bedrock=access)
        request = ModelRequest(instructions='Reply with the JSON object {"ok":true}.',
            messages=(Message(role="user", parts=(TextPart(text="Confirm."),)),), max_output_tokens=64,
            output=OutputSpec(name="answer", answer_schema_json=json.dumps({"type": "object", "properties": {
                "ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False})))
        report = asyncio.run(call(ledger, providers, OperationBinding("bedrock-smoke", args.operation_key),
                                 uuid4(), "smoke", request, "judge", deadline=time.monotonic() + 30,
                                 limits=CallLimits(retries_per_request=0, repairs=0, attempt_seconds=25)))
        if report.result is not None:
            summary["usage"] = report.result.usage.model_dump(mode="json")
            summary["request_id"] = report.result.provider_request_id
        known = [record.evidence.usage for record in report.attempts
                 if record.evidence is not None and record.evidence.usage is not None]
        if known:
            from policyops.budget.pricing import cost

            summary["cost_usd"] = str(sum((cost(config.price("judge"), usage).usd for usage in known), Decimal(0)))
        result_code = 0 if report.result is not None and report.result.outcome == "structured" else 1
    except Exception:
        # No exceptions/headers/bodies/configuration values reach stdout, stderr or a serialized report.
        result_code = 1
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps(summary, sort_keys=True))
    return result_code


if __name__ == "__main__":
    raise SystemExit(main())
