"""Bedrock pure wire, admission and accounting contracts; independent of credential installation."""

from __future__ import annotations

from dataclasses import fields, is_dataclass, replace
from decimal import Decimal
import hashlib
import json
from typing import Any

import pytest

from policyops.budget.config import DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.budget.prices import SNAPSHOT_2026_11_05, SNAPSHOT_2026_11_15, UnknownPrice
from policyops.budget.pricing import Usage, cost
from policyops.budget.registry import BEDROCK_REGISTRY, ChatModel, NotAllowed, Registry
from policyops.providers.adapters import _Accumulated, _observe
from policyops.providers.bedrock import K_FIXED, K_PER_MESSAGE, input_bound
from policyops.providers.capability import capability_record
from policyops.providers.contract import ContractGap, require_clean_environment
from policyops.providers.results import bedrock_evidence
from policyops.providers.serialize import PreparedRequest, prepare
from policyops.providers.tokenizer import load as load_tokenizer
from policyops_contracts.model import Message, ModelRequest, OutputSpec, TextPart, ToolResultPart, ToolSpec
from tests.unit.test_providers_contract import NamesOnly


MODEL = "us.anthropic.claude-haiku-5-5"
REGISTRY_MODEL = "bedrock:us.anthropic.claude-haiku-5-5"
SCHEMA = '{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false}'


def configuration(**changes: Any) -> Configuration:
    return Configuration(registry=BEDROCK_REGISTRY, actors={**DEFAULT_ACTORS,
                         "judge": ChatActor("judge", REGISTRY_MODEL, "low", **changes)},
                         caps=Caps(request_max_input=100_001))


def request(**changes: Any) -> ModelRequest:
    values: dict[str, Any] = {"instructions": "Reply with JSON.", "messages": (
        Message(role="user", parts=(TextPart(text="Confirm."),)),), "max_output_tokens": 64,
        "output": OutputSpec(name="answer", answer_schema_json=SCHEMA)}
    return ModelRequest(**(values | changes))


def prepared(**changes: Any) -> PreparedRequest:
    return prepare(request(**changes), configuration(), "judge")


def response(**changes: Any) -> dict[str, Any]:
    return {"id": "msg_1", "type": "message", "role": "assistant", "content": [{"type": "text", "text": '{"ok":true}'}],
            "model": "claude-haiku-5-5", "stop_reason": "end_turn",
            "usage": {"input_tokens": 12, "output_tokens": 5}} | changes


@pytest.mark.parametrize("name", ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "AWS_CA_BUNDLE", "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_STS_REGIONAL_ENDPOINTS",
    "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_BEARER_TOKEN_BEDROCK", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_LOG"])
def test_ambient_names_only_refusal(name: str) -> None:
    with pytest.raises(ContractGap, match=r"^bedrock.ambient_settings$"):
        require_clean_environment("bedrock", NamesOnly({name: "CANARY"}))


@pytest.mark.parametrize(("text", "messages"), [
    ("Confirm.", 1), ("你好世界🙂", 1), ("a", 256), ("policy " * 1000, 5)])
def test_admission_exceeds_fixture_text_tokens_and_counts_framing(text: str, messages: int) -> None:
    p = prepared(messages=tuple(Message(role="user" if i % 2 == 0 else "assistant", parts=(TextPart(text=text),))
                                for i in range(messages)))
    bound = input_bound(p)
    assert bound >= len(text.encode("utf-8")) * messages + K_FIXED + K_PER_MESSAGE * messages
    # Actual local BPE counts are a negative-control tokenizer, not claims about live Haiku usage. The proof is
    # the source-byte bound; a different BPE vocabulary cannot emit more text tokens than source bytes.
    fixture_tokens = load_tokenizer().count(text) * messages
    assert bound > fixture_tokens
    with_tool = prepared(tools=(ToolSpec(name="lookup", description="Lookup", parameters_schema_json=SCHEMA),))
    assert input_bound(with_tool) > input_bound(prepared())


def test_refusals_and_distinct_registry() -> None:
    with pytest.raises(ContractGap, match="long_context"):
        prepare(request(), configuration(max_input=100_001), "judge")
    for changes in ({"stream": True}, {"messages": (Message(role="user", parts=(ToolResultPart(
        call_id="x", content="no"),)),)}):
        with pytest.raises(ContractGap):
            prepared(**changes)


@pytest.mark.parametrize(("identifier", "code"), [
    ("anthropic.claude-haiku-5-5", "bedrock.on_demand_unsupported"),
    ("claude-haiku-5-5", "bedrock.on_demand_unsupported"),
    ("global.anthropic.claude-haiku-5-5", "bedrock.global_profile_unsupported"),
    ("us.anthropic.claude-haiku-5-5:0", "bedrock.model_unsupported"),
    ("us.anthropic.claude-haiku-5-5%3A0", "bedrock.model_unsupported"),
    ("us%2Eanthropic.claude-haiku-5-5", "bedrock.model_unsupported"),
    ("us.anthropic.claude-haiku-5-5/invoke", "bedrock.model_unsupported"),
    ("arn:aws:bedrock:us-west-2:123456789012:inference-profile/private", "bedrock.model_unsupported"),
])
def test_identifier_refusals_in_registry_and_serializer(identifier: str, code: str) -> None:
    model = "bedrock:" + identifier
    with pytest.raises(NotAllowed) as refused:
        BEDROCK_REGISTRY.chat(model, effort="low", cache_mode="none")
    assert str(refused.value) == code
    with pytest.raises(UnknownPrice):
        SNAPSHOT_2026_11_15.price(model)
    # Even a caller-created priced registry cannot redirect the fixed Bedrock adapter.
    price = replace(SNAPSHOT_2026_11_15.price(REGISTRY_MODEL), model=model)
    snapshot = replace(SNAPSHOT_2026_11_15, models={**SNAPSHOT_2026_11_15.models, model: price})
    registry = Registry(snapshot, {**BEDROCK_REGISTRY.models,
                                  model: ChatModel(model, frozenset({"low"}), frozenset({"none"}))})
    config = replace(configuration(), registry=registry,
                     actors={**DEFAULT_ACTORS, "judge": ChatActor("judge", model, "low")})
    with pytest.raises(ContractGap) as serialized:
        prepare(request(), config, "judge")
    assert str(serialized.value) == code


def test_profile_price_rates_and_residency_record() -> None:
    price = SNAPSHOT_2026_11_15.price(REGISTRY_MODEL)
    short = price.tier_for(100_000)
    assert (short.input, short.output, short.cache_writes["5m"], short.cache_writes["1h"], short.cache_read) == (
        Decimal("0.11"), Decimal("0.55"), Decimal("0.1375"), Decimal("0.22"), Decimal("0.011"))
    record = capability_record()
    protocol = record["protocol"]["bedrock"]
    assert protocol["model"] == MODEL and protocol["region"] == "us-west-2"
    assert protocol["serving_regions"] == ["us-east-1", "us-east-2", "us-west-2"]
    assert protocol["data_residency"] == "US"
    assert all(state == "not_run" for state in record["live"]["bedrock"].values())


@pytest.mark.parametrize("model", [MODEL, "anthropic.claude-haiku-5-5", "claude-haiku-5-5"])
def test_profile_routed_response_model(model: str) -> None:
    evidence = bedrock_evidence(response(model=model), prepared())
    assert evidence.block is None and evidence.usage == Usage(12, output=5, reasoning=None)
    assert evidence.returned_model == model


@pytest.mark.parametrize("model", [None, 123, "global.anthropic.claude-haiku-5-5", "unrelated-model"])
def test_profile_response_model_negative_controls(model: Any) -> None:
    evidence = bedrock_evidence(response(model=model), prepared())
    assert evidence.usage is None and evidence.block == "model_unconfirmed"


def test_response_model_omission_retains_endpoint_identity() -> None:
    body = response()
    del body["model"]
    assert bedrock_evidence(body, prepared()).block is None


@pytest.mark.parametrize("region", ["us-east-1", "us-east-2", "us-west-2"])
def test_profile_serving_region(region: str) -> None:
    usage = {"input_tokens": 12, "output_tokens": 5, "inference_geo": region}
    assert bedrock_evidence(response(usage=usage), prepared()).block is None
    assert bedrock_evidence(response(usage=usage | {"inference_geo": "eu-west-1"}), prepared()).usage is None


def test_usage_cache_pricing_and_contradictions() -> None:
    p = prepared()
    usage = {"input_tokens": 100, "cache_read_input_tokens": 200, "cache_creation_input_tokens": 50,
             "cache_creation": {"ephemeral_5m_input_tokens": 20, "ephemeral_1h_input_tokens": 30}, "output_tokens": 10}
    evidence = bedrock_evidence(response(usage=usage), p)
    assert evidence.usage == Usage(350, cache_read=200, cache_writes={"5m": 20, "1h": 30}, output=10, reasoning=None)
    assert evidence.block == "cache_write_under_none"
    assert cost(SNAPSHOT_2026_11_15.price(REGISTRY_MODEL), evidence.usage).usd == Decimal("0.00002805")
    for bad in (usage | {"cache_creation_input_tokens": 0}, usage | {"cache_creation_input_tokens": 51},
                usage | {"cache_creation": {"ephemeral_5m_input_tokens": 50}},
                usage | {"input_tokens": True}, usage | {"input_tokens": -1}, usage | {"service_tier": "standard"},
                usage | {"total_tokens": 359}):
        assert bedrock_evidence(response(usage=bad), p).usage is None
    assert bedrock_evidence(response(usage={"output_tokens": 1}), p).usage is None
    over = bedrock_evidence(response(usage={"input_tokens": 1, "output_tokens": 65}), p)
    assert over.block == "output_limit_exceeded"
    acc = _Accumulated()
    _observe(acc, {"input_tokens": 10})
    _observe(acc, {"input_tokens": 9})
    _observe(acc, {"input_tokens": 12})
    assert acc.usage_inconsistent  # retained existing cumulative contradiction guard


def test_old_snapshot_digest_and_defaults_unchanged() -> None:
    def normalize(value: Any) -> Any:
        if is_dataclass(value):
            return {f.name: normalize(getattr(value, f.name)) for f in fields(value)}
        if isinstance(value, dict) or hasattr(value, "items"):
            return {k: normalize(v) for k, v in value.items()}
        if isinstance(value, tuple):
            return [normalize(v) for v in value]
        return str(value) if isinstance(value, Decimal) else value

    digest = hashlib.sha256(json.dumps(normalize(SNAPSHOT_2026_11_05), sort_keys=True,
                                       separators=(",", ":")).encode()).hexdigest()
    assert digest == "7df606a1cda739a5c17509cb063e99306626200bbb2ca98b57d062b51151f089"
    assert SNAPSHOT_2026_11_05.models.keys() < SNAPSHOT_2026_11_15.models.keys()
    assert Configuration().actors["judge"].model == "claude-haiku-5-5"

