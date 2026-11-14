"""T11 provider contract, pure parts: strict canonical JSON, exact numbers, schema registration and validation, the
exact serialized requests and their identity, and the usage evidence rules (reviewer oracles 1-6).
"""

from __future__ import annotations

from decimal import Decimal, localcontext
import json
from typing import Any

import pytest

from policyops.budget.config import DEFAULT_ACTORS, ChatActor, Configuration
from policyops.budget.ledger import Diagnostic, Settlement
from policyops.budget.prices import SNAPSHOT_2026_11_05
from policyops.budget.pricing import Usage, cost
from policyops.providers.bounds import REQUEST_BOUNDS
from policyops.providers.canonical import (
    CanonicalError,
    canonical_bytes,
    fresh,
    output_bytes,
    sha256_hex,
    strict_loads,
)
from policyops.providers.contract import (
    CONTRACT_VERSION,
    ENDPOINTS,
    ContractGap,
    ambient_settings,
    require_clean_environment,
)
from policyops.providers.results import anthropic_evidence, anthropic_result, openai_evidence, openai_result
from policyops.providers.schema import SchemaGap, check_schema, validation_errors
from policyops.providers.serialize import prepare
from policyops.providers.tools import StepRefused, retail_tool_spec, to_agent_step
from policyops_contracts.agent import ToolCallStep
from policyops_contracts.model import (
    Message,
    ModelRequest,
    ModelResult,
    OutputSpec,
    ReportedUsage,
    TextPart,
    ToolCall,
    ToolUsePart,
)
from policyops_contracts.retail import Calculate, ExchangeDeliveredOrderItems, ReturnDeliveredOrderItems


def schema(**properties: Any) -> str:
    return json.dumps({"type": "object", "properties": properties, "required": sorted(properties),
                       "additionalProperties": False})


ANSWER = schema(decision={"type": "string", "enum": ["approve", "deny"]}, amount={"type": "integer", "minimum": 0})
RETURN = retail_tool_spec(ReturnDeliveredOrderItems, "Return delivered items to the original payment method.")


def request(**changes: Any) -> ModelRequest:
    body: dict[str, Any] = {
        "instructions": "Follow the retail policy.",
        "messages": (Message(role="user", parts=(TextPart(text="Please return my order #W0000001."),)),),
        "tools": (RETURN,), "max_output_tokens": 512} | changes
    return ModelRequest(**body)


def prepared(actor: str = "agent", configuration: Configuration | None = None, **changes: Any) -> Any:
    return prepare(request(**changes), configuration or Configuration(), actor)


# -- canonical JSON -----------------------------------------------------------------------------------------------

def test_canonical_bytes_are_strict_and_order_preserving() -> None:
    assert canonical_bytes({"b": [3, 1, 2], "a": "é"}) == '{"a":"é","b":[3,1,2]}'.encode()
    assert canonical_bytes({"x": False}) != canonical_bytes({"x": 0})  # never False == 0
    assert canonical_bytes({"x": True}) != canonical_bytes({"x": 1})
    for bad in ({"x": 0.5}, {"x": float("nan")}, {1: "x"}, {"x": Decimal("1.5")}, {"x": object()}):
        with pytest.raises(CanonicalError):
            canonical_bytes(bad)
    for text in ('{"a": 1, "a": 2}', '{"a": NaN}', '{"a": Infinity}', '{"a": 1', "[1, 2] x"):
        with pytest.raises(CanonicalError):
            strict_loads(text)


def test_output_numbers_are_exact_and_context_independent() -> None:
    value = strict_loads('{"a": 1.000000000000000000000000000001, "b": 1e400, "c": 1.0, "d": 123456789012345678901'
                         '234567890.5}')
    assert isinstance(value["b"], Decimal) and value["b"].is_finite()  # never float('inf')
    with pytest.raises(CanonicalError, match="range"):
        output_bytes(value)  # 1e400 is outside the supported exponent range
    del value["b"]
    with localcontext() as context:
        context.prec = 5  # the ambient context never changes the written digits
        assert output_bytes(value) == (b'{"a":1.000000000000000000000000000001,"c":1,'
                                       b'"d":123456789012345678901234567890.5}')


# -- schema registration and validation --------------------------------------------------------------------------

def test_a_retail_dto_schema_registers_with_a_documented_projection() -> None:
    checked = check_schema(RETURN.parameters_schema_json)
    wire = fresh(checked.wire)
    assert set(wire["properties"]) == {"order_id", "item_ids", "payment_method_id"}
    assert "pattern" not in json.dumps(wire) and "maxItems" not in json.dumps(wire)
    assert {"pattern", "minItems", "maxItems", "title"} <= set(checked.projected_away)
    # The full domain schema still validates locally: patterns and list bounds apply.
    assert validation_errors(checked, {"order_id": "#W0000001", "item_ids": ["1000000001"],
                                       "payment_method_id": "credit_card_0000001"}) == ()
    assert validation_errors(checked, {"order_id": "W1", "item_ids": [], "payment_method_id": "x"}) != ()


@pytest.mark.parametrize(("document", "reason"), [
    ({"type": "object", "properties": {"a": {"type": "string"}}, "required": [], "additionalProperties": False},
     "required"),
    ({"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}, "additionalProperties"),
    ({"type": "object", "properties": {"a": {"oneOf": [{"type": "string"}]}}, "required": ["a"],
      "additionalProperties": False}, "unsupported keywords"),
    ({"type": "object", "properties": {"a": {"$ref": "https://example.invalid/s.json"}}, "required": ["a"],
      "additionalProperties": False}, "local"),
    ({"type": "object", "properties": {"a": {"type": "string", "pattern": "^(?=a)a$"}}, "required": ["a"],
      "additionalProperties": False}, "linear-time regex engine"),
    ({"type": "object", "properties": {"a": {"type": "string", "pattern": "^(a)\\1$"}}, "required": ["a"],
      "additionalProperties": False}, "linear-time regex engine"),
    ({"type": "object", "properties": {"a": {"type": "number", "maximum": 1.5}}, "required": ["a"],
      "additionalProperties": False}, "canonical subset"),
    ({"type": "object", "properties": {"a": {"type": "string", "format": "email"}}, "required": ["a"],
      "additionalProperties": False}, "unsupported keywords"),
])
def test_unsupported_schemas_are_refused_before_any_send(document: dict[str, Any], reason: str) -> None:
    with pytest.raises(SchemaGap, match=reason):
        check_schema(json.dumps(document))


def test_numeric_validation_follows_the_dialect_without_rounding() -> None:
    checked = check_schema(schema(n={"type": "integer", "maximum": 1}, c={"const": 1}, b={"type": "boolean"}))

    def errors(text: str) -> tuple[str, ...]:
        return validation_errors(checked, strict_loads(text))

    assert errors('{"n": 1, "c": 1, "b": true}') == ()
    assert errors('{"n": 1.0, "c": 1.0, "b": false}') == ()  # an integral number is an integer
    assert errors('{"n": 1.000000000000000001, "c": 1, "b": true}') == ("maximum@/n", "type@/n")
    assert errors('{"n": true, "c": 1, "b": true}') == ("type@/n",)  # a bool is never an integer
    assert errors('{"n": 1, "c": true, "b": true}') == ("const@/c",)  # nor equal to 1
    assert errors('{"n": 1e400, "c": 1, "b": true}') == ("maximum@/n",)  # exact overflow, not infinity
    assert errors('{"n": 0, "c": 1, "b": 1}') == ("type@/b",)


# -- serialization and identity ----------------------------------------------------------------------------------

def test_openai_request_is_the_exact_contracted_body() -> None:
    body = fresh(prepared().body)
    assert body["prompt_cache_options"] == {"mode": "explicit"}  # cache none: no implicit 30m writes
    assert (body["service_tier"], body["store"], body["parallel_tool_calls"], body["truncation"]) == (
        "default", False, False, "disabled")
    assert body["reasoning"] == {"effort": "low"} and body["model"] == "gpt-6-luna"
    assert body["tools"][0]["strict"] is True and "pattern" not in json.dumps(body["tools"])
    assert set(fresh(prepared().count_body)) == {"model", "input", "instructions", "tools", "tool_choice",
                                                 "reasoning", "parallel_tool_calls", "truncation"}
    cached = Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "gpt-6-luna", "low", "30m")})
    assert fresh(prepared(configuration=cached).body)["prompt_cache_options"] == {"mode": "implicit", "ttl": "30m"}
    long_cache = Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "gpt-6-luna", "low", "12h")})
    with pytest.raises(ContractGap, match="30m"):
        prepared(configuration=long_cache)


# The approved smoke's exact cases (live-smoke-v3.1 smoke.cases()),
# with the request and count fingerprints that the frozen T11 source (93afd3b) produced and the ledger recorded.
SMOKE_ANSWER = json.dumps({"type": "object", "properties": {"decision": {"type": "string", "enum": ["approve", "deny"]},
                                                            "reason": {"type": "string", "maxLength": 200}},
                           "required": ["decision", "reason"], "additionalProperties": False}, sort_keys=True)
SMOKE_CALCULATE = retail_tool_spec(Calculate, "Evaluate an arithmetic expression. Never call anything else.")
FROZEN_SMOKE = {
    ("openai", "text"): ("33a890e99eed6a7b5cf52764158af4e301e7f8d2862a8261cab38dd8cba3f413",
                         "0b3289288547231c698545b196749c6411018e42a5f2f070cdb24c537d4976e1"),
    ("openai", "tool"): ("f6386e9bb73f3f843eab02323680af7969300f9ca084166dc97a48b9144175dc",
                         "1d5be0a0a2ccc041ee238d22952133f10c199c140deeb28afa035aefbba817e3"),
    ("openai", "structured"): ("7d407edeb586d9a47e48e54993c7c5dd5c98f0235c7a58b1c5632039370eaa69",
                               "85851916dd465abb93a47d9df94f5aa8679b04b4aadc22c0979a5107ce286c6f"),
    ("anthropic", "text"): ("c0cdf13a0b891f3e76a121183ecf5d42b30010b6a8826c86f53ea31f5d06eb3e",
                            "2367409df8eb6e69e3029ccea71a89d0a01528f3c22ce726f170beeeab80be22"),
    ("anthropic", "tool"): ("ae53becbbc3555f63b45b10fd5d7769fb380c85e8041e5a2a24db058ff4f7a20",
                            "56538bb19978d60db41b3120497ddfbea9a2aa73db03c09da82a8af1ac722163"),
    ("anthropic", "structured"): ("232495c5f28d0b0ad114843d8f9da9d8432d51c2ea07709cfe22d80a63ce3aa1",
                                  "0b11d0d84b6fd7c68addcc512917719efe54d0c7ab557d4ba7e36f95e970d36a"),
}


def smoke_request(name: str) -> ModelRequest:
    def user(text: str) -> tuple[Message, ...]:
        return (Message(role="user", parts=(TextPart(text=text),)),)
    if name == "text":
        return ModelRequest(instructions="You are a test fixture. Answer in one short sentence.",
                            messages=user("Say that the smoke test is running."), max_output_tokens=64)
    if name == "tool":
        return ModelRequest(instructions="You are a test fixture. Use the calculate tool exactly once and say nothing "
                            "else.", messages=user("What is 12 * 7?"), tools=(SMOKE_CALCULATE,), tool_choice="required",
                            max_output_tokens=64)
    return ModelRequest(instructions="You are a test fixture. Reply with the required JSON object only.",
                        messages=user("Decide 'approve' with a one-sentence reason."),
                        output=OutputSpec(name="answer", answer_schema_json=SMOKE_ANSWER), max_output_tokens=128,
                        stream=True)


def envelope_sha256(provider: str, body: dict[str, Any], *, bounded: bool = False) -> str:
    """The request fingerprint `prepare` computes, for an arbitrary body (to reconstruct the frozen one)."""
    endpoint = ENDPOINTS[provider]
    return sha256_hex(canonical_bytes({**({"bounds": dict(REQUEST_BOUNDS)} if bounded else {}),
                                       "contract": CONTRACT_VERSION, "provider": provider, "method": "POST",
                                       "host": endpoint.host, "path": endpoint.create_path, "query": {},
                                       "version_headers": dict(endpoint.version_headers), "body": body}))


@pytest.mark.parametrize(("provider", "name"), sorted(FROZEN_SMOKE))
def test_body_provenance_is_preserved_and_new_bounds_are_digest_bound(provider: str, name: str) -> None:
    actor = "agent" if provider == "openai" else "judge"
    current = prepare(smoke_request(name), Configuration(), actor)
    frozen_request, frozen_count = FROZEN_SMOKE[(provider, name)]
    assert sha256_hex(current.count_body) == frozen_count  # the count body never carried `speed`
    body = fresh(current.body)
    assert current.request_sha256 == envelope_sha256(provider, body, bounded=True)
    assert current.request_sha256 != envelope_sha256(provider, body)  # T23 bounds change admission identity
    if provider == "openai":
        assert envelope_sha256(provider, body) == frozen_request  # provider body bytes are unchanged
        return
    assert "speed" not in body and current.request_sha256 != frozen_request  # a new identity, as expected
    assert envelope_sha256(provider, body | {"speed": "standard"}) == frozen_request  # the only difference


@pytest.mark.parametrize("name", ["text", "tool", "structured"])
@pytest.mark.parametrize("stream", [False, True])
def test_every_haiku_request_shape_omits_speed_and_keeps_tier_thinking_and_effort(name: str, stream: bool) -> None:
    request_ = smoke_request(name).model_copy(update={"stream": stream})
    current = prepare(request_, Configuration(), "judge")
    body, count = fresh(current.body), fresh(current.count_body)
    assert "speed" not in body and "speed" not in count and body["stream"] is stream
    assert body["service_tier"] == "standard_only" and body["thinking"] == {"type": "disabled"}
    assert body["output_config"]["effort"] == "low"
    assert not {"temperature", "top_p", "top_k", "inference_geo", "cache_control", "betas", "fallbacks"} & set(body)


def test_anthropic_request_disables_thinking_and_pins_the_standard_tier() -> None:
    body = fresh(prepared("judge").body)
    assert body["thinking"] == {"type": "disabled"} and body["output_config"] == {"effort": "low"}
    assert body["service_tier"] == "standard_only" and "speed" not in body  # the optional field is omitted
    assert not {"temperature", "top_p", "top_k", "inference_geo", "cache_control"} & set(body)
    assert set(fresh(prepared("judge").count_body)) == {"model", "system", "messages", "tools", "tool_choice",
                                                        "output_config", "thinking"}
    cached = Configuration(actors={**DEFAULT_ACTORS, "judge": ChatActor("judge", "claude-haiku-5-5", "low", "5m")})
    with pytest.raises(ContractGap, match="not implemented"):
        prepared("judge", configuration=cached)


def test_every_request_change_is_a_different_identity() -> None:
    base = prepared()
    other_message = Message(role="user", parts=(TextPart(text="Also order #W0000002."),))
    variants = [
        prepared(max_output_tokens=511), prepared(stream=True), prepared(tool_choice="required"), prepared(tools=()),
        prepared(instructions="Follow the retail policy!"),
        prepared(output=OutputSpec(name="answer", answer_schema_json=ANSWER)),
        prepared(messages=(request().messages[0], Message(role="assistant", parts=(TextPart(text="ok"),)),
                           other_message)),
        prepared(configuration=Configuration(actors={**DEFAULT_ACTORS,
                                                     "agent": ChatActor("agent", "gpt-6-luna", "none")})),
    ]
    digests = {base.request_sha256} | {variant.request_sha256 for variant in variants}
    assert len(digests) == len(variants) + 1
    assert prepared().request_sha256 == base.request_sha256  # deterministic
    params = base.params()
    params["model"] = "gpt-6-flagship"  # a fresh decode: the bound bytes are unchanged
    assert fresh(base.body)["model"] == "gpt-6-luna"


def test_local_checks_refuse_before_anything_is_reserved() -> None:
    with pytest.raises(ContractGap, match="maximum"):
        prepared(max_output_tokens=4096)
    stray = Message(role="assistant", parts=(ToolUsePart(call_id="c1", name="unknown_tool", arguments_json="{}"),))
    with pytest.raises(ContractGap, match="undeclared"):
        prepared(messages=(request().messages[0], stray))
    floaty = Message(role="assistant", parts=(ToolUsePart(call_id="c1", name=RETURN.name,
                                                          arguments_json='{"a": 0.5}'),))
    with pytest.raises(ContractGap, match="canonical"):
        prepared(messages=(request().messages[0], floaty))


# -- usage evidence (reviewer oracles) ----------------------------------------------------------------------------

def openai_response(**changes: Any) -> dict[str, Any]:
    return {"id": "resp_1", "model": "gpt-6-luna", "status": "completed", "service_tier": "default",
            "output": [{"type": "message", "role": "assistant",
                        "content": [{"type": "output_text", "text": "Done."}]}],
            "usage": {"input_tokens": 1000, "input_tokens_details": {"cached_tokens": 400, "cache_write_tokens": 200},
                      "output_tokens": 120, "output_tokens_details": {"reasoning_tokens": 20},
                      "total_tokens": 1120}} | changes


def anthropic_message(**changes: Any) -> dict[str, Any]:
    return {"id": "msg_1", "model": "claude-haiku-5-5", "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "Done."}],
            "usage": {"input_tokens": 400, "cache_read_input_tokens": 400, "cache_creation_input_tokens": 200,
                      "cache_creation": {"ephemeral_5m_input_tokens": 150, "ephemeral_1h_input_tokens": 50},
                      "output_tokens": 120, "service_tier": "standard"}} | changes


def test_oracle_1_openai_total_includes_cache_and_output_includes_reasoning() -> None:
    cached = Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "gpt-6-luna", "low", "30m")})
    evidence = openai_evidence(openai_response(), prepared(configuration=cached), "30m")
    assert evidence.usage == Usage(1000, cache_read=400, cache_writes={"30m": 200}, output=120, reasoning=20)
    assert evidence.block is None
    assert cost(SNAPSHOT_2026_11_05.price("gpt-6-luna"), evidence.usage).usd == Decimal("0.000129")
    # The same writes under cache none are a known mismatch: the exact bill settles and progress is blocked.
    assert openai_evidence(openai_response(), prepared(), "none").block == "cache_write_under_none"


def test_oracle_2_anthropic_total_adds_reads_and_creation_and_checks_the_split() -> None:
    evidence = anthropic_evidence(anthropic_message(), prepared("judge"))
    # Reasoning was not reported: recorded as unreported (None), never as an observed zero.
    assert evidence.usage == Usage(1000, cache_read=400, cache_writes={"5m": 150, "1h": 50}, output=120, reasoning=None)
    assert cost(SNAPSHOT_2026_11_05.price("claude-haiku-5-5"), evidence.usage).usd == Decimal("0.00013275")
    assert evidence.block == "cache_write_under_none"  # only cache none is implemented for Anthropic
    split = {"ephemeral_5m_input_tokens": 150, "ephemeral_1h_input_tokens": 40}
    usage = anthropic_message()["usage"] | {"cache_creation": split}
    mismatch = anthropic_evidence(anthropic_message(usage=usage), prepared("judge"))
    assert (mismatch.usage, mismatch.block) == (None, "cache_split_mismatch")


@pytest.mark.parametrize(("changes", "code"), [
    ({"service_tier": "priority"}, "service_tier_unpriced"),
    ({"model": "gpt-6-sol"}, "model_unconfirmed"),
    ({"usage": {"input_tokens": True, "output_tokens": 1}}, "usage_malformed"),
    ({"usage": {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 9, "cache_write_tokens": 9},
                "output_tokens": 1, "output_tokens_details": {"reasoning_tokens": 0}}}, "usage_malformed"),
])
def test_oracle_5_unpriceable_openai_evidence_is_never_a_known_bill(changes: dict[str, Any], code: str) -> None:
    evidence = openai_evidence(openai_response(**changes), prepared(), "none")
    assert evidence.usage is None and evidence.reported.state == "unknown" and evidence.block == code
    assert isinstance(evidence.diagnostic, Diagnostic) and evidence.diagnostic.codes == (code,)


@pytest.mark.parametrize(("usage_change", "code"), [
    ({"cache_creation": None}, "cache_ttl_unknown"),
    ({"cache_read_input_tokens": None}, "usage_incomplete"),
    ({"service_tier": None}, "service_tier_unpriced"),
    ({"inference_geo": "us"}, "inference_geo_unpriced"),
    ({"speed": "fast"}, "speed_unpriced"),
])
def test_oracle_5_unpriceable_anthropic_evidence_stays_unresolved(usage_change: dict[str, Any], code: str) -> None:
    usage = anthropic_message()["usage"] | usage_change
    evidence = anthropic_evidence(anthropic_message(usage=usage), prepared("judge"))
    assert (evidence.usage, evidence.block) == (None, code)


def test_missing_usage_is_unknown_without_a_block_and_no_id_is_invented() -> None:
    evidence = openai_evidence(openai_response(usage=None, id=None), prepared(), "none")
    assert (evidence.usage, evidence.block, evidence.provider_request_id) == (None, None, None)


def test_oracle_4_refusal_truncation_and_invalid_output_still_carry_their_known_bill() -> None:
    p = prepared(output=OutputSpec(name="answer", answer_schema_json=ANSWER), tools=())
    refused = openai_response(output=[{"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}])
    truncated = openai_response(status="incomplete", incomplete_details={"reason": "max_output_tokens"})
    invalid = openai_response(output=[{"type": "message", "content": [{"type": "output_text", "text": "{bad"}]}])
    for response, outcome in ((refused, "refused"), (truncated, "truncated"), (invalid, "invalid_output")):
        evidence = openai_evidence(response, p, "none")
        assert evidence.usage is not None  # the attempt settles
        assert openai_result(response, p, evidence).outcome == outcome
    good = openai_response(output=[{"type": "message", "content": [
        {"type": "output_text", "text": '{"decision": "approve", "amount": 10.0}'}]}])
    result = openai_result(good, p, openai_evidence(good, p, "none"))
    assert (result.outcome, result.structured_json) == ("structured", '{"amount":10,"decision":"approve"}')


def test_anthropic_thinking_despite_disabled_is_a_contract_gap() -> None:
    p = prepared("judge")
    message = anthropic_message(content=[{"type": "thinking", "thinking": "secret", "signature": "s"},
                                         {"type": "text", "text": "Done."}],
                                usage=anthropic_message()["usage"] | {"cache_creation_input_tokens": 0,
                                                                     "cache_creation": None})
    evidence = anthropic_evidence(message, p)
    assert evidence.usage is not None and evidence.block == "thinking_returned"
    result = anthropic_result(message, p, evidence)
    assert result.outcome == "contract_gap" and "secret" not in result.model_dump_json()


# -- tools → one checked agent step (oracle 10) -------------------------------------------------------------------

def completed(*calls: ToolCall, text: str | None = None) -> ModelResult:
    return ModelResult(outcome="completed", provider="openai", requested_model="gpt-6-luna", text=text,
                       tool_calls=calls, usage=ReportedUsage(state="unknown"))


ARGS = '{"item_ids":["1000000001"],"order_id":"#W0000001","payment_method_id":"credit_card_0000001"}'


def test_only_one_valid_tool_call_or_one_message_becomes_an_agent_step() -> None:
    step = to_agent_step(completed(ToolCall(call_id="c1", name=RETURN.name, arguments_json=ARGS)))
    assert isinstance(step, ToolCallStep) and isinstance(step.call, ReturnDeliveredOrderItems)
    assert step.call.order_id == "#W0000001"
    two = ToolCall(call_id="c2", name=RETURN.name, arguments_json=ARGS)
    for result, code in ((completed(ToolCall(call_id="c1", name=RETURN.name, arguments_json=ARGS), two),
                          "several_tool_calls"),
                         (completed(ToolCall(call_id="c1", name=RETURN.name, arguments_json=ARGS), text="Done."),
                          "text_with_tool_call"),
                         (completed(ToolCall(call_id="c1", name=RETURN.name, arguments_json="[1]")),
                          "arguments_not_an_object")):
        with pytest.raises(StepRefused) as refused:
            to_agent_step(result)
        assert refused.value.code == code
    exchange = retail_tool_spec(ExchangeDeliveredOrderItems, "Exchange items.")
    unpaired = '{"item_ids":["1000000001"],"new_item_ids":[],"order_id":"#W0000001",' \
               '"payment_method_id":"credit_card_0000001"}'
    with pytest.raises(StepRefused, match="arguments_invalid"):  # the DTO's cross-field rule still applies
        to_agent_step(completed(ToolCall(call_id="c1", name=exchange.name, arguments_json=unpaired)))
    assert to_agent_step(completed(text="Your return is on its way.")).kind == "message"


# -- ambient SDK settings (names only) ----------------------------------------------------------------------------

class NamesOnly(dict[str, str]):
    """Iterating gives the names; reading any value fails, so a names-only check is provable."""

    def __getitem__(self, key: str) -> str:
        raise AssertionError("a value was read")

    def get(self, key: str, default: Any = None) -> Any:
        raise AssertionError("a value was read")

    def __contains__(self, key: object) -> bool:
        raise AssertionError("membership must go through the key set")


def test_disallowed_sdk_environment_names_refuse_clients_without_reading_values() -> None:
    environ = NamesOnly(dict.fromkeys(("OPENAI_ORG_ID", "ANTHROPIC_CUSTOM_HEADERS", "ANTHROPIC_PROFILE",
                                       "ANTHROPIC_API_KEY", "PATH"), "x"))
    assert ambient_settings("openai", environ) == ("OPENAI_ORG_ID",)
    assert ambient_settings("anthropic", environ) == ("ANTHROPIC_CUSTOM_HEADERS", "ANTHROPIC_PROFILE")
    with pytest.raises(ContractGap, match="OPENAI_ORG_ID"):
        require_clean_environment("openai", environ)
    require_clean_environment("openai", NamesOnly(dict.fromkeys(("OPENAI_API_KEY", "PATH"), "x")))


def test_only_explicitly_confirmed_model_ids_are_priced() -> None:
    for returned in ("gpt-6-luna-2026-11-05", "gpt-6-luna-latest", "GPT-6-LUNA"):
        evidence = openai_evidence(openai_response(model=returned), prepared(), "none")
        assert (evidence.usage, evidence.block) == (None, "model_unconfirmed"), returned
    dated = anthropic_evidence(anthropic_message(model="claude-haiku-5-5-20261001"), prepared("judge"))
    assert (dated.usage, dated.block) == (None, "model_unconfirmed")


def test_a_known_bill_beyond_the_declared_token_limits_settles_and_blocks() -> None:
    p = prepared(max_output_tokens=128)  # the actor reservation itself allows 2048 output tokens
    over = openai_response(usage={"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0,
                                                                                "cache_write_tokens": 0},
                                  "output_tokens": 129, "output_tokens_details": {"reasoning_tokens": 0},
                                  "total_tokens": 1029})
    evidence = openai_evidence(over, p, "none")
    assert evidence.usage is not None and evidence.usage.output == 129  # the exact bill is known and settles ...
    assert evidence.block == "output_limit_exceeded"  # ... but progress stops
    prompt = openai_response(usage={"input_tokens": 16_001, "input_tokens_details": {"cached_tokens": 0,
                                                                                     "cache_write_tokens": 0},
                                    "output_tokens": 10, "output_tokens_details": {"reasoning_tokens": 0},
                                    "total_tokens": 16_011})
    assert openai_evidence(prompt, p, "none").block == "input_limit_exceeded"
    usage = anthropic_message()["usage"] | {"output_tokens": 129, "cache_creation_input_tokens": 0,
                                            "cache_creation": None}
    assert anthropic_evidence(anthropic_message(usage=usage), prepared("judge", max_output_tokens=128)).block == (
        "output_limit_exceeded")


# -- C2: consistent shared usage (N1) and versioned settlement digests -------------------------------------------

@pytest.mark.parametrize("fields", [
    {"input_total": 10, "cache_read": 8, "cache_writes": (("30m", 5),), "output": 1},  # parts exceed the whole
    {"input_total": 10, "cache_read": 0, "output": 1, "reasoning": 2},  # reasoning exceeds output
    {"input_total": 10, "cache_read": 0, "cache_writes": (("30m", 1), ("30m", 1)), "output": 1},  # a TTL twice
    {"input_total": 10, "output": 1},  # a billed count missing
])
def test_known_shared_usage_must_be_consistent(fields: dict[str, Any]) -> None:
    with pytest.raises(ValueError):  # each construction names its own reason
        ReportedUsage(state="known", **fields)


def test_unreported_reasoning_is_none_and_v1_settlement_digests_are_unchanged() -> None:
    assert ReportedUsage(state="known", input_total=10, cache_read=0, output=1).reasoning is None
    reported = Settlement(Usage(1000, cache_read=400, cache_writes={"30m": 200}, output=120, reasoning=20), "resp_1")
    # Computed by the c6d31f5 (T10) code: a settlement with reported reasoning keeps its v1 representation.
    assert reported.canonical()["v"] == "policyops.usage/v1"
    assert reported.digest() == "2d1de595de5dbc051c9cb2eef65e5778ca34ddcbb1e3330fa5cf8f8c851d7c43"
    unreported = Settlement(Usage(1000, cache_read=400, output=120, reasoning=None), "resp_1")
    assert unreported.canonical()["v"] == "policyops.usage/v2" and unreported.canonical()["reasoning"] is None
