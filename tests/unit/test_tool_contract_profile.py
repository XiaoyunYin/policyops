"""Offline checks for the workbench tool-contract profile and its model boundary."""

import asyncio
import json
import time
from typing import Any, cast

import pytest
from sqlalchemy import Engine

from policyops.adapters.retail_client import Refused, Unknown
from policyops.budget.config import DEFAULT_ACTORS, ChatActor, Configuration
from policyops.gateway.ports import GatewayScope, RetailPort
from policyops.gateway.steps import Gateway
from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.adapters import GatewayToolPort
from policyops.orchestration.mechanics import notice_text
from policyops.orchestration.minimal import retail_catalog
from policyops.orchestration.profile import InvestigationProfile
from policyops.persistence.customer_authentications import AuthenticationConflict
from policyops.providers.calls import Providers
from policyops.providers.results import UNKNOWN, Evidence, openai_result
from policyops.providers.serialize import prepare
from policyops.providers.tokenizer import Tokenizer
from policyops.providers.tool_diagnostics import NOTICE_TABLE
from policyops.providers.tools import refused_arguments, to_agent_step
from policyops.runtime.investigation import build_investigation_spec, graph_digest
from policyops.runtime.spec import RuntimeCatalog, RuntimeSpec, binding
from policyops_contracts.agent import ToolCallStep
from policyops_contracts.clock import FixedClock
from policyops_contracts.conversation import AgentLimits, AgentToolCall, RuntimeNotice, UserMessage
from policyops_contracts.retail_service import FIXTURE_SHA256, OrderOutput, ReadResult, UserIdOutput
from policyops_contracts.retrieval import RetrievalConfig, RetrievalScope, canonical_sha256
from policyops_contracts.seeds import CustomerAuthentication
from policyops_testing.agent_fakes import calls, fictional_policy
from policyops_testing.gateway_cases import EMAIL, NAME_ZIP, SCOPE, FakeRetail, MemorySessions, W, state


PROFILE = InvestigationProfile.TOOL_CONTRACT_V1


def test_baseline_and_minimal_digests_at_9fbefc4() -> None:
    assert prompt.digest() == "3f4e1c679f32b1f655bcb7d213ab6a3a5c09951745dd8d69aa63bacb768d208c"
    assert prompt.catalog().digest() == "280ce688808f2a63628951841ce12eb92770267ab0c55dbd140733e2b10c0afe"
    assert graph_digest() == "7bf843e54e68a32b37c56dddeac9179b8e0f978c26a727eb14bd18b5ece59759"
    assert retail_catalog().digest() == "f1c3c0dfa72e3ba403217f4ce7e5b3b0761db6f6bd1bd272773643b7437661e7"
    assert retail_catalog(knowledge_tool=True).digest() == (
        "b61a398d83de55a9c536ea9298a921e24c36bc4b08b426b4f15deaef4ba63155")
    assert prompt.digest(PROFILE) != prompt.digest()
    assert prompt.catalog(PROFILE).digest() != prompt.catalog().digest()
    assert graph_digest(PROFILE) != graph_digest()
    assert PROFILE.lexical_mode == "bm25"


def make_spec(profile: InvestigationProfile, limits: AgentLimits | None = None) -> RuntimeSpec:
    def no_retail(scope: GatewayScope) -> RetailPort:
        raise AssertionError("building a runtime must stay offline")

    def no_provider() -> Providers:
        raise AssertionError("building a runtime must stay offline")

    return build_investigation_spec(
        env="test", engine=cast(Engine, None), configuration=Configuration(), policy=fictional_policy(),
        retrieval_scope=RetrievalScope(corpus_key="test-policy"), retrieval_config=RetrievalConfig(mode="lexical"),
        bindings=(W.binding(),), fixture_sha256=FIXTURE_SHA256, retail=no_retail, providers=no_provider,
        tokenizer=cast(Tokenizer, None), limits=limits, profile=profile,
    )


def test_runtime_fingerprint_binds_the_profile() -> None:
    baseline = make_spec(InvestigationProfile.BASELINE)
    candidate = make_spec(PROFILE)
    assert candidate.prompt_sha256 == prompt.digest(PROFILE)
    assert all(old != new for old, new in zip(binding(baseline), binding(candidate), strict=True))
    catalog = RuntimeCatalog.of([baseline, candidate], default=candidate.spec_id)
    assert catalog.start_spec is candidate and catalog.for_run(*binding(baseline)) is baseline
    assert RuntimeCatalog.of([candidate]).for_run(*binding(baseline)) is None
    with pytest.raises(ValueError, match="consecutive_invalid=2"):
        make_spec(PROFILE, AgentLimits(consecutive_invalid=3, knowledge_steps=16))


@pytest.mark.parametrize("configuration,parameters_key", [
    (Configuration(), "parameters"),
    (Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "claude-haiku-5-5", "low")}),
     "input_schema"),
])
def test_id_descriptions_survive_serialized_provider_request(configuration: Configuration, parameters_key: str) -> None:
    policy = fictional_policy()
    messages = (UserMessage(text="Help with my account"),)
    for profile in InvestigationProfile:
        request = prompt.request(policy, AgentLimits(), messages, profile=profile)
        prepared = prepare(request, configuration, "agent")
        instructions = prompt.PROMPT_V3 if profile is PROFILE else prompt.PROMPT
        assert request.instructions == instructions + "\n\n# Policy\n\n" + policy.text
        descriptions = {"order_id": "For order IDs, include the leading #, e.g. #W0000000.",
                        "user_id": "For user IDs, use the user_id returned by the authenticated lookup."}
        fields = [(key, schema) for tool in prepared.params()["tools"]
                  for key, schema in tool[parameters_key]["properties"].items() if key in descriptions]
        assert {key for key, _ in fields} == descriptions.keys()
        for key, field in fields:
            assert "pattern" not in field
            assert field.get("description") == (descriptions[key] if profile is PROFILE else None)


def observe(gateway: Gateway, name: str, arguments: dict[str, Any], enabled: bool | None = True) -> dict[str, Any]:
    response = calls(name, arguments).result
    assert response is not None
    step = to_agent_step(response)
    assert isinstance(step, ToolCallStep)
    call = AgentToolCall.model_validate(response.tool_calls[0].model_dump())
    port = (GatewayToolPort(gateway, None, 1) if enabled is None else
            GatewayToolPort(gateway, None, 1, disclose_lookup_user_id=enabled))
    result = asyncio.run(port.execute(call, step=step, deadline=time.monotonic() + 60))
    content: dict[str, Any] = json.loads(result.content)
    return content


@pytest.mark.parametrize(("name", "arguments"), [
    ("find_user_id_by_email", {"email": EMAIL}),
    ("find_user_id_by_name_zip", dict(zip(("first_name", "last_name", "zip"), NAME_ZIP, strict=True))),
])
def test_only_authenticated_lookups_disclose_the_bound_user(name: str, arguments: dict[str, Any]) -> None:
    gateway = Gateway(SCOPE, retail=FakeRetail(state()), sessions=MemorySessions(), clock=FixedClock(W.now))
    expected = {"kind": "lookup", "tool": name, "outcome": "authenticated"}
    assert observe(gateway, name, arguments, enabled=None) == expected
    assert observe(gateway, name, arguments) == expected | {"user_id": SCOPE.customer_user_id}


class ConflictingSessions(MemorySessions):
    def record(self, authentication: CustomerAuthentication) -> CustomerAuthentication:
        raise AuthenticationConflict("synthetic concurrent binding conflict")


@pytest.mark.parametrize(("case", "expected"), [
    ("mismatch", "lookup_identity_mismatch"),
    ("not_found", "not_found"),
    ("error", "retail_unavailable"),
    ("conflict", "authentication_conflict"),
])
def test_other_lookup_outcomes_do_not_disclose_either_user(case: str, expected: str) -> None:
    def tamper(call: Any, reply: Any, count: int) -> object:
        if case == "not_found":
            raise Refused(404, "not_found")
        if case == "error":
            return Unknown("synthetic")
        if case == "mismatch":
            return reply.model_copy(update={"output": UserIdOutput(user_id=W.other_user)})
        return reply

    sessions = ConflictingSessions() if case == "conflict" else MemorySessions()
    gateway = Gateway(SCOPE, retail=FakeRetail(state(), tamper=tamper), sessions=sessions, clock=FixedClock(W.now))
    content = observe(gateway, "find_user_id_by_email", {"email": EMAIL})
    assert "user_id" not in content
    assert W.user_id not in json.dumps(content) and W.other_user not in json.dumps(content)
    if case == "not_found":
        assert content["outcome"] == expected
    else:
        assert expected in json.dumps(content)


def test_disclosure_does_not_authorize_foreign_user_or_order() -> None:
    def foreign_order(call: Any, reply: ReadResult, count: int) -> ReadResult:
        if isinstance(reply.output, OrderOutput):
            order = reply.output.order.model_copy(update={"user_id": W.other_user})
            return reply.model_copy(update={"output": OrderOutput(order=order)})
        return reply

    retail = FakeRetail(state(), tamper=foreign_order)
    gateway = Gateway(SCOPE, retail=retail, sessions=MemorySessions(), clock=FixedClock(W.now))
    assert observe(gateway, "find_user_id_by_email", {"email": EMAIL})["user_id"] == W.user_id
    assert observe(gateway, "get_user_details", {"user_id": W.other_user})["code"] == "customer_mismatch"
    assert len(retail.calls) == 1
    assert observe(gateway, "get_order_details", {"order_id": W.order_id})["code"] == "customer_mismatch"
    assert len(retail.calls) == 2


@pytest.mark.parametrize(("tool", "source", "field", "kind", "guidance"), [
    ("find_user_id_by_email", '{"email":"invalid"}', "email", "pattern", "Use the required format."),
    ("find_user_id_by_name_zip", '{"first_name":"A","last_name":"B","zip":"x"}', "zip", "pattern",
     "Use a five-digit ZIP as a string."),
    ("get_user_details", '{"user_id":"!"}', "user_id", "pattern",
     "For user IDs, use the user_id returned by the authenticated lookup."),
    ("get_order_details", '{"order_id":"W9876543"}', "order_id", "pattern",
     "For order IDs, include the leading #, e.g. #W0000000."),
    ("get_product_details", '{"product_id":1}', "product_id", "type", "Use the JSON type in the tool schema."),
    ("get_item_details", '{}', "item_id", "missing", "Provide the required field."),
    ("list_all_product_types", '{"unknown":"discard"}', "arguments", "extra_field", "Use only the listed fields."),
    ("calculate", '{"expression":"1**1"}', "expression", "shape", "Check how the arguments fit together."),
    ("transfer_to_human_agents", json.dumps({"summary": "x" * 1001}), "summary", "too_long",
     "Shorten the value or list."),
    ("cancel_pending_order", '{"order_id":"#W0000000","reason":"unknown"}', "reason", "enum",
     "Use one of the listed values."),
    ("modify_pending_order_address", '{"order_id":"#W0000000"}', "address1", "missing", "Provide the required field."),
    ("modify_pending_order_payment", '{"order_id":"#W0000000"}', "payment_method_id", "missing",
     "Provide the required field."),
    ("modify_pending_order_items", '{"order_id":"#W0000000","item_ids":[]}', "item_ids", "too_short",
     "Provide a nonempty value or list."),
    ("return_delivered_order_items", '{"order_id":"#W0000000","item_ids":["invalid"]}', "item_ids", "pattern",
     "Use the required format."),
    ("exchange_delivered_order_items", '{"order_id":"#W0000000","item_ids":["0000000001"],"new_item_ids":1}',
     "new_item_ids", "type", "Use the JSON type in the tool schema."),
    ("modify_user_address", '{"user_id":true}', "user_id", "type", "Use the JSON type in the tool schema."),
    ("finish_answer", '{"v":"policyops.grounded-answer/v1","outcome":"answer","abstention":null,'
     '"assertions":[{"text":"x","policy_dependent":true,'
     '"citations":[{"step":-1,"evidence_id":"E1","quote":"x","start":null,"end":null}]}]}',
     "assertions.citations.step", "range", "Use a value within the allowed range."),
])
def test_notice_table(tool: str, source: str, field: str, kind: str, guidance: str) -> None:
    issue = refused_arguments(tool, source)
    assert issue is not None
    assert issue.model_dump(mode="json") == {"tool": tool, "field": field, "constraint": kind}
    assert notice_text("invalid_arguments", issue) == f"[runtime notice] {tool}.{field} ({kind}). {guidance}"


def test_full_notice_table_digest() -> None:
    assert canonical_sha256(sorted((*key, text) for key, text in NOTICE_TABLE.items())) == (
        "0b2ce6e37711f7e20afabc20ff53b475e8320c5a9922d58b3ef371daef010ca6")


def test_notices_never_copy_substrings_from_rejected_values_or_keys() -> None:
    # Vary keys, strings, array values and nested members. A disjoint alphabet also catches single-character leaks.
    for start in range(0xE000, 0xE100):
        key = chr(start) * 17
        value = chr(start + 256) * 29
        for tool, args in [
            ("get_order_details", {"order_id": value}),
            ("list_all_product_types", {key: [value]}),
            ("finish_answer", {"v": "policyops.grounded-answer/v1", "outcome": "abstain", "assertions": [],
                               "abstention": {"reason": "insufficient_evidence", "detail": None, key: value}}),
        ]:
            issue = refused_arguments(tool, json.dumps(args, ensure_ascii=False))
            assert issue is not None
            notice = RuntimeNotice(code="invalid_arguments", argument_issue=issue)
            for content in (notice.model_dump_json(), notice_text(notice.code, notice.argument_issue)):
                assert set(content).isdisjoint(key + value)


@pytest.mark.parametrize(("name", "source", "field"), [
    ("get_order_details", '{"order_id":"discard-this"}', "order_id"),
    ("finish_answer", '{"v":"policyops.grounded-answer/v1","outcome":"discard-this","assertions":[],"abstention":null}',
     "outcome"),
])
def test_provider_schema_refusal_keeps_only_a_profile_gated_diagnostic(name: str, source: str, field: str) -> None:
    response = {"status": "completed", "output": [{"type": "function_call", "call_id": "discard-id",
                                                  "name": name, "arguments": source}]}
    evidence = Evidence(None, UNKNOWN, None, None)
    for profile in InvestigationProfile:
        request = prompt.request(fictional_policy(), AgentLimits(), (UserMessage(text="Review."),), profile=profile)
        prepared = prepare(request, Configuration(), "agent", detailed_tool_errors=profile is PROFILE)
        result = openai_result(response, prepared, evidence)
        assert result.outcome == "invalid_output" and result.reason_code == "tool_arguments_schema"
        assert not result.tool_calls and result.text is None
        assert "discard" not in result.model_dump_json()
        if profile is PROFILE:
            assert result.argument_issue is not None and result.argument_issue.field == field
        else:
            assert "argument_issue" not in result.model_dump(mode="json")
