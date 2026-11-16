"""One US-profile InvokeModel exchange. No SDK HTTP, count API, worker, retry or credential acquisition."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx2
from pydantic import SecretStr

from policyops.providers.adapters import RESULT_ERRORS, Invocation, _retry_after, as_contract_gap
from policyops.providers.canonical import CanonicalError, canonical_bytes, strict_loads
from policyops.providers.contract import ENDPOINTS, ContractGap, require_clean_environment
from policyops.providers.results import anthropic_result, bedrock_evidence
from policyops.providers.serialize import PreparedRequest
from policyops.providers.transport import (
    TIMEOUT,
    BoundedTransport,
    Expected,
    ResponseTooLarge,
    TransportRefused,
    bounded_close,
    http_client,
)
from policyops_contracts.model import ModelResult


if TYPE_CHECKING:
    from policyops.providers.bedrock_auth import BedrockAccess


K_FIXED = 1024
K_PER_MESSAGE = 64


def input_bound(prepared: PreparedRequest) -> int:
    """Byte BPE text bound plus conservative message-template framing. No tokenizer or network."""
    body = prepared.params()
    total = len(body["system"].encode("utf-8"))
    for message in body["messages"]:
        for block in message["content"]:
            if block.get("type") != "text" or not isinstance(block.get("text"), str):
                raise ContractGap("bedrock.text_only_nonstreaming")
            total += len(block["text"].encode("utf-8"))
    # Count all schema keys, enums, names, descriptions, output schema and effort, including JSON punctuation.
    total += sum(len(canonical_bytes(body[key])) for key in ("tools", "output_config") if key in body)
    return total + K_FIXED + K_PER_MESSAGE * len(body["messages"])


def _parsed(data: dict[str, Any], prepared: PreparedRequest, request_id: str | None) -> Invocation:
    data = {**data, "_bedrock_request_id": request_id}
    evidence = bedrock_evidence(data, prepared)
    try:
        result = anthropic_result(data, prepared, evidence)
    except RESULT_ERRORS:
        result = ModelResult(outcome="failed", provider="bedrock", requested_model=prepared.model,
                             returned_model=evidence.returned_model, provider_request_id=evidence.provider_request_id,
                             usage=evidence.reported, reason_code="result_unrepresentable")
    if (not isinstance(data.get("id"), str) or not data["id"] or data.get("type") != "message"
            or data.get("role") != "assistant"):
        result = as_contract_gap(result, "response_malformed")
    content = data.get("content")
    if not isinstance(content, list) or any(not isinstance(b, dict) or b.get("type") != "text" for b in content):
        result = as_contract_gap(result, "unexpected_content_block")
    if evidence.block is not None:
        result = as_contract_gap(result, evidence.block)
    return Invocation(sent=True, result=result, evidence=evidence)


async def invoke(prepared: PreparedRequest, inner: httpx2.AsyncBaseTransport, access: BedrockAccess) -> Invocation:
    require_clean_environment("bedrock")
    headers = access.sign(prepared.body)  # synchronous, pure CPU; no worker survives a cancellation
    signed = {name.lower(): SecretStr(value) for name, value in headers.items()}
    transport = BoundedTransport(inner, Expected("bedrock", prepared.path, prepared.body), SecretStr(""),
                                 signed_headers=signed)
    http = http_client(transport, TIMEOUT)
    try:
        endpoint = ENDPOINTS["bedrock"]
        response = await http.post(endpoint.base_url + prepared.path, content=prepared.body, headers=headers)
        if response.status_code != 200:
            # Error bodies/messages and AWS error header values are never retained. ModelNotReady is HTTP 429;
            # ModelError (424) is retryable within the same bounded attempt policy. Access/agreement 403 is final.
            outcome = Invocation(sent=transport.sent, status=response.status_code,
                                 retry_after=_retry_after(response.headers), error=f"http_{response.status_code}")
        else:
            data = strict_loads(response.content)
            outcome = (_parsed(data, prepared, response.headers.get("x-amzn-requestid")) if isinstance(data, dict)
                       else Invocation(sent=transport.sent, error="response_not_object"))
    except CanonicalError:
        outcome = Invocation(sent=transport.sent, error="response_not_json")
    except TransportRefused as error:
        outcome = Invocation(sent=transport.sent, error=f"refused.{error.code}")
    except ResponseTooLarge as error:
        outcome = Invocation(sent=transport.sent, error=error.code)
    except httpx2.TimeoutException:
        outcome = Invocation(sent=transport.sent, error="timeout")
    except httpx2.TransportError:
        outcome = Invocation(sent=transport.sent, error="connection")
    finally:
        closed = await bounded_close(http.aclose)
    outcome.cleanup_confirmed = closed and not transport.cleanup_unconfirmed
    return outcome
