"""Exclusive, reversible upstream actor bindings through the bounded T11 path.

This is trusted evaluator composition. Simulator/judge inputs legitimately contain
hidden task data; none is forwarded to the agent bridge. Trials must be serial.
Upstream Loguru output is suppressed for the binding's lifetime, including setup.
No SDK raw_data is returned. The ledger, not upstream cost fields, bills calls.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import json
import threading
import time
from typing import Any, Literal, cast
from uuid import uuid5

from pydantic import ValidationError

from policyops.budget.config import ChatActor
from policyops.budget.ledger import EvalBinding, Ledger
from policyops.providers.bounds import preflight
from policyops.providers.calls import CallLimits, CallReport, Providers, call
from policyops_contracts.model import Message, ModelRequest, TextPart, ToolResultPart, ToolSpec, ToolUsePart
from policyops_evals.harness.inprocess import OwnedLoop
from policyops_evals.harness.tools import CatalogMapping, bounded_copy, map_upstream_tools, to_upstream_arguments


Actor = Literal["simulator", "judge"]
_EXCLUSIVE = threading.Lock()
_LIMITS = CallLimits(retries_per_request=0, repairs=0, backoff_seconds=0)
MAX_CONTENT = 200_000
MAX_TOTAL = 240_000


class ActorRefused(RuntimeError):
    """Fixed codes; provider/input exceptions must not enter normal diagnostics."""


def tripwire(*args: Any, **kwargs: Any) -> Any:
    raise ActorRefused("unbound_generation")


def _text(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_CONTENT:
        raise ActorRefused("content_bounds")
    return value


def actor_request(messages: object, tools: object, *, max_output: int) -> tuple[ModelRequest, CatalogMapping]:
    """Bound lengths before copying/serializing; preserve roles, calls and errors.

    Only text half-duplex histories are supported. Refuse audio, multiple system
    messages, leading assistant messages and unsupported tools rather than erase
    them or introduce synthetic instructions for the user/judge.
    """
    from tau2.data_model import message as up

    if type(messages) not in (list, tuple):
        raise ActorRefused("history_bounds")
    history = cast(list[Any] | tuple[Any, ...], messages)
    if not 2 <= len(history) <= 256:
        raise ActorRefused("history_bounds")
    if tools is not None and (type(tools) not in (list, tuple) or
                              len(cast(list[object] | tuple[object, ...], tools)) > 32):
        raise ActorRefused("tool_bounds")
    mapping = map_upstream_tools([] if tools is None else cast(list[object] | tuple[object, ...], tools))
    instructions: str | None = None
    converted: list[Message] = []
    total = 0
    for index, source in enumerate(history):
        if type(source) is up.SystemMessage:
            if index != 0:
                raise ActorRefused("system_position")
            instructions = _text(source.content)
            total += len(instructions)
            continue
        if type(source) not in (up.UserMessage, up.AssistantMessage, up.ToolMessage):
            raise ActorRefused("message_type")
        if type(source) in (up.UserMessage, up.AssistantMessage) and up.is_voice_message(source):
            raise ActorRefused("audio_unsupported")
        parts: list[TextPart | ToolUsePart | ToolResultPart] = []
        role: Literal["user", "assistant"] = "assistant" if type(source) is up.AssistantMessage else "user"
        if type(source) is up.ToolMessage:
            text = _text(source.content)
            total += len(text)
            parts.append(ToolResultPart(call_id=source.id, content=text, is_error=source.error))
        else:
            if source.content is not None:
                text = _text(source.content)
                total += len(text)
                parts.append(TextPart(text=text))
            calls = source.tool_calls
            if calls:
                if role != "assistant" or type(calls) is not list or len(calls) > 16:
                    raise ActorRefused("tool_history")
                for item in calls:
                    # Use the bounded schema copier before JSON allocation.
                    arguments = json.dumps(bounded_copy(item.arguments), separators=(",", ":"), ensure_ascii=False)
                    total += len(arguments)
                    parts.append(ToolUsePart(call_id=item.id, name=item.name, arguments_json=arguments))
        if total > MAX_TOTAL or not parts:
            raise ActorRefused("history_bounds")
        if converted and converted[-1].role == role:
            converted[-1] = Message(role=role, parts=converted[-1].parts + tuple(parts))
        else:
            converted.append(Message(role=role, parts=tuple(parts)))
    if instructions is None:
        raise ActorRefused("system_missing")
    request = ModelRequest(instructions=instructions, messages=tuple(converted), max_output_tokens=max_output,
        tools=tuple(ToolSpec(name=t.name, description=t.description, parameters_schema_json=t.parameters_schema_json)
                    for t in mapping.catalog.tools))
    preflight(request)
    return request, mapping


@dataclass(frozen=True)
class ActorCeilings:
    simulator: int
    judge: int

    def __post_init__(self) -> None:
        if any(type(v) is not int or not 1 <= v <= 256 for v in (self.simulator, self.judge)):
            raise ValueError("actor_call_bounds")


class ActorBindings:
    def __init__(self, ledger: Ledger, binding: EvalBinding, providers: Callable[[], Providers], *,
                 loop: OwnedLoop, deadline: float, ceilings: ActorCeilings,
                 upstream_seed: int | None = None) -> None:
        if not isinstance(binding, EvalBinding) or not 0 < deadline - time.monotonic() <= 900:
            raise ActorRefused("binding_invalid")
        self.ledger, self.binding, self.providers = ledger, binding, providers
        self.loop, self.deadline, self.ceilings = loop, deadline, ceilings
        # Upstream seeds its orchestration and adds this kwarg to UserSimulator.
        # T11 has no provider seed contract: accept only the recorded upstream
        # seed, without pretending the provider inference is deterministic.
        if upstream_seed is not None and type(upstream_seed) is not int:
            raise ActorRefused("seed_invalid")
        self.upstream_seed = upstream_seed
        self._indices: dict[Actor, int] = {"simulator": 0, "judge": 0}
        self._digests = {actor: ledger.configuration.reservation(actor).config_sha256
                         for actor in ("simulator", "judge")}
        self._owner: int | None = None
        self._judge_validator: Callable[[str], None] | None = None
        self.reports: list[tuple[Actor, CallReport]] = []

    def config(self, actor: Actor) -> ChatActor:
        config = self.ledger.configuration.actors[actor]
        if not isinstance(config, ChatActor):
            raise ActorRefused("actor_configuration")
        return config

    def _generate(self, actor: Actor, *, model: str, messages: object, tools: object = None,
                  call_name: str | None = None, **kwargs: Any) -> Any:
        from tau2.data_model.message import AssistantMessage, ToolCall

        if self._owner != threading.get_ident():
            raise ActorRefused("actor_owner")
        config = self.config(actor)
        allowed: dict[str, Any] = {"reasoning_effort": config.effort}
        if actor == "simulator" and self.upstream_seed is not None:
            allowed["seed"] = self.upstream_seed
        if model != config.model or kwargs != allowed:
            raise ActorRefused("actor_arguments")
        if call_name != ("user_simulator_response" if actor == "simulator" else "nl_assertions_eval"):
            raise ActorRefused("actor_call_site")
        if actor == "judge" and (self._judge_validator is None or tools):
            raise ActorRefused("judge_unscoped")
        if self.ledger.configuration.reservation(actor).config_sha256 != self._digests[actor]:
            raise ActorRefused("actor_configuration_changed")
        index = self._indices[actor]
        if index >= getattr(self.ceilings, actor):
            raise ActorRefused("actor_call_cap")
        try:
            request, mapping = actor_request(messages, tools, max_output=config.max_output)
        except Exception:
            raise ActorRefused("actor_input") from None
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise ActorRefused("deadline")
        self._indices[actor] += 1  # never replay a possibly dispatched call
        key = uuid5(self.binding.scenario_id, f"{actor}:{index}")
        try:
            report = self.loop.run(call(self.ledger, self.providers(), self.binding, key, f"eval.{actor}",
                request, actor, deadline=self.deadline, limits=_LIMITS), seconds=left)
        except Exception:
            raise ActorRefused("actor_failed") from None
        self.reports.append((actor, report))  # bounded by explicit actor ceilings; billing survives bad judge output
        result = report.result
        if (report.status != "result" or result is None or result.outcome != "completed"
                or report.cleanup_unconfirmed):
            raise ActorRefused("actor_" + report.status)
        if actor == "judge":
            if result.tool_calls or result.text is None:
                raise ActorRefused("judge_output")
            validator = self._judge_validator
            if validator is None:
                raise ActorRefused("judge_unscoped")
            validator(result.text)  # strict coverage BEFORE upstream json.loads/all([])
        try:
            calls = [ToolCall(id=item.call_id, name=item.name,
                arguments=to_upstream_arguments(mapping, item.name, item.arguments_json), requestor="assistant")
                for item in result.tool_calls]
            usage = result.usage
            return AssistantMessage(role="assistant", content=result.text, tool_calls=calls or None,
                usage={"prompt_tokens": usage.input_total, "completion_tokens": usage.output}
                    if usage.state == "known" else None, raw_data=None, cost=None)
        except (ValueError, ValidationError):
            raise ActorRefused("actor_output") from None

    @contextmanager
    def judging(self, validator: Callable[[str], None]) -> Iterator[None]:
        if self._owner != threading.get_ident() or self._judge_validator is not None:
            raise ActorRefused("judge_scope")
        self._judge_validator = validator
        try:
            yield
        finally:
            self._judge_validator = None

    @contextmanager
    def install(self) -> Iterator[ActorBindings]:
        if not _EXCLUSIVE.acquire(blocking=False):
            raise ActorRefused("actors_already_bound")
        saved: list[tuple[Any, str, Any]] = []
        log_state: Any = None
        logger: Any = None
        try:
            from loguru import logger
            # Preserve existing sink IDs/configuration; serialize these global changes.
            log_state = logger._core.enabled.copy(), logger._core.activation_list.copy(), logger._core.activation_none
            logger.disable("")
            import litellm
            from tau2.evaluator import evaluator_nl_assertions as nl
            from tau2.user import user_simulator as user
            from tau2.utils import llm_utils

            def replace(obj: Any, name: str, value: Any) -> None:
                saved.append((obj, name, getattr(obj, name)))
                setattr(obj, name, value)

            self._owner = threading.get_ident()
            for obj, name in ((llm_utils, "generate"), (llm_utils, "_generate_once"),
                              (llm_utils, "completion"), (litellm, "completion"), (litellm, "acompletion")):
                replace(obj, name, tripwire)
            replace(user, "generate", lambda **kw: self._generate("simulator", **kw))
            replace(nl, "generate", lambda **kw: self._generate("judge", **kw))
            replace(nl, "DEFAULT_LLM_NL_ASSERTIONS", self.config("judge").model)
            replace(nl, "DEFAULT_LLM_NL_ASSERTIONS_ARGS", {"reasoning_effort": self.config("judge").effort})
            yield self
        finally:
            self._owner = None
            self._judge_validator = None
            for obj, name, value in reversed(saved):
                setattr(obj, name, value)
            if logger is not None and log_state is not None:
                with logger._core.lock:
                    logger._core.enabled, logger._core.activation_list, logger._core.activation_none = log_state
            _EXCLUSIVE.release()
