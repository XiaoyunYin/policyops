"""N3 arms composed through the P1 profile at the workbench runtime boundary."""

from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
from threading import RLock
from typing import Never
from unittest.mock import patch

from sqlalchemy import Engine

from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.profile import InvestigationProfile
from policyops.providers.tokenizer import Tokenizer
from policyops.providers.tool_diagnostics import NOTICE_TABLE
from policyops.runtime.investigation import InvestigationExecutor
from policyops.runtime.spec import RuntimeSpec
from policyops_contracts.conversation import PolicyContext
from policyops_contracts.retrieval import canonical_sha256
from policyops_evals.scenarios import Refused
from policyops_evals.scenarios.runtime import scenario_spec


class Arm(StrEnum):
    BASELINE = "baseline"
    CANDIDATE = "tool-contract-v1"
    WITHOUT_PROMPT = "c-minus-f"
    WITHOUT_BM25 = "c-minus-d"
    REVISION = "tool-contract-v1r1"

    @property
    def profile(self) -> InvestigationProfile:
        if self is Arm.REVISION:
            return InvestigationProfile.TOOL_CONTRACT_V1R1
        return (InvestigationProfile.BASELINE if self is Arm.BASELINE
                else InvestigationProfile.TOOL_CONTRACT_V1)

    @contextmanager
    def compose(self) -> Iterator[None]:
        # P1 has no independent switches. Scope each override to one serial evaluator execution.
        # The graph's v1 checks, catalog, projection and notices still see the original enum member.
        with _COMPOSITION, ExitStack() as stack:
            if self is Arm.WITHOUT_PROMPT:
                stack.enter_context(patch.object(prompt, "PROMPT_V3", prompt.PROMPT))
            if self is Arm.WITHOUT_BM25:
                stack.enter_context(patch.object(InvestigationProfile, "lexical_mode", property(_all_terms)))
            yield

    def bind(self, spec: RuntimeSpec) -> RuntimeSpec:
        if self is not Arm.WITHOUT_PROMPT:
            return spec
        if not isinstance(spec.executor, InvestigationExecutor):
            raise Refused("the prompt ablation requires the investigation executor")
        # P1's runtime config hashes the profile, but its prompt digest is a separate fence.
        config = canonical_sha256({"base": spec.config_sha256, "arm": self, "prompt": spec.prompt_sha256})
        return replace(spec, config_sha256=config, executor=replace(spec.executor, config_sha256=config))


_COMPOSITION = RLock()
COMPARISON = (Arm.BASELINE, Arm.CANDIDATE)
ABLATIONS = (Arm.WITHOUT_PROMPT, Arm.WITHOUT_BM25)


def _all_terms(_: InvestigationProfile) -> str:
    return "all_terms"


def _unavailable(*_: object) -> Never:
    raise Refused("reference specs cannot execute")


@dataclass(frozen=True)
class Identity:
    profile: str
    profile_sha256: str
    prompt_sha256: str
    instruction_sha256: str
    catalog_sha256: str
    graph_sha256: str
    config_sha256: str
    notice_table_sha256: str | None
    lexical_mode: str


def identities(engine: Engine, policy: PolicyContext, tokenizer: Tokenizer, *,
               env: str = "local", arms: Sequence[Arm] = (*COMPARISON, *ABLATIONS)) -> dict[Arm, Identity]:
    """Hash the real runtime configuration with an empty case-binding list."""
    result = {}
    for arm in arms:
        with arm.compose():
            profile = arm.profile
            spec = arm.bind(scenario_spec(env=env, engine=engine, policy=policy, tokenizer=tokenizer,
                                         retail=_unavailable, providers=_unavailable, profile=profile))
            catalog = canonical_sha256(prompt.catalog(profile).model_dump(mode="json"))
            notices = (None if arm is Arm.BASELINE
                       else canonical_sha256(sorted((*key, value) for key, value in NOTICE_TABLE.items())))
            instructions = prompt.instructions(profile)
            lexical = profile.lexical_mode
            fields = {"profile": profile, "prompt": spec.prompt_sha256, "catalog": catalog,
                      "graph": spec.graph_sha256, "config": spec.config_sha256,
                      "notices": notices, "lexical_mode": lexical}
            result[arm] = Identity(profile, canonical_sha256(fields), spec.prompt_sha256,
                                   sha256(instructions.encode()).hexdigest(), catalog, spec.graph_sha256,
                                   spec.config_sha256, notices, lexical)
    return result
