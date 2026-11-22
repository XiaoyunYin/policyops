"""Run-bound retrieval, gateway preparation and strict evidence recording adapters."""

from dataclasses import dataclass, field
import json
import time
from typing import Literal
from uuid import UUID

from policyops.gateway.steps import Gateway
from policyops.orchestration.facts import critical_fact
from policyops.orchestration.graph import ABSTENTION
from policyops.orchestration.state import AwaitingApproval, InvestigationState
from policyops.orchestration.stops import InvestigationStop
from policyops.persistence import repositories as repo
from policyops.persistence.citations import CitationRecorder, citation_id
from policyops.persistence.database import ImmutableRecord, workspace_transaction
from policyops.persistence.runs import ClaimToken
from policyops.retrieval.grounding import EvidenceValidator
from policyops.retrieval.search import Retriever
from policyops.services.proposals import WRITE_CALLS, Prepared, ProposalService
from policyops_contracts.agent import AgentStep, ToolCallStep
from policyops_contracts.conversation import AgentMessage, AgentToolCall, KnowledgeResult, ToolResult
from policyops_contracts.gateway import LookupObservation, ToolError
from policyops_contracts.grounding import Assertion, CitationBundle, CitedQuote, GroundedAnswer, ValidatedAnswer
from policyops_contracts.proposal import EvidenceRef
from policyops_contracts.retrieval import RetrievalConfig, RetrievalQuery, RetrievalRefused, RetrievalScope
from policyops_contracts.scalars import CaseScope
from policyops_contracts.stops import StopDetails, StopReason


@dataclass(frozen=True)
class GatewayToolPort:
    """One run/sequence's validated action adapter. Retail access stays inside Gateway.step."""

    gateway: Gateway
    previous: AgentStep | None
    sequence: int
    disclose_lookup_user_id: bool = False

    async def execute(self, call: AgentToolCall, *, step: ToolCallStep, deadline: float) -> ToolResult:
        if time.monotonic() >= deadline:
            raise TimeoutError
        result = self.gateway.step(step, previous=self.previous, sequence=self.sequence)
        observation = result.observation
        if observation is None:
            raise ValueError("missing gateway observation")
        content = observation.model_dump_json()
        if (self.disclose_lookup_user_id and isinstance(observation, LookupObservation)
                and observation.outcome == "authenticated"):
            content = json.dumps(observation.model_dump(mode="json") | {"user_id": self.gateway.scope.customer_user_id},
                                 ensure_ascii=False, separators=(",", ":"))
        return ToolResult(call_id=call.call_id, content=content, is_error=isinstance(observation, ToolError))


@dataclass
class InvestigationAdapters:
    retriever: Retriever
    retrieval_scope: RetrievalScope
    retrieval_config: RetrievalConfig
    gateway: Gateway
    proposals: ProposalService
    token: ClaimToken
    validator: EvidenceValidator
    recorder: CitationRecorder
    references: dict[UUID, EvidenceRef] = field(default_factory=dict)
    by_step: dict[int, tuple[EvidenceRef, ...]] = field(default_factory=dict)
    disclose_lookup_user_id: bool = False

    def __post_init__(self) -> None:
        run = self.gateway.scope.run
        if (self.token.workspace_id, self.token.run_id) != (run.workspace_id, run.run_id) or any(
                w != run.workspace_id for w in (self.retriever.workspace_id, self.validator.workspace_id,
                                                self.recorder.workspace_id)):
            raise ValueError("investigation adapters have different run bindings")

    def record(self, answer: GroundedAnswer, steps: tuple[int, ...], deadline: float
               ) -> tuple[EvidenceRef, ...] | None:
        run = self.gateway.scope.run
        strict = answer.model_dump(mode="json")
        for assertion in strict["assertions"]:
            assertion["policy_dependent"] = True
        answer = GroundedAnswer.model_validate_json(json.dumps(strict))
        if answer.outcome != "answer" or any(not a.citations for a in answer.assertions):
            return None
        validated = self.validator.validate(answer, run_id=run.run_id, authorized_steps=steps,
                                             corpus_key=self.retrieval_scope.corpus_key, deadline=deadline)
        if (not isinstance(validated, ValidatedAnswer) or validated.outcome != "grounded"
                or validated.bundle is None or not validated.generation_current
                or any(c.status != "verified" for c in validated.citations)
                or len(validated.citations) != sum(len(a.citations) for a in answer.assertions)):
            return None
        bundle = validated.bundle
        refs = tuple(EvidenceRef(evidence_id=citation_id(run.workspace_id, c.trace_id, c.chunk_id,
                                                         c.span_start, c.span_end),
                                 document_version_id=c.document_version_id, content_sha256=c.version_sha256)
                     for c in bundle.claims)
        if len(set(self.references) | {r.evidence_id for r in refs}) > 32:
            return None
        if not self.observe(bundle, steps, deadline):
            return None
        self.references.update((r.evidence_id, r) for r in refs)
        return refs

    def observe(self, bundle: CitationBundle, steps: tuple[int, ...], deadline: float) -> bool:
        result = self.recorder.record(bundle, run_id=self.gateway.scope.run.run_id, authorized_steps=steps,
                                      corpus_key=self.retrieval_scope.corpus_key, deadline=deadline)
        if result.status == "recorded":
            return True
        if result.status == "record_ambiguous":
            observed = self.recorder.reconcile(bundle, run_id=self.gateway.scope.run.run_id, authorized_steps=steps,
                                                corpus_key=self.retrieval_scope.corpus_key, deadline=deadline)
            return observed.status == "recorded" and observed.generation_current is True
        return False

    async def search(self, query: str, *, conversation_id: UUID, index: int, deadline: float) -> KnowledgeResult:
        if conversation_id != self.gateway.scope.run.run_id or not 0 <= index < 16:
            raise ValueError("foreign retrieval invocation")
        found = await self.retriever.retrieve(RetrievalQuery(text=query, run_id=conversation_id, step=index,
                                                            scope=self.retrieval_scope, config=self.retrieval_config),
                                               deadline=deadline)
        if isinstance(found, RetrievalRefused):
            if found.code == "deadline_passed":
                raise InvestigationStop(StopDetails(reason=StopReason.ACTIVE_TIME))
            return KnowledgeResult(content="Policy retrieval unavailable.", is_error=True)
        # Bound the actual delivered text before recording; no second trace or independently reranked result.
        content = f"Retrieval step {index}\n{found.evidence_text}"
        try:
            result = KnowledgeResult(content=content)
        except ValueError:
            return KnowledgeResult(content="Policy evidence exceeds the delivery limit.", is_error=True)
        if found.evidence:
            answer = GroundedAnswer(v="policyops.grounded-answer/v1", outcome="answer", abstention=None,
                                    assertions=tuple(Assertion(
                                        text=e.text[:1000], policy_dependent=True,
                                        citations=(CitedQuote(step=index, evidence_id=e.evidence_id,
                                                              quote=e.text[:1000], start=0,
                                                              end=len(e.text[:1000])),)) for e in found.evidence))
            refs = self.record(answer, (index,), deadline)
            if refs is None:
                # Preserve the actual delivery, but an error never authorizes this step for finalization.
                return KnowledgeResult(content=content, is_error=True)
            self.by_step[index] = refs
        else:
            self.by_step[index] = ()
        return result

    def evidence(self, index: int) -> tuple[EvidenceRef, ...]:
        return self.by_step[index]

    def _step(self, state: InvestigationState) -> tuple[AgentToolCall, ToolCallStep]:
        action = state.next_action
        if action is None or action.call is None or not isinstance(action.step, ToolCallStep):
            raise ValueError("no validated retail action")
        return action.call, action.step

    async def read(self, state: InvestigationState, *, deadline: float) -> ToolResult:
        call, step = self._step(state)
        port = GatewayToolPort(self.gateway, state.previous_step, state.step_count,
                               disclose_lookup_user_id=self.disclose_lookup_user_id)
        return await port.execute(call, step=step, deadline=deadline)

    async def propose(self, state: InvestigationState, *, deadline: float) -> AwaitingApproval | ToolResult:
        call, step = self._step(state)
        if not isinstance(step.call, WRITE_CALLS):
            raise ValueError("not a write proposal")
        scope = self.gateway.scope
        # Reconcile a committed preparation BEFORE collecting mutable retail facts again.
        with workspace_transaction(self.proposals.app_engine, scope.run.workspace_id) as connection:
            row = repo.proposal_creation(connection, scope.run.run_id, state.step_count)
            if row is not None:
                proposal = repo.get_proposal(connection, row.proposal_id, row.proposal_version)
                presentation = repo.get_presentation(connection, row.proposal_id, row.proposal_version)
                message = (repo.message_by_id(connection, CaseScope(workspace_id=state.workspace_id,
                                                                    case_id=state.case_id), presentation.message_id)
                           if presentation is not None else None)
                if (proposal is None or presentation is None or message is None or proposal.action != step.call
                        or proposal.scope != scope.run or message.text != proposal.presentation.text
                        or tuple(proposal.evidence) != tuple(sorted(state.recorded_evidence,
                                                                  key=lambda r: str(r.evidence_id)))
                        or proposal.rationale != f"Requested tool: {call.name}."):
                    raise ImmutableRecord("proposal replay binding changed")
                return AwaitingApproval(proposal_id=row.proposal_id, proposal_version=row.proposal_version,
                                        fact=critical_fact(connection, row))
        if time.monotonic() >= deadline:
            raise TimeoutError
        result = self.gateway.step(step, previous=state.previous_step, sequence=state.step_count)
        if result.collected is None:
            return ToolResult(call_id=call.call_id, content=(result.observation.model_dump_json()
                                                            if result.observation else "Proposal refused."),
                              is_error=True)
        prepared = self.proposals.create_once(scope, step.call, result.collected, token=self.token,
                                              step=state.step_count, evidence=state.recorded_evidence,
                                              rationale=f"Requested tool: {call.name}.")
        if isinstance(prepared, Prepared):
            with workspace_transaction(self.proposals.app_engine, scope.run.workspace_id) as connection:
                row = repo.proposal_row(connection, prepared.proposal.proposal_id, prepared.proposal.proposal_version)
                if row is None:
                    raise ImmutableRecord("prepared proposal missing")
                return AwaitingApproval(proposal_id=row.proposal_id, proposal_version=row.proposal_version,
                                        fact=critical_fact(connection, row))
        return ToolResult(call_id=call.call_id, content="Proposal refused by deterministic policy checks.",
                          is_error=True)

    def finalize(self, state: InvestigationState, *, deadline: float
                 ) -> tuple[Literal["answered", "abstained"], str]:
        answer = None if state.next_action is None else state.next_action.answer
        if answer is None or answer.outcome != "answer":
            return "abstained", ABSTENTION
        refs = self.record(answer, state.retrieved_steps, deadline)
        if refs is None:
            return "abstained", ABSTENTION
        offset, lines = 0, []
        for assertion in answer.assertions:
            ids = refs[offset:offset + len(assertion.citations)]
            lines.append(assertion.text + " " + " ".join(f"[{r.evidence_id}]" for r in ids))
            offset += len(ids)
        text = "\n".join(lines)
        try:
            AgentMessage(text=text)
        except ValueError:
            return "abstained", ABSTENTION
        return "answered", text
