"""Supplemental scenario grader for the evidence a proposal reviewer can open."""

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256

from policyops.services.run_reads import EvidenceView
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.proposal import ActionProposal
from policyops_evals.scenarios.cases import Gold, PolicySpan


@dataclass(frozen=True)
class ClauseGrade:
    provenance: bool
    required: tuple[str, ...]
    covered: tuple[str, ...]

    @property
    def supported(self) -> bool:
        return self.provenance and self.required == self.covered


def required_spans(gold: Gold, policy: str) -> tuple[PolicySpan, ...]:
    if (gold.policy_sha256 != RETAIL_POLICY.sha256 or sha256(policy.encode()).hexdigest() != RETAIL_POLICY.sha256
            or not gold.clauses or tuple(span.rule_id for span in gold.clause_spans) != gold.clauses
            or any(span.start < 0 or not span.text or policy[span.start:span.start + len(span.text)] != span.text
                   for span in gold.clause_spans)):
        raise ValueError("required spans must match the pinned scenario policy")
    return gold.clause_spans


def covers(span: PolicySpan, start: int, end: int) -> bool:
    """Require full containment by one delivered quote, using half-open code point intervals."""
    return start <= span.start and span.start + len(span.text) <= end


def grade_proposal_clauses(
    gold: Gold, proposal: ActionProposal, evidence: Sequence[EvidenceView], policy: str,
) -> ClauseGrade | None:
    """Grade the exact persisted quote span, excluding surrounding UI context and rule labels.

    The caller supplies the sealed proposal and the linked evidence views read
    from storage. All proposal links must resolve in that run to the pinned
    policy. Multiple quotes may cover separate clauses; fragments do not union
    to cover a single required clause. An empty evidence list gives no support.
    """
    if gold.stratum not in {"cancel", "return"}:
        return None
    spans = required_spans(gold, policy)
    required = tuple(span.rule_id for span in spans)
    views = {view.citation_id: view for view in evidence}
    if (proposal.policy != RETAIL_POLICY or len(views) != len(evidence)
            or views.keys() != {ref.evidence_id for ref in proposal.evidence}):
        return ClauseGrade(False, required, ())
    intervals = []
    for ref in proposal.evidence:
        view = views[ref.evidence_id]
        if (view.scope != proposal.scope or view.document_version_id != ref.document_version_id
                or view.version_sha256 != ref.content_sha256 or view.version_sha256 != RETAIL_POLICY.sha256
                or not 0 <= view.excerpt_start <= view.span_start < view.span_end <= view.excerpt_end <= len(policy)
                or view.text != policy[view.excerpt_start:view.excerpt_end]
                or sha256(policy[view.span_start:view.span_end].encode()).hexdigest() != view.quote_sha256):
            return ClauseGrade(False, required, ())
        intervals.append((view.span_start, view.span_end))
    return ClauseGrade(True, required, tuple(
        span.rule_id for span in spans if any(covers(span, start, end) for start, end in intervals)
    ))
