"""Server-authored investigation outcomes and their case message text."""

from policyops_contracts.events import InvestigationReason


ABSTENTION_TEXT = {
    InvestigationReason.MODEL_ABSTAINED: "The investigation ended without a usable decision from the model.",
    InvestigationReason.CITATION_RECORDING_FAILED: "The investigation could not verify and record the citations.",
    InvestigationReason.RENDERED_ANSWER_INVALID: "The completed answer did not pass output validation.",
}
