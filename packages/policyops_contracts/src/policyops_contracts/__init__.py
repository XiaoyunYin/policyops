"""Wire contracts shared by the PolicyOps application and the evaluator.

This package may depend only on the standard library and Pydantic, so the
evaluator can import it without pulling in the application stack.

0.2.0 (T04) adds the retail tool, state, effect, proposal, consent, approval,
agent-step, event, error, seed and policy-rule contracts. 0.1.0 had only the
WireModel base, which is unchanged.
"""

from policyops_contracts.base import WireModel


CONTRACTS_SCHEMA_VERSION = "0.3.0"

__all__ = ["CONTRACTS_SCHEMA_VERSION", "WireModel"]
