"""Wire contracts shared by the PolicyOps application and the evaluator.

This package may depend only on the standard library and Pydantic, so the
evaluator can import it without pulling in the application stack.
"""

from policyops_contracts.base import WireModel


CONTRACTS_SCHEMA_VERSION = "0.1.0"

__all__ = ["CONTRACTS_SCHEMA_VERSION", "WireModel"]
