"""Payload-free termination codes from tau2 at the pinned upstream commit.

Kept SDK-free so historical taxonomy rendering never imports the simulator.
"""


SIMULATION_TERMINATIONS = frozenset({
    "user_stop", "agent_stop", "max_steps", "timeout", "too_many_errors", "agent_error", "user_error",
    "infrastructure_error", "context_window_exceeded", "unexpected_error",
})


# Lookup returns the plain string: tau2 passes str-mixin Enum members, whose
# str() is "TerminationReason.X" rather than the code.
_CODES = {code: code for code in SIMULATION_TERMINATIONS}


def closed_termination(value: object) -> str:
    return _CODES.get(value, "unknown") if isinstance(value, str) else "unknown"
