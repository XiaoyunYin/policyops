"""PolicyOps evaluator and retail-simulator wrapper.

Runs against pinned upstream tau2-bench. Hidden task data stays inside this
process; only policyops_contracts types cross into the application runtime.
"""

TAU2_COMMIT = "19f13ea3f5fba8b4c4d272d1353590f29dc53062"
