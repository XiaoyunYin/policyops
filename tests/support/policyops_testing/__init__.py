"""PolicyOps test harness: network guard, fake provider, seeds, redaction, evidence and an owned PostgreSQL.

Loaded as a pytest plugin (`policyops_testing.plugin`) by the application and evaluator test suites. The
helpers depend only on the standard library, pytest and policyops_contracts, except `postgres`, which needs
psycopg (application environment only).
"""
