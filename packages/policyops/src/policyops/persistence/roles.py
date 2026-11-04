"""Database role names and password verifiers for the application database.

Cluster-level roles (shared by every application database on one server):

* `policyops_app_migrator`: owns the application schemas and runs Alembic. Login, but no superuser, CREATEDB,
  CREATEROLE, REPLICATION or BYPASSRLS. Under FORCE ROW LEVEL SECURITY it has no data policies, so it reads no
  tenant rows (data migrations must set a scope or add an explicit, reviewed policy).
* `policyops_app_runtime`: the API/worker role. Tenant business tables only, through forced RLS with a
  transaction-local workspace scope; no DDL, no evaluation, auth-session, principal or retail grants.
* `policyops_auth_runtime`: the trusted authentication-service role (PLAN D1). Pre-workspace identity, session and
  membership lookups and provisioning in the `identity` schema only; no business, evaluation or retail grants.
* `policyops_eval_runtime`: evaluation recording in the `evaluation` schema only.

All runtime roles are NOINHERIT, so a mistaken membership grant cannot silently add privileges.
Retail roles and the retail schema belong to T16 and are never created or granted here.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import secrets
from typing import Final


APP_MIGRATOR: Final = "policyops_app_migrator"
APP_RUNTIME: Final = "policyops_app_runtime"
AUTH_RUNTIME: Final = "policyops_auth_runtime"
EVAL_RUNTIME: Final = "policyops_eval_runtime"
RUNTIME_ROLES: Final = (APP_RUNTIME, AUTH_RUNTIME, EVAL_RUNTIME)
ALL_ROLES: Final = (APP_MIGRATOR, *RUNTIME_ROLES)

SCRAM_ITERATIONS: Final = 4096  # PostgreSQL's default scram_iterations
MIN_PASSWORD_LENGTH: Final = 16


@dataclass(frozen=True, repr=False)
class RolePassword:
    """A login password held in memory only; never printed (repr is masked)."""

    role: str
    value: str

    def __post_init__(self) -> None:
        if self.role not in ALL_ROLES:
            raise ValueError(f"{self.role!r} is not an application role")
        if len(self.value) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"the {self.role} password must have at least {MIN_PASSWORD_LENGTH} characters")

    def __repr__(self) -> str:
        return f"RolePassword(role={self.role!r}, value=<hidden>)"


def scram_sha256_verifier(password: str, *, salt: bytes | None = None, iterations: int = SCRAM_ITERATIONS) -> str:
    """The SCRAM-SHA-256 verifier PostgreSQL stores for `password` (RFC 5802/7677, PostgreSQL's format).

    Bootstrap sends this verifier instead of the password, so the plaintext never reaches the server, its logs or
    pg_stat_activity. (The password is used as-is; PostgreSQL applies SASLprep, which leaves ASCII unchanged, so
    passwords are restricted to printable ASCII.)
    """
    if not password.isascii() or not password.isprintable():
        raise ValueError("passwords must be printable ASCII")
    salt = secrets.token_bytes(16) if salt is None else salt
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, iterations)
    client_key = hmac.digest(salted, b"Client Key", "sha256")
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.digest(salted, b"Server Key", "sha256")

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"
