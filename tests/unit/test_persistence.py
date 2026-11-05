"""Database-free checks of the persistence layer: secret handling, exact amounts, names and migration text."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
import re
from uuid import uuid4

from pydantic import ValidationError
import pytest

from policyops.persistence import migrate
from policyops.persistence.bootstrap import BootstrapError, _database_name
from policyops.persistence.database import make_engine
from policyops.persistence.records import NewJob, exact_usd
from policyops.persistence.roles import ALL_ROLES, APP_RUNTIME, RolePassword, scram_sha256_verifier


SYNTHETIC = "synthetic-password-" + "x" * 8


def test_role_passwords_are_never_shown_and_are_validated() -> None:
    password = RolePassword(APP_RUNTIME, SYNTHETIC)
    assert SYNTHETIC not in repr(password) and SYNTHETIC not in str(password)
    with pytest.raises(ValueError, match="at least"):
        RolePassword(APP_RUNTIME, "short")
    with pytest.raises(ValueError, match="not an application role"):
        RolePassword("postgres", SYNTHETIC)
    assert len(ALL_ROLES) == len(set(ALL_ROLES)) == 5


def test_scram_verifier_format_and_inputs() -> None:
    verifier = scram_sha256_verifier(SYNTHETIC, salt=b"\x00" * 16)
    assert re.fullmatch(r"SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]{24}\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}", verifier)
    assert verifier == scram_sha256_verifier(SYNTHETIC, salt=b"\x00" * 16)  # deterministic given the salt
    assert scram_sha256_verifier(SYNTHETIC) != scram_sha256_verifier(SYNTHETIC)  # random salt by default
    assert SYNTHETIC not in verifier
    for bad in ("pässword-synthetic-1", "tab\tseparated-synthetic"):
        with pytest.raises(ValueError, match="printable ASCII"):
            scram_sha256_verifier(bad)


@pytest.mark.parametrize("value", ["0", "0.000000000000000001", "999999.999999999999999999", "1.50"])
def test_exact_usd_accepts_finite_bounded_values(value: str) -> None:
    exact_usd(Decimal(value), "x")


@pytest.mark.parametrize("value", ["0.0000000000000000001", "1000000", "-1E-18", "NaN", "Infinity", "sNaN"])
def test_exact_usd_rejects_rather_than_rounds(value: str) -> None:
    with pytest.raises(ValueError):
        exact_usd(Decimal(value), "x")


@pytest.mark.parametrize("name", ["postgres", "template1", "pg_app", "app-db", "app;drop", "App", "1app", "a" * 64])
def test_database_names_are_plain_identifiers(name: str) -> None:
    with pytest.raises(BootstrapError):
        _database_name(name)


def test_engine_pool_is_bounded() -> None:
    for size in (0, 51):
        with pytest.raises(ValueError):
            make_engine(lambda: None, pool_size=size)  # type: ignore[arg-type,return-value]


MIGRATION_TEXT = "\n".join(path.read_text(encoding="utf-8")
                           for path in sorted((migrate.MIGRATIONS / "versions").glob("*.py")))


@pytest.mark.parametrize("pattern", [
    r"(?i)\bretail\.", r"(?i)create\s+schema\s+retail", r"(?i)create\s+extension", r"(?i)alter\s+default\s+privileges",
    r"(?i)security\s+definer", r"(?i)bypassrls", r"(?i)grant\s+[^;]*\bto\s+public\b",
    r"(?i)grant\s+[^;]*\bdelete\b", r"(?i)on\s+delete\s+(cascade|set\s+null)",
])
# Column types (no floats, no rounding NUMERIC(p, s)) are checked on the live catalog in the integration suite.
def test_migrations_avoid_forbidden_constructs(pattern: str) -> None:
    assert re.search(pattern, MIGRATION_TEXT) is None, pattern


def test_revisions_are_sequential_and_documented() -> None:
    assert migrate.revisions() == ["0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008"]
    assert migrate.head() == "0008"
    for path in sorted((migrate.MIGRATIONS / "versions").glob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert text.startswith('"""') and "def downgrade() -> None:" in text and "refuse_data_loss" in text, path.name
    assert Path(migrate.MIGRATIONS / "env.py").is_file()


def test_new_job_requires_a_deadline_after_availability() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValidationError, match="deadline"):
        NewJob(id=uuid4(), workspace_id=uuid4(), run_id=uuid4(), dedupe_key="k", kind="x", run_generation=0,
               max_attempts=1, available_at=now, deadline_at=now, created_at=now)
