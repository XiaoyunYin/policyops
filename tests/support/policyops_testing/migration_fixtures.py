"""Seed historical migration fixtures using current app code only at the current schema head.

The explicit lossy downgrade constructs the old fixture; it is never an application runtime configuration.
Historical migration assertions then use SQL, or upgrade to head before invoking current runtime code.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from policyops.persistence import migrate
from policyops.persistence.importer import ImportReport, import_synthetic_world
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_testing.app_database import AppDatabase


@contextmanager
def seed_at_head(database: AppDatabase) -> Iterator[None]:
    previous = database.current()
    assert previous is not None
    database.upgrade(migrate.head())
    try:
        yield
    finally:
        if previous != migrate.head():
            database.downgrade(previous, allow_data_loss=True)


def seed_world(database: AppDatabase) -> ImportReport:
    with seed_at_head(database):
        return import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
