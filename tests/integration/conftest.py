"""Fixtures for application-database integration tests (real pinned PostgreSQL; `postgres` marker)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from policyops_testing.app_database import AppCluster, AppDatabase, NewDatabase
from policyops_testing.postgres import OwnedPostgres


@pytest.fixture(scope="session")
def app_cluster(postgres: OwnedPostgres) -> AppCluster:
    return AppCluster.provision(postgres)


@pytest.fixture
def new_app_database(app_cluster: AppCluster) -> Iterator[NewDatabase]:
    """Factory for fresh bootstrapped databases (each a unique owned name); engines are disposed at teardown."""
    created: list[AppDatabase] = []

    def make(label: str = "test", *, extensions: bool = True, revision: str | None = "head") -> AppDatabase:
        database = app_cluster.create_database(label, extensions=extensions)
        created.append(database)
        if revision is not None:
            database.upgrade(revision)
        return database

    yield make
    for database in created:
        database.dispose()


@pytest.fixture(scope="module")
def shared_db(app_cluster: AppCluster) -> Iterator[AppDatabase]:
    """One migrated database per module for tests that isolate themselves by fresh workspace IDs."""
    database = app_cluster.create_database("shared")
    database.upgrade()
    yield database
    database.dispose()
