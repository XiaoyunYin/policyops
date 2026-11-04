"""Shared synthetic retail world fixture (see policyops.domain.examples)."""

import pytest

from policyops.domain.examples import World


@pytest.fixture
def world() -> World:
    return World()
