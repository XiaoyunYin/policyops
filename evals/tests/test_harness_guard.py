"""The evaluator suite runs under the same in-process network guard as the application suite."""

import socket
import urllib.request

import pytest

from policyops_testing import network
from policyops_testing.network import NetworkBlocked


def test_guard_is_installed_in_the_evaluator_session() -> None:
    assert network.installed() and socket.socket.connect is network._connect


@pytest.mark.parametrize("target", ["http://203.0.113.10/", "https://github.com/"])
def test_evaluator_tests_cannot_reach_the_network(target: str) -> None:
    with pytest.raises(NetworkBlocked):
        urllib.request.urlopen(target, timeout=2)  # noqa: S310 - the guard must refuse it
