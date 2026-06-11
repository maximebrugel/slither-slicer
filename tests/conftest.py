"""Shared fixtures. Compilation is the slow part, so each contract is compiled
once per test session and reused.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from slither_slicer import Slicer

FIXTURES = Path(__file__).parent / "fixtures"


def _slicer(name: str) -> Slicer:
    return Slicer(str(FIXTURES / name))


@pytest.fixture(scope="session")
def access_control() -> Slicer:
    return _slicer("AccessControl.sol")


@pytest.fixture(scope="session")
def reentrancy() -> Slicer:
    return _slicer("Reentrancy.sol")


@pytest.fixture(scope="session")
def interproc() -> Slicer:
    return _slicer("Interproc.sol")


@pytest.fixture(scope="session")
def tainted_index() -> Slicer:
    return _slicer("TaintedIndex.sol")


@pytest.fixture(scope="session")
def library() -> Slicer:
    return _slicer("Library.sol")


def node_set(sl) -> set[tuple[str, str]]:
    """(node_id, reason) pairs for a slice."""
    return {(n.node_id, n.reason) for n in sl.nodes}


def ids(sl) -> set[str]:
    return {n.node_id for n in sl.nodes}


def reasons(sl) -> set[str]:
    return {n.reason for n in sl.nodes}
