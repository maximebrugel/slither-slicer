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


@pytest.fixture(scope="session")
def inherited() -> Slicer:
    return _slicer("Inherited.sol")


@pytest.fixture(scope="session")
def guards() -> Slicer:
    return _slicer("Guards.sol")


@pytest.fixture(scope="session")
def implicit_flow() -> Slicer:
    return _slicer("ImplicitFlow.sol")


@pytest.fixture(scope="session")
def proxy() -> Slicer:
    return _slicer("Proxy.sol")


@pytest.fixture(scope="session")
def tokens() -> Slicer:
    return _slicer("Tokens.sol")


@pytest.fixture(scope="session")
def cei_safe() -> Slicer:
    return _slicer("CEISafe.sol")


@pytest.fixture(scope="session")
def storage_stitch() -> Slicer:
    return _slicer("StorageStitch.sol")


@pytest.fixture(scope="session")
def cross_contract() -> Slicer:
    return _slicer("CrossContract.sol")


@pytest.fixture(scope="session")
def custom_errors() -> Slicer:
    return _slicer("CustomErrors.sol")


@pytest.fixture(scope="session")
def try_catch() -> Slicer:
    return _slicer("TryCatch.sol")


@pytest.fixture(scope="session")
def structs() -> Slicer:
    return _slicer("Structs.sol")


@pytest.fixture(scope="session")
def loops() -> Slicer:
    return _slicer("Loops.sol")


@pytest.fixture(scope="session")
def fallback_receive() -> Slicer:
    return _slicer("FallbackReceive.sol")


@pytest.fixture(scope="session")
def multi_inherit() -> Slicer:
    return _slicer("MultiInherit.sol")


def node_set(sl) -> set[tuple[str, str]]:
    """(node_id, reason) pairs for a slice."""
    return {(n.node_id, n.reason) for n in sl.nodes}


def ids(sl) -> set[str]:
    return {n.node_id for n in sl.nodes}


def reasons(sl) -> set[str]:
    return {n.reason for n in sl.nodes}
