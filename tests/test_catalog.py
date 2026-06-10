"""Sink / source catalog detection."""

from __future__ import annotations

from slither_slicer.catalog.sinks import find_sinks
from slither_slicer.catalog.sources import find_sources


def test_sinks_detected(reentrancy):
    c = reentrancy._contract("Reentrancy")
    origins = sorted({s.origin for s in find_sinks(c)})
    assert "sink:ether_transfer" in origins
    assert "sink:state_write" in origins


def test_ether_transfer_sink_targets_call_value(reentrancy):
    c = reentrancy._contract("Reentrancy")
    transfer = next(s for s in find_sinks(c) if s.origin == "sink:ether_transfer")
    assert transfer.variable_name == "amount_1"
    assert transfer.function_name == "Reentrancy.withdraw()"


def test_no_spurious_empty_sinks(reentrancy):
    """Phi pseudo-defs at entry points must not register as state-write sinks."""
    sinks = reentrancy.slice_all_sinks("Reentrancy")
    for s in sinks:
        assert s.nodes, f"empty slice for {s.criterion.origin}"


def test_sources_detected(access_control):
    c = access_control._contract("AccessControl")
    origins = {s.origin for s in find_sources(c)}
    assert "source:parameter" in origins
    assert "source:caller" in origins  # msg.sender
    assert "source:call_value" in origins  # msg.value


def test_selfdestruct_sink():
    from pathlib import Path

    from slither_slicer import Slicer

    src = Path(__file__).parent / "fixtures" / "Selfdestruct.sol"
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.20;\n"
        "contract Boom {\n"
        "    address owner;\n"
        "    function kill() external { selfdestruct(payable(owner)); }\n"
        "}\n"
    )
    try:
        sl = Slicer(str(src))
        c = sl._contract("Boom")
        assert any(s.origin == "sink:selfdestruct" for s in find_sinks(c))
    finally:
        src.unlink(missing_ok=True)
