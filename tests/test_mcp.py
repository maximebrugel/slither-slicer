"""MCP tool behaviour.

Tools are tested by calling their plain `_impl` helpers directly (the FastMCP
decorators are thin wrappers), with the project passed explicitly. This keeps the
agent-surface contract honest without spinning up a stdio transport.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from slither_slicer import mcp_server as m

FIXTURES = Path(__file__).parent / "fixtures"
AC = str(FIXTURES / "AccessControl.sol")
RE = str(FIXTURES / "Reentrancy.sol")
IP = str(FIXTURES / "Interproc.sol")


def test_list_contracts():
    assert m.list_contracts_impl(AC)["contracts"] == ["AccessControl"]


def test_list_functions_shape():
    funcs = m.list_functions_impl("AccessControl", AC)["functions"]
    by_name = {f["name"]: f for f in funcs}
    assert by_name["withdraw(uint256)"]["modifiers"] == ["onlyOwner"]
    assert by_name["withdraw(uint256)"]["visibility"] == "external"
    assert set(by_name["withdraw(uint256)"]) == {
        "name",
        "canonical_name",
        "visibility",
        "modifiers",
        "is_constructor",
        "mutability",
    }


def test_slice_all_sinks_is_compact_catalog():
    out = m.slice_all_sinks_impl("Reentrancy", RE)
    origins = {s["origin"] for s in out["sinks"]}
    assert "sink:ether_transfer" in origins
    assert "sink:state_write" in origins
    # compact: summaries carry no node bodies, but enough to drill in
    sample = out["sinks"][0]
    assert set(sample) == {
        "origin",
        "function",
        "variable",
        "direction",
        "location",
        "criterion_node_id",
        "guarded",
        "node_count",
        "state_vars_written",
        "external_calls",
        "call_kinds",
        "events_emitted",
        "entry_points",
        "notes",
    }
    assert "nodes" not in sample


def test_slice_all_sources_catalog():
    out = m.slice_all_sources_impl("AccessControl", AC)
    origins = {s["origin"] for s in out["sources"]}
    assert "source:parameter" in origins
    assert "source:caller" in origins


def test_slice_from_reproduces_modifier_guard():
    blob = m.slice_from_impl("AccessControl.withdraw(uint256)", "amount", "backward", AC)
    node_reasons = {(n["node_id"], n["reason"]) for n in blob["nodes"]}
    assert ("AccessControl.onlyOwner()#1", "modifier-guard") in node_reasons
    assert blob["criterion"]["direction"] == "BACKWARD"


def test_slice_from_rejects_bad_direction():
    with pytest.raises(ValueError):
        m.slice_from_impl("AccessControl.withdraw(uint256)", "amount", "sideways", AC)


def test_access_control_full_slice():
    blob = m.access_control_of_impl("AccessControl.withdraw(uint256)", AC)
    assert any(n["function"] == "AccessControl.onlyOwner()" for n in blob["nodes"])
    assert blob["criterion"]["origin"] == "access-control"


def test_find_callers_and_callees_interproc():
    callers = m.find_callers_impl("Interproc._transfer(address,uint256)", IP)
    assert callers["callers"][0]["caller"] == "Interproc.withdraw(uint256)"
    assert callers["is_entry_point"] is False

    callees = m.find_callees_impl("Interproc.withdraw(uint256)", IP)
    assert any(
        c["target"] == "Interproc._transfer(address,uint256)" and c["kind"] == "internal"
        for c in callees["in_scope"]
    )
    # the external call lives in _transfer, not withdraw
    ext = m.find_callees_impl("Interproc._transfer(address,uint256)", IP)["external"]
    assert ext and ext[0]["kind"] in ("external", "low_level", "delegatecall")


def test_find_callers_marks_entry_point():
    callers = m.find_callers_impl("AccessControl.withdraw(uint256)", AC)
    assert callers["callers"] == []
    assert callers["is_entry_point"] is True


def test_explain_dependence_connected_and_directional():
    out = m.explain_dependence_impl(
        "Reentrancy.withdraw()#4", "Reentrancy.withdraw()#1", RE
    )
    assert out["connected"] is True
    assert out["path"][0]["node_id"] == "Reentrancy.withdraw()#4"
    assert out["path"][-1]["node_id"] == "Reentrancy.withdraw()#1"


def test_explain_dependence_cross_function_noted():
    out = m.explain_dependence_impl(
        "Interproc.withdraw(uint256)#1", "Interproc._transfer(address,uint256)#3", IP
    )
    assert out["connected"] is False
    assert "cross-function" in out["note"]


def test_missing_project_raises(monkeypatch):
    monkeypatch.delenv("SLITHER_SLICER_PROJECT", raising=False)
    with pytest.raises(ValueError):
        m.list_contracts_impl(None)


def test_env_project_used(monkeypatch):
    monkeypatch.setenv("SLITHER_SLICER_PROJECT", AC)
    assert m.list_contracts_impl(None)["contracts"] == ["AccessControl"]
