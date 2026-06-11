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
SS = str(FIXTURES / "StorageStitch.sol")
XC = str(FIXTURES / "CrossContract.sol")


def test_list_contracts():
    assert m.list_contracts_impl(AC)["contracts"] == [
        {"name": "AccessControl", "kind": "contract", "is_most_derived": True}
    ]


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


def test_audit_overview_shape():
    out = m.audit_overview_impl("Reentrancy", RE)
    assert out["contract"] == "Reentrancy"
    rows = {r["function"]: r for r in out["entry_points"]}
    w = rows["Reentrancy.withdraw()"]
    assert set(w) == {
        "function",
        "visibility",
        "mutability",
        "guarded",
        "state_written",
        "value_out",
        "external_calls",
        "token_sinks",
        "sink_origins",
        "state_write_after_external_call",
    }
    assert w["guarded"] is False
    assert w["state_write_after_external_call"] is True


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
        "state_write_after_external_call",
        "node_count",
        "state_vars_written",
        "storage_writers",
        "external_calls",
        "call_kinds",
        "events_emitted",
        "entry_points",
        "notes",
    }
    assert "nodes" not in sample


def test_state_var_xref_impl():
    out = m.state_var_xref_impl("StorageStitch", "balances", SS)
    assert out["state_var"] == "balances"
    writer_fns = {w["function"] for w in out["writers"]}
    assert any(fn.endswith("deposit()") for fn in writer_fns)
    assert any("slash" in fn for fn in writer_fns)


def test_slice_from_storage_depth_pulls_writers():
    blob = m.slice_from_impl(
        node_id="StorageStitch.withdraw()#5", direction="backward", project=SS, storage_depth=1
    )
    writers = {w["function"] for w in blob["storage_writers"]}
    assert any(fn.endswith("deposit()") for fn in writers)


def test_slice_from_storage_depth_zero_is_baseline():
    blob = m.slice_from_impl(
        node_id="StorageStitch.withdraw()#5", direction="backward", project=SS, storage_depth=0
    )
    assert blob["storage_writers"] == []


def test_slice_from_cross_contract_descends():
    blob = m.slice_from_impl(
        node_id="Vault.pull(address,uint256)#1", project=XC, cross_contract=True
    )
    assert any(n.startswith("cross-contract:Token.transfer") for n in blob["notes"])
    assert "Token.transfer(address,uint256)" in blob["functions_touched"]


def test_slice_from_cross_contract_off_by_default():
    blob = m.slice_from_impl(node_id="Vault.pull(address,uint256)#1", project=XC)
    assert not any(n.startswith("cross-contract:") for n in blob["notes"])


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


def test_explain_dependence_cross_function_ascent():
    """A formal-param read in a callee is connected to the caller's callsite via
    ascent — cross-function reach the v1 tool refused."""
    out = m.explain_dependence_impl(
        "Interproc._transfer(address,uint256)#3", "Interproc.withdraw(uint256)#2", IP
    )
    assert out["connected"] is True
    kinds = {p["edge_kind"] for p in out["path"]}
    assert "callee" in kinds


def test_explain_dependence_cross_function_storage():
    """Two functions sharing a state variable are connected by a storage edge:
    deposit writes `balances`, withdraw reads it."""
    out = m.explain_dependence_impl(
        "StorageStitch.withdraw()#1", "StorageStitch.deposit()#1", SS, depth=2
    )
    assert out["connected"] is True
    assert any(p["edge_kind"] == "storage-dep" for p in out["path"])


def test_explain_dependence_unconnected_within_depth():
    out = m.explain_dependence_impl(
        "StorageStitch.withdraw()#1", "StorageStitch.slash(address,uint256)#0", SS, depth=1
    )
    assert out["connected"] is False
    assert "depth=1" in out["note"]


def test_missing_project_raises(monkeypatch):
    monkeypatch.delenv("SLITHER_SLICER_PROJECT", raising=False)
    with pytest.raises(ValueError):
        m.list_contracts_impl(None)


def test_env_project_used(monkeypatch):
    monkeypatch.setenv("SLITHER_SLICER_PROJECT", AC)
    names = [c["name"] for c in m.list_contracts_impl(None)["contracts"]]
    assert names == ["AccessControl"]
