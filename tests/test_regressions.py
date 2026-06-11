"""Regression tests for the audit-blindness fixes.

Each test pins a behavior that used to fail silently: invisible inherited code,
`guarded` false positives, no-op composed-var slices, dropped implicit flows,
undrillable whole-node sinks, and stale byte-accurate source after edits.
"""

from __future__ import annotations

from pathlib import Path

from slither_slicer import Slicer
from slither_slicer.catalog.access import is_guarded
from slither_slicer.catalog.sinks import find_sinks
from slither_slicer.catalog.sources import find_sources
from slither_slicer.slicer import backward_slice

FIXTURES = Path(__file__).parent / "fixtures"


# -- inherited code is live code ---------------------------------------------
def test_inherited_sink_cataloged(inherited):
    """An ether transfer declared in a base contract is a sink of the derived."""
    c = inherited._contract("Vault")
    sinks = find_sinks(c)
    assert any(
        s.origin == "sink:ether_transfer" and s.function_name == "Base.sweep(address)"
        for s in sinks
    )


def test_ascent_climbs_into_base_declared_caller(inherited):
    """Backward ascent from a sink must find callsites declared in the base."""
    c = inherited._contract("Vault")
    crit = next(
        s
        for s in find_sinks(c)
        if s.origin == "sink:state_write" and s.function_name == "Base._store(uint256)"
    )
    s = backward_slice(c, crit)
    assert "Base.baseEntry(uint256)" in s.functions_touched
    assert "Vault.deposit()" in s.functions_touched


def test_list_contracts_includes_base():
    from slither_slicer import mcp_server as m

    out = m.list_contracts_impl(str(FIXTURES / "Inherited.sol"))
    by_name = {c["name"]: c for c in out["contracts"]}
    assert by_name["Vault"]["is_most_derived"] is True
    assert by_name["Base"]["is_most_derived"] is False


def test_depth_controls_ascent(inherited):
    """two -> one -> _store: the second ascent level needs depth=2."""
    c = inherited._contract("Vault")
    crit = next(
        s
        for s in find_sinks(c)
        if s.origin == "sink:state_write" and s.function_name == "Base._store(uint256)"
    )
    shallow = backward_slice(c, crit, depth=1)
    deep = backward_slice(c, crit, depth=2)
    assert "Base.two(uint256)" not in shallow.functions_touched
    assert "Base.two(uint256)" in deep.functions_touched


# -- guarded means the CALLER is restricted -----------------------------------
def test_nonreentrant_is_not_guarded(guards):
    c = guards._contract("Guards")
    assert is_guarded(c.get_function_from_signature("poke()")) is False


def test_indirect_modifier_check_is_guarded(guards):
    c = guards._contract("Guards")
    assert is_guarded(c.get_function_from_signature("adminIndirect(uint256)")) is True


def test_inline_caller_check_is_guarded(guards):
    c = guards._contract("Guards")
    assert is_guarded(c.get_function_from_signature("adminInline(uint256)")) is True


def test_solvency_check_is_not_guarded(guards):
    """require(balances[msg.sender] >= amount) reads the caller but restricts
    nothing about who may call — every ERC20.transfer would be 'guarded'."""
    c = guards._contract("Guards")
    assert is_guarded(c.get_function_from_signature("spend(uint256)")) is False


def test_bool_allowlist_lookup_is_guarded(guards):
    c = guards._contract("Guards")
    assert is_guarded(c.get_function_from_signature("gated(uint256)")) is True


def test_unguarded_sink_surfaces_in_catalog(guards):
    """End to end: the nonReentrant-only state write reads guarded=False."""
    slices = guards.slice_all_sinks("Guards")
    poke = [s for s in slices if s.criterion.function_name == "Guards.poke()"]
    assert poke and all(s.guarded is False for s in poke)


# -- composed-var criteria + implicit flows -----------------------------------
def test_forward_slice_msg_value_by_name(implicit_flow):
    """`msg.value` by name must seed the real IR occurrences (was a no-op), and
    the write guarded by the tainted branch (implicit flow) must be included."""
    s = implicit_flow.forward_slice("ImplicitFlow.play()", "msg.value")
    code = {n.source.code.strip() for n in s.nodes}
    assert any("v > 1" in c for c in code)  # tainted branch reached through `v`
    assert any("won = true" in c for c in code)  # implicit flow under the branch
    assert s.state_vars_written == ["won"]


def test_forward_slice_msg_value_via_mcp():
    from slither_slicer import mcp_server as m

    blob = m.slice_from_impl(
        "ImplicitFlow.play()", "msg.value", "forward", str(FIXTURES / "ImplicitFlow.sol")
    )
    assert "won" in blob["state_vars_written"]


def test_source_catalog_dedupes_composed_vars(reentrancy):
    """One msg.sender criterion per function, not one per reading node."""
    c = reentrancy._contract("Reentrancy")
    callers = [
        s
        for s in find_sources(c)
        if s.origin == "source:caller" and s.function_name == "Reentrancy.withdraw()"
    ]
    assert len(callers) == 1


# -- whole-node sinks are drillable via node_id --------------------------------
def test_delegatecall_sink_drillable_by_node_id():
    from slither_slicer import mcp_server as m

    proj = str(FIXTURES / "Proxy.sol")
    cat = m.slice_all_sinks_impl("Proxy", proj)
    sink = next(s for s in cat["sinks"] if s["origin"] == "sink:delegatecall")
    blob = m.slice_from_impl(node_id=sink["criterion_node_id"], project=proj)
    assert blob["nodes"], "drill-in slice must not be empty"
    assert sink["criterion_node_id"] in {n["node_id"] for n in blob["nodes"]}
    assert blob["criterion"]["function"] == "Proxy.exec(bytes)"


def test_slice_at_node_library_api(proxy):
    from slither_slicer.criteria import Direction

    cat = find_sinks(proxy._contract("Proxy"))
    crit = next(s for s in cat if s.origin == "sink:delegatecall")
    node_id = f"{crit.function_name}#{crit.node.node_id}"
    s = proxy.slice_at_node(node_id, direction=Direction.BACKWARD)
    assert any(n.node_id == node_id for n in s.nodes)


def test_staticcall_is_not_a_sink(proxy):
    sinks = find_sinks(proxy._contract("Proxy"))
    assert not any(s.function_name == "Proxy.peek(address)" for s in sinks)


# -- byte accuracy survives edits ----------------------------------------------
_STALE_SRC = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity 0.8.20;\n"
    "contract A {\n"
    "    uint256 public x;\n"
    "    function set(uint256 v) external { x = v; }\n"
    "}\n"
)


def test_source_bytes_fresh_after_edit(tmp_path):
    src = tmp_path / "A.sol"
    src.write_text(_STALE_SRC)
    s1 = Slicer(str(src)).backward_slice("A.set(uint256)", "x")
    assert any(n.source.code == "x = v" for n in s1.nodes)

    src.write_text(_STALE_SRC.replace("x = v;", "x = v + 1;"))
    s2 = Slicer(str(src)).backward_slice("A.set(uint256)", "x")
    assert any(n.source.code == "x = v + 1" for n in s2.nodes)


def test_mcp_recompiles_on_edit(tmp_path):
    from slither_slicer import mcp_server as m

    src = tmp_path / "A.sol"
    src.write_text(_STALE_SRC)
    proj = str(src)
    first = m._get_slicer(proj)
    assert m._get_slicer(proj) is first  # unchanged -> cached

    src.write_text(_STALE_SRC.replace("x = v;", "x = v + 1;"))
    assert m._get_slicer(proj) is not first  # edited -> recompiled
