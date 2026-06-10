"""Lower-level checks on the two dependence analyses."""

from __future__ import annotations

from slither_slicer.dependence.control import control_parents
from slither_slicer.dependence.data import build_def_map, build_use_map


def _func(slicer, contract, sig):
    return slicer._contract(contract).get_function_from_signature(sig)


def test_def_use_maps_are_consistent(reentrancy):
    f = _func(reentrancy, "Reentrancy", "withdraw()")
    def_map = build_def_map(f)
    use_map = build_use_map(f)
    assert def_map  # there are definitions
    # every used SSA var that is also defined points at a real def site
    for var_id in use_map:
        if var_id in def_map:
            node, op = def_map[var_id]
            assert node in f.nodes


def test_require_creates_control_dependence(reentrancy):
    """``require(amount > 0)`` is a linear SolidityCall, not a branch — yet every
    statement after it must be control-dependent on it via the modelled abort
    edge to the exit."""
    f = _func(reentrancy, "Reentrancy", "withdraw()")
    cp = control_parents(f)
    by_id = {n.node_id: n for n in f.nodes}
    require_node = by_id[2]  # require(amount > 0)
    call_node = by_id[4]  # the external call
    assert require_node in cp.get(call_node, set())


def test_control_dependence_is_direct_not_transitive(reentrancy):
    """FOW control dependence records *direct* parents. The post-call write
    (node 6) sits right after ``require(ok)`` (node 5), so its direct guard is
    node 5; node 5 is in turn guarded by ``require(amount > 0)`` (node 2). The
    slicer's transitive closure is what ultimately pulls both in."""
    f = _func(reentrancy, "Reentrancy", "withdraw()")
    cp = control_parents(f)
    by_id = {n.node_id: n for n in f.nodes}
    assert by_id[5] in cp.get(by_id[6], set())  # write guarded by require(ok)
    assert by_id[2] in cp.get(by_id[5], set())  # require(ok) guarded by require(amount>0)
