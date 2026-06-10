"""Raw-graph helpers (the human/CLI window into the PDG)."""

from __future__ import annotations

from slither_slicer import graph as g


def _func(slicer, contract, sig):
    return slicer._contract(contract).get_function_from_signature(sig)


def test_global_node_id_round_trips(reentrancy):
    c = reentrancy._contract("Reentrancy")
    f = c.get_function_from_signature("withdraw()")
    for n in f.nodes:
        nid = g.global_node_id(n)
        assert g.resolve_node(c, nid) is n


def test_resolve_node_rejects_garbage(reentrancy):
    c = reentrancy._contract("Reentrancy")
    for bad in ["nope", "Reentrancy.withdraw()#999", "Reentrancy.withdraw()#x"]:
        try:
            g.resolve_node(c, bad)
            raise AssertionError(f"expected failure for {bad!r}")
        except ValueError:
            pass


def test_pdg_edges_well_formed(reentrancy):
    f = _func(reentrancy, "Reentrancy", "withdraw()")
    edges = g.pdg_edges(f)
    assert edges
    for src, dst, kind in edges:
        assert kind in (g.DATA, g.CONTROL)
        assert src in f.nodes and dst in f.nodes


def test_find_path_directional(reentrancy):
    """The external call (node 4) depends on the balance read (node 1); the
    reverse is not true."""
    c = reentrancy._contract("Reentrancy")
    f = c.get_function_from_signature("withdraw()")
    call = g.resolve_node(c, "Reentrancy.withdraw()#4")
    read = g.resolve_node(c, "Reentrancy.withdraw()#1")

    path = g.find_path(f, call, read)
    assert path is not None
    assert [g.global_node_id(n) for n, _ in path] == [
        "Reentrancy.withdraw()#4",
        "Reentrancy.withdraw()#1",
    ]
    assert path[-1][1] == g.DATA

    assert g.find_path(f, read, call) is None  # read does not depend on the call


def test_find_path_threads_control_and_data(reentrancy):
    """The post-call write (node 6) reaches the balance read (node 1) through a
    control edge then data edges."""
    c = reentrancy._contract("Reentrancy")
    f = c.get_function_from_signature("withdraw()")
    write = g.resolve_node(c, "Reentrancy.withdraw()#6")
    read = g.resolve_node(c, "Reentrancy.withdraw()#1")
    path = g.find_path(f, write, read)
    assert path is not None
    kinds = {kind for _, kind in path[1:]}
    assert g.CONTROL in kinds and g.DATA in kinds
