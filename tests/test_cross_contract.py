"""Cross-contract descent: the resolver, the cheap resolved_target annotation,
and opt-in descent into a resolvable external callee."""

from __future__ import annotations

from slither_slicer import Direction
from slither_slicer.interproc import is_cross_contract_call, resolve_high_level_target


def _calls_in(contract, fnsig):
    f = contract.get_function_from_signature(fnsig)
    return [op for n in f.nodes for op in n.irs_ssa if is_cross_contract_call(op)]


def test_resolver_concrete_target(cross_contract):
    c = cross_contract._contract("Vault")
    (op,) = _calls_in(c, "pull(address,uint256)")
    fn, note = resolve_high_level_target(op)
    assert note is None
    assert fn.canonical_name == "Token.transfer(address,uint256)"


def test_resolver_interface_single_implementer(cross_contract):
    c = cross_contract._contract("Vault")
    (op,) = _calls_in(c, "readPrice()")
    fn, note = resolve_high_level_target(op)
    assert note is None
    assert fn.canonical_name == "Oracle.price()"


def test_resolver_interface_ambiguous(cross_contract):
    c = cross_contract._contract("Vault")
    (op,) = _calls_in(c, "readQuote()")
    fn, note = resolve_high_level_target(op)
    assert fn is None
    assert note == "cross-contract-ambiguous:IPriced:2-impls"


def _pull_sink(slicer, **kw):
    return next(
        x
        for x in slicer.slice_all_sinks("Vault", **kw)
        if "pull" in x.criterion.function_name and x.criterion.origin == "sink:token_transfer"
    )


def test_resolved_target_annotation_is_default_on(cross_contract):
    """Even without descent, the external call is statically annotated with the
    single concrete contract it resolves to — a cheap orientation fact."""
    s = _pull_sink(cross_contract, cross_contract=False)
    externals = [c for c in s.calls if c["kind"] == "external"]
    assert any(c["resolved_target"] == "Token.transfer(address,uint256)" for c in externals)
    # but no descent happened
    assert not any(n.startswith("cross-contract:") for n in s.notes)
    assert "Token.transfer(address,uint256)" not in s.functions_touched


def test_cross_contract_descends_into_callee(cross_contract):
    """With cross_contract=True, Token.transfer's body (`bal[to] += amount`) is
    pulled into the slice and a cross-contract note records the assumption."""
    s = _pull_sink(cross_contract, cross_contract=True)
    assert "cross-contract:Token.transfer(address,uint256)" in s.notes
    assert "Token.transfer(address,uint256)" in s.functions_touched
    callee_nodes = [n for n in s.nodes if n.node_id.startswith("Token.transfer")]
    assert callee_nodes
    assert any("bal" in n.source.code for n in callee_nodes)


def test_ambiguous_call_never_descends(cross_contract):
    """A call through an interface with two implementers stays opaque, with an
    explanatory note — never a silent or wrong descent."""
    # readQuote is view (no sink); slice forward from its boundary via a node id.
    c = cross_contract._contract("Vault")
    (op,) = _calls_in(c, "readQuote()")
    node = next(n for n in c.get_function_from_signature("readQuote()").nodes if op in n.irs_ssa)
    node_id = f"Vault.readQuote()#{node.node_id}"
    s = cross_contract.slice_at_node(node_id, direction=Direction.BACKWARD, cross_contract=True)
    assert "cross-contract-ambiguous:IPriced:2-impls" in s.notes
    assert not any(
        fn.startswith("PricedA") or fn.startswith("PricedB") for fn in s.functions_touched
    )
