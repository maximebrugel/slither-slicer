"""Library-call descent, call classification, guarded flag, richer context.

These pin the behaviour added after the slicer was run against a real Foundry
project, where ~58% of calls were library calls being dropped as opaque.
"""

from __future__ import annotations

from conftest import ids, node_set


def _sink(slicer, origin):
    return next(s for s in slicer.slice_all_sinks("Library") if s.criterion.origin == origin)


def test_library_call_descended_data_and_control(library):
    """Backward slice from the `total = doubled` write must reach *both* the
    library's validation guard (`require(x>0)`, via control dependence) and its
    body (`return x*2`, via data-flow descent) — the code that was previously
    dropped as an opaque external boundary."""
    s = _sink(library, "sink:state_write")
    got = node_set(s)
    assert ("LibMath.checkedDouble(uint256)#1", "control-dep") in got  # require(x>0) guard
    assert ("LibMath.checkedDouble(uint256)#2", "callee") in got  # return x*2 body
    # access-control guard still pulled in
    assert ("Library.onlyOwner()#1", "modifier-guard") in got
    assert "LibMath.checkedDouble(uint256)" in s.functions_touched


def test_calls_classified_as_library_not_opaque(library):
    s = _sink(library, "sink:state_write")
    kinds = {c["kind"] for c in s.calls}
    assert kinds == {"library"}
    # a descended library call is NOT an opaque boundary
    assert s.external_calls == []
    assert all(c["in_scope"] for c in s.calls)


def test_guarded_flag(library):
    """`store` is onlyOwner (guarded); `forward` is open (unguarded)."""
    assert _sink(library, "sink:state_write").guarded is True
    assert _sink(library, "sink:arbitrary_call").guarded is False


def test_arbitrary_call_sink(library):
    """`forward(address target, ...)` calls an attacker-controlled target."""
    s = _sink(library, "sink:arbitrary_call")
    assert s.criterion.function_name == "Library.forward(address,bytes)"
    # the opaque low-level call to the param target is recorded as a boundary
    assert any(c["kind"] == "low_level" for c in s.calls)


def test_entry_points_and_types(library):
    s = _sink(library, "sink:state_write")
    assert s.entry_points == ["Library.store(uint256)"]
    assert s.state_var_types.get("total") == "uint256"


def test_events_emitted_in_forward_slice(library):
    """A forward slice from `amount` flows into the `emit Stored(doubled)`."""
    fs = library.forward_slice("Library.store(uint256)", "amount")
    assert [e["name"] for e in fs.events_emitted] == ["Stored"]


def test_seed_is_whole_node_not_library_name(library):
    """The external/arbitrary-call sink seeds the whole node (variable=None),
    never the library/contract name."""
    s = _sink(library, "sink:arbitrary_call")
    assert s.criterion.variable_name is None


def test_no_guard_dropped_with_library(library):
    s = _sink(library, "sink:state_write")
    assert "Library.onlyOwner()#1" in ids(s)
