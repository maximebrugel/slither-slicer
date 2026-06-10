"""Golden slice tests.

These pin the *exact* set of included node ids and their reason tags for
hand-verified fixtures. Slicing is easy to get subtly wrong, so every assertion
is intentionally tight. The most important invariant — repeated below as its own
check — is that a guard node is never dropped.
"""

from __future__ import annotations

from conftest import ids, node_set


def _origin(slicer, contract, origin):
    return next(s for s in slicer.slice_all_sinks(contract) if s.criterion.origin == origin)


# --- Access control: the modifier-inclusion regression guard ----------------
def test_access_control_modifier_guard_included(access_control):
    """An ``onlyOwner`` withdraw slice MUST carry the modifier's
    ``require(msg.sender == owner)`` node. This is the whole point of pulling
    modifier bodies in — a naive slice over the function's own nodes misses it.
    """
    s = _origin(access_control, "AccessControl", "sink:ether_transfer")
    assert node_set(s) == {
        ("AccessControl.onlyOwner()#1", "modifier-guard"),
        ("AccessControl.withdraw(uint256)#1", "data-dep"),
        ("AccessControl.withdraw(uint256)#2", "control-dep"),
        ("AccessControl.withdraw(uint256)#5", "criterion"),
    }
    # the guard is present and tagged as a modifier guard
    assert ("AccessControl.onlyOwner()#1", "modifier-guard") in node_set(s)


def test_access_control_helper(access_control):
    s = access_control.access_control_of("AccessControl.withdraw(uint256)")
    assert "AccessControl.onlyOwner()#1" in ids(s)
    assert s.criterion.origin == "access-control"
    assert "owner" in s.state_vars_read


# --- Reentrancy: read before / write after the external call ----------------
def test_reentrancy_backward_from_transfer_includes_balance_read(reentrancy):
    s = _origin(reentrancy, "Reentrancy", "sink:ether_transfer")
    assert node_set(s) == {
        ("Reentrancy.withdraw()#1", "data-dep"),  # uint256 amount = balances[msg.sender]
        ("Reentrancy.withdraw()#2", "control-dep"),  # require(amount > 0)
        ("Reentrancy.withdraw()#4", "criterion"),  # the call{value: amount}
    }
    assert s.external_calls == ['msg.sender.call{value: amount}()']
    assert "imprecise-alias:balances" in s.notes


def test_reentrancy_state_write_slice_sees_external_call(reentrancy):
    """Backward slice from the post-call state write ``balances[...] = 0`` must
    reach the external call that precedes it — that adjacency *is* the
    reentrancy signal.
    """
    sinks = reentrancy.slice_all_sinks("Reentrancy")
    s = next(
        x
        for x in sinks
        if x.criterion.origin == "sink:state_write"
        and x.criterion.function_name == "Reentrancy.withdraw()"
    )
    got = node_set(s)
    assert ("Reentrancy.withdraw()#6", "criterion") in got  # the state write
    assert ("Reentrancy.withdraw()#4", "data-dep") in got  # the external call
    assert s.external_calls == ['msg.sender.call{value: amount}()']
    assert "balances" in s.state_vars_written


# --- Tainted index: alias handling + the imprecise-alias note ---------------
def test_tainted_index_forward_reaches_state_write(tainted_index):
    s = tainted_index.forward_slice("TaintedIndex.set(uint256,uint256)", "key")
    assert node_set(s) == {
        ("TaintedIndex.set(uint256,uint256)#1", "criterion"),  # idx = key + 1
        ("TaintedIndex.set(uint256,uint256)#2", "data-dep"),  # slots[idx] = val
    }
    assert "slots" in s.state_vars_written
    assert "imprecise-alias:slots" in s.notes


# --- Inter-procedural: one-level descent with arg mapping -------------------
def test_interproc_forward_descends_and_maps_args(interproc):
    s = interproc.forward_slice("Interproc.withdraw(uint256)", "amount")
    got = node_set(s)
    # criterion + the internal call live in the caller
    assert ("Interproc.withdraw(uint256)#2", "control-dep") in got
    # descent reached the callee body, mapping actual `amount` -> formal `value`
    callee_nodes = {nid for nid, _ in got if nid.startswith("Interproc._transfer")}
    assert callee_nodes  # we crossed the boundary
    assert all(r == "callee" for nid, r in got if nid.startswith("Interproc._transfer"))
    assert "balances" in s.state_vars_written
    assert s.external_calls == ['to.call{value: value}()']
    # both functions appear
    assert "Interproc._transfer(address,uint256)" in s.functions_touched
    assert "Interproc.withdraw(uint256)" in s.functions_touched


def test_interproc_backward_from_sink_ascends_to_caller(interproc):
    """Backward from the transfer (which lives in the callee) should climb to the
    caller's callsite, mapping the formal ``value`` back to the actual ``amount``."""
    s = _origin(interproc, "Interproc", "sink:ether_transfer")
    got_ids = ids(s)
    assert "Interproc._transfer(address,uint256)#3" in got_ids  # the transfer (criterion)
    # the callsite node in withdraw is pulled in as the caller boundary
    assert any(nid.startswith("Interproc.withdraw") for nid in got_ids)


# --- A guard is never dropped (cross-fixture invariant) ---------------------
def test_no_guard_dropped(access_control, reentrancy):
    """Every sink slice in a guarded function must retain its guards."""
    for s in access_control.slice_all_sinks("AccessControl"):
        if s.criterion.function_name == "AccessControl.withdraw(uint256)":
            assert "AccessControl.onlyOwner()#1" in ids(s)
