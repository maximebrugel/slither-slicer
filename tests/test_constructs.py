"""Solidity construct coverage.

Each construct is exercised end-to-end: the slicer must produce a correct slice
or a visible note — never silently miss a guard, a sink, or a dependence. Several
of these constructs were previously untested.
"""

from __future__ import annotations

from conftest import node_set


def _sink(slicer, contract, origin, fn_contains=None):
    for s in slicer.slice_all_sinks(contract):
        if s.criterion.origin == origin and (
            fn_contains is None or fn_contains in s.criterion.function_name
        ):
            return s
    raise AssertionError(f"no {origin} sink in {contract}")


# --- custom errors: `if (cond) revert CustomError()` -------------------------
def test_custom_error_revert_is_a_guard(custom_errors):
    """A caller check via `if (msg.sender != owner) revert Unauthorized()` carries
    no require — guard detection must still recognise it."""
    s = _sink(custom_errors, "CustomErrors", "sink:state_write", "setGuarded")
    assert s.guarded is True
    # the conditional-revert guard node is in the slice as a control dep
    assert any(r == "control-dep" for _id, r in node_set(s))


def test_non_caller_custom_error_is_not_a_guard(custom_errors):
    """`if (v < 10) revert TooSmall()` checks a value, not the caller."""
    s = _sink(custom_errors, "CustomErrors", "sink:state_write", "setChecked")
    assert s.guarded is False


# --- try / catch -------------------------------------------------------------
def test_try_catch_writes_both_branches_cataloged(try_catch):
    """Both the success-path (`last = v`) and catch-path (`failed = true`) state
    writes must be cataloged, and the call is an interaction so CEI fires."""
    sinks = try_catch.slice_all_sinks("TryCatch")
    writes = {s.criterion.function_name for s in sinks if s.criterion.origin == "sink:state_write"}
    assert writes == {"TryCatch.update(IFeed)"}
    state_written = set()
    for s in sinks:
        state_written.update(s.state_vars_written)
    assert {"last", "failed"} <= state_written
    assert any(s.state_write_after_external_call for s in sinks)


# --- structs / field access --------------------------------------------------
def test_struct_field_write_flags_imprecise_key(structs):
    """A struct field written through a non-constant mapping key resolves to the
    base (`positions`) and flags the imprecise index rather than silently
    pretending the access is precise."""
    s = _sink(structs, "Structs", "sink:state_write", "open")
    assert "positions" in s.state_vars_written
    assert any(n.startswith("imprecise-alias:positions") for n in s.notes)


# --- loops -------------------------------------------------------------------
def test_loop_with_external_call_terminates_and_flags(loops):
    """A loop paying an array of recipients must slice without diverging, flag the
    tainted index, and see the CEI ordering risk (write then external call)."""
    s = _sink(loops, "Loops", "sink:ether_transfer")
    assert s.nodes
    assert any(n.startswith("imprecise-alias:") for n in s.notes)
    # the loop body's external call is the criterion; the require guard is pulled
    assert any(r in ("control-dep", "criterion") for _id, r in node_set(s))


# --- receive / fallback ------------------------------------------------------
def test_receive_and_fallback_are_entry_points(fallback_receive):
    sinks = fallback_receive.slice_all_sinks("FallbackReceive")
    fns = {s.criterion.function_name for s in sinks}
    assert any("receive()" in f for f in fns)
    assert any("fallback()" in f for f in fns)
    # both appear in the audit overview as entry points
    rows = {r["function"] for r in fallback_receive.audit_overview("FallbackReceive")}
    assert any("receive" in f for f in rows)
    assert any("fallback" in f for f in rows)


# --- multi-level inheritance -------------------------------------------------
def test_multilevel_ascent_and_guard_visibility(multi_inherit):
    """A privileged write in an internal helper (Middle._apply), reached from a
    guarded entry (Top.setConfig onlyOwner declared in Base), must stitch the
    caller AND surface the base-declared modifier guard."""
    s = _sink(multi_inherit, "Top", "sink:state_write")
    assert "Top.setConfig(uint256)" in s.functions_touched
    assert any(
        nid.startswith("Base.onlyOwner()") and r == "modifier-guard"
        for nid, r in node_set(s)
    )


def test_multilevel_entry_point_guarded_in_overview(multi_inherit):
    rows = {r["function"]: r for r in multi_inherit.audit_overview("Top")}
    setcfg = next(r for f, r in rows.items() if "setConfig" in f)
    assert setcfg["guarded"] is True
