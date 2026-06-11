"""Pattern-level audit heuristics: CEI ordering + the audit-overview triage tool."""

from __future__ import annotations

from slither_slicer.patterns import audit_overview, state_write_after_external_call


def test_cei_violation_detected_on_reentrancy(reentrancy):
    """``withdraw`` writes ``balances[...] = 0`` after the external call — the
    checks-effects-interactions ordering risk must be flagged."""
    c = reentrancy._contract("Reentrancy")
    withdraw = c.get_function_from_signature("withdraw()")
    assert state_write_after_external_call(withdraw) is True


def test_cei_correct_is_not_flagged(cei_safe):
    """Effects-before-interactions has no state write reachable after the call."""
    c = cei_safe._contract("CEISafe")
    withdraw = c.get_function_from_signature("withdraw()")
    assert state_write_after_external_call(withdraw) is False


def test_cei_flag_on_slice(reentrancy):
    """The flag rides on the slice so the agent sees it without a second call."""
    s = next(
        x
        for x in reentrancy.slice_all_sinks("Reentrancy")
        if x.criterion.origin == "sink:ether_transfer"
    )
    assert s.state_write_after_external_call is True
    assert s.to_json()["state_write_after_external_call"] is True


def test_audit_overview_rows(reentrancy):
    rows = audit_overview(reentrancy._contract("Reentrancy"))
    by_fn = {r["function"]: r for r in rows}
    # both entry points present; constructor excluded
    assert "Reentrancy.withdraw()" in by_fn
    assert "Reentrancy.deposit()" in by_fn

    withdraw = by_fn["Reentrancy.withdraw()"]
    assert withdraw["guarded"] is False
    assert withdraw["value_out"] is True
    assert withdraw["state_write_after_external_call"] is True
    assert "balances" in withdraw["state_written"]
    assert withdraw["external_calls"]  # the call{value:} boundary

    deposit = by_fn["Reentrancy.deposit()"]
    assert deposit["state_write_after_external_call"] is False


def test_audit_overview_marks_guarded(access_control):
    rows = audit_overview(access_control._contract("AccessControl"))
    withdraw = next(r for r in rows if r["function"].startswith("AccessControl.withdraw"))
    assert withdraw["guarded"] is True


def test_audit_overview_token_sinks(tokens):
    rows = audit_overview(tokens._contract("Vault"))
    pay = next(r for r in rows if r["function"] == "Vault.pay(address,uint256)")
    assert "sink:token_transfer" in pay["token_sinks"]
