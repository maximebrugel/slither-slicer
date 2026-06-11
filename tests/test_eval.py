"""Vulnerability eval harness.

End-to-end assertions that the slicer surfaces the right audit signal on a corpus
of classic vulnerable patterns — beyond unit fixtures, this exercises the public
API (audit_overview, slice_all_sinks, access_control_of) the way an agent would,
and locks in the security semantics. Table-driven so the corpus grows easily.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from slither_slicer import Slicer

EVAL = Path(__file__).parent / "eval"


def _slicer(name: str) -> Slicer:
    return Slicer(str(EVAL / name))


def _overview(sl: Slicer, contract: str) -> dict:
    return {r["function"]: r for r in sl.audit_overview(contract)}


def _origins_for(sl: Slicer, contract: str, fn_contains: str) -> set[str]:
    return {
        s.criterion.origin
        for s in sl.slice_all_sinks(contract)
        if fn_contains in s.criterion.function_name
    }


# --- reentrancy: state write after the external call ------------------------
def test_reentrancy_cei_violation():
    sl = _slicer("Reentrancy.sol")
    w = _overview(sl, "VulnerableBank")["VulnerableBank.withdraw()"]
    assert w["state_write_after_external_call"] is True
    assert w["guarded"] is False
    assert "sink:ether_transfer" in w["sink_origins"]


# --- unprotected selfdestruct ------------------------------------------------
def test_unprotected_selfdestruct():
    sl = _slicer("UnprotectedSelfdestruct.sol")
    kill = _overview(sl, "Wallet")["Wallet.kill()"]
    assert "sink:selfdestruct" in kill["sink_origins"]
    assert kill["guarded"] is False


# --- tx.origin authentication is phishable ----------------------------------
def test_tx_origin_auth_guard_uses_tx_origin():
    sl = _slicer("TxOriginAuth.sol")
    # the function is "guarded", but the guard depends on tx.origin — the bug
    ac = sl.access_control_of("Phishable.withdraw(address)")
    assert any("tx.origin" in ir for n in ac.nodes for ir in n.ir)


# --- arbitrary external call (attacker-controlled target) -------------------
def test_arbitrary_call_target_is_parameter():
    sl = _slicer("ArbitraryCall.sol")
    assert "sink:arbitrary_call" in _origins_for(sl, "Forwarder", "forward")


# --- missing access control on privileged setters ---------------------------
def test_missing_access_control_distinguishes_guarded():
    sl = _slicer("MissingAccessControl.sol")
    ov = _overview(sl, "Config")
    # the buggy setters are unguarded privileged writes
    assert ov["Config.setFee(uint256)"]["guarded"] is False
    assert ov["Config.setTreasury(address)"]["guarded"] is False
    assert "sink:state_write" in ov["Config.setFee(uint256)"]["sink_origins"]
    # the correctly-guarded one is distinguished
    assert ov["Config.setOwner(address)"]["guarded"] is True


# --- arbitrary delegatecall (storage-context takeover) ----------------------
def test_arbitrary_delegatecall():
    sl = _slicer("ArbitraryDelegatecall.sol")
    ex = _overview(sl, "Proxy")["Proxy.execute(address,bytes)"]
    assert "sink:delegatecall" in ex["sink_origins"]
    assert ex["guarded"] is False


# --- corpus robustness: every eval contract slices without crashing ---------
@pytest.mark.parametrize(
    "name,contract",
    [
        ("Reentrancy.sol", "VulnerableBank"),
        ("UnprotectedSelfdestruct.sol", "Wallet"),
        ("TxOriginAuth.sol", "Phishable"),
        ("ArbitraryCall.sol", "Forwarder"),
        ("MissingAccessControl.sol", "Config"),
        ("ArbitraryDelegatecall.sol", "Proxy"),
    ],
)
def test_corpus_slices_cleanly(name, contract):
    sl = _slicer(name)
    sinks = sl.slice_all_sinks(contract)
    assert sinks, f"{name} produced no sinks"
    for s in sinks:
        blob = s.to_json()  # must serialize without error
        assert blob["nodes"], f"empty slice for {s.criterion.origin} in {name}"
