"""`check_state_invariant` (opt-in agent v2) behaviour.

As in test_agent.py, the LLM call is not golden-testable, so we test the
deterministic scaffolding and the two completeness invariants that make this tool
safe: writer-coverage (every writer in the complete set is judged) and
evidence-containment (no finding cites a node the engine never produced). A fake
`kimi` stands in for the real CLI; verdicts are built from the *real* writer
node_ids so the tests don't hard-code Slither's node numbering.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from slither_slicer.agent import tools

FIXTURES = Path(__file__).parent / "fixtures"
VAULT = str(FIXTURES / "InvariantVault.sol")


# --------------------------------------------------------------------------- #
# fake kimi (mirrors test_agent.py)
# --------------------------------------------------------------------------- #
def _install_fake_kimi(tmp_path, monkeypatch, *, stdout="", stderr="", code=0):
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    script = bindir / "kimi"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.stdout.write({stdout!r})\n"
        f"sys.stderr.write({stderr!r})\n"
        f"sys.exit({code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("SLITHER_SLICER_AGENT_ALLOW_SHELL", "1")  # installing implies intent to run
    return bindir


def _stream(final_verdict: dict, *, tool_name="mcp__slicer__state_var_xref") -> str:
    lines = [
        json.dumps(
            {
                "role": "assistant",
                "content": "Pulling the related writer set.",
                "tool_calls": [
                    {"type": "function", "id": "tc_1",
                     "function": {"name": tool_name, "arguments": "{}"}}
                ],
            }
        ),
        json.dumps({"role": "tool", "tool_call_id": "tc_1", "content": "…writers…"}),
    ]
    fenced = "```json\n" + json.dumps(final_verdict) + "\n```"
    lines.append(json.dumps({"role": "assistant", "content": fenced}))
    return "\n".join(lines) + "\n"


def _writer_ids():
    facts = tools._invariant_seed_facts(VAULT, "InvariantVault", "totalSupply", ("balances",))
    return [w["node_id"] for w in facts["writers"]]


def _src(node_id):
    return {"filename": "x.sol", "start": 0, "length": 1, "lines": [1], "code": "x"}


def _verdict(writer_ids, *, status="checked", findings=None, dispositions=None):
    disp = (
        dispositions
        if dispositions is not None
        else [{"node_id": n, "disposition": "holds", "invariant_id": "inv1"} for n in writer_ids]
    )
    return {
        "tool": "check_state_invariant",
        "contract": "InvariantVault",
        "state_var": "totalSupply",
        "status": status,
        "hypothesized_invariants": (
            []
            if status == "invariant-unknown"
            else [{"id": "inv1", "predicate": "totalSupply == sum(balances)",
                   "inferred_from": "name", "kind": "relational", "confidence": "high"}]
        ),
        "writer_dispositions": disp,
        "findings": findings or [],
        "unresolved": [],
        "confidence": "medium",
    }


# --------------------------------------------------------------------------- #
# deterministic scaffolding (no kimi)
# --------------------------------------------------------------------------- #
def test_dry_run_seed_carries_complete_writer_set_and_contract():
    out = tools.check_state_invariant(
        "InvariantVault", "totalSupply", VAULT, related=["balances"], dry_run=True
    )
    assert out["dry_run"] is True
    seed = out["seed_prompt"]
    for anchor in ("COMPLETENESS CONTRACT", "writer_dispositions", "balances", "totalSupply"):
        assert anchor in seed
    for nid in _writer_ids():  # the exhaustive writer set must be in the seed
        assert nid in seed


def test_same_type_siblings_auto_seeded_excluding_constants():
    # balances and debts are both mapping(address=>uint256); CAP (constant) excluded
    facts = tools._invariant_seed_facts(VAULT, "InvariantVault", "balances", ())
    assert "debts" in facts["related"]
    assert "CAP" not in facts["related"]


def test_synthetic_constant_writer_filtered_to_no_writers():
    # CAP's only "writer" is Slither's slitherConstructorConstantVariables synthetic fn
    facts = tools._invariant_seed_facts(VAULT, "InvariantVault", "CAP", ())
    assert facts["writers"] == []
    out = tools.check_state_invariant("InvariantVault", "CAP", VAULT)  # before any gate
    assert out["status"] == "no-writers"


def test_completeness_caveat_set_when_contract_has_assembly():
    asm = tools._invariant_seed_facts(VAULT, "AssemblyVault", "total", ())
    assert asm["completeness_caveat"] and "assembly" in asm["completeness_caveat"].lower()
    clean = tools._invariant_seed_facts(VAULT, "InvariantVault", "totalSupply", ())
    assert clean["completeness_caveat"] is None


def test_unknown_variable_is_error():
    out = tools.check_state_invariant("InvariantVault", "doesNotExist", VAULT, dry_run=True)
    assert out["status"] == "error"


# --------------------------------------------------------------------------- #
# fail-closed gate
# --------------------------------------------------------------------------- #
def test_run_blocked_without_optin(monkeypatch):
    monkeypatch.delenv("SLITHER_SLICER_AGENT_ALLOW_SHELL", raising=False)
    out = tools.check_state_invariant("InvariantVault", "totalSupply", VAULT)
    assert out["status"] == "blocked"
    assert "SLITHER_SLICER_AGENT_ALLOW_SHELL" in out["note"]
    # dry_run still works under the gate
    assert tools.check_state_invariant(
        "InvariantVault", "totalSupply", VAULT, dry_run=True
    )["dry_run"]


# --------------------------------------------------------------------------- #
# end-to-end with a fake kimi: the two completeness invariants
# --------------------------------------------------------------------------- #
def test_full_coverage_violation_passes_through(tmp_path, monkeypatch):
    wids = _writer_ids()
    bad = next(n for n in wids if "badMint" in n)
    finding = {
        "kind": "invariant-violation", "invariant_id": "inv1", "severity": "high",
        "writer_node_id": bad, "attacker_reachable": True,
        "claim": "badMint bumps totalSupply without balances",
        "evidence": [{"node_id": bad, "source_ref": _src(bad), "role": "writer"}],
    }
    _install_fake_kimi(tmp_path, monkeypatch, stdout=_stream(_verdict(wids, findings=[finding])))
    out = tools.check_state_invariant("InvariantVault", "totalSupply", VAULT, related=["balances"])
    assert out["status"] == "checked"
    assert out["findings"][0]["kind"] == "invariant-violation"
    assert out["completeness_caveat"] is None  # stamped from facts
    assert out["tools_used"] == ["mcp__slicer__state_var_xref"]


def test_coverage_hard_fail_on_missing_disposition(tmp_path, monkeypatch):
    wids = _writer_ids()
    partial = [{"node_id": n, "disposition": "holds"} for n in wids[:-1]]  # drop one
    _install_fake_kimi(tmp_path, monkeypatch, stdout=_stream(_verdict(wids, dispositions=partial)))
    out = tools.check_state_invariant("InvariantVault", "totalSupply", VAULT)
    assert out["status"] == "error"
    assert "coverage" in out["note"].lower()


def test_hallucinated_site_rejected(tmp_path, monkeypatch):
    wids = _writer_ids()
    ghost = "InvariantVault.ghost()#99"  # not a real writer/reader node
    finding = {
        "kind": "invariant-violation", "invariant_id": "inv1", "severity": "high",
        "writer_node_id": ghost, "attacker_reachable": True, "claim": "hallucinated",
        "evidence": [{"node_id": ghost, "source_ref": _src(ghost)}],
    }
    _install_fake_kimi(tmp_path, monkeypatch, stdout=_stream(_verdict(wids, findings=[finding])))
    out = tools.check_state_invariant("InvariantVault", "totalSupply", VAULT)
    assert out["status"] == "error"
    assert "hallucinated" in out["note"].lower() or "outside" in out["note"].lower()


def test_abstain_passes_through_untouched(tmp_path, monkeypatch):
    # invariant-unknown: empty dispositions allowed (coverage skipped), empty findings
    v = _verdict([], status="invariant-unknown")
    _install_fake_kimi(tmp_path, monkeypatch, stdout=_stream(v))
    out = tools.check_state_invariant("InvariantVault", "totalSupply", VAULT)
    assert out["status"] == "invariant-unknown"
    assert out["findings"] == []


def test_caveat_stamped_on_assembly_contract(tmp_path, monkeypatch):
    facts = tools._invariant_seed_facts(VAULT, "AssemblyVault", "total", ())
    wids = [w["node_id"] for w in facts["writers"]]
    v = {
        "tool": "check_state_invariant", "contract": "AssemblyVault", "state_var": "total",
        "status": "checked",
        "hypothesized_invariants": [
            {"id": "i", "predicate": "p", "kind": "bound", "confidence": "low"}
        ],
        "writer_dispositions": [{"node_id": n, "disposition": "holds"} for n in wids],
        "findings": [], "unresolved": [], "confidence": "low",
    }
    _install_fake_kimi(tmp_path, monkeypatch, stdout=_stream(v))
    out = tools.check_state_invariant("AssemblyVault", "total", VAULT)
    assert out["status"] == "checked"
    assert out["completeness_caveat"] and "assembly" in out["completeness_caveat"].lower()


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #
def test_register_adds_check_state_invariant():
    import asyncio

    from mcp.server.fastmcp import FastMCP

    from slither_slicer.agent import register_agent_tools

    server = FastMCP("test")
    register_agent_tools(server)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "check_state_invariant" in names


# --------------------------------------------------------------------------- #
# optional live smoke
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(
    os.environ.get("KIMI_LIVE") != "1", reason="live Kimi run; needs login + tokens"
)
def test_live_relational_violation(monkeypatch):
    monkeypatch.setenv("SLITHER_SLICER_AGENT_ALLOW_SHELL", "1")
    out = tools.check_state_invariant(
        "InvariantVault", "totalSupply", VAULT, related=["balances"]
    )
    assert out.get("status") in {"checked", "partial"}
    # a faithful run dispositions every writer and should flag the relational divergence
    assert out.get("writer_dispositions")
    assert any(i.get("kind") == "relational" for i in out.get("hypothesized_invariants", []))
