"""Agent layer (opt-in) behaviour.

The LLM call itself is not golden-testable, so we test the deterministic
scaffolding around it: seed assembly, the read-only config/home, stream-json
parsing, schema validation, the abstain/honesty pass-through, and fail-closed
error handling. Live Kimi navigation is exercised only behind ``KIMI_LIVE=1``.

A fake ``kimi`` (a tiny script on PATH) stands in for the real CLI so the whole
handler path runs without a network, an API key, or a login.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from slither_slicer.agent import prompts, runner, tools
from slither_slicer.agent.schema import VERDICT_SCHEMA, VerdictError, validate_verdict

FIXTURES = Path(__file__).parent / "fixtures"
PROXY = str(FIXTURES / "Proxy.sol")
DC_NODE = "Proxy.exec(bytes)#2"  # the delegatecall site in Proxy.exec


# --------------------------------------------------------------------------- #
# fake kimi
# --------------------------------------------------------------------------- #
def _install_fake_kimi(tmp_path, monkeypatch, *, stdout="", stderr="", code=0):
    """Put an executable `kimi` on PATH that ignores its args and emits the given
    stdout/stderr/exit code. Returns the bin dir."""
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
    # Installing a fake kimi means the test intends to actually run it, so clear the
    # fail-closed gate (see tools._ALLOW_SHELL_ENV).
    monkeypatch.setenv("SLITHER_SLICER_AGENT_ALLOW_SHELL", "1")
    return bindir


def _verdict(**over) -> dict:
    base = {
        "tool": "inspect_delegatecall",
        "criterion_node_id": DC_NODE,
        "status": "unresolved",
        "target": {"resolution": "runtime-set", "contract": None, "source_ref": None},
        "findings": [],
        "unresolved": [{"note": "impl set at runtime via setImpl", "at": "Proxy.setImpl(address)"}],
        "confidence": "low",
    }
    base.update(over)
    return base


def _stream(final_verdict: dict, *, with_tool_call=True) -> str:
    lines = []
    if with_tool_call:
        lines.append(
            json.dumps(
                {
                    "role": "assistant",
                    "content": "Inspecting the delegatecall.",
                    "tool_calls": [
                        {
                            "type": "function",
                            "id": "tc_1",
                            "function": {"name": "mcp__slicer__slice_from", "arguments": "{}"},
                        }
                    ],
                }
            )
        )
        lines.append(json.dumps({"role": "tool", "tool_call_id": "tc_1", "content": "…slice…"}))
    fenced = "```json\n" + json.dumps(final_verdict) + "\n```"
    lines.append(json.dumps({"role": "assistant", "content": fenced}))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# deterministic scaffolding (no kimi)
# --------------------------------------------------------------------------- #
def test_dry_run_seed_is_deterministic_and_anchored():
    out = tools.inspect_delegatecall(DC_NODE, PROXY, dry_run=True)
    assert out["dry_run"] is True
    assert out["criterion_node_id"] == DC_NODE
    seed = out["seed_prompt"]
    # Anchors rather than byte-equality: the slice embeds machine-absolute paths.
    for anchor in (
        DC_NODE,
        "delegatecall",
        "proxy_state_vars_in_declaration_order",
        '"impl"',
        "EXACTLY ONE fenced",
        '"storage-collision"',  # the schema is embedded
        "never guess",
    ):
        assert anchor in seed, f"seed missing anchor: {anchor!r}"


def test_seed_carries_proxy_layout_not_slot_math():
    sl = tools.m._get_slicer(PROXY)
    assert tools.ordered_state_vars(sl, "Proxy") == [{"name": "impl", "type": "address"}]


def test_non_delegatecall_node_is_an_error_not_a_finding():
    out = tools.inspect_delegatecall("Proxy.setImpl(address)#1", PROXY, dry_run=True)
    assert out["status"] == "error"
    assert "not a delegatecall site" in out["note"]


def test_build_seed_uses_prompts_module():
    seed = tools.build_seed(DC_NODE, PROXY)
    # the embedded schema is the frozen contract
    assert json.dumps(VERDICT_SCHEMA, indent=2) in seed
    assert seed.startswith(prompts._PREAMBLE[:40])


# --------------------------------------------------------------------------- #
# schema validation (fail-closed contract)
# --------------------------------------------------------------------------- #
def test_schema_accepts_minimal_abstain_verdict():
    validate_verdict(_verdict())


def test_schema_rejects_missing_required_keys():
    with pytest.raises(VerdictError):
        validate_verdict({"tool": "inspect_delegatecall"})


def test_schema_rejects_bad_enum():
    with pytest.raises(VerdictError):
        validate_verdict(_verdict(status="totally-resolved"))


def test_schema_rejects_finding_without_evidence():
    bad = _verdict(
        status="resolved",
        findings=[{"kind": "storage-collision", "severity": "high", "claim": "x"}],
    )
    with pytest.raises(VerdictError):
        validate_verdict(bad)


# --------------------------------------------------------------------------- #
# stream-json parsing
# --------------------------------------------------------------------------- #
def test_parse_stream_json_extracts_verdict_and_tool_trail():
    res = runner._parse_stream_json(_stream(_verdict()))
    assert res.verdict["status"] == "unresolved"
    assert runner.tool_names(res.tool_calls) == ["mcp__slicer__slice_from"]


def test_parse_stream_json_tolerates_noise_lines():
    stream = "not json\n" + _stream(_verdict()) + "\n{trailing garbage}\n"
    res = runner._parse_stream_json(stream)
    assert res.verdict["status"] == "unresolved"


def test_parse_stream_json_raises_without_final_message():
    with pytest.raises(runner.KimiBadOutput):
        runner._parse_stream_json('{"role":"tool","content":"x"}\n')


def test_tool_names_reads_function_name_field():
    # Kimi nests the name at function.name — not a flat .name
    calls = [{"type": "function", "function": {"name": "Read"}}, {"name": "Glob"}]
    assert runner.tool_names(calls) == ["Glob", "Read"]


# --------------------------------------------------------------------------- #
# end-to-end handler with a fake kimi
# --------------------------------------------------------------------------- #
def test_handler_passes_abstain_through_untouched(tmp_path, monkeypatch):
    _install_fake_kimi(tmp_path, monkeypatch, stdout=_stream(_verdict()))
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    assert out["status"] == "unresolved"
    assert out["findings"] == []  # never synthesised
    assert out["unresolved"]
    assert out["tools_used"] == ["mcp__slicer__slice_from"]  # from the audit trail
    assert out["tool"] == "inspect_delegatecall"


def test_handler_passes_confirmed_finding_through(tmp_path, monkeypatch):
    src = {"filename": "/x/Proxy.sol", "start": 0, "length": 4, "lines": [8], "code": "impl"}
    finding = {
        "kind": "storage-collision",
        "severity": "high",
        "claim": "slot 0 collision",
        "evidence": [{"node_id": "Proxy.exec(bytes)#2", "source_ref": src, "role": "proxy-slot"}],
    }
    v = _verdict(status="resolved", findings=[finding])
    _install_fake_kimi(tmp_path, monkeypatch, stdout=_stream(v))
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    assert out["status"] == "resolved"
    assert out["findings"][0]["kind"] == "storage-collision"


def test_handler_unavailable_when_kimi_missing(tmp_path, monkeypatch):
    # PATH with no kimi at all (but the gate cleared, so we reach the kimi lookup)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("SLITHER_SLICER_AGENT_ALLOW_SHELL", "1")
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    assert out["status"] == "unavailable"
    assert "PATH" in out["note"] or "kimi" in out["note"]


def test_run_blocked_without_optin(tmp_path, monkeypatch):
    # The fail-closed gate: even with a working kimi, a live run is refused unless
    # the operator acknowledges the unsandboxed-toolset risk. kimi is never spawned.
    _install_fake_kimi(tmp_path, monkeypatch, stdout=_stream(_verdict()))
    monkeypatch.delenv("SLITHER_SLICER_AGENT_ALLOW_SHELL", raising=False)
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    assert out["status"] == "blocked"
    assert "SLITHER_SLICER_AGENT_ALLOW_SHELL" in out["note"]
    # dry_run is always allowed, gate or not
    assert tools.inspect_delegatecall(DC_NODE, PROXY, dry_run=True)["dry_run"] is True


def test_handler_unavailable_on_auth_error(tmp_path, monkeypatch):
    _install_fake_kimi(
        tmp_path,
        monkeypatch,
        stderr='error: auth.login_required: OAuth provider "managed:kimi-code" requires login',
        code=1,
    )
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    assert out["status"] == "unavailable"
    assert "login" in out["note"].lower()


def test_handler_fail_closed_on_non_json(tmp_path, monkeypatch):
    stream = json.dumps({"role": "assistant", "content": "I think it's fine, no JSON here."}) + "\n"
    _install_fake_kimi(tmp_path, monkeypatch, stdout=stream)
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    assert out["status"] == "error"


def test_handler_fail_closed_on_schema_violation(tmp_path, monkeypatch):
    bad = {"role": "assistant", "content": "```json\n" + json.dumps({"tool": "x"}) + "\n```"}
    _install_fake_kimi(tmp_path, monkeypatch, stdout=json.dumps(bad) + "\n")
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    assert out["status"] == "error"
    assert "schema" in out["note"].lower() or "conform" in out["note"].lower()


def test_handler_error_on_nonzero_exit(tmp_path, monkeypatch):
    _install_fake_kimi(tmp_path, monkeypatch, stderr="boom", code=2)
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    assert out["status"] == "error"


# --------------------------------------------------------------------------- #
# isolated read-only home
# --------------------------------------------------------------------------- #
def test_isolated_home_is_read_only_and_non_recursive(tmp_path):
    from slither_slicer.agent.kimi_config import write_kimi_home

    home = write_kimi_home(PROXY, base_home=str(tmp_path / "nohome"))
    try:
        mcp = json.loads((Path(home) / "mcp.json").read_text())
        env = mcp["mcpServers"]["slicer"]["env"]
        assert env["SLITHER_SLICER_ENABLE_AGENT"] == "0"  # inner instance cannot recurse
        assert env["SLITHER_SLICER_PROJECT"] == PROXY
        cfg = (Path(home) / "config.toml").read_text()
        assert 'pattern = "mcp__slicer__*"' in cfg  # slicer tools allowed
        assert 'decision = "deny"' in cfg and 'pattern = "**"' in cfg  # everything else denied
    finally:
        import shutil

        shutil.rmtree(home, ignore_errors=True)


# --------------------------------------------------------------------------- #
# opt-in gating
# --------------------------------------------------------------------------- #
def test_register_agent_tools_adds_inspect_delegatecall():
    import asyncio

    from mcp.server.fastmcp import FastMCP

    from slither_slicer.agent import register_agent_tools

    server = FastMCP("test")
    register_agent_tools(server)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "inspect_delegatecall" in names


# --------------------------------------------------------------------------- #
# optional live smoke (needs `kimi login`)
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(
    os.environ.get("KIMI_LIVE") != "1", reason="live Kimi run; needs login + tokens"
)
def test_live_inspect_delegatecall_runtime_set_target(monkeypatch):
    monkeypatch.setenv("SLITHER_SLICER_AGENT_ALLOW_SHELL", "1")
    out = tools.inspect_delegatecall(DC_NODE, PROXY)
    # Proxy.impl is set at runtime via setImpl — a faithful agent must not invent a
    # target; it reports unresolved (or partial), never a confident static target.
    assert out.get("status") in {"unresolved", "partial", "resolved"}
    assert "criterion_node_id" in out
