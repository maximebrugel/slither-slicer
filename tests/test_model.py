"""Model + output-schema tests.

The JSON schema is the contract between the slicer and the Phase 3 retrieval
tools, so it is asserted explicitly. Every node must also carry a byte-accurate
``SourceRef`` — the agent must always be able to reach real bytes.
"""

from __future__ import annotations

import json

REQUIRED_TOP_LEVEL = {
    "criterion",
    "guarded",
    "state_write_after_external_call",
    "storage_writers",
    "functions_touched",
    "entry_points",
    "state_vars_read",
    "state_vars_written",
    "state_var_types",
    "external_calls",
    "calls",
    "events_emitted",
    "notes",
    "nodes",
}
REQUIRED_NODE_KEYS = {"node_id", "function", "ntype", "ir", "reason", "source"}
REQUIRED_SOURCE_KEYS = {"filename", "start", "length", "lines", "code"}


def test_json_schema(reentrancy):
    s = reentrancy.slice_all_sinks("Reentrancy")[0]
    blob = s.to_json()
    assert set(blob.keys()) == REQUIRED_TOP_LEVEL
    # round-trips through json
    assert json.loads(json.dumps(blob)) == blob

    crit = blob["criterion"]
    assert set(crit.keys()) == {"function", "variable", "direction", "origin"}
    assert crit["direction"] in ("BACKWARD", "FORWARD")

    for node in blob["nodes"]:
        assert set(node.keys()) == REQUIRED_NODE_KEYS
        assert set(node["source"].keys()) == REQUIRED_SOURCE_KEYS


def test_source_ref_is_byte_accurate(reentrancy):
    """Every node's recorded code must equal the exact bytes at its offset."""
    s = next(
        x
        for x in reentrancy.slice_all_sinks("Reentrancy")
        if x.criterion.origin == "sink:ether_transfer"
    )
    for node in s.nodes:
        src = node.source
        with open(src.filename, "rb") as fh:
            fh.seek(src.start)
            raw = fh.read(src.length).decode("utf-8")
        assert raw == src.code
        assert src.lines  # 1-indexed line list is populated


def _ether_sink(slicer, contract):
    return next(
        x
        for x in slicer.slice_all_sinks(contract)
        if x.criterion.origin == "sink:ether_transfer"
    )


def test_max_nodes_is_noop_when_unset(access_control):
    s = _ether_sink(access_control, "AccessControl")
    assert s.to_json() == s.to_json(max_nodes=None)
    assert not any(n.startswith("truncated:") for n in s.to_json()["notes"])


def test_max_nodes_truncates_supporting_node_and_notes(reentrancy):
    """The reentrancy ether sink has 2 guards (control-dep + criterion) and one
    supporting data-dep. max_nodes=2 drops the data-dep and keeps both guards."""
    s = _ether_sink(reentrancy, "Reentrancy")
    total = len(s.nodes)
    blob = s.to_json(max_nodes=2)
    assert len(blob["nodes"]) == 2
    assert f"truncated:2-of-{total}-nodes" in blob["notes"]
    reasons = {n["reason"] for n in blob["nodes"]}
    assert "data-dep" not in reasons  # the supporting node was dropped
    assert "criterion" in reasons


def test_max_nodes_never_drops_a_guard(access_control):
    """With max_nodes=1 the onlyOwner modifier guard must still survive — guards
    are the audit payload, so the budget is exceeded rather than a guard dropped."""
    s = _ether_sink(access_control, "AccessControl")
    blob = s.to_json(max_nodes=1)
    reasons = {n["reason"] for n in blob["nodes"]}
    assert "modifier-guard" in reasons
    assert len(blob["nodes"]) > 1  # guards alone exceed the cap
    assert any(n.startswith("truncated:") for n in blob["notes"])


def test_to_source_reconstruction(reentrancy):
    s = next(
        x
        for x in reentrancy.slice_all_sinks("Reentrancy")
        if x.criterion.origin == "sink:ether_transfer"
    )
    text = s.to_source()
    assert "balances[msg.sender]" in text
    assert "call{value: amount}" in text
