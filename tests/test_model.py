"""Model + output-schema tests.

The JSON schema is the contract between the slicer and the Phase 3 retrieval
tools, so it is asserted explicitly. Every node must also carry a byte-accurate
``SourceRef`` — the agent must always be able to reach real bytes.
"""

from __future__ import annotations

import json

REQUIRED_TOP_LEVEL = {
    "criterion",
    "functions_touched",
    "state_vars_read",
    "state_vars_written",
    "external_calls",
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


def test_to_source_reconstruction(reentrancy):
    s = next(
        x
        for x in reentrancy.slice_all_sinks("Reentrancy")
        if x.criterion.origin == "sink:ether_transfer"
    )
    text = s.to_source()
    assert "balances[msg.sender]" in text
    assert "call{value: amount}" in text
