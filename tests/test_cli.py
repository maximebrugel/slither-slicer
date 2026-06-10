"""CLI smoke tests + a robustness sweep across every fixture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slither_slicer.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_sinks_json(tmp_path, capsys):
    out = tmp_path / "sinks.json"
    project = str(FIXTURES / "Reentrancy.sol")
    args = [project, "--contract", "Reentrancy", "--sinks", "--json", str(out)]
    rc = main(args)
    assert rc == 0
    data = json.loads(out.read_text())
    assert isinstance(data, list) and data
    assert all("nodes" in s for s in data)


def test_cli_explicit_backward(capsys):
    rc = main(
        [
            str(FIXTURES / "AccessControl.sol"),
            "--function",
            "AccessControl.withdraw(uint256)",
            "--var",
            "amount",
            "--backward",
        ]
    )
    assert rc == 0
    blob = json.loads(capsys.readouterr().out)
    assert blob["criterion"]["direction"] == "BACKWARD"


def test_cli_access_control(capsys):
    rc = main([str(FIXTURES / "AccessControl.sol"), "--access-control", "AccessControl"])
    assert rc == 0
    slices = json.loads(capsys.readouterr().out)
    assert isinstance(slices, list)
    all_nodes = [n for s in slices for n in s["nodes"]]
    assert any(n["function"] == "AccessControl.onlyOwner()" for n in all_nodes)


@pytest.mark.parametrize(
    "fixture,contract",
    [
        ("AccessControl.sol", "AccessControl"),
        ("Reentrancy.sol", "Reentrancy"),
        ("Interproc.sol", "Interproc"),
        ("TaintedIndex.sol", "TaintedIndex"),
    ],
)
def test_robustness_all_sinks_produce_valid_json(fixture, contract):
    """Every fixture must compile, slice every sink, and emit valid JSON without
    crashing — the robustness contract a real ScaBench project would also have
    to satisfy."""
    from slither_slicer import Slicer

    sl = Slicer(str(FIXTURES / fixture))
    for s in sl.slice_all_sinks(contract):
        blob = s.to_json()
        json.dumps(blob)  # serialisable
        assert "nodes" in blob
