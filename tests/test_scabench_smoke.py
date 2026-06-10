"""ScaBench robustness smoke test.

Point ``SCABENCH_PROJECT`` at a real ScaBench project to exercise the slicer
across real-world Solidity (many solc versions, larger contracts). Correctness
is *not* asserted here — only that the slicer compiles the project, slices every
sink in every contract, and emits valid JSON without crashing.

    SCABENCH_PROJECT=/path/to/project uv run pytest tests/test_scabench_smoke.py
"""

from __future__ import annotations

import json
import os

import pytest

_PROJECT = os.environ.get("SCABENCH_PROJECT")


@pytest.mark.skipif(not _PROJECT, reason="set SCABENCH_PROJECT to run")
def test_scabench_project_slices_without_crashing():
    from slither_slicer import Slicer

    sl = Slicer(_PROJECT)
    total = 0
    for contract in sl._loader.contracts:
        for s in sl.slice_all_sinks(contract.name):
            json.dumps(s.to_json())  # must serialise
            total += 1
    # robustness, not correctness: we just need to have survived the sweep
    assert total >= 0
