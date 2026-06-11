"""Solidity source detectors -> forward-slice criteria.

Sources are untrusted / externally-influenced inputs. We slice *forward* from
them to find everything they can taint.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.core.declarations import SolidityVariableComposed
from slither.slithir.operations import HighLevelCall, LibraryCall

from ..criteria import Direction, SliceCriterion

if TYPE_CHECKING:
    from slither.core.declarations import Contract

_ENTRY_VISIBILITY = ("public", "external")

# Composed solidity variables we treat as untrusted/environmental sources.
_SOURCE_SOLIDITY_VARS = {
    "msg.sender",
    "msg.value",
    "tx.origin",
    "block.timestamp",
    "block.number",
}


def _crit(node, var, origin: str) -> SliceCriterion:
    return SliceCriterion(node=node, variable=var, direction=Direction.FORWARD, origin=origin)


def find_sources(contract: Contract) -> list[SliceCriterion]:
    """Return every forward-slice criterion seeded by a source in ``contract``."""
    crits: list[SliceCriterion] = []

    # Inherited-inclusive: a source read in a base contract is live code of the
    # derived contract — scanning only declared functions would hide it.
    for func in contract.functions_and_modifiers:
        # External input: parameters of public/external functions.
        if func.visibility in _ENTRY_VISIBILITY:
            entry = func.entry_point or (func.nodes[0] if func.nodes else None)
            if entry is not None:
                for param in func.parameters:
                    crits.append(_crit(entry, param, "source:parameter"))

        # One criterion per (function, composed var), seeded at the first node
        # that reads it: seed resolution collects *every* occurrence of a
        # composed variable in the function, so per-node criteria would just be
        # near-identical slices of the same taint.
        seen_composed: set[str] = set()
        for node in func.nodes:
            for op in node.irs_ssa:
                # Caller identity / call value / environment.
                for var in op.read:
                    name = str(var)
                    is_src = isinstance(var, SolidityVariableComposed) and (
                        name in _SOURCE_SOLIDITY_VARS
                    )
                    if is_src and name not in seen_composed:
                        seen_composed.add(name)
                        crits.append(_crit(node, var, _origin_for(name)))
                # Return values of *true external* calls are untrusted (oracle-ish);
                # library returns are our own trusted code, so they are excluded.
                if (
                    isinstance(op, HighLevelCall)
                    and not isinstance(op, LibraryCall)
                    and getattr(op, "lvalue", None) is not None
                ):
                    crits.append(_crit(node, op.lvalue, "source:external_return"))
    return crits


def _origin_for(name: str) -> str:
    if name in ("msg.sender", "tx.origin"):
        return "source:caller"
    if name == "msg.value":
        return "source:call_value"
    return "source:environment"
