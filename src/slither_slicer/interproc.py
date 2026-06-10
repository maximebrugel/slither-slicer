"""Call-graph stitching: actual <-> formal mapping for one-level descent.

v1 descends exactly one level through the call graph, and only into *internal*
callees that resolve within the same contract / inheritance tree. ``HighLevelCall``
to external contracts is an opaque boundary (handled in :mod:`slicer`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.slithir.operations import InternalCall

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract, Function

# How many call boundaries a single trace may cross. v1 = 1.
MAX_BOUNDARY_CROSSINGS = 1


def resolved_internal_calls(function: Function) -> list[tuple[Node, InternalCall, Function]]:
    """Every resolved, non-modifier internal call in ``function``:
    ``(node, op, callee)``.
    """
    out = []
    for node in function.nodes:
        for op in node.irs_ssa:
            if isinstance(op, InternalCall) and not op.is_modifier_call and op.function is not None:
                out.append((node, op, op.function))
    return out


def callsites_of(contract: Contract, callee: Function) -> list[tuple[Function, Node, InternalCall]]:
    """All in-scope internal callsites that invoke ``callee``: ``(caller, node, op)``."""
    out = []
    for caller in contract.functions_and_modifiers_declared:
        for node, op, target in resolved_internal_calls(caller):
            if target is callee:
                out.append((caller, node, op))
    return out


def actual_to_formal(op: InternalCall, callee: Function) -> list[tuple[object, object]]:
    """Pair each actual argument (SSA var at the callsite) with its formal
    parameter (the callee's declared :class:`Variable`), by position.
    """
    pairs = []
    formals = callee.parameters
    for i, actual in enumerate(op.arguments):
        if i < len(formals):
            pairs.append((actual, formals[i]))
    return pairs
