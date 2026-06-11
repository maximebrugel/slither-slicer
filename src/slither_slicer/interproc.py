"""Call-graph stitching: actual <-> formal mapping for one-level descent.

v1 descends exactly one level through the call graph, and only into *internal*
callees that resolve within the same contract / inheritance tree. ``HighLevelCall``
to external contracts is an opaque boundary (handled in :mod:`slicer`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.slithir.operations import InternalCall, LibraryCall

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract, Function
    from slither.slithir.operations import Operation

# How many call boundaries a single trace may cross. v1 = 1.
MAX_BOUNDARY_CROSSINGS = 1


def is_descendable_call(op: Operation) -> bool:
    """True for calls we can resolve to in-scope code and descend into.

    ``LibraryCall`` is a subclass of ``HighLevelCall`` but, like an
    ``InternalCall``, targets resolvable in-scope code (``using Lib for T`` /
    ``Lib.fn(...)``) — so it is stitched, not treated as an opaque boundary.
    Modifier invocations are handled separately (always pulled in as guards).
    """
    if isinstance(op, LibraryCall):
        return op.function is not None
    if isinstance(op, InternalCall):
        return not op.is_modifier_call and op.function is not None
    return False


def resolved_internal_calls(function: Function) -> list[tuple[Node, InternalCall, Function]]:
    """Every resolved, non-modifier *internal* call in ``function``:
    ``(node, op, callee)``.

    Internal calls only — this backs ``callsites_of`` (used for **ascent**),
    where climbing out of a library function to all its callsites would explode.
    We descend *into* libraries but never ascend *out* of them.
    """
    out = []
    for node in function.nodes:
        for op in node.irs_ssa:
            if isinstance(op, InternalCall) and not op.is_modifier_call and op.function is not None:
                out.append((node, op, op.function))
    return out


def resolved_library_calls(function: Function) -> list[tuple[Node, LibraryCall, Function]]:
    """Every resolved library call in ``function``: ``(node, op, callee)``."""
    out = []
    for node in function.nodes:
        for op in node.irs_ssa:
            if isinstance(op, LibraryCall) and op.function is not None:
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
