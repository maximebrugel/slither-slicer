"""SSA def-use -> data-dependence edges.

We work in SlithIR SSA form: each SSA use has exactly one reaching definition
(or a ``Phi`` that merges several). That makes def-use unambiguous, which is the
whole point of slicing over SSA rather than raw expressions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.slithir.operations import Index, Member, Phi
from slither.slithir.operations.operation import Operation
from slither.slithir.variables import Constant, ReferenceVariable

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Function

# An SSA "variable" is anything SlithIR can read/write. We key def/use maps by
# Python object identity (id), which Slither keeps stable per SSA version.
DefSite = tuple["Node", Operation]


def op_defs(op: Operation) -> list:
    """The SSA variables defined (written) by ``op``."""
    lvalue = getattr(op, "lvalue", None)
    if lvalue is None:
        return []
    return [lvalue]


def op_reads(op: Operation) -> list:
    """The SSA variables read by ``op``.

    ``Phi`` merges its operands (``rvalues``) rather than ``read``; everything
    else exposes its uses through ``read``. ``InternalCall`` (and friends) carry
    their actual arguments in ``arguments`` *separately* from ``read`` — without
    folding those in, taint never flows across a call. Constants are dropped —
    they are never definitions, so chasing them is pointless.
    """
    if isinstance(op, Phi):
        raw = list(op.rvalues)
    else:
        raw = list(op.read)
        seen = {id(v) for v in raw}
        for arg in getattr(op, "arguments", None) or []:
            if id(arg) not in seen:
                seen.add(id(arg))
                raw.append(arg)
    return [v for v in raw if not isinstance(v, Constant)]


def build_def_map(function: Function) -> dict[int, DefSite]:
    """Map ``id(ssa_var) -> (node, op)`` for every SSA definition in ``function``."""
    def_map: dict[int, DefSite] = {}
    for node in function.nodes:
        for op in node.irs_ssa:
            for var in op_defs(op):
                def_map[id(var)] = (node, op)
    return def_map


def build_use_map(function: Function) -> dict[int, list[DefSite]]:
    """Map ``id(ssa_var) -> [(node, op), ...]`` for every SSA use in ``function``."""
    use_map: dict[int, list[DefSite]] = {}
    for node in function.nodes:
        for op in node.irs_ssa:
            for var in op_reads(op):
                use_map.setdefault(id(var), []).append((node, op))
    return use_map


def imprecise_index(op: Operation):
    """If ``op`` is a mapping/array/struct access through a non-constant index,
    return ``(base_var, index_var)``; otherwise ``None``.

    These are the aliasing cases SlithIR cannot resolve to a single concrete
    storage slot. We attach the dependence to the whole base and flag it rather
    than silently pretending the access is precise.
    """
    if not isinstance(op, (Index, Member)):
        return None
    reads = list(op.read)
    if len(reads) < 2:
        return None
    base, index = reads[0], reads[1]
    if isinstance(index, Constant):
        return None
    return base, index


def base_of_reference(var):
    """Resolve a SlithIR ``ReferenceVariable`` to the underlying storage/local it
    points to (best effort). Returns ``var`` unchanged if it is not a reference.
    """
    seen = set()
    while isinstance(var, ReferenceVariable):
        if id(var) in seen:
            break
        seen.add(id(var))
        nxt = getattr(var, "points_to_origin", None) or getattr(var, "points_to", None)
        if nxt is None:
            break
        var = nxt
    return var
