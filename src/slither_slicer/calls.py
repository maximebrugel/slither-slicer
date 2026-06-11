"""Classify a SlithIR call operation.

A flat ``external_calls`` string list conflates three very different things: a
trusted in-scope library call we descended into, a real opaque call to another
contract, and a ``delegatecall``. The agent needs them distinguished — only the
opaque ones are boundaries; the library ones are part of the program we *did*
follow. This module is the single place that classification lives, used by both
the slicer (slice metadata) and the catalog.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.slithir.operations import (
    HighLevelCall,
    InternalCall,
    LibraryCall,
    LowLevelCall,
)

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.slithir.operations import Operation

# Call kinds that are opaque boundaries — code we cannot see and do not descend
# into. Everything else is in-scope.
OPAQUE_KINDS = frozenset({"external", "delegatecall", "low_level"})


def is_opaque_kind(kind: str) -> bool:
    return kind in OPAQUE_KINDS


def _location(node: Node) -> str:
    sm = node.source_mapping
    line = sm.lines[0] if sm.lines else 0
    return f"{sm.filename.short}:{line}"


def classify_call(op: Operation, node: Node) -> dict | None:
    """Classify ``op`` as a call, or return ``None`` if it is not one of interest.

    ``kind`` is one of ``library`` / ``internal`` (in-scope, descended) or
    ``external`` / ``delegatecall`` / ``low_level`` (opaque boundaries). Solidity
    builtins (``require``/``keccak256``/…) and events are intentionally excluded.
    """
    # LibraryCall is a subclass of HighLevelCall — check it first.
    if isinstance(op, LibraryCall):
        kind, in_scope = "library", True
        target = op.function.canonical_name if op.function is not None else str(op.destination)
    elif isinstance(op, InternalCall):
        if op.is_modifier_call:
            return None
        kind, in_scope = "internal", True
        target = op.function.canonical_name if op.function is not None else None
    elif isinstance(op, LowLevelCall):
        fname = str(op.function_name)
        kind = "delegatecall" if fname == "delegatecall" else "low_level"
        in_scope = False
        target = str(op.destination)
    elif isinstance(op, HighLevelCall):
        kind, in_scope = "external", False
        target = str(op.destination)
    else:
        return None

    expr = str(op.expression) if getattr(op, "expression", None) is not None else str(op)
    return {
        "expr": expr,
        "kind": kind,
        "target": target,
        "in_scope": in_scope,
        "location": _location(node),
    }
