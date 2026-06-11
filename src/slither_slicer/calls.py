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

# ERC20/721 value-movement methods -> token-sink origin. Matched on the *called
# function's name* so a SafeERC20 library wrapper (``token.safeTransfer(...)``,
# which we descend into rather than treat as opaque) is recognised as value
# movement at the calling contract exactly like a raw ``token.transfer(...)``.
# This is a name heuristic: only consulted for contract/interface calls
# (HighLevelCall / LibraryCall), never internal calls.
TOKEN_SINK_ORIGINS = {
    "transfer": "sink:token_transfer",
    "transferFrom": "sink:token_transfer",
    "safeTransfer": "sink:token_transfer",
    "safeTransferFrom": "sink:token_transfer",
    "approve": "sink:token_approval",
    "safeApprove": "sink:token_approval",
    "increaseAllowance": "sink:token_approval",
    "decreaseAllowance": "sink:token_approval",
    "safeIncreaseAllowance": "sink:token_approval",
    "safeDecreaseAllowance": "sink:token_approval",
    "mint": "sink:token_supply",
    "burn": "sink:token_supply",
    "burnFrom": "sink:token_supply",
}


def is_opaque_kind(kind: str) -> bool:
    return kind in OPAQUE_KINDS


def token_sink_origin(op: Operation) -> str | None:
    """Token-flow sink origin for a call ``op``, or ``None``.

    Matched by the called function's name; the caller restricts this to
    contract/interface calls so an in-scope helper named ``transfer`` is not
    mistaken for an ERC20 movement.
    """
    func = getattr(op, "function", None)
    name = getattr(func, "name", None) if func is not None else None
    if name is None:
        return None
    return TOKEN_SINK_ORIGINS.get(name)


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

    # Cheap static annotation (always on): if an external call's destination type
    # resolves to exactly one concrete in-scope contract, name it. This is a fact,
    # not a descent — it gives the agent "this external call resolves to X.f"
    # without the assumption-laden cross-contract traversal (opt-in on the slicer).
    resolved_target = None
    if kind == "external":
        from .interproc import resolve_high_level_target

        resolved, _why = resolve_high_level_target(op)
        if resolved is not None:
            resolved_target = resolved.canonical_name

    expr = str(op.expression) if getattr(op, "expression", None) is not None else str(op)
    return {
        "expr": expr,
        "kind": kind,
        "target": target,
        "in_scope": in_scope,
        "location": _location(node),
        "resolved_target": resolved_target,
    }
