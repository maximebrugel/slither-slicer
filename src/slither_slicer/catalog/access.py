"""Access-control detection — is a function's caller restricted?

Whether a sink sits in a *guarded* function is the single highest-signal fact for
an audit: an unguarded privileged write or external call is where bugs live. A
guard is a check of caller *identity*, detected two ways:

- a **modifier** whose code (transitively, through functions it calls — OZ
  ``onlyOwner`` delegates to ``_checkOwner()``) reads ``msg.sender``/``tx.origin``, or
- an in-body ``require``/``assert`` whose condition actually *checks* the caller:
  an equality comparison against it, a boolean allowlist lookup indexed by it, or
  a checker call taking it as an argument.

Merely *reading* the caller does not count — ``require(balances[msg.sender] >=
amount)`` is a solvency check anyone with a balance passes, and ``nonReentrant``
reads only a lock. Counting those (as Slither's broader ``is_protected``
heuristic does) would mark every ERC20 ``transfer`` guarded and silently
suppress the unguarded-sink headline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.core.declarations import SolidityVariableComposed
from slither.slithir.operations import (
    Binary,
    BinaryType,
    HighLevelCall,
    Index,
    InternalCall,
    SolidityCall,
)

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Function

_CALLER_VARS = {"msg.sender", "tx.origin"}

_IDENTITY_COMPARISONS = (BinaryType.EQUAL, BinaryType.NOT_EQUAL)


def _is_caller_var(v) -> bool:
    return isinstance(v, SolidityVariableComposed) and str(v) in _CALLER_VARS


def is_caller_check(node: Node) -> bool:
    """True if ``node`` is a ``require``/``assert`` whose condition checks the
    caller's *identity* (see module docstring) — not one that merely reads it."""
    has_require = any(
        isinstance(op, SolidityCall) and op.function.name.startswith(("require(", "assert("))
        for op in node.irs_ssa
    )
    if not has_require:
        return False
    for op in node.irs_ssa:
        # msg.sender == owner / msg.sender != attacker
        if isinstance(op, Binary) and op.type in _IDENTITY_COMPARISONS:
            if any(_is_caller_var(v) for v in op.read):
                return True
        # isOperator[msg.sender] — a boolean allowlist lookup
        if isinstance(op, Index):
            reads = list(op.read)
            if (
                len(reads) >= 2
                and _is_caller_var(reads[1])
                and str(getattr(op.lvalue, "type", "")) == "bool"
            ):
                return True
        # hasRole(ADMIN, msg.sender) / acl.check(msg.sender)
        if isinstance(op, (InternalCall, HighLevelCall)):
            if any(_is_caller_var(a) for a in (op.arguments or [])):
                return True
    return False


def caller_check_nodes(function: Function) -> list[Node]:
    """All in-body caller-identity check nodes of ``function``."""
    return [n for n in function.nodes if is_caller_check(n)]


def modifier_restricts_caller(modifier: Function) -> bool:
    """True if ``modifier`` reads caller identity — directly or via a function
    it calls (OZ ``onlyOwner`` delegates to ``_checkOwner()``).

    A bare "has a modifier" test is the wrong signal: ``nonReentrant`` /
    ``whenNotPaused`` read only state and restrict nothing about the caller.
    """
    try:
        read = modifier.all_solidity_variables_read()
    except Exception:
        return False
    return any(str(v) in _CALLER_VARS for v in read)


def is_guarded(function: Function) -> bool:
    """True if ``function`` restricts who may call it (see module docstring)."""
    if getattr(function, "is_constructor", False):
        return True  # deployer-only
    if any(modifier_restricts_caller(m) for m in getattr(function, "modifiers", [])):
        return True
    return bool(caller_check_nodes(function))
