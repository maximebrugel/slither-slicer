"""Access-control detection — is a function's caller restricted?

Whether a sink sits in a *guarded* function is the single highest-signal fact for
an audit: an unguarded privileged write or external call is where bugs live. We
detect a guard three ways and take the union, because each catches cases the
others miss:

- the function carries a **modifier** (``onlyOwner``, ``onlyRoles``, …),
- it has an in-body **caller-identity check** (``require(msg.sender == ...)`` /
  ``require(tx.origin == ...)``), or
- Slither's own ``is_protected`` heuristic flags it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.core.declarations import SolidityVariableComposed
from slither.slithir.operations import SolidityCall

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Function

_CALLER_VARS = {"msg.sender", "tx.origin"}


def is_caller_check(node: Node) -> bool:
    """True if ``node`` is a ``require``/``assert`` that reads caller identity."""
    has_require = any(
        isinstance(op, SolidityCall) and op.function.name.startswith(("require(", "assert("))
        for op in node.irs_ssa
    )
    if not has_require:
        return False
    for op in node.irs_ssa:
        for v in op.read:
            if isinstance(v, SolidityVariableComposed) and str(v) in _CALLER_VARS:
                return True
    return False


def caller_check_nodes(function: Function) -> list[Node]:
    """All in-body caller-identity check nodes of ``function``."""
    return [n for n in function.nodes if is_caller_check(n)]


def is_guarded(function: Function) -> bool:
    """True if ``function`` restricts who may call it (see module docstring)."""
    if getattr(function, "modifiers", None):
        return True
    if caller_check_nodes(function):
        return True
    try:
        return bool(function.is_protected())
    except Exception:
        return False
