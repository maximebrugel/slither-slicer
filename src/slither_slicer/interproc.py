"""Call-graph stitching: actual <-> formal mapping for one-level descent.

v1 descends exactly one level through the call graph, and only into *internal*
callees that resolve within the same contract / inheritance tree. ``HighLevelCall``
to external contracts is an opaque boundary (handled in :mod:`slicer`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.core.declarations import Contract, Function
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.slithir.operations import HighLevelCall, InternalCall, LibraryCall

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.slithir.operations import Operation

# How many call boundaries a single trace may cross. v1 = 1.
MAX_BOUNDARY_CROSSINGS = 1

# Cross-contract descent is a separate, opt-in axis (different msg.sender, different
# storage, runtime address may differ from the static type) — its own budget.
MAX_CROSS_CONTRACT_CROSSINGS = 1


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


def is_cross_contract_call(op: Operation) -> bool:
    """A call to another contract we *may* descend into when ``cross_contract`` is
    enabled: a true external ``HighLevelCall`` (a ``LibraryCall`` is already
    in-scope and handled by ``is_descendable_call``). ``delegatecall`` is a
    ``LowLevelCall``, never a ``HighLevelCall``, so it is excluded here."""
    return isinstance(op, HighLevelCall) and not isinstance(op, LibraryCall)


def _implementers(decl: Contract, sig: str) -> list[Function]:
    """Concrete, implemented functions matching ``sig`` on ``decl`` or any contract
    that derives from it (the case where ``decl`` is an interface / abstract)."""
    out: list[Function] = []
    for c in [decl, *decl.derived_contracts]:
        if c.is_interface or getattr(c, "is_abstract", False):
            continue
        fn = c.get_function_from_signature(sig)
        if fn is not None and getattr(fn, "is_implemented", False):
            out.append(fn)
    return out


def resolve_high_level_target(op: Operation) -> tuple[Function | None, str | None]:
    """Resolve an external ``HighLevelCall`` to a single concrete in-scope callee,
    or explain why it must stay opaque.

    Returns ``(function, None)`` when the static destination type resolves to
    exactly one implemented function, else ``(None, note)`` where ``note`` is the
    reason suffix (``cross-contract-ambiguous`` / ``-no-impl`` / ``-unresolved``).
    The runtime address may differ from the static type (proxies / injected
    mocks) — this is a static over-approximation the caller records as a note.
    """
    callee = getattr(op, "function", None)
    # Concrete case: op.function already names an implemented function on a real
    # (non-interface) contract — Slither resolved it for us.
    if (
        isinstance(callee, Function)
        and getattr(callee, "is_implemented", False)
        and getattr(callee, "contract", None) is not None
        and not callee.contract.is_interface
    ):
        return callee, None
    # Interface case: op.function is the (unimplemented) interface stub. Resolve
    # through the destination's declared type and its implementers.
    if not isinstance(callee, Function):
        return None, "cross-contract-unresolved"
    dest = getattr(op, "destination", None)
    dtype = getattr(dest, "type", None)
    if not isinstance(dtype, UserDefinedType) or not isinstance(dtype.type, Contract):
        return None, "cross-contract-unresolved"
    decl = dtype.type
    impls = _implementers(decl, callee.full_name)
    if len(impls) == 1:
        return impls[0], None
    if len(impls) > 1:
        return None, f"cross-contract-ambiguous:{decl.name}:{len(impls)}-impls"
    return None, f"cross-contract-no-impl:{decl.name}"


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
    """All in-scope internal callsites that invoke ``callee``: ``(caller, node, op)``.

    Inherited-inclusive: a caller declared in a base contract is live code of
    the derived contract, so ascent must climb into it too.
    """
    out = []
    for caller in contract.functions_and_modifiers:
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
