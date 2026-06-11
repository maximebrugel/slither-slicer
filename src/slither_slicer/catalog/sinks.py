"""Solidity sink detectors -> backward-slice criteria.

Sinks are value/authority/state-changing points. We slice *backward* from them
to recover everything that influences the dangerous action.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.core.cfg.node import NodeType
from slither.slithir.operations import (
    HighLevelCall,
    LibraryCall,
    LowLevelCall,
    Operation,
    Send,
    SolidityCall,
    Transfer,
)
from slither.slithir.variables import Constant

from ..criteria import Direction, SliceCriterion
from ..dependence.data import base_of_reference

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract

_ENTRY_VISIBILITY = ("public", "external")


def _has_nonzero_value(op) -> bool:
    cv = getattr(op, "call_value", None)
    if cv is None:
        return False
    if isinstance(cv, Constant) and cv.value in (0, None):
        return False
    return True


def _is_view_or_pure(op) -> bool:
    func = getattr(op, "function", None)
    if func is None:
        return False
    return getattr(func, "view", False) or getattr(func, "pure", False)


def _entry_points(contract: Contract) -> set:
    """Ids of functions reachable from an external/public entry point.

    A function qualifies if it is itself an entry point, or if any function that
    can reach it (``all_reachable_from_functions``) is one.
    """
    entry_ids = {id(f) for f in contract.functions if f.visibility in _ENTRY_VISIBILITY}
    reachable = set(entry_ids)
    for f in contract.functions:
        callers = getattr(f, "all_reachable_from_functions", set())
        if any(id(g) in entry_ids for g in callers):
            reachable.add(id(f))
    return reachable


def _crit(node: Node, var, origin: str) -> SliceCriterion:
    return SliceCriterion(node=node, variable=var, direction=Direction.BACKWARD, origin=origin)


def find_sinks(contract: Contract) -> list[SliceCriterion]:
    """Return every backward-slice criterion seeded by a sink in ``contract``."""
    crits: list[SliceCriterion] = []
    entries = _entry_points(contract)

    for func in contract.functions_and_modifiers_declared:
        for node in func.nodes:
            for op in node.irs_ssa:
                crits.extend(_call_sink_for_op(node, op))
            # Privileged state write: any state var written by a node in a
            # function reachable from an external entry. Detected at node level
            # (deduped; skips SSA-scaffolding nodes) rather than per-op.
            if id(func) in entries and node.type not in (
                NodeType.ENTRYPOINT,
                NodeType.PLACEHOLDER,
            ):
                for sv in node.state_variables_written:
                    crits.append(_crit(node, sv, "sink:state_write"))
    return crits


def _call_sink_for_op(node, op: Operation) -> list[SliceCriterion]:
    """Sinks that are a single SlithIR call/transfer/destruct operation."""
    # selfdestruct(address)
    if isinstance(op, SolidityCall) and op.function.name.startswith(("selfdestruct(", "suicide(")):
        arg = op.arguments[0] if op.arguments else None
        return [_crit(node, arg, "sink:selfdestruct")]

    # Ether transfer via .transfer()/.send()
    if isinstance(op, (Transfer, Send)):
        return [_crit(node, getattr(op, "call_value", None), "sink:ether_transfer")]

    if isinstance(op, LowLevelCall):
        fname = str(op.function_name)
        if fname == "delegatecall":
            # whole-node criterion: trace everything flowing into the call
            return [_crit(node, None, "sink:delegatecall")]
        if _has_nonzero_value(op):
            return [_crit(node, op.call_value, "sink:ether_transfer")]
        return [_crit(node, None, _external_origin(node, op))]

    # LibraryCall is a HighLevelCall subclass but is in-scope code we descend
    # into — never a (dangerous, opaque) external-call sink.
    is_true_external = isinstance(op, HighLevelCall) and not isinstance(op, LibraryCall)
    if is_true_external and not _is_view_or_pure(op):
        if _has_nonzero_value(op):
            return [_crit(node, op.call_value, "sink:ether_transfer")]
        return [_crit(node, None, _external_origin(node, op))]

    return []


def _external_origin(node: Node, op) -> str:
    """``sink:arbitrary_call`` when the call *target* is attacker-controlled (a
    public/external function parameter), else ``sink:external_call``."""
    dest = base_of_reference(getattr(op, "destination", None))
    nsv = getattr(dest, "non_ssa_version", dest)
    func = node.function
    if func.visibility in _ENTRY_VISIBILITY and nsv in func.parameters:
        return "sink:arbitrary_call"
    return "sink:external_call"


def _is_state_var(var) -> bool:
    # StateIRVariable / StateVariable both carry this discriminator.
    return bool(getattr(var, "is_storage", False)) or type(var).__name__ in (
        "StateIRVariable",
        "StateVariable",
    )
