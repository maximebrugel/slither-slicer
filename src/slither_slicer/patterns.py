"""Pattern-level audit heuristics over a whole function / contract.

These are coarse, function-scoped signals (not slices) the agent uses to triage
an attack surface: which entry points are guarded, which move value, and the
classic checks-effects-interactions ordering risk (a state write reachable
*after* an external call — the shape behind reentrancy). They reuse the same call
classification and guard detection as the slicer, so the signals never disagree
with a slice the agent drills into.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.slithir.operations import (
    HighLevelCall,
    LibraryCall,
    LowLevelCall,
    Send,
    Transfer,
)

from .catalog.access import is_guarded
from .catalog.sinks import find_sinks

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract, Function
    from slither.slithir.operations import Operation

_ENTRY_VISIBILITY = ("public", "external")


def _is_external_interaction(op: Operation) -> bool:
    """An external message call or value send — the 'interaction' in CEI.

    Library calls are excluded (in-scope code we descend into); ``Transfer`` /
    ``Send`` (``.transfer`` / ``.send``) are included since they hand control to
    an arbitrary recipient's ``receive`` / fallback.
    """
    if isinstance(op, (Transfer, Send, LowLevelCall)):
        return True
    return isinstance(op, HighLevelCall) and not isinstance(op, LibraryCall)


def state_write_after_external_call(function: Function) -> bool:
    """True if a state write is reachable (intra-function) *after* an external
    call — the checks-effects-interactions ordering risk behind reentrancy.

    Forward CFG reachability from each external-interaction node: if any node
    reachable along ``sons`` writes state, effects follow the interaction. This
    is intentionally intra-function (v1); a slice drilled from the sink shows the
    cross-function picture.
    """
    ext_nodes = [
        n for n in function.nodes if any(_is_external_interaction(op) for op in n.irs_ssa)
    ]
    for start in ext_nodes:
        seen: set[int] = set()
        stack: list[Node] = list(start.sons)
        while stack:
            n = stack.pop()
            if id(n) in seen:
                continue
            seen.add(id(n))
            if n.state_variables_written:
                return True
            stack.extend(n.sons)
    return False


def _mutability(f: Function) -> str:
    if f.pure:
        return "pure"
    if f.view:
        return "view"
    if f.payable:
        return "payable"
    return "nonpayable"


def audit_overview(contract: Contract) -> list[dict]:
    """One row per external entry point — the attack surface at a glance.

    Each row: visibility, mutability, whether the caller is restricted
    (``guarded``), the state it writes, whether it moves value, its opaque
    external calls, any token sinks, the full set of sink origins reachable in
    it, and the CEI ordering flag. Inherited-inclusive: entry points declared in
    base contracts are live code of ``contract``.
    """
    origins_by_fn: dict[str, set[str]] = {}
    for crit in find_sinks(contract):
        origins_by_fn.setdefault(crit.function_name, set()).add(crit.origin)

    rows: list[dict] = []
    for f in contract.functions:
        if f.visibility not in _ENTRY_VISIBILITY or f.is_constructor:
            continue
        name = f.canonical_name
        external_calls: list[str] = []
        value_out = False
        for node in f.nodes:
            for op in node.irs_ssa:
                if not _is_external_interaction(op):
                    continue
                if isinstance(op, (Transfer, Send)) or getattr(op, "call_value", None) is not None:
                    value_out = True
                ex = getattr(op, "expression", None)
                expr = str(ex) if ex is not None else str(op)
                if expr not in external_calls:
                    external_calls.append(expr)
        origins = origins_by_fn.get(name, set())
        rows.append(
            {
                "function": name,
                "visibility": f.visibility,
                "mutability": _mutability(f),
                "guarded": is_guarded(f),
                "state_written": sorted(str(v) for v in f.all_state_variables_written()),
                "value_out": value_out,
                "external_calls": external_calls,
                "token_sinks": sorted(o for o in origins if o.startswith("sink:token_")),
                "sink_origins": sorted(origins),
                "state_write_after_external_call": state_write_after_external_call(f),
            }
        )
    rows.sort(key=lambda r: r["function"])
    return rows
