"""slither-slicer: byte-accurate program slicing for Solidity.

Public entry point is :class:`Slicer`. Everything else (PDG construction,
dependence analyses, the sink/source catalog) is composed underneath it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.core.declarations import SolidityVariableComposed
from slither.slithir.operations import SolidityCall

from .catalog.sinks import find_sinks
from .catalog.sources import find_sources
from .criteria import Direction, SliceCriterion
from .dependence.data import op_reads
from .loader import Loader
from .model import Slice, SliceNode, SourceRef
from .slicer import _Slicer, backward_slice, forward_slice

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract, Function

__all__ = [
    "Slicer",
    "Slice",
    "SliceNode",
    "SourceRef",
    "SliceCriterion",
    "Direction",
]

_CALLER_VARS = {"msg.sender", "tx.origin"}


def _split_function_spec(spec: str) -> tuple[str | None, str]:
    """``"Vault.withdraw()"`` -> ``("Vault", "withdraw()")``. A bare signature
    (no contract) returns ``(None, spec)``."""
    if "." in spec and "(" in spec and spec.index(".") < spec.index("("):
        contract, _, sig = spec.partition(".")
        return contract, sig
    return None, spec


class Slicer:
    """The public API: compile a project, then slice it."""

    def __init__(self, project: str, solc_version: str | None = None):
        self._loader = Loader(project, solc_version=solc_version)
        self.slither = self._loader.slither

    # -- contract / function / variable resolution -------------------------
    def _contract(self, name: str | None) -> Contract:
        if name is not None:
            return self._loader.contract(name)
        derived = self._loader.contracts
        if not derived:
            raise ValueError("no contracts found in project")
        return derived[0]

    def _resolve_function(self, spec: str) -> tuple[Contract, Function]:
        cname, sig = _split_function_spec(spec)
        contract = self._contract(cname)
        func = contract.get_function_from_signature(sig)
        if func is None:
            for f in contract.functions_and_modifiers:
                if f.name == sig or f.canonical_name == spec or f.full_name == sig:
                    func = f
                    break
        if func is None:
            avail = ", ".join(sorted(f.full_name for f in contract.functions))
            raise ValueError(f"function {spec!r} not found. available: {avail}")
        return contract, func

    def _resolve_variable(self, function: Function, name: str):
        if name in ("msg.sender", "msg.value", "tx.origin", "block.timestamp", "block.number"):
            return SolidityVariableComposed(name)
        for v in list(function.parameters) + list(function.local_variables):
            if v.name == name:
                return v
        for v in function.contract.state_variables:
            if v.name == name:
                return v
        for v in function.returns:
            if v.name == name:
                return v
        raise ValueError(f"variable {name!r} not found in {function.canonical_name}")

    def _pick_node(self, function: Function, variable, direction: Direction) -> Node:
        """Choose the criterion node when the caller gives only function+variable.

        Backward: the *last* node touching the variable (its final use/def).
        Forward: the *first* node touching it, or the entry for a parameter that
        is only read later.
        """
        touching: list[Node] = []
        for n in function.nodes:
            names = {str(v) for v in n.variables_read + n.variables_written}
            if str(variable) in names:
                touching.append(n)
        if not touching:
            return function.entry_point or function.nodes[0]
        if direction is Direction.BACKWARD:
            return max(touching, key=lambda n: n.source_mapping.start)
        return min(touching, key=lambda n: n.source_mapping.start)

    # -- catalog-driven ----------------------------------------------------
    def slice_all_sinks(self, contract: str | None = None) -> list[Slice]:
        c = self._contract(contract)
        return [backward_slice(c, crit) for crit in find_sinks(c)]

    def slice_all_sources(self, contract: str | None = None) -> list[Slice]:
        c = self._contract(contract)
        return [forward_slice(c, crit) for crit in find_sources(c)]

    # -- explicit criteria -------------------------------------------------
    def backward_slice(self, function: str, variable: str | None = None) -> Slice:
        contract, func = self._resolve_function(function)
        var = self._resolve_variable(func, variable) if variable else None
        node = (
            self._pick_node(func, var, Direction.BACKWARD)
            if var is not None
            else (func.entry_point or func.nodes[0])
        )
        crit = SliceCriterion(node=node, variable=var, direction=Direction.BACKWARD)
        return backward_slice(contract, crit)

    def forward_slice(self, function: str, variable: str | None = None) -> Slice:
        contract, func = self._resolve_function(function)
        var = self._resolve_variable(func, variable) if variable else None
        node = (
            self._pick_node(func, var, Direction.FORWARD)
            if var is not None
            else (func.entry_point or func.nodes[0])
        )
        crit = SliceCriterion(node=node, variable=var, direction=Direction.FORWARD)
        return forward_slice(contract, crit)

    # -- access control ----------------------------------------------------
    def access_control_of(self, function: str) -> Slice:
        """Return the guard context protecting ``function``: its modifier guard
        nodes plus any in-body ``require`` that checks caller identity."""
        contract, func = self._resolve_function(function)
        sc = _Slicer(contract)
        crit = SliceCriterion(
            node=func.entry_point or func.nodes[0],
            variable=None,
            direction=Direction.BACKWARD,
            origin="access-control",
        )
        sc._include_modifier_guards(func)
        for n in func.nodes:
            if _is_caller_check(n):
                sc._add_node(n, "control-dep")
                for op in n.irs_ssa:
                    for r in op_reads(op):
                        sc._push(r, func, 0)
        sc._saturate_backward()
        return sc._finish(crit)


def _is_caller_check(node: Node) -> bool:
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
