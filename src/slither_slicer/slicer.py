"""Backward / forward slicing = reachability over the PDG.

The PDG (:mod:`pdg`) gives us data- and control-dependence edges per function.
A slice is the set of nodes reachable from the criterion along those edges, plus
two Solidity-specific additions a generic slicer would miss:

- **modifier guards** of the criterion's enclosing function (access control), and
- **one level of inter-procedural descent** through resolved internal calls.

Anything that could not be followed precisely is recorded as a ``note`` rather
than silently dropped — for an audit, a visible "I couldn't follow this" is far
safer than a slice that looks complete but isn't.

SSA ``Phi`` operations are pseudo-statements (they merge SSA versions at joins /
loop headers and have no source of their own). We traverse *through* them to the
real definitions but never emit them as slice nodes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.core.cfg.node import NodeType
from slither.core.declarations import SolidityVariableComposed
from slither.slithir.operations import HighLevelCall, InternalCall, LowLevelCall, Phi
from slither.slithir.variables import Constant

from .catalog.sinks import _is_state_var
from .criteria import Direction, SliceCriterion
from .dependence.data import base_of_reference, imprecise_index, op_defs, op_reads
from .interproc import MAX_BOUNDARY_CROSSINGS, actual_to_formal, callsites_of
from .model import Slice, SliceNode, SourceRef
from .pdg import build_pdg

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract, Function

# Reason priority — when a node is reached more than once, the strongest wins.
_REASON_RANK = {
    "criterion": 5,
    "modifier-guard": 4,
    "control-dep": 3,
    "callee": 2,
    "data-dep": 1,
}

# Node types that are pure CFG scaffolding, never emitted as slice statements.
_SCAFFOLDING = (NodeType.ENTRYPOINT, NodeType.PLACEHOLDER)


def _is_ssa_var(var) -> bool:
    return hasattr(var, "non_ssa_version") or isinstance(var, (SolidityVariableComposed, Constant))


def _matches(ssa_var, target) -> bool:
    if ssa_var is target:
        return True
    nsv = getattr(ssa_var, "non_ssa_version", None)
    if nsv is not None and (nsv is target or nsv == target):
        return True
    return str(ssa_var) == str(target)


class _Slicer:
    def __init__(self, contract: Contract):
        self.contract = contract
        self.included: dict[Node, str] = {}  # node -> reason
        self.notes: list[str] = []
        self.external_calls: list[str] = []
        self._visited: set[int] = set()
        # worklist entries: (ssa_var, owning_function, crossings)
        self._work: list[tuple[object, Function, int]] = []

    # -- bookkeeping -------------------------------------------------------
    def _add_node(self, node: Node, reason: str) -> None:
        cur = self.included.get(node)
        if cur is None or _REASON_RANK[reason] > _REASON_RANK[cur]:
            self.included[node] = reason
        if node.type == NodeType.ASSEMBLY:
            self._note(f"assembly-boundary:{node.function.canonical_name}")

    def _note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)

    def _push(self, var, function: Function, crossings: int) -> None:
        self._work.append((var, function, crossings))

    # -- seed resolution ---------------------------------------------------
    def _resolve_seed_vars(self, criterion: SliceCriterion) -> list:
        node, var, direction = criterion.node, criterion.variable, criterion.direction
        function = node.function

        if var is None:
            seeds: list = []
            for op in node.irs_ssa:
                seeds.extend(op_reads(op) if direction is Direction.BACKWARD else op_defs(op))
            return seeds

        if getattr(var, "non_ssa_version", None) is not None:
            return [var]  # already an SSA-versioned variable
        if isinstance(var, (SolidityVariableComposed, Constant)):
            return [var]

        return self._ssa_versions_of(function, var, node, direction)

    def _ssa_versions_of(self, function, target, node, direction) -> list:
        pdg = build_pdg(function)
        at_node, roots, all_versions = [], [], []
        for n in function.nodes:
            for op in n.irs_ssa:
                for v in op_reads(op) + op_defs(op):
                    if _matches(v, target):
                        all_versions.append(v)
                        if n is node:
                            at_node.append(v)
                        if id(v) not in pdg.def_map:
                            roots.append(v)
        if direction is Direction.BACKWARD:
            return at_node or all_versions
        return roots or at_node or all_versions

    # == backward ==========================================================
    def backward(self, criterion: SliceCriterion) -> Slice:
        func = criterion.node.function
        if criterion.node.type not in _SCAFFOLDING:
            self._add_node(criterion.node, "criterion")
        for v in self._resolve_seed_vars(criterion):
            self._push(v, func, 0)

        self._saturate_backward()
        self._include_modifier_guards(func)
        self._saturate_backward()
        return self._finish(criterion)

    def _saturate_backward(self) -> None:
        while True:
            self._run_backward_data()
            if not self._control_closure_step():
                break

    def _run_backward_data(self) -> None:
        while self._work:
            var, function, crossings = self._work.pop()
            if id(var) in self._visited:
                continue
            self._visited.add(id(var))

            pdg = build_pdg(function)
            site = pdg.def_site(var)
            if site is None:
                self._maybe_ascend(var, function, crossings)
                continue
            dnode, dop = site
            if isinstance(dop, Phi):
                # A formal parameter's entry merge (``value_1 := phi(amount_1)``)
                # links to the *caller's* actual, which lives in another function.
                # Ascend through the callsites rather than threading a var into
                # the wrong PDG.
                if dnode.type == NodeType.ENTRYPOINT and self._is_param_version(var, function):
                    self._maybe_ascend(var, function, crossings)
                else:
                    for r in op_reads(dop):  # thread through the merge
                        self._push(r, function, crossings)
                continue
            self._add_node(dnode, "callee" if crossings > 0 else "data-dep")
            if isinstance(dop, InternalCall) and not dop.is_modifier_call and dop.function:
                self._descend_backward(dop, crossings)
            for r in op_reads(dop):
                self._push(r, function, crossings)

    @staticmethod
    def _is_param_version(var, function: Function) -> bool:
        return getattr(var, "non_ssa_version", None) in function.parameters

    def _maybe_ascend(self, var, function: Function, crossings: int) -> None:
        """``var`` has no in-function definition. If it is a formal parameter and
        ``function`` is called from in scope, climb to the actuals (one level)."""
        if crossings >= MAX_BOUNDARY_CROSSINGS:
            return
        target = getattr(var, "non_ssa_version", var)
        if target not in function.parameters:
            return
        idx = function.parameters.index(target)
        for _caller, node, op in callsites_of(self.contract, function):
            self._add_node(node, "callee")
            if idx < len(op.arguments):
                self._push(op.arguments[idx], node.function, crossings + 1)

    def _descend_backward(self, op: InternalCall, crossings: int) -> None:
        if crossings >= MAX_BOUNDARY_CROSSINGS:
            self._note(f"interproc-depth-limit:{op.function.canonical_name}")
            return
        callee = op.function
        for n in callee.nodes:
            for cop in n.irs_ssa:
                lv = getattr(cop, "lvalue", None)
                is_state_write = lv is not None and _is_state_var(base_of_reference(lv))
                if n.type == NodeType.RETURN or is_state_write:
                    if n.type not in _SCAFFOLDING:
                        self._add_node(n, "callee")
                    for r in op_reads(cop):
                        self._push(r, callee, crossings + 1)

    # == forward ===========================================================
    def forward(self, criterion: SliceCriterion) -> Slice:
        func = criterion.node.function
        if criterion.node.type not in _SCAFFOLDING:
            self._add_node(criterion.node, "criterion")
        for v in self._resolve_seed_vars(criterion):
            self._push(v, func, 0)

        self._run_forward_data()
        self._forward_control(criterion.node)
        self._include_modifier_guards(func)
        self._run_backward_data()  # resolve modifier-guard data deps
        return self._finish(criterion)

    def _run_forward_data(self) -> None:
        while self._work:
            var, function, crossings = self._work.pop()
            if id(var) in self._visited:
                continue
            self._visited.add(id(var))

            pdg = build_pdg(function)
            for unode, uop in pdg.use_sites(var):
                if isinstance(uop, Phi):
                    for d in op_defs(uop):  # thread through the merge
                        self._push(d, function, crossings)
                    continue
                if unode.type not in _SCAFFOLDING:
                    self._add_node(unode, "callee" if crossings > 0 else "data-dep")
                if isinstance(uop, InternalCall) and not uop.is_modifier_call and uop.function:
                    self._descend_forward(uop, var, crossings)
                for d in op_defs(uop):
                    self._push(d, function, crossings)

    def _descend_forward(self, op: InternalCall, tainted_actual, crossings: int) -> None:
        if crossings >= MAX_BOUNDARY_CROSSINGS:
            self._note(f"interproc-depth-limit:{op.function.canonical_name}")
            return
        callee = op.function
        seeded: set[int] = set()
        for actual, formal in actual_to_formal(op, callee):
            if str(actual) != str(tainted_actual):
                continue
            # Taint every SSA version of the matching formal parameter inside the
            # callee — the input flows into all of them.
            for n in callee.nodes:
                for cop in n.irs_ssa:
                    for v in op_reads(cop) + op_defs(cop):
                        if getattr(v, "non_ssa_version", None) is formal and id(v) not in seeded:
                            seeded.add(id(v))
                            self._push(v, callee, crossings + 1)

    def _forward_control(self, criterion_node: Node) -> None:
        pdg = build_pdg(criterion_node.function)
        for node, guards in pdg.control_parents.items():
            if criterion_node in guards and node.type not in _SCAFFOLDING:
                self._add_node(node, "control-dep")

    # == control closure (backward) ========================================
    def _control_closure_step(self) -> bool:
        added = False
        for node in list(self.included):
            pdg = build_pdg(node.function)
            for guard in pdg.guards_of(node):
                if guard not in self.included and guard.type not in _SCAFFOLDING:
                    self._add_node(guard, "control-dep")
                    added = True
                    for op in guard.irs_ssa:
                        for r in op_reads(op):
                            self._push(r, node.function, 0)
        return added

    # == modifiers =========================================================
    def _include_modifier_guards(self, function: Function) -> None:
        for modifier in getattr(function, "modifiers", []):
            for n in modifier.nodes:
                if self._is_guard_node(n):
                    self._add_node(n, "modifier-guard")
                    for op in n.irs_ssa:
                        for r in op_reads(op):
                            self._push(r, modifier, 0)

    @staticmethod
    def _is_guard_node(node: Node) -> bool:
        if node.type in _SCAFFOLDING:
            return False
        return any(not isinstance(op, Phi) for op in node.irs_ssa)

    # == helpers ===========================================================
    def _collect_metadata(self) -> None:
        """Scan the final node set for two things worth surfacing:

        - external-call boundaries (``HighLevelCall`` is opaque; a value-bearing
          ``LowLevelCall`` is the transfer itself), and
        - imprecise aliasing through non-constant mapping/array/struct indices.
        """
        for node in self.included:
            for op in node.irs_ssa:
                if isinstance(op, (HighLevelCall, LowLevelCall)):
                    text = str(op.expression) if op.expression is not None else str(op)
                    if text not in self.external_calls:
                        self.external_calls.append(text)
                res = imprecise_index(op)
                if res is not None:
                    base, _index = res
                    resolved = base_of_reference(base)
                    name = getattr(resolved, "non_ssa_version", None) or resolved
                    self._note(f"imprecise-alias:{name}")

    # == finish ============================================================
    def _finish(self, criterion: SliceCriterion) -> Slice:
        self._collect_metadata()
        ordered = sorted(
            self.included.items(),
            key=lambda kv: (kv[0].source_mapping.start, kv[0].source_mapping.length),
        )
        slice_nodes: list[SliceNode] = []
        functions_touched: list[str] = []
        state_read: list[str] = []
        state_written: list[str] = []

        for node, reason in ordered:
            fname = node.function.canonical_name
            if fname not in functions_touched:
                functions_touched.append(fname)
            slice_nodes.append(
                SliceNode(
                    node_id=f"{fname}#{node.node_id}",
                    function=fname,
                    ntype=node.type.name,
                    ir=[str(op) for op in node.irs_ssa],
                    source=SourceRef.from_node(node),
                    reason=reason,
                )
            )
            for sv in node.state_variables_read:
                if str(sv) not in state_read:
                    state_read.append(str(sv))
            for sv in node.state_variables_written:
                if str(sv) not in state_written:
                    state_written.append(str(sv))

        return Slice(
            criterion=criterion,
            nodes=slice_nodes,
            functions_touched=functions_touched,
            state_vars_read=state_read,
            state_vars_written=state_written,
            external_calls=list(self.external_calls),
            notes=list(self.notes),
        )


def backward_slice(contract: Contract, criterion: SliceCriterion) -> Slice:
    return _Slicer(contract).backward(criterion)


def forward_slice(contract: Contract, criterion: SliceCriterion) -> Slice:
    return _Slicer(contract).forward(criterion)
