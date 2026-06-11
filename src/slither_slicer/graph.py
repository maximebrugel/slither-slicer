"""Raw PDG access — for the human researcher, not the agent.

The agent surface (slices, via :class:`~slither_slicer.Slicer` and the MCP
server) deliberately never exposes raw node-by-node edges: walking them is the
error-prone, multi-hop work the deterministic slicer exists to take off the
agent's plate. But the raw graph is invaluable for *debugging the slicer*, so it
lives here and in the CLI (``--pdg``), where a person drives it.

Node identity here matches the ``"Contract.fn(args)#3"`` ids that slices already
emit (:class:`~slither_slicer.model.SliceNode.node_id`), so a human can paste a
node id straight from a slice into ``--pdg`` / ``explain_dependence``.

Edges are derived from the PDG and **thread through ``Phi``** pseudo-defs exactly
as :mod:`slither_slicer.slicer` does, so a path here is a path the slicer would
also have followed.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from slither.slithir.operations import Phi

from .dependence.data import op_reads
from .dependence.storage import build_storage_xref
from .interproc import callsites_of, is_descendable_call
from .pdg import build_pdg

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract, Function

DATA = "data-dep"
CONTROL = "control-dep"
CALLEE = "callee"
STORAGE = "storage-dep"


def global_node_id(node: Node) -> str:
    """The stable id a slice would emit for ``node``."""
    return f"{node.function.canonical_name}#{node.node_id}"


def resolve_node(contract: Contract, node_id: str) -> Node:
    """Map a ``"Contract.fn(args)#3"`` id back to its Slither :class:`Node`."""
    if "#" not in node_id:
        raise ValueError(f"malformed node id (expected '<function>#<n>'): {node_id!r}")
    func_spec, _, local = node_id.rpartition("#")
    try:
        local_id = int(local)
    except ValueError as exc:
        raise ValueError(f"malformed node id (non-integer index): {node_id!r}") from exc

    func = _find_function(contract, func_spec)
    for n in func.nodes:
        if n.node_id == local_id:
            return n
    raise ValueError(f"no node #{local_id} in {func.canonical_name}")


def _find_function(contract: Contract, spec: str) -> Function:
    # spec is a canonical name "Contract.fn(args)"; also accept a bare signature.
    sig = spec.split(".", 1)[1] if "." in spec else spec
    func = contract.get_function_from_signature(sig)
    if func is not None:
        return func
    for f in contract.functions_and_modifiers:
        if f.canonical_name == spec or f.full_name == sig or f.name == sig:
            return f
    raise ValueError(f"function {spec!r} not found in {contract.name}")


def _def_node(pdg, var) -> Node | None:
    """The node that defines ``var``, threading through ``Phi`` merges to a real
    (non-``Phi``) definition — mirrors the slicer's traversal."""
    seen: set[int] = set()
    worklist = [var]
    while worklist:
        v = worklist.pop()
        if id(v) in seen:
            continue
        seen.add(id(v))
        site = pdg.def_site(v)
        if site is None:
            continue
        dnode, dop = site
        if isinstance(dop, Phi):
            worklist.extend(op_reads(dop))
            continue
        return dnode
    return None


def data_dependencies(pdg, node: Node) -> set:
    """Nodes that ``node`` depends on through SSA data flow."""
    deps: set = set()
    for op in node.irs_ssa:
        if isinstance(op, Phi):
            continue
        for var in op_reads(op):
            dnode = _def_node(pdg, var)
            if dnode is not None and dnode is not node:
                deps.add(dnode)
    return deps


def control_dependencies(pdg, node: Node) -> set:
    """Guard nodes that ``node`` is control-dependent on."""
    return {g for g in pdg.guards_of(node) if g is not node}


def successors(pdg, node: Node) -> list[tuple[Node, str]]:
    """Combined dependency edges out of ``node``: ``(target, kind)``."""
    out: list[tuple[Node, str]] = []
    out.extend((d, DATA) for d in data_dependencies(pdg, node))
    out.extend((g, CONTROL) for g in control_dependencies(pdg, node))
    return out


def pdg_edges(function: Function) -> list[tuple[Node, Node, str]]:
    """The full ``(src, dst, kind)`` edge list for ``function`` (human / CLI)."""
    pdg = build_pdg(function)
    edges: list[tuple[Node, Node, str]] = []
    for node in function.nodes:
        for target, kind in successors(pdg, node):
            edges.append((node, target, kind))
    return edges


def find_path(function: Function, src: Node, dst: Node) -> list[tuple[Node, str]] | None:
    """Shortest dependency path ``src -> ... -> dst`` over the union PDG, or
    ``None`` if ``dst`` does not influence ``src``.

    Returned as ``[(src, "seed"), (next, kind), ..., (dst, kind)]`` — each hop
    carries the edge kind that reached it.
    """
    if src is dst:
        return [(src, "seed")]
    pdg = build_pdg(function)
    # BFS; remember predecessor + edge kind to reconstruct the path.
    prev: dict[int, tuple[Node, str]] = {}
    seen = {id(src)}
    queue: deque[Node] = deque([src])
    while queue:
        cur = queue.popleft()
        for target, kind in successors(pdg, cur):
            if id(target) in seen:
                continue
            seen.add(id(target))
            prev[id(target)] = (cur, kind)
            if target is dst:
                return _reconstruct(src, dst, prev)
            queue.append(target)
    return None


def _reconstruct(src: Node, dst: Node, prev: dict) -> list[tuple[Node, str]]:
    chain: list[tuple[Node, str]] = []
    node = dst
    while node is not src:
        parent, kind = prev[id(node)]
        chain.append((node, kind))
        node = parent
    chain.append((src, "seed"))
    chain.reverse()
    return chain


def _node_reads_formal(node: Node) -> bool:
    """True if ``node`` reads a formal parameter of its own function — the hook
    for ascent (the value came from the caller's actual argument)."""
    params = set(node.function.parameters)
    for op in node.irs_ssa:
        for v in op_reads(op):
            if getattr(v, "non_ssa_version", None) in params:
                return True
    return False


def _interproc_neighbors(contract: Contract, node: Node, crossings: int, depth: int):
    """Dependence neighbours of ``node`` for interprocedural path finding:
    intra-function data/control edges, plus call descent (into a callee's returns
    / state writes), ascent (to a callee's callsites) and storage (to writers of a
    state var the node reads). Inter-procedural edges cost one crossing and are
    gated by ``depth``."""
    pdg = build_pdg(node.function)
    for target, kind in successors(pdg, node):
        yield target, kind, crossings

    if crossings >= depth:
        return

    # Descent: a resolvable call's result depends on the callee's returns / writes.
    for op in node.irs_ssa:
        if is_descendable_call(op) and op.function is not None:
            for cn in op.function.nodes:
                if cn.type.name == "RETURN" or cn.state_variables_written:
                    yield cn, CALLEE, crossings + 1

    # Ascent: a formal param read depends on the actuals at every callsite.
    if _node_reads_formal(node):
        for _caller, cnode, _op in callsites_of(contract, node.function):
            yield cnode, CALLEE, crossings + 1

    # Storage: a state var read depends on its writers across the contract.
    xref = build_storage_xref(contract)
    for sv in node.state_variables_read:
        for _wfn, wnode in xref.writers.get(sv.canonical_name, []):
            if wnode is not node:
                yield wnode, STORAGE, crossings + 1


def find_path_interproc(
    contract: Contract, src: Node, dst: Node, depth: int = 2
) -> list[tuple[Node, str]] | None:
    """Shortest dependency path ``src -> ... -> dst`` across function boundaries
    (call descent / ascent and shared storage), bounded by ``depth`` crossings, or
    ``None`` if ``dst`` does not influence ``src`` within that budget."""
    if src is dst:
        return [(src, "seed")]
    prev: dict[int, tuple[Node, str]] = {}
    seen = {id(src)}
    queue: deque[tuple[Node, int]] = deque([(src, 0)])
    while queue:
        cur, crossings = queue.popleft()
        for target, kind, nx in _interproc_neighbors(contract, cur, crossings, depth):
            if id(target) in seen:
                continue
            seen.add(id(target))
            prev[id(target)] = (cur, kind)
            if target is dst:
                return _reconstruct(src, dst, prev)
            queue.append((target, nx))
    return None
