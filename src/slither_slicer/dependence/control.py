"""Post-dominance frontier -> control-dependence edges.

Data flow alone is not a slice. Without control dependence the guards
(``require``, ``if``, loop and modifier conditions) get dropped — and for an
audit the guard is usually the most important statement in the slice.

Slither exposes *forward* dominators (``node.dominators`` etc.) but not
post-dominators, so we compute them here on the reversed CFG using the standard
iterative dominator algorithm, then derive control dependence via the
Ferrante-Ottenstein-Warren post-dominator-tree walk (Cooper's formulation).

A wrinkle specific to Solidity: ``require``/``assert``/``revert`` do *not* create
a branch node in Slither's CFG — they are linear ``SolidityCall`` expressions
that may abort. We model that abort path by giving such nodes a virtual edge to
the exit, which makes every statement after a ``require`` correctly
control-dependent on it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from slither.slithir.operations import SolidityCall

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Function

_EXIT = "__EXIT__"  # virtual exit sentinel

_ABORT_PREFIXES = ("require(", "assert(", "revert(", "revert ")


def _is_abort_node(node: Node) -> bool:
    """True if executing ``node`` can abort the function (``require``/``assert``/
    ``revert``), giving it an implicit edge to the exit."""
    for op in node.irs_ssa:
        if isinstance(op, SolidityCall):
            name = op.function.name
            if name.startswith(("require(", "assert(", "revert(")):
                return True
    # NodeType.THROW handled via terminal detection (no sons -> connects to exit)
    return False


def _successors(function: Function) -> dict:
    """Augmented successor map: real CFG sons, plus a virtual exit edge for
    terminal nodes and for abort-capable (``require``/``assert``) nodes."""
    succ: dict = {}
    for node in function.nodes:
        sons = list(node.sons)
        outs = [s for s in sons]
        if not sons:
            outs.append(_EXIT)  # terminal node -> exit
        if _is_abort_node(node) and _EXIT not in outs:
            outs.append(_EXIT)  # abort path -> exit
        succ[node] = outs
    succ[_EXIT] = []
    return succ


def _post_dominators(function: Function, succ: dict) -> dict:
    """Compute post-dominator sets: ``pdom[n]`` = nodes that post-dominate ``n``.

    This is the dominator relation on the reversed CFG rooted at the virtual exit.
    """
    all_nodes = list(function.nodes) + [_EXIT]
    # Predecessors in the reversed graph == successors in the forward graph.
    rpred: dict = {n: [] for n in all_nodes}
    for n in function.nodes:
        for s in succ[n]:
            rpred[n].append(s)  # reverse edge s -> n means n's rpred includes s

    universe = set(map(id, all_nodes))
    by_id = {id(n): n for n in all_nodes}

    pdom: dict = {id(n): set(universe) for n in all_nodes}
    pdom[id(_EXIT)] = {id(_EXIT)}

    changed = True
    while changed:
        changed = False
        for n in all_nodes:
            if n is _EXIT:
                continue
            preds = rpred[n]
            if preds:
                inter = set.intersection(*(pdom[id(p)] for p in preds))
            else:
                inter = set()
            new = {id(n)} | inter
            if new != pdom[id(n)]:
                pdom[id(n)] = new
                changed = True
    return pdom, by_id


def _immediate_post_dominators(function: Function, pdom: dict, by_id: dict) -> dict:
    """Derive ipdom(n): the closest strict post-dominator (fewest post-dominators)."""
    ipdom: dict = {}
    for n in list(function.nodes) + [_EXIT]:
        strict = [d for d in pdom[id(n)] if d != id(n)]
        if not strict:
            ipdom[id(n)] = None
            continue
        # The immediate post-dominator is the *closest* strict post-dominator:
        # the one every other strict post-dominator also post-dominates, i.e. the
        # one with the largest post-dominator set.
        ipdom[id(n)] = max(strict, key=lambda d: len(pdom[d]))
    return ipdom


def control_parents(function: Function) -> dict:
    """Return ``{node: {controlling_guard_node, ...}}`` for ``function``.

    ``Y in cd_parents`` maps to the set of branch/abort nodes ``X`` such that
    ``Y`` is control-dependent on ``X``.
    """
    succ = _successors(function)
    pdom, by_id = _post_dominators(function, succ)
    ipdom = _immediate_post_dominators(function, pdom, by_id)

    parents: dict = {}
    for a in function.nodes:
        outs = succ[a]
        if len(outs) < 2:
            continue  # only branch/abort points create control dependence
        target = ipdom[id(a)]
        for b in outs:
            runner = id(b)
            while runner is not None and runner != target:
                rnode = by_id.get(runner)
                if rnode is not _EXIT and rnode is not None and rnode is not a:
                    parents.setdefault(rnode, set()).add(a)
                runner = ipdom.get(runner)
    return parents
