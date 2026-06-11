"""MCP server — the agent's surface to the slicer.

Design rule (the thesis of the whole project, applied to the API boundary): the
agent chooses *what* to slice; the deterministic engine decides *how* to
traverse. So every tool here returns either a **deterministic slice** or a
**bounded, discrete lookup**. There is intentionally no tool that hands the agent
raw PDG edges to walk node-by-node — that is exactly the error-prone, context-
flooding work the slicer exists to absorb. Raw-graph access lives in
:mod:`slither_slicer.graph` and the CLI ``--pdg`` flag, for a human.

Tools:
  Orientation : list_contracts, list_functions, audit_overview
  Catalog     : slice_all_sinks, slice_all_sources   (compact — drill in with slice_from)
  Full slices : access_control_of, slice_from
  Call graph  : find_callers, find_callees
  Storage     : state_var_xref                       (readers/writers of a state var)
  Explorer    : explain_dependence                   (one bounded path query)

Project selection: an explicit ``project`` arg, else the ``SLITHER_SLICER_PROJECT``
env var. Compiled projects are cached per path (compilation is the slow part).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from mcp.server.fastmcp import FastMCP

from . import Direction, Slicer
from . import graph as g
from .calls import classify_call
from .interproc import callsites_of

if TYPE_CHECKING:
    from slither.core.cfg.node import Node

    from .model import Slice

mcp = FastMCP("slither-slicer")

# project path -> (slicer, source snapshot at compile time)
_SLICERS: dict[str, tuple[Slicer, tuple[int, int]]] = {}


# --------------------------------------------------------------------------- #
# project resolution + caching
# --------------------------------------------------------------------------- #
def _resolve_project(project: str | None) -> str:
    path = project or os.environ.get("SLITHER_SLICER_PROJECT")
    if not path:
        raise ValueError(
            "no project given: pass `project` or set SLITHER_SLICER_PROJECT in the "
            "MCP server config"
        )
    return path


def _project_snapshot(path: str) -> tuple[int, int]:
    """``(file_count, max_mtime_ns)`` over the project's ``.sol`` files — a cheap
    change detector, so an edit mid-session triggers a recompile instead of
    silently serving slices of code that no longer exists."""
    p = Path(path)
    files = [p] if p.is_file() else p.rglob("*.sol")
    count, latest = 0, 0
    for f in files:
        try:
            mtime = f.stat().st_mtime_ns
        except OSError:
            continue
        count += 1
        latest = max(latest, mtime)
    return count, latest


def _get_slicer(project: str | None) -> Slicer:
    path = _resolve_project(project)
    snapshot = _project_snapshot(path)
    cached = _SLICERS.get(path)
    if cached is not None and cached[1] == snapshot:
        return cached[0]
    slicer = Slicer(path)
    _SLICERS[path] = (slicer, snapshot)
    return slicer


# --------------------------------------------------------------------------- #
# shared formatting helpers
# --------------------------------------------------------------------------- #
def _location(node: Node) -> str:
    sm = node.source_mapping
    line = sm.lines[0] if sm.lines else 0
    return f"{sm.filename.short}:{line}"


def _summarize(s: Slice) -> dict:
    """A compact, high-density descriptor of a slice — no node bodies. Enough for
    the agent to decide whether to drill in with ``slice_from``."""
    crit = s.criterion
    return {
        "origin": crit.origin,
        "function": crit.function_name,
        "variable": crit.variable_name,
        "direction": crit.direction.name,
        "location": _location(crit.node),
        "criterion_node_id": g.global_node_id(crit.node),
        "guarded": s.guarded,
        "state_write_after_external_call": s.state_write_after_external_call,
        "node_count": len(s.nodes),
        "state_vars_written": s.state_vars_written,
        "storage_writers": sorted({w["state_var"] for w in s.storage_writers}),
        "external_calls": s.external_calls,
        "call_kinds": sorted({c["kind"] for c in s.calls}),
        "events_emitted": [e["name"] for e in s.events_emitted],
        "entry_points": s.entry_points,
        "notes": s.notes,
    }


# --------------------------------------------------------------------------- #
# tool implementations (plain, independently testable)
# --------------------------------------------------------------------------- #
def list_contracts_impl(project: str | None = None) -> dict:
    """Every contract in the project — bases and libraries included, since
    inherited code is live code: a sink declared in a base is reachable through
    the derived contract."""
    sl = _get_slicer(project)
    derived = {id(c) for c in sl.slither.contracts_derived}
    contracts = [
        {
            "name": c.name,
            "kind": c.contract_kind or "contract",
            "is_most_derived": id(c) in derived,
        }
        for c in sl.slither.contracts
    ]
    contracts.sort(key=lambda c: (not c["is_most_derived"], c["name"]))
    return {"contracts": contracts}


def list_functions_impl(contract: str, project: str | None = None) -> dict:
    sl = _get_slicer(project)
    c = sl._contract(contract)
    funcs = []
    for f in c.functions:
        funcs.append(
            {
                "name": f.full_name,
                "canonical_name": f.canonical_name,
                "visibility": f.visibility,
                "modifiers": [m.name for m in f.modifiers],
                "is_constructor": f.is_constructor,
                "mutability": _mutability(f),
            }
        )
    return {"contract": c.name, "functions": funcs}


def _mutability(f) -> str:
    if f.pure:
        return "pure"
    if f.view:
        return "view"
    if f.payable:
        return "payable"
    return "nonpayable"


def audit_overview_impl(contract: str, project: str | None = None) -> dict:
    sl = _get_slicer(project)
    c = sl._contract(contract)
    return {"contract": c.name, "entry_points": sl.audit_overview(contract=c.name)}


def slice_all_sinks_impl(contract: str, project: str | None = None) -> dict:
    sl = _get_slicer(project)
    c = sl._contract(contract)
    sinks = [_summarize(s) for s in sl.slice_all_sinks(contract=c.name)]
    return {"contract": c.name, "sinks": sinks}


def slice_all_sources_impl(contract: str, project: str | None = None) -> dict:
    sl = _get_slicer(project)
    c = sl._contract(contract)
    sources = [_summarize(s) for s in sl.slice_all_sources(contract=c.name)]
    return {"contract": c.name, "sources": sources}


def access_control_of_impl(function: str, project: str | None = None) -> dict:
    sl = _get_slicer(project)
    return sl.access_control_of(function).to_json()


def slice_from_impl(
    function: str | None = None,
    variable: str | None = None,
    direction: str = "backward",
    project: str | None = None,
    node_id: str | None = None,
    depth: int = 1,
    max_nodes: int | None = None,
    storage_depth: int = 0,
    cross_contract: bool = False,
) -> dict:
    sl = _get_slicer(project)
    d = direction.lower()
    if d not in ("backward", "forward"):
        raise ValueError(f"direction must be 'backward' or 'forward', got {direction!r}")
    if node_id is not None:
        # Exact-node criterion — the drill-in path for catalog summaries, whose
        # `criterion_node_id` names the precise sink/source node (a whole-node
        # criterion like a delegatecall has no variable to slice by).
        dirn = Direction.BACKWARD if d == "backward" else Direction.FORWARD
        sl_obj = sl.slice_at_node(
            node_id,
            variable=variable,
            direction=dirn,
            depth=depth,
            storage_depth=storage_depth,
            cross_contract=cross_contract,
        )
        return sl_obj.to_json(max_nodes=max_nodes)
    if function is None:
        raise ValueError("pass `function` (with optional `variable`) or `node_id`")
    if d == "backward":
        sl_obj = sl.backward_slice(
            function=function,
            variable=variable,
            depth=depth,
            storage_depth=storage_depth,
            cross_contract=cross_contract,
        )
    else:
        sl_obj = sl.forward_slice(
            function=function, variable=variable, depth=depth, cross_contract=cross_contract
        )
    return sl_obj.to_json(max_nodes=max_nodes)


def state_var_xref_impl(contract: str, variable: str, project: str | None = None) -> dict:
    sl = _get_slicer(project)
    c = sl._contract(contract)
    return sl.state_var_xref(contract=c.name, variable=variable)


def find_callers_impl(function: str, project: str | None = None) -> dict:
    sl = _get_slicer(project)
    contract, func = sl._resolve_function(function)
    callers = [
        {"caller": caller.canonical_name, "location": _location(node)}
        for caller, node, _op in callsites_of(contract, func)
    ]
    return {
        "function": func.canonical_name,
        "callers": callers,
        # Entry-point status is visibility alone: a public function is directly
        # attacker-reachable even if it also has internal callers.
        "is_entry_point": func.visibility in ("public", "external"),
    }


def find_callees_impl(function: str, project: str | None = None) -> dict:
    """Calls made by ``function``, split into in-scope (internal + library, which
    the slicer descends into) and opaque external boundaries."""
    sl = _get_slicer(project)
    _contract, func = sl._resolve_function(function)
    in_scope, external = [], []
    seen: set[str] = set()
    for node in func.nodes:
        for op in node.irs_ssa:
            info = classify_call(op, node)
            if info is None or info["expr"] in seen:
                continue
            seen.add(info["expr"])
            entry = {
                "call": info["expr"],
                "kind": info["kind"],
                "target": info["target"],
                "location": info["location"],
            }
            (in_scope if info["in_scope"] else external).append(entry)
    return {"function": func.canonical_name, "in_scope": in_scope, "external": external}


def explain_dependence_impl(
    node_a_id: str, node_b_id: str, project: str | None = None, depth: int = 2
) -> dict:
    """Is ``node_b`` reachable from ``node_a`` over the PDG (does B influence A),
    and by what path? One bounded path — not the neighbourhood. Crosses function
    boundaries (call descent / ascent and shared storage) up to ``depth``
    crossings; same-function queries use the precise intra-function PDG."""
    sl = _get_slicer(project)
    node_a = _resolve_node(sl, node_a_id)
    node_b = _resolve_node(sl, node_b_id)

    if node_a.function is node_b.function:
        function = node_a.function
        forward = g.find_path(function, node_a, node_b)
        if forward is not None:
            return _path_result(forward, f"{node_b_id} influences {node_a_id}")
        backward = g.find_path(function, node_b, node_a)
        if backward is not None:
            return _path_result(backward, f"{node_a_id} influences {node_b_id}")
        return {"connected": False, "path": [], "note": "no dependence path in either direction"}

    contract = sl._contract(node_a_id.split(".", 1)[0])
    forward = g.find_path_interproc(contract, node_a, node_b, depth=depth)
    if forward is not None:
        return _path_result(forward, f"{node_b_id} influences {node_a_id}")
    backward = g.find_path_interproc(contract, node_b, node_a, depth=depth)
    if backward is not None:
        return _path_result(backward, f"{node_a_id} influences {node_b_id}")
    return {
        "connected": False,
        "path": [],
        "note": f"no dependence path within depth={depth} crossings",
    }


def _resolve_node(sl: Slicer, node_id: str) -> Node:
    contract_name = node_id.split(".", 1)[0]
    contract = sl._contract(contract_name)
    return g.resolve_node(contract, node_id)


def _path_result(path, note: str) -> dict:
    return {
        "connected": True,
        "direction": note,
        "path": [{"node_id": g.global_node_id(n), "edge_kind": kind} for n, kind in path],
    }


# --------------------------------------------------------------------------- #
# MCP tool registrations (thin wrappers — docstrings become tool descriptions)
# --------------------------------------------------------------------------- #
@mcp.tool()
def list_contracts(project: str | None = None) -> dict:
    """List every contract in the project (bases and libraries included), with
    its kind and whether it is most-derived (deployable)."""
    return list_contracts_impl(project)


@mcp.tool()
def list_functions(contract: str, project: str | None = None) -> dict:
    """List a contract's functions with visibility, modifiers and mutability —
    use this to find a function/variable to slice."""
    return list_functions_impl(contract, project)


@mcp.tool()
def audit_overview(contract: str, project: str | None = None) -> dict:
    """The attack surface of a contract in one call — the first move in an audit.
    One row per external entry point with: visibility, mutability, whether the
    caller is restricted (`guarded`), state it writes, whether it moves value,
    its opaque external calls, token sinks, all reachable sink origins, and
    `state_write_after_external_call` (the checks-effects-interactions / reentrancy
    ordering flag). Drill into any row with `slice_all_sinks` / `slice_from`."""
    return audit_overview_impl(contract, project)


@mcp.tool()
def slice_all_sinks(contract: str, project: str | None = None) -> dict:
    """Compact catalog of every sink in a contract (ether transfers, external
    calls, delegatecall, selfdestruct, privileged state writes), inherited code
    included. Returns a summary per sink, not full slices — drill into one with
    `slice_from`, passing its `criterion_node_id` as `node_id`."""
    return slice_all_sinks_impl(contract, project)


@mcp.tool()
def slice_all_sources(contract: str, project: str | None = None) -> dict:
    """Compact catalog of every untrusted source in a contract (parameters,
    msg.sender/value, tx.origin, environment/oracle returns), inherited code
    included. Drill in with `slice_from` (direction='forward'), passing the
    summary's `criterion_node_id` as `node_id`."""
    return slice_all_sources_impl(contract, project)


@mcp.tool()
def access_control_of(function: str, project: str | None = None) -> dict:
    """Full guard-context slice protecting a function: its modifier guards plus
    any in-body caller-identity `require`. e.g. function='Vault.withdraw()'."""
    return access_control_of_impl(function, project)


@mcp.tool()
def slice_from(
    function: str | None = None,
    variable: str | None = None,
    direction: str = "backward",
    project: str | None = None,
    node_id: str | None = None,
    depth: int = 1,
    max_nodes: int | None = None,
    storage_depth: int = 0,
    cross_contract: bool = False,
) -> dict:
    """Deterministic program slice from an agent-chosen criterion. Either pass
    `node_id` (a node id from a slice or catalog summary's `criterion_node_id`,
    like 'Vault.withdraw(uint256)#5') to slice from that exact statement, or
    `function` (like 'Vault.withdraw()') with an optional `variable` name in it.
    `direction` is 'backward' (what influences it) or 'forward' (what it
    influences); `depth` is how many call boundaries to cross (default 1).
    `storage_depth` (backward only, default 0=off) pulls cross-function writers of
    the state vars the slice reads, tagged `storage-dep` and listed in
    `storage_writers`. `cross_contract` (default off) descends into another
    in-scope contract when an external call's destination type resolves to exactly
    one concrete contract, adding a `cross-contract:<Callee>` note (the runtime
    address may differ — proxies stay opaque). `max_nodes` caps the returned node
    body for a large slice (guards are always kept; a `truncated:<kept>-of-<total>-
    nodes` note is added). Returns the slice with byte-accurate source for every
    node, control/data/modifier-guard reasons, touched state and external calls."""
    return slice_from_impl(
        function,
        variable,
        direction,
        project,
        node_id,
        depth,
        max_nodes,
        storage_depth,
        cross_contract,
    )


@mcp.tool()
def state_var_xref(contract: str, variable: str, project: str | None = None) -> dict:
    """Readers and writers of a contract state variable, each with location,
    node_id, `guarded` status and entry-point reachability — the cheap way to see
    who touches storage X. To pull this dataflow *into* a slice, use `slice_from`
    with `storage_depth=1`. e.g. contract='Vault', variable='balances'."""
    return state_var_xref_impl(contract, variable, project)


@mcp.tool()
def find_callers(function: str, project: str | None = None) -> dict:
    """Direct internal callsites of a function (who calls it, and where)."""
    return find_callers_impl(function, project)


@mcp.tool()
def find_callees(function: str, project: str | None = None) -> dict:
    """Functions and external calls invoked by a function."""
    return find_callees_impl(function, project)


@mcp.tool()
def explain_dependence(
    node_a_id: str, node_b_id: str, project: str | None = None, depth: int = 2
) -> dict:
    """Are two slice nodes connected in the PDG, and by what path? Node ids look
    like 'Vault.withdraw()#5' (as returned in slice nodes). Returns one bounded
    dependence path, or that they are unconnected. Crosses function boundaries
    (call descent/ascent and shared storage) up to `depth` crossings (default 2);
    same-function queries use the precise intra-function PDG."""
    return explain_dependence_impl(node_a_id, node_b_id, project, depth)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
