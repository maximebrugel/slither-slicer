"""MCP server — the agent's surface to the slicer.

Design rule (the thesis of the whole project, applied to the API boundary): the
agent chooses *what* to slice; the deterministic engine decides *how* to
traverse. So every tool here returns either a **deterministic slice** or a
**bounded, discrete lookup**. There is intentionally no tool that hands the agent
raw PDG edges to walk node-by-node — that is exactly the error-prone, context-
flooding work the slicer exists to absorb. Raw-graph access lives in
:mod:`slither_slicer.graph` and the CLI ``--pdg`` flag, for a human.

Tools:
  Orientation : list_contracts, list_functions
  Catalog     : slice_all_sinks, slice_all_sources   (compact — drill in with slice_from)
  Full slices : access_control_of, slice_from
  Call graph  : find_callers, find_callees
  Explorer    : explain_dependence                   (one bounded path query)

Project selection: an explicit ``project`` arg, else the ``SLITHER_SLICER_PROJECT``
env var. Compiled projects are cached per path (compilation is the slow part).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from mcp.server.fastmcp import FastMCP
from slither.slithir.operations import HighLevelCall, LowLevelCall

from . import Slicer
from . import graph as g
from .interproc import callsites_of, resolved_internal_calls

if TYPE_CHECKING:
    from slither.core.cfg.node import Node

    from .model import Slice

mcp = FastMCP("slither-slicer")

_SLICERS: dict[str, Slicer] = {}


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


def _get_slicer(project: str | None) -> Slicer:
    path = _resolve_project(project)
    if path not in _SLICERS:
        _SLICERS[path] = Slicer(path)
    return _SLICERS[path]


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
        "node_count": len(s.nodes),
        "state_vars_written": s.state_vars_written,
        "external_calls": s.external_calls,
        "notes": s.notes,
    }


# --------------------------------------------------------------------------- #
# tool implementations (plain, independently testable)
# --------------------------------------------------------------------------- #
def list_contracts_impl(project: str | None = None) -> dict:
    sl = _get_slicer(project)
    return {"contracts": [c.name for c in sl._loader.contracts]}


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
    function: str,
    variable: str | None = None,
    direction: str = "backward",
    project: str | None = None,
) -> dict:
    sl = _get_slicer(project)
    d = direction.lower()
    if d == "backward":
        return sl.backward_slice(function=function, variable=variable).to_json()
    if d == "forward":
        return sl.forward_slice(function=function, variable=variable).to_json()
    raise ValueError(f"direction must be 'backward' or 'forward', got {direction!r}")


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
        "is_entry_point": func.visibility in ("public", "external") and not callers,
    }


def find_callees_impl(function: str, project: str | None = None) -> dict:
    sl = _get_slicer(project)
    _contract, func = sl._resolve_function(function)
    internal = [
        {"callee": callee.canonical_name, "location": _location(node)}
        for node, _op, callee in resolved_internal_calls(func)
    ]
    # External calls (High/Low-level) are opaque boundaries — scan node ops, the
    # same way the slicer collects them, rather than trusting any one accessor.
    external = []
    seen: set[str] = set()
    for node in func.nodes:
        for op in node.irs_ssa:
            if isinstance(op, (HighLevelCall, LowLevelCall)):
                text = str(op.expression) if op.expression is not None else str(op)
                if text not in seen:
                    seen.add(text)
                    external.append({"call": text, "location": _location(node), "opaque": True})
    return {"function": func.canonical_name, "internal": internal, "external": external}


def explain_dependence_impl(
    node_a_id: str, node_b_id: str, project: str | None = None
) -> dict:
    """Is ``node_b`` reachable from ``node_a`` over the PDG (does B influence A),
    and by what path? One bounded path — not the neighbourhood."""
    sl = _get_slicer(project)
    func_a = node_a_id.rpartition("#")[0]
    func_b = node_b_id.rpartition("#")[0]
    if func_a != func_b:
        return {
            "connected": False,
            "path": [],
            "note": (
                "cross-function dependence is not traversed here (v1). Both nodes "
                "must belong to the same function; use slice_from for inter-"
                "procedural reach."
            ),
        }
    node_a = _resolve_node(sl, node_a_id)
    node_b = _resolve_node(sl, node_b_id)
    function = node_a.function

    forward = g.find_path(function, node_a, node_b)
    if forward is not None:
        return _path_result(forward, f"{node_b_id} influences {node_a_id}")
    backward = g.find_path(function, node_b, node_a)
    if backward is not None:
        return _path_result(backward, f"{node_a_id} influences {node_b_id}")
    return {"connected": False, "path": [], "note": "no dependence path in either direction"}


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
    """List the contracts defined in the project."""
    return list_contracts_impl(project)


@mcp.tool()
def list_functions(contract: str, project: str | None = None) -> dict:
    """List a contract's functions with visibility, modifiers and mutability —
    use this to find a function/variable to slice."""
    return list_functions_impl(contract, project)


@mcp.tool()
def slice_all_sinks(contract: str, project: str | None = None) -> dict:
    """Compact catalog of every sink in a contract (ether transfers, external
    calls, delegatecall, selfdestruct, privileged state writes). Returns a
    summary per sink, not full slices — drill into one with `slice_from` using
    its `function` and `variable`."""
    return slice_all_sinks_impl(contract, project)


@mcp.tool()
def slice_all_sources(contract: str, project: str | None = None) -> dict:
    """Compact catalog of every untrusted source in a contract (parameters,
    msg.sender/value, tx.origin, environment/oracle returns). Drill in with
    `slice_from` (direction='forward')."""
    return slice_all_sources_impl(contract, project)


@mcp.tool()
def access_control_of(function: str, project: str | None = None) -> dict:
    """Full guard-context slice protecting a function: its modifier guards plus
    any in-body caller-identity `require`. e.g. function='Vault.withdraw()'."""
    return access_control_of_impl(function, project)


@mcp.tool()
def slice_from(
    function: str,
    variable: str | None = None,
    direction: str = "backward",
    project: str | None = None,
) -> dict:
    """Deterministic program slice from an agent-chosen criterion. `function` is
    like 'Vault.withdraw()'; `variable` is a variable name in it (omit for a
    whole-node criterion); `direction` is 'backward' (what influences it) or
    'forward' (what it influences). Returns the full slice with byte-accurate
    source for every node, control/data/modifier-guard reasons, touched state and
    external calls."""
    return slice_from_impl(function, variable, direction, project)


@mcp.tool()
def find_callers(function: str, project: str | None = None) -> dict:
    """Direct internal callsites of a function (who calls it, and where)."""
    return find_callers_impl(function, project)


@mcp.tool()
def find_callees(function: str, project: str | None = None) -> dict:
    """Functions and external calls invoked by a function."""
    return find_callees_impl(function, project)


@mcp.tool()
def explain_dependence(node_a_id: str, node_b_id: str, project: str | None = None) -> dict:
    """Are two slice nodes connected in the PDG, and by what path? Node ids look
    like 'Vault.withdraw()#5' (as returned in slice nodes). Returns one bounded
    dependence path, or that they are unconnected. Same function only (v1)."""
    return explain_dependence_impl(node_a_id, node_b_id, project)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
