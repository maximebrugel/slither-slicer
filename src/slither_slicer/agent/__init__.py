"""Opt-in LLM sub-agent layer for slither-slicer.

This package is never imported on the default path. It registers *only* when
``SLITHER_SLICER_ENABLE_AGENT=1`` (see :mod:`slither_slicer.mcp_server`). The
admissibility principle: an agent is allowed only where deterministic analysis has
already bottomed out and the engine emitted a marker instead of a fact — starting
with the ``delegatecall`` boundary. The agent is seeded with the engine's facts and
navigates with a fresh, read-only slicer instance; its verdict is structured, every
claim tied to a node_id + byte-exact source, and unresolved items are marked, never
guessed.
"""

from __future__ import annotations


def register_agent_tools(server) -> None:
    """Register the agentic tools on ``server`` (the FastMCP instance). The
    handlers resolve projects and slicers through :mod:`slither_slicer.mcp_server`'s
    cached helpers, so no provider needs to be threaded in.

    Imports are local so that merely importing this package — e.g. for the
    deterministic seed/dry-run/config helpers in tests — does not require the MCP
    server to be constructed."""
    from ..mcp_server import _resolve_project
    from . import tools

    @server.tool()
    def inspect_delegatecall(
        node_id: str, project: str | None = None, dry_run: bool = False
    ) -> dict:
        """Agentic inspection of a `delegatecall` boundary the deterministic slicer
        cannot cross. Seeds an LLM sub-agent with the engine's facts (the backward
        slice of the delegatecall site, the proxy's ordered storage layout) and lets
        it reason across the seam: implementation resolution, storage-layout
        collision, unprotected init/admin reachable through the delegatecall, and
        target controllability. The sub-agent navigates with a read-only slicer
        instance and returns a structured verdict; every claim is tied to a node_id
        and byte-exact source, and anything it cannot resolve is marked under
        `unresolved`, never guessed. `node_id` is the delegatecall site (e.g.
        'Proxy.exec(bytes)#2'). Pass `dry_run=true` to get the seed prompt without
        spending tokens (always allowed). A live run is fail-closed: it returns
        `status` 'blocked' unless SLITHER_SLICER_AGENT_ALLOW_SHELL=1 is set (the
        installed Kimi can't be restricted to read-only tools in print mode and the
        analyzed code is untrusted). Returns 'unavailable' if `kimi` is absent or not
        logged in."""
        return tools.inspect_delegatecall(node_id, _resolve_project(project), dry_run=dry_run)

    @server.tool()
    def check_state_invariant(
        contract: str,
        state_var: str,
        related: list[str] | None = None,
        project: str | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Agentic check of the state invariant(s) a variable participates in — the
        semantic bug class (accounting drift, share inflation, under-collateralization)
        static analysis can't pattern-match. Built on `state_var_xref`'s COMPLETE writer
        set: the sub-agent is handed every writer of `state_var` (each pre-tagged guarded
        / entry_point) plus the complete writer sets of same-type siblings and any
        caller-named `related` vars, and does the one thing the engine can't — name the
        intended invariant and decide which writers break it. It cannot under-count
        mutation sites (every writer is given; coverage is machine-enforced); the
        validator also rejects any finding citing a node outside the deterministic set.
        Returns a verdict whose headline `hypothesized_invariants` a human accepts or
        rejects before trusting findings, with a `completeness_caveat` when inline
        assembly may hide `sstore` writes. `dry_run=true` returns the seed without
        spending tokens (always allowed); a live run is fail-closed behind
        SLITHER_SLICER_AGENT_ALLOW_SHELL=1, returns 'no-writers' for an unwritten
        variable, and 'unavailable' if `kimi` is absent or not logged in. e.g.
        contract='Vault', state_var='totalSupply', related=['balances']."""
        return tools.check_state_invariant(
            contract, state_var, _resolve_project(project), related=related, dry_run=dry_run
        )


__all__ = ["register_agent_tools"]
