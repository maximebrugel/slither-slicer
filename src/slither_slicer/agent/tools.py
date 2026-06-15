"""Agentic-inspection tool handlers.

The handler is deterministic scaffolding around one non-deterministic call: it
seeds the agent with what the engine already knows, drives Kimi with a read-only
slicer as its toolset, and validates the result against the frozen schema. Any
deviation — missing delegatecall, bad JSON, schema violation, no `kimi`, not
logged in — returns a structured ``status`` rather than a fabricated finding.
"""

from __future__ import annotations

import os
import shutil

from .. import mcp_server as m
from . import prompts, runner
from .kimi_config import write_kimi_home
from .schema import (
    INVARIANT_VERDICT_SCHEMA,
    VERDICT_SCHEMA,
    VerdictError,
    assert_evidence_within_writer_set,
    assert_writer_coverage,
    validate_verdict,
)

# Bounded so the seed stays well within context even for a large proxy.
_SLICE_MAX_NODES = 60
# Per-writer slices for check_state_invariant — kept tight since there is one per writer.
_WRITE_SLICE_MAX = 40
# Same-type sibling pre-load is capped; the agent can pull any dropped one on demand.
_MAX_RELATED = 12

# Live execution is gated. The installed Kimi CLI (v0.14.3) auto-approves tool calls
# in print mode (`-p`) and exposes shell/write builtins (Bash/Write/Edit) that no
# CLI flag or config can disable on this version — so a hard read-only toolset
# cannot be guaranteed. The analyzed Solidity is *untrusted* input, which makes a
# prompt-injection -> auto-approved-shell path a real RCE vector. So we fail closed:
# `dry_run` always works, but spawning Kimi requires the operator to acknowledge the
# residual risk by exporting SLITHER_SLICER_AGENT_ALLOW_SHELL=1 (intended for a
# trusted target in a sandboxed environment). Defense-in-depth when enabled: an
# isolated $KIMI_CODE_HOME registering only a read-only slicer, an isolated cwd
# outside the user's tree, and a read-only seed instruction.
_ALLOW_SHELL_ENV = "SLITHER_SLICER_AGENT_ALLOW_SHELL"
_TIMEOUT_ENV = "SLITHER_SLICER_AGENT_TIMEOUT"
_DEFAULT_TIMEOUT_S = 300


def _blocked(**extra) -> dict:
    """The fail-closed status returned when a live run is requested without the
    operator acknowledging the unsandboxed-toolset risk (shared by all agent tools)."""
    return {
        "status": "blocked",
        **extra,
        "note": (
            "live agent run is disabled. The installed Kimi CLI auto-approves tool "
            "calls in print mode and exposes shell/write tools that cannot be disabled, "
            "so a read-only guarantee is not possible — and the analyzed Solidity is "
            "untrusted (prompt-injection -> shell = RCE). Use dry_run to inspect the "
            f"seed, or set {_ALLOW_SHELL_ENV}=1 to run anyway on a trusted target in a "
            "sandboxed environment."
        ),
    }


def ordered_state_vars(slicer, contract_name: str) -> list[dict]:
    """A contract's storage-occupying state variables in declaration order, with
    types — declaration order + type only, NOT slot computation (the agent reasons
    about packing). Constants/immutables hold no storage slot and are excluded."""
    c = slicer._contract(contract_name)
    ordered = getattr(c, "state_variables_ordered", None) or c.state_variables
    out = []
    for sv in ordered:
        if getattr(sv, "is_constant", False) or getattr(sv, "is_immutable", False):
            continue
        out.append({"name": sv.name, "type": str(sv.type)})
    return out


def build_seed(node_id: str, project: str) -> str:
    """Assemble the deterministic seed prompt for a delegatecall site, or raise
    ``ValueError`` if ``node_id`` is not a delegatecall site."""
    sl = m._get_slicer(project)
    blob = m.slice_from_impl(node_id=node_id, project=project, max_nodes=_SLICE_MAX_NODES)
    dc = next((c for c in blob["calls"] if c.get("kind") == "delegatecall"), None)
    if dc is None:
        raise ValueError(f"{node_id} is not a delegatecall site")

    proxy_contract = node_id.split(".", 1)[0]
    return prompts.build_delegatecall_seed(
        criterion_node_id=node_id,
        delegatecall_call=dc,
        proxy_contract=proxy_contract,
        proxy_state_vars=ordered_state_vars(sl, proxy_contract),
        slice_json=blob,
        schema=VERDICT_SCHEMA,
    )


def inspect_delegatecall(node_id: str, project: str, *, dry_run: bool = False) -> dict:
    """Drive the sub-agent across a delegatecall boundary. ``project`` is an
    already-resolved path. See the registered tool docstring for behaviour."""
    # 1. Deterministic seed — reuse what the engine already computed.
    try:
        seed = build_seed(node_id, project)
    except ValueError as e:
        return {"status": "error", "note": str(e)}

    # 2. dry_run mirrors the CLI's --pdg: return the seed without spending tokens.
    if dry_run:
        return {"dry_run": True, "criterion_node_id": node_id, "seed_prompt": seed}

    # 3. Fail closed: live execution can't guarantee a read-only toolset on this
    #    Kimi version, and the analyzed code is untrusted. Require explicit opt-in.
    if os.environ.get(_ALLOW_SHELL_ENV) != "1":
        return _blocked(criterion_node_id=node_id)

    # 4. Drive Kimi with a read-only slicer as its toolset, in an isolated home.
    timeout_s = int(os.environ.get(_TIMEOUT_ENV) or _DEFAULT_TIMEOUT_S)
    home = write_kimi_home(project)
    try:
        result = runner.run_kimi(prompt=seed, kimi_home=home, timeout_s=timeout_s)
    except runner.KimiUnavailable as e:
        return {"status": "unavailable", "note": str(e)}
    except runner.KimiTimeout as e:
        return {"status": "timeout", "note": str(e)}
    except runner.KimiBadOutput as e:
        return {"status": "error", "note": str(e)}
    finally:
        shutil.rmtree(home, ignore_errors=True)

    # 5. Fail closed: validate against the frozen schema before returning anything.
    try:
        verdict = validate_verdict(result.verdict)
    except VerdictError as e:
        return {"status": "error", "note": str(e)}
    verdict.setdefault("tool", "inspect_delegatecall")
    verdict.setdefault("criterion_node_id", node_id)
    verdict["tools_used"] = runner.tool_names(result.tool_calls)
    return verdict


# --------------------------------------------------------------------------- #
# check_state_invariant — semantic reasoning on a complete deterministic substrate
# --------------------------------------------------------------------------- #
def _real_writer(w: dict) -> bool:
    """Exclude Slither's synthetic constant/default-initialization functions
    (``slitherConstructor*``): those are declaration-site artifacts, not runtime
    mutation sites a caller/attacker can trigger."""
    return "slitherConstructor" not in w["function"]


def _related_names(sl, contract: str, state_var: str, caller_related: tuple) -> list[str]:
    """Relational partners: caller-supplied UNION same-Solidity-type siblings (e.g.
    every other `mapping(address => uint256)`), minus the target itself. Constants and
    immutables hold no mutable storage, so they are never auto-seeded as siblings."""
    c = sl._contract(contract)
    target = next((v for v in c.state_variables if v.name == state_var), None)
    names = set(caller_related)
    if target is not None:
        ttype = str(target.type)
        names |= {
            v.name
            for v in c.state_variables
            if str(v.type) == ttype
            and not getattr(v, "is_constant", False)
            and not getattr(v, "is_immutable", False)
        }
    names.discard(state_var)
    return sorted(names)


def _completeness_caveat(sl, contract: str) -> str | None:
    """Surface where the 'complete writer set' may have holes (the safety argument
    must be honest). Slither attributes writes via ``node.state_variables_written``,
    which does not see inline-assembly ``sstore`` or writes performed by another
    contract delegatecalling into this storage. Detect inline assembly deterministically.
    """
    c = sl._contract(contract)
    has_assembly = any(
        n.type.name == "ASSEMBLY" for f in c.functions_and_modifiers for n in f.nodes
    )
    if has_assembly:
        return (
            "contract contains inline assembly; storage writes via `sstore` (and any "
            "writes performed by another contract delegatecalling into this storage) "
            "are not attributed by Slither and may be missing from the writer set — "
            "treat completeness as best-effort and lower confidence accordingly."
        )
    return None


def _writer_row(project: str, w: dict) -> dict:
    return {
        "node_id": w["node_id"],
        "function": w["function"],
        "guarded": w["guarded"],
        "entry_point": w["is_entry_point"],
        "location": w["location"],
        # backward slice of the write: byte-exact source + what influences the value
        "write_slice": m.slice_from_impl(
            node_id=w["node_id"], project=project, max_nodes=_WRITE_SLICE_MAX
        ),
    }


def _invariant_seed_facts(project: str, contract: str, state_var: str, related: tuple) -> dict:
    """The deterministic seed: the COMPLETE writer set of ``state_var`` (each tagged
    guarded / entry_point, with its write slice), plus the complete writer sets of
    related variables, plus an honest completeness caveat. Raises ``ValueError`` for
    an unknown contract/variable (incl. a bad caller-supplied ``related`` name)."""
    sl = m._get_slicer(project)
    xref = sl.state_var_xref(contract, state_var)  # complete (as attributed by Slither)
    writers = [_writer_row(project, w) for w in xref["writers"] if _real_writer(w)]

    rel_all = _related_names(sl, contract, state_var, related)
    notes: list[str] = []
    rel_names = rel_all
    if len(rel_all) > _MAX_RELATED:
        keep = list(related) + [n for n in rel_all if n not in related]
        rel_names = keep[:_MAX_RELATED]
        dropped = [n for n in rel_all if n not in rel_names]
        notes.append(
            f"same-type sibling set capped at {_MAX_RELATED}; dropped {dropped} "
            "(pull via mcp__slicer__state_var_xref if a relation needs one)"
        )
    related_sets = {
        v: [
            {k: w[k] for k in ("node_id", "function", "guarded", "is_entry_point")}
            for w in sl.state_var_xref(contract, v)["writers"]
            if _real_writer(w)
        ]
        for v in rel_names
    }
    return {
        "contract": contract,
        "state_var": state_var,
        "var_type": xref["type"],
        "writers": writers,  # the exhaustive set
        "readers": [r["node_id"] for r in xref["readers"]],
        "related": related_sets,
        "completeness_caveat": _completeness_caveat(sl, contract),
        "notes": notes,
    }


def _allowed_node_ids(project: str, contract: str) -> set[str]:
    """Every writer + reader node_id across all state vars of the contract — the
    deterministic set a finding may cite. Admits agent-pulled related variables (they
    are writers of other vars here) without depending on the audit trail."""
    sl = m._get_slicer(project)
    c = sl._contract(contract)
    allowed: set[str] = set()
    for sv in c.state_variables:
        try:
            xref = sl.state_var_xref(contract, sv.name)
        except ValueError:
            continue
        allowed |= {w["node_id"] for w in xref["writers"]}
        allowed |= {r["node_id"] for r in xref["readers"]}
    return allowed


def check_state_invariant(
    contract: str, state_var: str, project: str, *, related=None, dry_run: bool = False
) -> dict:
    """Drive the sub-agent to check the invariant(s) a state variable participates in.
    ``project`` is already-resolved. See the registered tool docstring for behaviour."""
    # 1. Deterministic seed — the COMPLETE writer set is the load-bearing substrate.
    try:
        facts = _invariant_seed_facts(project, contract, state_var, tuple(related or ()))
    except ValueError as e:
        return {"status": "error", "note": str(e)}
    if not facts["writers"]:
        return {
            "status": "no-writers",
            "note": f"{contract}.{state_var} is never written; nothing to check",
        }

    seed = prompts.build_invariant_seed(facts=facts, schema=INVARIANT_VERDICT_SCHEMA)

    # 2. dry_run: the seed without spending tokens (always allowed).
    if dry_run:
        return {
            "dry_run": True,
            "contract": contract,
            "state_var": state_var,
            "seed_prompt": seed,
        }

    # 3. Same fail-closed gate as inspect_delegatecall.
    if os.environ.get(_ALLOW_SHELL_ENV) != "1":
        return _blocked(contract=contract, state_var=state_var)

    # 4. Drive Kimi with a read-only slicer as its toolset, in an isolated home.
    timeout_s = int(os.environ.get(_TIMEOUT_ENV) or _DEFAULT_TIMEOUT_S)
    home = write_kimi_home(project)
    try:
        result = runner.run_kimi(prompt=seed, kimi_home=home, timeout_s=timeout_s)
    except runner.KimiUnavailable as e:
        return {"status": "unavailable", "note": str(e)}
    except runner.KimiTimeout as e:
        return {"status": "timeout", "note": str(e)}
    except runner.KimiBadOutput as e:
        return {"status": "error", "note": str(e)}
    finally:
        shutil.rmtree(home, ignore_errors=True)

    # 5. Fail closed: schema + the two completeness invariants (coverage, containment).
    try:
        verdict = validate_verdict(result.verdict, schema=INVARIANT_VERDICT_SCHEMA)
        if verdict.get("status") != "invariant-unknown":
            assert_writer_coverage(verdict, [w["node_id"] for w in facts["writers"]])
        assert_evidence_within_writer_set(verdict, _allowed_node_ids(project, contract))
    except VerdictError as e:
        return {"status": "error", "note": str(e)}

    verdict.setdefault("tool", "check_state_invariant")
    verdict.setdefault("contract", contract)
    verdict.setdefault("state_var", state_var)
    verdict["completeness_caveat"] = facts["completeness_caveat"]
    verdict["tools_used"] = runner.tool_names(result.tool_calls)
    return verdict
