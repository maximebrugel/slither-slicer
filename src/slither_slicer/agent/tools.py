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
from .schema import VERDICT_SCHEMA, VerdictError, validate_verdict

# Bounded so the seed stays well within context even for a large proxy.
_SLICE_MAX_NODES = 60

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
        return {
            "status": "blocked",
            "criterion_node_id": node_id,
            "note": (
                "live agent run is disabled. The installed Kimi CLI auto-approves "
                "tool calls in print mode and exposes shell/write tools that cannot "
                "be disabled, so a read-only guarantee is not possible — and the "
                "analyzed Solidity is untrusted (prompt-injection -> shell = RCE). "
                f"Use dry_run to inspect the seed, or set {_ALLOW_SHELL_ENV}=1 to run "
                "anyway on a trusted target in a sandboxed environment."
            ),
        }

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
