"""Seed-prompt assembly for the inspection sub-agent.

The seed does three jobs: hand over the deterministic facts the engine already
computed (so the agent never re-derives structure Slither knows), constrain the
agent to the opaque seam and to navigating with the slicer's own tools, and
mandate a single JSON verdict conforming to the frozen schema.

For the ``delegatecall`` boundary specifically, the seed carries the proxy's
*ordered* state variables (declaration order + type — not slot math): per the
project decision, the agent reasons about slot packing itself rather than the
engine adding a deterministic slot primitive. The agent obtains the
implementation's layout from source via its read tools / the slicer instance.
"""

from __future__ import annotations

import json
from typing import Any

_PREAMBLE = """\
You are a Solidity security sub-agent inside a static-analysis pipeline. A
deterministic slicer has already done all the structural analysis it can; your
ONLY job is to reason across the `delegatecall` boundary it cannot cross.

Rules:
- DO NOT re-derive facts you are given below — they are authoritative.
- DO NOT grep-and-guess. Navigate with the `mcp__slicer__*` tools (slice_from,
  audit_overview, state_var_xref, find_callees, find_callers, list_functions,
  list_contracts, explain_dependence). These compile the whole project and return
  byte-exact `source` for any contract/function — get the implementation's code and
  layout through them (e.g. `audit_overview`/`list_functions`/`slice_from` on the
  implementation contract). Do NOT rely on reading files from disk.
- Cite EVERY claim with a node_id and the byte-exact source (the slicer returns
  `source` blocks you can copy verbatim).
- If you cannot resolve something, record it under "unresolved" — never guess.
"""

_TASK = """\
Your task:
1. Resolve which implementation contract this delegatecall actually executes. If
   the address is set at runtime and not statically knowable, mark the target
   resolution "runtime-set" or "unknown" — do NOT invent a target.
2. Compare the proxy's storage layout to the implementation's, slot by slot.
   Report any collision (a different variable occupying the same storage slot).
   Account for variable packing and inheritance order yourself.
3. Check whether the implementation exposes unprotected initialization or admin
   functions reachable through the delegatecall.
4. Check whether the delegatecall target address is attacker-influenceable.
"""


def _output_contract(schema: dict[str, Any]) -> str:
    return (
        "Respond with EXACTLY ONE fenced ```json block conforming to this schema, "
        "and nothing after it:\n\n```json\n"
        + json.dumps(schema, indent=2)
        + "\n```\n"
    )


def build_delegatecall_seed(
    *,
    criterion_node_id: str,
    delegatecall_call: dict,
    proxy_contract: str,
    proxy_state_vars: list[dict],
    slice_json: dict,
    schema: dict[str, Any],
) -> str:
    """Assemble the full seed prompt for ``inspect_delegatecall``."""
    facts = {
        "criterion_node_id": criterion_node_id,
        "delegatecall_site": delegatecall_call,
        "proxy_contract": proxy_contract,
        "proxy_state_vars_in_declaration_order": proxy_state_vars,
        "backward_slice_of_the_delegatecall": slice_json,
    }
    return (
        _PREAMBLE
        + "\nDeterministic facts (authoritative — do not contradict):\n```json\n"
        + json.dumps(facts, indent=2)
        + "\n```\n\n"
        + _TASK
        + "\n"
        + _output_contract(schema)
    )
