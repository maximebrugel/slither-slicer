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


# --------------------------------------------------------------------------- #
# check_state_invariant
# --------------------------------------------------------------------------- #
_INVARIANT_PREAMBLE = """\
You are a Solidity invariant-analysis sub-agent inside a static-analysis pipeline. A
deterministic slicer has given you the COMPLETE set of writers of a state variable.
Your job is the one thing it cannot do: state the invariant the code is meant to
preserve, and decide which writers break it.

COMPLETENESS CONTRACT (do not violate):
- The writer set below is EXHAUSTIVE. Do NOT grep source to look for other writers.
- To bring in a related variable, call mcp__slicer__state_var_xref on it — that returns
  its COMPLETE writer set too. Read source ONLY to understand a write's logic, never to
  discover a write.
- If you believe a write exists outside the given sets, that is a slicer bug: record it
  under "unresolved". Do NOT invent it as a finding.
- Honor `completeness_caveat`: when it is non-null the writer set may be incomplete
  (e.g. inline-assembly `sstore`, or writes by another contract delegatecalling into
  this storage) — lower your confidence and note the gap under "unresolved".
"""

_INVARIANT_TASK = """\
Your task:
1. Hypothesize the invariant(s) this variable participates in — from its name, type, and
   what the writers do. Prioritise RELATIONAL invariants (e.g. a supply total that must
   equal the sum of per-account balances). State each as a checkable predicate, with what
   you inferred it from and a confidence.
2. Emit a disposition for EVERY writer in the complete set: holds | violates |
   underconstrained. Use the attached guarded / entry_point flags — do not re-derive
   them. `writer_dispositions` MUST cover exactly the given writer node_ids (no more, no
   fewer).
3. A "invariant-violation" finding requires a writer that breaks an invariant AND is
   attacker-reachable (entry_point and not adequately guarded). A writer that breaks it
   but is admin-only is at most "underconstrained-setter".
4. Cite every claim with the writer's node_id and byte-exact source (copy the `source`
   from the writer's write_slice). If naming/usage is too opaque to infer any invariant,
   return status "invariant-unknown".
"""


def build_invariant_seed(*, facts: dict, schema: dict[str, Any]) -> str:
    """Assemble the full seed prompt for ``check_state_invariant``. ``facts`` is the
    deterministic seed from :func:`slither_slicer.agent.tools._invariant_seed_facts`
    (the complete writer set + related sets + completeness caveat)."""
    return (
        _INVARIANT_PREAMBLE
        + "\nDeterministic facts (authoritative — the writer set is COMPLETE):\n```json\n"
        + json.dumps(facts, indent=2)
        + "\n```\n\n"
        + _INVARIANT_TASK
        + "\n"
        + _output_contract(schema)
    )
