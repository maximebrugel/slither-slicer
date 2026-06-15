"""The frozen verdict contract for agentic inspection tools.

This is the analogue, on the agent surface, of the slice JSON schema pinned in
``tests/test_model.py``: a structured shape every agentic tool must return, where
every claim is tied to a ``node_id`` + byte-exact ``source_ref``, and "I couldn't
resolve this" is a marked ``unresolved`` item — never a confident guess. The
``status`` / ``unresolved`` fields are how the project's "marked, never silently
dropped" discipline survives the introduction of a non-deterministic agent.

Validation is deliberately *fail-closed*: a verdict that does not conform raises,
and the handler turns that into an error status rather than passing a partial or
fabricated finding through to the orchestrator.
"""

from __future__ import annotations

from typing import Any

# A SourceRef on the verdict reuses the exact 5-key shape of model.SourceRef, so
# the agent's evidence is the same byte-accurate reference the deterministic layer
# emits — not an LLM paraphrase.
_SOURCE_REF = {
    "type": "object",
    "required": ["filename", "start", "length", "lines", "code"],
    "additionalProperties": True,
    "properties": {
        "filename": {"type": "string"},
        "start": {"type": "integer"},
        "length": {"type": "integer"},
        "lines": {"type": "array", "items": {"type": "integer"}},
        "code": {"type": "string"},
    },
}

VERDICT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["tool", "criterion_node_id", "status", "findings", "unresolved"],
    "additionalProperties": True,
    "properties": {
        "tool": {"type": "string"},
        "criterion_node_id": {"type": "string"},
        "status": {"enum": ["resolved", "unresolved", "partial"]},
        "target": {
            "type": ["object", "null"],
            "properties": {
                "resolution": {
                    "enum": ["static-single", "runtime-set", "ambiguous", "unknown"]
                },
                "contract": {"type": ["string", "null"]},
                "source_ref": {"anyOf": [_SOURCE_REF, {"type": "null"}]},
            },
            "additionalProperties": True,
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["kind", "severity", "claim", "evidence"],
                "additionalProperties": True,
                "properties": {
                    "kind": {
                        "enum": [
                            "storage-collision",
                            "unprotected-init",
                            "attacker-controlled-target",
                            "admin-overlap",
                            "none",
                        ]
                    },
                    "severity": {"enum": ["high", "medium", "low", "info"]},
                    "claim": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["node_id", "source_ref"],
                            "additionalProperties": True,
                            "properties": {
                                "node_id": {"type": "string"},
                                "source_ref": {"anyOf": [_SOURCE_REF, {"type": "null"}]},
                                "role": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "unresolved": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["note"],
                "additionalProperties": True,
                "properties": {
                    "note": {"type": "string"},
                    "at": {"type": "string"},
                },
            },
        },
        "tools_used": {"type": "array", "items": {"type": "string"}},
        "confidence": {"enum": ["high", "medium", "low"]},
    },
}


# Verdict contract for ``check_state_invariant`` (agent v2). Same frozen-contract
# discipline as VERDICT_SCHEMA. ``hypothesized_invariants`` is top-level and first —
# it is the risk surface a human accepts or rejects before trusting any finding;
# ``writer_dispositions`` is the machine-checkable coverage record (every writer in
# the complete set gets exactly one disposition — see assert_writer_coverage).
INVARIANT_VERDICT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": [
        "tool",
        "contract",
        "state_var",
        "status",
        "hypothesized_invariants",
        "writer_dispositions",
        "findings",
        "unresolved",
    ],
    "additionalProperties": True,
    "properties": {
        "tool": {"type": "string"},
        "contract": {"type": "string"},
        "state_var": {"type": "string"},
        "status": {"enum": ["checked", "invariant-unknown", "partial"]},
        "completeness_caveat": {"type": ["string", "null"]},
        "hypothesized_invariants": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "predicate", "kind", "confidence"],
                "additionalProperties": True,
                "properties": {
                    "id": {"type": "string"},
                    "predicate": {"type": "string"},
                    "inferred_from": {"type": "string"},
                    "kind": {"enum": ["relational", "bound", "monotonic", "conservation"]},
                    "confidence": {"enum": ["high", "medium", "low"]},
                },
            },
        },
        "writer_dispositions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["node_id", "disposition"],
                "additionalProperties": True,
                "properties": {
                    "node_id": {"type": "string"},
                    "disposition": {"enum": ["holds", "violates", "underconstrained"]},
                    "invariant_id": {"type": ["string", "null"]},
                },
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["kind", "severity", "writer_node_id", "claim", "evidence"],
                "additionalProperties": True,
                "properties": {
                    "kind": {"enum": ["invariant-violation", "underconstrained-setter"]},
                    "invariant_id": {"type": ["string", "null"]},
                    "severity": {"enum": ["high", "medium", "low", "info"]},
                    "writer_node_id": {"type": "string"},
                    "attacker_reachable": {"type": "boolean"},
                    "claim": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["node_id", "source_ref"],
                            "additionalProperties": True,
                            "properties": {
                                "node_id": {"type": "string"},
                                "source_ref": {"anyOf": [_SOURCE_REF, {"type": "null"}]},
                                "role": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "unresolved": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["note"],
                "additionalProperties": True,
                "properties": {"note": {"type": "string"}, "at": {"type": "string"}},
            },
        },
        "tools_used": {"type": "array", "items": {"type": "string"}},
        "confidence": {"enum": ["high", "medium", "low"]},
    },
}


class VerdictError(ValueError):
    """A verdict that does not conform to its frozen schema / completeness contract."""


def validate_verdict(obj: Any, schema: dict | None = None) -> dict:
    """Validate ``obj`` against a frozen verdict ``schema`` (default
    :data:`VERDICT_SCHEMA`), returning it unchanged on success and raising
    :class:`VerdictError` on any non-conformance.

    ``jsonschema`` is imported lazily so the rest of the agent package (prompt
    assembly, dry-run, config generation) works without the ``agent`` extra; only
    actually validating a live verdict requires it.
    """
    try:
        import jsonschema
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise VerdictError(
            "the `agent` extra is required to validate verdicts: uv sync --extra agent"
        ) from e

    if not isinstance(obj, dict):
        raise VerdictError(f"verdict must be a JSON object, got {type(obj).__name__}")
    try:
        jsonschema.validate(obj, schema or VERDICT_SCHEMA)
    except jsonschema.ValidationError as e:
        raise VerdictError(f"verdict does not conform to schema: {e.message}") from e
    return obj


def assert_writer_coverage(verdict: dict, writer_node_ids) -> dict:
    """Hard coverage check for ``check_state_invariant``: the set of node_ids in
    ``writer_dispositions`` must EQUAL the complete writer set the engine handed the
    agent — no skipped mutation site, no invented one. This is the machine-checkable
    expression of the completeness thesis; raises :class:`VerdictError` on mismatch.
    """
    dispositioned = {d.get("node_id") for d in verdict.get("writer_dispositions", [])}
    expected = set(writer_node_ids)
    missing = expected - dispositioned
    extra = dispositioned - expected
    if missing or extra:
        raise VerdictError(
            f"writer coverage incomplete — missing dispositions for {sorted(missing)}, "
            f"unexpected {sorted(extra)}: every writer in the complete set must get "
            "exactly one disposition (no skips, no inventions)"
        )
    return verdict


def assert_evidence_within_writer_set(verdict: dict, allowed_node_ids) -> dict:
    """Containment check: no finding may cite a node the engine never produced. A
    finding pinned to a node outside the deterministic writer/reader set is, by
    definition, a hallucinated mutation site. Raises :class:`VerdictError`.
    """
    allowed = set(allowed_node_ids)
    for f in verdict.get("findings", []):
        cited = {f["writer_node_id"]} if f.get("writer_node_id") else set()
        cited |= {ev["node_id"] for ev in f.get("evidence", []) if ev.get("node_id")}
        outside = cited - allowed
        if outside:
            raise VerdictError(
                f"finding cites {sorted(outside)} outside the deterministic "
                "writer/reader set — rejecting as hallucinated mutation site(s)"
            )
    return verdict
