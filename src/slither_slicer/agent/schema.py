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


class VerdictError(ValueError):
    """A verdict that does not conform to :data:`VERDICT_SCHEMA`."""


def validate_verdict(obj: Any) -> dict:
    """Validate ``obj`` against the frozen verdict schema, returning it unchanged
    on success and raising :class:`VerdictError` on any non-conformance.

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
        jsonschema.validate(obj, VERDICT_SCHEMA)
    except jsonschema.ValidationError as e:
        raise VerdictError(f"verdict does not conform to schema: {e.message}") from e
    return obj
