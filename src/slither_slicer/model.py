"""Core data model for slices.

Every node in a slice carries an exact, byte-accurate :class:`SourceRef` so the
agent layer can always recover real source bytes rather than an LLM paraphrase.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slither.core.cfg.node import Node

    from .criteria import SliceCriterion


@lru_cache(maxsize=64)
def _read_file_bytes_cached(filename: str, mtime_ns: int, size: int) -> bytes:
    with open(filename, "rb") as fh:
        return fh.read()


def _read_file_bytes(filename: str) -> bytes:
    # Keyed on (mtime, size) so an edited-and-recompiled file is re-read — a
    # filename-only cache would splice new byte offsets into stale bytes.
    st = os.stat(filename)
    return _read_file_bytes_cached(filename, st.st_mtime_ns, st.st_size)


@dataclass(frozen=True)
class SourceRef:
    """A byte-accurate reference into a source file."""

    filename: str  # absolute path
    start: int  # byte offset
    length: int  # bytes
    lines: list[int]  # 1-indexed source lines
    code: str  # exact source text for this span

    @classmethod
    def from_node(cls, node: Node) -> SourceRef:
        sm = node.source_mapping
        filename = sm.filename.absolute
        try:
            raw = _read_file_bytes(filename)
            code = raw[sm.start : sm.start + sm.length].decode("utf-8", errors="replace")
        except OSError:
            code = ""
        return cls(
            filename=filename,
            start=sm.start,
            length=sm.length,
            lines=list(sm.lines),
            code=code,
        )

    def to_json(self) -> dict:
        return {
            "filename": self.filename,
            "start": self.start,
            "length": self.length,
            "lines": self.lines,
            "code": self.code,
        }


@dataclass
class SliceNode:
    node_id: str  # stable id: f"{function.canonical_name}#{node.node_id}"
    function: str  # canonical name of declaring function/modifier
    ntype: str  # NodeType name (IF, EXPRESSION, RETURN, ...)
    ir: list[str]  # str() of each SSA op on this node (for the agent)
    source: SourceRef
    reason: str  # "criterion" | "data-dep" | "control-dep" | "modifier-guard" | "callee"

    def to_json(self) -> dict:
        return {
            "node_id": self.node_id,
            "function": self.function,
            "ntype": self.ntype,
            "ir": self.ir,
            "reason": self.reason,
            "source": self.source.to_json(),
        }


@dataclass
class Slice:
    criterion: SliceCriterion
    nodes: list[SliceNode] = field(default_factory=list)  # ordered by source position
    functions_touched: list[str] = field(default_factory=list)
    state_vars_read: list[str] = field(default_factory=list)
    state_vars_written: list[str] = field(default_factory=list)
    state_var_types: dict[str, str] = field(default_factory=dict)  # name -> declared type
    external_calls: list[str] = field(default_factory=list)  # opaque boundaries hit
    calls: list[dict] = field(default_factory=list)  # every call, classified (see calls.py)
    guarded: bool = False  # does the criterion's function restrict its caller?
    events_emitted: list[dict] = field(default_factory=list)  # {name, location}
    entry_points: list[str] = field(default_factory=list)  # external fns reaching the criterion
    notes: list[str] = field(default_factory=list)  # limitations triggered

    def to_source(self) -> str:
        """Minimal reconstruction: the source spans of every included node,
        grouped by function and ordered by source position.

        This is intentionally a best-effort reconstruction (not guaranteed to
        compile) — it gives the agent and a human reviewer the exact relevant
        bytes with just enough scaffolding to read them in context.
        """
        out: list[str] = []
        by_func: dict[str, list[SliceNode]] = {}
        for n in self.nodes:
            by_func.setdefault(n.function, []).append(n)

        for func, fnodes in by_func.items():
            out.append(f"// --- {func} ---")
            seen_spans: set[tuple[int, int]] = set()
            for n in sorted(fnodes, key=lambda x: x.source.start):
                key = (n.source.start, n.source.length)
                if key in seen_spans:
                    continue
                seen_spans.add(key)
                code = n.source.code.strip()
                if not code:
                    continue
                line = n.source.lines[0] if n.source.lines else 0
                out.append(f"    {code}    // L{line} [{n.reason}]")
            out.append("")
        return "\n".join(out).rstrip() + "\n"

    def to_json(self) -> dict:
        return {
            "criterion": self.criterion.to_json(),
            "guarded": self.guarded,
            "functions_touched": self.functions_touched,
            "entry_points": self.entry_points,
            "state_vars_read": self.state_vars_read,
            "state_vars_written": self.state_vars_written,
            "state_var_types": self.state_var_types,
            "external_calls": self.external_calls,
            "calls": self.calls,
            "events_emitted": self.events_emitted,
            "notes": self.notes,
            "nodes": [n.to_json() for n in self.nodes],
        }
