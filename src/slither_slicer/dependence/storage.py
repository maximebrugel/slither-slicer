"""Storage reverse-index: who reads / writes each state variable.

The slicer's data dependence is SSA def-use *within* a function. State variables
break that boundary: ``withdraw`` reads ``balances`` but the writers live in
*other* functions (``deposit``, ``slash``). v1 surfaced the names a slice touched
but never connected them — the #1 documented blind spot.

This index maps each state variable to its read and write sites across the whole
contract (inherited-inclusive), so the slicer can optionally stitch the writers of
a read variable into a backward slice (reason ``storage-dep``), and the
``state_var_xref`` tool can answer "who touches X" without a slice at all.

Keyed by ``canonical_name`` (a string), not SSA/object identity: a state variable
has one canonical name per contract, and ``Node.state_variables_read/written``
hands us the non-SSA :class:`StateVariable` directly — so there is no SSA-vs-non-SSA
identity question to get wrong.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from slither.core.cfg.node import NodeType

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Contract, Function
    from slither.core.variables.state_variable import StateVariable

_SCAFFOLDING = (NodeType.ENTRYPOINT, NodeType.PLACEHOLDER)

Site = tuple["Function", "Node"]


@dataclass(frozen=True)
class StorageXref:
    """Per-contract reverse index, keyed by state-variable canonical name."""

    writers: dict[str, list[Site]]
    readers: dict[str, list[Site]]


@lru_cache(maxsize=128)
def build_storage_xref(contract: Contract) -> StorageXref:
    """Build (once per contract, cached) the read/write site index over every
    function and modifier — inherited-inclusive, scaffolding nodes skipped."""
    writers: dict[str, list[Site]] = {}
    readers: dict[str, list[Site]] = {}
    for func in contract.functions_and_modifiers:
        for node in func.nodes:
            if node.type in _SCAFFOLDING:
                continue
            for sv in node.state_variables_written:
                writers.setdefault(sv.canonical_name, []).append((func, node))
            for sv in node.state_variables_read:
                readers.setdefault(sv.canonical_name, []).append((func, node))
    return StorageXref(writers=writers, readers=readers)


def writers_of(contract: Contract, state_var: StateVariable) -> list[Site]:
    return build_storage_xref(contract).writers.get(state_var.canonical_name, [])


def readers_of(contract: Contract, state_var: StateVariable) -> list[Site]:
    return build_storage_xref(contract).readers.get(state_var.canonical_name, [])
