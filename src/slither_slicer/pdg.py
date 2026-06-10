"""Per-function Program Dependence Graph.

A PDG bundles, for a single function, everything the slicer needs:
- the SSA def/use maps (data dependence, :mod:`dependence.data`)
- control-parent edges (control dependence, :mod:`dependence.control`)

The slicer (:mod:`slicer`) does reachability over this; nothing here makes
slicing decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING

from .dependence.control import control_parents
from .dependence.data import DefSite, build_def_map, build_use_map

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.declarations import Function


@dataclass
class PDG:
    function: Function
    def_map: dict[int, DefSite] = field(default_factory=dict)
    use_map: dict[int, list[DefSite]] = field(default_factory=dict)
    control_parents: dict = field(default_factory=dict)  # Node -> set[Node]

    def def_site(self, ssa_var) -> DefSite | None:
        return self.def_map.get(id(ssa_var))

    def use_sites(self, ssa_var) -> list[DefSite]:
        return self.use_map.get(id(ssa_var), [])

    def guards_of(self, node: Node) -> set:
        return self.control_parents.get(node, set())


@lru_cache(maxsize=256)
def build_pdg(function: Function) -> PDG:
    """Build (and cache) the PDG for ``function``.

    Caching is keyed on the Slither ``Function`` object, which is stable for the
    lifetime of a compiled :class:`~slither.Slither` instance.
    """
    return PDG(
        function=function,
        def_map=build_def_map(function),
        use_map=build_use_map(function),
        control_parents=control_parents(function),
    )
