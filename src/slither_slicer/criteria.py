"""The slicing criterion: what to slice, in which direction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slither.core.cfg.node import Node
    from slither.core.variables.variable import Variable


class Direction(Enum):
    BACKWARD = auto()  # statements that influence the criterion
    FORWARD = auto()  # statements influenced by the criterion


@dataclass
class SliceCriterion:
    node: Node  # Slither CFG node
    variable: Variable | None  # None = whole-node criterion
    direction: Direction
    origin: str | None = None  # e.g. "sink:ether_transfer", "source:msg.sender"

    @property
    def function_name(self) -> str:
        return self.node.function.canonical_name

    @property
    def variable_name(self) -> str | None:
        return str(self.variable) if self.variable is not None else None

    def to_json(self) -> dict:
        return {
            "function": self.function_name,
            "variable": self.variable_name,
            "direction": self.direction.name,
            "origin": self.origin,
        }
