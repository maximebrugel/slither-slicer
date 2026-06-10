"""Rendering helpers: a slice -> JSON / reconstructed source.

The per-slice logic lives on :class:`~slither_slicer.model.Slice`
(``to_json`` / ``to_source``); this module only adds top-level conveniences for
the CLI and for emitting collections of slices.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Slice


def to_json_str(sl: Slice, indent: int = 2) -> str:
    return json.dumps(sl.to_json(), indent=indent)


def slices_to_json(slices: list[Slice]) -> list[dict]:
    return [s.to_json() for s in slices]


def slices_to_json_str(slices: list[Slice], indent: int = 2) -> str:
    return json.dumps(slices_to_json(slices), indent=indent)


def to_source(sl: Slice) -> str:
    return sl.to_source()
