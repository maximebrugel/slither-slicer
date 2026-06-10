"""Compile a project and build the Slither object.

Slither is the source of truth; this module is only responsible for getting a
project to compile (the annoying part for real-world Solidity, which spans many
``solc`` versions) and handing back a ready :class:`~slither.Slither` instance.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from slither import Slither
from slither.core.declarations import Contract

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _detect_pragma_version(target: str) -> str | None:
    """Best-effort: read the first concrete version out of a ``pragma`` line.

    Only used as a hint for ``solc-select`` when the caller did not pin a
    version; a caret/range pragma resolves to its floor, which compiles in the
    common case.
    """
    path = Path(target)
    files = [path] if path.is_file() else list(path.rglob("*.sol"))
    for f in files[:50]:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        m = _PRAGMA_RE.search(text)
        if m:
            v = _VERSION_RE.search(m.group(1))
            if v:
                return v.group(1)
    return None


def _select_solc(version: str) -> None:
    """Install (if needed) and select ``version`` via solc-select. Failures are
    non-fatal — crytic-compile may still find a usable compiler."""
    try:
        subprocess.run(
            ["solc-select", "install", version],
            check=False,
            capture_output=True,
            timeout=300,
        )
        subprocess.run(
            ["solc-select", "use", version],
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        pass


class Loader:
    """Compiles ``target`` and exposes the resulting Slither object."""

    def __init__(self, target: str, solc_version: str | None = None, auto_solc: bool = True):
        self.target = target
        version = solc_version
        if version is None and auto_solc:
            version = _detect_pragma_version(target)
        if version:
            _select_solc(version)
        self.slither = Slither(target)

    def contract(self, name: str) -> Contract:
        matches = self.slither.get_contract_from_name(name)
        if not matches:
            available = ", ".join(sorted(c.name for c in self.slither.contracts))
            raise ValueError(f"contract {name!r} not found. available: {available}")
        return matches[0]

    @property
    def contracts(self) -> list[Contract]:
        return list(self.slither.contracts_derived)
