"""Generate an isolated, read-only Kimi home for an inspection sub-agent.

The seam this opens has to stay deterministic *inside*: the sub-agent navigates
with a fresh slither-slicer MCP instance (its toolset) and reads source — nothing
that can write, exec, or recurse. We enforce that two ways:

1. **A relocated ``$KIMI_CODE_HOME``** (a temp dir) holding our own ``mcp.json`` and
   ``config.toml`` — so we never mutate the user's real Kimi config — that registers
   exactly one MCP server: a slicer instance with ``SLITHER_SLICER_ENABLE_AGENT=0``
   (the inner instance is purely deterministic and cannot spawn its own sub-agent).
2. **``default_plan_mode = true``** in that config: plan mode exposes only read-only
   tools (no Bash/Write/Edit). This is the REAL read-only lever in print mode —
   ``kimi -p`` auto-approves tool calls and (in v0.14.3) cannot take
   ``--plan``/``--yolo``/``--auto`` on the CLI, so ``[[permission.rules]]`` do not
   gate it; we still append an allow-slicer/deny-rest rule set as defense-in-depth.

The OAuth credential lives under the real home, so we copy it into the isolated
home; otherwise the relocated home would fail ``kimi login``'s token lookup.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path

# Read builtins the sub-agent legitimately needs to inspect the opaque impl source.
# Everything not listed (Shell, Write, Edit, …) falls through to the catch-all deny.
_ALLOWED_BUILTINS = ("Read", "Grep", "Glob", "List", "LS")

# Home entries that carry login state — copied into the relocated home so auth
# survives the $KIMI_CODE_HOME relocation. v0.14.3 stores the OAuth token in
# `credentials/` (older builds used `oauth/`); `device_id` identifies the install.
_CREDENTIAL_ENTRIES = ("credentials", "oauth", "device_id")


def real_kimi_home() -> str:
    """The user's actual Kimi home (where the OAuth credential lives)."""
    return os.environ.get("KIMI_CODE_HOME") or os.path.expanduser("~/.kimi-code")


def _repo_root() -> str:
    """Walk up from this file to the checkout root (the dir with pyproject.toml),
    so the inner slicer launches the same way the repo's `.mcp.json` does."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return str(parent)
    return str(here.parents[3])  # src/slither_slicer/agent/kimi_config.py -> root


def _permission_rules(server_name: str) -> str:
    lines = [
        "",
        "# --- read-only posture injected by slither-slicer agent layer ---",
        "[[permission.rules]]",
        'decision = "allow"',
        f'pattern = "mcp__{server_name}__*"',
    ]
    for tool in _ALLOWED_BUILTINS:
        lines += ["", "[[permission.rules]]", 'decision = "allow"', f'pattern = "{tool}"']
    # Catch-all: any tool not explicitly allowed (Shell/Write/Edit, other MCP) is denied.
    lines += ["", "[[permission.rules]]", 'decision = "deny"', 'pattern = "**"', ""]
    return "\n".join(lines)


def mcp_servers_config(project: str, server_name: str = "slicer") -> dict:
    """The ``mcp.json`` payload registering the inner read-only slicer instance.

    Critically sets ``SLITHER_SLICER_ENABLE_AGENT=0`` so the inner instance is
    purely deterministic and cannot recurse into another sub-agent. The project
    path is made absolute so it resolves regardless of the sub-agent's cwd (which
    is an isolated temp dir, deliberately outside the user's tree)."""
    return {
        "mcpServers": {
            server_name: {
                "command": "uv",
                "args": [
                    "run",
                    "--directory",
                    _repo_root(),
                    "--extra",
                    "mcp",
                    "slither-slicer-mcp",
                ],
                "env": {
                    "SLITHER_SLICER_PROJECT": os.path.abspath(project),
                    "SLITHER_SLICER_ENABLE_AGENT": "0",
                },
            }
        }
    }


def write_kimi_home(
    project: str,
    *,
    server_name: str = "slicer",
    base_home: str | None = None,
) -> str:
    """Materialise an isolated ``$KIMI_CODE_HOME`` and return its path.

    The caller is responsible for cleanup (``shutil.rmtree``). ``base_home`` is the
    real home to inherit provider/model/OAuth config from (defaults to
    :func:`real_kimi_home`).
    """
    import json

    base = base_home or real_kimi_home()
    home = tempfile.mkdtemp(prefix="slither-kimi-home-")

    # 1. mcp.json — the sub-agent's deterministic toolset.
    (Path(home) / "mcp.json").write_text(
        json.dumps(mcp_servers_config(project, server_name), indent=2)
    )

    # 2. config.toml — inherit provider/model/OAuth wiring, then enforce read-only.
    #    The REAL lever in print mode is `default_plan_mode = true`: print mode
    #    cannot take --plan/--yolo/--auto and auto-approves tool calls, so
    #    permission.rules don't gate it — plan mode (read-only tools: no Bash/Write/
    #    Edit) does. The permission.rules are appended as defense-in-depth only.
    base_cfg = Path(base) / "config.toml"
    cfg_text = base_cfg.read_text() if base_cfg.is_file() else ""
    if re.search(r"(?m)^\s*default_plan_mode\s*=", cfg_text):
        cfg_text = re.sub(
            r"(?m)^\s*default_plan_mode\s*=.*$", "default_plan_mode = true", cfg_text
        )
    else:  # top-level key must precede any [table]; the base config opens with these
        cfg_text = "default_plan_mode = true\n" + cfg_text
    (Path(home) / "config.toml").write_text(cfg_text + _permission_rules(server_name))

    # 3. Login state — relocating the home would otherwise break auth, so copy the
    #    credential store / device id across (whichever layout this version uses).
    for entry in _CREDENTIAL_ENTRIES:
        src = Path(base) / entry
        if src.is_dir():
            shutil.copytree(src, Path(home) / entry, dirs_exist_ok=True)
        elif src.is_file():
            shutil.copy2(src, Path(home) / entry)

    return home
