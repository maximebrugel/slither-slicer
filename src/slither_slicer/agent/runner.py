"""The Kimi subprocess driver — the only module that knows the Kimi CLI exists.

Everything Kimi-specific (its flags, its stream-json wire format, its auth error)
is isolated here so the rest of the agent layer talks in terms of a prompt in and
a parsed verdict out. A different backend would be a sibling of this module.

Verified against the INSTALLED Kimi Code CLI v0.14.3 (the public docs site
describes a newer build with extra flags this version rejects):

  * print mode is ``kimi -p <prompt> --output-format stream-json`` (also ``-m``);
  * v0.14.3 has NO ``--print`` / ``--mcp-config-file`` / ``-w`` / ``--add-dir``;
  * ``-p`` cannot be combined with ``--yolo`` or ``--auto`` ("Cannot combine
    --prompt with --yolo/--auto") — so there is no flag-based auto-approval in
    print mode; tool approval is governed by ``[[permission.rules]]`` in config;
  * working dir is the process ``cwd``; MCP servers come from ``mcp.json`` under
    the (optionally relocated, ``$KIMI_CODE_HOME``) home;
  * stream-json stdout is JSONL: assistant lines carry ``content`` (str) and an
    optional ``tool_calls`` array whose tool name lives at ``function.name``;
    tool-result lines carry ``role == "tool"``. The verdict is the last assistant
    ``content``.
  * not logged in -> exit 1 with ``auth.login_required`` on stderr.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field


class KimiError(RuntimeError):
    """Base class for every way a Kimi run can fail."""


class KimiUnavailable(KimiError):
    """`kimi` is not installed, or the host is not logged in."""


class KimiTimeout(KimiError):
    """The subprocess exceeded its wall-clock budget."""


class KimiBadOutput(KimiError):
    """`kimi` exited non-zero, or its output could not be parsed."""


@dataclass
class KimiResult:
    verdict: dict  # the parsed final-assistant JSON object (schema-validated upstream)
    tool_calls: list[dict] = field(default_factory=list)  # audit trail from the JSONL
    raw_stdout: str = ""


def _require_kimi() -> str:
    path = shutil.which("kimi")
    if not path:
        raise KimiUnavailable(
            "`kimi` is not on PATH. Install the Kimi Code CLI and run `kimi login`."
        )
    return path


def run_kimi(
    *,
    prompt: str,
    timeout_s: int = 180,
    model: str | None = None,
    kimi_home: str | None = None,
    workdir: str | None = None,
) -> KimiResult:
    """Run one non-interactive Kimi prompt and return the parsed verdict.

    ``kimi_home`` sets ``$KIMI_CODE_HOME`` to relocate Kimi's whole home (mcp.json
    + config.toml) to an isolated, read-only-scoped directory without touching the
    user's real config (see :mod:`slither_slicer.agent.kimi_config`).

    ``workdir`` is the subprocess cwd. It deliberately defaults to a throwaway temp
    dir *outside* the user's tree: Kimi discovers project-level MCP config
    (``.mcp.json`` / ``.kimi-code/``) by walking up from cwd, so running inside the
    project would pull in stray servers pointing at other projects. The sub-agent
    reaches the real source through the inner slicer (absolute project path) and the
    absolute ``source`` refs already embedded in the seed.
    """
    kimi = _require_kimi()
    argv = [kimi, "-p", prompt, "--output-format", "stream-json"]
    if model:
        argv += ["-m", model]

    env = dict(os.environ)
    if kimi_home:
        env["KIMI_CODE_HOME"] = kimi_home

    own_workdir = workdir is None
    cwd = workdir or tempfile.mkdtemp(prefix="slither-kimi-cwd-")

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=cwd,
            env=env,
        )
    except subprocess.TimeoutExpired as e:
        raise KimiTimeout(f"kimi exceeded {timeout_s}s") from e
    finally:
        if own_workdir:
            shutil.rmtree(cwd, ignore_errors=True)

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        # Auth is a "go run `kimi login`" condition, not a malformed-run bug.
        if "auth.login_required" in stderr or "login_required" in stderr:
            raise KimiUnavailable(
                "kimi is not logged in — run `kimi login` (requires a Kimi Code plan)."
            )
        raise KimiBadOutput(f"kimi exited {proc.returncode}: {stderr[-2000:]}")

    return _parse_stream_json(proc.stdout)


def _parse_stream_json(stdout: str) -> KimiResult:
    """Parse Kimi's ``--output-format stream-json`` (JSONL).

    Each line is a message object. Assistant messages carry ``content`` (str) and
    may carry ``tool_calls``; the last assistant message is the verdict. Tool and
    metadata lines are accumulated only for the audit trail. Unparseable lines are
    skipped (the stream may interleave non-message diagnostics).
    """
    final_text: str | None = None
    tool_calls: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        calls = msg.get("tool_calls")
        if isinstance(calls, list):
            tool_calls += [c for c in calls if isinstance(c, dict)]
        if msg.get("role") == "assistant" and isinstance(msg.get("content"), str):
            final_text = msg["content"]  # last assistant message wins

    if final_text is None:
        raise KimiBadOutput("no final assistant message in kimi stream-json output")

    return KimiResult(
        verdict=_extract_json_object(final_text),
        tool_calls=tool_calls,
        raw_stdout=stdout,
    )


def _extract_json_object(text: str) -> dict:
    """The seed prompt instructs Kimi to end with a single fenced ```json object.

    Tolerate an optional ```json fence and any leading prose; raise KimiBadOutput
    if no JSON object can be recovered (fail closed — never fabricate)."""
    text = text.strip()
    if "```" in text:
        # take the content of the last fenced block
        fences = text.split("```")
        if len(fences) >= 3:
            block = fences[-2]
            if block.lstrip().lower().startswith("json"):
                block = block.lstrip()[4:]
            text = block.strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise KimiBadOutput(f"final assistant message was not a JSON object: {e}") from e
    if not isinstance(obj, dict):
        raise KimiBadOutput("final assistant message JSON was not an object")
    return obj


def tool_names(tool_calls: list[dict]) -> list[str]:
    """Sorted unique tool names from a stream-json audit trail.

    Kimi nests the name at ``tool_calls[].function.name``."""
    names = set()
    for c in tool_calls:
        fn = c.get("function")
        if isinstance(fn, dict) and isinstance(fn.get("name"), str):
            names.add(fn["name"])
        elif isinstance(c.get("name"), str):  # tolerate a flatter shape
            names.add(c["name"])
    return sorted(names)
