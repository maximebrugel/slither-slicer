# slither-slicer

Turn a Solidity codebase into a queryable **Program Dependence Graph** and extract
**minimal, byte-accurate program slices** for a given criterion — a sink, a
source, or a specific variable at a node.

This is the structural layer (Phase 2) that retrieval tools and a reasoning agent
sit on top of. The design principle throughout: **Slither is the source of
truth.** The slicer never guesses structure an analyzer already knows exactly —
it composes Slither's SSA IR, data-dependency, and CFG into a PDG and does
reachability over it.

## Install

Uses [`uv`](https://docs.astral.sh/uv/). Slither needs a matching `solc`; the
loader auto-detects the pragma and switches via `solc-select` (override with
`--solc`).

```bash
uv sync --extra dev
uv run solc-select install 0.8.20    # or whatever your contracts need
```

## CLI

```bash
# every sink slice in a contract (backward slices)
uv run slither-slicer path/to/project --contract Vault --sinks

# every source slice (forward slices)
uv run slither-slicer path/to/project --contract Vault --sources

# explicit criterion (--depth controls how many call boundaries to cross)
uv run slither-slicer path/to/project \
    --function "Vault.withdraw()" --var amount --backward --depth 2 --json out.json

# access-control guard slices for a contract
uv run slither-slicer path/to/project --access-control Vault

# cap nodes per slice for a large codebase (guards are always kept)
uv run slither-slicer path/to/project --contract Vault --sinks --max-nodes 40
```

## Library

```python
from slither_slicer import Slicer

sl = Slicer("path/to/project")                       # compiles via crytic-compile

overview = sl.audit_overview(contract="Vault")       # attack surface, one row/entry point
slices = sl.slice_all_sinks(contract="Vault")        # list[Slice]
slices = sl.slice_all_sources(contract="Vault")
guards = sl.access_control_of("Vault.withdraw()")    # guard-context Slice
xref = sl.state_var_xref("Vault", "balances")        # readers + writers of a state var

s = sl.backward_slice(function="Vault.withdraw()", variable="amount")
s = sl.forward_slice(function="Vault.deposit()", variable="msg.value")
s = sl.slice_at_node("Vault.withdraw()#5")              # exact-node criterion
# every slicing method takes depth=N (call boundaries to cross, default 1).
# backward slices also take storage_depth=N (stitch cross-function state writers,
# default 0=off) and cross_contract=True (descend into resolvable external callees).

s.to_json()              # structured output (frozen schema — see below)
s.to_json(max_nodes=40)  # cap the node body (guards always kept; adds a truncated: note)
s.to_source()            # minimal reconstructed source
```

## MCP server (for Claude Code / agents)

A stdio MCP server exposes the slicer to an agent. The design rule — the thesis of
the project applied to the API boundary — is that **the agent chooses *what* to
slice; the deterministic engine decides *how* to traverse.** So every tool returns
a deterministic slice or a bounded, discrete lookup. There is deliberately **no
tool that hands the agent raw PDG edges to walk node-by-node** — that multi-hop
traversal is the error-prone, context-flooding work the slicer exists to absorb.
Raw-graph access lives in the library (`slither_slicer.graph`) and CLI (`--pdg`),
for a human debugging the slicer.

Install the extra and register the server (project-scoped `.mcp.json` is included):

```bash
uv sync --extra mcp
```

```json
{
  "mcpServers": {
    "slither-slicer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--extra", "mcp", "slither-slicer-mcp"],
      "env": { "SLITHER_SLICER_PROJECT": "path/to/project" }
    }
  }
}
```

The project is taken from `SLITHER_SLICER_PROJECT`; every tool also accepts an
optional `project` arg to analyze any project in the session. Compiled projects
are cached per path and recompiled automatically when a `.sol` file changes, so
slices never describe code that no longer exists. In a Claude Code session, run
`/mcp` to confirm the server is **connected** and see the tools.

| tool | purpose |
|---|---|
| `audit_overview` | **the first move** — attack surface in one call: one row per entry point with guard status, value movement, external calls, sink origins, and the CEI ordering flag |
| `list_contracts` / `list_functions` | orientation — bases and libraries included |
| `slice_all_sinks` / `slice_all_sources` | **compact** catalog of sinks/sources — drill in with `slice_from(node_id=…)` |
| `access_control_of` | full guard-context slice for a function |
| `slice_from` | full slice from an agent-chosen criterion: a `node_id` from any slice/summary, or `(function, variable)`; `direction`, `depth`, `storage_depth`, `cross_contract`, `max_nodes` |
| `state_var_xref` | readers and writers of a state variable, each with location, guard status and entry-point reachability |
| `find_callers` / `find_callees` | call-graph lookups |
| `explain_dependence` | one bounded PDG path between two slice nodes — crosses call/storage boundaries up to `depth` |

The raw PDG (for a human) is at `slither-slicer <project> --pdg "Vault.withdraw()"`.

### Agentic inspection (opt-in)

An LLM sub-agent is admissible in exactly one place: **where deterministic analysis
has already bottomed out** and the engine emitted a marker instead of a fact — the
`delegatecall` boundary it never descends. Everything else stays deterministic; an
LLM there would only add noise and cost.

`inspect_delegatecall(node_id)` seeds a sub-agent with the facts the engine already
computed (the backward slice of the delegatecall site, the proxy's *ordered* storage
layout) and lets it reason across the seam: which implementation actually executes,
storage-layout collisions, unprotected init/admin reachable through the call, and
target controllability. The sub-agent **navigates with a fresh, read-only slicer
instance** (so the seam is still answered deterministically, one hop further out) and
returns a structured verdict — every claim tied to a `node_id` + byte-exact source,
and anything it can't resolve marked under `unresolved`, **never guessed**. `dry_run`
returns the seed prompt without spending tokens (the agentic analogue of `--pdg`).

This layer is **off by default** — the deterministic build is free and golden-testable.
It registers only when `SLITHER_SLICER_ENABLE_AGENT=1`, and it requires:

```bash
uv sync --extra agent          # Python side: only a JSON-schema validator
kimi login                     # external Kimi Code CLI on PATH + a Kimi Code plan
```

```json
{
  "mcpServers": {
    "slither-slicer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--extra", "mcp", "--extra", "agent", "slither-slicer-mcp"],
      "env": {
        "SLITHER_SLICER_PROJECT": "path/to/project",
        "SLITHER_SLICER_ENABLE_AGENT": "1"
      }
    }
  }
}
```

Safety posture (read this before enabling). The sub-agent runs in an isolated
`$KIMI_CODE_HOME` registering only a read-only slicer (`SLITHER_SLICER_ENABLE_AGENT=0`,
so it can't recurse), in a throwaway cwd outside your tree, with a read-only seed
instruction. **But** the installed Kimi CLI (v0.14.3) auto-approves tool calls in
print mode and exposes shell/write builtins (`Bash`/`Write`/`Edit`) that no CLI flag
or config can disable — so a *hard* read-only toolset cannot be guaranteed. Since the
analyzed Solidity is untrusted input, a prompt-injection → auto-approved-shell path is
a real RCE vector. Therefore live execution is **fail-closed**: `inspect_delegatecall`
returns `status: "blocked"` unless you explicitly acknowledge the risk with
`SLITHER_SLICER_AGENT_ALLOW_SHELL=1` (intended for a trusted target in a sandboxed
environment). `dry_run` always works without it. (`SLITHER_SLICER_AGENT_TIMEOUT`
overrides the 300s wall-clock budget.)

If `kimi` is absent or not logged in the tool returns `status: "unavailable"`; any
malformed/non-conforming verdict returns an error status — it never fabricates a
finding. **Trust caveat:** storage-collision reasoning rests on the LLM computing slot
packing from the seeded layout (the engine does not compute slots), so treat a
`storage-collision` finding as a lead to verify, with its cited `node_id`/source, not a
proven fact.

## What a slice contains

Every node carries an exact `SourceRef` (`filename`, byte `start`/`length`,
1-indexed `lines`, and the exact `code` bytes) — the agent can always reach real
source, never a paraphrase. Each node is tagged with **why** it was included:

| reason | meaning |
|---|---|
| `criterion` | the slicing criterion itself |
| `data-dep` | pulled by SSA def-use data dependence |
| `control-dep` | pulled by control dependence (an `if`/loop/`require` guard) |
| `modifier-guard` | a modifier node guarding the enclosing function |
| `callee` | reached by one level of inter-procedural descent/ascent |
| `storage-dep` | a cross-function writer of a state var the slice reads (`storage_depth > 0`) |

A slice also surfaces:

- `guarded` — does the criterion's function restrict its caller's *identity*? A
  modifier that reads `msg.sender`/`tx.origin` (transitively — OZ `onlyOwner` →
  `_checkOwner()`), or an in-body identity check (`require(msg.sender == …)`, a
  boolean allowlist lookup, a checker call taking the caller). Merely *reading*
  the caller does not count: `nonReentrant` and
  `require(balances[msg.sender] >= amount)` restrict nothing about who may call.
  An unguarded value/authority/state sink is the headline audit signal. A guard
  written the modern way — `if (msg.sender != owner) revert Unauthorized()`, with
  no `require` — counts too.
- `state_write_after_external_call` — the checks-effects-interactions ordering
  risk behind reentrancy: a state write reachable *after* an external call.
- `calls` — **every** call in the slice, classified: `library`/`internal` are
  in-scope (we descended into them), `external`/`delegatecall`/`low_level` are
  opaque boundaries. Each carries `resolved_target` — the single concrete contract
  an external call's destination type resolves to, if any (a static fact, surfaced
  even without cross-contract descent). `external_calls` is the opaque subset as
  strings.
- `storage_writers` — when `storage_depth > 0`, the cross-function writers of the
  state vars this slice reads, each with `guarded` / `is_entry_point` flags.
- `events_emitted`, `entry_points` (external functions that reach the criterion),
  `state_vars_read`/`written` + `state_var_types`, `functions_touched`, `notes`.

### Output schema

The `to_json()` shape is the contract between this slicer and the Phase 3
retrieval tools. See `tests/test_model.py` for the asserted schema.

## How it works

- **Data dependence** (`dependence/data.py`) — over SlithIR **SSA**, so every use
  has exactly one reaching definition (or a `Phi`). Def/use maps are keyed by SSA
  variable identity. References (`arr[i]`, `s.f`, mapping accesses) are followed
  through `points_to`; non-constant indices are flagged `imprecise-alias:<base>`.
- **Control dependence** (`dependence/control.py`) — the standard
  Ferrante–Ottenstein–Warren algorithm. Slither exposes forward dominators but
  **not** post-dominators, so we compute them on the reversed CFG. A Solidity
  wrinkle: `require`/`assert`/`revert` are linear `SolidityCall`s, not branches —
  we model their abort path with a virtual edge to the exit so every statement
  after a `require` is correctly control-dependent on it. A call into in-scope
  code that itself reverts (a validation library like `LibChecks.checkNotZero`)
  is recognised the same way, so it guards its callsite like an inline `require`.
- **PDG + slicing** (`pdg.py`, `slicer.py`) — a slice is reachability over the
  union of those edges, plus modifier-guard inclusion and depth-limited
  inter-procedural stitching (`interproc.py`; default one boundary, raise with
  `depth=`/`--depth`). Slither's SSA already inlines a callee's formals as entry
  `Phi`s of the caller's actuals, which we use to map arguments across the call
  boundary. **Library calls** (`using Lib for T`) are in-scope code, so they are
  descended into like internal calls — not treated as opaque (this recovers the
  bulk of a real project's call graph).
- **Implicit flows (forward)** — a statement guarded by a tainted *branch*
  (`if (v > 1 ether) { won = true; }`) is in the forward slice, and taint
  continues through it. Abort-only nodes are deliberately excluded from this
  closure: every statement after a tainted `require` is technically
  control-dependent on it, and including them would drag the whole tail of the
  function into every slice.
- **Catalog** (`catalog/`) — Solidity-specific sink/source detectors that produce
  criteria automatically (ether transfers, external calls, `delegatecall`,
  `selfdestruct`, privileged state writes, arbitrary-call to an attacker-
  controlled target, ERC20/721 token movement — `transfer`/`approve`/`mint`/`burn`,
  including SafeERC20 library wrappers; parameters, `msg.sender`/`tx.origin`,
  `msg.value`, environment/oracle returns). Scanning is **inherited-inclusive**: a
  sink declared in a base contract is live code of the derived contract, so it is
  cataloged there (and ascent climbs into base-declared callers).
- **Triage** (`patterns.py`) — `audit_overview` gives the whole attack surface in
  one call (entry points × guarded × value out × external calls × sink origins ×
  CEI ordering), and the checks-effects-interactions flag rides on every slice.

## Known limitations (marked, never silently dropped)

Per the audit principle that a visible *"I couldn't follow this"* is far safer
than a slice that looks complete but isn't, the slicer appends a `note` and keeps
going when it hits:

- **`assembly { }` blocks** — slices stop at the boundary (`assembly-boundary:<fn>`).
- **Imprecise aliasing** — mapping/array/struct writes through a non-constant
  index (`imprecise-alias:<base>`).
- **Cross-function state effects** — *opt-in*: `storage_depth=N` stitches the
  cross-function writers of state vars a slice reads (tagged `storage-dep`, listed
  in `storage_writers`); `state_var_xref` lists readers/writers without a slice.
  Off by default (the writers are surfaced as `state_vars_read`/`written`).
- **Inter-procedural depth** — depth-limited (default one boundary; raise with
  `depth=`/`--depth`); calls beyond the limit are marked
  (`interproc-depth-limit:<fn>`).
- **External / proxy / `delegatecall` boundaries** — calls to *other contracts*
  are opaque by default (recorded in `external_calls` / `calls`). *Opt-in*:
  `cross_contract=True` descends when the destination type resolves to exactly one
  concrete in-scope contract (note `cross-contract:<Callee>`; the runtime address
  may differ, so proxies / multi-implementer interfaces stay opaque with a
  `cross-contract-ambiguous`/`-unresolved` note). `delegatecall` is never
  descended. In-scope **library** calls are never boundaries — they are descended.

## Tests

```bash
uv run pytest
```

Golden tests pin the exact included `node_id`s and reason tags for hand-verified
fixtures (`tests/fixtures/`), with a standing invariant that a guard node is
never dropped. Point `SCABENCH_PROJECT` at a real project for a robustness sweep:

```bash
SCABENCH_PROJECT=/path/to/project uv run pytest tests/test_scabench_smoke.py
```
