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

# explicit criterion
uv run slither-slicer path/to/project \
    --function "Vault.withdraw()" --var amount --backward --json out.json

# access-control guard slices for a contract
uv run slither-slicer path/to/project --access-control Vault
```

## Library

```python
from slither_slicer import Slicer

sl = Slicer("path/to/project")                       # compiles via crytic-compile

slices = sl.slice_all_sinks(contract="Vault")        # list[Slice]
slices = sl.slice_all_sources(contract="Vault")
guards = sl.access_control_of("Vault.withdraw()")    # guard-context Slice

s = sl.backward_slice(function="Vault.withdraw()", variable="amount")
s = sl.forward_slice(function="Vault.deposit()", variable="msg.value")

s.to_json()      # structured output (frozen schema — see below)
s.to_source()    # minimal reconstructed source
```

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

A slice also surfaces `functions_touched`, `state_vars_read`, `state_vars_written`,
`external_calls` (opaque boundaries hit), and `notes` (limitations triggered).

### Output schema

The `to_json()` shape is the contract between this slicer and the Phase 3
retrieval tools — **frozen**. See `tests/test_model.py` for the asserted schema.

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
  after a `require` is correctly control-dependent on it.
- **PDG + slicing** (`pdg.py`, `slicer.py`) — a slice is reachability over the
  union of those edges, plus modifier-guard inclusion and one level of
  inter-procedural stitching (`interproc.py`). Slither's SSA already inlines a
  callee's formals as entry `Phi`s of the caller's actuals, which we use to map
  arguments across the call boundary.
- **Catalog** (`catalog/`) — Solidity-specific sink/source detectors that produce
  criteria automatically (ether transfers, external calls, `delegatecall`,
  `selfdestruct`, privileged state writes; parameters, `msg.sender`/`tx.origin`,
  `msg.value`, environment/oracle returns).

## Known limitations (marked, never silently dropped)

Per the audit principle that a visible *"I couldn't follow this"* is far safer
than a slice that looks complete but isn't, the slicer appends a `note` and keeps
going when it hits:

- **`assembly { }` blocks** — slices stop at the boundary (`assembly-boundary:<fn>`).
- **Imprecise aliasing** — mapping/array/struct writes through a non-constant
  index (`imprecise-alias:<base>`).
- **Cross-function state effects** — v1 flags the state vars a slice touches but
  does not stitch full state dataflow between functions (the agent layer does
  that reasoning).
- **Inter-procedural depth** — one level only; deeper calls are marked
  (`interproc-depth-limit:<fn>`).
- **External / proxy / `delegatecall` boundaries** — `HighLevelCall`s to other
  contracts are opaque; recorded in `external_calls`, not descended into.

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
