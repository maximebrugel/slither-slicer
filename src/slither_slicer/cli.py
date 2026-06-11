"""Command-line interface.

    slither-slicer <project> --contract Vault --sinks
    slither-slicer <project> --function "Vault.withdraw()" --var amount --backward --json out.json
    slither-slicer <project> --access-control Vault
"""

from __future__ import annotations

import argparse
import sys

from . import Slicer
from .render import slices_to_json_str, to_json_str


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="slither-slicer", description=__doc__)
    p.add_argument("project", help="path to the Solidity project / file")
    p.add_argument("--contract", help="contract name (defaults to first derived contract)")
    p.add_argument("--solc", help="pin a solc version (else auto-detected from pragma)")

    p.add_argument("--sinks", action="store_true", help="slice backward from every sink")
    p.add_argument("--sources", action="store_true", help="slice forward from every source")
    p.add_argument("--access-control", metavar="CONTRACT", help="guard slices for a contract")

    p.add_argument("--function", help='explicit criterion: e.g. "Vault.withdraw()"')
    p.add_argument("--var", help="variable name for the explicit criterion")
    p.add_argument("--backward", action="store_true", help="backward slice (default)")
    p.add_argument("--forward", action="store_true", help="forward slice")
    p.add_argument(
        "--depth",
        type=int,
        default=1,
        help="call boundaries an explicit slice may cross (default 1)",
    )

    p.add_argument(
        "--pdg",
        metavar="FUNCTION",
        help='dump the raw PDG (nodes + data/control edges) for a function, e.g. '
        '"Vault.withdraw()" — for debugging the slicer, not for agents',
    )

    p.add_argument("--json", metavar="PATH", help="write JSON output to PATH (else stdout)")
    p.add_argument("--source", action="store_true", help="print reconstructed source too")
    p.add_argument(
        "--max-nodes",
        type=int,
        default=None,
        help="cap nodes per slice in JSON output (guards always kept; adds a "
        "truncated:<kept>-of-<total>-nodes note)",
    )
    return p


def _emit(text: str, path: str | None) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {path}", file=sys.stderr)
    else:
        print(text)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    sl = Slicer(args.project, solc_version=args.solc)

    if args.access_control:
        slices = []
        for spec in _guarded_functions(sl, args.access_control):
            slices.append(sl.access_control_of(spec))
        _emit(slices_to_json_str(slices, max_nodes=args.max_nodes), args.json)
        print(f"# {len(slices)} guard slice(s)", file=sys.stderr)
        if args.source:
            for s in slices:
                print(s.to_source())
        return 0

    if args.sinks:
        slices = sl.slice_all_sinks(contract=args.contract)
        _emit(slices_to_json_str(slices, max_nodes=args.max_nodes), args.json)
        print(f"# {len(slices)} sink slice(s)", file=sys.stderr)
        return 0

    if args.sources:
        slices = sl.slice_all_sources(contract=args.contract)
        _emit(slices_to_json_str(slices, max_nodes=args.max_nodes), args.json)
        print(f"# {len(slices)} source slice(s)", file=sys.stderr)
        return 0

    if args.function:
        if args.forward:
            s = sl.forward_slice(function=args.function, variable=args.var, depth=args.depth)
        else:
            s = sl.backward_slice(function=args.function, variable=args.var, depth=args.depth)
        _emit(to_json_str(s, max_nodes=args.max_nodes), args.json)
        if args.source:
            print(s.to_source())
        return 0

    if args.pdg:
        _dump_pdg(sl, args.pdg)
        return 0

    print(
        "nothing to do: pass --sinks, --sources, --access-control, or --function",
        file=sys.stderr,
    )
    return 2


def _dump_pdg(sl: Slicer, function_spec: str) -> None:
    """Print the raw per-function PDG — nodes and their data/control edges.

    This is the human researcher's window into the graph (debugging the slicer);
    the agent surface deliberately never exposes raw edges.
    """
    from . import graph as g

    _contract, func = sl._resolve_function(function_spec)
    print(f"# PDG for {func.canonical_name}")
    print("# nodes:")
    for n in func.nodes:
        ir = " ; ".join(str(op) for op in n.irs_ssa) or "(no ir)"
        print(f"  {g.global_node_id(n)}  [{n.type.name}]  {ir}")
    print("# edges (src depends on dst):")
    for src, dst, kind in g.pdg_edges(func):
        print(f"  {g.global_node_id(src)} -> {g.global_node_id(dst)}  [{kind}]")


def _guarded_functions(sl: Slicer, contract_name: str) -> list[str]:
    """Every external/public function of the contract, guarded ones first. Each
    yields a guard-context slice via :meth:`Slicer.access_control_of`."""
    c = sl._contract(contract_name)
    entries = [f for f in c.functions if f.visibility in ("public", "external")]
    entries.sort(key=lambda f: (not f.modifiers, f.full_name))  # modifiers first
    return [f"{c.name}.{f.full_name}" for f in entries]


if __name__ == "__main__":
    raise SystemExit(main())
