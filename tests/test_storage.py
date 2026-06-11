"""Storage dataflow stitching: the reverse index, opt-in writer stitching, and
the state_var_xref orientation tool."""

from __future__ import annotations

from conftest import node_set

from slither_slicer.dependence.storage import build_storage_xref, readers_of, writers_of


def _balances(contract):
    return next(v for v in contract.state_variables if v.name == "balances")


def test_xref_indexes_readers_and_writers(storage_stitch):
    c = storage_stitch._contract("StorageStitch")
    bal = _balances(c)
    writer_fns = {fn.name for fn, _node in writers_of(c, bal)}
    reader_fns = {fn.name for fn, _node in readers_of(c, bal)}
    # written in deposit, slash, withdraw; read in slash, withdraw
    assert {"deposit", "slash", "withdraw"} <= writer_fns
    assert {"slash", "withdraw"} <= reader_fns


def test_xref_is_cached(storage_stitch):
    c = storage_stitch._contract("StorageStitch")
    assert build_storage_xref(c) is build_storage_xref(c)


def test_storage_depth_zero_is_baseline(storage_stitch):
    """With stitching off, the withdraw sink slice has no storage-dep nodes and
    no storage_writers — identical to pre-feature behavior."""
    s = next(
        x
        for x in storage_stitch.slice_all_sinks("StorageStitch", storage_depth=0)
        if x.criterion.origin == "sink:ether_transfer"
    )
    assert s.storage_writers == []
    assert all(n.reason != "storage-dep" for n in s.nodes)


def test_storage_depth_one_pulls_writers(storage_stitch):
    """storage_depth=1 pulls the cross-function writers of `balances` into the
    withdraw sink slice. The storage_writers list is the provenance signal: it
    names deposit, slash and withdraw's own write with correct guard / entry
    flags. (A plain `= 0` writer keeps reason storage-dep; a compound `+=` / `-=`
    writer re-enters as data-dep via its own intra-statement reference.)"""
    s = storage_stitch.slice_all_sinks("StorageStitch", storage_depth=1)
    s = next(x for x in s if x.criterion.origin == "sink:ether_transfer")

    # at least one genuine storage-dep node (the withdraw `balances = 0` write)
    assert any(n.reason == "storage-dep" for n in s.nodes)

    # every cross-function writer's node is present in the slice (any reason)
    node_ids = {n.node_id for n in s.nodes}
    assert any("deposit" in nid for nid in node_ids)
    assert any("slash" in nid for nid in node_ids)

    # the provenance list names the writers with correct flags
    writers_by_fn = {w["function"]: w for w in s.storage_writers}
    assert any(fn.endswith("deposit()") for fn in writers_by_fn)
    slash_writer = next(w for fn, w in writers_by_fn.items() if "slash" in fn)
    assert slash_writer["guarded"] is True  # slash is onlyOwner
    assert slash_writer["is_entry_point"] is True
    deposit_writer = next(w for fn, w in writers_by_fn.items() if "deposit" in fn)
    assert deposit_writer["guarded"] is False


def test_storage_stitch_pulls_writer_own_guard(storage_stitch):
    """The trailing re-saturation must pull slash's own `require(amount <=
    balances[user])` guard, so the stitched writer is not left dangling."""
    s = next(
        x
        for x in storage_stitch.slice_all_sinks("StorageStitch", storage_depth=1)
        if x.criterion.origin == "sink:ether_transfer"
    )
    pairs = node_set(s)
    # slash has a control-dep guard node pulled alongside its write
    assert any(nid.startswith("StorageStitch.slash") and r == "control-dep" for nid, r in pairs)


def test_state_var_xref_shape(storage_stitch):
    xref = storage_stitch.state_var_xref("StorageStitch", "balances")
    assert xref["state_var"] == "balances"
    assert "mapping" in xref["type"]
    writer_fns = {w["function"] for w in xref["writers"]}
    assert any(fn.endswith("deposit()") for fn in writer_fns)
    sample = xref["writers"][0]
    assert set(sample) == {
        "function",
        "location",
        "node_id",
        "guarded",
        "is_entry_point",
        "reason",
    }


def test_state_var_xref_unknown_var_raises(storage_stitch):
    import pytest

    with pytest.raises(ValueError, match="not found"):
        storage_stitch.state_var_xref("StorageStitch", "nonexistent")
