defmodule Exnode.Store.SnapshotTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Codec.Block
  alias Exnode.Store.{Guard, KV, Snapshot}
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp blocks(n) do
    @chain
    |> BB.read_chain()
    |> Enum.take(n)
    |> Enum.map(&elem(Block.decode_exact(&1), 1))
  end

  defp take_snap!(a, chain_dir) do
    meta = %{
      tip: Archive.tip(a),
      ends: Map.new(a.segs, fn {k, s} -> {k, Archive.Segments.position(s)} end),
      wpruned: a.wpruned
    }

    Snapshot.take_canonical!(a.kv, chain_dir, meta)
  end

  defp open_canonical(chain_dir, opts \\ []) do
    hot = Keyword.get(opts, :hot, Path.join(chain_dir, "archive"))
    cold = Keyword.get(opts, :cold)
    g = Guard.acquire!(chain_dir, name: "canonical", require_clean_mark: false)
    {:ok, kv} = KV.open(Path.join(chain_dir, "index"), mode: :canonical, guard: g)

    a =
      Archive.open(kv, hot, cold, @p.genesis,
        strict_clean: Keyword.get(opts, :strict_clean, false),
        defer_prune: Keyword.get(opts, :defer_prune, true),
        prune_keep: opts[:prune_keep],
        max: opts[:max]
      )

    {g, kv, a}
  end

  defp close_clean(g, kv, a) do
    Archive.close(a)
    KV.close(kv)
    :ok = Guard.release_clean!(g)
  end

  defp simulate_crash(g, kv, a) do
    Exnode.Archive.Overlay.close(a.overlay)
    Enum.each(a.segs, fn {_, s} -> Exnode.Archive.Segments.close(s) end)
    Enum.each(a.readers, fn {_, r} -> Exnode.Archive.Segments.close_reader(r) end)
    KV.close(kv)
    Guard.abandon(g)
  end

  test "rotated snapshots restore exact prior state after live DB corruption and torn segment tails",
       %{tmp_dir: dir} do
    chain_dir = Path.join(dir, "regtest")
    cold_dir = Path.join(dir, "cold")
    bs = blocks(10)
    {first5, next5} = Enum.split(bs, 5)

    {g, kv, a} = open_canonical(chain_dir, cold: cold_dir)

    a =
      Enum.reduce(first5, a, fn b, a ->
        Archive.connect(a, b, a.tip.height + 1, [],
          commit: false,
          delta: %{created: %{}, spent: []}
        )
      end)
      |> Archive.flush()

    {:ok, -1} = take_snap!(a, chain_dir)
    snap_tip = Archive.tip(a)

    # Verify hard-linking: snapshot SSTs share inodes with live index/.
    live_ssts = Path.wildcard(Path.join([chain_dir, "index", "*.sst"]))
    snap_ssts = Path.wildcard(Path.join([chain_dir, "snapshots", "primary", "*.sst"]))
    assert live_ssts != [] and snap_ssts != []

    live_inodes = MapSet.new(live_ssts, &File.stat!(&1).inode)
    snap_inodes = MapSet.new(snap_ssts, &File.stat!(&1).inode)
    assert MapSet.size(MapSet.intersection(live_inodes, snap_inodes)) > 0

    # Write more blocks AFTER snapshot (appending to hot & cold segments and mutating live DB),
    # plus create ephemeral staging/.
    {:ok, stg} = KV.open(Path.join(chain_dir, "staging"), mode: :staging)
    :ok = KV.write(stg, [{:put, :pending, <<1::256>>, "raw"}], sync: false)
    KV.close(stg)

    a =
      Enum.reduce(next5, a, fn b, a ->
        Archive.connect(a, b, a.tip.height + 1, [],
          commit: false,
          delta: %{created: %{}, spent: []}
        )
      end)

    # Append torn garbage directly to hot outputs and cold inputs/witness segments.
    for p <- [
          Path.join([chain_dir, "archive", "outputs", "00000.seg"]),
          Path.join([cold_dir, "inputs", "00000.seg"]),
          Path.join([cold_dir, "witness", "00000.seg"])
        ] do
      File.write!(p, "TORN_TAIL_BYTES", [:append])
    end

    # Crash (flush.lock left on disk) AND trash live index/ (corrupt mutable
    # MANIFEST/CURRENT/WAL and unlink live SSTs; snapshot's hard-linked SSTs survive).
    simulate_crash(g, kv, a)

    for f <-
          Path.wildcard(Path.join([chain_dir, "index", "MANIFEST-*"])) ++
            Path.wildcard(Path.join([chain_dir, "index", "*.log"])) ++
            [Path.join([chain_dir, "index", "CURRENT"])],
        File.exists?(f),
        do: File.write!(f, "CORRUPTED_LIVE_DB")

    for f <- Path.wildcard(Path.join([chain_dir, "index", "*.sst"])), do: File.rm!(f)

    # Normal open MUST refuse the dirty store.
    assert_raise Exnode.StorageError, ~r/did not close cleanly/, fn ->
      open_canonical(chain_dir, cold: cold_dir, strict_clean: true)
    end

    # Restore recovers exact snapshot tip, truncates hot+cold tails, wipes staging/.
    {:ok, restored} = Snapshot.restore!(chain_dir, cold: cold_dir)
    assert restored.slot == :primary
    assert restored.tip == snap_tip
    refute File.exists?(Path.join(chain_dir, "staging"))
    assert Guard.inspect_lock(chain_dir) == :clean

    # Reopen with strict_clean: true succeeds and every block reconstructs byte-exactly!
    {g2, kv2, a2} = open_canonical(chain_dir, cold: cold_dir, strict_clean: true)
    assert Archive.tip(a2) == snap_tip

    for {b, h} <- Enum.with_index(first5, 1) do
      assert Archive.read_block(a2, Archive.id_at(a2, h)) == b.raw
    end

    close_clean(g2, kv2, a2)
  end

  test "crash mid-rotation (primary moved to secondary, staging incomplete) falls back to secondary",
       %{tmp_dir: dir} do
    chain_dir = Path.join(dir, "regtest")
    [b1, b2] = blocks(2)

    {g, kv, a} = open_canonical(chain_dir)
    a = Archive.connect(a, b1, 1, []) |> Archive.flush()
    {:ok, -1} = take_snap!(a, chain_dir)
    tip1 = Archive.tip(a)

    a = Archive.connect(a, b2, 2, []) |> Archive.flush()
    {:ok, -1} = take_snap!(a, chain_dir)
    tip2 = Archive.tip(a)
    assert tip2.height == 2

    simulate_crash(g, kv, a)

    # Simulate crash right after `mv primary secondary` and before `mv staging primary`:
    # primary is missing (or incomplete without SNAPSHOT_OK), while secondary holds tip1.
    File.rm_rf!(Path.join([chain_dir, "snapshots", "primary"]))
    File.mkdir_p!(Path.join([chain_dir, "snapshots", "staging"]))
    File.write!(Path.join([chain_dir, "snapshots", "staging", "PARTIAL"]), "x")

    {:ok, restored} = Snapshot.restore!(chain_dir)
    assert restored.slot == :secondary
    assert restored.tip == tip1
    refute File.exists?(Path.join([chain_dir, "snapshots", "staging"]))

    {g2, kv2, a2} = open_canonical(chain_dir, strict_clean: true)
    assert Archive.tip(a2) == tip1
    assert Archive.read_block(a2, Archive.id_at(a2, 1)) == b1.raw
    close_clean(g2, kv2, a2)
  end

  test "faulted store refuses restore without --force-from-snapshot, succeeds with it", %{
    tmp_dir: dir
  } do
    chain_dir = Path.join(dir, "regtest")
    [b1] = blocks(1)

    {g, kv, a} = open_canonical(chain_dir)
    a = Archive.connect(a, b1, 1, []) |> Archive.flush()
    {:ok, -1} = take_snap!(a, chain_dir)
    tip1 = Archive.tip(a)

    capture_log(fn ->
      Guard.latch_fault(g, :segments, :eio, "simulated disk error")
    end)

    simulate_crash(g, kv, a)

    assert_raise Exnode.StorageError, ~r/--force-from-snapshot/, fn ->
      Snapshot.restore!(chain_dir)
    end

    {:ok, restored} = Snapshot.restore!(chain_dir, force_from_snapshot: true)
    assert restored.tip == tip1
    assert Guard.inspect_lock(chain_dir) == :clean
  end

  test "deferred witness pruning never deletes a witness segment referenced by any retained snapshot",
       %{tmp_dir: dir} do
    chain_dir = Path.join(dir, "regtest")
    bs = blocks(40)

    {g, kv, a} = open_canonical(chain_dir, defer_prune: true, prune_keep: 10, max: 200)

    # First batch: blocks 1..20, snapshot 1 (primary only)
    a =
      Enum.reduce(Enum.take(bs, 20), a, fn b, a ->
        Archive.connect(a, b, a.tip.height + 1, [],
          commit: false,
          delta: %{created: %{}, spent: []}
        )
      end)
      |> Archive.flush()

    {:ok, safe1} = take_snap!(a, chain_dir)
    a = Archive.finalize_pruned_witness(a, safe1)
    wp1 = a.wpruned
    assert wp1 >= 0

    # Second batch: blocks 21..40, snapshot 2 -> primary has wp2, secondary still has wp1.
    a =
      Enum.reduce(Enum.drop(bs, 20), a, fn b, a ->
        Archive.connect(a, b, a.tip.height + 1, [],
          commit: false,
          delta: %{created: %{}, spent: []}
        )
      end)
      |> Archive.flush()

    {:ok, safe2} = take_snap!(a, chain_dir)
    a = Archive.finalize_pruned_witness(a, safe2)
    wp2 = a.wpruned
    assert wp2 > wp1
    assert safe2 == wp1

    # Segments > wp1 (still needed by secondary!) MUST still exist on disk!
    wdir = Path.join([chain_dir, "archive", "witness"])

    for seg <- (wp1 + 1)..wp2 do
      assert File.exists?(Path.join(wdir, String.pad_leading("#{seg}", 5, "0") <> ".seg")),
             "witness segment #{seg} deleted while secondary snapshot still references it!"
    end

    # Crashing and falling back to secondary MUST succeed!
    simulate_crash(g, kv, a)
    File.rm_rf!(Path.join([chain_dir, "snapshots", "primary"]))
    {:ok, restored} = Snapshot.restore!(chain_dir)
    assert restored.slot == :secondary
    assert restored.wpruned == wp1

    {g2, kv2, a2} =
      open_canonical(chain_dir, strict_clean: true, defer_prune: true, prune_keep: 10, max: 200)

    assert Archive.tip(a2).height == 20
    close_clean(g2, kv2, a2)
  end

  test "derived store snapshot & restore (and wipe fallback when no derived snapshot exists)", %{
    tmp_dir: dir
  } do
    chain_dir = Path.join(dir, "regtest")
    derived_dir = Path.join(chain_dir, "derived")
    File.mkdir_p!(derived_dir)

    # Case 1: Dirty derived with no snapshot -> wiped.
    gd = Guard.acquire!(derived_dir, name: "derived", require_clean_mark: false)
    {:ok, dkv} = KV.open(derived_dir, mode: :derived, guard: gd)
    :ok = KV.write(dkv, [{:put, :filters, "k", "v"}], sync: true)
    KV.close(dkv)
    Guard.abandon(gd)

    assert Snapshot.restore_derived!(chain_dir) == :wiped
    refute File.exists?(derived_dir)

    # Case 2: Derived with snapshot -> restored to exact snapshot state.
    File.mkdir_p!(derived_dir)
    gd2 = Guard.acquire!(derived_dir, name: "derived", require_clean_mark: false)
    {:ok, dkv2} = KV.open(derived_dir, mode: :derived, guard: gd2)
    :ok = KV.write(dkv2, [{:put, :filters, "k", "v1"}], sync: true)
    :ok = Snapshot.take_derived!(dkv2, chain_dir)
    :ok = KV.write(dkv2, [{:put, :filters, "k", "v2"}], sync: true)
    KV.close(dkv2)
    Guard.abandon(gd2)

    assert {:restored, :primary} == Snapshot.restore_derived!(chain_dir)
    assert Guard.inspect_lock(derived_dir) == :clean
    {:ok, dkv3} = KV.open(derived_dir, mode: :derived)
    assert KV.get(dkv3, :filters, "k") == {:ok, "v1"}
    KV.close(dkv3)
  end
end
