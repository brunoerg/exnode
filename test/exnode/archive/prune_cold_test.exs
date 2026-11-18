defmodule Exnode.Archive.PruneColdTest do
  @moduledoc "Cold datadir and witness pruning."
  use ExUnit.Case, async: true

  alias Exnode.Archive
  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  defp blocks, do: for(raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1))

  defp start(dir, opts) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link([params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot")] ++ opts)

    %{kv: kv, hs: hs, cs: cs}
  end

  defp stop(n) do
    GenServer.stop(n.cs)
    GenServer.stop(n.hs)
    KV.close(n.kv)
  end

  test "cold datadir: inputs and witness go there, outputs stay hot, blocks reconstruct", %{
    tmp_dir: dir
  } do
    bs = blocks()
    n = start(dir, cold: Path.join(dir, "cold"))
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)

    assert File.ls!(Path.join(dir, "hot")) |> Enum.sort() == ["outputs"]
    assert File.ls!(Path.join(dir, "cold")) |> Enum.sort() == ["inputs", "witness"]

    State.with_archive(n.cs, fn a ->
      for {b, h} <- Enum.with_index(bs, 1),
          do: assert(Archive.read_block(a, Archive.id_at(a, h)) == b.raw)
    end)

    stop(n)
    n = start(dir, cold: Path.join(dir, "cold"))
    assert State.tip(n.cs).height == 150

    State.with_archive(n.cs, fn a ->
      assert Archive.read_block(a, Archive.id_at(a, 150)) == List.last(bs).raw
    end)
  end

  test "witness pruning keeps the last N blocks, survives restart, and allows shallow reorgs", %{
    tmp_dir: dir
  } do
    bs = blocks()
    # Tiny segments (a few blocks each), keep 20 blocks.
    opts = [segment_max: 200, prune_witness: true, prune_keep: 20]
    n = start(dir, opts)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)

    wdir = Path.join([dir, "hot", "witness"])
    odir = Path.join([dir, "hot", "outputs"])
    pruned = State.with_archive(n.cs, &Archive.witness_pruned/1)
    assert pruned > 5
    # The pruned witness files are gone; outputs and inputs are untouched.
    for s <- 0..pruned,
        do: refute(File.exists?(Path.join(wdir, String.pad_leading("#{s}", 5, "0") <> ".seg")))

    assert File.exists?(Path.join(odir, "00000.seg"))

    check = fn n ->
      State.with_archive(n.cs, fn a ->
        for {b, h} <- Enum.with_index(bs, 1),
            h > 150 - 20,
            do: assert(Archive.read_block(a, Archive.id_at(a, h)) == b.raw, "kept block #{h}")

        assert Archive.read_block(a, Archive.id_at(a, 10)) == {:error, :witness_pruned}
        # Spend data is unaffected: coins still resolve.
        assert {:ok, _} = Archive.resolve(a, hd(Enum.at(bs, 9).txs).txid, 0)
      end)
    end

    check.(n)
    stop(n)
    n = start(dir, opts)
    assert State.tip(n.cs).height == 150
    check.(n)

    # A 2-block reorg from 149 (within the kept window) reconnects archived
    # blocks, then back again.
    b149 = Enum.at(bs, 148)
    f150 = BB.build(b149.header, [BB.coinbase(150, 25 * @coin, <<0x52>>)])
    f151 = BB.build(f150.header, [BB.coinbase(151, 25 * @coin)])
    {:ok, :stored} = State.submit_block(n.cs, f150)
    {:ok, :connected} = State.submit_block(n.cs, f151)
    assert State.tip(n.cs).hash == f151.header.hash
    b151 = BB.build(List.last(bs).header, [BB.coinbase(151, 25 * @coin)])
    b152 = BB.build(b151.header, [BB.coinbase(152, 25 * @coin)])
    {:ok, :stored} = State.submit_block(n.cs, b151)
    {:ok, :connected} = State.submit_block(n.cs, b152)
    assert State.tip(n.cs).hash == b152.header.hash
    stop(n)
  end

  # Regression: with a mempool, disconnect_to read each
  # disconnected block raw for the mempool's re-add; a block below the
  # pruning horizon gave {:error, :witness_pruned} and a MatchError, so a
  # reorg deeper than the kept blocks crashed the chain state on every
  # restart. Without a mempool the same reorg worked.
  test "a reorg below the witness-pruning horizon works with a mempool", %{tmp_dir: dir} do
    bs = blocks()
    opts = [segment_max: 200, prune_witness: true, prune_keep: 20, mempool: :cs3_mempool_name]
    n = start(dir, opts)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)

    State.with_archive(n.cs, fn a ->
      {:error, :witness_pruned} = Archive.read_block(a, Archive.id_at(a, 101))
    end)

    # A longer branch from 100: blocks 101..150 are disconnected.
    {fork, _} =
      Enum.map_reduce(101..151, Enum.at(bs, 99).header, fn h, prev ->
        value = if h < 150, do: 50 * @coin, else: 25 * @coin
        b = BB.build(prev, [BB.coinbase(h, value, <<0x52>>)])
        {b, b.header}
      end)

    {:ok, _} = Headers.process_headers(n.hs, Enum.map(fork, & &1.header))
    for b <- fork, do: {:ok, _} = State.submit_block(n.cs, b, requested: true)
    assert State.tip(n.cs).hash == List.last(fork).header.hash
    stop(n)
  end

  # Regression: a reader carries the prune point of its
  # commit. A prune after it deleted witness files the reader still thought
  # present, and its next read of them crashed on the missing file (REST
  # answered 500).
  test "a reader taken before a prune reads the newly pruned blocks as pruned, without crashing",
       %{tmp_dir: dir} do
    bs = blocks()
    n = start(dir, segment_max: 200, prune_witness: true, prune_keep: 20)
    for b <- Enum.take(bs, 60), do: {:ok, :connected} = State.submit_block(n.cs, b)
    State.commit_now(n.cs)
    old = State.with_archive(n.cs, &Archive.reader/1)
    old_pruned = old.wpruned

    for b <- Enum.drop(bs, 60), do: {:ok, :connected} = State.submit_block(n.cs, b)
    State.commit_now(n.cs)
    assert State.with_archive(n.cs, &Archive.witness_pruned/1) > old_pruned

    # Blocks the old reader saw unpruned whose witness files are gone now.
    raced =
      for h <- 1..60,
          id = Archive.id_at(old, h),
          rec = Archive.block_record!(old, id),
          s = Map.get(rec, :wseg),
          s != nil and s > old_pruned and Archive.witness_pruned?(old, id),
          do: {h, id}

    assert raced != []

    for {h, id} <- raced do
      assert Archive.read_block(old, id) == {:error, :witness_pruned}
      cb = hd(Enum.at(bs, h - 1).txs)
      assert {:ok, tx, _, _, _} = Archive.read_tx(old, cb.txid)
      assert tx.txid == cb.txid
    end

    stop(n)
  end
end
