defmodule Exnode.Chain.StateTest do
  use ExUnit.Case, async: true

  alias Exnode.Archive
  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @p ChainParams.get(:regtest)
  @coin 100_000_000

  defp blocks, do: for(raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1))

  defp start(dir) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        cold: Path.join(dir, "cold")
      )

    %{kv: kv, hs: hs, cs: cs}
  end

  defp resolve(cs, txid, vout), do: State.with_archive(cs, &Archive.resolve(&1, txid, vout))

  setup %{tmp_dir: dir} do
    n = start(dir)
    bs = blocks()
    for b <- bs, do: assert({:ok, :connected} = State.submit_block(n.cs, b))
    Map.merge(n, %{bs: bs, dir: dir})
  end

  test "150 bitcoind blocks connect; every block is reconstructed byte-exactly", %{cs: cs, bs: bs} do
    assert State.tip(cs).height == 150

    State.with_archive(cs, fn a ->
      for {b, h} <- Enum.with_index(bs, 1) do
        assert Archive.read_block(a, Archive.id_at(a, h)) == b.raw
      end

      # Genesis is archived too, and its coinbase is unspendable.
      assert Archive.read_block(a, 0) == @p.genesis.raw
      assert Archive.resolve(a, hd(@p.genesis.txs).txid, 0) == :missing
    end)
  end

  test "spends, maturity, in-block chains, reorg and restart", %{cs: cs, bs: bs, dir: dir} = n do
    [b1, b2, b3 | _] = bs
    tip = List.last(bs).header
    cb1 = hd(b1.txs).txid

    assert {:ok, %{value: v, height: 1, coinbase: true}} = resolve(cs, cb1, 0)
    assert v == 50 * @coin

    # Block 151 spends cb1 and, in the same block, spends that tx's output.
    t1 = BB.spend_op_true(cb1, 0, 50 * @coin - 1000)
    t2 = BB.spend_op_true(t1.txid, 0, 50 * @coin - 2000)
    b151 = BB.build(tip, [BB.coinbase(151, 25 * @coin + 2000), t1, t2])
    assert {:ok, :connected} = State.submit_block(cs, b151)
    assert resolve(cs, cb1, 0) == :missing
    assert resolve(cs, t1.txid, 0) == :missing
    assert {:ok, %{value: 4_999_998_000, height: 151}} = resolve(cs, t2.txid, 0)

    # A competing branch from 150 with two blocks wins (more work); it spends cb2 instead.
    t3 = BB.spend_op_true(hd(b2.txs).txid, 0, 50 * @coin)
    f151 = BB.build(tip, [BB.coinbase(151, 25 * @coin, <<0x52>>), t3])
    assert {:ok, :stored} = State.submit_block(cs, f151)
    f152 = BB.build(f151.header, [BB.coinbase(152, 25 * @coin)])
    assert {:ok, :connected} = State.submit_block(cs, f152)
    assert State.tip(cs).hash == f152.header.hash

    # The old branch's spends no longer count; the new branch's do.
    assert {:ok, _} = resolve(cs, cb1, 0)
    assert resolve(cs, t2.txid, 0) == :missing
    assert resolve(cs, hd(b2.txs).txid, 0) == :missing
    assert {:ok, _} = resolve(cs, t3.txid, 0)

    # Reorg back: extend the original branch to 153 (the archived 151 is reused).
    b152 = BB.build(b151.header, [BB.coinbase(152, 25 * @coin)])
    assert {:ok, :stored} = State.submit_block(cs, b152)
    b153 = BB.build(b152.header, [BB.coinbase(153, 25 * @coin)])
    assert {:ok, :connected} = State.submit_block(cs, b153)
    assert resolve(cs, cb1, 0) == :missing
    assert {:ok, _} = resolve(cs, t2.txid, 0)
    assert {:ok, _} = resolve(cs, hd(b2.txs).txid, 0)

    # Batched resolution equals per-outpoint resolution for every outpoint
    # ever created on either branch (spent, unspent, missing, unknown).
    State.with_archive(cs, fn a ->
      all =
        for b <- bs ++ [b151, f151, f152, b152, b153],
            tx <- b.txs,
            v <- 0..length(tx.outputs),
            do: {tx.txid, v}

      all = all ++ [{<<1::256>>, 0}]
      batched = Archive.resolve_many(a, all)

      for {t, v} = op <- all,
          do: assert(batched[op] == Archive.resolve(a, t, v), "outpoint #{inspect(op)}")
    end)

    # Restart from disk.
    for pid <- [n.cs, n.hs], do: GenServer.stop(pid)
    KV.close(n.kv)
    n2 = start(dir)
    assert State.tip(n2.cs).hash == b153.header.hash
    assert {:ok, _} = resolve(n2.cs, t2.txid, 0)
    assert resolve(n2.cs, cb1, 0) == :missing

    State.with_archive(n2.cs, fn a ->
      assert Archive.read_block(a, Archive.id_at(a, 151)) == b151.raw
    end)

    _ = b3
  end

  test "segments written after the last KV commit are truncated on reopen",
       %{bs: bs, dir: dir} = n do
    for pid <- [n.cs, n.hs], do: GenServer.stop(pid)
    KV.close(n.kv)

    # Simulate a crash between "segments written" and "KV batch committed":
    # junk at the end of every segment file.
    for kind <- ["outputs", "inputs", "witness"],
        root <- ["hot", "cold"],
        d = Path.join([dir, root, kind]),
        File.dir?(d),
        f <- File.ls!(d) do
      File.write!(Path.join(d, f), :crypto.strong_rand_bytes(777), [:append])
    end

    n2 = start(dir)
    assert State.tip(n2.cs).height == 150
    tip = List.last(bs).header
    t = BB.spend_op_true(hd(hd(bs).txs).txid, 0, 50 * @coin)
    b = BB.build(tip, [BB.coinbase(151, 25 * @coin), t])
    assert {:ok, :connected} = State.submit_block(n2.cs, b)

    State.with_archive(n2.cs, fn a ->
      # The new block's records start where the committed data ended, not after the junk.
      assert Archive.read_block(a, Archive.id_at(a, 151)) == b.raw
      assert Archive.read_block(a, Archive.id_at(a, 150)) == List.last(bs).raw
      assert {:ok, %{value: v}} = Archive.resolve(a, t.txid, 0)
      assert v == 50 * @coin
    end)
  end

  test "tiny segments: sparse groups and blocks straddle segment files", %{bs: bs, dir: dir} do
    # 100-byte segments: blocks roll to new files every few blocks, so 64-id
    # sparse groups span many segments.
    {:ok, kv} = KV.open(Path.join(dir, "kv-tiny"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "tiny"),
        segment_max: 100
      )

    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    assert length(File.ls!(Path.join([dir, "tiny", "outputs"]))) > 20

    State.with_archive(cs, fn a ->
      for {b, h} <- Enum.with_index(bs, 1),
          do: assert(Archive.read_block(a, Archive.id_at(a, h)) == b.raw)

      ops = for b <- bs, tx <- b.txs, do: {tx.txid, 0}
      batched = Archive.resolve_many(a, ops)
      for {t, v} = op <- ops, do: assert(batched[op] == Archive.resolve(a, t, v))
      assert Enum.all?(ops, &match?({:ok, _}, batched[&1]))
    end)
  end

  test "received but unconnected blocks are kept on disk and survive a restart",
       %{bs: bs, dir: dir} = n do
    tip = List.last(bs).header
    b151 = BB.build(tip, [BB.coinbase(151, 25 * @coin)])
    b152 = BB.build(b151.header, [BB.coinbase(152, 25 * @coin)])
    b153 = BB.build(b152.header, [BB.coinbase(153, 25 * @coin)])
    # Headers first, so the blocks can arrive out of order.
    {:ok, _} = Headers.process_headers(n.hs, [b151.header, b152.header, b153.header])
    assert {:ok, :stored} = State.submit_block(n.cs, b153)
    assert {:ok, :stored} = State.submit_block(n.cs, b152)
    assert State.tip(n.cs).height == 150

    for pid <- [n.cs, n.hs], do: GenServer.stop(pid)
    KV.close(n.kv)
    n2 = start(dir)
    # Only 151 needs to be supplied; 152 and 153 come from the pending store.
    assert {:ok, :connected} = State.submit_block(n2.cs, b151)
    assert State.tip(n2.cs).hash == b153.header.hash
    # Connected blocks are removed from the pending store.
    assert KV.fold_prefix(n2.kv, :pending, <<>>, 0, fn _, c -> c + 1 end) == 0
  end

  test "startup recovers an archived branch after a durable partial reorg",
       %{bs: bs, dir: dir} = n do
    # Headers of the new most-work branch survive, but none of its data
    # does. The old blocks are already archived, with no pending copies.
    fork = BB.build(Enum.at(bs, -4).header, [BB.coinbase(148, 50 * @coin, <<0x52>>)])

    {more, _} =
      Enum.map_reduce(149..152, fork.header, fn h, prev ->
        b = BB.build(prev, [BB.coinbase(h, 25 * @coin)])
        {b.header, b.header}
      end)

    {:ok, _} = Headers.process_headers(n.hs, [fork.header | more])
    GenServer.stop(n.cs)
    # The on-disk state left by an interruption between DisconnectTip calls.
    a = Archive.open(n.kv, Path.join(dir, "hot"), Path.join(dir, "cold"), @p.genesis)
    {a, _} = Archive.disconnect_tip(a)
    {a, _} = Archive.disconnect_tip(a)
    assert Archive.tip(a).height == 148
    Archive.close(a)

    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: n.hs,
        kv: n.kv,
        hot: Path.join(dir, "hot"),
        cold: Path.join(dir, "cold")
      )

    assert State.tip(cs).hash == List.last(bs).header.hash
    assert State.tip(cs).height == 150
    assert {:ok, _} = resolve(cs, hd(hd(bs).txs).txid, 0)
  end

  test "equal-work bodies use activatable arrival order, not first header or map order",
       %{bs: bs} = n do
    parent = BB.build(List.last(bs).header, [BB.coinbase(151, 25 * @coin)])
    a = BB.build(parent.header, [BB.coinbase(152, 25 * @coin, <<0x52>>)])
    b = BB.build(parent.header, [BB.coinbase(152, 25 * @coin, <<0x53>>)])
    {:ok, _} = Headers.process_headers(n.hs, [parent.header, a.header])
    {:ok, _} = Headers.process_headers(n.hs, [b.header])
    assert Headers.best_header(n.hs).hash == a.header.hash
    assert {:ok, :stored} = State.submit_block(n.cs, b, requested: true)
    assert {:ok, :stored} = State.submit_block(n.cs, a, requested: true)
    assert {:ok, :connected} = State.submit_block(n.cs, parent, requested: true)
    assert State.tip(n.cs).hash == b.header.hash
    # No equal-work reorg back to the header-first branch.
    assert {:ok, :duplicate} = State.submit_block(n.cs, a)
    assert State.tip(n.cs).hash == b.header.hash
  end

  describe "rejections" do
    test "premature coinbase spend", %{cs: cs, bs: bs} do
      tip = List.last(bs).header
      young = Enum.at(bs, 60)
      t = BB.spend_op_true(hd(young.txs).txid, 0, 50 * @coin)
      b = BB.build(tip, [BB.coinbase(151, 25 * @coin), t])

      assert {:error, {:consensus, "bad-txns-premature-spend-of-coinbase"}} =
               State.submit_block(cs, b)

      assert State.tip(cs).height == 150
    end

    test "double spend within a block", %{cs: cs, bs: bs} do
      tip = List.last(bs).header
      cb = hd(hd(bs).txs).txid

      b =
        BB.build(tip, [
          BB.coinbase(151, 25 * @coin),
          BB.spend_op_true(cb, 0, 1),
          BB.spend_op_true(cb, 0, 2)
        ])

      assert {:error, {:consensus, "bad-txns-inputs-missingorspent"}} = State.submit_block(cs, b)
    end

    test "mutated block is rejected but its hash is not poisoned", %{cs: cs, bs: bs} do
      [b1, b2 | _] = bs
      tip = List.last(bs).header
      tx1 = BB.spend_op_true(hd(b1.txs).txid, 0, 50 * @coin)
      tx2 = BB.spend_op_true(hd(b2.txs).txid, 0, 50 * @coin)
      cb = BB.coinbase(151, 25 * @coin)
      mutated = BB.build(tip, [cb, tx1, tx2, tx2], merkle_txs: [cb, tx1, tx2])
      assert {:error, {:mutated, "bad-txns-duplicate"}} = State.submit_block(cs, mutated)
      honest = BB.build(tip, [cb, tx1, tx2])
      assert {:ok, :connected} = State.submit_block(cs, honest)
    end

    test "a mutated copy of a connected block is rejected as mutated, not a duplicate", %{
      cs: cs,
      bs: bs
    } do
      [b1, b2 | _] = bs
      tip = List.last(bs).header
      tx1 = BB.spend_op_true(hd(b1.txs).txid, 0, 50 * @coin)
      tx2 = BB.spend_op_true(hd(b2.txs).txid, 0, 50 * @coin)
      cb = BB.coinbase(151, 25 * @coin)
      honest = BB.build(tip, [cb, tx1, tx2])
      assert {:ok, :connected} = State.submit_block(cs, honest)

      mutated = BB.build(tip, [cb, tx1, tx2, tx2], merkle_txs: [cb, tx1, tx2])
      assert mutated.header.hash == honest.header.hash
      assert {:error, {:mutated, "bad-txns-duplicate"}} = State.submit_block(cs, mutated)
      assert {:ok, :duplicate} = State.submit_block(cs, honest)
      assert State.tip(cs).hash == honest.header.hash
    end

    test "invalid block is marked failed; its children are rejected as bad-prevblk", %{
      cs: cs,
      bs: bs
    } do
      tip = List.last(bs).header
      bad = BB.build(tip, [BB.coinbase(151, 25 * @coin + 1)])
      assert {:error, {:consensus, "bad-cb-amount"}} = State.submit_block(cs, bad)
      child = BB.build(bad.header, [BB.coinbase(152, 25 * @coin)])
      assert {:error, {:invalid_prev, "bad-prevblk"}} = State.submit_block(cs, child)
    end
  end
end
