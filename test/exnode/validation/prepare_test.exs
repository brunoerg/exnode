defmodule Exnode.Validation.PrepareTest do
  @moduledoc """
  The pure preparation engine against the
  reference: `Prepare.check(block, Prepare.populate(...))` must return
  exactly what `Connect.connect_block/6` returns (every field of a success,
  the same first failure), for the same archive, header context, view and
  options. Run inside the chain state (`peek_archive`), on top of the
  150-block regtest fixture (CSV active, BIP30 enforced at every height).
  """
  use ExUnit.Case, async: true
  import Bitwise

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Validation.{Connect, Prepare}

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  setup %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"))
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    %{cs: cs, hs: hs, bs: bs, tip: List.last(bs).header}
  end

  defp cb(bs, h), do: hd(Enum.at(bs, h - 1).txs).txid

  # Both engines on `block` (headers accepted first), with `opts` built
  # from the archive (base_out etc.) by `opts_fun`.
  defp both(t, block, opts_fun \\ fn _a -> [scripts: :defer] end) do
    {:ok, _} = Headers.process_headers(t.hs, [block.header])
    idx = Headers.index(t.hs)
    entry = HeaderIndex.lookup(idx, block.header.hash)

    State.peek_archive(t.cs, fn a ->
      opts = opts_fun.(a)
      ref = Connect.connect_block(a, block, entry, @p, idx, opts)
      new = Prepare.check(block, Prepare.populate(a, block, entry, @p, idx, opts))
      {ref, new}
    end)
  end

  defp same(t, block, opts_fun \\ fn _a -> [scripts: :defer] end) do
    {ref, new} = both(t, block, opts_fun)
    assert new == ref
    ref
  end

  defp spend(txid, v, value, opts \\ []), do: BB.tx([{txid, v, opts}], [{value, <<0x51>>}])

  defp block(t, txs, cb_value \\ 25 * @coin),
    do: BB.build(t.tip, [BB.coinbase(151, cb_value) | txs])

  test "valid spends, in both scripts modes", t do
    b = block(t, for(h <- 1..5, do: spend(cb(t.bs, h), 0, 50 * @coin - 1_000)))
    assert {:ok, %{fees: 5_000, checks: [_ | _]}} = same(t, b)

    assert {:ok, %{checks: nil, scripts_checked: false}} =
             same(t, b, fn _ -> [scripts: false] end)
  end

  test "same-block order: earlier outputs only; double spends; forward references", t do
    t1 = spend(cb(t.bs, 1), 0, 50 * @coin)
    t2 = spend(t1.txid, 0, 50 * @coin)
    assert {:ok, _} = same(t, block(t, [t1, t2]))
    assert {:error, {:consensus, "bad-txns-inputs-missingorspent"}} = same(t, block(t, [t2, t1]))
    dup = spend(cb(t.bs, 1), 0, 50 * @coin - 7)
    assert {:error, {:consensus, "bad-txns-inputs-missingorspent"}} = same(t, block(t, [t1, dup]))
  end

  test "maturity, values, fees and reward", t do
    # Coinbase of height 100 at 151: 51 confirmations.
    assert {:error, {:consensus, "bad-txns-premature-spend-of-coinbase"}} =
             same(t, block(t, [spend(cb(t.bs, 100), 0, 50 * @coin)]))

    assert {:error, {:consensus, "bad-txns-in-belowout"}} =
             same(t, block(t, [spend(cb(t.bs, 1), 0, 50 * @coin + 1)]))

    assert {:error, {:consensus, "bad-cb-amount"}} =
             same(t, block(t, [spend(cb(t.bs, 1), 0, 50 * @coin - 10)], 25 * @coin + 11))

    assert {:ok, %{fees: 10}} =
             same(t, block(t, [spend(cb(t.bs, 1), 0, 50 * @coin - 10)], 25 * @coin + 10))
  end

  test "BIP30: an output with an unspent duplicate txid is refused", t do
    # Block 1's coinbase again (same height script, same outputs): same txid, unspent.
    dup_cb = hd(Enum.at(t.bs, 0).txs)
    b = BB.build(t.tip, [dup_cb])
    {ref, new} = both(t, b)
    assert new == ref
    assert ref == {:error, {:consensus, "bad-txns-BIP30"}}
  end

  test "BIP68: height and time relative locks, at the boundaries", t do
    # BB.tx builds version 2 txs (BIP68 applies when the disable bit is clear).
    v2 = fn txid, seq -> spend(txid, 0, 50 * @coin, sequence: seq) end
    # Height lock: coin at height h, lock n: needs h + n - 1 < 151.
    ok_h = v2.(cb(t.bs, 1), 149)
    bad_h = v2.(cb(t.bs, 2), 150)
    assert {:ok, _} = same(t, block(t, [ok_h]))
    assert {:error, {:consensus, "bad-txns-nonfinal"}} = same(t, block(t, [bad_h]))
    # Time lock (type flag): 0 units passes; a huge one fails.
    type = 1 <<< 22
    assert {:ok, _} = same(t, block(t, [v2.(cb(t.bs, 3), type)]))

    assert {:error, {:consensus, "bad-txns-nonfinal"}} =
             same(t, block(t, [v2.(cb(t.bs, 4), type ||| 0xFFFF)]))

    # A time lock on an output of the same block (coin height = 151).
    t1 = spend(cb(t.bs, 5), 0, 50 * @coin)
    t2 = v2.(t1.txid, type)
    assert {:ok, _} = same(t, block(t, [t1, t2]))
  end

  test "BIP68 time lock exactly at the MTP boundary", t do
    # Coin at height h: locked until MTP(h - 1) + units * 512 - 1 < MTP(150).
    idx = Headers.index(t.hs)
    tip = HeaderIndex.lookup(idx, t.tip.hash)
    mtp = fn h -> HeaderIndex.median_time_past(idx, HeaderIndex.ancestor(idx, tip, h)) end
    type = 1 <<< 22

    for h <- [2, 20, 50] do
      units = div(mtp.(150) - mtp.(h - 1), 512)
      # Largest passing lock, then one unit more.
      pass = spend(cb(t.bs, h), 0, 50 * @coin, sequence: type ||| units)
      fail = spend(cb(t.bs, h), 0, 50 * @coin, sequence: type ||| units + 1)
      assert {:ok, _} = same(t, block(t, [pass]))
      assert {:error, {:consensus, "bad-txns-nonfinal"}} = same(t, block(t, [fail]))
    end
  end

  # Core EvaluateSequenceLocks: a relative time lock is satisfied only if
  # min_time < prev MTP, where min_time = MTP(coin height - 1) + units *
  # 512 - 1. The fixture's timestamps cannot make the two equal, so a
  # candidate branch of 11 empty blocks (connected) is built on 150 with
  # timestamps putting its MTP exactly at `min_time + offset`; the spender
  # is the 12th block. Expected verdicts are Core's, not only agreement.
  defp time_lock_at(t, offset) do
    idx = Headers.index(t.hs)
    tip = HeaderIndex.lookup(idx, t.tip.hash)
    mtp = fn e -> HeaderIndex.median_time_past(idx, e) end
    coin_h = 2
    m_coin = mtp.(HeaderIndex.ancestor(idx, tip, coin_h - 1))
    # Enough units that the branch's times are all above MTP(150).
    units = div(mtp.(tip) - m_coin, 512) + 2
    min_time = m_coin + units * 512 - 1
    target = min_time + offset

    # Strictly increasing times; the MTP of 151..161 is the 6th (156) = target.
    {branch, last} =
      Enum.map_reduce(151..161, t.tip, fn h, prev ->
        b = BB.build(prev, [BB.coinbase(h, 25 * @coin)], time: target + h - 156)
        {b, b.header}
      end)

    for b <- branch, do: {:ok, :connected} = State.submit_block(t.cs, b)
    idx = Headers.index(t.hs)
    prev_mtp = mtp.(HeaderIndex.lookup(idx, last.hash))
    assert prev_mtp == target
    assert prev_mtp - min_time == offset

    tx = spend(cb(t.bs, coin_h), 0, 50 * @coin, sequence: 1 <<< 22 ||| units)
    b = BB.build(last, [BB.coinbase(162, 25 * @coin), tx], time: target + 6)
    {ref, new} = both(t, b)
    assert new == ref
    ref
  end

  test "BIP68 time lock: min_time == prev MTP is nonfinal (Core: lockPair.second >= nBlockTime)",
       t do
    assert time_lock_at(t, 0) == {:error, {:consensus, "bad-txns-nonfinal"}}
  end

  test "BIP68 time lock: min_time == prev MTP - 1 is final", t do
    assert {:ok, %{spent: [_]}} = time_lock_at(t, 1)
  end

  test "a speculative chain: the second block seen through the first's delta", t do
    t1 = spend(cb(t.bs, 1), 0, 50 * @coin)
    b1 = block(t, [t1])
    {:ok, r1} = same(t, b1)
    t2 = spend(t1.txid, 0, 50 * @coin)
    b2 = BB.build(b1.header, [BB.coinbase(152, 25 * @coin), t2])

    opts = fn a ->
      [scripts: :defer, view: [r1.delta], base_out: Exnode.Archive.next_ids(a).out + r1.n_outputs]
    end

    assert {:ok, %{spent: [_]}} = same(t, b2, opts)
    # A double spend across the two blocks.
    b2x =
      BB.build(b1.header, [BB.coinbase(152, 25 * @coin), spend(cb(t.bs, 1), 0, 50 * @coin - 3)])

    assert {:error, {:consensus, "bad-txns-inputs-missingorspent"}} = same(t, b2x, opts)
  end

  test "random blocks: same result and first failure as the reference", t do
    :rand.seed(:exsss, {7, 11, 13})

    for i <- 1..200 do
      n = :rand.uniform(6)

      {txs, _} =
        Enum.map_reduce(1..n, [], fn _, made ->
          tx =
            case {:rand.uniform(6), made} do
              # Spend an earlier tx of this block.
              {1, [m | _]} ->
                spend(m.txid, 0, 50 * @coin - :rand.uniform(100))

              # A premature or mature coinbase, maybe overspent.
              {2, _} ->
                spend(cb(t.bs, :rand.uniform(150)), 0, 50 * @coin - :rand.uniform(3) + 1)

              # A non-existent output.
              {3, _} ->
                spend(:crypto.strong_rand_bytes(32), 0, 1)

              # A relative lock.
              {4, _} ->
                spend(cb(t.bs, :rand.uniform(60)), 0, 50 * @coin, sequence: :rand.uniform(200))

              _ ->
                spend(cb(t.bs, :rand.uniform(50)), 0, 50 * @coin - :rand.uniform(1_000))
            end

          {tx, [tx | made]}
        end)

      b = block(t, txs, 25 * @coin + :rand.uniform(3_000))
      {ref, new} = both(t, b, fn _ -> [scripts: Enum.random([:defer, false])] end)
      assert new == ref, "random block #{i}"
    end
  end
end
