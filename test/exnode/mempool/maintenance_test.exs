defmodule Exnode.Mempool.MaintenanceTest do
  @moduledoc """
  Mempool maintenance (the parts the bitcoind replay does not reach):
  TrimToSize (lowest-feerate chunk first, rolling minimum fee bump and
  decay), expiry (336 h), and removeForBlock of confirmed and conflicting
  txs. Runs a real chain state and mempool on a regtest chain built here,
  with coinbases to P2WSH(OP_TRUE).
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Tx
  alias Exnode.Mempool
  alias Exnode.Mempool.Pool
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @spk <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)

  defp spend({txid, vout, value}, fee, n \\ 1) do
    ins = [
      %Tx.In{
        prev_hash: txid,
        prev_index: vout,
        script_sig: <<>>,
        sequence: 0xFFFFFFFD,
        witness: [<<0x51>>]
      }
    ]

    outs = for _ <- 1..n, do: %Tx.Out{value: div(value - fee, n), script_pubkey: @spk}
    BB.finalize(%Tx{version: 2, inputs: ins, outputs: outs, locktime: 0})
  end

  setup %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    name = :"mp_#{System.unique_integer([:positive])}"
    {:ok, clock} = Agent.start_link(fn -> 1_800_000_000 end)

    {:ok, cs} =
      State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), mempool: name)

    # 120 blocks; coinbases 1..110 pay to P2WSH(OP_TRUE).
    {blocks, _} =
      Enum.map_reduce(1..120, @p.genesis.header, fn h, prev ->
        b =
          BB.build(prev, [
            BB.coinbase_with(h, 50 * 100_000_000, outputs: [{50 * 100_000_000, @spk}])
          ])

        {b, b.header}
      end)

    for b <- blocks, do: {:ok, :connected} = State.submit_block(cs, b)
    coins = for b <- Enum.take(blocks, 110), do: {hd(b.txs).txid, 0, 50 * 100_000_000}

    start_mp = fn policy ->
      {:ok, mp} =
        Mempool.start_link(
          name: name,
          chain_state: cs,
          headers: hs,
          params: @p,
          policy: policy,
          clock: fn -> Agent.get(clock, & &1) end
        )

      mp
    end

    %{cs: cs, coins: coins, start_mp: start_mp, clock: clock, last: List.last(blocks)}
  end

  test "trim evicts the lowest-feerate chunk, bumps the rolling min fee, and it decays", %{
    coins: coins,
    start_mp: start_mp,
    clock: clock,
    cs: cs,
    last: last
  } do
    # The usage approximation is ~0.9 kB per 1-in/1-out tx: room for about 6.
    mp = start_mp.(max_size: 6_000)

    fees = [
      500,
      2_000,
      1_000,
      3_000,
      4_000,
      5_000,
      6_000,
      7_000,
      8_000,
      9_000,
      10_000,
      11_000,
      12_000
    ]

    txs = for {c, f} <- Enum.zip(coins, fees), do: spend(c, f)
    results = for t <- txs, do: Mempool.accept(mp, t)

    # Some txs were evicted, cheapest first; the 500-sat one is gone.
    in_pool = for t <- txs, Mempool.has?(mp, t.txid), do: t
    assert length(in_pool) < length(txs)
    refute Mempool.has?(mp, hd(txs).txid)
    assert Mempool.has?(mp, List.last(txs).txid)
    _ = results

    # The rolling minimum is now above the cheapest survivor's evicted peers:
    # a new 500-sat tx is refused by "mempool min fee not met".
    low = spend(Enum.at(coins, 14), 500)
    assert {:error, %{reason: "mempool min fee not met"}} = Mempool.accept(mp, low)

    # No block since the bump: no decay, even after 12 hours.
    Agent.update(clock, &(&1 + 12 * 3600))

    assert {:error, %{reason: "mempool min fee not met"}} =
             Mempool.accept(mp, spend(Enum.at(coins, 15), 500))

    # After a block, the rolling minimum decays (halflife 12 h, shorter while the
    # pool is small) and finally drops to zero: the cheap tx passes the fee
    # check, then is trimmed at once as the worst chunk of a full pool
    # (Core's "mempool full").
    blk = BB.build(last.header, [BB.coinbase_with(121, 0, outputs: [{50 * 100_000_000, @spk}])])
    {:ok, :connected} = State.submit_block(cs, blk)
    :ok = Mempool.sync_to(mp, blk.header.hash)
    Agent.update(clock, &(&1 + 7 * 24 * 3600))

    assert {:error, %{reason: "mempool full"}} =
             Mempool.accept(mp, spend(Enum.at(coins, 16), 500))
  end

  test "expiry removes txs older than 336 hours (with descendants)", %{
    coins: coins,
    start_mp: start_mp,
    clock: clock
  } do
    mp = start_mp.([])
    parent = spend(Enum.at(coins, 0), 1_000)
    child = spend({parent.txid, 0, hd(parent.outputs).value}, 1_000)
    {:ok, _} = Mempool.accept(mp, parent)
    {:ok, _} = Mempool.accept(mp, child)

    Agent.update(clock, &(&1 + 336 * 3600 + 1))
    # LimitMempoolSize (with Expire) runs on the next acceptance.
    {:ok, _} = Mempool.accept(mp, spend(Enum.at(coins, 1), 1_000))
    refute Mempool.has?(mp, parent.txid)
    refute Mempool.has?(mp, child.txid)
    assert Mempool.size(mp) == 1
  end

  test "a block removes confirmed txs and txs conflicting with it", %{
    cs: cs,
    coins: coins,
    start_mp: start_mp,
    last: last
  } do
    mp = start_mp.([])
    a = spend(Enum.at(coins, 0), 1_000)
    b = spend(Enum.at(coins, 1), 1_000)
    b_child = spend({b.txid, 0, hd(b.outputs).value}, 1_000)
    # A conflicting spend of b's input, mined instead of b.
    b2 = spend(Enum.at(coins, 1), 3_000, 2)
    for t <- [a, b, b_child], do: {:ok, _} = Mempool.accept(mp, t)

    cb = fn extra, wit ->
      BB.coinbase_with(121, 0, outputs: [{50 * 100_000_000 + 4_000, @spk} | extra], witness: wit)
    end

    blk = BB.build_segwit(last.header, cb, [a, b2])
    {:ok, :connected} = State.submit_block(cs, blk)
    :ok = Mempool.sync_to(mp, blk.header.hash)

    refute Mempool.has?(mp, a.txid)
    refute Mempool.has?(mp, b.txid)
    refute Mempool.has?(mp, b_child.txid)
    assert Mempool.size(mp) == 0
  end

  # Regression: the unbroadcast set was pruned only when a
  # peer requested the tx. A local tx that left the pool (here expired) and
  # was accepted again from P2P still read as unbroadcast.
  test "a tx that leaves the pool leaves the unbroadcast set", %{
    coins: coins,
    start_mp: start_mp,
    clock: clock
  } do
    mp = start_mp.([])
    t = spend(Enum.at(coins, 0), 1_000)
    {:ok, _} = Mempool.accept(mp, t, unbroadcast: true)
    assert Mempool.unbroadcast?(mp, t.txid)

    Agent.update(clock, &(&1 + 336 * 3600 + 1))
    {:ok, _} = Mempool.accept(mp, spend(Enum.at(coins, 1), 1_000))
    refute Mempool.has?(mp, t.txid)
    assert Mempool.unbroadcast_count(mp) == 0

    # Back from a peer (no unbroadcast flag): not a local submission.
    {:ok, _} = Mempool.accept(mp, t)
    refute Mempool.unbroadcast?(mp, t.txid)
  end

  # Regression: a reorg re-adds a tx whose child is
  # already in the mempool; the two must be linked (Core:
  # UpdateTransactionsFromBlock), or removing the parent leaves the child
  # spending an output that exists nowhere.
  test "a reorg links re-added txs to their mempool children; a later conflict removes both",
       %{cs: cs, coins: coins, start_mp: start_mp, last: last} do
    mp = start_mp.([])

    cb = fn h, value ->
      fn extra, wit -> BB.coinbase_with(h, 0, outputs: [{value, @spk} | extra], witness: wit) end
    end

    # p confirmed in 121; its child c enters the mempool.
    p = spend(Enum.at(coins, 0), 1_000)
    b121 = BB.build_segwit(last.header, cb.(121, 50 * 100_000_000 + 1_000), [p])
    {:ok, :connected} = State.submit_block(cs, b121)
    :ok = Mempool.sync_to(mp, b121.header.hash)
    c = spend({p.txid, 0, hd(p.outputs).value}, 1_000)
    {:ok, _} = Mempool.accept(mp, c)

    # A longer fork without p: 121 is disconnected and p comes back.
    f121 = BB.build_segwit(last.header, cb.(121, 49 * 100_000_000), [])
    f122 = BB.build_segwit(f121.header, cb.(122, 49 * 100_000_000), [])
    for b <- [f121, f122], do: {:ok, _} = State.submit_block(cs, b)
    assert State.tip(cs).hash == f122.header.hash
    :ok = Mempool.sync_to(mp, f122.header.hash)

    assert Mempool.has?(mp, p.txid)
    assert Mempool.has?(mp, c.txid)
    assert MapSet.member?(Mempool.entry(mp, p.txid).children, c.txid)
    assert MapSet.member?(Mempool.entry(mp, c.txid).parents, p.txid)
    pool = Mempool.pool(mp)
    assert Pool.cluster(pool, p.txid) == Pool.cluster(pool, c.txid)

    # A block mining a conflicting spend of p's input: p and its child go.
    p2 = spend(Enum.at(coins, 0), 3_000, 2)
    f123 = BB.build_segwit(f122.header, cb.(123, 50 * 100_000_000 + 3_000), [p2])
    {:ok, :connected} = State.submit_block(cs, f123)
    :ok = Mempool.sync_to(mp, f123.header.hash)
    refute Mempool.has?(mp, p.txid)
    refute Mempool.has?(mp, c.txid)
    assert Mempool.size(mp) == 0
  end

  # Regression: a re-added tx merges the clusters of all its
  # in-pool children with no limit check. Here three 30-tx chains (each a
  # legal cluster) become one 91-tx cluster; with more outputs the merged
  # cluster grows without bound and its linearization blocks the mempool
  # for minutes. Core trims oversized clusters after the re-add.
  test "a reorg re-add that merges child clusters past the limit is trimmed back",
       %{cs: cs, coins: coins, start_mp: start_mp, last: last} do
    mp = start_mp.([])

    cb = fn h, value ->
      fn extra, wit -> BB.coinbase_with(h, 0, outputs: [{value, @spk} | extra], witness: wit) end
    end

    p = spend(Enum.at(coins, 0), 3_000, 3)
    b121 = BB.build_segwit(last.header, cb.(121, 50 * 100_000_000 + 3_000), [p])
    {:ok, :connected} = State.submit_block(cs, b121)
    :ok = Mempool.sync_to(mp, b121.header.hash)

    chains =
      for v <- 0..2 do
        {chain, _} =
          Enum.map_reduce(1..30, {p.txid, v, Enum.at(p.outputs, v).value}, fn _, coin ->
            t = spend(coin, 500)
            {t, {t.txid, 0, hd(t.outputs).value}}
          end)

        for t <- chain, do: {:ok, _} = Mempool.accept(mp, t)
        chain
      end

    pool = Mempool.pool(mp)
    assert MapSet.size(Pool.cluster(pool, hd(hd(chains)).txid)) == 30

    f121 = BB.build_segwit(last.header, cb.(121, 49 * 100_000_000), [])
    f122 = BB.build_segwit(f121.header, cb.(122, 49 * 100_000_000), [])
    for b <- [f121, f122], do: {:ok, _} = State.submit_block(cs, b)
    :ok = Mempool.sync_to(mp, f122.header.hash)

    pool = Mempool.pool(mp)
    assert Pool.exists?(pool, p.txid)
    cluster = Pool.cluster(pool, p.txid)
    assert MapSet.size(cluster) <= Pool.cluster_count_limit()
    # 1 + 90 txs before the trim; what was dropped was a descendant-closed set.
    assert Pool.size(pool) == MapSet.size(cluster)
    assert Pool.size(pool) < 91

    for {txid, e} <- pool.entries,
        i <- e.tx.inputs,
        txid != p.txid,
        do: assert(Pool.exists?(pool, i.prev_hash), "#{Base.encode16(txid)} lost its parent")
  end

  # Regression: a reorg spanning several chain-state turns
  # reaches the mempool as several updates, while the chain view it re-adds
  # against already includes the later reconnects. A disconnected tx that is
  # confirmed again in that view ("txn-already-known") must not take its
  # valid mempool children with it.
  test "a re-add judged against a view that already reconnected the tx keeps its children",
       %{cs: cs, coins: coins, start_mp: start_mp, last: last} do
    mp = start_mp.([])

    cb = fn extra, wit ->
      BB.coinbase_with(121, 0, outputs: [{50 * 100_000_000 + 1_000, @spk} | extra], witness: wit)
    end

    p = spend(Enum.at(coins, 0), 1_000)
    b121 = BB.build_segwit(last.header, cb, [p])
    {:ok, :connected} = State.submit_block(cs, b121)
    :ok = Mempool.sync_to(mp, b121.header.hash)
    c = spend({p.txid, 0, hd(p.outputs).value}, 1_000)
    {:ok, _} = Mempool.accept(mp, c)

    # The first update of such a reorg: p's block disconnected; the view
    # (the chain state) has p confirmed again.
    send(mp, {:mempool_update, b121.header.hash, [{:disconnected, [hd(b121.txs), p]}]})
    :ok = Mempool.sync_to(mp, b121.header.hash)

    refute Mempool.has?(mp, p.txid)
    assert Mempool.has?(mp, c.txid)
  end

  # Regression: the chain state sent a reorg's disconnect events to the
  # mempool at the end of the turn that disconnected, before the replacement
  # blocks connected (their scripts were still running). The mempool then
  # re-added and re-verified txs the new chain confirms again, and trimmed
  # the pool before they left it. Core keeps the disconnectpool until the
  # new chain has more work than the old tip (ActivateBestChainStep).
  test "a reorg reaches the mempool with its connects, so reconfirmed txs are not re-added",
       %{cs: cs, coins: coins, start_mp: start_mp, last: last} do
    mp = start_mp.([])

    cb = fn h, value ->
      fn extra, wit -> BB.coinbase_with(h, 0, outputs: [{value, @spk} | extra], witness: wit) end
    end

    p = spend(Enum.at(coins, 0), 1_000)
    b121 = BB.build_segwit(last.header, cb.(121, 50 * 100_000_000 + 1_000), [p])
    {:ok, :connected} = State.submit_block(cs, b121)
    :ok = Mempool.sync_to(mp, b121.header.hash)

    # The fork confirms p again; its first block has a script to verify.
    f121 = BB.build_segwit(last.header, cb.(121, 49 * 100_000_000 + 1_000), [p])
    f122 = BB.build_segwit(f121.header, cb.(122, 49 * 100_000_000), [])
    :erlang.trace(mp, true, [:receive])
    for b <- [f121, f122], do: {:ok, _} = State.submit_block(cs, b)
    assert State.tip(cs).hash == f122.header.hash
    :ok = Mempool.sync_to(mp, f122.header.hash)
    :erlang.trace(mp, false, [:receive])

    updates = collect_updates(mp)
    assert updates != []

    for events <- updates do
      kinds = Enum.map(events, &elem(&1, 0))
      # Every disconnect arrives with the connects that follow it.
      if :disconnected in kinds, do: assert(List.last(kinds) == :connected, inspect(kinds))
    end

    refute Mempool.has?(mp, p.txid)
  end

  # Regression: after a reorg, the final/mature check read every mempool
  # entry's chain coins with one chain-state call per entry (only the
  # disconnected txs' coins were prefetched). Core's filter_final_and_mature
  # reads coins only for entries spending a coinbase or with relative locks
  # whose inputs moved.
  test "after a reorg the final/mature check does not query the chain state per entry",
       %{cs: cs, coins: coins, start_mp: start_mp, last: last} do
    mp = start_mp.([])

    cb = fn h, value ->
      fn extra, wit -> BB.coinbase_with(h, 0, outputs: [{value, @spk} | extra], witness: wit) end
    end

    n = 30
    p = spend(Enum.at(coins, 0), 1_000, n)
    b121 = BB.build_segwit(last.header, cb.(121, 50 * 100_000_000 + 1_000), [p])
    b122 = BB.build_segwit(b121.header, cb.(122, 50 * 100_000_000), [])

    for b <- [b121, b122], do: {:ok, :connected} = State.submit_block(cs, b)
    :ok = Mempool.sync_to(mp, b122.header.hash)

    for {o, v} <- Enum.with_index(p.outputs),
        do: {:ok, _} = Mempool.accept(mp, spend({p.txid, v, o.value}, 500))

    assert Mempool.size(mp) == n

    f122 = BB.build_segwit(b121.header, cb.(122, 49 * 100_000_000), [])
    f123 = BB.build_segwit(f122.header, cb.(123, 49 * 100_000_000), [])
    :erlang.trace(cs, true, [:receive])
    for b <- [f122, f123], do: {:ok, _} = State.submit_block(cs, b)
    :ok = Mempool.sync_to(mp, f123.header.hash)
    :erlang.trace(cs, false, [:receive])

    assert Mempool.size(mp) == n
    views = count_views(cs, mp)
    assert views < 5, "#{views} mempool_view calls"
  end

  defp collect_updates(mp) do
    receive do
      {:trace, ^mp, :receive, {:mempool_update, _, events}} -> [events | collect_updates(mp)]
      {:trace, ^mp, :receive, _} -> collect_updates(mp)
    after
      200 -> []
    end
  end

  defp count_views(cs, mp) do
    receive do
      {:trace, ^cs, :receive, {:"$gen_call", {^mp, _}, {:mempool_view, _}}} ->
        1 + count_views(cs, mp)

      {:trace, ^cs, :receive, _} ->
        count_views(cs, mp)
    after
      200 -> 0
    end
  end
end
