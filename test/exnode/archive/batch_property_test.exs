defmodule Exnode.Archive.BatchPropertyTest do
  @moduledoc """
  The in-memory batch and coin cache never change an
  answer. A node with random batch sizes and cache budgets (including a
  cache small enough to evict constantly), a reorg and a mid-batch kill must
  resolve every outpoint exactly as a reference node that commits every block
  and caches nothing.
  """
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Exnode.Archive
  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @moduletag timeout: 600_000
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000
  @op_true <<0x51>>

  defp fixture, do: for(raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1))

  defp start(dir, name, opts) do
    {:ok, kv} = KV.open(Path.join(dir, "#{name}-kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link(
        [params: @p, headers: hs, kv: kv, hot: Path.join(dir, "#{name}-hot")] ++ opts
      )

    %{kv: kv, hs: hs, cs: cs}
  end

  # A random branch of `n` blocks on `prev`, spending from `pool`
  # (`%{op => value}` of mature OP_TRUE coins). Each block spends a few coins,
  # makes in-block chains, and adds OP_RETURN (unspendable) outputs. Blocks get
  # `tag` in the coinbase so branches differ.
  defp branch(prev, height, n, pool, tag) do
    Enum.map_reduce(1..n, {prev, pool}, fn i, {prev, pool} ->
      h = height + i
      {txs, pool} = random_txs(pool, :rand.uniform(4) - 1)

      cb =
        BB.coinbase_with(h, 25 * @coin, outputs: [{25 * @coin, @op_true}, {0, <<0x6A, tag, i>>}])

      b = BB.build(prev, [cb | txs])
      {{b, pool}, {b.header, pool}}
    end)
    |> then(fn {pairs, acc} ->
      {Enum.map(pairs, &elem(&1, 0)), Enum.map(pairs, &elem(&1, 1)), acc}
    end)
  end

  defp random_txs(pool, 0), do: {[], pool}

  defp random_txs(pool, _k) when map_size(pool) == 0, do: {[], pool}

  defp random_txs(pool, k) do
    {op, value} = Enum.random(pool)
    pool = Map.delete(pool, op)
    parts = :rand.uniform(3)
    each = div(value, parts)
    outs = for _ <- 1..parts, do: {each, @op_true}
    outs = if :rand.uniform(3) == 1, do: outs ++ [{0, <<0x6A, 0x01>>}], else: outs
    t = BB.tx([op], outs)
    created = for v <- 0..(parts - 1), into: %{}, do: {{t.txid, v}, each}

    # Sometimes spend one of the new outputs in the same block (in-block chain).
    {txs, created} =
      if :rand.uniform(2) == 1 do
        t2 = BB.tx([{t.txid, 0}], [{each, @op_true}])
        {[t, t2], created |> Map.delete({t.txid, 0}) |> Map.put({t2.txid, 0}, each)}
      else
        {[t], created}
      end

    {more, pool} = random_txs(Map.merge(pool, created), k - 1)
    {txs ++ more, pool}
  end

  defp all_ops(blocks) do
    for b <- blocks, tx <- b.txs, v <- 0..length(tx.outputs), do: {tx.txid, v}
  end

  defp assert_same(test_node, ref, ops, label) do
    got = State.peek_archive(test_node.cs, &Archive.resolve_many(&1, ops))

    want =
      State.with_archive(ref.cs, fn a ->
        Map.new(ops, fn {t, v} = op -> {op, Archive.resolve(a, t, v)} end)
      end)

    for op <- ops do
      assert got[op] == want[op],
             "#{label}: #{inspect(op)} batched=#{inspect(got[op])} ref=#{inspect(want[op])}"
    end
  end

  # Archive.chain_tx_count at every height equals a running count of the
  # chain's txs (regtest genesis has 1), and is nil above the tip.
  defp assert_chain_tx(node, blocks, label) do
    want = [1 | Enum.scan(blocks, 1, &(&2 + length(&1.txs)))]
    n = length(blocks)

    got =
      State.with_archive(node.cs, fn a ->
        for h <- 0..(n + 1), do: Archive.chain_tx_count(a, h)
      end)

    assert got == want ++ [nil], label
  end

  property "batched, cached resolution equals the committed reference", %{tmp_dir: dir} do
    base = fixture()

    check all(
            seed <- integer(1..1_000_000),
            batch <- integer(1..40),
            cache <- member_of([0, 2_000, 1_000_000_000]),
            kill_at <- integer(5..55),
            max_runs: 12
          ) do
      :rand.seed(:exsss, {seed, batch, cache})
      run = Path.join(dir, "run-#{seed}-#{batch}-#{cache}")
      ref = start(run, "ref", batch_blocks: 1, cache_bytes: 0)
      tn = start(run, "test", batch_blocks: batch, cache_bytes: cache)

      for b <- base, node <- [ref, tn], do: {:ok, :connected} = State.submit_block(node.cs, b)

      # Mature coinbases of blocks 1..40 (spendable from height 151).
      pool =
        for b <- Enum.take(base, 40),
            into: %{},
            do: {{hd(b.txs).txid, 0}, hd(hd(b.txs).outputs).value}

      tip = List.last(base).header
      {main, pools, _} = branch(tip, 150, 60, pool, 1)

      # Headers first, so the best header is ahead and the batch fills up.
      for node <- [ref, tn],
          do: {:ok, _} = Headers.process_headers(node.hs, Enum.map(main, & &1.header))

      ops = all_ops(base ++ main) ++ [{<<1::256>>, 0}]

      tn =
        main
        |> Enum.with_index(1)
        |> Enum.reduce(tn, fn {b, i}, tn ->
          {:ok, :connected} = State.submit_block(ref.cs, b)
          {:ok, :connected} = State.submit_block(tn.cs, b)
          if rem(i, 7) == 0, do: assert_same(tn, ref, ops, "main #{i}")
          # The batch really holds uncommitted blocks (the property is not vacuous).
          {n, _} = State.peek_archive(tn.cs, &Archive.batch_size/1)
          if batch > 1 and i == 1, do: assert(n == 1)

          if i == kill_at do
            # Crash mid-batch: uncommitted blocks are lost, then reconnected
            # from their pending copies at restart.
            Process.unlink(tn.cs)
            Process.exit(tn.cs, :kill)
            GenServer.stop(tn.hs)
            KV.close(tn.kv)
            tn = start(run, "test", batch_blocks: batch, cache_bytes: cache)
            :ok = State.await_idle(tn.cs)
            assert State.tip(tn.cs).hash == b.header.hash
            tn
          else
            tn
          end
        end)

      assert_same(tn, ref, ops, "main end")
      assert_chain_tx(tn, base ++ main, "chain tx count, main end")

      # Reorg: a fork from 30 blocks below the tip, one block longer, that
      # spends a different random subset.
      fork_at = 150 + 30
      fork_prev = Enum.at(main, 30 - 1).header
      {fork, _, _} = branch(fork_prev, fork_at, 31, Enum.at(pools, 30 - 1), 2)

      for node <- [ref, tn],
          do: {:ok, _} = Headers.process_headers(node.hs, Enum.map(fork, & &1.header))

      ops = ops ++ all_ops(fork)

      # Downloaded after its headers, so requested: the fork has less work than
      # the tip until its last blocks (unrequested, those would be skipped).
      for b <- fork,
          node <- [ref, tn],
          do: {:ok, _} = State.submit_block(node.cs, b, requested: true)

      assert State.tip(tn.cs).hash == List.last(fork).header.hash
      assert State.tip(ref.cs).hash == List.last(fork).header.hash
      assert_same(tn, ref, ops, "after reorg")
      chain = base ++ Enum.take(main, 30) ++ fork
      for node <- [ref, tn], do: assert_chain_tx(node, chain, "chain tx count, after reorg")

      # A restart rebuilds the counts from the block records.
      GenServer.stop(tn.cs)
      GenServer.stop(tn.hs)
      KV.close(tn.kv)
      tn = start(run, "test", batch_blocks: batch, cache_bytes: cache)
      assert_chain_tx(tn, chain, "chain tx count, after restart")

      # Every block on the selected chain reconstructs byte-exactly.
      State.with_archive(tn.cs, fn a ->
        for {b, h} <- Enum.with_index(Enum.take(main, 30) ++ fork, 151),
            do: assert(Archive.read_block(a, Archive.id_at(a, h)) == b.raw)
      end)

      for node <- [ref, tn] do
        GenServer.stop(node.cs)
        GenServer.stop(node.hs)
        KV.close(node.kv)
      end
    end
  end
end
