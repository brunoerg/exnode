defmodule Exnode.Chain.PrefetchTest do
  @moduledoc """
  The prefetch stage (Chain.Prefetch) changes nothing but where the
  committed lookups run. The same block sequence goes through three chain
  states: prefetch with small batches (commits during the path, so
  prefetched answers go stale), prefetch with one large batch (nothing
  committed during the path, so the overlay must answer before the
  prefetched committed answers), and a reference without prefetch. Every
  submit result, rejection reason, tip, header status and every coin ever
  created agree.
  """
  use ExUnit.Case, async: true

  alias Exnode.Archive
  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  defp node(dir, name, opts) do
    {:ok, kv} = KV.open(Path.join([dir, name, "kv"]))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link(
        [params: @p, headers: hs, kv: kv, hot: Path.join([dir, name, "hot"]), listeners: [self()]] ++
          opts
      )

    %{cs: cs, hs: hs}
  end

  # Headers first, then all blocks but the first, then the first: one
  # activation connects the whole path (the case prefetch serves). Downloaded
  # blocks were requested (Core fRequested), so a fork with less work than
  # the tip so far is still stored.
  defp submit_path(n, blocks) do
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(blocks, & &1.header))
    rest = for b <- tl(blocks), do: State.submit_block(n.cs, b, requested: true)
    [State.submit_block(n.cs, hd(blocks), requested: true) | rest]
  end

  defp chain(prev, start_h, specs) do
    {blocks, _} =
      Enum.map_reduce(Enum.with_index(specs, 1), prev, fn {txs, i}, prev ->
        b = BB.build(prev, [BB.coinbase(start_h + i, 25 * @coin) | txs])
        {b, b.header}
      end)

    blocks
  end

  defp coins(n, ops), do: State.with_archive(n.cs, &Archive.resolve_many(&1, ops))

  test "warm cache: overlay-answered inputs are not looked up by prefetch; results equal no prefetch",
       %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    # Same batching; only the coin cache differs. With cache_bytes 0 the
    # overlay keeps no committed coins, so prefetch must look everything up.
    warm = node(dir, "warm", batch_blocks: 1000, prefetch_depth: 16, commit_at_tip: false)

    cold =
      node(dir, "cold",
        batch_blocks: 1000,
        prefetch_depth: 16,
        commit_at_tip: false,
        cache_bytes: 0
      )

    ref = node(dir, "ref", batch_blocks: 1000, prefetch_depth: 0, commit_at_tip: false)
    nodes = [warm, cold, ref]
    for n <- nodes, b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)
    for n <- nodes, do: State.commit_now(n.cs)

    cb = fn h -> hd(Enum.at(bs, h - 1).txs).txid end
    t = fn txid, v -> BB.spend_op_true(txid, v, 50 * @coin) end
    # 20 blocks spending committed coinbases (warm: cached), some also an
    # output of the previous path block (uncommitted: in every overlay).
    specs =
      for i <- 1..20 do
        if rem(i, 4) == 0,
          do: [t.(cb.(i), 0), t.(cb.(40 + i), 0)],
          else: [t.(cb.(i), 0)]
      end

    blocks = chain(List.last(bs).header, 150, specs)
    # The setup blocks were prefetched too: measure the path alone.
    before = Map.new(nodes, &{&1.cs, State.work_stats(&1.cs)})
    results = for n <- nodes, do: submit_path(n, blocks)
    assert Enum.uniq(results) |> length() == 1
    assert State.tip(warm.cs) == State.tip(ref.cs) and State.tip(cold.cs) == State.tip(ref.cs)
    assert State.tip(warm.cs).hash == List.last(blocks).header.hash

    delta = fn n, part ->
      now = State.work_stats(n.cs)[part]
      Map.new(now, fn {k, v} -> {k, v - Map.get(before[n.cs][part], k, 0)} end)
    end

    # The 25 inputs spend committed coinbases: cached in warm, not in cold.
    # Regtest enforces BIP30, so every block also looks up its own new
    # outputs: never cached, so looked up (a txindex miss) in both.
    inputs = Enum.sum(for b <- blocks, tx <- tl(b.txs), do: length(tx.inputs))
    bip30 = Enum.sum(for b <- blocks, tx <- b.txs, do: length(tx.outputs))
    assert inputs == 25
    w = delta.(warm, :prefetch)
    c = delta.(cold, :prefetch)
    assert w.considered == inputs + bip30 and c.considered == w.considered, inspect({w, c})
    assert c.omitted == 0 and c.sent == c.considered, inspect(c)
    assert w.omitted == inputs and w.sent == bip30, inspect(w)
    assert w.committed_ops == w.sent and c.committed_ops == c.sent
    # Output reads: none for warm (BIP30 misses read no outputs), one group
    # per cached-in-warm coinbase for cold.
    assert w.output_groups == 0 and c.output_groups == inputs, inspect({w, c})
    # The omitted inputs were answered by the overlay at use, not looked up
    # by the chain state instead: no fallback lookups on this path.
    assert delta.(warm, :chain_state).committed_ops == 0

    # Read after the counters: coins/2 resolves through the chain state.
    ops = for b <- bs ++ blocks, tx <- b.txs, v <- 0..(length(tx.outputs) - 1), do: {tx.txid, v}
    assert coins(warm, ops) == coins(ref, ops) and coins(cold, ops) == coins(ref, ops)
  end

  test "an omitted cached coin evicted before use is looked up by normal resolution",
       %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    n = node(dir, "n", batch_blocks: 1000, prefetch_depth: 0)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)
    State.commit_now(n.cs)

    cached = for h <- 1..10, do: {hd(Enum.at(bs, h - 1).txs).txid, 0}
    unknown = [{:crypto.hash(:sha256, "none"), 0}]
    ops = cached ++ unknown ++ [hd(cached)]

    # Prepare as a worker would: in another process, committed reader + hint.
    hint = State.peek_archive(n.cs, &Archive.overlay_hint/1)
    reader = State.peek_archive(n.cs, &Archive.reader/1)

    {answers, f} =
      Task.async(fn -> Archive.prefetch_answers(reader, ops, hint) end) |> Task.await()

    assert f == %{considered: 11, omitted: 10, sent: 1}
    # Omitted means absent, never :missing; only the committed lookup is in.
    assert Map.keys(answers) == unknown and answers[hd(unknown)] == :missing

    reference = State.peek_archive(n.cs, &Archive.resolve_many(&1, ops))
    assert Enum.count(reference, &match?({_, {:ok, _}}, &1)) == 10

    # Between preparation and use, the cache drops 3 of the omitted coins
    # (in the owner process, as an eviction would; the epoch is unchanged).
    evicted = Enum.take(cached, 3)

    {result, stats} =
      State.peek_archive(n.cs, fn a ->
        :ok = Exnode.Archive.Overlay.drop(a.overlay, evicted)
        Archive.take_stats()
        r = Archive.resolve_many(a, ops, answers)
        {r, Archive.take_stats()}
      end)

    assert result == reference
    # Exactly the evicted coins went to the committed lookup; the prefetched
    # answer and the still-cached coins did not.
    assert stats.committed_ops == 3
  end

  test "prefetch with stale epochs gives the same results as no prefetch, including a double spend after a commit",
       %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    pf = node(dir, "pf", batch_blocks: 3, prefetch_depth: 16)
    pf2 = node(dir, "pf2", batch_blocks: 1000, prefetch_depth: 16, commit_at_tip: false)
    ref = node(dir, "ref", batch_blocks: 1000, prefetch_depth: 0)
    nodes = [pf, pf2, ref]
    for n <- nodes, b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)
    for n <- [pf2, ref], do: State.commit_now(n.cs)

    cb = fn h -> hd(Enum.at(bs, h - 1).txs).txid end
    t = fn txid, v -> BB.spend_op_true(txid, v, 50 * @coin) end
    spend_cb = for h <- 1..40, into: %{}, do: {h, t.(cb.(h), 0)}

    # 30 blocks: each spends a mature coinbase; some spend outputs of earlier
    # blocks in the same path. Block 11 spends an output block 1 created,
    # and block 12 double-spends what block 2 spent: 10 blocks back, so
    # those blocks are retired but (in pf2) uncommitted, and only the
    # overlay knows; prefetched committed answers say "missing" and
    # "unspent". In pf a commit lies in between, so they are stale instead.
    specs =
      for i <- 1..30 do
        cond do
          i == 11 -> [spend_cb[i], t.(spend_cb[1].txid, 0)]
          i == 12 -> [BB.spend_op_true(cb.(2), 0, 50 * @coin - 3)]
          i in [5, 9, 20] -> [spend_cb[i], t.(spend_cb[i - 1].txid, 0)]
          true -> [spend_cb[i]]
        end
      end

    blocks = chain(List.last(bs).header, 150, specs)
    results = for n <- nodes, do: submit_path(n, blocks)
    assert Enum.uniq(results) |> length() == 1

    for _ <- nodes do
      assert_received {:block_invalid, h, {:consensus, "bad-txns-inputs-missingorspent"}}
      assert h == Enum.at(blocks, 11).header.hash
    end

    assert State.tip(pf.cs) == State.tip(ref.cs) and State.tip(pf2.cs) == State.tip(ref.cs)
    assert State.tip(pf.cs).hash == Enum.at(blocks, 10).header.hash
    stats = State.prefetch_stats(pf.cs)
    assert stats.used > 0, "no prefetched answer was used: #{inspect(stats)}"
    assert stats.stale > 0, "no prefetched answer went stale: #{inspect(stats)}"
    stats2 = State.prefetch_stats(pf2.cs)
    assert stats2.used >= 10 and stats2.stale == 0, inspect(stats2)
    assert State.prefetch_stats(ref.cs) == %{used: 0, stale: 0, none: 0}

    # Every coin ever created, and every header status, agree.
    ops = for b <- bs ++ blocks, tx <- b.txs, v <- 0..(length(tx.outputs) - 1), do: {tx.txid, v}
    assert coins(pf, ops) == coins(ref, ops) and coins(pf2, ops) == coins(ref, ops)

    for b <- blocks, n <- [pf, pf2] do
      assert HeaderIndex.lookup(Headers.index(n.hs), b.header.hash).status ==
               HeaderIndex.lookup(Headers.index(ref.hs), b.header.hash).status
    end

    # A reorg to a heavier fork of new blocks from block 5 (prefetched path).
    fork = chain(Enum.at(blocks, 4).header, 155, for(i <- 6..20, do: [t.(cb.(20 + i), 0)]))
    results = for n <- nodes, do: submit_path(n, fork)
    assert Enum.uniq(results) |> length() == 1
    assert State.tip(pf.cs) == State.tip(ref.cs) and State.tip(pf2.cs) == State.tip(ref.cs)
    assert State.tip(pf.cs).hash == List.last(fork).header.hash
    ops = ops ++ for b <- fork, tx <- b.txs, v <- 0..(length(tx.outputs) - 1), do: {tx.txid, v}
    assert coins(pf, ops) == coins(ref, ops) and coins(pf2, ops) == coins(ref, ops)

    # And back: extending the first branch past the fork reconnects its
    # archived blocks 6..11 (no prefetch on that path), then new ones that
    # spend coins the fork had spent.
    back = chain(Enum.at(blocks, 10).header, 161, for(i <- 1..12, do: [t.(cb.(20 + 5 + i), 0)]))
    results = for n <- nodes, do: submit_path(n, back)
    assert Enum.uniq(results) |> length() == 1
    assert State.tip(pf.cs) == State.tip(ref.cs) and State.tip(pf2.cs) == State.tip(ref.cs)
    assert State.tip(pf.cs).hash == List.last(back).header.hash
    ops = ops ++ for b <- back, tx <- b.txs, v <- 0..(length(tx.outputs) - 1), do: {tx.txid, v}
    assert coins(pf, ops) == coins(ref, ops) and coins(pf2, ops) == coins(ref, ops)
  end
end
