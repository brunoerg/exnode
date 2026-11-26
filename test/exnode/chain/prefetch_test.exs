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
    # Answers that crossed a commit: carried over one (revalidated) or stale.
    assert stats.stale + stats.revalidated > 0,
           "no prefetched answer crossed a commit: #{inspect(stats)}"

    stats2 = State.prefetch_stats(pf2.cs)
    assert stats2.used >= 10 and stats2.stale == 0 and stats2.revalidated == 0, inspect(stats2)

    assert State.prefetch_stats(ref.cs) ==
             %{used: 0, revalidated: 0, reval_dropped: 0, stale: 0, none: 0}

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

  test "answers carried over one commit drop what it changed: a spend of a batch output, a double spend",
       %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    # A commit when the 20th block of the path retires. Preparation (which
    # takes the prefetched answers) runs at most 8 blocks ahead of
    # retirement, and prefetch 11 ahead of preparation: blocks 29 and 30
    # are prefetched before that commit (when block 18, 19 is prepared)
    # and prepared after it, before the next.
    pf =
      node(dir, "pf",
        batch_blocks: 20,
        batch_ms: 600_000,
        batch_ms_behind: 600_000,
        prefetch_depth: 11,
        commit_at_tip: false,
        # No coin cache: after the commit, coins come from the committed
        # state, not from the overlay.
        cache_bytes: 0
      )

    ref = node(dir, "ref", batch_blocks: 1000, prefetch_depth: 0)
    nodes = [pf, ref]
    for n <- nodes, b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)
    for n <- nodes, do: State.commit_now(n.cs)

    cb = fn h -> hd(Enum.at(bs, h - 1).txs).txid end
    spend = for h <- 1..30, into: %{}, do: {h, BB.spend_op_true(cb.(h), 0, 50 * @coin)}

    # Blocks 29 and 30 are prefetched before blocks 19 and 20 connect, so
    # the hint knows nothing of their effects: block 29 spends an output
    # block 19 created (prefetched: missing), block 30 double-spends what
    # block 20 spent (prefetched: unspent). The commit archives both, and
    # then only the committed state knows: revalidation must drop both
    # answers.
    specs =
      for i <- 1..30 do
        cond do
          i == 29 -> [spend[i], BB.spend_op_true(spend[19].txid, 0, 50 * @coin - 1)]
          i == 30 -> [BB.spend_op_true(cb.(20), 0, 50 * @coin - 3)]
          true -> [spend[i]]
        end
      end

    blocks = chain(List.last(bs).header, 150, specs)
    results = for n <- nodes, do: submit_path(n, blocks)
    assert Enum.uniq(results) |> length() == 1

    for _ <- nodes do
      assert_received {:block_invalid, h, {:consensus, "bad-txns-inputs-missingorspent"}}
      assert h == List.last(blocks).header.hash
    end

    assert State.tip(pf.cs) == State.tip(ref.cs)
    assert State.tip(pf.cs).hash == Enum.at(blocks, 28).header.hash

    stats = State.prefetch_stats(pf.cs)
    assert stats.revalidated >= 2 and stats.stale == 0, inspect(stats)
    # Block 29's and block 30's answers the commit changed.
    assert stats.reval_dropped >= 2, inspect(stats)

    ops = for b <- bs ++ blocks, tx <- b.txs, v <- 0..(length(tx.outputs) - 1), do: {tx.txid, v}
    assert coins(pf, ops) == coins(ref, ops)
  end

  test "post-BIP34 linear chain skips txindex history reads and falls back on reorg", %{
    tmp_dir: dir
  } do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    b150 = List.last(bs)
    p_bip34 = %{@p | bip34_height: 150, bip34_hash: b150.header.hash}

    start_node = fn name, extra ->
      {:ok, kv} = KV.open(Path.join([dir, name, "kv"]))
      {:ok, hs} = Headers.start_link(params: p_bip34, kv: kv)

      {:ok, cs} =
        State.start_link(
          [
            params: p_bip34,
            headers: hs,
            kv: kv,
            hot: Path.join([dir, name, "hot"]),
            listeners: [self()]
          ] ++ extra
        )

      %{cs: cs, hs: hs, kv: kv}
    end

    pf = start_node.("pf", batch_blocks: 1000, prefetch_depth: 16, commit_at_tip: false)
    ref = start_node.("ref", batch_blocks: 1000, prefetch_depth: 0, commit_at_tip: false)

    for n <- [pf, ref] do
      for b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)
      State.commit_now(n.cs)
    end

    cb = fn h -> hd(Enum.at(bs, h - 1).txs).txid end
    txs = for i <- 1..6, do: BB.spend_op_true(cb.(i), 0, 50 * @coin)
    blocks = chain(b150.header, 150, Enum.map(txs, &[&1]))

    before_pf = State.work_stats(pf.cs)
    assert Enum.uniq(for n <- [pf, ref], do: submit_path(n, blocks)) |> length() == 1
    for n <- [pf, ref], do: State.commit_now(n.cs)
    after_pf = State.work_stats(pf.cs)

    pf_delta = fn part, k ->
      Map.get(after_pf[part], k, 0) - Map.get(before_pf[part], k, 0)
    end

    # Past pinned BIP34 on a linear archive: prefetch and archive skip txindex history reads.
    assert pf_delta.(:prefetch, :history_rows) == 0
    assert pf_delta.(:prefetch, :history_extra) == 0
    assert pf_delta.(:chain_state, :txindex_reads) == 0
    assert pf_delta.(:chain_state, :txindex_skipped) == 12

    # Trigger a reorg at height 156 re-confirming the exact same tx (tx6) on a competing fork.
    b155 = Enum.at(blocks, 4)
    tx6 = List.last(txs)

    f156 =
      BB.build(b155.header, [
        BB.coinbase_with(156, 25 * @coin, outputs: [{25 * @coin, <<0x51>>}, {0, <<0x6A, 99>>}]),
        tx6
      ])

    f157 = BB.build(f156.header, [BB.coinbase(157, 25 * @coin)])

    before_reorg = State.work_stats(pf.cs)
    assert Enum.uniq(for n <- [pf, ref], do: submit_path(n, [f156, f157])) |> length() == 1
    for n <- [pf, ref], do: State.commit_now(n.cs)
    after_reorg = State.work_stats(pf.cs)

    assert Map.get(after_reorg.chain_state, :txindex_skipped, 0) ==
             Map.get(before_reorg.chain_state, :txindex_skipped, 0)

    # Both the orphaned block 156 and competing fork f156 occurrences of tx6 are kept.
    for n <- [pf, ref] do
      {:ok, bin} = KV.get(n.kv, :txindex, tx6.txid)
      assert length(Archive.decode_txindex(bin)) == 2
    end

    ops =
      for b <- bs ++ blocks ++ [f156, f157],
          tx <- b.txs,
          v <- 0..(length(tx.outputs) - 1),
          do: {tx.txid, v}

    assert coins(pf, ops) == coins(ref, ops)
  end

  test "bip34_unique_txids? enforces pinned BIP34 hash, height bounds, and BIP30 repeat exceptions",
       %{tmp_dir: dir} do
    alias Exnode.Validation.Connect

    {:ok, kv} = KV.open(Path.join(dir, "kv-bip34"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    b1 = BB.build(@p.genesis.header, [BB.coinbase(1, 50 * @coin)])
    b2 = BB.build(b1.header, [BB.coinbase(2, 50 * @coin)])
    {:ok, _} = Headers.process_headers(hs, [b1.header, b2.header])
    idx = Headers.index(hs)
    e0 = HeaderIndex.lookup(idx, @p.genesis.header.hash)
    e1 = HeaderIndex.lookup(idx, b1.header.hash)
    e2 = HeaderIndex.lookup(idx, b2.header.hash)

    # Regtest has a zero bip34_hash, so bip34_unique_txids? is always false.
    refute Connect.bip34_unique_txids?(e2, e1, @p, idx)

    # Pin block 1 as the BIP34 activation block: block 1 itself is false, block 2 is true.
    p_pinned = %{@p | bip34_height: 1, bip34_hash: e1.hash}
    refute Connect.bip34_unique_txids?(e1, e0, p_pinned, idx)
    assert Connect.bip34_unique_txids?(e2, e1, p_pinned, idx)

    # At or above BIP34_IMPLIES_BIP30_LIMIT (1_983_702): false.
    refute Connect.bip34_unique_txids?(%{e2 | height: 1_983_702}, e1, p_pinned, idx)

    # Historical BIP30 repeat hash/height: false even if bip34_anc matched.
    bip30_hash =
      Base.decode16!("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
        case: :lower
      )
      |> :binary.decode_unsigned(:big)
      |> :binary.encode_unsigned(:little)
      |> then(fn b -> b <> :binary.copy(<<0>>, 32 - byte_size(b)) end)

    refute Connect.bip34_unique_txids?(
             %{e2 | height: 91_842, hash: bip30_hash},
             e1,
             p_pinned,
             idx
           )
  end
end
