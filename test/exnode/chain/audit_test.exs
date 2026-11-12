defmodule Exnode.Chain.AuditTest do
  @moduledoc """
  Core v32.1's anti-DoS gates for blocks that arrive over P2P, on the
  `submit_block/3` (BLOCK message) path:

  1. `ProcessMessage` BLOCK computes `min_pow_checked` from the claimed work
     (parent's work + block proof >= `GetAntiDoSWorkThreshold`), and
     `AcceptBlockHeader` rejects a new header without it
     (`too-little-chainwork`), requested or not.
  2. `AcceptBlock` does not store an unrequested block whose chain has less
     work than the active tip, that is more than `MIN_BLOCKS_TO_KEEP` (288)
     above the tip, or whose work is below `nMinimumChainWork`.
  3. A requested block skips the gates of 2; an unrequested next-tip block
     passes them and connects.

  Nothing a gate drops reaches the `pending` column family.

  Invalid-block bookkeeping (fix-03 WS4), as Core's `ProcessNewBlock` and
  `InvalidBlockFound`:
  4. A `CheckBlock` failure is returned but never marks the block failed;
     `ContextualCheckBlock` and connect failures do.
  5. Marking a block failed marks every descendant (`SetBlockFailureFlags`),
     persisted; the best header is then the most-work entry not failed
     (`RecalculateBestHeader`), also after a restart (`LoadBlockIndex`).
  """
  use ExUnit.Case, async: true

  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.ChainParams
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @p ChainParams.get(:regtest)
  @coin 100_000_000

  defp blocks, do: for(raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1))

  # A node with the 150-block chain connected.
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

    bs = blocks()
    for b <- bs, do: {:ok, _} = State.submit_block(cs, b)
    assert State.tip(cs).height == 150
    %{kv: kv, hs: hs, cs: cs, bs: bs}
  end

  # `n` blocks on top of `prev` (heights from `h`), oldest first.
  defp extend(prev, h, n) do
    {chain, _} =
      Enum.map_reduce(h..(h + n - 1), prev.header, fn height, prev ->
        b = BB.build(prev, [BB.coinbase(height, 25 * @coin)])
        {b, b.header}
      end)

    chain
  end

  defp status(n, b), do: HeaderIndex.lookup(Headers.index(n.hs), b.header.hash).status

  # A block on `prev` at `height` with these txs (coinbase first).
  defp block(prev, txs), do: BB.build(prev.header, txs)

  defp cb(height, value \\ 25 * @coin, opts \\ []),
    do: BB.coinbase_with(height, value, Keyword.merge([outputs: [{value, <<0x51>>}]], opts))

  # `n` blocks on `prev`, from height `h`, the `bad`-th (1-based) paying
  # one satoshi too much (a connect-time `bad-cb-amount`).
  defp fork(prev, h, n, bad \\ nil) do
    {chain, _} =
      Enum.map_reduce(1..n, prev, fn i, prev ->
        value = if i == bad, do: 25 * @coin + 1, else: 25 * @coin

        b =
          block(prev, [
            cb(h + i - 1, value,
              script_sig: Exnode.Test.ScriptAsm.parse("#{h + i - 1}") <> <<i, 7>>
            )
          ])

        {b, b}
      end)

    chain
  end

  defp pending?(n, b), do: KV.get(n.kv, :pending, b.header.hash) != :not_found

  # 400 blocks past the tip, headers accepted; the last is > 288 above the tip.
  defp far_ahead(n) do
    chain = extend(List.last(n.bs), 151, 400)
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(chain, & &1.header))
    chain
  end

  test "an unrequested block on a less-work fork: header rejected as low work, nothing stored",
       %{tmp_dir: dir} do
    n = start(dir)
    # A 1-block fork from genesis: valid PoW, valid block, but 2 block proofs
    # of work against a threshold of 150 - 144 = 6 (regtest min work is 0).
    fork = BB.build(@p.genesis.header, [BB.coinbase(1, 50 * @coin, <<0x52>>)])

    assert {:error, {:header_low_work, "too-little-chainwork"}} = State.submit_block(n.cs, fork)
    refute pending?(n, fork)
    assert HeaderIndex.lookup(Headers.index(n.hs), fork.header.hash) == nil

    # Requested or not: the header check comes first (Core computes
    # min_pow_checked the same way for both).
    assert {:error, {:header_low_work, _}} = State.submit_block(n.cs, fork, requested: true)
    refute pending?(n, fork)
  end

  test "an unrequested block more than 288 above the tip: header accepted, block skipped",
       %{tmp_dir: dir} do
    n = start(dir)
    last = List.last(far_ahead(n))
    assert HeaderIndex.lookup(Headers.index(n.hs), last.header.hash).height == 550

    assert {:ok, :skipped} = State.submit_block(n.cs, last)
    refute pending?(n, last)
    # Deferred (IBD) submission goes through the same gates.
    assert {:ok, :skipped} = State.submit_block(n.cs, last, defer: true, source: self())
    refute pending?(n, last)
    assert State.tip(n.cs).height == 150
  end

  test "an unrequested less-work sibling with a known header is skipped", %{tmp_dir: dir} do
    n = start(dir)
    # A sibling of block 150: its chain has the tip's work, so it is stored;
    # a sibling of block 149 has less and is not.
    [b149, b150] = Enum.take(n.bs, -2)
    [same] = extend(Enum.at(n.bs, -2), 150, 1)
    [less] = extend(Enum.at(n.bs, -3), 149, 1)
    assert same.header.hash != b150.header.hash and less.header.hash != b149.header.hash

    assert {:ok, :stored} = State.submit_block(n.cs, same)
    assert pending?(n, same)
    assert {:ok, :skipped} = State.submit_block(n.cs, less)
    refute pending?(n, less)
  end

  test "a requested block is stored past the gates; an unrequested next-tip block connects",
       %{tmp_dir: dir} do
    n = start(dir)
    chain = far_ahead(n)
    last = List.last(chain)

    assert {:ok, :stored} = State.submit_block(n.cs, last, requested: true)
    assert pending?(n, last)

    next = hd(chain)
    assert {:ok, :connected} = State.submit_block(n.cs, next)
    assert State.tip(n.cs).hash == next.header.hash
  end

  # --- invalid-block bookkeeping (fix-03 WS4) ---------------------------------

  test "a CheckBlock failure is returned but the block is not marked failed", %{tmp_dir: dir} do
    n = start(dir)
    tip = List.last(n.bs)
    long_sig = Exnode.Test.ScriptAsm.parse("151") <> :binary.copy(<<0>>, 98)
    assert byte_size(long_sig) == 101

    cases = [
      {block(tip, [cb(151), cb(151, 1, script_sig: Exnode.Test.ScriptAsm.parse("151") <> <<9>>)]),
       "bad-cb-multiple"},
      {block(tip, [cb(151, 25 * @coin, script_sig: long_sig)]), "bad-cb-length"}
    ]

    for {b, reason} <- cases do
      assert {:error, {:consensus, ^reason}} = State.submit_block(n.cs, b)
      assert status(n, b) == :valid_header
      # Not cached as invalid: the same CheckBlock error again, not duplicate-invalid.
      assert {:error, {:consensus, ^reason}} = State.submit_block(n.cs, b)
      # A header extending it is still accepted.
      child = block(b, [cb(152)])
      assert {:ok, _} = Headers.process_headers(n.hs, [child.header])
      assert status(n, child) == :valid_header
    end

    assert State.tip(n.cs).height == 150
  end

  test "ContextualCheckBlock and connect failures still mark the block failed",
       %{tmp_dir: dir} do
    n = start(dir)
    tip = List.last(n.bs)
    # BIP34: the coinbase must start with the height (152 is not 151).
    bad_height =
      block(tip, [cb(151, 25 * @coin, script_sig: Exnode.Test.ScriptAsm.parse("152") <> <<0>>)])

    assert {:error, {:consensus, "bad-cb-height"}} = State.submit_block(n.cs, bad_height)
    assert status(n, bad_height) == :failed
    assert {:error, {_, "duplicate-invalid"}} = State.submit_block(n.cs, bad_height)

    [bad_amount] = fork(tip, 151, 1, 1)
    assert {:error, {:consensus, "bad-cb-amount"}} = State.submit_block(n.cs, bad_amount)
    assert status(n, bad_amount) == :failed
  end

  test "a failed block's descendants are all marked failed, persisted, and not extended",
       %{tmp_dir: dir} do
    n = start(dir)
    chain = fork(List.last(n.bs), 151, 5, 2)
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(chain, & &1.header))
    assert Headers.index(n.hs).best.hash == List.last(chain).header.hash

    for b <- Enum.take(chain, 2), do: State.submit_block(n.cs, b, requested: true)
    assert State.tip(n.cs).height == 151
    assert Enum.map(chain, &status(n, &1)) == [:valid_header, :failed, :failed, :failed, :failed]
    # The best header is back on the active tip (nothing else has more work).
    assert Headers.index(n.hs).best.hash == hd(chain).header.hash

    # Persisted: a fresh index from the same store agrees.
    {:ok, hs2} = Headers.start_link(params: @p, kv: n.kv)
    idx2 = Headers.index(hs2)

    assert Enum.map(chain, &HeaderIndex.lookup(idx2, &1.header.hash).status) ==
             [:valid_header, :failed, :failed, :failed, :failed]

    [child] = fork(List.last(chain), 156, 1)

    assert {:error, {:invalid_prev, "bad-prevblk"}, _} =
             Headers.process_headers(n.hs, [child.header])
  end

  test "after an invalidation the best header is the most-work branch not failed, also after a restart",
       %{tmp_dir: dir} do
    n = start(dir)
    # A: 5 headers on the tip (151..155), its first block invalid on connect.
    # B: 5 headers from block 148 (149..153): more work than the tip (150).
    a = fork(List.last(n.bs), 151, 5, 1)
    b = fork(Enum.at(n.bs, 147), 149, 5)
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(a, & &1.header))
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(b, & &1.header))
    assert Headers.index(n.hs).best.hash == List.last(a).header.hash

    assert {:error, {:consensus, "bad-cb-amount"}} =
             State.submit_block(n.cs, hd(a), requested: true)

    assert Enum.all?(a, &(status(n, &1) == :failed))
    # Core RecalculateBestHeader: B (153), not the active tip (150).
    idx = Headers.index(n.hs)
    assert idx.best.hash == List.last(b).header.hash
    assert HeaderIndex.hash_at(idx, 153) == List.last(b).header.hash
    assert HeaderIndex.hash_at(idx, 154) == nil

    # Restart: the failed A is still the most-work chain, but never the best header.
    {:ok, hs2} = Headers.start_link(params: @p, kv: n.kv)
    idx2 = Headers.index(hs2)
    assert idx2.best.hash == List.last(b).header.hash
    assert HeaderIndex.lookup(idx2, List.last(a).header.hash).chain_work > idx2.best.chain_work
  end
end
