defmodule Exnode.Chain.DeferredTest do
  @moduledoc """
  Deferred submission (`submit_block(defer: true)`, used by peers in IBD):
  the chain state stores the block and replies at once, then connects in
  steps of `activation_step` blocks (Core `ActivateBestChainStep`), serving
  its mailbox between steps. The outcome must equal synchronous submission:
  same tip, same coins, same header statuses, through an invalid block and
  a reorg; and the source of a block found invalid on connect is told
  (Core `BlockChecked`).
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
        [params: @p, headers: hs, kv: kv, hot: Path.join([dir, name, "hot"])] ++ opts
      )

    %{cs: cs, hs: hs}
  end

  # Headers first, then every block but the first, then the first (the IBD
  # shape: blocks wait on one missing block, then a long path connects).
  # Downloaded blocks were requested (Core fRequested), so a fork with less
  # work than the tip so far is still stored.
  defp submit_path(n, blocks, opts) do
    opts = Keyword.put(opts, :requested, true)
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(blocks, & &1.header))
    rest = for b <- tl(blocks), do: State.submit_block(n.cs, b, opts)
    [State.submit_block(n.cs, hd(blocks), opts) | rest]
  end

  defp chain(prev, start_h, specs) do
    {blocks, _} =
      Enum.map_reduce(Enum.with_index(specs, 1), prev, fn {txs, i}, prev ->
        b = BB.build(prev, [BB.coinbase(start_h + i, 25 * @coin) | txs])
        {b, b.header}
      end)

    blocks
  end

  defp await_tip(n, hash) do
    unless Exnode.Test.Wait.until?(fn -> State.tip(n.cs).hash == hash end),
      do:
        flunk(
          "tip never reached #{Exnode.Crypto.Hash.to_hex(hash)}: at #{State.tip(n.cs).height}"
        )
  end

  defp coins(n, ops), do: State.with_archive(n.cs, &Archive.resolve_many(&1, ops))

  test "deferred submission connects in steps, serves calls between steps, and ends like synchronous submission",
       %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    # Turns here stop on the step budget only: under load the 50 ms time
    # budget (`turn_ms`) could end a turn before its first retirement.
    steps = [activation_step: 4, batch_blocks: 7, turn_ms: 60_000]
    d = node(dir, "def", steps)
    ref = node(dir, "ref", [])
    defer = [defer: true, source: self()]

    # Every deferred reply is :stored, before anything connects.
    assert Enum.uniq(submit_path(d, bs, defer)) == [{:ok, :stored}]
    # The turn queued by the last submission runs before this call, the next
    # after it. With prefetch on, that turn may stop early to wait for a
    # prefetch result (it never blocks), so at most one step is done.
    assert State.tip(d.cs).height <= 4
    for b <- bs, do: {:ok, :connected} = State.submit_block(ref.cs, b)
    await_tip(d, List.last(bs).header.hash)
    # No turn ever connected more than one step (activation_step: 4).
    assert State.work_stats(d.cs).pipeline.turn_retired_max == 4

    # Without prefetch nothing is waited for: the call is served with exactly
    # one step done.
    d0 = node(dir, "def0", [prefetch_depth: 0] ++ steps)
    assert Enum.uniq(submit_path(d0, bs, defer)) == [{:ok, :stored}]
    assert State.tip(d0.cs).height == 4
    await_tip(d0, List.last(bs).header.hash)

    cb = fn h -> hd(Enum.at(bs, h - 1).txs).txid end
    t = fn txid, v -> BB.spend_op_true(txid, v, 50 * @coin) end
    spend_cb = for h <- 1..40, into: %{}, do: {h, t.(cb.(h), 0)}

    # 30 blocks; block 12 double-spends what block 2 spent (found on connect).
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
    assert Enum.uniq(submit_path(d, blocks, defer)) == [{:ok, :stored}]
    submit_path(ref, blocks, [])
    bad = Enum.at(blocks, 11).header.hash

    assert_receive {:block_checked, ^bad,
                    {:error, {:consensus, "bad-txns-inputs-missingorspent"}}},
                   5_000

    await_tip(d, State.tip(ref.cs).hash)
    assert State.tip(d.cs).hash == Enum.at(blocks, 10).header.hash
    # Only the invalid block's source is told; valid blocks send nothing.
    refute_received {:block_checked, _, _}

    # A reorg onto a heavier fork from block 5, deferred.
    fork = chain(Enum.at(blocks, 4).header, 155, for(i <- 6..20, do: [t.(cb.(20 + i), 0)]))
    assert Enum.uniq(submit_path(d, fork, defer)) == [{:ok, :stored}]
    submit_path(ref, fork, [])
    await_tip(d, List.last(fork).header.hash)
    assert State.tip(d.cs) == State.tip(ref.cs)

    ops =
      for b <- bs ++ blocks ++ fork,
          tx <- b.txs,
          v <- 0..(length(tx.outputs) - 1),
          do: {tx.txid, v}

    assert coins(d, ops) == coins(ref, ops)

    for b <- blocks ++ fork do
      assert HeaderIndex.lookup(Headers.index(d.hs), b.header.hash).status ==
               HeaderIndex.lookup(Headers.index(ref.hs), b.header.hash).status
    end
  end

  test "a deferred block failing a pre-store check still replies with the error", %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    d = node(dir, "def", [])
    b = hd(bs)
    # Bad merkle root: CheckBlock fails before the block is stored.
    bad = %{b | txs: b.txs ++ b.txs}
    assert {:error, {_, _}} = State.submit_block(d.cs, bad, defer: true, source: self())
    assert {:ok, :stored} = State.submit_block(d.cs, b, defer: true, source: self())
    await_tip(d, b.header.hash)
  end
end
