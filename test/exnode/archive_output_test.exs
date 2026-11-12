defmodule Exnode.ArchiveOutputTest do
  @moduledoc """
  Point reads for serving (fix-03 WS3): `Archive.output/3`, `outputs/2` and
  `read_tx/2` agree with the fully reconstructed blocks, on the regtest
  fixture chain (bitcoind's 150 blocks) and on a chain with segwit spends
  (`Exnode.Test.SpendChain`), with witness pruning and after a reorg.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Archive
  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Test.SpendChain

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../fixtures/regtest/chain150.bin", __DIR__)

  defp start(dir, opts \\ []) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link([params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot")] ++ opts)

    cs
  end

  defp reader(cs) do
    State.commit_now(cs)
    State.peek_archive(cs, &Archive.reader/1)
  end

  # Every output of every tx of `blocks`, against `read_block_txs/2`.
  defp assert_outputs(r, blocks) do
    for b <- blocks do
      {:ok, rebuilt} = Archive.read_block_txs(r, Archive.block_id(r, b.header.hash))

      for {tx, pos} <- Enum.with_index(rebuilt.txs) do
        for {o, v} <- Enum.with_index(tx.outputs), do: assert(Archive.output(r, tx.txid, v) == o)
        assert Archive.output(r, tx.txid, length(tx.outputs)) == nil
        # The tx alone, as in its rebuilt block (witnesses empty when pruned).
        assert {:ok, ^tx, header, _id, ^pos} = Archive.read_tx(r, tx.txid)
        assert header == b.header
      end
    end
  end

  test "bitcoind fixture chain: every output and tx read alone equals the rebuilt block",
       %{tmp_dir: dir} do
    cs = start(dir)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    assert_outputs(reader(cs), bs)
  end

  test "spends, witness pruning, unknown txids, and a reorg's stale txs", %{tmp_dir: dir} do
    # Tiny segments and keep 10: the early segwit blocks lose their witnesses.
    cs = start(dir, segment_max: 200, prune_witness: true, prune_keep: 10)
    {bs, _} = SpendChain.build(@p.genesis.header, 140)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    r = reader(cs)
    assert Archive.witness_pruned(r) >= 0
    assert_outputs(r, bs)

    # The 11-input tx's block had its witnesses pruned: outputs are unaffected.
    many = Enum.at(Enum.at(bs, 110).txs, 1)
    assert length(many.inputs) == 11
    assert {:ok, pruned, _, _, 1} = Archive.read_tx(r, many.txid)
    assert pruned.txid == many.txid and Enum.all?(pruned.inputs, &(&1.witness == []))
    assert Archive.output(r, many.txid, 2) == Enum.at(many.outputs, 2)
    assert Archive.output(r, :crypto.hash(:sha256, "nothing"), 0) == nil

    # Reorg: blocks 139..140 are replaced by three blocks without their txs.
    fork_base = Enum.at(bs, 137).header

    {fork, _} =
      Enum.map_reduce(139..141, fork_base, fn h, prev ->
        b =
          BB.build(prev, [
            BB.coinbase_with(h, 50 * 100_000_000, outputs: [{50 * 100_000_000, SpendChain.spk()}])
          ])

        {b, b.header}
      end)

    # Requested, as a download would be (unrequested equal-work siblings are skipped).
    for b <- fork, do: assert({:ok, _} = State.submit_block(cs, b, requested: true))
    assert State.tip(cs).height == 141
    r = reader(cs)
    stale = Enum.flat_map(Enum.slice(bs, 138, 2), &tl(&1.txs))

    for tx <- stale do
      # Only in a block off the active chain: not served as a prevout.
      assert Archive.output(r, tx.txid, 0) == nil

      assert Archive.outputs(r, [{tx.txid, 0}, {tx.txid, 1}]) == %{
               {tx.txid, 0} => nil,
               {tx.txid, 1} => nil
             }
    end

    assert_outputs(r, Enum.take(bs, 138) ++ fork)
  end

  property "outputs/2 equals output/3 for any batch, valid or not", %{tmp_dir: dir} do
    cs = start(dir)
    {bs, _} = SpendChain.build(@p.genesis.header, 125)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    r = reader(cs)
    txids = for b <- bs, tx <- b.txs, do: tx.txid
    unknown = for i <- 1..5, do: :crypto.hash(:sha256, <<i>>)

    check all(
            ops <- list_of(tuple({member_of(txids ++ unknown), integer(0..4)}), max_length: 40),
            max_runs: 100
          ) do
      assert Archive.outputs(r, ops) ==
               Map.new(ops, fn {t, v} = op -> {op, Archive.output(r, t, v)} end)
    end
  end
end
