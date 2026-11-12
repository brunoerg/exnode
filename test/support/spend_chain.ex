defmodule Exnode.Test.SpendChain do
  @moduledoc """
  A regtest chain with spends, for tests that serve or read txs (REST,
  archive point reads). Blocks 1..110 pay their coinbase to
  P2WSH(OP_TRUE) (`spk/0`); block 111 holds an 11-input tx spending
  coinbases 1..11; blocks 112..`top` each hold a spend of coinbase h-100
  split between `spk/0` and `spk2/0`, and a spend of the previous block's
  `spk/0` split output. All spends are segwit (witness `[OP_TRUE]`).
  """
  alias Exnode.Codec.Tx
  alias Exnode.Test.BlockBuilder, as: BB

  @coin 100_000_000
  @op_true <<0x51>>

  def spk, do: <<0, 32>> <> :crypto.hash(:sha256, @op_true)
  # P2WSH(OP_1 OP_DROP OP_TRUE): a second anyone-can-spend script.
  def spk2, do: <<0, 32>> <> :crypto.hash(:sha256, <<0x51, 0x75, 0x51>>)
  def witness_script(spk), do: if(spk == spk(), do: @op_true, else: <<0x51, 0x75, 0x51>>)

  @doc "A tx spending `coins` (`[{txid, vout, value, spk}]`) to `outs` (`[{value, spk}]`)."
  def spend(coins, outs) do
    ins =
      for {t, v, _, s} <- coins,
          do: %Tx.In{
            prev_hash: t,
            prev_index: v,
            script_sig: <<>>,
            sequence: 0xFFFFFFFD,
            witness: [witness_script(s)]
          }

    BB.finalize(%Tx{
      version: 2,
      locktime: 0,
      inputs: ins,
      outputs: for({value, s} <- outs, do: %Tx.Out{value: value, script_pubkey: s})
    })
  end

  defp segwit_block(prev, height, txs, fees) do
    cb = fn extra, wit ->
      BB.coinbase_with(height, 0, outputs: [{50 * @coin + fees, spk()} | extra], witness: wit)
    end

    BB.build_segwit(prev, cb, txs)
  end

  @doc """
  Builds blocks 1..`top` (`top` <= 149: one subsidy era) on `genesis`.
  Returns `{blocks, coinbase_coins}`, the coins `{txid, 0, value, spk}` of
  coinbases 1..110 (1..`top - 100` are spent by the chain).
  """
  def build(genesis, top \\ 130) do
    {plain, prev} =
      Enum.map_reduce(1..110, genesis, fn h, prev ->
        b = BB.build(prev, [BB.coinbase_with(h, 50 * @coin, outputs: [{50 * @coin, spk()}])])
        {b, b.header}
      end)

    cbs = for b <- plain, do: {hd(b.txs).txid, 0, 50 * @coin, spk()}

    # Block 111: one tx with 11 inputs (mature: 100 confirmations) and 3 outputs.
    many =
      spend(Enum.take(cbs, 11), [
        {100 * @coin, spk()},
        {200 * @coin, spk2()},
        {250 * @coin - 11_000, spk()}
      ])

    b111 = segwit_block(prev, 111, [many], 11_000)

    {rest, _} =
      Enum.map_reduce(112..top//1, {b111, nil}, fn h, {prev, split} ->
        # Coinbase h-100 (12 upward: 1..11 went into block 111).
        cb = Enum.at(cbs, h - 100 - 1)
        s = spend([cb], [{25 * @coin, spk()}, {25 * @coin - 1_000, spk2()}])

        chained =
          if split,
            do: [spend([{split.txid, 0, 25 * @coin, spk()}], [{25 * @coin - 1_000, spk()}])],
            else: []

        b = segwit_block(prev.header, h, [s | chained], 1_000 * (1 + length(chained)))
        {b, {b, s}}
      end)

    {plain ++ [b111 | rest], cbs}
  end
end
