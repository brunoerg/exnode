defmodule Exnode.Mempool.ExtractBestTest do
  @moduledoc """
  `Pool.extract_best/3` (Core `ExtractBestByMiningScoreWithTopology`), which
  orders tx announcements: chunk feerate first, parents before children
  (CPFP chunks), the best `n`, the rest returned, unknown txids dropped.
  """
  use ExUnit.Case, async: true

  alias Exnode.Codec.Tx
  alias Exnode.Mempool.Pool

  defp tx(prevs, tag) do
    {:ok, t} =
      %Tx{
        version: 2,
        locktime: 0,
        inputs:
          for(
            {h, v} <- prevs,
            do: %Tx.In{prev_hash: h, prev_index: v, script_sig: <<>>, sequence: 0xFFFFFFFF}
          ),
        outputs: [%Tx.Out{value: tag, script_pubkey: <<0x51>>}]
      }
      |> Tx.encode()
      |> IO.iodata_to_binary()
      |> Tx.decode_exact()

    t
  end

  defp add(pool, t, fee, weight) do
    Pool.add(pool, %Pool.Entry{
      tx: t,
      txid: t.txid,
      wtxid: t.wtxid,
      fee: fee,
      weight: weight,
      vsize: div(weight + 3, 4),
      sigops: 0,
      time: 0,
      height: 0,
      spends_coinbase: false
    })
  end

  test "chunk feerate order, CPFP parent before its child, best n and the rest" do
    ext = fn i -> {:crypto.hash(:sha256, <<i>>), 0} end
    lone_hi = tx([ext.(1)], 1)
    lone_lo = tx([ext.(2)], 2)
    parent = tx([ext.(3)], 3)
    child = tx([{parent.txid, 0}], 4)

    pool =
      Pool.new()
      |> add(lone_lo, 1_000, 400)
      |> add(parent, 100, 400)
      |> add(child, 20_000, 400)
      |> add(lone_hi, 8_000, 400)

    ids = [
      lone_lo.txid,
      child.txid,
      parent.txid,
      lone_hi.txid,
      :crypto.hash(:sha256, "missing"),
      child.txid
    ]

    {all, []} = Pool.extract_best(pool, ids, 10)
    # Chunks: {parent, child} at 20100/800 = 25.1/wu, lone_hi 20/wu, lone_lo 2.5/wu.
    assert Enum.map(all, & &1.txid) == [parent.txid, child.txid, lone_hi.txid, lone_lo.txid]

    {best, rest} = Pool.extract_best(pool, ids, 2)
    assert Enum.map(best, & &1.txid) == [parent.txid, child.txid]
    assert Enum.sort(rest) == Enum.sort([lone_hi.txid, lone_lo.txid])
  end
end
