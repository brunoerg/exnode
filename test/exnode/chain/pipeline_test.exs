defmodule Exnode.Chain.PipelineTest do
  @moduledoc """
  The connect pipeline (scripts of block N running while
  N+1.. get their non-script checks) reports exactly what one-at-a-time
  connection would. Headers arrive first and blocks out of order, so a single
  activation connects the whole path.
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  setup %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        listeners: [self()]
      )

    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    %{cs: cs, hs: hs, bs: bs, tip: List.last(bs).header}
  end

  # Spends coinbase `cb` (OP_TRUE) with a scriptSig that makes the script fail.
  defp bad_script_tx(cb),
    do: BB.tx([{cb, 0, script_sig: <<0x00, 0x6A>>}], [{50 * @coin, <<0x51>>}])

  defp good_tx(cb), do: BB.spend_op_true(cb, 0, 50 * @coin)

  # A chain of blocks on `prev`; `txs_at.(i)` gives block i's non-coinbase txs.
  defp chain(prev, n, txs_at) do
    Enum.map_reduce(1..n, prev, fn i, prev ->
      b = BB.build(prev, [BB.coinbase(150 + i, 25 * @coin) | txs_at.(i)])
      {b, b.header}
    end)
    |> elem(0)
  end

  # Headers first; then every block but the first (stored), then the first:
  # one activation connects the whole path through the pipeline.
  defp submit_path(cs, hs, blocks) do
    {:ok, _} = Headers.process_headers(hs, Enum.map(blocks, & &1.header))
    for b <- tl(blocks), do: assert({:ok, :stored} = State.submit_block(cs, b))
    State.submit_block(cs, hd(blocks))
  end

  defp status(hs, b), do: HeaderIndex.lookup(Headers.index(hs), b.header.hash).status

  test "script failure in block N with valid blocks in flight: N rejected, nothing after N connected",
       %{cs: cs, hs: hs, bs: bs, tip: tip} do
    cb = fn h -> hd(Enum.at(bs, h - 1).txs).txid end
    # Block 3 of 12 has a bad script; the others spend valid coins.
    blocks =
      chain(tip, 12, fn i -> if i == 3, do: [bad_script_tx(cb.(i))], else: [good_tx(cb.(i))] end)

    # The submitted block (the first) connects; the failure is block 3.
    {:ok, :connected} = submit_path(cs, hs, blocks)

    assert State.tip(cs).hash == Enum.at(blocks, 1).header.hash
    assert_received {:block_invalid, h, {:consensus, "block-script-verify-flag-failed"}}
    assert h == Enum.at(blocks, 2).header.hash
    refute_received {:block_invalid, _, _}
    assert status(hs, Enum.at(blocks, 2)) == :failed
    # Not connected, and never reported as invalid themselves (only as failed descendants).
    for b <- Enum.drop(blocks, 2),
        h = b.header.hash,
        do: refute_received({:block_connected, ^h, _})

    # Blocks 1 and 2 did connect.
    for b <- Enum.take(blocks, 2),
        h = b.header.hash,
        do: assert_received({:block_connected, ^h, _})
  end

  test "non-script failure in N+1 while N's scripts are pending: N connected, N+1 rejected with its reason",
       %{cs: cs, hs: hs, bs: bs, tip: tip} do
    cb = fn h -> hd(Enum.at(bs, h - 1).txs).txid end
    # Block 2 spends block 1's spend again: missing input (not a script error).
    first = good_tx(cb.(1))
    dup = BB.spend_op_true(cb.(1), 0, 50 * @coin - 1)

    blocks =
      chain(tip, 5, fn
        1 -> [first]
        2 -> [dup]
        i -> [good_tx(cb.(i))]
      end)

    {:ok, :connected} = submit_path(cs, hs, blocks)
    assert State.tip(cs).hash == hd(blocks).header.hash
    assert_received {:block_invalid, h, {:consensus, "bad-txns-inputs-missingorspent"}}
    assert h == Enum.at(blocks, 1).header.hash
  end

  test "N has a script failure and N+1 a non-script failure: N is the one reported",
       %{cs: cs, hs: hs, bs: bs, tip: tip} do
    cb = fn h -> hd(Enum.at(bs, h - 1).txs).txid end
    # N+1 overpays its coinbase (bad-cb-amount), checked while N's scripts run.
    [b1] = chain(tip, 1, fn _ -> [bad_script_tx(cb.(1))] end)
    b2 = BB.build(b1.header, [BB.coinbase(152, 25 * @coin + 1)])
    {:error, {:consensus, "block-script-verify-flag-failed"}} = submit_path(cs, hs, [b1, b2])

    assert State.tip(cs).hash == tip.hash
    assert_received {:block_invalid, h, {:consensus, "block-script-verify-flag-failed"}}
    assert h == b1.header.hash
    refute_received {:block_invalid, _, _}
  end

  test "outputs created by in-flight blocks are spendable by later in-flight blocks",
       %{cs: cs, hs: hs, bs: bs, tip: tip} do
    cb = hd(hd(bs).txs).txid
    t1 = good_tx(cb)
    t2 = BB.spend_op_true(t1.txid, 0, 50 * @coin)
    t3 = BB.spend_op_true(t2.txid, 0, 50 * @coin)

    blocks =
      chain(tip, 4, fn
        1 -> [t1]
        2 -> [t2]
        3 -> [t3]
        _ -> []
      end)

    {:ok, :connected} = submit_path(cs, hs, blocks)
    assert State.tip(cs).hash == List.last(blocks).header.hash
    assert State.with_archive(cs, &Exnode.Archive.resolve(&1, t2.txid, 0)) == :missing
    assert {:ok, %{height: 153}} = State.with_archive(cs, &Exnode.Archive.resolve(&1, t3.txid, 0))
  end

  test "double spend across two in-flight blocks is caught", %{cs: cs, hs: hs, bs: bs, tip: tip} do
    cb = hd(hd(bs).txs).txid

    blocks =
      chain(tip, 3, fn
        1 -> [good_tx(cb)]
        3 -> [BB.spend_op_true(cb, 0, 50 * @coin - 7)]
        _ -> []
      end)

    {:ok, :connected} = submit_path(cs, hs, blocks)
    assert State.tip(cs).hash == Enum.at(blocks, 1).header.hash
    assert_received {:block_invalid, h, {:consensus, "bad-txns-inputs-missingorspent"}}
    assert h == Enum.at(blocks, 2).header.hash
  end
end
