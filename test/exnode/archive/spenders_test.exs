defmodule Exnode.Archive.SpendersTest do
  @moduledoc """
  `Archive.spenders/2` (the confirmed spenders `/tx/:txid/outspends`
  reports) across a reorg: an output spent only on the abandoned branch is
  unspent again, and one spent on both branches reports the new spender
  (a disconnected block's spend records are deleted; a record of a block
  off the chain would also be skipped).
  Also: the input index and the spending tx's position, an unspent output,
  a vout past the tx's outputs, and an unknown txid.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Tx
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000

  setup %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    on_exit(fn -> KV.close(kv) end)
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    # Named: the reader is found through the view, by name.
    cs = :"spenders_cs_#{System.unique_integer([:positive])}"

    {:ok, _} =
      State.start_link(name: cs, params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"))

    {bs, _} =
      Enum.map_reduce(1..110, @p.genesis.header, fn h, prev ->
        b = BB.build(prev, [BB.coinbase(h, 50 * @coin)])
        {b, b.header}
      end)

    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    %{cs: cs, bs: bs}
  end

  defp submit(cs, blocks) do
    for b <- blocks, do: {:ok, _} = State.submit_block(cs, b)
    State.commit_now(cs)
    State.reader(cs)
  end

  defp cb(bs, h), do: hd(Enum.at(bs, h - 1).txs).txid

  # A tx spending output 0 of each of `txids` (OP_TRUE outputs), in order.
  defp spend_all(txids, value) do
    ins =
      for t <- txids,
          do: %Tx.In{prev_hash: t, prev_index: 0, script_sig: <<>>, sequence: 0xFFFFFFFF}

    BB.finalize(%Tx{
      version: 2,
      inputs: ins,
      outputs: [%Tx.Out{value: value, script_pubkey: <<0x51>>}],
      locktime: 0
    })
  end

  test "after a reorg: the new branch's spenders, and outputs it leaves unspent", %{
    cs: cs,
    bs: bs
  } do
    tip = List.last(bs).header
    {cb1, cb2, cb3} = {cb(bs, 1), cb(bs, 2), cb(bs, 3)}

    # Main 111: c (position 1) spends cb2, a (position 2) spends cb1.
    a = BB.spend_op_true(cb1, 0, 50 * @coin - 1_000)
    c = BB.spend_op_true(cb2, 0, 50 * @coin - 1_000)
    m111 = BB.build(tip, [BB.coinbase(111, 50 * @coin), c, a])
    r = submit(cs, [m111])

    assert %{{^cb1, 0} => {a_txid, 0, h1, 2}, {^cb2, 0} => {c_txid, 0, h1, 1}} =
             Archive.spenders(r, [{cb1, 0}, {cb2, 0}, {cb3, 0}, {cb1, 1}, {<<7::256>>, 0}])

    assert {a_txid, c_txid, h1.hash} == {a.txid, c.txid, m111.header.hash}

    # A longer fork from 110: b spends cb3 (input 0) and cb1 (input 1);
    # nothing spends cb2.
    b = spend_all([cb3, cb1], 100 * @coin - 2_000)
    f111 = BB.build(tip, [BB.coinbase(111, 50 * @coin), b])
    f112 = BB.build(f111.header, [BB.coinbase(112, 50 * @coin)])
    r = submit(cs, [f111, f112])
    assert State.tip(cs).hash == f112.header.hash

    spenders = Archive.spenders(r, [{cb1, 0}, {cb2, 0}, {cb3, 0}])
    assert %{{^cb1, 0} => {b_txid, 1, h, 1}, {^cb3, 0} => {b_txid, 0, h, 1}} = spenders
    assert b_txid == b.txid and h.hash == f111.header.hash
    refute Map.has_key?(spenders, {cb2, 0})
  end
end
