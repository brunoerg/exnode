defmodule Exnode.Archive.BIP30DisconnectTest do
  use ExUnit.Case, async: true

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)

  # Storage-level fixtures: duplicate coinbases model the pre-BIP34
  # historical overwrites, without needing to mine 91k mainnet headers.
  # This intentionally bypasses contextual consensus/maturity validation.
  defp open(dir) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {kv, Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis)}
  end

  defp duplicate_pair do
    cb = BB.coinbase(1, 50 * 100_000_000)
    b1 = BB.build(@p.genesis.header, [cb])
    b2 = BB.build(b1.header, [cb])
    {cb, b1, b2}
  end

  defp assert_missing(a, txid) do
    assert Archive.resolve(a, txid, 0) == :missing
    assert Archive.resolve_many(a, [{txid, 0}]) == %{{txid, 0} => :missing}
    assert Archive.committed_answers(Archive.reader(a), [{txid, 0}]) == %{{txid, 0} => :missing}
  end

  test "disconnecting an overwrite destroys the old coin durably; reconnecting the original recreates it",
       %{tmp_dir: dir} do
    {kv, a} = open(dir)
    {cb, b1, b2} = duplicate_pair()
    a = Archive.connect(a, b1, 1, [])
    {:ok, original} = Archive.resolve(a, cb.txid, 0)
    a = Archive.connect(a, b2, 2, [])
    assert {:ok, %{height: 2}} = Archive.resolve(a, cb.txid, 0)
    {a, _} = Archive.disconnect_tip(a)
    assert MapSet.member?(a.overwritten, original.output_id)
    assert_missing(a, cb.txid)
    Archive.close(a)

    a = Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis)
    assert_missing(a, cb.txid)
    {a, _} = Archive.disconnect_tip(a)
    a = Archive.connect(a, b1, 1, [])
    assert {:ok, ^original} = Archive.resolve(a, cb.txid, 0)
    # Repeating the overwrite/disconnect cycle has the same lost-coin result.
    a = Archive.connect(a, b2, 2, [])
    {a, _} = Archive.disconnect_tip(a)
    assert_missing(a, cb.txid)
    Archive.close(a)
    KV.close(kv)
  end

  test "a fully spent previous occurrence is not destroyed: disconnecting its spender restores it",
       %{tmp_dir: dir} do
    {kv, a} = open(dir)
    {cb, b1, _} = duplicate_pair()
    a = Archive.connect(a, b1, 1, [])
    {:ok, original} = Archive.resolve(a, cb.txid, 0)
    spend = BB.spend_op_true(cb.txid, 0, 49 * 100_000_000)
    b2 = BB.build(b1.header, [BB.coinbase(2, 50 * 100_000_000), spend])
    a = Archive.connect(a, b2, 2, [original.output_id])
    b3 = BB.build(b2.header, [cb])
    a = Archive.connect(a, b3, 3, [])
    {a, _} = Archive.disconnect_tip(a)
    assert a.overwritten == MapSet.new()
    assert_missing(a, cb.txid)
    {a, _} = Archive.disconnect_tip(a)
    assert {:ok, ^original} = Archive.resolve(a, cb.txid, 0)
    Archive.close(a)
    KV.close(kv)
  end

  test "historical repeat records from old archives recover their overwrite without a migration",
       %{tmp_dir: dir} do
    {kv, a} = open(dir)
    {cb, b1, b2} = duplicate_pair()
    repeat = Hash.from_hex("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")
    # Use the historical identity only at the storage layer to exercise the
    # compatibility path. No claim that this is a mainnet-valid block.
    b2 = %{b2 | header: %{b2.header | hash: repeat}}
    a = Archive.connect(a, b1, 1, []) |> Archive.connect(b2, 2, [])

    rec =
      Archive.block_record!(a, a.tip.id) |> Map.delete(:overwritten) |> Map.put(:height, 91_842)

    KV.write(kv, [{:put, :blocks, <<a.tip.id::32>>, :erlang.term_to_binary(rec)}])
    {a, _} = Archive.disconnect_tip(a)
    assert_missing(a, cb.txid)
    Archive.close(a)
    KV.close(kv)
  end
end
