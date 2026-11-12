defmodule Exnode.P2P.CompactBlockTest do
  use ExUnit.Case, async: true

  alias Exnode.Codec.Block
  alias Exnode.P2P.CompactBlock, as: CB
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  # A block with a coinbase and 6 spends.
  defp block do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    txs = for b <- Enum.take(bs, 6), do: BB.spend_op_true(hd(b.txs).txid, 0, 49 * 100_000_000)
    BB.build(List.last(bs).header, [BB.coinbase(151, 25 * 100_000_000) | txs])
  end

  # A mempool that knows `txs`.
  defp matcher(txs) do
    fn {k0, k1}, wanted ->
      w = MapSet.new(wanted)

      for tx <- txs,
          id = CB.short_id(k0, k1, tx.wtxid),
          MapSet.member?(w, id),
          into: %{},
          do: {id, tx}
    end
  end

  test "round trip of the cmpctblock message" do
    b = block()
    c = CB.from_block(b, 0x1122334455667788)
    assert {:ok, d} = CB.decode(CB.encode(c))
    assert d.header.hash == b.header.hash
    assert d.short_ids == c.short_ids
    assert [{0, cb}] = d.prefilled
    assert cb.txid == hd(b.txs).txid
  end

  test "full mempool: the block rebuilds byte for byte" do
    b = block()
    {:ok, p} = CB.init(CB.from_block(b, 7), matcher(tl(b.txs)))
    assert CB.missing(p) == []
    assert {:ok, rebuilt} = CB.fill(p, [])
    assert rebuilt.raw == b.raw
  end

  test "missing txs are requested and filled from blocktxn" do
    b = block()
    known = b.txs |> tl() |> Enum.drop(2)
    {:ok, p} = CB.init(CB.from_block(b, 7), matcher(known))
    assert CB.missing(p) == [1, 2]

    msg = CB.encode_getblocktxn(b.header.hash, [1, 2])
    assert {:ok, h, [1, 2]} = CB.decode_getblocktxn(msg)
    assert h == b.header.hash

    {:ok, _, txs} = CB.decode_blocktxn(CB.encode_blocktxn(b.header.hash, Enum.slice(b.txs, 1, 2)))
    assert {:ok, rebuilt} = CB.fill(p, txs)
    assert rebuilt.raw == b.raw
    # Wrong count of missing txs: invalid.
    assert CB.fill(p, [Enum.at(b.txs, 1)]) == :invalid
  end

  test "a mempool collision leaves the slot missing; a wrong tx makes the block fail (mutated)" do
    b = block()
    c = CB.from_block(b, 9)
    [id1 | _] = c.short_ids

    collide = fn keys, wanted -> Map.put(matcher(tl(b.txs)).(keys, wanted), id1, :collided) end
    {:ok, p} = CB.init(c, collide)
    assert CB.missing(p) == [1]

    # The peer answers with a different tx: merkle mismatch, so fall back.
    other = BB.spend_op_true(<<9::256>>, 0, 1)
    assert CB.fill(p, [other]) == :failed
  end

  test "duplicate short ids in the block fail; empty compact blocks are invalid" do
    b = block()
    c = CB.from_block(b, 3)

    dup = %{
      c
      | short_ids: [hd(c.short_ids) | tl(c.short_ids)] |> List.replace_at(1, hd(c.short_ids))
    }

    assert CB.init(dup, matcher([])) == :failed
    assert CB.init(%{c | short_ids: [], prefilled: []}, matcher([])) == :invalid
    assert CB.init(%{c | prefilled: [{99, hd(b.txs)}]}, matcher([])) == :invalid
  end

  test "malformed payloads" do
    assert CB.decode(<<1, 2, 3>>) == {:error, :malformed}
    c = CB.encode(CB.from_block(block(), 1))
    assert CB.decode(binary_part(c, 0, byte_size(c) - 1)) == {:error, :malformed}
    assert CB.decode(c <> <<0>>) == {:error, :malformed}
  end
end
