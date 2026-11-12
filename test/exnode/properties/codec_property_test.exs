defmodule Exnode.Properties.CodecPropertyTest do
  @moduledoc """
  Serialization properties: transactions and blocks round-trip byte for
  byte, ids and sizes follow Core's definitions, merkle roots and the
  CVE-2012-2459 mutation flag, compact targets, P2P messages and RPC amounts.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties
  import Bitwise

  alias Exnode.Codec.{Block, Tx}
  alias Exnode.Consensus.Pow
  alias Exnode.Crypto.Hash
  alias Exnode.P2P.Message
  alias Exnode.Test.Generators, as: G
  alias Exnode.Validation.Merkle

  property "tx: encode/decode round-trips; txid, wtxid and weight follow BIP141" do
    check all(tx <- G.tx(), max_runs: 500) do
      raw = tx.raw
      assert IO.iodata_to_binary(Tx.encode(tx)) == raw
      stripped = IO.iodata_to_binary(Tx.encode(tx, witness: false))
      witness? = Enum.any?(tx.inputs, &(&1.witness != []))

      # SerializeTransaction writes the witness only if some input has one.
      assert tx.has_witness == witness?
      assert tx.txid == Hash.hash256(stripped)
      assert tx.wtxid == Hash.hash256(raw)
      if not witness?, do: assert(raw == stripped and tx.txid == tx.wtxid)
      assert Tx.base_size(tx) == byte_size(stripped)
      assert Tx.weight(tx) == 3 * byte_size(stripped) + byte_size(raw)

      # Decoding the stripped form gives the same tx without witnesses.
      {:ok, s} = Tx.decode_exact(stripped)
      assert s.txid == tx.txid and Enum.all?(s.inputs, &(&1.witness == []))
    end
  end

  property "tx: a truncated or extended encoding never decodes exactly" do
    check all(
            tx <- G.tx(),
            cut <- integer(1..20),
            junk <- binary(min_length: 1, max_length: 8),
            max_runs: 300
          ) do
      raw = tx.raw
      short = binary_part(raw, 0, max(byte_size(raw) - cut, 0))
      assert match?({:error, _}, Tx.decode_exact(short))
      assert match?({:error, _}, Tx.decode_exact(raw <> junk))
    end
  end

  property "block: round-trips, the header hash commits to the merkle root" do
    check all(b <- G.block(), max_runs: 200) do
      assert IO.iodata_to_binary(Block.encode(b)) == b.raw
      assert b.header.hash == Hash.hash256(binary_part(b.raw, 0, 80))
      assert Merkle.block_root(b.txs) == {b.header.merkle_root, false}
    end
  end

  # Reference: the textbook recursive definition.
  defp ref_root([h]), do: h

  defp ref_root(hs) do
    hs = if rem(length(hs), 2) == 1, do: hs ++ [List.last(hs)], else: hs
    hs |> Enum.chunk_every(2) |> Enum.map(fn [a, b] -> Hash.hash256(a <> b) end) |> ref_root()
  end

  property "merkle: root equals the reference; duplicating an odd tail gives the same root, flagged mutated" do
    check all(hs <- uniq_list_of(G.hash(), min_length: 1, max_length: 40), max_runs: 300) do
      {root, mutated} = Merkle.compute_root(hs)
      assert root == ref_root(hs)
      refute mutated

      if rem(length(hs), 2) == 1 and length(hs) > 1 do
        # CVE-2012-2459: [.., c] and [.., c, c] share a root; Core flags the latter.
        assert Merkle.compute_root(hs ++ [List.last(hs)]) == {root, true}
      end
    end
  end

  property "compact targets: GetCompact/SetCompact keep the top 23 bits and are idempotent" do
    value =
      one_of([
        integer(0..0xFFFFFF),
        map(binary(length: 32), &:binary.decode_unsigned/1),
        map(integer(0..255), &(1 <<< &1))
      ])

    check all(v <- value, max_runs: 1000) do
      c = Pow.get_compact(v)
      {v2, neg, ovf} = Pow.set_compact(c)
      refute neg or ovf
      assert v2 <= v
      size = c >>> 24
      if size > 3, do: assert(v - v2 < 1 <<< (8 * (size - 3))), else: assert(v2 == v)
      assert Pow.get_compact(v2) == c
      # The mantissa's sign bit is never set by GetCompact(false).
      assert (c &&& 0x00800000) == 0
    end
  end

  defp message do
    hashes = list_of(G.hash(), max_length: 20)

    item =
      gen(
        all(
          t <- member_of([:tx, :block, :filtered_block, :cmpct_block, :wtx]),
          h <- G.hash(),
          w <- boolean(),
          do: %{type: t, hash: h, witness: w and t in [:tx, :block]}
        )
      )

    one_of([
      map(integer(0..0xFFFFFFFFFFFFFFFF), &{:ping, &1}),
      map(integer(0..0xFFFFFFFFFFFFFFFF), &{:pong, &1}),
      map(integer(0..0x7FFFFFFFFFFFFFFF), &{:feefilter, &1}),
      gen(all(a <- boolean(), v <- integer(1..2), do: {:sendcmpct, %{announce: a, version: v}})),
      gen(
        all(
          c <- member_of([:getheaders, :getblocks]),
          loc <- hashes,
          stop <- G.hash(),
          do: {c, %{locator: loc, hash_stop: stop}}
        )
      ),
      gen(
        all(
          c <- member_of([:inv, :getdata, :notfound]),
          items <- list_of(item, max_length: 20),
          do: {c, items}
        )
      ),
      gen(
        all(
          c <- member_of([:getcfilters, :getcfheaders]),
          s <- integer(0..0xFFFFFFFF),
          h <- G.hash(),
          do: {c, %{filter_type: 0, start_height: s, stop_hash: h}}
        )
      ),
      map(G.hash(), &{:getcfcheckpt, %{filter_type: 0, stop_hash: &1}})
    ])
  end

  # Messages exnode both sends and parses (the BIP157 replies cfilter /
  # cfheaders / cfcheckpt are only sent; their bytes are checked against
  # bitcoind in interop/block_filters_test.exs).
  property "P2P messages: decode(encode(m)) re-encodes to the same bytes" do
    check all(m <- message(), max_runs: 1000) do
      {cmd, payload} = Message.encode(m)
      payload = IO.iodata_to_binary(payload)
      assert {:ok, decoded} = Message.decode(cmd, payload)
      {^cmd, again} = Message.encode(decoded)
      assert IO.iodata_to_binary(again) == payload
    end
  end

  property "RPC amounts: ValueFromAmount prints exactly 8 decimals of the satoshi value" do
    check all(
            sat <-
              one_of([
                integer(-2_100_000_000_000_000..2_100_000_000_000_000),
                integer(-1000..1000)
              ]),
            max_runs: 1000
          ) do
      s = Jason.encode!(Exnode.RPC.JSON.amount(sat))
      assert [int, frac] = String.split(String.trim_leading(s, "-"), ".")
      assert byte_size(frac) == 8

      assert String.to_integer(int <> frac) * if(String.starts_with?(s, "-"), do: -1, else: 1) ==
               sat

      # Jason reads it back as the same number of BTC (to float precision).
      assert_in_delta Jason.decode!(s), sat / 100_000_000, 1.0e-8
    end
  end
end
