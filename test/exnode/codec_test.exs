defmodule Exnode.CodecTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Codec.{Block, CompactSize, Tx}
  alias Exnode.Crypto.Hash

  @fixtures Path.expand("../fixtures/core-v32.1", __DIR__)

  # Mainnet genesis block (Core kernel/chainparams.cpp CreateGenesisBlock).
  @genesis_hex "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

  test "mainnet genesis decodes, hashes and round-trips" do
    raw = Base.decode16!(@genesis_hex, case: :lower)
    {:ok, b} = Block.decode_exact(raw)

    assert Hash.to_hex(b.header.hash) ==
             "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

    [cb] = b.txs

    assert Hash.to_hex(cb.txid) ==
             "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

    assert cb.txid == b.header.merkle_root
    assert Tx.coinbase?(cb)
    assert IO.iodata_to_binary(Block.encode(b)) == raw

    assert :binary.referenced_byte_size(cb.raw) == byte_size(raw),
           "tx raw should be a sub-binary of the block"
  end

  test "every Core tx vector round-trips byte-exactly, and txid matches the non-witness hash" do
    for f <- ["tx_valid.json", "tx_invalid.json"],
        [[_ | _], hex, _] <- Jason.decode!(File.read!(Path.join(@fixtures, f))) do
      raw = Base.decode16!(hex, case: :mixed)
      {:ok, tx} = Tx.decode_exact(raw)
      assert IO.iodata_to_binary(Tx.encode(tx)) == raw
      assert tx.wtxid == Hash.hash256(raw)
      assert tx.txid == Hash.hash256(Tx.encode(tx, witness: false))
      assert Tx.base_size(tx) == IO.iodata_length(Tx.encode(tx, witness: false))
    end
  end

  describe "Core UnserializeTransaction quirks" do
    test "empty vin with zero flag byte leaves vout unread" do
      raw = <<1::little-32, 0, 0, 0::little-32>>
      assert {:ok, %Tx{inputs: [], outputs: []}} = Tx.decode_exact(raw)
    end

    test "witness flag with all-empty witnesses is rejected (superfluous witness record)" do
      inp = [<<0::256>>, <<0::32>>, <<0>>, <<0xFFFFFFFF::32>>]
      raw = IO.iodata_to_binary([<<2::little-32, 0, 1, 1>>, inp, <<0>>, <<0>>, <<0::32>>])
      assert {:error, :superfluous_witness_record} = Tx.decode_exact(raw)
    end

    test "unknown optional data flag is rejected" do
      raw = IO.iodata_to_binary([<<2::little-32, 0, 2, 0, 0>>, <<0::32>>])
      assert {:error, :unknown_tx_optional_data} = Tx.decode_exact(raw)
    end

    test "truncation" do
      assert {:error, :truncated} = Tx.decode_exact(<<1, 0, 0>>)
    end
  end

  describe "Block.tx_ranges" do
    defp block_of(tx_raws),
      do: IO.iodata_to_binary([<<0::640>>, CompactSize.encode(length(tx_raws)), tx_raws])

    test "agrees with decode on every Core tx vector, one block of them all" do
      raws =
        for f <- ["tx_valid.json", "tx_invalid.json"],
            [[_ | _], hex, _] <- Jason.decode!(File.read!(Path.join(@fixtures, f))),
            raw = Base.decode16!(hex, case: :mixed),
            do: raw

      bin = block_of(raws)
      {:ok, b} = Block.decode_exact(bin)
      {:ok, ranges} = Block.tx_ranges(bin)
      assert Tuple.to_list(ranges) |> Enum.map(fn {o, l} -> binary_part(bin, o, l) end) == raws
      assert Enum.map(b.txs, & &1.raw) == raws
    end

    test "agrees with decode on the regtest fixture chain" do
      path = Path.expand("../fixtures/regtest/chain150.bin", __DIR__)

      for raw <- Exnode.Test.BlockBuilder.read_chain(path) do
        {:ok, b} = Block.decode_exact(raw)
        {:ok, ranges} = Block.tx_ranges(raw)

        assert for({o, l} <- Tuple.to_list(ranges), do: binary_part(raw, o, l)) ==
                 Enum.map(b.txs, & &1.raw)
      end
    end

    test "fails where decode fails" do
      inp = [<<0::256>>, <<0::32>>, <<0>>, <<0xFFFFFFFF::32>>]
      ok = <<1::little-32, 0, 0, 0::little-32>>

      for bad <- [
            # superfluous witness record
            IO.iodata_to_binary([<<2::little-32, 0, 1, 1>>, inp, <<0>>, <<0>>, <<0::32>>]),
            # unknown optional data
            IO.iodata_to_binary([<<2::little-32, 0, 2, 0, 0>>, <<0::32>>]),
            # truncated
            <<1, 0, 0>>,
            # non-canonical CompactSize input count
            <<1::little-32, 253, 1, 0>>
          ] do
        bin = block_of([bad])
        assert {:error, r} = Block.decode_exact(bin)
        assert Block.tx_ranges(bin) == {:error, r}
      end

      assert {:error, :trailing_data} = Block.tx_ranges(block_of([ok]) <> <<0>>)
      assert {:error, :truncated} = Block.tx_ranges(<<0::320>>)
      # A count larger than the txs present.
      assert {:error, :truncated} = Block.tx_ranges(<<0::640, 2>> <> ok)
    end

    property "agrees with decode on generated txs" do
      check all(txs <- StreamData.list_of(Exnode.Test.Generators.tx(), max_length: 5)) do
        raws = for tx <- txs, do: IO.iodata_to_binary(Tx.encode(tx))
        bin = block_of(raws)
        {:ok, ranges} = Block.tx_ranges(bin)
        assert for({o, l} <- Tuple.to_list(ranges), do: binary_part(bin, o, l)) == raws
      end
    end
  end

  describe "CompactSize" do
    test "non-canonical encodings are rejected" do
      assert catch_throw(CompactSize.decode(<<253, 252, 0>>)) ==
               {:codec_error, :non_canonical_compact_size}

      assert catch_throw(CompactSize.decode(<<254, 0xFF, 0xFF, 0, 0>>)) ==
               {:codec_error, :non_canonical_compact_size}

      assert catch_throw(CompactSize.decode(<<255, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0>>)) ==
               {:codec_error, :non_canonical_compact_size}
    end

    test "MAX_SIZE range check" do
      assert catch_throw(CompactSize.decode(CompactSize.encode(0x02000001))) ==
               {:codec_error, :compact_size_too_large}

      assert {0x02000001, ""} = CompactSize.decode(CompactSize.encode(0x02000001), false)
    end

    property "round-trips and reports its size" do
      check all(
              n <-
                one_of([integer(0..300), integer(0..0xFFFFFFFF), integer(0..0xFFFFFFFFFFFFFFFF)])
            ) do
        enc = CompactSize.encode(n)
        assert byte_size(enc) == CompactSize.size(n)
        assert {^n, "rest"} = CompactSize.decode(enc <> "rest", false)
      end
    end
  end

  property "decoder never raises on arbitrary bytes, only returns {:ok, _} | {:error, _}" do
    check all(bin <- binary(max_length: 400), max_runs: 2000) do
      assert match?({:ok, _}, Tx.decode_exact(bin)) or match?({:error, _}, Tx.decode_exact(bin))

      assert match?({:ok, _}, Block.decode_exact(bin)) or
               match?({:error, _}, Block.decode_exact(bin))
    end
  end
end
