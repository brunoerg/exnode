defmodule Exnode.BlockFilterTest do
  @moduledoc "Core v32.1 src/test/data/blockfilters.json (BIP158 test vectors)."
  use ExUnit.Case, async: true

  alias Exnode.BlockFilter
  alias Exnode.Codec.Block
  alias Exnode.Crypto.Hash

  @vectors Path.expand("../fixtures/core-v32.1/blockfilters.json", __DIR__)

  test "basic filters and headers match all vectors" do
    [_header | rows] = @vectors |> File.read!() |> Jason.decode!()

    for [height, hash, block_hex, prev_scripts, prev_header, filter_hex, header_hex, note] <- rows do
      {:ok, b} = block_hex |> Base.decode16!(case: :lower) |> Block.decode_exact()
      assert Hash.to_hex(b.header.hash) == hash
      spent = Enum.map(prev_scripts, &Base.decode16!(&1, case: :lower))
      filter = BlockFilter.build(b, spent)

      assert Base.encode16(filter, case: :lower) == filter_hex,
             "height #{height} (#{note}): filter"

      assert Hash.to_hex(BlockFilter.header(filter, Hash.from_hex(prev_header))) == header_hex,
             "height #{height}: header"
    end
  end
end
