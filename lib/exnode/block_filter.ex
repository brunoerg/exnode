defmodule Exnode.BlockFilter do
  @moduledoc """
  BIP158 basic block filters. Port of Core v32.1 `blockfilter.cpp`
  (`GCSFilter`, `BasicFilterElements`, `BlockFilter::ComputeHeader`).

  * Elements: every output script of the block except empty and OP_RETURN
    ones, and every script the block's inputs spend (except empty), as a set.
  * Each element is SipHash-2-4'd with the block hash's first 16 bytes as key,
    mapped to `[0, N * M)` (FastRange64), sorted, and the deltas are
    Golomb-Rice coded with P = 19 (M = 784931).
  * Serialization: CompactSize(N) followed by the bit stream (MSB first,
    zero-padded).
  * Header: `hash256(hash256(filter) || prev_header)`; the genesis block's
    previous header is zero.
  """
  import Bitwise

  alias Exnode.Codec.{Block, CompactSize}
  alias Exnode.Crypto.{Hash, SipHash}

  @p 19
  @m 784_931

  @doc "The basic filter of `block`, given the scripts its inputs spend (block undo, in any order)."
  # Core: BlockFilter(BASIC, block, block_undo) -> GCSFilter(params, BasicFilterElements(...))
  def build(%Block{} = block, spent_scripts) do
    build(
      block.header.hash,
      for(tx <- block.txs, o <- tx.outputs, do: o.script_pubkey),
      spent_scripts
    )
  end

  @doc "The filter from the block hash, all its output scripts and the scripts its inputs spent."
  def build(block_hash, output_scripts, spent_scripts) when is_binary(block_hash) do
    outs = for s <- output_scripts, s != <<>>, :binary.first(s) != 0x6A, do: s
    elements = MapSet.new(outs ++ Enum.reject(spent_scripts, &(&1 == <<>>)))
    <<k0::little-64, k1::little-64, _::binary>> = block_hash
    encode(elements, k0, k1)
  end

  defp encode(elements, k0, k1) do
    n = MapSet.size(elements)
    f = n * @m

    values =
      elements
      |> Enum.map(fn e -> (SipHash.hash(k0, k1, e) * f) >>> 64 end)
      |> Enum.sort()

    {bits, _} =
      Enum.reduce(values, {[], 0}, fn v, {acc, last} ->
        delta = v - last
        q = delta >>> @p
        # Unary quotient, a 0, then the low P bits.
        {[<<delta &&& (1 <<< @p) - 1::size(@p)>>, <<0::1>>, ones(q) | acc], v}
      end)

    stream = bits |> Enum.reverse() |> :erlang.list_to_bitstring() |> pad()
    IO.iodata_to_binary([CompactSize.encode(n), stream])
  end

  defp ones(0), do: <<>>
  defp ones(q), do: <<(1 <<< q) - 1::size(q)>>

  # Bitstrings: list_to_bitstring keeps bits; pad to a whole byte.
  defp pad(bits) do
    rem = rem(bit_size(bits), 8)
    if rem == 0, do: bits, else: <<bits::bitstring, 0::size(8 - rem)>>
  end

  @doc "Core `BlockFilter::GetHash`: hash256 of the encoded filter."
  def filter_hash(filter), do: Hash.hash256(filter)

  @doc "Core `BlockFilter::ComputeHeader(prev_header)`."
  def header(filter, prev_header), do: Hash.hash256([filter_hash(filter), prev_header])

  @doc """
  Core `GCSFilter::MatchAny`: true if any of `elements` is (probably) in the
  filter of block `block_hash` (false positives at rate 1/M, no false
  negatives). Raises on a malformed filter.
  """
  # Core: GCSFilter::MatchAny / MatchInternal (blockfilter.cpp)
  def match_any?(filter, block_hash, elements) do
    {n, stream} = CompactSize.decode(filter)
    <<k0::little-64, k1::little-64, _::binary>> = block_hash
    f = n * @m
    wanted = MapSet.new(elements, fn e -> (SipHash.hash(k0, k1, e) * f) >>> 64 end)
    n > 0 and MapSet.size(wanted) > 0 and scan(stream, n, 0, wanted)
  end

  defp scan(_bits, 0, _last, _wanted), do: false

  defp scan(bits, left, last, wanted) do
    {q, bits} = unary(bits, 0)
    <<r::size(@p), bits::bitstring>> = bits
    v = last + (q <<< @p ||| r)
    MapSet.member?(wanted, v) or scan(bits, left - 1, v, wanted)
  end

  # Core GolombRiceDecode: count 1 bits up to the terminating 0.
  defp unary(<<1::1, rest::bitstring>>, q), do: unary(rest, q + 1)
  defp unary(<<0::1, rest::bitstring>>, q), do: {q, rest}

  @doc "Elements count N of an encoded filter."
  def n(filter), do: filter |> CompactSize.decode() |> elem(0)
end
