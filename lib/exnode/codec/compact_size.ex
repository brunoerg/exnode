defmodule Exnode.Codec.CompactSize do
  @moduledoc """
  Bitcoin CompactSize integers.

  Port of `ReadCompactSize` / `WriteCompactSize` from Core `src/serialize.h`
  (pinned v32.1). Decoding rejects non-canonical encodings and, when
  `range_check` is on (the default), values above `MAX_SIZE` (0x02000000).
  """

  # serialize.h: inline constexpr uint64_t MAX_SIZE = 0x02000000;
  @max_size 0x02000000

  def max_size, do: @max_size

  @doc """
  Decodes a CompactSize from the front of `bin`.

  Returns `{value, rest}`. Throws `{:codec_error, reason}` on truncation,
  non-canonical encoding or (with range check) a size above MAX_SIZE.
  """
  # Core: ReadCompactSize(Stream& is, bool range_check = true)
  def decode(bin, range_check \\ true)

  def decode(<<n, rest::binary>>, _rc) when n < 253, do: {n, rest}

  def decode(<<253, n::little-16, rest::binary>>, rc) do
    if n < 253, do: throw({:codec_error, :non_canonical_compact_size})
    check_range(n, rc)
    {n, rest}
  end

  def decode(<<254, n::little-32, rest::binary>>, rc) do
    if n < 0x10000, do: throw({:codec_error, :non_canonical_compact_size})
    check_range(n, rc)
    {n, rest}
  end

  def decode(<<255, n::little-64, rest::binary>>, rc) do
    if n < 0x100000000, do: throw({:codec_error, :non_canonical_compact_size})
    check_range(n, rc)
    {n, rest}
  end

  def decode(_bin, _rc), do: throw({:codec_error, :truncated})

  defp check_range(n, true) when n > @max_size, do: throw({:codec_error, :compact_size_too_large})
  defp check_range(_n, _), do: :ok

  @doc "Encodes `n` as a CompactSize (Core `WriteCompactSize`)."
  def encode(n) when n < 253, do: <<n>>
  def encode(n) when n <= 0xFFFF, do: <<253, n::little-16>>
  def encode(n) when n <= 0xFFFFFFFF, do: <<254, n::little-32>>
  def encode(n), do: <<255, n::little-64>>

  @doc "Size in bytes of the CompactSize encoding of `n` (Core `GetSizeOfCompactSize`)."
  def size(n) when n < 253, do: 1
  def size(n) when n <= 0xFFFF, do: 3
  def size(n) when n <= 0xFFFFFFFF, do: 5
  def size(_n), do: 9

  @doc "Decodes a CompactSize-prefixed byte vector, returning `{bytes, rest}` (bytes is a sub-binary)."
  def decode_bytes(bin) do
    case decode(bin) do
      # The empty vector is the shared literal: no heap per item. A witness
      # stack of millions of empty items otherwise cost a fresh
      # binary each, ~45 B of heap per wire byte.
      {0, rest} ->
        {<<>>, rest}

      {len, rest} ->
        case rest do
          <<bytes::binary-size(len), rest2::binary>> -> {bytes, rest2}
          _ -> throw({:codec_error, :truncated})
        end
    end
  end

  def encode_bytes(bytes), do: [encode(byte_size(bytes)), bytes]
end
