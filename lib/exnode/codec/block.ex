defmodule Exnode.Codec.Header do
  @moduledoc "80-byte block header (Core `CBlockHeader`, primitives/block.h)."
  alias Exnode.Crypto.Hash

  defstruct [:version, :prev_hash, :merkle_root, :time, :bits, :nonce, :hash, :raw]

  @doc "Decodes an 80-byte header from the front of `bin`. Returns `{header, rest}`."
  def decode(<<raw::binary-size(80), rest::binary>>) do
    <<version::little-signed-32, prev::binary-size(32), merkle::binary-size(32), time::little-32,
      bits::little-32, nonce::little-32>> = raw

    {%__MODULE__{
       version: version,
       prev_hash: prev,
       merkle_root: merkle,
       time: time,
       bits: bits,
       nonce: nonce,
       hash: Hash.hash256(raw),
       raw: raw
     }, rest}
  end

  def decode(_), do: throw({:codec_error, :truncated})

  def encode(%__MODULE__{} = h) do
    <<h.version::little-signed-32, h.prev_hash::binary, h.merkle_root::binary, h.time::little-32,
      h.bits::little-32, h.nonce::little-32>>
  end
end

defmodule Exnode.Codec.Block do
  @moduledoc """
  Block (de)serialization (Core `CBlock`, primitives/block.h): header followed
  by a CompactSize-prefixed vector of transactions with witness. Transactions
  are sub-binaries of the received block.
  """
  alias Exnode.Codec.{CompactSize, Header, Tx}

  defstruct [:header, :txs, :raw]

  @doc "Decodes a block from the front of `bin`. Returns `{block, rest}`; throws `{:codec_error, _}`."
  def decode(bin) do
    {header, rest} = Header.decode(bin)
    {n, rest} = CompactSize.decode(rest)
    {txs, rest} = decode_txs(n, rest, [])
    raw = binary_part(bin, 0, byte_size(bin) - byte_size(rest))
    {%__MODULE__{header: header, txs: txs, raw: raw}, rest}
  end

  defp decode_txs(0, rest, acc), do: {Enum.reverse(acc), rest}

  defp decode_txs(n, rest, acc) do
    {tx, rest} = Tx.decode(rest)
    decode_txs(n - 1, rest, [tx | acc])
  end

  @doc "Decodes a whole binary as exactly one block."
  def decode_exact(bin) do
    case decode(bin) do
      {b, ""} -> {:ok, b}
      {_b, _} -> {:error, :trailing_data}
    end
  catch
    {:codec_error, reason} -> {:error, reason}
  end

  @doc """
  The extent of each transaction in a serialized block, without decoding
  it: `{:ok, {{offset, length}, ...}}` in block order, or `{:error, reason}`
  where `decode_exact/1` would fail. Costs one small tuple per transaction
  instead of the decoded block (several times its size).
  """
  def tx_ranges(<<_header::binary-size(80), rest::binary>> = bin) do
    {n, rest} = CompactSize.decode(rest)
    {ranges, rest} = scan_txs(n, rest, byte_size(bin), [])

    if rest == "",
      do: {:ok, List.to_tuple(ranges)},
      else: {:error, :trailing_data}
  catch
    {:codec_error, reason} -> {:error, reason}
  end

  def tx_ranges(_), do: {:error, :truncated}

  defp scan_txs(0, rest, _size, acc), do: {Enum.reverse(acc), rest}

  defp scan_txs(n, rest, size, acc) do
    rest2 = Tx.skip(rest)
    start = size - byte_size(rest)
    scan_txs(n - 1, rest2, size, [{start, byte_size(rest) - byte_size(rest2)} | acc])
  end

  def encode(%__MODULE__{header: h, txs: txs}, opts \\ []) do
    [Header.encode(h), CompactSize.encode(length(txs)), Enum.map(txs, &Tx.encode(&1, opts))]
  end
end
