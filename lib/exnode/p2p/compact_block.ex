defmodule Exnode.P2P.CompactBlock do
  @moduledoc """
  BIP152 compact blocks, version 2 (wtxid short ids). Ports of Core v32.1
  `blockencodings.cpp`: `CBlockHeaderAndShortTxIDs` (serialization,
  `FillShortTxIDSelector`, `GetShortID`) and `PartiallyDownloadedBlock`
  (`InitData`, `FillBlock`), plus the `getblocktxn` / `blocktxn` messages
  (`BlockTransactionsRequest` / `BlockTransactions`).

  Not ported: Core's unordered_map bucket-size limit in `InitData` (a
  hash-table DoS guard tied to its implementation), and the extra-txn pool
  (`vExtraTxnForCompact`, recently replaced/rejected txs). Without that pool,
  such txs are fetched with `getblocktxn`.
  """
  import Bitwise

  alias Exnode.Codec.{Block, CompactSize, Header, Tx}
  alias Exnode.Crypto.SipHash
  alias Exnode.Validation.Block, as: BlockRules

  # MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT
  @max_txs div(4_000_000, 40)

  defstruct [:header, :nonce, short_ids: [], prefilled: []]

  # --- message codecs --------------------------------------------------------------

  @doc "Decodes a `cmpctblock` payload. `prefilled` holds absolute indexes."
  def decode(payload) do
    with <<hdr::binary-size(80), nonce::little-64, rest::binary>> <- payload,
         {header, ""} <- Header.decode(hdr),
         {n, rest} <- CompactSize.decode(rest),
         true <- n <= @max_txs || :too_many,
         <<ids::binary-size(n * 6), rest::binary>> <- rest,
         {m, rest} <- CompactSize.decode(rest),
         true <- m <= @max_txs || :too_many,
         {:ok, prefilled} <- decode_prefilled(m, rest, -1, []) do
      short_ids = for <<id::little-48 <- ids>>, do: id
      {:ok, %__MODULE__{header: header, nonce: nonce, short_ids: short_ids, prefilled: prefilled}}
    else
      _ -> {:error, :malformed}
    end
  catch
    {:codec_error, _} -> {:error, :malformed}
  end

  # Differential indexes: absolute = previous + diff + 1 (must fit uint16).
  defp decode_prefilled(0, <<>>, _last, acc), do: {:ok, Enum.reverse(acc)}
  defp decode_prefilled(0, _extra, _last, _acc), do: {:error, :trailing}

  defp decode_prefilled(n, bin, last, acc) do
    {diff, rest} = CompactSize.decode(bin)
    idx = last + diff + 1

    if idx > 0xFFFF do
      {:error, :index}
    else
      {tx, rest} = Tx.decode(rest)
      decode_prefilled(n - 1, rest, idx, [{idx, tx} | acc])
    end
  end

  @doc "Core `CBlockHeaderAndShortTxIDs(block, nonce)`: the coinbase prefilled, all other txs as short ids."
  def from_block(%Block{txs: [cb | rest]} = b, nonce) do
    {k0, k1} = keys(b.header, nonce)

    %__MODULE__{
      header: b.header,
      nonce: nonce,
      short_ids: for(tx <- rest, do: short_id(k0, k1, tx.wtxid)),
      prefilled: [{0, cb}]
    }
  end

  def encode(%__MODULE__{} = c) do
    {pre, _} =
      Enum.map_reduce(c.prefilled, -1, fn {idx, tx}, last ->
        {[CompactSize.encode(idx - last - 1), Tx.encode(tx)], idx}
      end)

    IO.iodata_to_binary([
      Header.encode(c.header),
      <<c.nonce::little-64>>,
      CompactSize.encode(length(c.short_ids)),
      for(id <- c.short_ids, do: <<id::little-48>>),
      CompactSize.encode(length(c.prefilled)),
      pre
    ])
  end

  @doc "Core `FillShortTxIDSelector`: SipHash keys from SHA256(header || nonce)."
  def keys(header, nonce) do
    <<k0::little-64, k1::little-64, _::binary>> =
      :crypto.hash(:sha256, [Header.encode(header), <<nonce::little-64>>])

    {k0, k1}
  end

  @doc "Core `GetShortID`: the low 48 bits of SipHash-2-4(wtxid)."
  def short_id(k0, k1, wtxid), do: SipHash.hash(k0, k1, wtxid) &&& 0xFFFFFFFFFFFF

  def tx_count(%__MODULE__{short_ids: s, prefilled: p}), do: length(s) + length(p)

  @doc "`getblocktxn` payload: block hash and differentially encoded indexes."
  def encode_getblocktxn(hash, indexes) do
    {diffs, _} =
      Enum.map_reduce(indexes, -1, fn i, last -> {CompactSize.encode(i - last - 1), i} end)

    IO.iodata_to_binary([hash, CompactSize.encode(length(indexes)), diffs])
  end

  # Core BlockTransactionsRequest: indexes are `uint16_t`, and
  # DifferenceFormatter::Unser throws "differential value overflow" once one
  # passes 65535. Indexes strictly increase, so a count above 65536 cannot
  # decode either; both are refused before anything is built (an
  # unbounded count decoded ~40x the message size into a list).
  @max_blocktxn_index 0xFFFF

  def decode_getblocktxn(<<hash::binary-size(32), rest::binary>>) do
    {n, rest} = CompactSize.decode(rest)
    if n > @max_blocktxn_index + 1, do: throw({:codec_error, :differential_overflow})

    {idx, _} =
      Enum.map_reduce(1..n//1, {rest, -1}, fn _, {bin, last} ->
        {d, bin} = CompactSize.decode(bin)
        i = last + d + 1
        if i > @max_blocktxn_index, do: throw({:codec_error, :differential_overflow})
        {i, {bin, i}}
      end)

    {:ok, hash, idx}
  catch
    {:codec_error, _} -> {:error, :malformed}
  end

  # Shorter than the block hash (as decode_blocktxn/1).
  def decode_getblocktxn(_payload), do: {:error, :malformed}

  def encode_blocktxn(hash, txs),
    do: encode_blocktxn_raw(hash, Enum.map(txs, &Tx.encode/1))

  @doc "`blocktxn` from already serialized (with witness) transactions."
  def encode_blocktxn_raw(hash, raw_txs),
    do: IO.iodata_to_binary([hash, CompactSize.encode(length(raw_txs)), raw_txs])

  @doc "Decodes `blocktxn`: `{:ok, block_hash, [tx]}`."
  def decode_blocktxn(<<hash::binary-size(32), rest::binary>>) do
    {n, rest} = CompactSize.decode(rest)
    {txs, _} = Enum.map_reduce(1..n//1, rest, fn _, bin -> Tx.decode(bin) end)
    {:ok, hash, txs}
  catch
    {:codec_error, _} -> {:error, :malformed}
  end

  def decode_blocktxn(_), do: {:error, :malformed}

  # --- reconstruction (PartiallyDownloadedBlock) ------------------------------------

  @doc """
  Core `PartiallyDownloadedBlock::InitData`. `match` is
  `fn {k0, k1}, short_ids -> %{short_id => tx | :collided}` (the mempool's
  txs whose short id is wanted). Returns `{:ok, partial}`, `:invalid` (the
  peer misbehaved) or `:failed` (a short-id collision in the block: fetch
  the full block).
  """
  # Core: PartiallyDownloadedBlock::InitData (blockencodings.cpp)
  def init(%__MODULE__{} = c, match) do
    count = tx_count(c)

    cond do
      c.short_ids == [] and c.prefilled == [] ->
        :invalid

      count > @max_txs ->
        :invalid

      Enum.any?(c.prefilled, fn {idx, _} -> idx >= count end) ->
        :invalid

      true ->
        avail = Map.new(c.prefilled)

        # Short ids fill the positions not taken by prefilled txs, in order.
        positions = Enum.reject(0..(count - 1)//1, &Map.has_key?(avail, &1))
        by_id = Enum.zip(c.short_ids, positions) |> Map.new()

        if map_size(by_id) != length(c.short_ids) do
          :failed
        else
          # No short ids (all txs prefilled): nothing to look up, so no
          # pass over the mempool.
          found =
            if map_size(by_id) == 0,
              do: %{},
              else: match.(keys(c.header, c.nonce), Map.keys(by_id))

          avail =
            Enum.reduce(found, avail, fn
              {_id, :collided}, acc -> acc
              {id, tx}, acc -> Map.put(acc, by_id[id], tx)
            end)

          {:ok, %{header: c.header, count: count, txs: avail}}
        end
    end
  end

  @doc "Indexes of txs still missing."
  def missing(%{count: n, txs: avail}),
    do: for(i <- 0..(n - 1)//1, not Map.has_key?(avail, i), do: i)

  @doc """
  Core `PartiallyDownloadedBlock::FillBlock`: fill the gaps with
  `missing_txs` (in index order). `{:ok, block}`, `:invalid` (wrong count) or
  `:failed` (mutated: merkle root or witness commitment mismatch, e.g. a
  short-id collision picked the wrong tx).
  """
  # Core: PartiallyDownloadedBlock::FillBlock + IsBlockMutated
  def fill(%{header: h, count: n, txs: avail} = partial, missing_txs, segwit_active \\ true) do
    gaps = missing(partial)

    if length(gaps) != length(missing_txs) do
      :invalid
    else
      all = Map.merge(avail, Map.new(Enum.zip(gaps, missing_txs)))
      txs = for i <- 0..(n - 1)//1, do: all[i]
      raw = IO.iodata_to_binary(Block.encode(%Block{header: h, txs: txs}))

      case Block.decode_exact(raw) do
        {:ok, b} ->
          if mutated?(b, segwit_active), do: :failed, else: {:ok, b}

        _ ->
          :failed
      end
    end
  end

  @doc "Core `IsBlockMutated`: merkle root, 64-byte txs without a coinbase, witness root."
  def mutated?(%Block{txs: txs} = b, check_witness_root) do
    cond do
      BlockRules.check_merkle_root(b) != :ok -> true
      txs == [] or not Tx.coinbase?(hd(txs)) -> Enum.any?(txs, &(Tx.base_size(&1) == 64))
      BlockRules.check_witness_malleation(b, check_witness_root) != :ok -> true
      true -> false
    end
  end
end
