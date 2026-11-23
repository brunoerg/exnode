defmodule Exnode.Codec.Tx do
  @moduledoc """
  Transaction (de)serialization.

  Port of `UnserializeTransaction` / `SerializeTransaction` from Core
  `src/primitives/transaction.h` (pinned v32.1), with `allow_witness = true`
  (TX_WITH_WITNESS) unless stated otherwise.

  Byte fields are sub-binaries of the input, so no bytes are copied. `raw` is
  the exact slice the transaction was parsed from. txid and wtxid are hashed
  straight from raw slices, never from a re-serialization.
  """

  alias Exnode.Codec.CompactSize
  alias Exnode.Crypto.Hash

  defmodule In do
    @moduledoc false
    defstruct [:prev_hash, :prev_index, :script_sig, :sequence, witness: []]
  end

  defmodule Out do
    @moduledoc false
    defstruct [:value, :script_pubkey]
  end

  defstruct [
    :version,
    :inputs,
    :outputs,
    :locktime,
    :raw,
    :txid,
    :wtxid,
    :has_witness,
    :base_size
  ]

  @type t :: %__MODULE__{}

  @doc "Decodes one transaction from the front of `bin`. Returns `{tx, rest}`; throws `{:codec_error, _}`."
  # Core: UnserializeTransaction (primitives/transaction.h)
  def decode(bin) when is_binary(bin) do
    case bin do
      <<version::little-32, after_version::binary>> ->
        decode_after_version(bin, version, after_version)

      _ ->
        throw({:codec_error, :truncated})
    end
  end

  defp decode_after_version(bin, version, after_version) do
    {vin, rest} = decode_inputs(after_version)

    # Mirror Core exactly: an empty vin is read as the segwit marker; then the
    # flag byte follows. If the flag is 0, vout is NOT read (stays empty).
    {flags, vin, vout, rest, body_start} =
      if vin == [] do
        case rest do
          <<flags, rest2::binary>> when flags != 0 ->
            body_start = byte_size(bin) - byte_size(rest2)
            {vin, rest3} = decode_inputs(rest2)
            {vout, rest4} = decode_outputs(rest3)
            {flags, vin, vout, rest4, body_start}

          <<0, rest2::binary>> ->
            {0, [], [], rest2, nil}

          _ ->
            throw({:codec_error, :truncated})
        end
      else
        {vout, rest2} = decode_outputs(rest)
        {0, vin, vout, rest2, nil}
      end

    body_end = byte_size(bin) - byte_size(rest)

    {flags, vin, rest} =
      if Bitwise.band(flags, 1) == 1 do
        {vin, rest} = decode_witnesses(vin, rest, [])

        if not Enum.any?(vin, &(&1.witness != [])),
          do: throw({:codec_error, :superfluous_witness_record})

        {Bitwise.bxor(flags, 1), vin, rest}
      else
        {flags, vin, rest}
      end

    if flags != 0, do: throw({:codec_error, :unknown_tx_optional_data})

    case rest do
      <<locktime::little-32, rest2::binary>> ->
        total = byte_size(bin) - byte_size(rest2)
        raw = binary_part(bin, 0, total)
        has_witness = body_start != nil and Enum.any?(vin, &(&1.witness != []))
        wtxid = Hash.hash256(raw)

        txid =
          if has_witness do
            # txid commits to the non-witness serialization:
            # version || vin || vout || locktime, hashed from raw slices.
            body = binary_part(bin, body_start, body_end - body_start)
            Hash.hash256([binary_part(bin, 0, 4), body, <<locktime::little-32>>])
          else
            wtxid
          end

        # Non-witness size: version + body (vin, vout) + locktime, from slice offsets.
        base_size = if has_witness, do: 4 + (body_end - body_start) + 4, else: total

        tx = %__MODULE__{
          base_size: base_size,
          version: version,
          inputs: vin,
          outputs: vout,
          locktime: locktime,
          raw: raw,
          txid: txid,
          wtxid: wtxid,
          has_witness: has_witness
        }

        {tx, rest2}

      _ ->
        throw({:codec_error, :truncated})
    end
  end

  defp decode_inputs(bin) do
    {n, rest} = CompactSize.decode(bin)
    decode_n(n, rest, &decode_input/1, [])
  end

  defp decode_outputs(bin) do
    {n, rest} = CompactSize.decode(bin)
    decode_n(n, rest, &decode_output/1, [])
  end

  defp decode_n(0, rest, _f, acc), do: {Enum.reverse(acc), rest}

  defp decode_n(n, rest, f, acc) do
    {item, rest} = f.(rest)
    decode_n(n - 1, rest, f, [item | acc])
  end

  defp decode_input(<<prev_hash::binary-size(32), prev_index::little-32, rest::binary>>) do
    {script_sig, rest} = CompactSize.decode_bytes(rest)

    case rest do
      <<sequence::little-32, rest2::binary>> ->
        {%In{
           prev_hash: prev_hash,
           prev_index: prev_index,
           script_sig: script_sig,
           sequence: sequence
         }, rest2}

      _ ->
        throw({:codec_error, :truncated})
    end
  end

  defp decode_input(_), do: throw({:codec_error, :truncated})

  # CAmount is int64_t: decode as signed.
  defp decode_output(<<value::little-signed-64, rest::binary>>) do
    {spk, rest} = CompactSize.decode_bytes(rest)
    {%Out{value: value, script_pubkey: spk}, rest}
  end

  defp decode_output(_), do: throw({:codec_error, :truncated})

  defp decode_witnesses([], rest, acc), do: {Enum.reverse(acc), rest}

  defp decode_witnesses([txin | tail], bin, acc) do
    {n, rest} = CompactSize.decode(bin)
    {stack, rest} = decode_n(n, rest, &CompactSize.decode_bytes/1, [])
    decode_witnesses(tail, rest, [%{txin | witness: stack} | acc])
  end

  @doc """
  Skips one transaction at the front of `bin` and returns the rest. Accepts
  exactly what `decode/1` accepts, and throws the same `{:codec_error, _}`,
  but builds no structs and hashes nothing: only the transaction's extent
  is wanted.
  """
  def skip(<<_version::binary-size(4), rest::binary>>) do
    {nin, rest} = CompactSize.decode(rest)
    rest = skip_inputs(nin, rest)

    # As decode/1: an empty vin is the segwit marker, then the flag byte.
    {flags, nin, rest} =
      if nin == 0 do
        case rest do
          <<flags, rest2::binary>> when flags != 0 ->
            {nin, rest3} = CompactSize.decode(rest2)
            rest3 = skip_inputs(nin, rest3)
            {nout, rest4} = CompactSize.decode(rest3)
            {flags, nin, skip_outputs(nout, rest4)}

          <<0, rest2::binary>> ->
            {0, 0, rest2}

          _ ->
            throw({:codec_error, :truncated})
        end
      else
        {nout, rest} = CompactSize.decode(rest)
        {0, nin, skip_outputs(nout, rest)}
      end

    {flags, rest} =
      if Bitwise.band(flags, 1) == 1 do
        {any_witness, rest} = skip_witnesses(nin, rest, false)
        if not any_witness, do: throw({:codec_error, :superfluous_witness_record})
        {Bitwise.bxor(flags, 1), rest}
      else
        {flags, rest}
      end

    if flags != 0, do: throw({:codec_error, :unknown_tx_optional_data})

    case rest do
      <<_locktime::binary-size(4), rest2::binary>> -> rest2
      _ -> throw({:codec_error, :truncated})
    end
  end

  def skip(_), do: throw({:codec_error, :truncated})

  defp skip_inputs(0, rest), do: rest

  defp skip_inputs(n, <<_prevout::binary-size(36), rest::binary>>) do
    case skip_bytes(rest) do
      <<_sequence::binary-size(4), rest2::binary>> -> skip_inputs(n - 1, rest2)
      _ -> throw({:codec_error, :truncated})
    end
  end

  defp skip_inputs(_, _), do: throw({:codec_error, :truncated})

  defp skip_outputs(0, rest), do: rest

  defp skip_outputs(n, <<_value::binary-size(8), rest::binary>>),
    do: skip_outputs(n - 1, skip_bytes(rest))

  defp skip_outputs(_, _), do: throw({:codec_error, :truncated})

  defp skip_witnesses(0, rest, any), do: {any, rest}

  defp skip_witnesses(n, bin, any) do
    {items, rest} = CompactSize.decode(bin)
    skip_witnesses(n - 1, skip_items(items, rest), any or items > 0)
  end

  defp skip_items(0, rest), do: rest
  defp skip_items(n, rest), do: skip_items(n - 1, skip_bytes(rest))

  defp skip_bytes(bin) do
    {len, rest} = CompactSize.decode(bin)

    case rest do
      <<_::binary-size(len), rest2::binary>> -> rest2
      _ -> throw({:codec_error, :truncated})
    end
  end

  @doc "Decodes a whole binary as exactly one transaction."
  def decode_exact(bin) do
    case decode(bin) do
      {tx, ""} -> {:ok, tx}
      {_tx, _} -> {:error, :trailing_data}
    end
  catch
    {:codec_error, reason} -> {:error, reason}
  end

  @doc """
  Serializes a transaction (Core `SerializeTransaction`). With `witness: true`
  the extended format is used when any input has a witness.
  """
  def encode(%__MODULE__{} = tx, opts \\ []) do
    witness? = Keyword.get(opts, :witness, true) and Enum.any?(tx.inputs, &(&1.witness != []))

    [
      <<tx.version::little-32>>,
      if(witness?, do: <<0, 1>>, else: []),
      CompactSize.encode(length(tx.inputs)),
      Enum.map(tx.inputs, &encode_input/1),
      CompactSize.encode(length(tx.outputs)),
      Enum.map(tx.outputs, &encode_output/1),
      if(witness?, do: Enum.map(tx.inputs, &encode_witness(&1.witness)), else: []),
      <<tx.locktime::little-32>>
    ]
  end

  defp encode_input(%In{} = i) do
    [
      i.prev_hash,
      <<i.prev_index::little-32>>,
      CompactSize.encode_bytes(i.script_sig),
      <<i.sequence::little-32>>
    ]
  end

  defp encode_output(%Out{} = o),
    do: [<<o.value::little-signed-64>>, CompactSize.encode_bytes(o.script_pubkey)]

  def encode_witness(stack),
    do: [CompactSize.encode(length(stack)), Enum.map(stack, &CompactSize.encode_bytes/1)]

  @doc "Coinbase test (Core `CTransaction::IsCoinBase`)."
  def coinbase?(%__MODULE__{inputs: [%In{prev_hash: <<0::256>>, prev_index: 0xFFFFFFFF}]}),
    do: true

  def coinbase?(_), do: false

  @doc "Serialized size without witness (Core `GetSerializeSize(TX_NO_WITNESS(tx))`)."
  def base_size(%__MODULE__{base_size: n}) when is_integer(n), do: n
  def base_size(%__MODULE__{has_witness: false, raw: raw}) when is_binary(raw), do: byte_size(raw)
  def base_size(tx), do: tx |> encode(witness: false) |> IO.iodata_length()

  def total_size(%__MODULE__{raw: raw}), do: byte_size(raw)

  # consensus/consensus.h: WITNESS_SCALE_FACTOR = 4
  @doc "Transaction weight (Core `GetTransactionWeight`)."
  def weight(tx), do: base_size(tx) * 3 + total_size(tx)
end
