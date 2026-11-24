defmodule Exnode.Archive.Codec do
  @moduledoc """
  On-disk wire encoders and decoders for archive segment records (outputs,
  inputs, witnesses), sparse-index location keys and packed `{seg, offset}`
  pointers, and `txindex` occurrence lists.

  Segment decoders return `{record, rest}` or `:more` when the buffer ends
  mid-record; non-canonical or oversize lengths raise `Exnode.StorageError`
  immediately via `guard/1`.
  """

  alias Exnode.Codec.{CompactSize, Tx}

  # --- segment record encoders -------------------------------------------------

  def encode_output(%Tx.Out{value: value, script_pubkey: spk}),
    do: [<<value::little-signed-64>>, CompactSize.encode_bytes(spk)]

  def encode_input(%Tx.In{} = i) do
    [
      i.prev_hash,
      <<i.prev_index::little-32>>,
      CompactSize.encode_bytes(i.script_sig),
      <<i.sequence::little-32>>
    ]
  end

  def encode_witness(witness), do: Tx.encode_witness(witness)

  # --- segment record decoders (return :more on truncation) --------------------

  def decode_output(<<v::little-signed-64, rest::binary>>),
    do: guard(fn -> cs_bytes(rest, &{v, &1}) end)

  def decode_output(_), do: :more

  def decode_input(<<ph::binary-size(32), pi::little-32, rest::binary>>) do
    guard(fn ->
      {ss, rest} = CompactSize.decode_bytes(rest)

      case rest do
        <<seq::little-32, r::binary>> -> {{ph, pi, ss, seq}, r}
        _ -> :more
      end
    end)
  end

  def decode_input(_), do: :more

  # The record with its exact bytes (the wire encoding, used for the
  # stripped txid by Query.read_index_facts/3): {prev_hash, prev_index, raw}
  # and {value, script_pubkey, raw}. Same strict decoding as above.
  def decode_input_raw(bin) do
    case decode_input(bin) do
      {{ph, pi, _ss, _seq}, rest} ->
        {{ph, pi, binary_part(bin, 0, byte_size(bin) - byte_size(rest))}, rest}

      :more ->
        :more
    end
  end

  def decode_output_raw(bin) do
    case decode_output(bin) do
      {{v, spk}, rest} -> {{v, spk, binary_part(bin, 0, byte_size(bin) - byte_size(rest))}, rest}
      :more -> :more
    end
  end

  def decode_witness(bin) do
    guard(fn ->
      {n, rest} = CompactSize.decode(bin)
      take_items(n, rest, [])
    end)
  end

  defp take_items(0, rest, acc), do: {Enum.reverse(acc), rest}

  defp take_items(n, bin, acc) do
    {item, rest} = CompactSize.decode_bytes(bin)
    take_items(n - 1, rest, [item | acc])
  end

  defp cs_bytes(bin, f) do
    {b, rest} = CompactSize.decode_bytes(bin)
    {f.(b), rest}
  end

  # Only truncation means "read more": a corrupt length (non-canonical or
  # above MAX_SIZE) raises at once instead of growing the read to the
  # segment's end.
  def guard(f) do
    f.()
  catch
    {:codec_error, :truncated} ->
      :more

    {:codec_error, reason} ->
      raise Exnode.StorageError,
        source: :archive,
        reason: {:corrupt_record, reason},
        message: "corrupt archive record (#{reason})"
  end

  # --- txindex entries ---------------------------------------------------------

  # txindex value: one 22-byte entry per occurrence of the txid,
  # <<block_id::32, pos::24, nout::24, base_out::48, base_in::48>>. Archives
  # in the first format stored an Erlang term, which starts with byte 131; a
  # binary entry starts with the block id's top byte, which is 131 only from
  # block id 131 * 2^24 (2.2 billion), so both formats are read.
  def encode_txindex(list),
    do: for({b, pos, o, n, i} <- list, into: <<>>, do: <<b::32, pos::24, n::24, o::48, i::48>>)

  def decode_txindex(<<131, _::binary>> = bin), do: :erlang.binary_to_term(bin)

  def decode_txindex(bin),
    do: for(<<b::32, pos::24, n::24, o::48, i::48 <- bin>>, do: {b, pos, o, n, i})

  # --- sparse location keys & pointers -----------------------------------------

  def loc_key(:outputs, n), do: <<0, n::64>>
  def loc_key(:inputs, n), do: <<1, n::64>>
  def loc_key(:witness, n), do: <<2, n::64>>

  def pack_loc({seg, off}), do: <<seg::16, off::48>>
  def unpack_loc(<<seg::16, off::48>>), do: {seg, off}
end
