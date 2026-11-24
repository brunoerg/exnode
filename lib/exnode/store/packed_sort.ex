defmodule Exnode.Store.PackedSort do
  @moduledoc """
  Orders a packed run of KV records by key and frames packed runs directly
  into RocksDB `WriteBatch` wire format (`native/sort_nif`), for
  `Exnode.Store.KV.write/3`.

  The layout is `{:put_packed, ...}`'s (`Exnode.Store.KV`): `key <> value`
  records with `key_size`-byte keys and `value_size`-byte values, or with
  `:var`, each value preceded by its 32-bit big-endian length. Keys compare
  bytewise, as RocksDB's default comparator. The sort is stable: records
  with equal keys keep their order, so writing the sorted run gives the same
  store as writing the input run (the last put of a key wins either way).

  Why: a commit's rows go into RocksDB's memtable skiplist, and random key
  order costs a cache miss per level per insert. Framing directly into
  `WriteBatch` records in C also avoids millions of per-record `batch_put`
  NIF calls and `enif_make_copy` allocations on the calling scheduler.
  """
  @on_load :load_nif

  @doc false
  def load_nif do
    path = :filename.join(:code.priv_dir(:exnode), ~c"native/sort_nif")
    :erlang.load_nif(path, 0)
  end

  @doc "`bin`'s records ordered by key (stable). Raises on a cut-short record."
  def sort(bin, key_size, 0)
      when is_binary(bin) and is_integer(key_size) and key_size > 0 do
    if rem(byte_size(bin), key_size) != 0, do: raise(ArgumentError, "truncated packed keys")
    if byte_size(bin) < 2 * key_size, do: bin, else: sort_keys(bin, key_size, [])
  end

  def sort(bin, key_size, value_size)
      when is_binary(bin) and is_integer(key_size) and key_size > 0 do
    vs =
      case value_size do
        :var -> 0
        n when is_integer(n) and n > 0 -> n
      end

    sort_nif(bin, key_size, vs)
  end

  @doc """
  Frames `bins` (a packed binary or a list of packed binaries) as RocksDB
  `WriteBatch` put records for column family `cf_id`, optionally sorting
  stably by key in the same pass. Returns `{:ok, wb_records_bin, count,
  kv_bytes}` or `:truncated` if any record is cut short.
  """
  def encode_write_batch(cf_id, key_size, value_size, bins, sort? \\ false)
      when is_integer(cf_id) and cf_id >= 0 and is_integer(key_size) and key_size > 0 do
    {vs, var_bit} =
      case value_size do
        :var -> {0, 2}
        n when is_integer(n) and n >= 0 -> {n, 0}
      end

    flags = Bitwise.bor(if(sort?, do: 1, else: 0), var_bit)
    encode_wb_nif(cf_id, key_size, vs, bins, flags)
  end

  defp sort_keys(<<>>, _ks, acc),
    do: acc |> Enum.reverse() |> Enum.sort() |> IO.iodata_to_binary()

  defp sort_keys(bin, ks, acc) do
    <<k::binary-size(ks), rest::binary>> = bin
    sort_keys(rest, ks, [k | acc])
  end

  defp sort_nif(_bin, _ks, _vs), do: :erlang.nif_error(:nif_not_loaded)
  defp encode_wb_nif(_cf_id, _ks, _vs, _bins, _sort), do: :erlang.nif_error(:nif_not_loaded)
end
