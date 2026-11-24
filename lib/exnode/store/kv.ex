defmodule Exnode.Store.KV do
  @moduledoc """
  Thin wrapper over RocksDB (erlang-rocksdb). This module is the only place
  that calls `:rocksdb`.

  Column families hold the archive indexes: `txindex`, `spends`,
  `blocks`, `headers`, `meta`. RocksDB handles are safe to share across
  processes, so a `%KV{}` can be passed around freely.

  Writes go through `write/3`, a single atomic batch. A connected block
  commits its index entries, spends and status in one batch.
  """

  defstruct [:db, :cfs, :path]

  @type t :: %__MODULE__{}
  @type op ::
          {:put, atom(), binary(), binary()}
          | {:delete, atom(), binary()}
          | {:merge, atom(), binary(), binary()}
          | {:put_packed, atom(), pos_integer(), non_neg_integer() | :var, binary()}

  # poisoned: blocks quarantined after a validation crash (Chain.State).
  @default_cfs [
    :txindex,
    :spends,
    :blocks,
    :blockhash,
    :locs,
    :headers,
    :pending,
    :meta,
    :filters,
    :scripthash,
    :poisoned
  ]

  @default_max_open_files 512

  # RocksDB refuses a second open of a store this VM already holds ("lock
  # hold by current process"). A closed handle can hold it a moment longer:
  # erlang-rocksdb frees the database when its last reference goes, and a
  # native call still running on it (say, from a process that was killed)
  # holds one until it returns. So wait a little for such a handle to go
  # before failing; a store some live handle really holds still fails.
  @lock_wait_ms 5_000

  @doc "RocksDB's open table-file bound when `open/2` is given none."
  def default_max_open_files, do: @default_max_open_files

  @doc "Opens (creating if needed) the store at `path` with the given column families
  (`:max_open_files`: RocksDB's open table-file bound, default
  `default_max_open_files/0`; `:lock_wait_ms`: how long to wait for another
  handle in this VM to release the store, default 5 s)."
  @spec open(Path.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def open(path, opts \\ []) do
    names = Keyword.get(opts, :column_families, @default_cfs)
    create? = Keyword.get(opts, :create_if_missing, true)

    if not create? and not File.dir?(path) do
      {:error, :enoent}
    else
      if create?, do: File.mkdir_p!(path)

      {:ok, cache} =
        :rocksdb.new_cache(:lru, Keyword.get(opts, :block_cache_bytes, 256 * 1024 * 1024))

      # Table files RocksDB keeps open (its default, -1, keeps every SST open:
      # 920 descriptors on a mainnet store at 593k, past a 1,024 soft limit).
      # Bounded like Core's LevelDB max_open_files; the node sizes it from the
      # process's descriptor limit (Exnode.FdBudget).
      db_opts = [
        create_if_missing: create?,
        create_missing_column_families: create?,
        max_background_jobs: 4,
        bytes_per_sync: 1024 * 1024,
        max_open_files: Keyword.get(opts, :max_open_files, @default_max_open_files)
      ]

      cf_descs = [
        {~c"default", []} | Enum.map(names, &{Atom.to_charlist(&1), cf_options(&1, cache)})
      ]

      deadline =
        System.monotonic_time(:millisecond) + Keyword.get(opts, :lock_wait_ms, @lock_wait_ms)

      case open_db(String.to_charlist(path), db_opts, cf_descs, deadline) do
        {:ok, db, [_default | handles]} ->
          {:ok, %__MODULE__{db: db, cfs: Map.new(Enum.zip(names, handles)), path: path}}

        {:error, _} = err ->
          err
      end
    end
  end

  # Retries while this VM holds the store, until `deadline` (see @lock_wait_ms).
  defp open_db(path, db_opts, cf_descs, deadline) do
    case :rocksdb.open(path, db_opts, cf_descs) do
      {:error, {:db_open, msg}} = err ->
        if held_in_vm?(msg) and System.monotonic_time(:millisecond) < deadline do
          Process.sleep(20)
          open_db(path, db_opts, cf_descs, deadline)
        else
          err
        end

      other ->
        other
    end
  end

  defp held_in_vm?(msg), do: :string.find(msg, ~c"lock hold by current process") != :nomatch

  # Point lookups dominate (txindex: mostly misses, e.g. BIP30 checks and new
  # txids; blockhash; locs), so every family gets a bloom filter and a shared
  # block cache. `spends` keys are <<output_id::64, block_id::32>> and are
  # always read by seeking to an output id, so its filter is on the 8-byte
  # prefix. Settings only affect new SST files, so existing stores open as is.
  defp cf_options(cf, cache) do
    table = [
      block_cache: cache,
      bloom_filter_policy: 10,
      cache_index_and_filter_blocks: true,
      format_version: 5
    ]

    # LZ4 when the RocksDB build has it (liblz4-dev present at build time).
    # Compression is recorded per SST block, so stores written uncompressed
    # stay readable and are compressed as they compact.
    base = [
      block_based_table_options: table,
      write_buffer_size: 64 * 1024 * 1024,
      level_compaction_dynamic_level_bytes: true,
      compression: compression()
    ]

    case cf do
      :spends -> [prefix_extractor: {:fixed_prefix_transform, 8}] ++ base
      :pending -> pending_blob_options() ++ base
      # Per-script totals are updated by merges (`{:merge, ...}` ops of
      # `:erlang.term_to_binary({:int_add, n})` onto an integer term).
      :scripthash -> [merge_operator: :erlang_merge_operator] ++ base
      _ -> base
    end
  end

  # `pending` holds raw blocks from receipt until the commit that archives
  # them. Held past a memtable flush, each block used to be rewritten by
  # every compaction until its delete caught up: 29 GB of `pending` SST
  # output in 4 hours of mainnet IBD at ~625k, on a disk the prefetch reads
  # were waiting on. With blob files the block is written once at flush and
  # compactions move only the key and a blob reference. Blocks die in
  # roughly arrival order, so whole blob files become garbage and are
  # dropped; garbage collection relocates the few long-lived blocks
  # (quarantined, or held through a halt) so they don't pin a file.
  # Values under `min_blob_size` (tiny early blocks) stay inline. No
  # compression: block data compresses poorly and each block is read once.
  # Like every column-family option this applies to new files only; an
  # existing store's `pending` SSTs drain through normal compaction.
  @doc false
  def pending_blob_options do
    [
      enable_blob_files: true,
      min_blob_size: 4096,
      blob_file_size: 64 * 1024 * 1024,
      blob_compression_type: :none,
      enable_blob_garbage_collection: true,
      blob_garbage_collection_age_cutoff: 0.5
    ]
  end

  @doc "The compression used for new SST files: `:lz4` if this RocksDB build supports it, else `:none`."
  def compression do
    case :persistent_term.get({__MODULE__, :compression}, nil) do
      nil ->
        c = if lz4_supported?(), do: :lz4, else: :none
        :persistent_term.put({__MODULE__, :compression}, c)
        c

      c ->
        c
    end
  end

  # RocksDB refuses to open a column family with an unsupported compression,
  # so probe with a throwaway in-memory store.
  defp lz4_supported? do
    dir = Path.join(System.tmp_dir!(), "exnode-lz4-probe-#{System.unique_integer([:positive])}")

    try do
      case :rocksdb.open(String.to_charlist(dir), create_if_missing: true, compression: :lz4) do
        {:ok, db} ->
          :ok = :rocksdb.put(db, "k", :binary.copy("v", 4096), [])
          ok = :rocksdb.flush(db, []) == :ok
          :rocksdb.close(db)
          ok

        {:error, _} ->
          false
      end
    after
      File.rm_rf(dir)
    end
  end

  def close(%__MODULE__{db: db}) do
    :rocksdb.close(db)
  rescue
    # Already closed: erlang-rocksdb raises badarg for a closing handle.
    ArgumentError -> :ok
  end

  defmodule Error do
    @moduledoc """
    RocksDB could not read (an I/O error, corruption, a missing file): a
    fault of the host's storage, never an answer about the key.
    """
    defexception [:op, :cf, :reason]
    @impl true
    def message(%{op: op, cf: cf, reason: r}), do: "store #{op} on #{cf} failed: #{inspect(r)}"
  end

  @doc "Point lookup. A read error raises `Exnode.Store.KV.Error` (no caller can answer for it)."
  @spec get(t(), atom(), binary()) :: {:ok, binary()} | :not_found
  def get(%__MODULE__{db: db, cfs: cfs}, cf, key) do
    case :rocksdb.get(db, Map.fetch!(cfs, cf), key, []) do
      {:error, reason} -> raise Error, op: :get, cf: cf, reason: reason
      found -> found
    end
  end

  @doc "Batched lookup. Results are in key order: `{:ok, value} | :not_found`; a read error raises like `get/3`."
  @spec multi_get(t(), atom(), [binary()]) :: [{:ok, binary()} | :not_found]
  def multi_get(_kv, _cf, []), do: []

  def multi_get(%__MODULE__{db: db, cfs: cfs}, cf, keys) do
    found = :rocksdb.multi_get(db, Map.fetch!(cfs, cf), keys, [])

    case Enum.find(found, &match?({:error, _}, &1)) do
      {:error, reason} -> raise Error, op: :multi_get, cf: cf, reason: reason
      nil -> found
    end
  end

  @doc """
  Applies `ops` atomically as one write batch, in order. `{:put_packed, cf,
  key_size, value_size, bin}` is a run of puts to `cf` in one binary:
  `bin` is `key <> value` records with `key_size`-byte keys and
  `value_size`-byte values, or with `:var`, each value preceded by its
  32-bit big-endian length. It writes exactly what the same `{:put, ...}`
  ops in that order would (and counts as that many ops); only the caller's
  heap differs (one binary instead of one tuple and two binaries per put).
  `{:merge, cf, key, operand}` applies the family's merge operator (only
  `:scripthash` has one).
  `sort_packed: true` writes each column family that only `put_packed`
  ops of one shape touch as one key-ordered run (see `sort_packed/1`
  below); the store written is the same, the memtable inserts are faster.
  `sync: true` (the default)
  fsyncs the WAL before returning. `stats: true` adds this write to the
  calling process's counters (`take_stats/0`): native batch construction
  (`batch_put`/`batch_delete` calls) is timed apart from `write_batch`.
  """
  @spec write(t(), [op()], keyword()) :: :ok | {:error, term()}
  def write(%__MODULE__{db: db, cfs: cfs}, ops, opts \\ []) do
    stats = Keyword.get(opts, :stats, false)
    t0 = if stats, do: System.monotonic_time(:microsecond)
    ops = if Keyword.get(opts, :sort_packed, false), do: sort_packed(ops), else: ops
    {:ok, batch} = :rocksdb.batch()

    try do
      {n, bytes} =
        Enum.reduce(ops, {0, 0}, fn
          {:put, cf, k, v}, {n, b} ->
            :ok = :rocksdb.batch_put(batch, Map.fetch!(cfs, cf), k, v)
            {n + 1, b + byte_size(k) + byte_size(v)}

          {:delete, cf, k}, {n, b} ->
            :ok = :rocksdb.batch_delete(batch, Map.fetch!(cfs, cf), k)
            {n + 1, b + byte_size(k)}

          {:merge, cf, k, v}, {n, b} ->
            :ok = :rocksdb.batch_merge(batch, Map.fetch!(cfs, cf), k, v)
            {n + 1, b + byte_size(k) + byte_size(v)}

          {:put_packed, cf, ks, vs, bin}, {n, b} ->
            put_packed(batch, Map.fetch!(cfs, cf), ks, vs, bin, n, b)
        end)

      t1 = if stats, do: System.monotonic_time(:microsecond)
      result = :rocksdb.write_batch(db, batch, sync: Keyword.get(opts, :sync, true))

      if stats do
        t2 = System.monotonic_time(:microsecond)
        bump(:kv_writes, 1)
        bump(:kv_ops, n)
        bump(:kv_bytes, bytes)
        bump(:kv_build_us, t1 - t0)
        bump(:kv_write_us, t2 - t1)

        if t2 - t1 > (Process.get({__MODULE__, :stat, :kv_write_max_us}) || 0),
          do: Process.put({__MODULE__, :stat, :kv_write_max_us}, t2 - t1)
      end

      result
    after
      :rocksdb.release_batch(batch)
    end
  end

  # `sort_packed: true`: in each column family written only by
  # `put_packed` ops of one record shape, the runs are joined in order and
  # sorted by key (`Exnode.Store.PackedSort`, stable), so the memtable
  # takes them in key order. The store written is the same: within such a
  # family the last put of a key still wins, and families are independent,
  # so moving the run within the batch changes nothing. A family with any
  # other op, or runs of two shapes, is left as given.
  defp sort_packed(ops) do
    shapes =
      Enum.reduce(ops, %{}, fn
        {:put_packed, cf, ks, vs, _}, acc ->
          Map.update(acc, cf, {ks, vs}, &if(&1 == {ks, vs}, do: &1, else: :mixed))

        op, acc ->
          Map.put(acc, elem(op, 1), :mixed)
      end)

    sortable = for {cf, {_, _}} <- shapes, into: MapSet.new(), do: cf

    if MapSet.size(sortable) == 0 do
      ops
    else
      {runs, rest} =
        Enum.split_with(ops, &(elem(&1, 0) == :put_packed and elem(&1, 1) in sortable))

      sorted =
        runs
        |> Enum.group_by(&elem(&1, 1), &elem(&1, 4))
        |> Enum.sort()
        |> Enum.map(fn {cf, bins} ->
          {ks, vs} = Map.fetch!(shapes, cf)

          {:put_packed, cf, ks, vs,
           Exnode.Store.PackedSort.sort(IO.iodata_to_binary(bins), ks, vs)}
        end)

      sorted ++ rest
    end
  end

  defp put_packed(_batch, _cf, _ks, _vs, <<>>, n, b), do: {n, b}

  defp put_packed(batch, cf, ks, :var, bin, n, b) do
    <<k::binary-size(ks), len::32, v::binary-size(len), rest::binary>> = bin
    :ok = :rocksdb.batch_put(batch, cf, k, v)
    put_packed(batch, cf, ks, :var, rest, n + 1, b + ks + len)
  end

  defp put_packed(batch, cf, ks, vs, bin, n, b) do
    <<k::binary-size(ks), v::binary-size(vs), rest::binary>> = bin
    :ok = :rocksdb.batch_put(batch, cf, k, v)
    put_packed(batch, cf, ks, vs, rest, n + 1, b + ks + vs)
  end

  @doc """
  Takes (and resets) this process's counters of `write(..., stats: true)`:
  `kv_writes`, `kv_ops`, `kv_bytes` (keys and values), `kv_build_us`
  (native batch construction), `kv_write_us` (`write_batch`, the WAL fsync
  included with `sync: true`) and `kv_write_max_us` (the longest one; a
  maximum, not a sum).
  """
  def take_stats do
    Map.new(
      [:kv_writes, :kv_ops, :kv_bytes, :kv_build_us, :kv_write_us, :kv_write_max_us],
      fn k ->
        {k, Process.delete({__MODULE__, :stat, k}) || 0}
      end
    )
  end

  defp bump(k, n),
    do: Process.put({__MODULE__, :stat, k}, (Process.get({__MODULE__, :stat, k}) || 0) + n)

  @doc """
  An iterator over `cf` in total key order. Every iterator uses
  `total_order_seek`: with the `spends` prefix extractor, RocksDB's default
  prefix-seek mode measured ~5 ms per seek on a testnet4 store against
  ~5 µs in total order, with identical results (profile, 2026-11-03).
  Callers stop at the end of their prefix themselves.
  """
  def iterator(%__MODULE__{db: db, cfs: cfs}, cf) do
    case :rocksdb.iterator(db, Map.fetch!(cfs, cf), total_order_seek: true) do
      {:ok, it} -> it
      {:error, reason} -> raise Error, op: :iterator, cf: cf, reason: reason
    end
  end

  @doc "Runs `fun.(it)` with a total-order iterator over `cf`, always closing `it`."
  def with_iterator(%__MODULE__{} = kv, cf, fun) do
    it = iterator(kv, cf)

    try do
      fun.(it)
    after
      :rocksdb.iterator_close(it)
    end
  end

  @doc """
  Moves iterator `it` on `cf`. Returns `{:ok, key, value}` or `:end` when the
  iterator reaches the end; raises `Exnode.Store.KV.Error` on any other error
  tuple (note: upstream erlang-rocksdb 3.1.2 checks `itr->Valid()` before
  `itr->status()`, returning `:invalid_iterator` when an SST read invalidates
  the iterator).
  """
  def iter_move(it, cf, action) do
    case :rocksdb.iterator_move(it, action) do
      {:ok, k, v} -> {:ok, k, v}
      {:error, :invalid_iterator} -> :end
      {:error, reason} -> raise Error, op: :iterator_move, cf: cf, reason: reason
    end
  end

  @doc "Folds over `{key, value}` pairs in `cf` whose key starts with `prefix`, in key order."
  def fold_prefix(%__MODULE__{} = kv, cf, prefix, acc, fun) do
    with_iterator(kv, cf, fn it ->
      do_fold(it, cf, iter_move(it, cf, {:seek, prefix}), prefix, acc, fun)
    end)
  end

  @doc """
  Folds over the keys in `cf` that start with `prefix`, in key order,
  without reading values stored in blob files (`allow_unprepared_value`:
  the iterator leaves a blob value unread until asked, and this never
  asks). Inline values are read with their keys as usual.
  """
  def fold_keys(%__MODULE__{db: db, cfs: cfs}, cf, prefix, acc, fun) do
    it =
      case :rocksdb.iterator(db, Map.fetch!(cfs, cf),
             total_order_seek: true,
             allow_unprepared_value: true
           ) do
        {:ok, it} -> it
        {:error, reason} -> raise Error, op: :iterator, cf: cf, reason: reason
      end

    try do
      do_fold(it, cf, iter_move(it, cf, {:seek, prefix}), prefix, acc, fn {k, _v}, acc ->
        fun.(k, acc)
      end)
    after
      :rocksdb.iterator_close(it)
    end
  end

  @doc false
  # Flushes `cf`'s memtable to disk (tests: puts the data in SST and blob files).
  def flush(%__MODULE__{db: db, cfs: cfs}, cf),
    do: :rocksdb.flush(db, Map.fetch!(cfs, cf), wait: true)

  defp do_fold(it, cf, {:ok, k, v}, prefix, acc, fun) do
    if :binary.longest_common_prefix([k, prefix]) == byte_size(prefix),
      do: do_fold(it, cf, iter_move(it, cf, :next), prefix, fun.({k, v}, acc), fun),
      else: acc
  end

  defp do_fold(_it, _cf, :end, _prefix, acc, _fun), do: acc

  @doc """
  Folds over the `{key, value}` pairs in `cf` whose key starts with `prefix`,
  in reverse key order, starting below `before` (exclusive; nil: from the
  last key with `prefix`). `fun` returns `{:cont, acc}` or `{:halt, acc}`,
  so a page reads only the rows it uses.
  """
  def fold_prefix_reverse(%__MODULE__{} = kv, cf, prefix, before, acc, fun) do
    # Above every key with `prefix` (keys here are far shorter than this).
    target = before || prefix <> :binary.copy(<<0xFF>>, 256)

    with_iterator(kv, cf, fn it ->
      first =
        case iter_move(it, cf, {:seek_for_prev, target}) do
          {:ok, ^before, _} -> iter_move(it, cf, :prev)
          other -> other
        end

      do_fold_reverse(it, cf, first, prefix, acc, fun)
    end)
  end

  defp do_fold_reverse(it, cf, {:ok, k, v}, prefix, acc, fun) do
    if :binary.longest_common_prefix([k, prefix]) == byte_size(prefix) do
      case fun.({k, v}, acc) do
        {:cont, acc} -> do_fold_reverse(it, cf, iter_move(it, cf, :prev), prefix, acc, fun)
        {:halt, acc} -> acc
      end
    else
      acc
    end
  end

  defp do_fold_reverse(_it, _cf, :end, _prefix, acc, _fun), do: acc
end
