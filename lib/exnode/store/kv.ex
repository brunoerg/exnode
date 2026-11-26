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

  defstruct [:db, :cfs, :cf_ids, :path]

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

      bg_jobs =
        Keyword.get(opts, :max_background_jobs, max(4, min(System.schedulers_online(), 8)))

      # Table files RocksDB keeps open (its default, -1, keeps every SST open:
      # 920 descriptors on a mainnet store at 593k, past a 1,024 soft limit).
      # Bounded like Core's LevelDB max_open_files; the node sizes it from the
      # process's descriptor limit (Exnode.FdBudget).
      db_opts = [
        create_if_missing: create?,
        create_missing_column_families: create?,
        max_background_jobs: bg_jobs,
        max_subcompactions: Keyword.get(opts, :max_subcompactions, 2),
        compaction_readahead_size: 2 * 1024 * 1024,
        enable_pipelined_write: true,
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
          {:ok,
           %__MODULE__{
             db: db,
             cfs: Map.new(Enum.zip(names, handles)),
             cf_ids: discover_cf_ids(names, handles),
             path: path
           }}

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

  # Probes each handle's internal 32-bit RocksDB column-family ID in memory
  # (zero DB writes) so `write/3` can frame `WriteBatch` binaries directly.
  defp discover_cf_ids(names, handles) do
    {:ok, batch} = :rocksdb.batch()

    try do
      names
      |> Enum.with_index()
      |> Enum.zip(handles)
      |> Enum.each(fn {{_name, idx}, handle} ->
        :ok = :rocksdb.batch_put(batch, handle, <<idx::32>>, <<>>)
      end)

      ids_by_idx =
        Map.new(:rocksdb.batch_tolist(batch), fn
          {:put, cf_id, <<idx::32>>, <<>>} -> {idx, cf_id}
          {:put, <<idx::32>>, <<>>} -> {idx, 0}
        end)

      names
      |> Enum.with_index()
      |> Map.new(fn {name, idx} -> {name, Map.fetch!(ids_by_idx, idx)} end)
    after
      :rocksdb.release_batch(batch)
    end
  end

  # Point and batched lookups dominate (`txindex` and `spends`: mostly misses;
  # `blockhash`, `headers`, `filters`, `poisoned`), so those families get
  # whole-key bloom filters and interpolation-capable index search in the
  # shared block cache. Hit-mostly families (`blockhash`, `headers`, `filters`)
  # set `optimize_filters_for_hits` to skip bottommost-level filters (~90% of
  # filter size). Dense/hit-only families (`blocks`, `locs`, `pending`) and
  # prefix-scanned `scripthash` (whole-key bloom is ignored on `Seek` without
  # a prefix extractor) omit bloom filters to keep filter memory for `txindex`
  # and `spends`. Settings only affect new SST files, so existing stores open
  # as is.
  defp cf_options(cf, cache) do
    bloom =
      if cf in [:blocks, :locs, :pending, :scripthash],
        do: [],
        else: [bloom_filter_policy: 10]

    table =
      bloom ++
        [
          block_cache: cache,
          cache_index_and_filter_blocks: true,
          index_block_search_type: :auto,
          format_version: 5
        ]

    {wb_size, max_wb} =
      cond do
        cf in [:txindex, :spends, :pending, :scripthash] -> {64 * 1024 * 1024, 4}
        cf in [:meta, :poisoned] -> {4 * 1024 * 1024, 2}
        true -> {16 * 1024 * 1024, 2}
      end

    hit_opts =
      if cf in [:blockhash, :headers, :filters],
        do: [optimize_filters_for_hits: true],
        else: []

    # LZ4 when the RocksDB build has it (liblz4-dev present at build time).
    # Compression is recorded per SST block, so stores written uncompressed
    # stay readable and are compressed as they compact.
    base =
      hit_opts ++
        [
          block_based_table_options: table,
          write_buffer_size: wb_size,
          max_write_buffer_number: max_wb,
          memtable_batch_lookup_optimization: true,
          level_compaction_dynamic_level_bytes: true,
          compression: compression()
        ]

    case cf do
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
  #
  # RocksDB selects the oldest `floor(age_cutoff * n_blob_files)` files for
  # both passive relocation during compaction and forced GC. An `age_cutoff`
  # of `0.5` relocated live blocks in the older half of the download queue
  # on every compaction (~2.3 TB of blob writes and ~1.6 TB of reads over a
  # full mainnet IBD), while `0.0` would disable GC entirely (`cutoff == 0`).
  # At `0.1` with `force_threshold: 0.85`, normal in-flight queues (< 10
  # blob files) never rewrite live blocks and drop dead files for free,
  # while old files pinned past that window are compacted once >= 85% dead.
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
      blob_garbage_collection_age_cutoff: 0.1,
      blob_garbage_collection_force_threshold: 0.85
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
    found = :rocksdb.multi_get(db, Map.fetch!(cfs, cf), keys, async_io: true)

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
  def write(%__MODULE__{db: db, cf_ids: cf_ids}, ops, opts \\ []) do
    stats = Keyword.get(opts, :stats, false)
    t0 = if stats, do: System.monotonic_time(:microsecond)

    {wb, n, bytes} =
      encode_write_batch(ops, cf_ids, Keyword.get(opts, :sort_packed, false))

    t1 = if stats, do: System.monotonic_time(:microsecond)
    result = :rocksdb.write_binary_update(db, wb, sync: Keyword.get(opts, :sync, true))

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
  end

  # Encodes `ops` directly into RocksDB's `WriteBatch` wire format
  # (`<<seq::little-64, count::little-32, records::binary>>`).
  #
  # With `sort_packed?: true`, in each column family written only by
  # `put_packed` ops of one record shape, the runs are sorted stably by key
  # and framed into `WriteBatch` records in one native pass
  # (`Exnode.Store.PackedSort.encode_write_batch/5`), so the memtable takes
  # them in key order without intermediate binary concatenation or per-record
  # NIF calls. A family with any other op, or runs of two shapes, is encoded
  # in the exact order given.
  defp encode_write_batch(ops, cf_ids, false) do
    {chunks, n, bytes} = encode_ops_seq(ops, cf_ids, [], 0, 0)
    {IO.iodata_to_binary([<<0::little-64, n::little-32>> | Enum.reverse(chunks)]), n, bytes}
  end

  defp encode_write_batch(ops, cf_ids, true) do
    shapes =
      Enum.reduce(ops, %{}, fn
        {:put_packed, cf, ks, vs, _}, acc ->
          Map.update(acc, cf, {ks, vs}, &if(&1 == {ks, vs}, do: &1, else: :mixed))

        op, acc ->
          Map.put(acc, elem(op, 1), :mixed)
      end)

    sortable = for {cf, {_, _}} <- shapes, into: MapSet.new(), do: cf

    if MapSet.size(sortable) == 0 do
      encode_write_batch(ops, cf_ids, false)
    else
      {runs, rest} =
        Enum.split_with(ops, &(elem(&1, 0) == :put_packed and elem(&1, 1) in sortable))

      {chunks, n, bytes} =
        runs
        |> Enum.group_by(&elem(&1, 1), &elem(&1, 4))
        |> Enum.sort()
        |> Enum.reduce({[], 0, 0}, fn {cf, bins}, {acc, n, b} ->
          {ks, vs} = Map.fetch!(shapes, cf)
          cf_id = Map.fetch!(cf_ids, cf)

          {:ok, chunk, cnt, kv_b} =
            Exnode.Store.PackedSort.encode_write_batch(cf_id, ks, vs, bins, true)

          {[chunk | acc], n + cnt, b + kv_b}
        end)

      {chunks, n, bytes} = encode_ops_seq(rest, cf_ids, chunks, n, bytes)
      {IO.iodata_to_binary([<<0::little-64, n::little-32>> | Enum.reverse(chunks)]), n, bytes}
    end
  end

  defp encode_ops_seq([], _cf_ids, chunks, n, bytes), do: {chunks, n, bytes}

  defp encode_ops_seq([{:put, cf, k, v} | rest], cf_ids, chunks, n, bytes)
       when is_binary(k) and is_binary(v) do
    chunk = encode_wb_kv(Map.fetch!(cf_ids, cf), 0x01, 0x05, k, v)
    encode_ops_seq(rest, cf_ids, [chunk | chunks], n + 1, bytes + byte_size(k) + byte_size(v))
  end

  defp encode_ops_seq([{:delete, cf, k} | rest], cf_ids, chunks, n, bytes)
       when is_binary(k) do
    chunk = encode_wb_k(Map.fetch!(cf_ids, cf), 0x00, 0x04, k)
    encode_ops_seq(rest, cf_ids, [chunk | chunks], n + 1, bytes + byte_size(k))
  end

  defp encode_ops_seq([{:merge, cf, k, v} | rest], cf_ids, chunks, n, bytes)
       when is_binary(k) and is_binary(v) do
    chunk = encode_wb_kv(Map.fetch!(cf_ids, cf), 0x02, 0x06, k, v)
    encode_ops_seq(rest, cf_ids, [chunk | chunks], n + 1, bytes + byte_size(k) + byte_size(v))
  end

  defp encode_ops_seq([{:put_packed, cf, ks, vs, bin} | rest], cf_ids, chunks, n, bytes) do
    cf_id = Map.fetch!(cf_ids, cf)

    {:ok, chunk, cnt, kv_b} =
      Exnode.Store.PackedSort.encode_write_batch(cf_id, ks, vs, bin, false)

    encode_ops_seq(rest, cf_ids, [chunk | chunks], n + cnt, bytes + kv_b)
  end

  defp encode_wb_kv(0, tag0, _tag_cf, k, v),
    do: [tag0, varint32(byte_size(k)), k, varint32(byte_size(v)), v]

  defp encode_wb_kv(cf_id, _tag0, tag_cf, k, v),
    do: [tag_cf, varint32(cf_id), varint32(byte_size(k)), k, varint32(byte_size(v)), v]

  defp encode_wb_k(0, tag0, _tag_cf, k),
    do: [tag0, varint32(byte_size(k)), k]

  defp encode_wb_k(cf_id, _tag0, tag_cf, k),
    do: [tag_cf, varint32(cf_id), varint32(byte_size(k)), k]

  defp varint32(v) when v < 128, do: <<v>>

  defp varint32(v),
    do: <<Bitwise.bor(Bitwise.band(v, 0x7F), 0x80), varint32(Bitwise.bsr(v, 7))::binary>>

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
  An iterator over `cf` bounded to the sought key's prefix (`prefix_same_as_start:
  true`), allowing RocksDB to consult prefix bloom filters when `cf` configures
  a `prefix_extractor`.
  """
  def prefix_iterator(%__MODULE__{db: db, cfs: cfs}, cf) do
    case :rocksdb.iterator(db, Map.fetch!(cfs, cf), prefix_same_as_start: true) do
      {:ok, it} -> it
      {:error, reason} -> raise Error, op: :iterator, cf: cf, reason: reason
    end
  end

  @doc "Runs `fun.(it)` with a prefix-bounded iterator over `cf`, always closing `it`."
  def with_prefix_iterator(%__MODULE__{} = kv, cf, fun) do
    it = prefix_iterator(kv, cf)

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
