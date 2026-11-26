defmodule Exnode.Archive.Segments do
  @moduledoc """
  Append-only segment files for one record kind (`:outputs`, `:inputs`,
  `:witness`). Files are `<dir>/<kind>/NNNNN.seg`, each at most
  `@max_segment_bytes`. A block's records never span two segments: the
  writer rolls to a new segment only at block boundaries.

  Durability contract (with `Exnode.Archive`'s commit):
  1. A new segment file's directory entry is fsynced when the file is
     created (`roll/1`, and the first file in `open/3`), before any record is
     written to it, so no commit can reference a file whose name may be lost.
  2. `append_block/2` writes a block's records; `sync/1` fsyncs the data.
  3. The archive commits its synced KV batch (index, tip, segment ends) only
     after `sync/1`.
  4. Deleting a segment (`remove/2`, witness pruning) fsyncs the directory.

  Recovery: `truncate_to/2` is called at startup with the committed end of
  each kind. Bytes written after it (a torn tail) are discarded, as before.
  A committed segment that is missing, or shorter than its committed end,
  is corruption (lost directory entry, partial restore, deleted file): it
  raises instead of being recreated or zero-extended, so the node refuses to
  start rather than serve fabricated zero-value outputs. The operator must
  resync or restore; there is no automatic repair.

  The writer handle is a raw file owned by the calling process. Readers
  open their own handles (`open_reader/1`).
  """

  import Bitwise

  alias Exnode.StorageError
  alias Exnode.Store.Guard

  @max_segment_bytes 1 <<< 30

  defstruct [:dir, :kind, :seg, :offset, :fd, :guard, max: @max_segment_bytes]

  @doc """
  Opens the writer for `kind` under `root`.

  Options:
  * `:committed` — `{seg, offset}` for an existing archive; all live segments
    `min_seg..seg` are verified before any file or directory is created.
  * `:min_seg` — lowest expected live segment (default `0`; for `:witness`,
    `wpruned + 1`).
  * `:strict_clean` — when `true` (clean open with no `flush.lock`), requires
    exact segment size equality and no trailing segment files `> seg`.
  * `:guard` — optional `Exnode.Store.Guard` for fault latching.
  """
  def open(root, kind, opts \\ []) do
    guard = Keyword.get(opts, :guard)
    Guard.check!(guard)
    dir = Path.join(root, Atom.to_string(kind))
    min_seg = Keyword.get(opts, :min_seg, 0)
    strict? = Keyword.get(opts, :strict_clean, false)

    if c = opts[:committed], do: check_committed!(dir, kind, c, min_seg, strict?, guard)
    new_dir = not File.dir?(dir)
    File.mkdir_p!(dir)
    {seg, size} = last_segment(dir, guard)
    new_file = not File.exists?(path(dir, seg))

    fd =
      io_ok!(
        guard,
        {:open, kind, seg},
        :file.open(path(dir, seg), [:raw, :binary, :read, :write])
      )

    # First use: the new directory's entry (in its parent) and the first
    # segment's entry are made durable before anything is written.
    if new_dir, do: sync_dir(Path.dirname(dir), guard)
    if new_file, do: sync_dir(dir, guard)
    _ = io_ok!(guard, {:position, kind, seg}, :file.position(fd, :eof))

    %__MODULE__{
      dir: dir,
      kind: kind,
      seg: seg,
      offset: size,
      fd: fd,
      guard: guard,
      max: Keyword.get(opts, :max, @max_segment_bytes)
    }
  end

  def close(%__MODULE__{fd: fd}), do: :file.close(fd)

  defp path(dir, seg),
    do: Path.join(dir, String.pad_leading(Integer.to_string(seg), 5, "0") <> ".seg")

  defp last_segment(dir, guard) do
    entries = io_ok!(guard, {:ls, dir}, File.ls(dir))

    case entries
         |> Enum.filter(&String.ends_with?(&1, ".seg"))
         |> Enum.sort()
         |> List.last() do
      nil ->
        {0, 0}

      f ->
        stat = io_ok!(guard, {:stat, f}, File.stat(Path.join(dir, f)))
        {f |> Path.rootname() |> String.to_integer(), stat.size}
    end
  end

  @doc "Current end position `{segment, offset}`."
  def position(%__MODULE__{seg: s, offset: o}), do: {s, o}

  @doc """
  Position-independent layout of one block's `records` (a list of iodata)
  whose ids start at `base`: `{records, rel, total}`, `rel` the
  `{id, offset in the block}` of the ids that are multiples of `every`
  (newest first). Pure, so any process may compute it; `records` may be
  flattened to one binary before `append_layout/2`.
  """
  def layout(records, base, every) do
    {rel, total, _} =
      Enum.reduce(records, {[], 0, base}, fn r, {acc, off, id} ->
        acc = if rem(id, every) == 0, do: [{id, off} | acc], else: acc
        {acc, off + IO.iodata_length(r), id + 1}
      end)

    {records, rel, total}
  end

  @doc """
  Writes a `layout/3` result; returns `{segments, first, sparse}`, where
  `first` is the first record's `{seg, offset}` and `sparse` is
  `[{id, {seg, offset}}]` for the ids that are multiples of `every`, in order.
  """
  def append_layout(%__MODULE__{} = st, {records, rel, total}) do
    st = if st.offset > 0 and st.offset + total > st.max, do: roll(st), else: st
    %{seg: seg, offset: start} = st
    sparse = Enum.reduce(rel, [], fn {id, off}, acc -> [{id, {seg, start + off}} | acc] end)
    {write(st, records, total), {seg, start}, sparse}
  end

  @doc """
  Appends one block's `records` (a list of iodata). Returns
  `{segments, [{seg, offset}]}`, the location of each record, in order.
  """
  def append_block(%__MODULE__{} = st, records) do
    total = Enum.reduce(records, 0, &(&2 + IO.iodata_length(&1)))
    st = if st.offset > 0 and st.offset + total > st.max, do: roll(st), else: st

    {locs, _} =
      Enum.map_reduce(records, st.offset, fn r, off ->
        {{st.seg, off}, off + IO.iodata_length(r)}
      end)

    {write(st, records, total), locs}
  end

  defp write(st, records, total) do
    Guard.check!(st.guard)
    t0 = System.monotonic_time(:microsecond)
    io_ok!(st.guard, {:write, st.kind, st.seg}, :file.write(st.fd, records))
    bump(:seg_writes, 1)
    bump(:seg_write_bytes, total)
    bump(:seg_write_us, System.monotonic_time(:microsecond) - t0)
    %{st | offset: st.offset + total}
  end

  defp roll(st) do
    t0 = System.monotonic_time(:microsecond)
    st = do_roll(st)
    bump(:seg_rolls, 1)
    bump(:seg_roll_us, System.monotonic_time(:microsecond) - t0)
    st
  end

  defp do_roll(st) do
    Guard.check!(st.guard)
    seg = st.seg + 1
    # Locations store the segment number in 16 bits: one more would wrap.
    if seg > 0xFFFF do
      StorageError.raise_and_latch!(
        st.guard,
        :segments,
        {:segment_overflow, st.kind, st.seg},
        "archive #{st.kind} has no segment number left after #{st.seg}"
      )
    end

    io_ok!(st.guard, {:sync, st.kind, st.seg}, :file.sync(st.fd))
    io_ok!(st.guard, {:close, st.kind, st.seg}, :file.close(st.fd))

    fd =
      io_ok!(
        st.guard,
        {:open, st.kind, seg},
        :file.open(path(st.dir, seg), [:raw, :binary, :read, :write])
      )

    # The new file's directory entry is durable before any record is written
    # to it, so a later commit never references a file a power loss can drop.
    sync_dir(st.dir, st.guard)
    %{st | seg: seg, offset: 0, fd: fd}
  end

  # fsync of a directory (OTP 28 `:directory` mode; Linux fsyncs a read-only directory handle).
  # Failing is fatal: without it the archive's durability contract cannot hold.
  defp sync_dir(dir, guard) do
    Guard.sync_dir!(dir, guard)
  end

  def sync(%__MODULE__{fd: fd, guard: guard, kind: kind, seg: seg}) do
    Guard.check!(guard)
    io_ok!(guard, {:sync, kind, seg}, :file.sync(fd))
  end

  @doc """
  Deletes segment `seg` (witness pruning), closing this process's cached
  read handle for it. Never the segment being written.
  """
  def remove(%__MODULE__{dir: dir, seg: current, guard: guard}, seg) when seg < current do
    Guard.check!(guard)
    p = path(dir, seg)

    handles = handles()

    case Map.pop(handles, p) do
      {nil, _} ->
        :ok

      {{fd, _}, rest} ->
        :file.close(fd)
        Process.put({__MODULE__, :handles}, rest)
    end

    # Only an actual deletion needs its directory entry made durable (open/3
    # re-removes every already-pruned segment at each start).
    case File.rm(p) do
      :ok -> sync_dir(dir, guard)
      {:error, :enoent} -> :ok
      {:error, reason} -> io_ok!(guard, {:remove, p}, {:error, reason})
    end

    :ok
  end

  @doc """
  Deletes a pruned witness segment offline (during restore, when no writer is open).
  """
  def remove_offline!(root, kind, seg) do
    dir = Path.join(root, Atom.to_string(kind))
    p = path(dir, seg)

    case File.rm(p) do
      :ok -> Guard.sync_dir!(dir)
      {:error, :enoent} -> :ok
      {:error, reason} -> io_ok!(nil, {:remove, p}, {:error, reason})
    end
  end

  @doc """
  Crash recovery / restore: drops data written after the committed end
  `{seg, offset}`. Later segment files are deleted (with directory fsync) and
  the committed segment is truncated and fsynced. Raises if any live committed
  segment is missing or if `seg` is shorter than `offset`.
  """
  def truncate_to(%__MODULE__{} = st, {seg, offset}, min_seg \\ 0) do
    Guard.check!(st.guard)
    io_ok!(st.guard, {:close, st.kind, st.seg}, :file.close(st.fd))
    removed = remove_trailing_segments!(st.dir, seg, st.guard)
    if removed > 0, do: sync_dir(st.dir, st.guard)

    # Check before opening for write: opening would create a missing file,
    # and truncating past the end would zero-extend it.
    check_committed!(st.dir, st.kind, {seg, offset}, min_seg, false, st.guard)

    fd =
      io_ok!(
        st.guard,
        {:open, st.kind, seg},
        :file.open(path(st.dir, seg), [:raw, :binary, :read, :write])
      )

    _ = io_ok!(st.guard, {:position, st.kind, seg}, :file.position(fd, offset))
    io_ok!(st.guard, {:truncate, st.kind, seg}, :file.truncate(fd))
    io_ok!(st.guard, {:sync, st.kind, seg}, :file.sync(fd))
    %{st | seg: seg, offset: offset, fd: fd}
  end

  @doc """
  Offline verification and truncation of `<root>/<kind>` to `{seg, offset}`
  (used by `Exnode.Store.Snapshot.restore!/2` without opening a writer).
  """
  def verify_committed_dir!(root, kind, {seg, offset}, min_seg \\ 0) do
    dir = Path.join(root, Atom.to_string(kind))
    check_committed!(dir, kind, {seg, offset}, min_seg, false, nil)
  end

  @doc """
  Offline truncation of `<root>/<kind>` to `{seg, offset}` (used by snapshot
  restore): removes trailing segments > `seg` with dir fsync, truncates `seg`
  to `offset`, and fsyncs.
  """
  def truncate_dir!(root, kind, {seg, offset}, min_seg \\ 0) do
    dir = Path.join(root, Atom.to_string(kind))
    check_committed!(dir, kind, {seg, offset}, min_seg, false, nil)
    removed = remove_trailing_segments!(dir, seg, nil)
    if removed > 0, do: Guard.sync_dir!(dir)

    fd = io_ok!(nil, {:open, kind, seg}, :file.open(path(dir, seg), [:raw, :binary, :read, :write]))

    try do
      _ = io_ok!(nil, {:position, kind, seg}, :file.position(fd, offset))
      io_ok!(nil, {:truncate, kind, seg}, :file.truncate(fd))
      io_ok!(nil, {:sync, kind, seg}, :file.sync(fd))
    after
      :file.close(fd)
    end

    :ok
  end

  defp remove_trailing_segments!(dir, seg, guard) do
    entries = io_ok!(guard, {:ls, dir}, File.ls(dir))

    trailing =
      for f <- entries,
          String.ends_with?(f, ".seg"),
          n = f |> Path.rootname() |> String.to_integer(),
          n > seg,
          do: f

    for f <- trailing do
      io_ok!(guard, {:remove, f}, File.rm(Path.join(dir, f)))
    end

    length(trailing)
  end

  defp check_committed!(dir, kind, {seg, offset}, min_seg, strict?, guard) do
    # Verify every live intermediate segment exists and is non-empty.
    for s <- min_seg..(seg - 1)//1 do
      case File.stat(path(dir, s)) do
        {:error, :enoent} ->
          StorageError.raise_and_latch!(
            guard,
            :segments,
            {:missing_segment, kind, s},
            "archive #{kind} segment #{s} missing but committed state references up to #{seg}: " <>
              "the archive is corrupt; restore or resync required"
          )

        {:error, reason} ->
          io_ok!(guard, {:stat, kind, s}, {:error, reason})

        {:ok, %{size: 0}} ->
          StorageError.raise_and_latch!(
            guard,
            :segments,
            {:empty_segment, kind, s},
            "archive #{kind} segment #{s} is empty but committed state references up to #{seg}: " <>
              "the archive is corrupt; restore or resync required"
          )

        {:ok, _} ->
          :ok
      end
    end

    # Verify the final committed segment.
    case File.stat(path(dir, seg)) do
      {:error, :enoent} ->
        StorageError.raise_and_latch!(
          guard,
          :segments,
          {:missing_segment, kind, seg},
          "archive #{kind} segment #{seg} missing but committed state references it: " <>
            "the archive is corrupt; resync required"
        )

      {:error, reason} ->
        io_ok!(guard, {:stat, kind, seg}, {:error, reason})

      {:ok, %{size: size}} when size < offset ->
        StorageError.raise_and_latch!(
          guard,
          :segments,
          {:short_segment, kind, seg, size, offset},
          "archive #{kind} segment #{seg} is shorter than the committed end (#{size} < #{offset}): " <>
            "the archive is corrupt; resync required"
        )

      {:ok, %{size: size}} when strict? and size > offset ->
        StorageError.raise_and_latch!(
          guard,
          :segments,
          {:trailing_bytes_on_clean_open, kind, seg, size, offset},
          "archive #{kind} segment #{seg} has unexpected trailing bytes on clean open (#{size} > #{offset}): " <>
            "store does not match committed metadata; restore or resync required"
        )

      {:ok, _} ->
        :ok
    end

    if strict? do
      entries = io_ok!(guard, {:ls, dir}, File.ls(dir))

      extra =
        for f <- entries,
            String.ends_with?(f, ".seg"),
            n = f |> Path.rootname() |> String.to_integer(),
            n > seg,
            do: n

      if extra != [] do
        StorageError.raise_and_latch!(
          guard,
          :segments,
          {:trailing_segments_on_clean_open, kind, extra, seg},
          "archive #{kind} has unexpected segment(s) #{inspect(extra)} past committed #{seg} on clean open"
        )
      end
    end

    :ok
  end

  defp io_ok!(_guard, _ctx, :ok), do: :ok
  defp io_ok!(_guard, _ctx, {:ok, val}), do: val

  defp io_ok!(guard, ctx, err) do
    StorageError.raise_and_latch!(
      guard,
      :segments,
      {:io_error, ctx, err},
      "archive segment I/O failed (#{inspect(ctx)}): #{inspect(err)}"
    )
  end

  # --- reading -----------------------------------------------------------------

  defmodule Reader do
    @moduledoc false
    defstruct [:dir, :guard, :wpruned_live]
  end

  def open_reader(%__MODULE__{dir: dir, guard: guard}),
    do: %Reader{dir: dir, guard: guard}

  def open_reader(root, kind, guard \\ nil, wpruned_live \\ nil),
    do: %Reader{
      dir: Path.join(root, Atom.to_string(kind)),
      guard: guard,
      wpruned_live: wpruned_live
    }

  @doc """
  Reads at `{seg, offset}`, skips `n` records and returns the next one. Used
  with the sparse index (n < 64). A run of records may continue in the next
  segment (see `read_run/6`).
  """
  def read_nth(%Reader{} = r, loc, n, decode, chunk \\ 4096) do
    [rec] = read_run(r, loc, n, 1, decode, chunk)
    rec
  end

  @doc """
  Skips `skip` records at `{seg, offset}`, then reads `count` consecutive
  records and returns them as a list.

  Ids are contiguous across segments, but a segment only rolls at a block
  boundary. A sparse-index group (64 ids) can therefore span two segments.
  When a read consumes a segment exactly to its end, it continues at offset 0
  of the next segment.
  """
  def read_run(%Reader{guard: guard} = r, {seg, offset}, skip, count, decode, chunk \\ 65_536) do
    Guard.check!(guard)
    fd = fd(r, seg)
    bump(:preads, 1)
    bump(:pread_bytes, chunk)

    data =
      case :file.pread(fd, offset, chunk) do
        {:ok, d} -> d
        :eof -> <<>>
        {:error, reason} -> io_ok!(guard, {:pread, r.dir, seg, offset}, {:error, reason})
      end

    eof = byte_size(data) < chunk

    case take(data, skip, count, decode, [], guard) do
      {:ok, recs} ->
        recs

      {:more, skip_left, count_left, acc, rest} when eof and rest == <<>> ->
        # The segment ended exactly on a record boundary: continue in the next one.
        more = read_run(r, {seg + 1, 0}, skip_left, count_left, decode)
        Enum.reverse(acc) ++ more

      {:more, _, _, _, _} when eof ->
        StorageError.raise_and_latch!(
          guard,
          :segments,
          {:truncated_segment, seg, offset},
          "archive segment truncated at #{seg}:#{offset}"
        )

      {:more, _, _, _, _} ->
        read_run(r, {seg, offset}, skip, count, decode, chunk * 4)
    end
  end

  defp take(_data, 0, 0, _decode, acc, _guard), do: {:ok, Enum.reverse(acc)}

  defp take(data, skip, count, decode, acc, guard) do
    case decode.(data) do
      :more -> {:more, skip, count, acc, data}
      {_rec, rest} when skip > 0 -> take(rest, skip - 1, count, decode, acc, guard)
      {rec, rest} -> take(rest, 0, count - 1, decode, [rec | acc], guard)
    end
  rescue
    e in Exnode.StorageError ->
      Guard.latch_fault(guard, e.source || :archive, e.reason, Exception.message(e))
      reraise e, __STACKTRACE__
  end

  @doc """
  Takes (and resets) this process's counters: `preads` (positional
  reads issued by `read_run/6`, retries and next-segment continuations
  included) and `pread_bytes` (bytes requested); the writer's
  `seg_writes`, `seg_write_bytes`, `seg_write_us` (`append_block/2`'s
  write call, page cache: not device time) and `seg_rolls`, `seg_roll_us`
  (rollover: the old segment's fsync, the new file and its directory
  fsync); `read_opens` (read handles opened: cache misses of `fd/2`).
  """
  def take_stats do
    Map.new(
      [
        :preads,
        :pread_bytes,
        :seg_writes,
        :seg_write_bytes,
        :seg_write_us,
        :seg_rolls,
        :seg_roll_us,
        :read_opens
      ],
      fn k ->
        {k, Process.delete({__MODULE__, :stat, k}) || 0}
      end
    )
  end

  defp bump(key, n),
    do: Process.put({__MODULE__, :stat, key}, (Process.get({__MODULE__, :stat, key}) || 0) + n)

  @read_handles 16

  @doc """
  Read handles one process keeps open (least recently used closed first).
  Each long-lived reader holds at most this many descriptors, whatever the
  number of segments; the node's descriptor budget counts on it
  (`Exnode.FdBudget`). A miss costs one `open`.
  """
  def read_handles, do: @read_handles

  @doc """
  Lowers this process's read-handle cap to `n` (closing the oldest handles
  beyond it). RPC and REST connection handlers use it: each is a reader,
  their number is bounded only by the API connection cap, and the
  descriptor budget counts `Exnode.FdBudget.api_read_handles/0` for each.
  """
  def limit_read_handles(n) when is_integer(n) and n > 0 do
    Process.put({__MODULE__, :cap}, n)
    Process.put({__MODULE__, :handles}, shrink(handles(), n))
    :ok
  end

  defp cap, do: Process.get({__MODULE__, :cap}) || @read_handles

  defp shrink(handles, n) when map_size(handles) > n, do: shrink(evict_oldest(handles), n)
  defp shrink(handles, _n), do: handles

  # Raw read handles belong to the process that opened them, so they are
  # cached in that process's dictionary: path => {fd, last use}, at most
  # @read_handles of them.
  defp fd(%Reader{guard: guard} = r, seg) do
    p = path(r.dir, seg)
    handles = handles()
    tick = (Process.get({__MODULE__, :tick}) || 0) + 1
    Process.put({__MODULE__, :tick}, tick)

    case handles do
      %{^p => {fd, _}} ->
        Process.put({__MODULE__, :handles}, %{handles | p => {fd, tick}})
        fd

      _ ->
        handles = shrink(handles, cap() - 1)

        fd =
          case :file.open(p, [:raw, :binary, :read]) do
            {:ok, fd} ->
              fd

            {:error, :enoent}
            when r.wpruned_live != nil ->
              if seg <= :atomics.get(r.wpruned_live, 1) do
                raise Exnode.StorageError,
                  source: :segments,
                  reason: {:witness_pruned, seg},
                  message: "witness segment #{seg} was pruned"
              else
                io_ok!(guard, {:open_read, p}, {:error, :enoent})
              end

            err ->
              io_ok!(guard, {:open_read, p}, err)
          end

        bump(:read_opens, 1)
        Process.put({__MODULE__, :handles}, Map.put(handles, p, {fd, tick}))
        fd
    end
  end

  defp handles, do: Process.get({__MODULE__, :handles}) || %{}

  defp evict_oldest(handles) do
    {p, {fd, _}} = Enum.min_by(handles, fn {_, {_, t}} -> t end)
    :file.close(fd)
    Map.delete(handles, p)
  end

  @doc "Closes this process's cached read handles under the reader's directory."
  def close_reader(%Reader{dir: dir}) do
    {close, keep} = Map.split_with(handles(), fn {p, _} -> String.starts_with?(p, dir) end)
    for {_, {fd, _}} <- close, do: :file.close(fd)
    Process.put({__MODULE__, :handles}, keep)
    :ok
  end

  @doc false
  # This process's open read handles (tests).
  def open_read_handles, do: map_size(handles())
end
