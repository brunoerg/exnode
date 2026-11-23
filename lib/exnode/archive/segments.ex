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

  @max_segment_bytes 1 <<< 30

  defstruct [:dir, :kind, :seg, :offset, :fd, max: @max_segment_bytes]

  @doc """
  Opens the writer for `kind` under `root`. With `committed: {seg, offset}`
  (an existing archive), the committed segment is checked first, before
  any file or directory is created (see `truncate_to/2`).
  """
  def open(root, kind, opts \\ []) do
    dir = Path.join(root, Atom.to_string(kind))
    if c = opts[:committed], do: check_committed!(dir, kind, c)
    new_dir = not File.dir?(dir)
    File.mkdir_p!(dir)
    {seg, size} = last_segment(dir)
    new_file = not File.exists?(path(dir, seg))
    {:ok, fd} = :file.open(path(dir, seg), [:raw, :binary, :read, :write])
    # First use: the new directory's entry (in its parent) and the first
    # segment's entry are made durable before anything is written.
    if new_dir, do: sync_dir(Path.dirname(dir))
    if new_file, do: sync_dir(dir)
    {:ok, _} = :file.position(fd, :eof)

    %__MODULE__{
      dir: dir,
      kind: kind,
      seg: seg,
      offset: size,
      fd: fd,
      max: Keyword.get(opts, :max, @max_segment_bytes)
    }
  end

  def close(%__MODULE__{fd: fd}), do: :file.close(fd)

  defp path(dir, seg),
    do: Path.join(dir, String.pad_leading(Integer.to_string(seg), 5, "0") <> ".seg")

  defp last_segment(dir) do
    case dir
         |> File.ls!()
         |> Enum.filter(&String.ends_with?(&1, ".seg"))
         |> Enum.sort()
         |> List.last() do
      nil -> {0, 0}
      f -> {f |> Path.rootname() |> String.to_integer(), File.stat!(Path.join(dir, f)).size}
    end
  end

  @doc "Current end position `{segment, offset}`."
  def position(%__MODULE__{seg: s, offset: o}), do: {s, o}

  @doc """
  Appends one block's `records` (a list of iodata) whose ids start at
  `base`, as `append_block/2`, but returns only what the archive keeps:
  `{segments, first, sparse}`, `first` the first record's location and
  `sparse` `[{id, {seg, offset}}]` for the ids that are multiples of
  `every`, in order. One pass over the records; the write is the same.
  """
  def append_sparse(%__MODULE__{} = st, records, base, every),
    do: append_layout(st, layout(records, base, every))

  @doc """
  The position-independent part of `append_sparse/4`: `{records, rel,
  total}`, `rel` the `{id, offset in the block}` of the ids that are
  multiples of `every` (newest first). Pure, so any process may compute it;
  `records` may be flattened to one binary before `append_layout/2`.
  """
  def layout(records, base, every) do
    {rel, total, _} =
      Enum.reduce(records, {[], 0, base}, fn r, {acc, off, id} ->
        acc = if rem(id, every) == 0, do: [{id, off} | acc], else: acc
        {acc, off + IO.iodata_length(r), id + 1}
      end)

    {records, rel, total}
  end

  @doc "Writes a `layout/3` result; returns what `append_sparse/4` returns."
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
    t0 = System.monotonic_time(:microsecond)
    :ok = :file.write(st.fd, records)
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
    seg = st.seg + 1
    # Locations store the segment number in 16 bits: one more would wrap.
    if seg > 0xFFFF, do: raise("archive #{st.kind} has no segment number left after #{st.seg}")
    :ok = :file.sync(st.fd)
    :ok = :file.close(st.fd)
    {:ok, fd} = :file.open(path(st.dir, seg), [:raw, :binary, :read, :write])
    # The new file's directory entry is durable before any record is written
    # to it, so a later commit never references a file a power loss can drop.
    sync_dir(st.dir)
    %{st | seg: seg, offset: 0, fd: fd}
  end

  # fsync of a directory (OTP 28 `:directory` mode; Linux fsyncs a read-only directory handle).
  # Failing is fatal: without it the archive's durability contract cannot hold.
  defp sync_dir(dir) do
    with {:ok, fd} <- :file.open(String.to_charlist(dir), [:read, :raw, :directory]),
         :ok <- :file.sync(fd),
         :ok <- :file.close(fd) do
      :ok
    else
      err ->
        raise "cannot fsync directory #{dir} (#{inspect(err)}): the archive's durability contract needs it"
    end
  end

  def sync(%__MODULE__{fd: fd}), do: :file.sync(fd)

  @doc """
  Deletes segment `seg` (witness pruning), closing this process's cached
  read handle for it. Never the segment being written.
  """
  def remove(%__MODULE__{dir: dir, seg: current}, seg) when seg < current do
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
    if File.rm(p) == :ok, do: sync_dir(dir)
    :ok
  end

  @doc """
  Crash recovery: drops data written after the committed end `{seg, offset}`.
  Later segment files are deleted and the committed segment is truncated.
  Raises if the committed segment is missing or shorter than `offset`
  (corruption; never recreated or zero-filled).
  """
  def truncate_to(%__MODULE__{} = st, {seg, offset}) do
    :ok = :file.close(st.fd)

    for f <- File.ls!(st.dir),
        String.ends_with?(f, ".seg"),
        n = f |> Path.rootname() |> String.to_integer(),
        n > seg,
        do: File.rm!(Path.join(st.dir, f))

    # Check before opening for write: opening would create a missing file,
    # and truncating past the end would zero-extend it.
    check_committed!(st.dir, st.kind, {seg, offset})
    {:ok, fd} = :file.open(path(st.dir, seg), [:raw, :binary, :read, :write])
    {:ok, _} = :file.position(fd, offset)
    :ok = :file.truncate(fd)
    :ok = :file.sync(fd)
    %{st | seg: seg, offset: offset, fd: fd}
  end

  defp check_committed!(dir, kind, {seg, offset}) do
    case File.stat(path(dir, seg)) do
      {:error, :enoent} ->
        raise "archive #{kind} segment #{seg} missing but committed state references it: " <>
                "the archive is corrupt; resync required"

      {:ok, %{size: size}} when size < offset ->
        raise "archive #{kind} segment #{seg} is shorter than the committed end (#{size} < #{offset}): " <>
                "the archive is corrupt; resync required"

      {:ok, _} ->
        :ok
    end
  end

  # --- reading -----------------------------------------------------------------

  defmodule Reader do
    @moduledoc false
    defstruct [:dir, fds: %{}]
  end

  def open_reader(%__MODULE__{dir: dir}), do: %Reader{dir: dir}
  def open_reader(root, kind), do: %Reader{dir: Path.join(root, Atom.to_string(kind))}

  @doc """
  Reads at `{seg, offset}`, skips `n` records and returns the next one. Used
  with the sparse index (n < 64). A run of records may continue in the next
  segment (see `read_run/6`).
  """
  def read_nth(%Reader{} = r, loc, n, decode, chunk \\ 4096) do
    {r, [rec]} = read_run(r, loc, n, 1, decode, chunk)
    {r, rec}
  end

  @doc """
  Skips `skip` records at `{seg, offset}`, then reads `count` consecutive
  records. Returns `{reader, records}`.

  Ids are contiguous across segments, but a segment only rolls at a block
  boundary. A sparse-index group (64 ids) can therefore span two segments.
  When a read consumes a segment exactly to its end, it continues at offset 0
  of the next segment.
  """
  def read_run(%Reader{} = r, {seg, offset}, skip, count, decode, chunk \\ 65_536) do
    {r, fd} = fd(r, seg)
    bump(:preads, 1)
    bump(:pread_bytes, chunk)

    data =
      case :file.pread(fd, offset, chunk) do
        {:ok, d} -> d
        :eof -> <<>>
      end

    eof = byte_size(data) < chunk

    case take(data, skip, count, decode, []) do
      {:ok, recs} ->
        {r, recs}

      {:more, skip_left, count_left, acc, rest} when eof and rest == <<>> ->
        # The segment ended exactly on a record boundary: continue in the next one.
        {r, more} = read_run(r, {seg + 1, 0}, skip_left, count_left, decode)
        {r, Enum.reverse(acc) ++ more}

      {:more, _, _, _, _} when eof ->
        raise "archive segment truncated at #{seg}:#{offset}"

      {:more, _, _, _, _} ->
        read_run(r, {seg, offset}, skip, count, decode, chunk * 4)
    end
  end

  defp take(_data, 0, 0, _decode, acc), do: {:ok, Enum.reverse(acc)}

  defp take(data, skip, count, decode, acc) do
    case decode.(data) do
      :more -> {:more, skip, count, acc, data}
      {_rec, rest} when skip > 0 -> take(rest, skip - 1, count, decode, acc)
      {rec, rest} -> take(rest, 0, count - 1, decode, [rec | acc])
    end
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
  defp fd(%Reader{} = r, seg) do
    p = path(r.dir, seg)
    handles = handles()
    tick = (Process.get({__MODULE__, :tick}) || 0) + 1
    Process.put({__MODULE__, :tick}, tick)

    case handles do
      %{^p => {fd, _}} ->
        Process.put({__MODULE__, :handles}, %{handles | p => {fd, tick}})
        {r, fd}

      _ ->
        handles = shrink(handles, cap() - 1)
        {:ok, fd} = :file.open(p, [:raw, :binary, :read])
        bump(:read_opens, 1)
        Process.put({__MODULE__, :handles}, Map.put(handles, p, {fd, tick}))
        {r, fd}
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
