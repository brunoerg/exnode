defmodule Exnode.Archive.SegmentsTest do
  @moduledoc """
  Segment durability and recovery.
  * A torn tail after the committed end is discarded and committed records
    read back unchanged (as before).
  * A committed segment that is missing, or shorter than the committed end,
    makes recovery raise; it is no longer recreated or zero-extended.
  * Rolling to new segments, and removing pruned ones, still work across
    reopens.
  Recovery is exercised as `Archive.open` does it: `open/3`, then
  `truncate_to/2` with the committed end. One test goes through
  `Archive.open` itself.
  """
  use ExUnit.Case, async: true

  alias Exnode.Archive.Segments

  @moduletag :tmp_dir

  # Records are length-prefixed binaries.
  defp rec(i), do: <<byte_size(payload(i))::16, payload(i)::binary>>
  defp payload(i), do: :binary.copy(<<rem(i, 251)>>, 10 + rem(i, 40))
  defp decode(<<n::16, p::binary-size(n), rest::binary>>), do: {p, rest}
  defp decode(_), do: :more

  # Appends `n` blocks of 3 records each; returns {segments, locations}.
  defp write(s, from, n) do
    Enum.reduce(from..(from + n - 1), {s, []}, fn b, {s, acc} ->
      {s, locs} = Segments.append_block(s, for(i <- 0..2, do: rec(b * 3 + i)))
      {s, acc ++ Enum.zip(locs, for(i <- 0..2, do: b * 3 + i))}
    end)
  end

  defp read_all(root, locs) do
    r = Segments.open_reader(root, :outputs)
    for {loc, i} <- locs, do: {Segments.read_nth(r, loc, 0, &decode/1), i}
  end

  defp reopen(root, committed, opts \\ []) do
    min_seg = Keyword.get(opts, :min_seg, 0)
    s = Segments.open(root, :outputs, opts)
    Segments.truncate_to(s, committed, min_seg)
  end

  test "a torn tail after the committed end is discarded; committed records are intact", %{
    tmp_dir: root
  } do
    {s, locs} = write(Segments.open(root, :outputs), 0, 20)
    :ok = Segments.sync(s)
    committed = Segments.position(s)
    # Written after the commit, then a crash.
    {s, _} = write(s, 20, 5)
    :ok = Segments.sync(s)
    :ok = Segments.close(s)

    s = reopen(root, committed)
    assert Segments.position(s) == committed
    {seg, off} = committed

    assert File.stat!(
             Path.join([root, "outputs", String.pad_leading("#{seg}", 5, "0") <> ".seg"])
           ).size == off

    assert for({p, i} <- read_all(root, locs), do: p == payload(i)) |> Enum.all?()
    # Appending continues from the committed end.
    {s, _} = write(s, 20, 1)
    assert elem(Segments.position(s), 1) > off
  end

  test "rolling over several segments, then reopening: everything committed reads back", %{
    tmp_dir: root
  } do
    {s, locs} = write(Segments.open(root, :outputs, max: 400), 0, 60)
    :ok = Segments.sync(s)
    committed = Segments.position(s)
    assert elem(committed, 0) >= 3
    :ok = Segments.close(s)
    _ = reopen(root, committed, max: 400)
    assert for({p, i} <- read_all(root, locs), do: p == payload(i)) |> Enum.all?()
  end

  test "a missing committed segment raises (no recreated, zero-filled file)", %{tmp_dir: root} do
    {s, _} = write(Segments.open(root, :outputs, max: 400), 0, 60)
    :ok = Segments.sync(s)
    {seg, _} = committed = Segments.position(s)
    :ok = Segments.close(s)
    path = Path.join([root, "outputs", String.pad_leading("#{seg}", 5, "0") <> ".seg"])
    File.rm!(path)

    assert_raise Exnode.StorageError,
                 ~r/segment #{seg} missing but committed state references it: the archive is corrupt/,
                 fn ->
                   reopen(root, committed, max: 400)
                 end

    # The old behaviour (a recreated, zero-extended file) is gone.
    refute File.exists?(path)
  end

  test "a committed segment shorter than the committed end raises (no zero-extension)", %{
    tmp_dir: root
  } do
    {s, _} = write(Segments.open(root, :outputs), 0, 20)
    :ok = Segments.sync(s)
    {seg, off} = committed = Segments.position(s)
    :ok = Segments.close(s)
    path = Path.join([root, "outputs", String.pad_leading("#{seg}", 5, "0") <> ".seg"])
    {:ok, fd} = :file.open(path, [:raw, :binary, :read, :write])
    {:ok, _} = :file.position(fd, off - 10)
    :ok = :file.truncate(fd)
    :ok = :file.close(fd)

    assert_raise Exnode.StorageError,
                 ~r/shorter than the committed end \(#{off - 10} < #{off}\)/,
                 fn ->
                   reopen(root, committed)
                 end

    assert File.stat!(path).size == off - 10
  end

  test "open/3 with a committed end checks it before creating anything", %{tmp_dir: root} do
    assert_raise Exnode.StorageError, ~r/outputs segment 0 missing/, fn ->
      Segments.open(root, :outputs, committed: {0, 1234})
    end

    refute File.exists?(Path.join(root, "outputs"))
  end

  test "remove/2 deletes a pruned segment; reopening afterwards works", %{tmp_dir: root} do
    {s, locs} = write(Segments.open(root, :outputs, max: 400), 0, 60)
    :ok = Segments.sync(s)
    committed = Segments.position(s)
    :ok = Segments.remove(s, 0)
    refute File.exists?(Path.join([root, "outputs", "00000.seg"]))
    :ok = Segments.close(s)
    _ = reopen(root, committed, max: 400, min_seg: 1)
    # Records in later segments are still there.
    later = Enum.filter(locs, fn {{seg, _}, _} -> seg > 0 end)
    assert for({p, i} <- read_all(root, later), do: p == payload(i)) |> Enum.all?()
  end

  # Locations keep the segment number in 16 bits (<<seg::16, off::48>>).
  test "rolling past segment 0xFFFF raises instead of wrapping", %{tmp_dir: root} do
    {s, _} = write(Segments.open(root, :outputs, max: 10), 0, 1)
    s = %{s | seg: 0xFFFF}

    assert_raise Exnode.StorageError, ~r/no segment number left after 65535/, fn ->
      Segments.append_block(s, [rec(0)])
    end

    refute File.exists?(Path.join([root, "outputs", "65536.seg"]))
  end

  test "a corrupt record length raises at once instead of reading to the segment's end", %{
    tmp_dir: root
  } do
    # A non-canonical CompactSize (0xFD then a value below 253) before 4 MiB of filler.
    bad = <<1::little-signed-64, 0xFD, 5, 0>>

    {s, [loc, _]} =
      Segments.append_block(Segments.open(root, :outputs), [bad, :binary.copy(<<7>>, 4_194_304)])

    :ok = Segments.sync(s)

    assert Exnode.Archive.decode_output(binary_part(bad, 0, 9)) == :more
    _ = Segments.take_stats()
    r = Segments.open_reader(root, :outputs)

    assert_raise Exnode.StorageError,
                 ~r/corrupt archive record \(non_canonical_compact_size\)/,
                 fn ->
                   Segments.read_nth(r, loc, 0, &Exnode.Archive.decode_output/1)
                 end

    assert Segments.take_stats().preads == 1
    Segments.close_reader(r)
    Segments.close(s)
  end

  describe "through Archive.open" do
    alias Exnode.Store.KV
    alias Exnode.Test.BlockBuilder, as: BB

    @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

    test "a lost committed outputs segment fails the start-up loudly", %{tmp_dir: dir} do
      p = Exnode.ChainParams.get(:regtest)
      {:ok, kv} = KV.open(Path.join(dir, "kv"))
      a = Exnode.Archive.open(kv, Path.join(dir, "hot"), nil, p.genesis)

      a =
        Enum.reduce(BB.read_chain(@chain), a, fn raw, a ->
          {:ok, b} = Exnode.Codec.Block.decode_exact(raw)
          Exnode.Archive.connect(a, b, a.tip.height + 1, [])
        end)

      _ = Exnode.Archive.flush(a)
      File.rm!(Path.join([dir, "hot", "outputs", "00000.seg"]))

      assert_raise Exnode.StorageError,
                   ~r/outputs segment 0 missing but committed state references it/,
                   fn ->
                     Exnode.Archive.open(kv, Path.join(dir, "hot"), nil, p.genesis)
                   end

      # Failing before any file is opened: nothing was recreated.
      refute File.exists?(Path.join([dir, "hot", "outputs", "00000.seg"]))
    end

    test "a missing intermediate segment raises and latches the guard", %{tmp_dir: dir} do
      import ExUnit.CaptureLog

      g = Exnode.Store.Guard.acquire!(dir, name: "canonical", require_clean_mark: false)
      s = Segments.open(dir, :outputs, max: 400, guard: g)
      {s, _} = write(s, 0, 60)
      :ok = Segments.sync(s)
      {seg, _} = committed = Segments.position(s)
      assert seg >= 3
      :ok = Segments.close(s)

      # Delete an intermediate segment (00001.seg), leaving the final segment intact.
      File.rm!(Path.join([dir, "outputs", "00001.seg"]))

      capture_log(fn ->
        assert_raise Exnode.StorageError, ~r/outputs segment 1 missing/, fn ->
          Segments.open(dir, :outputs, committed: committed, guard: g)
        end
      end)

      assert Exnode.Store.Guard.faulted?(g)
      Exnode.Store.Guard.abandon(g)
    end

    test "strict_clean open refuses unexpected trailing bytes past committed end", %{tmp_dir: dir} do
      s = Segments.open(dir, :outputs)
      {s, _} = write(s, 0, 10)
      :ok = Segments.sync(s)
      committed = Segments.position(s)
      {s, _} = write(s, 10, 2)
      :ok = Segments.sync(s)
      :ok = Segments.close(s)

      assert_raise Exnode.StorageError, ~r/unexpected trailing bytes on clean open/, fn ->
        Segments.open(dir, :outputs, committed: committed, strict_clean: true)
      end

      # Offline truncate_dir! restores exact committed end so strict_clean succeeds.
      :ok = Segments.truncate_dir!(dir, :outputs, committed)
      s2 = Segments.open(dir, :outputs, committed: committed, strict_clean: true)
      assert Segments.position(s2) == committed
      :ok = Segments.close(s2)
    end

    test "reconstruct integrity failure latches guard and raises StorageError", %{tmp_dir: dir} do
      import ExUnit.CaptureLog

      g = Exnode.Store.Guard.acquire!(dir, name: "canonical", require_clean_mark: false)
      p = Exnode.ChainParams.get(:regtest)
      {:ok, kv} = KV.open(Path.join(dir, "kv"), mode: :canonical, guard: g)
      a = Exnode.Archive.open(kv, Path.join(dir, "hot"), nil, p.genesis)
      [raw1 | _] = BB.read_chain(@chain)
      {:ok, b1} = Exnode.Codec.Block.decode_exact(raw1)
      a = Exnode.Archive.connect(a, b1, 1, [])
      a = Exnode.Archive.flush(a)

      # Corrupt a byte in the outputs segment so merkle root fails on read_block.
      seg0 = Path.join([dir, "hot", "outputs", "00000.seg"])
      bin = File.read!(seg0)
      flipped = Bitwise.bxor(:binary.last(bin), 0xFF)
      File.write!(seg0, binary_part(bin, 0, byte_size(bin) - 1) <> <<flipped>>)

      capture_log(fn ->
        assert_raise Exnode.StorageError, ~r/failed merkle check/, fn ->
          Exnode.Archive.read_block(a, Exnode.Archive.id_at(a, 1))
        end
      end)

      assert Exnode.Store.Guard.faulted?(g)
      Exnode.Archive.close(a)
      KV.close(kv)
      Exnode.Store.Guard.abandon(g)
    end
  end
end

defmodule Exnode.Archive.SegmentsSparseTest do
  @moduledoc """
  `Segments.append_layout/2` with `Segments.layout/3` writes exactly what
  `append_block/2` writes (same bytes, same rollovers) and returns the first
  location and the locations of ids that are multiples of `every`, as derived
  from `append_block/2`'s per-record locations.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Archive.Segments

  @moduletag :tmp_dir

  property "append_layout equals append_block's locations, filtered", %{tmp_dir: root} do
    check all(
            blocks <-
              list_of(list_of(integer(1..90), min_length: 1, max_length: 40), max_length: 12),
            base <- integer(0..200),
            every <- member_of([1, 4, 64]),
            max <- member_of([150, 400, 100_000]),
            max_runs: 60
          ) do
      n = System.unique_integer([:positive])
      a = Segments.open(Path.join(root, "a#{n}"), :outputs, max: max)
      b = Segments.open(Path.join(root, "b#{n}"), :outputs, max: max)

      {a, b, _} =
        Enum.reduce(blocks, {a, b, base}, fn sizes, {a, b, id0} ->
          recs = for {sz, k} <- Enum.with_index(sizes), do: [<<k>>, :binary.copy(<<id0>>, sz - 1)]
          {a, locs} = Segments.append_block(a, recs)
          {b, first, sparse} = Segments.append_layout(b, Segments.layout(recs, id0, every))
          assert first == hd(locs)

          assert sparse ==
                   for(
                     {loc, id} <- Enum.with_index(locs, id0),
                     rem(id, every) == 0,
                     do: {id, loc}
                   )

          assert Segments.position(a) == Segments.position(b)
          {a, b, id0 + length(sizes)}
        end)

      for s <- [a, b], do: :ok = Segments.sync(s)

      files = fn dir ->
        for f <- Enum.sort(File.ls!(dir)), do: {f, File.read!(Path.join(dir, f))}
      end

      assert files.(Path.join([root, "a#{n}", "outputs"])) ==
               files.(Path.join([root, "b#{n}", "outputs"]))

      Segments.close(a)
      Segments.close(b)
    end
  end
end

defmodule Exnode.Archive.SegmentsHandlesTest do
  @moduledoc """
  The per-process read-handle cache is bounded (`Segments.read_handles/0`)
  and evicted handles are closed at the OS level. Synchronous: it counts
  this OS process's open descriptors, which concurrent tests would change.
  """
  use ExUnit.Case, async: false

  alias Exnode.Archive.Segments

  @moduletag :tmp_dir

  defp rec(i), do: <<byte_size(payload(i))::16, payload(i)::binary>>
  defp payload(i), do: :binary.copy(<<rem(i, 251)>>, 10 + rem(i, 40))
  defp decode(<<n::16, p::binary-size(n), rest::binary>>), do: {p, rest}
  defp decode(_), do: :more

  defp write(s, from, n) do
    Enum.reduce(from..(from + n - 1), {s, []}, fn b, {s, acc} ->
      {s, locs} = Segments.append_block(s, for(i <- 0..2, do: rec(b * 3 + i)))
      {s, acc ++ Enum.zip(locs, for(i <- 0..2, do: b * 3 + i))}
    end)
  end

  test "a reader keeps at most read_handles/0 segment files open; reads stay exact", %{
    tmp_dir: root
  } do
    s = Segments.open(root, :outputs, max: 200)
    {s, locs} = write(s, 0, 300)
    :ok = Segments.sync(s)
    segs = locs |> Enum.map(fn {{seg, _}, _} -> seg end) |> Enum.uniq() |> length()
    assert segs > 3 * Segments.read_handles()

    # In a fresh process, so its handle cache and descriptors are its own.
    task =
      Task.async(fn ->
        fds = fn -> length(File.ls!("/proc/self/fd")) end
        before = fds.()
        r = Segments.open_reader(root, :outputs)

        # Every record, twice, in an order that cycles through all segments.
        for {loc, i} <- locs ++ Enum.reverse(locs) do
          assert Segments.read_nth(r, loc, 0, &decode/1) == payload(i)
          assert Segments.open_read_handles() <= Segments.read_handles()
        end

        held = Segments.open_read_handles()
        grew = fds.() - before
        Segments.close_reader(r)
        {held, grew, Segments.open_read_handles(), fds.() - before}
      end)

    {held, grew, after_close, after_fds} = Task.await(task, 30_000)
    assert held == Segments.read_handles()
    # Evicted handles are closed at the OS level, not just forgotten.
    assert grew <= Segments.read_handles()
    assert after_close == 0
    assert after_fds <= 0
    Segments.close(s)
  end

  # Regression: API connection processes keep fewer handles.
  test "limit_read_handles/1 lowers this process's cap and closes the excess", %{tmp_dir: root} do
    s = Segments.open(root, :outputs, max: 200)
    {s, locs} = write(s, 0, 100)
    :ok = Segments.sync(s)

    task =
      Task.async(fn ->
        r = Segments.open_reader(root, :outputs)
        for {loc, _} <- locs, do: Segments.read_nth(r, loc, 0, &decode/1)
        full = Segments.open_read_handles()
        Segments.limit_read_handles(2)
        shrunk = Segments.open_read_handles()

        for {loc, i} <- locs do
          assert Segments.read_nth(r, loc, 0, &decode/1) == payload(i)
          assert Segments.open_read_handles() <= 2
        end

        Segments.close_reader(r)
        {full, shrunk}
      end)

    assert {16, 2} = Task.await(task, 30_000)
  end
end
