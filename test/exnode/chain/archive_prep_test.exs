defmodule Exnode.Chain.ArchivePrepTest do
  @moduledoc """
  Archive preparation (`Archive.prepare_append/7` in a short-lived process
  while later blocks are validated) changes nothing that is archived: the
  same chain, connected through the pipeline with and without it, leaves
  byte-identical stores. With it, blocks are archived from their prepared
  records; when the guessed ids no longer match, or the preparation
  fails, the block is archived in place.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000
  @op_true <<0x51>>

  # The store, except column families written outside the archive.
  @cfs [:txindex, :spends, :blocks, :blockhash, :locs, :meta]

  defp start(dir, name, opts) do
    {:ok, kv} = KV.open(Path.join(dir, "kv-#{name}"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link(
        [params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot-#{name}")] ++ opts
      )

    %{kv: kv, hs: hs, cs: cs}
  end

  # chain150, then `n` blocks each spending an earlier coinbase into several
  # outputs and a tx spending one of those within the block (in-block
  # spends, so the deltas have both created and spent coins).
  defp blocks(n) do
    base = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)

    {more, _} =
      Enum.map_reduce(1..n//1, List.last(base).header, fn i, prev ->
        cb = hd(Enum.at(base, i - 1).txs).txid
        split = BB.tx([{cb, 0}], for(_ <- 1..5, do: {10 * @coin - 1000, @op_true}))
        child = BB.spend_op_true(split.txid, 2, 10 * @coin - 2000)
        b = BB.build(prev, [BB.coinbase(150 + i, 25 * @coin), split, child])
        {b, b.header}
      end)

    base ++ more
  end

  # Headers first, then the blocks newest first: the last submission
  # (the first block) connects the whole path through the pipeline.
  defp feed(%{cs: cs, hs: hs}, bs) do
    {:ok, _} = Headers.process_headers(hs, Enum.map(bs, & &1.header))
    for b <- Enum.reverse(tl(bs)), do: {:ok, :stored} = State.submit_block(cs, b)
    {:ok, :connected} = State.submit_block(cs, hd(bs))
    _ = State.commit_now(cs)
  end

  defp dump(kv) do
    for cf <- @cfs, into: %{} do
      {cf, KV.fold_prefix(kv, cf, <<>>, [], &[&1 | &2]) |> Enum.reverse()}
    end
  end

  defp archive_counts(cs) do
    w = State.work_stats(cs)

    {Map.get(w.chain_state, :append_prepared, 0),
     Map.get(w.chain_state, :append_prepared_mismatch, 0)}
  end

  test "the same store with and without archive preparation, through the pipeline",
       %{tmp_dir: dir} do
    bs = blocks(40)
    with_prep = start(dir, "prep", archive_prep: true)
    without = start(dir, "inline", archive_prep: false)
    feed(with_prep, bs)
    feed(without, bs)

    assert State.tip(with_prep.cs).hash == List.last(bs).header.hash
    assert State.tip(without.cs).hash == List.last(bs).header.hash
    assert dump(with_prep.kv) == dump(without.kv)

    {prepared, mismatched} = archive_counts(with_prep.cs)
    # Every block after genesis is archived from its prepared records.
    assert prepared == length(bs)
    assert mismatched == 0
    assert archive_counts(without.cs) == {0, 0}
  end

  for {how, fun} <- [
        raises: quote(do: fn -> raise "injected" end),
        is_killed: quote(do: fn -> Process.exit(self(), :kill) end)
      ] do
    test "a block whose preparation #{how} is archived in place", %{tmp_dir: dir} do
      bs = blocks(12)
      victims = MapSet.new([Enum.at(bs, 3), Enum.at(bs, 155)], & &1.header.hash)
      fail = unquote(fun)
      hook = fn b -> if MapSet.member?(victims, b.header.hash), do: fail.() end
      with_prep = start(dir, "prep", archive_prep: true, test_archive_prep_hook: hook)
      without = start(dir, "inline", archive_prep: false)
      feed(with_prep, bs)
      feed(without, bs)

      assert State.tip(with_prep.cs).hash == List.last(bs).header.hash
      assert dump(with_prep.kv) == dump(without.kv)
      assert archive_counts(with_prep.cs) == {length(bs) - 2, 0}
    end
  end

  test "prepared records whose ids no longer match are ignored: the block is encoded in place",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    a = Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis)
    {:ok, kv2} = KV.open(Path.join(dir, "kv2"))
    b = Archive.open(kv2, Path.join(dir, "b"), nil, @p.genesis)
    [b1, b2 | _] = tl(blocks(0))
    no_delta = %{created: %{}, spent: []}
    Archive.take_stats()

    # Prepared for b1's ids, used for b2: ignored.
    stale = Archive.prepare_append(b2, 2, [], Archive.next_ids(a), no_delta)
    a = Archive.connect(a, b1, 1, [], delta: no_delta, commit: false)
    a = Archive.connect(a, b2, 2, [], delta: no_delta, commit: false, prepared: stale)
    _ = Archive.flush(a)

    b = Archive.connect(b, b1, 1, [], delta: no_delta, commit: false)
    b = Archive.connect(b, b2, 2, [], delta: no_delta, commit: false)
    _ = Archive.flush(b)

    stats = Archive.take_stats()
    assert stats.append_prepared_mismatch == 1
    assert stats.append_prepared == 0
    assert dump(kv) == dump(kv2)
  end
end
