defmodule Exnode.Archive.TxindexHistoryTest do
  @moduledoc """
  `Archive.connect/5`'s `:history` (prefetched committed txindex rows, see
  `Archive.prefetch_block/4`) never changes what is archived. The same
  storage-level sequence runs without history, with history read just
  before each connect, and with stale history (an old epoch, wrong rows);
  every txindex row (all occurrences, forks included), the effects digest
  and the resolved coins are identical, and the counters at the lookup
  seam show the reads that were avoided or done.

  Storage fixtures, not consensus-valid blocks: a tx twice in one block, a
  tx repeated in later blocks and on a competing fork, arbitrary spent
  output ids and a legacy term-encoded row bypass contextual validation.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Replay.Seed
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @op_true <<0x51>>

  @no_delta %{created: %{}, spent: []}

  defp cb(h, tag),
    do: BB.coinbase_with(h, 50 * @coin, outputs: [{50 * @coin, @op_true}, {0, <<0x6A, tag>>}])

  defp history(_a, _block, :none), do: nil

  defp history(a, block, :fresh) do
    {_, _, h} = Archive.prefetch_block(Archive.reader(a), [], nil, Enum.map(block.txs, & &1.txid))
    h
  end

  # Claims every txid has no row, at an epoch that has passed: must be ignored.
  defp history(a, block, :stale),
    do: %{epoch: Archive.epoch(a) - 1, rows: Map.new(block.txs, &{&1.txid, :not_found})}

  defp connect(a, block, h, spent, mode, commit \\ true) do
    a =
      Archive.connect(a, block, h, spent,
        delta: @no_delta,
        commit: false,
        history: history(a, block, mode)
      )

    if commit, do: Archive.flush(a), else: a
  end

  defp dump(kv),
    do:
      KV.fold_prefix(kv, :txindex, "", [], fn {k, v}, acc ->
        [{k, Archive.decode_txindex(v)} | acc]
      end)

  defp run(dir, mode) do
    {:ok, kv} = KV.open(Path.join(dir, "kv-#{mode}"))
    a = Archive.open(kv, Path.join(dir, "a-#{mode}"), nil, @p.genesis)
    Archive.take_stats()

    t = BB.tx([{:binary.copy(<<7>>, 32), 0}], [{@coin, @op_true}])
    # A tx whose txid already has a legacy (term-encoded) row naming an
    # unknown block: its history is decoded and extended, not lost.
    x = BB.tx([{:binary.copy(<<8>>, 32), 1}], [{@coin, @op_true}])
    :ok = KV.write(kv, [{:put, :txindex, x.txid, :erlang.term_to_binary([{9_999, 0, 0, 1, 0}])}])

    b1 = BB.build(@p.genesis.header, [cb(1, 1)])
    b2 = BB.build(b1.header, [cb(2, 2), t, t])
    b3 = BB.build(b2.header, [cb(3, 3), t])
    b4 = BB.build(b3.header, [cb(4, 4), t])
    b5 = BB.build(b4.header, [cb(5, 5), x, t])
    f4 = BB.build(b3.header, [cb(4, 40), t])
    b6 = BB.build(b5.header, [cb(6, 6), t])

    a = connect(a, b1, 1, [], mode)
    # The same tx twice in one block, then again in the next (uncommitted) one.
    a = connect(a, b2, 2, [1, 1], mode, false)
    a = connect(a, b3, 3, [1], mode, false)
    a = Archive.flush(a)
    # Committed occurrences plus a new one; then a legacy row.
    a = connect(a, b4, 4, [1], mode)
    a = connect(a, b5, 5, [1, 1], mode)
    # A competing fork with the same tx, then back: b4 and b5 reconnect as
    # archived blocks (no append).
    {a, _} = Archive.disconnect_tip(a)
    {a, _} = Archive.disconnect_tip(a)
    a = connect(a, f4, 4, [1], mode)
    {a, _} = Archive.disconnect_tip(a)
    a = connect(a, b4, 4, [1], mode)
    a = connect(a, b5, 5, [1, 1], mode)
    a = connect(a, b6, 6, [1], mode)

    result = %{
      rows: dump(kv),
      digest: Seed.effects_digest(a, 0, 6),
      coins: Archive.resolve_many(a, [{t.txid, 0}, {x.txid, 0}, {t.txid, 1}]),
      stats:
        Map.take(Archive.take_stats(), [:txindex_reads, :txindex_reused, :txindex_hint_stale])
    }

    Archive.close(a)
    KV.close(kv)
    {result, t, x}
  end

  test "history reuse archives exactly what fresh reads do, and the seam counts it", %{
    tmp_dir: dir
  } do
    {none, t, x} = run(dir, :none)
    {fresh, _, _} = run(dir, :fresh)
    {stale, _, _} = run(dir, :stale)

    for r <- [fresh, stale] do
      assert r.rows == none.rows
      assert r.digest == none.digest
      assert r.coins == none.coins
    end

    rows = Map.new(none.rows)
    # Every occurrence is kept: b2 (twice), b3, b4, the fork's f4, b5, b6.
    assert length(rows[t.txid]) == 7
    assert [{9_999, 0, 0, 1, 0}, {_, 1, _, 1, _}] = rows[x.txid]

    # Without history every txid not in the batch is read; with fresh history
    # none is (in-batch txids never were); stale history is never used.
    assert none.stats.txindex_reused == 0 and none.stats.txindex_reads > 0
    assert fresh.stats.txindex_reads == 0
    assert fresh.stats.txindex_reused == none.stats.txindex_reads
    assert stale.stats.txindex_reused == 0
    assert stale.stats.txindex_reads == none.stats.txindex_reads
    # Seven appends (b1..b6 and f4; reconnects append nothing).
    assert stale.stats.txindex_hint_stale == 7
  end

  test "the batch's list wins over a history row for the same txid", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    a = Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis)
    t = BB.tx([{:binary.copy(<<7>>, 32), 0}], [{@coin, @op_true}])
    b1 = BB.build(@p.genesis.header, [cb(1, 1), t])
    b2 = BB.build(b1.header, [cb(2, 2), t])
    # Read before b1 is connected: t has no committed row (true, and current).
    {_, _, h2} = Archive.prefetch_block(Archive.reader(a), [], nil, Enum.map(b2.txs, & &1.txid))
    assert h2.rows[t.txid] == :not_found
    a = Archive.connect(a, b1, 1, [1], delta: @no_delta, commit: false)
    a = Archive.connect(a, b2, 2, [1], delta: @no_delta, commit: false, history: h2)
    a = Archive.flush(a)
    {:ok, bin} = KV.get(kv, :txindex, t.txid)
    assert [{1, 1, _, 1, _}, {2, 1, _, 1, _}] = Archive.decode_txindex(bin)
    Archive.close(a)
    KV.close(kv)
  end

  test "spend records map each non-coinbase input id to its spent output id; a mismatch raises",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    a = Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis)
    in0 = Archive.next_ids(a).inp
    t1 = BB.tx([{:binary.copy(<<1>>, 32), 0}, {:binary.copy(<<2>>, 32), 5}], [{@coin, @op_true}])
    t2 = BB.tx([{:binary.copy(<<3>>, 32), 1}], [{@coin, @op_true}])
    b1 = BB.build(@p.genesis.header, [cb(1, 1), t1, t2])

    for bad <- [[11, 12], [11, 12, 13, 14]] do
      assert_raise ArgumentError, fn ->
        Archive.connect(a, b1, 1, bad, delta: @no_delta, commit: false)
      end
    end

    # A failed connect leaves the archive struct unusable (the chain state
    # restarts); a fresh one archives the block.
    Archive.close(%{a | batch: %{a.batch | n: 0}})
    KV.close(kv)
    {:ok, kv} = KV.open(Path.join(dir, "kv2"))
    a = Archive.open(kv, Path.join(dir, "a2"), nil, @p.genesis)
    a = Archive.connect(a, b1, 1, [11, 12, 13])

    rows =
      KV.fold_prefix(kv, :spends, "", [], fn {<<o::64, b::32>>, <<i::64>>}, acc ->
        [{o, b, i} | acc]
      end)

    # The coinbase's input is in0; t1's are in0 + 1, + 2; t2's is in0 + 3.
    assert Enum.sort(rows) == [{11, 1, in0 + 1}, {12, 1, in0 + 2}, {13, 1, in0 + 3}]
    Archive.close(a)
    KV.close(kv)
  end
end
