defmodule Exnode.Archive.RevalidateTest do
  @moduledoc """
  `Archive.revalidate/4` carries prefetched committed answers over one
  commit: every answer it keeps equals what the committed state says after
  the commit, it drops exactly the answers the commit may have changed (an
  output the batch spent, a txid the batch archived), and it refuses
  (`:stale`) after two commits, a disconnect, or a commit that reconnected
  an archived block.

  Storage fixtures (arbitrary spent output ids), not consensus-valid blocks.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @op_true <<0x51>>
  @no_delta %{created: %{}, spent: []}

  defp cb(h),
    do: BB.coinbase_with(h, 50 * @coin, outputs: [{50 * @coin, @op_true}, {0, <<0x6A, h>>}])

  defp connect(a, block, h, spent),
    do: Archive.connect(a, block, h, spent, delta: @no_delta, commit: false)

  defp out_id(a, op) do
    {:ok, %{output_id: id}} = Map.fetch!(Archive.committed_answers(a, [op]), op)
    id
  end

  defp open(dir) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    a = Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis)
    {a, kv}
  end

  test "kept answers equal the committed state after the commit; changed ones are dropped",
       %{tmp_dir: dir} do
    {a, kv} = open(dir)
    # Committed: b1, b2 (two coinbases, a tx with three outputs).
    t = BB.tx([{:binary.copy(<<7>>, 32), 0}], for(_ <- 1..3, do: {@coin, @op_true}))
    b1 = BB.build(@p.genesis.header, [cb(1)])
    b2 = BB.build(b1.header, [cb(2), t])
    a = a |> connect(b1, 1, []) |> connect(b2, 2, [1]) |> Archive.flush()

    # The batch: b3 spends t:1 and b1's coinbase output; u (new) is in it.
    u = BB.tx([{t.txid, 1}], [{@coin, @op_true}])
    b3 = BB.build(b2.header, [cb(3), u])
    spent = [out_id(a, {t.txid, 1})]
    a = connect(a, b3, 3, spent)

    ops = [
      {t.txid, 0},
      {t.txid, 1},
      {t.txid, 2},
      {hd(b1.txs).txid, 0},
      {hd(b1.txs).txid, 1},
      {u.txid, 0},
      {hd(b3.txs).txid, 0},
      {:binary.copy(<<9>>, 32), 0}
    ]

    # A prefetch worker's answers and history, at the epoch before the commit.
    e = Archive.epoch(a)
    {answers, _, history} = Archive.prefetch_block(Archive.reader(a), ops, nil, [u.txid, t.txid])
    assert map_size(answers) == length(ops)
    a = Archive.flush(a)
    assert Archive.epoch(a) == e + 1

    {:ok, kept, hist, dropped} = Archive.revalidate(a, e, answers, history)
    now = Archive.committed_answers(a, ops)

    # Every kept answer is the committed state's after the commit.
    for {op, r} <- kept, do: assert({op, r} == {op, now[op]})

    # Dropped: t:1 (spent by the batch), u:0 and b3's coinbase (txids the
    # batch archived, "missing" before the commit and unspent after it).
    assert (Map.keys(answers) -- Map.keys(kept)) |> Enum.sort() ==
             Enum.sort([{t.txid, 1}, {u.txid, 0}, {hd(b3.txs).txid, 0}])

    assert dropped == 3
    assert answers[{t.txid, 1}] != now[{t.txid, 1}]
    assert answers[{u.txid, 0}] != now[{u.txid, 0}]
    # The history names u, a txid of the batch: not carried over.
    assert hist == nil

    {:ok, _, hist2, _} =
      Archive.revalidate(a, e, answers, %{history | rows: Map.take(history.rows, [t.txid])})

    assert hist2.epoch == Archive.epoch(a)

    # Current answers are not this function's: only epoch + 1.
    assert Archive.revalidate(a, e + 1, answers, nil) == :stale
    assert Archive.revalidate(a, e - 1, answers, nil) == :stale

    # Two commits since: stale.
    b4 = BB.build(b3.header, [cb(4)])
    a = a |> connect(b4, 4, []) |> Archive.flush()
    assert Archive.revalidate(a, e, answers, nil) == :stale
    assert {:ok, _, _, _} = Archive.revalidate(a, e + 1, answers, nil)

    # A disconnect (it commits first, then changes the chain): stale.
    e2 = Archive.epoch(a)
    {a, _} = Archive.disconnect_tip(a)
    assert Archive.epoch(a) > e2
    assert Archive.revalidate(a, Archive.epoch(a) - 1, answers, nil) == :stale

    # A commit whose batch reconnected the archived b4: stale.
    e3 = Archive.epoch(a)
    a = a |> connect(b4, 4, []) |> Archive.flush()
    assert Archive.epoch(a) == e3 + 1
    assert Archive.revalidate(a, e3, answers, nil) == :stale

    Archive.close(a)
    KV.close(kv)
  end
end
