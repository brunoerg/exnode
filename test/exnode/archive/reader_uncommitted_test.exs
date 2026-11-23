defmodule Exnode.Archive.ReaderUncommittedTest do
  @moduledoc """
  Regression: the reader shares the archive's live chain tables, which
  `connect(commit: false)` fills before anything is committed. After a
  reorg, a reader resolved a height to an uncommitted block (whose record
  is not in the KV, so `block_record!/2` raised) and saw a reconnected
  block as on chain before its spend records were committed (an output it
  spends read as unspent while the block read as on chain).

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

  defp cb(h, tag),
    do: BB.coinbase_with(h, 50 * @coin, outputs: [{50 * @coin, @op_true}, {0, <<0x6A, tag>>}])

  defp connect(a, block, h, spent),
    do: Archive.connect(a, block, h, spent, delta: @no_delta, commit: false)

  test "a reader sees only committed blocks across a reorg", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    a = Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis)

    t = BB.tx([{:binary.copy(<<7>>, 32), 0}], [{@coin, @op_true}, {@coin, @op_true}])
    b1 = BB.build(@p.genesis.header, [cb(1, 1), t])
    a = a |> connect(b1, 1, [1]) |> Archive.flush()

    {:ok, %{output_id: out}} =
      Map.fetch!(Archive.committed_answers(a, [{t.txid, 1}]), {t.txid, 1})

    u = BB.tx([{t.txid, 1}], [{@coin, @op_true}])
    b2 = BB.build(b1.header, [cb(2, 2), u])
    a = a |> connect(b2, 2, [out]) |> Archive.flush()
    id2 = Archive.id_at(a, 2)
    r = Archive.reader(a)
    assert Archive.spent_on_chain?(r, out)

    # Reorg back onto b2, not yet committed: the reader keeps the committed
    # chain (b2 off it, t:1 unspent), consistently.
    {a, ^id2} = Archive.disconnect_tip(a)
    a = connect(a, b2, 2, [out])
    assert Archive.on_chain?(a, id2)

    for r <- [r, Archive.reader(a)] do
      assert Archive.id_at(r, 2) == nil
      refute Archive.on_chain?(r, id2)
      refute Archive.spent_on_chain?(r, out)
    end

    a = Archive.flush(a)
    assert Archive.id_at(r, 2) == id2
    assert Archive.on_chain?(r, id2)
    assert Archive.spent_on_chain?(r, out)

    # Reorg onto a new block, not yet committed: its record is only in the batch.
    b2x = BB.build(b1.header, [cb(2, 3)])
    {a, ^id2} = Archive.disconnect_tip(a)
    a = connect(a, b2x, 2, [])
    idx = Archive.id_at(a, 2)
    assert idx != id2
    assert Archive.chain_tx_count(a, 2) == 4

    for r <- [r, Archive.reader(a)] do
      assert Archive.id_at(r, 2) == nil
      assert Archive.chain_tx_count(r, 2) == nil
      refute Archive.on_chain?(r, idx)
      assert Archive.id_at(r, 1) == Archive.id_at(a, 1)
    end

    a = Archive.flush(a)
    assert Archive.id_at(r, 2) == idx
    assert Archive.block_record!(r, idx).hash == b2x.header.hash

    Archive.close(a)
    KV.close(kv)
  end
end
