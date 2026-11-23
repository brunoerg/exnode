defmodule Exnode.Index.FollowerUncommittedReorgTest do
  @moduledoc """
  Regression: after a reorg onto blocks connected but not yet committed,
  the view's reader resolved the indexed tip's height to an uncommitted
  block whose record is only in the chain state's batch, and the rewind
  raised MatchError on every sync until the batch was committed (up to
  minutes behind the tip), so the index kept the disconnected branch.
  """
  use ExUnit.Case, async: true
  import Exnode.Test.Wait

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Index.Follower
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Test.SpendChain

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @cf :scripthash

  defp block(prev, height, value) do
    cb = fn extra, wit ->
      BB.coinbase_with(height, 0, outputs: [{value, SpendChain.spk()} | extra], witness: wit)
    end

    BB.build_segwit(prev, cb, [])
  end

  defp submit(cs, blocks) do
    for b <- blocks, do: assert({:ok, _} = State.submit_block(cs, b, requested: true))
    tip = List.last(blocks).header.hash
    assert wait_until(fn -> State.tip(cs).hash == tip end, 30_000)
  end

  defp nothing, do: fn _, _, _ -> [] end

  defp sync_all(kv, cs) do
    case Follower.sync(kv, @cf, cs, nothing(), nothing()) do
      :more -> sync_all(kv, cs)
      :done -> :ok
    end
  end

  test "the index rewinds off a branch replaced by uncommitted blocks", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs = :"follower_uncommitted_cs_#{System.unique_integer([:positive])}"

    {:ok, _} =
      State.start_link(
        name: cs,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        commit_at_tip: false,
        batch_ms: 600_000,
        batch_ms_behind: 600_000
      )

    {bs, _} = SpendChain.build(@p.genesis.header, 1)
    base = List.last(bs)
    c = length(bs) + 1
    x = block(base.header, c, 50 * @coin)
    submit(cs, bs ++ [x])
    State.commit_now(cs)
    :ok = sync_all(kv, cs)
    assert Follower.tip(kv, @cf) == {c, x.header.hash}

    # A longer fork from c - 1 wins; the disconnect of x is committed, the
    # fork's blocks are not.
    f1 = block(base.header, c, 49 * @coin)
    f2 = block(f1.header, c + 1, 49 * @coin)
    submit(cs, [f1, f2])
    view = State.view(cs)
    assert State.view_committed(view) == c - 1

    :ok = sync_all(kv, cs)
    assert Follower.tip(kv, @cf) == {c - 1, base.header.hash}
    assert Follower.hash_at(kv, @cf, c) == nil

    State.commit_now(cs)
    :ok = sync_all(kv, cs)
    assert Follower.tip(kv, @cf) == {c + 1, f2.header.hash}

    State.with_archive(cs, fn a ->
      for h <- 0..(c + 1),
          do:
            assert(
              Follower.hash_at(kv, @cf, h) == Archive.block_record!(a, Archive.id_at(a, h)).hash
            )
    end)

    GenServer.stop(cs)
    GenServer.stop(hs)
    KV.close(kv)
  end
end
