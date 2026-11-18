defmodule Exnode.Index.FollowerReorgRaceTest do
  @moduledoc """
  The follower reads the live chain table while it builds a batch, so a reorg
  can land mid-batch. Before the fix, the tip was re-read after the rows were
  built: the batch stored the old branch's block at height C (its rows and
  `"h"` entry) under the new branch's tip hash, so the next rewind saw an
  active tip and kept the stale rows forever (scripthash: phantom history;
  block filters: stuck on the missing parent).
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
    State.commit_now(cs)
  end

  defp nothing, do: fn _, _, _ -> [] end

  defp sync_all(kv, cs, connect) do
    case Follower.sync(kv, @cf, cs, connect, nothing()) do
      :more -> sync_all(kv, cs, connect)
      :done -> :ok
    end
  end

  defp active_hash(cs, h) do
    State.with_archive(cs, fn a -> Archive.block_record!(a, Archive.id_at(a, h)).hash end)
  end

  test "a reorg while a batch is built never leaves rows of one branch under the other's tip",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs = :"follower_race_cs_#{System.unique_integer([:positive])}"

    {:ok, _} =
      State.start_link(name: cs, params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"))

    {bs, _} = SpendChain.build(@p.genesis.header, 1)
    base = List.last(bs)
    c = length(bs) + 1
    submit(cs, bs)
    :ok = sync_all(kv, cs, nothing())
    assert Follower.tip(kv, @cf) == {c - 1, base.header.hash}

    x = block(base.header, c, 50 * @coin)
    submit(cs, [x])

    # A longer fork from c - 1 wins while the follower is building height c.
    f1 = block(base.header, c, 49 * @coin)
    f2 = block(f1.header, c + 1, 49 * @coin)
    test = self()

    racing = fn height, _id, _reader ->
      if height == c and !Process.get(:reorged) do
        Process.put(:reorged, true)
        submit(cs, [f1, f2])
        send(test, :reorged)
      end

      []
    end

    _ = Follower.sync(kv, @cf, cs, racing, nothing())
    assert_received :reorged
    :ok = sync_all(kv, cs, nothing())

    assert active_hash(cs, c) == f1.header.hash
    assert Follower.tip(kv, @cf) == {c + 1, f2.header.hash}
    # Every indexed height names the active block (no stale entry for x).
    for h <- 0..(c + 1),
        do: assert(Follower.hash_at(kv, @cf, h) == active_hash(cs, h), "height #{h}")

    GenServer.stop(cs)
    GenServer.stop(hs)
    KV.close(kv)
  end
end
