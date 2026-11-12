defmodule Exnode.Chain.CommitCadenceTest do
  @moduledoc """
  The batch's age rule (Core `FlushStateToDisk` role): near the best header
  a batch is committed once its oldest block is `batch_ms` old; while the
  tip is at least `batch_blocks` behind the best header (IBD) the limit is
  `batch_ms_behind`, so the block and byte limits set the cadence. Each
  commit voids the prefetched answers in flight, and a short timer on slow
  blocks left prefetch nothing to use.
  """
  use ExUnit.Case, async: true

  alias Exnode.Archive
  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  # From the state, not `State.with_archive/2`, which commits first.
  defp committed(cs), do: Archive.committed_tip(:sys.get_state(cs).a).height

  test "far behind the best header, a batch older than batch_ms is not committed; near it, it is",
       %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    # Every batch is past batch_ms at once; batch_ms_behind never passes.
    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        batch_blocks: 128,
        batch_ms: 0,
        batch_ms_behind: 3_600_000,
        prefetch_depth: 0
      )

    # 150 headers known: blocks 1..22 leave the tip 128 or more behind.
    {:ok, _} = Headers.process_headers(hs, Enum.map(bs, & &1.header))

    for b <- Enum.take(bs, 22) do
      assert {:ok, :connected} = State.submit_block(cs, b)
      assert committed(cs) == 0
    end

    assert State.tip(cs).height == 22

    # Block 23: 127 behind, so the 0 ms age rule applies again.
    assert {:ok, :connected} = State.submit_block(cs, Enum.at(bs, 22))
    assert committed(cs) == 23
  end
end
