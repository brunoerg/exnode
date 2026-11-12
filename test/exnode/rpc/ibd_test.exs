defmodule Exnode.RPC.IBDTest do
  @moduledoc """
  SVC-6 (STATE_MACHINES.md): `initialblockdownload` was computed apart by
  RPC (tip age only, committed tip) and peers (age or minimum work), and
  never latched: once caught up, a tip older than 24 h put the node back in
  IBD. Core latches it (`m_cached_finished_ibd`); both read
  `ChainState.view_ibd?/4` now.
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Clock
  alias Exnode.Codec.Block
  alias Exnode.RPC.Methods
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  test "IBD ends once the tip is recent and stays ended when it ages", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    name = :"ibd_cs_#{System.unique_integer([:positive])}"

    {:ok, _} =
      State.start_link(name: name, params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"))

    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(name, b)
    t = List.last(bs).header.time

    clock = Clock.new()
    ctx = %{headers: hs, chain_state: name, params: @p, clock: clock}

    ibd = fn ->
      elem(Methods.call("getblockchaininfo", [], ctx), 1)
      |> Jason.encode!()
      |> Jason.decode!()
      |> Map.fetch!("initialblockdownload")
    end

    Clock.set(clock, t + 48 * 3600)
    assert ibd.() == true

    Clock.set(clock, t + 60)
    assert ibd.() == false

    # Latched: the tip ageing again does not put the node back in IBD.
    Clock.set(clock, t + 48 * 3600)
    assert ibd.() == false
  end
end
