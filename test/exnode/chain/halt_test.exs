defmodule Exnode.Chain.HaltTest do
  @moduledoc """
  CS-2 (STATE_MACHINES.md): a shadow-divergence halt is durable. Before, it
  lived only in memory: any chain-state restart replayed every held
  `pending` block (descendants of the divergent one included) and committed
  them before the shadow could halt again, and a restart without `--shadow`
  never halted at all. Now:
  1. the halt writes a synced mark before taking effect;
  2. a restart (here without any shadow) stays halted and connects nothing,
     the held blocks kept;
  3. only an explicit clear (`clear_halt/1`, or the mix task offline)
     resumes connection, and the clear survives a restart.
  """
  use Exnode.NodeCase, async: true
  import ExUnit.CaptureLog

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp start_cs(dir, kv, hs) do
    name = :"halt_cs_#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), name: name)

    {cs, name}
  end

  test "a halt survives restarts without a shadow; only clear_halt resumes", %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    {before, later} = Enum.split(bs, 140)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {cs, name} = start_cs(dir, kv, hs)
    for b <- before, do: {:ok, :connected} = State.submit_block(cs, b)
    assert State.clear_halt(cs) == :not_halted

    capture_log(fn ->
      GenServer.cast(cs, {:halt, :shadow_divergence})
      # A second divergence does not replace the first reason.
      GenServer.cast(cs, {:halt, :other})
      assert GenServer.call(cs, :halted) == :shadow_divergence
    end)

    assert %{reason: :shadow_divergence, height: 140} = State.halt_mark(kv)

    # Blocks keep arriving while halted: stored and held, never connected.
    for b <- later, do: {:ok, :stored} = State.submit_block(cs, b, defer: true)
    assert State.tip(cs).height == 140

    # Restart, no shadow: still halted, startup replay connects nothing.
    GenServer.stop(cs)
    log = capture_log(fn -> send(self(), {:cs, start_cs(dir, kv, hs)}) end)
    assert_received {:cs, {cs2, name2}}
    assert log =~ "block connection HALTED"
    assert GenServer.call(cs2, :halted) == :shadow_divergence
    assert State.view_halted(State.view(name2)) == :shadow_divergence
    assert State.tip(cs2).height == 140

    # The operator clears it: the held blocks connect.
    capture_log(fn -> assert State.clear_halt(cs2) == :shadow_divergence end)
    assert State.halt_mark(kv) == nil
    assert wait_until(fn -> State.tip(cs2).height == 150 end)
    assert State.view_halted(State.view(name2)) == false
    State.commit_now(cs2)
    GenServer.stop(cs2)

    {cs3, _} = start_cs(dir, kv, hs)
    assert GenServer.call(cs3, :halted) == false
    assert State.tip(cs3).height == 150
    _ = name
  end
end
