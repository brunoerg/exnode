defmodule Exnode.Chain.GcSettingsTest do
  @moduledoc """
  The chain state's per-process GC settings reach it through the node's
  options, survive a supervisor restart, and are not applied to chain
  states started directly (tests): `min_heap_size` and the binary virtual
  heap floor (`State.default_min_bin_vheap_size/0`). Effective values are
  read back from the process (the VM rounds them up to its heap sizes).
  """
  use Exnode.NodeCase

  alias Exnode.Chain.{Headers, State}
  alias Exnode.Store.KV

  @p Exnode.ChainParams.get(:regtest)

  defp gc(pid), do: elem(Process.info(pid, :garbage_collection), 1)

  # The VM's defaults, as a fresh process has them.
  defp vm_defaults do
    pid = spawn(fn -> receive do: (:stop -> :ok) end)
    d = gc(pid)
    send(pid, :stop)
    d
  end

  test "a node's chain state has both floors, also after a crash restart", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    cs = GenServer.whereis(n.chain_state)
    g = gc(cs)
    assert g[:min_heap_size] >= State.default_min_heap_size()
    assert g[:min_bin_vheap_size] >= State.default_min_bin_vheap_size()

    ref = Process.monitor(cs)
    Process.exit(cs, :kill)
    assert_receive {:DOWN, ^ref, _, _, _}
    wait_until(fn -> (pid = GenServer.whereis(n.chain_state)) && pid != cs end)
    g = gc(GenServer.whereis(n.chain_state))
    assert g[:min_heap_size] >= State.default_min_heap_size()
    assert g[:min_bin_vheap_size] >= State.default_min_bin_vheap_size()
  end

  test "chain_state_min_bin_vheap: nil keeps the VM default", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir, chain_state_min_bin_vheap: nil)

    assert gc(GenServer.whereis(n.chain_state))[:min_bin_vheap_size] ==
             vm_defaults()[:min_bin_vheap_size]
  end

  test "a directly started chain state keeps the VM defaults", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"))
    d = vm_defaults()
    g = gc(cs)
    assert g[:min_heap_size] == d[:min_heap_size]
    assert g[:min_bin_vheap_size] == d[:min_bin_vheap_size]
    GenServer.stop(cs)
    GenServer.stop(hs)
    KV.close(kv)
  end
end
