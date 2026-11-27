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

  test "explicit GC floors reach the node's chain state and survive a crash restart",
       %{tmp_dir: dir} do
    heap = 2_000_000
    bin_vheap = 4_000_000

    %{n: n} =
      TestNode.start(dir,
        chain_state_min_heap: heap,
        chain_state_min_bin_vheap: bin_vheap
      )

    cs = GenServer.whereis(n.chain_state)
    g = gc(cs)
    assert g[:min_heap_size] >= heap
    assert g[:min_bin_vheap_size] >= bin_vheap

    ref = Process.monitor(cs)
    Process.exit(cs, :kill)
    assert_receive {:DOWN, ^ref, _, _, _}
    wait_until(fn -> (pid = GenServer.whereis(n.chain_state)) && pid != cs end)
    g = gc(GenServer.whereis(n.chain_state))
    assert g[:min_heap_size] >= heap
    assert g[:min_bin_vheap_size] >= bin_vheap
  end

  test "node defaults keep the VM GC defaults", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    d = vm_defaults()
    g = gc(GenServer.whereis(n.chain_state))
    assert g[:min_heap_size] == d[:min_heap_size]
    assert g[:min_bin_vheap_size] == d[:min_bin_vheap_size]
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

  test "GcProbe starts cleanly and never clobbers an existing VM system_monitor" do
    prev = :erlang.system_monitor()

    try do
      holder = spawn_link(fn -> receive do: (:stop -> :ok) end)
      :erlang.system_monitor(holder, [{:long_schedule, 1_000}])
      assert {:erlang_monitor, {^holder, _}} = {:erlang_monitor, :erlang.system_monitor()}

      target = spawn_link(fn -> receive do: (:stop -> :ok) end)
      {probe_pid, _c} = probe = Exnode.Chain.GcProbe.start(target)
      assert is_map(Exnode.Chain.GcProbe.take(probe))
      # Existing monitor is untouched.
      assert {^holder, _} = :erlang.system_monitor()

      send(target, :stop)
      send(holder, :stop)
      Process.unlink(probe_pid)
      Process.exit(probe_pid, :kill)
    after
      case prev do
        :undefined ->
          :erlang.system_monitor(:undefined)

        {p, opts} ->
          if Process.alive?(p),
            do: :erlang.system_monitor(p, opts),
            else: :erlang.system_monitor(:undefined)
      end
    end
  end
end
