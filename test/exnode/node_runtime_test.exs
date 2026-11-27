defmodule Exnode.NodeRuntimeTest do
  @moduledoc """
  Tests for `Exnode.Node.Runtime` and `:protected` `Exnode.Chain.View`:
  * Zero `:persistent_term` churn across node start/stop, component restarts,
    and `ScriptExec` worker churn.
  * Killing `Node.Runtime` restarts downstream children cleanly under
    `:rest_for_one` with a freshly reopened RocksDB handle.
  * `Chain.View` is `:protected` ETS, rejects non-owner writes, and latches
    `ibd_done` concurrently from non-owner processes via `:atomics`.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.{Headers, State, View}
  alias Exnode.Codec.Block
  alias Exnode.Index.BlockFilter
  alias Exnode.Node.Runtime
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Validation.ScriptExec

  @p Exnode.ChainParams.get(:regtest)
  @chain Path.expand("../fixtures/regtest/chain150.bin", __DIR__)

  defp pt_keys do
    :persistent_term.get()
    |> Enum.map(&elem(&1, 0))
    |> MapSet.new()
  end

  defp exnode_pt_keys do
    for {k, _} <- :persistent_term.get(),
        match?(
          {m, _}
          when m in [
                 Exnode.Node,
                 Exnode.Chain.Headers,
                 Exnode.Chain.State,
                 Exnode.Index.BlockFilter,
                 Exnode.Index.Scripthash
               ],
          k
        ) or
          match?({Exnode.Validation.ScriptExec, :workers, _}, k) or
          match?({Exnode.Node, :stopping, _}, k),
        do: k
  end

  test "zero :persistent_term churn across node lifecycle, restarts, and ScriptExec worker churn",
       %{tmp_dir: dir} do
    # Warm up the one-time VM-global KV compression probe and Logger/OTP internals.
    _ = KV.compression()

    %{n: n, name: name} =
      TestNode.start(dir, block_filter_index: true, index_scripthash: true)

    assert exnode_pt_keys() == []
    before_keys = pt_keys()
    before_count = :persistent_term.info().count

    # Kill an idle ScriptExec worker -> replacement publishes updated worker list in ETS.
    exec = GenServer.whereis(n.script_exec)
    [idle | _] = :sys.get_state(exec).idle
    Process.exit(idle, :kill)
    _ = ScriptExec.stats(n.script_exec)

    assert exnode_pt_keys() == []
    assert :persistent_term.info().count == before_count
    assert pt_keys() == before_keys

    # Restart Headers (cascades ChainState, Relay, P2P, Services).
    hdr_pid = GenServer.whereis(n.headers)
    Process.exit(hdr_pid, :kill)
    wait_until(fn -> (p = GenServer.whereis(n.headers)) && p != hdr_pid end)
    wait_until(fn -> GenServer.whereis(n.chain_state) != nil end)

    assert exnode_pt_keys() == []

    # Mark stopping and stop the node; restart a fresh node on the same datadir.
    Exnode.Node.mark_stopping(name)
    assert Exnode.Node.stopping?(name)
    assert exnode_pt_keys() == []

    :ok = stop_supervised(name)
    assert :ets.whereis(n.handles) == :undefined
    assert exnode_pt_keys() == []

    %{name: name2} = TestNode.start(dir, name: name)
    refute Exnode.Node.stopping?(name2)
    assert exnode_pt_keys() == []
  end

  test "killing Node.Runtime reopens RocksDB and restarts downstream children cleanly", %{
    tmp_dir: dir
  } do
    %{n: n, name: name} = TestNode.start(dir, block_filter_index: true)

    bs =
      for raw <- Enum.take(BB.read_chain(@chain), 5),
          do: elem(Block.decode_exact(raw), 1)

    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)
    tip5 = List.last(bs).header.hash
    :ok = BlockFilter.sync_to(n.filter_index, tip5)

    rt_before = GenServer.whereis(n.runtime)
    kv_before_id = :erlang.phash2(Runtime.kv(name).db)
    cs_before = GenServer.whereis(n.chain_state)
    hdr_before = GenServer.whereis(n.headers)

    # Clear the test process's heap so it does not pin the RocksDB NIF handle
    # across the Node.Runtime :kill -> reopen cycle.
    :erlang.garbage_collect()

    ref = Process.monitor(rt_before)
    Process.exit(rt_before, :kill)
    assert_receive {:DOWN, ^ref, :process, ^rt_before, :killed}, 2_000

    # Wait for Node.Runtime and downstream chain processes to come back with new pids.
    wait_until(fn ->
      rt = GenServer.whereis(n.runtime)
      hdr = GenServer.whereis(n.headers)
      cs = GenServer.whereis(n.chain_state)
      bf = GenServer.whereis(n.filter_index)

      is_pid(rt) and rt != rt_before and is_pid(hdr) and hdr != hdr_before and is_pid(cs) and
        cs != cs_before and is_pid(bf)
    end)

    kv_after = Runtime.kv(name)
    assert :erlang.phash2(kv_after.db) != kv_before_id

    # Downstream readers/writers work against the reopened KV without stale-DB errors.
    assert State.tip(n.chain_state).hash == tip5
    assert Headers.best_header(n.headers).hash == tip5
    assert {:ok, _, _} = BlockFilter.get(n.filter_index, tip5)

    # Submitting another block succeeds on the reopened store.
    b6 = @chain |> BB.read_chain() |> Enum.at(5) |> Block.decode_exact() |> elem(1)
    assert {:ok, :connected} = State.submit_block(n.chain_state, b6)
    State.commit_now(n.chain_state)
    assert State.tip(n.chain_state).hash == b6.header.hash
  end

  test "Chain.View is :protected ETS and latches ibd_done concurrently from non-owner processes",
       %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    view = State.view(n.chain_state)
    idx = Headers.index(n.headers)

    assert :ets.info(view, :protection) == :protected
    assert :ets.info(view, :owner) == GenServer.whereis(n.archive_writer)

    # Direct writes from a non-owner process fail with ArgumentError.
    assert_raise ArgumentError, fn ->
      :ets.insert(view, {:tamper, true})
    end

    bs =
      for raw <- Enum.take(BB.read_chain(@chain), 5),
          do: elem(Block.decode_exact(raw), 1)

    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    t = List.last(bs).header.time

    # While tip is older than 24 h, non-owner readers see IBD = true.
    assert View.view_ibd?(view, idx, t + 48 * 3600, @p) == true

    # Concurrent non-owner readers latch ibd_done via :atomics without raising.
    results =
      1..16
      |> Enum.map(fn _ ->
        Task.async(fn -> View.view_ibd?(view, idx, t + 60, @p) end)
      end)
      |> Task.await_many(5_000)

    assert Enum.all?(results, &(&1 == false))

    # Latched: stays false even when clock moves past 24 h.
    assert View.view_ibd?(view, idx, t + 48 * 3600, @p) == false

    # active_gen seqlock slot is even when quiescent and bumps monotonically.
    gen = View.view_active_gen(view)
    assert gen > 0 and rem(gen, 2) == 0
    assert View.bump_active_gen(view) == gen + 1
    assert View.view_active_gen(view) == gen + 1
  end
end
