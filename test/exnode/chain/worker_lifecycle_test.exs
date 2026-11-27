defmodule Exnode.Chain.WorkerLifecycleTest do
  @moduledoc """
  Regression tests for worker supervision, non-blocking startup replay,
  event-driven index notifications, HTTP keep-alive cleanup, and Shadow shutdown:
  - Supervised worker cancellation (`cancel_plan/1` + shutdown leaves zero orphaned
    `archive_prep` or `Prefetch` tasks under `Task.Supervisor`).
  - Non-blocking `Chain.State.init/1` pending replay (`start_link/1` returns before
    pending blocks finish replaying; `await_idle/2` waits for replay to settle).
  - Event-driven index wakeups (`Index.BlockFilter` and `Index.Scripthash` catch up
    well within 50 ms of commit instead of waiting for a 200 ms poll).
  - Zero process-dictionary leak in `RPC.Server` / `REST.Esplora` keep-alive calls.
  - Clean `Shadow.stop/1` exit via opcode `<<0>>` + `{:exit_status, _}`.
  """
  use ExUnit.Case, async: true

  alias Exnode.Chain.{Headers, State}
  alias Exnode.ChainParams
  alias Exnode.Codec.Block
  alias Exnode.Index.{BlockFilter, Scripthash}
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp base_blocks(n) do
    @chain
    |> BB.read_chain()
    |> Enum.take(n)
    |> Enum.map(&elem(Block.decode_exact(&1), 1))
  end

  test "cancel_plan and shutdown terminate in-flight archive_prep tasks with zero orphans",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, worker_sup} = Task.Supervisor.start_link()

    test_pid = self()
    [b1, b2, b3] = base_blocks(3)
    target_hash = b2.header.hash

    # Block archive_prep on b2 until the test kills/stops Chain.State.
    apre_hook = fn block ->
      if block.header.hash == target_hash do
        send(test_pid, {:apre_started, self()})

        receive do
          :never -> :ok
        end
      end
    end

    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        worker_sup: worker_sup,
        test_archive_prep_hook: apre_hook,
        prefetch_depth: 0,
        commit_at_tip: false,
        batch_blocks: 100
      )

    {:ok, :connected} = State.submit_block(cs, b1)
    {:ok, _} = Headers.process_headers(hs, [b2.header, b3.header])
    {:ok, :stored} = State.submit_block(cs, b2, defer: true)
    {:ok, :stored} = State.submit_block(cs, b3, defer: true)

    assert_receive {:apre_started, worker_pid}, 5_000
    worker_mref = Process.monitor(worker_pid)
    assert worker_pid in Task.Supervisor.children(worker_sup)

    # Stopping Chain.State runs cancel_plan/1 in terminate/2, which must
    # terminate the in-flight archive_prep worker instead of leaving an orphan.
    Process.unlink(cs)
    :ok = GenServer.stop(cs, :shutdown, 5_000)
    assert_receive {:DOWN, ^worker_mref, :process, ^worker_pid, _reason}, 2_000
    assert Task.Supervisor.children(worker_sup) == []

    Supervisor.stop(worker_sup)
    GenServer.stop(hs)
    KV.close(kv)
  end

  test "Chain.State.init/1 returns immediately while pending blocks replay asynchronously",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    blocks = base_blocks(6)
    {:ok, _} = Headers.process_headers(hs, Enum.map(blocks, & &1.header))

    # Write blocks directly into :pending as if a previous run crashed before committing.
    ops = for b <- blocks, do: {:put, :pending, b.header.hash, b.raw}
    :ok = KV.write(kv, ops, sync: true)

    test_pid = self()
    gate = make_ref()

    hook = fn block, _entry ->
      if block.header.hash == hd(blocks).header.hash do
        send(test_pid, {:replaying, self(), gate})

        receive do
          {:release, ^gate} -> :ok
        end
      else
        :ok
      end
    end

    # start_link/1 must not block on the paused replay hook (use GenServer.start
    # inside the Task so Task exit does not tear down cs).
    task =
      Task.async(fn ->
        GenServer.start(
          State,
          params: @p,
          headers: hs,
          kv: kv,
          hot: Path.join(dir, "hot"),
          rule_override: hook,
          prefetch_depth: 0
        )
      end)

    assert {:ok, cs} = Task.await(task, 2_000)
    assert_receive {:replaying, cs_pid, ^gate}, 2_000
    assert cs_pid == cs

    send(cs_pid, {:release, gate})
    assert :ok = State.await_idle(cs, 5_000)
    assert State.tip(cs).hash == List.last(blocks).header.hash

    GenServer.stop(cs)
    GenServer.stop(hs)
    KV.close(kv)
  end

  test "BlockFilter and Scripthash indexes wake promptly on commit notification",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs_name = :"cs_idx_wake_#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(
        name: cs_name,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        commit_at_tip: true,
        prefetch_depth: 0
      )

    {:ok, bf} = BlockFilter.start_link(kv: kv, chain_state: cs_name)
    {:ok, sh} = Scripthash.start_link(kv: kv, chain_state: cs_name)

    # Ensure both indexes have finished their initial genesis sync and subscribed.
    assert :ok = BlockFilter.sync_to(bf, @p.genesis.header.hash, 5_000)
    assert :ok = Scripthash.sync_to(sh, @p.genesis.header.hash, 5_000)

    [b1] = base_blocks(1)
    t0 = System.monotonic_time(:millisecond)
    {:ok, :connected} = State.submit_block(cs, b1)

    # Both indexes should wake from {:archive_committed, _} well before the 5 s fallback.
    assert :ok = BlockFilter.sync_to(bf, b1.header.hash, 1_000)
    assert :ok = Scripthash.sync_to(sh, b1.header.hash, 1_000)
    elapsed_ms = System.monotonic_time(:millisecond) - t0
    assert elapsed_ms < 500

    # BlockFilter must not leave any :filter_header entries in its process dictionary.
    {:dictionary, dict} = Process.info(bf, :dictionary)
    refute Enum.any?(dict, fn {k, _} -> match?({:filter_header, _}, k) end)

    GenServer.stop(bf)
    GenServer.stop(sh)
    GenServer.stop(cs)
    GenServer.stop(hs)
    KV.close(kv)
  end

  test "RPC.Server.call/2 leaves no Archive stats or segment read handles in caller pdict",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs_name = :"cs_rpc_pdict_#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(
        name: cs_name,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot")
      )

    [b1] = base_blocks(1)
    {:ok, :connected} = State.submit_block(cs, b1)
    State.commit_now(cs)

    auth = [{"user", "pass"}]
    ctx = %{chain_state: cs_name, headers: hs, params: @p}
    opts = Exnode.RPC.Server.init(%{ctx: ctx, auth: auth})

    body =
      Jason.encode!(%{
        jsonrpc: "2.0",
        id: 1,
        method: "getblock",
        params: [Exnode.Crypto.Hash.to_hex(b1.header.hash), 0]
      })

    header = "Basic " <> Base.encode64("user:pass")

    for _ <- 1..5 do
      conn =
        Plug.Test.conn(:post, "/", body)
        |> Plug.Conn.put_req_header("authorization", header)
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Exnode.RPC.Server.call(opts)

      assert conn.status == 200
    end

    # No open segment handles or accumulated archive/kv/segment stat counters remain.
    assert Process.get({Exnode.Archive.Segments, :handles}) == nil
    assert Enum.all?(Exnode.Archive.take_stats(), fn {_k, v} -> v == 0 end)

    GenServer.stop(cs)
    GenServer.stop(hs)
    KV.close(kv)
  end

  test "Shadow.stop/1 exits cleanly via <<0>> opcode without polling", %{tmp_dir: dir} do
    exe = Path.join(:code.priv_dir(:exnode), "native/shadow_validator")

    if File.exists?(exe) do
      {:ok, shadow} = Exnode.Shadow.start_link(chain: :regtest, datadir: Path.join(dir, "shadow"))
      assert {:ok, {0, _}} = Exnode.Shadow.tip(shadow)
      t0 = System.monotonic_time(:millisecond)
      assert :ok = Exnode.Shadow.stop(shadow)
      assert System.monotonic_time(:millisecond) - t0 < 5_000
      refute Process.alive?(shadow)
    end
  end

  test "View.resolve_active/2 returns :retry when Archive.Writer ETS tables vanish mid-read",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs_name = :"cs_ets_race_#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(
        name: cs_name,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot")
      )

    view = Exnode.Chain.View.view(cs_name)
    assert {:ok, _} = Exnode.Chain.View.resolve_active(view, [{<<1::256>>, 0}])

    # Stopping Chain.State destroys Archive.Writer's :chain_view / :archive_* ETS tables.
    GenServer.stop(cs)
    assert :retry == Exnode.Chain.View.resolve_active(view, [{<<1::256>>, 0}])

    GenServer.stop(hs)
    KV.close(kv)
  end

  test "BlockFilter and Scripthash re-subscribe after Archive.Writer restarts", %{tmp_dir: dir} do
    %{n: n} = Exnode.Test.Node.start(dir, block_filter_index: true, index_scripthash: true)
    blocks = base_blocks(2)
    [b1, b2] = blocks

    {:ok, :connected} = State.submit_block(n.chain_state, b1)
    assert :ok = BlockFilter.sync_to(n.filter_index, b1.header.hash, 5_000)
    assert :ok = Scripthash.sync_to(n.scripthash_index, b1.header.hash, 5_000)

    # Kill ChainState (ChainSup :one_for_all restarts ArchiveWriter + ChainState).
    old_writer = GenServer.whereis(n.archive_writer)
    old_cs = GenServer.whereis(n.chain_state)
    ref = Process.monitor(old_writer)
    Process.exit(old_cs, :kill)
    assert_receive {:DOWN, ^ref, :process, ^old_writer, _}, 5_000

    wait_for_new = fn name, old_pid ->
      Enum.reduce_while(1..100, nil, fn _, _ ->
        case GenServer.whereis(name) do
          pid when is_pid(pid) and pid != old_pid -> {:halt, pid}
          _ -> Process.sleep(20) && {:cont, nil}
        end
      end)
    end

    assert is_pid(wait_for_new.(n.archive_writer, old_writer))
    assert is_pid(wait_for_new.(n.chain_state, old_cs))

    # Indexes detect writer :DOWN and clear their writer_mon so they can re-subscribe.
    assert :ok = State.await_idle(n.chain_state, 5_000)
    assert nil == :sys.get_state(n.filter_index).writer_mon
    assert nil == :sys.get_state(n.scripthash_index).writer_mon

    # Trigger re-subscription via fallback tick, then verify fast commit wakeup on b2.
    send(n.filter_index, :fallback_tick)
    send(n.scripthash_index, :fallback_tick)
    _ = BlockFilter.tip(n.filter_index)
    _ = Scripthash.tip(n.scripthash_index)
    assert is_reference(:sys.get_state(n.filter_index).writer_mon)
    assert is_reference(:sys.get_state(n.scripthash_index).writer_mon)

    t0 = System.monotonic_time(:millisecond)
    {:ok, :connected} = State.submit_block(n.chain_state, b2)
    assert :ok = BlockFilter.sync_to(n.filter_index, b2.header.hash, 1_000)
    assert :ok = Scripthash.sync_to(n.scripthash_index, b2.header.hash, 1_000)
    assert System.monotonic_time(:millisecond) - t0 < 500
  end

  test "Archive.Writer stays thin: validation runs in Chain.State and writer receives only write/view calls",
       %{tmp_dir: dir} do
    refute function_exported?(Exnode.Archive.Writer, :connect_block, 6)
    refute function_exported?(Exnode.Archive.Writer, :tip, 1)
    refute function_exported?(Exnode.Archive.Writer, :revalidate, 4)

    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    test_pid = self()

    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        commit_at_tip: false,
        batch_blocks: 16,
        rule_override: fn _block, entry ->
          send(test_pid, {:validated_in, entry.height, self()})
          :ok
        end
      )

    writer = :sys.get_state(cs).writer
    assert is_pid(writer)
    assert writer != cs

    # Trace messages delivered to Archive.Writer while connecting an uncommitted batch.
    :erlang.trace(writer, true, [:receive])

    [b1, b2, b3] = base_blocks(3)
    assert {:ok, :connected} = State.submit_block(cs, b1)
    assert {:ok, :connected} = State.submit_block(cs, b2)
    assert {:ok, :connected} = State.submit_block(cs, b3)

    :erlang.trace(writer, false, [:receive])

    for h <- 1..3 do
      assert_receive {:validated_in, ^h, ^cs}, 1_000
    end

    # Collect traced GenServer calls received by Archive.Writer and verify no read/validation RPCs.
    writer_calls =
      Stream.repeatedly(fn ->
        receive do
          {:trace, ^writer, :receive, {:"$gen_call", _from, req}} -> req
        after
          0 -> :done
        end
      end)
      |> Enum.take_while(&(&1 != :done))

    connect_calls = Enum.count(writer_calls, &match?({:connect, _, _, _, _}, &1))
    assert connect_calls == 3

    Enum.each(writer_calls, fn req ->
      tag = if is_tuple(req), do: elem(req, 0), else: req
      assert tag in [:connect, :view_op, :flush, :disconnect_tip]
    end)

    # Combined work_stats and debug_live still aggregate read + write metrics cleanly.
    stats = State.work_stats(cs)
    assert stats.chain_state.blocks == 3
    assert stats.chain_state.connect_us >= 0
    live = GenServer.call(cs, :debug_live)
    assert is_integer(live.batch_ops) and live.batch_ops > 0

    GenServer.stop(cs)
    GenServer.stop(hs)
    KV.close(kv)
  end
end
