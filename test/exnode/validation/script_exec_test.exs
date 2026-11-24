defmodule Exnode.Validation.ScriptExecTest do
  @moduledoc """
  The shared script executor's scheduling contract,
  with deterministic barriers instead of timing: jobs run a test `run`
  function that reports itself and blocks until released.

  * Running jobs never exceed `workers`, across owners and the mempool path.
  * Lowest priority first (the oldest block's chunks), the mempool's
    reserved share, cancellation (queued dropped, running result discarded,
    the permit held until the job returns), release exactly once.
  * Worker death: a busy worker is not replaced (its native call may still
    run), an idle one is; a named executor restarted after a kill waits for
    the old workers; `GenServer.stop` waits for running jobs.
  * Instances are independent.
  """
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog

  alias Exnode.Validation.ScriptExec

  # A run function: tells the test which job started, then blocks until
  # `{:release, id}` (or `:release_all`) arrives at the worker. Tracks the
  # number of jobs running at once in `counter` (slot 1 now, slot 2 max).
  defp barrier_run(test, counter) do
    fn job ->
      id = job_id(job)
      now = :atomics.add_get(counter, 1, 1)
      bump_max(counter, now)
      send(test, {:started, id, self()})

      receive do
        {:release, ^id} -> :ok
        :release_all -> :ok
      end

      :atomics.sub(counter, 1, 1)
      Map.get(job, :result, :ok)
    end
  end

  defp bump_max(c, now) do
    m = :atomics.get(c, 2)
    if now > m and :atomics.compare_exchange(c, 2, m, now) != m, do: bump_max(c, now)
  end

  defp job_id(%{kind: :tx, raw: raw}), do: {:tx, raw}
  defp job_id(%{tag: tag}), do: tag

  defp block_job(tag, prio, extra \\ %{}),
    do: Map.merge(%{tag: tag, group: elem(tag, 0), prio: prio, checks: [], flags: 0}, extra)

  defp start(opts) do
    counter = :atomics.new(2, [])
    {:ok, ex} = ScriptExec.start_link(Keyword.merge([run: barrier_run(self(), counter)], opts))
    {ex, counter}
  end

  defp started(n) do
    for _ <- 1..n do
      assert_receive {:started, id, pid}, 2_000
      {id, pid}
    end
  end

  test "running jobs never exceed the cap; every result goes to the owner once" do
    {ex, counter} = start(workers: 3)
    ScriptExec.submit(ex, for(i <- 1..5, do: block_job({:b2, i}, {2, i})))
    ScriptExec.submit(ex, for(i <- 1..5, do: block_job({:b1, i}, {1, i})))
    running = started(3)
    refute_receive {:started, _, _}, 100
    assert :atomics.get(counter, 1) == 3
    assert ScriptExec.stats(ex).queued_block == 7

    # Release one at a time: each release lets exactly one more start.
    {_, _, done} =
      Enum.reduce(1..10, {running, 3, []}, fn _, {[{id, pid} | rest], n_started, done} ->
        send(pid, {:release, id})
        assert_receive {:script_exec, ^id, :ok, %{native_us: _}}, 2_000

        if n_started < 10,
          do: {rest ++ started(1), n_started + 1, [id | done]},
          else: {rest, n_started, [id | done]}
      end)

    assert length(Enum.uniq(done)) == 10
    refute_receive {:script_exec, _, _, _}, 100
    assert :atomics.get(counter, 2) == 3
    s = ScriptExec.stats(ex)
    assert s.running == 0 and s.queued_block == 0 and s.done_block == 10 and s.running_hwm == 3
  end

  test "lowest priority first: the oldest block's chunks run before a later block's" do
    {ex, _counter} = start(workers: 1)
    # Block 2's jobs arrive first and one starts at once; then block 1's.
    ScriptExec.submit(ex, for(i <- 1..3, do: block_job({:b2, i}, {2, i})))
    [{first, p}] = started(1)
    assert first == {:b2, 1}
    ScriptExec.submit(ex, for(i <- 1..3, do: block_job({:b1, i}, {1, i})))
    _ = ScriptExec.stats(ex)
    send(p, {:release, first})

    order =
      for _ <- 1..5 do
        [{id, pid}] = started(1)
        send(pid, {:release, id})
        id
      end

    assert order == [{:b1, 1}, {:b1, 2}, {:b1, 3}, {:b2, 2}, {:b2, 3}]
  end

  test "mempool calls share the cap and get their reserved worker ahead of queued block work" do
    {ex, counter} = start(workers: 2, other_reserve: 1)
    ScriptExec.submit(ex, for(i <- 1..4, do: block_job({:b, i}, {1, i})))
    [{a, pa}, {b, pb}] = started(2)
    test = self()
    v = Task.async(fn -> ScriptExec.verify(ex, "mempool-tx", [], 0) end)
    refute_receive {:started, _, _}, 100
    # A block job finishes: the freed worker goes to the waiting mempool call.
    send(pa, {:release, a})
    assert_receive {:script_exec, ^a, :ok, _}
    assert [{{:tx, "mempool-tx"}, pv}] = started(1)
    send(pv, {:release, {:tx, "mempool-tx"}})
    assert Task.await(v) == :ok
    _ = test
    send(pb, {:release, b})

    for _ <- 1..2 do
      [{id, pid}] = started(1)
      send(pid, {:release, id})
    end

    assert :atomics.get(counter, 2) == 2
  end

  test "cancel: queued jobs dropped, a running one keeps its worker until it returns and its result is discarded" do
    {ex, counter} = start(workers: 1)

    ScriptExec.submit(ex, [
      block_job({:x, 1}, {1, 1}),
      block_job({:x, 2}, {1, 2}),
      block_job({:y, 1}, {2, 1})
    ])

    [{{:x, 1}, p1}] = started(1)
    ScriptExec.cancel(ex, [:x])
    # The cancelled running job still holds the only worker: nothing else starts.
    refute_receive {:started, _, _}, 100
    assert ScriptExec.stats(ex).running == 1
    send(p1, {:release, {:x, 1}})
    # Its result is discarded; {:x, 2} was dropped; {:y, 1} runs next.
    [{{:y, 1}, py}] = started(1)
    refute_received {:script_exec, {:x, _}, _, _}
    send(py, {:release, {:y, 1}})
    assert_receive {:script_exec, {:y, 1}, :ok, _}
    refute_receive {:started, _, _}, 100
    s = ScriptExec.stats(ex)
    assert s.cancelled_queued == 1 and s.discarded == 1 and s.running == 0
    # Cancelling again, or an unknown group, changes nothing (release exactly once).
    ScriptExec.cancel(ex, [:x, :never])
    assert ScriptExec.stats(ex).running == 0
    assert :atomics.get(counter, 1) == 0
  end

  test "an owner's death cancels its queued jobs" do
    {ex, _counter} = start(workers: 1)
    test = self()

    owner =
      spawn(fn ->
        ScriptExec.submit(ex, [block_job({:o, 1}, {1, 1}), block_job({:o, 2}, {1, 2})])
        send(test, :submitted)
        receive do: (:never -> :ok)
      end)

    assert_receive :submitted
    [{{:o, 1}, p}] = started(1)
    Process.exit(owner, :kill)
    # The kill and the executor's DOWN are asynchronous to this process: a call
    # alone can be served before the DOWN arrives, so wait for the cancel itself.
    Exnode.Test.Wait.wait_until(fn -> ScriptExec.stats(ex).cancelled_queued == 1 end)
    send(p, {:release, {:o, 1}})
    refute_receive {:started, _, _}, 200
    assert ScriptExec.stats(ex).cancelled_queued == 1
  end

  test "a busy worker that dies is not replaced (its native call may still run); an idle one is" do
    Process.flag(:trap_exit, true)
    {ex, _counter} = start(workers: 2)
    ScriptExec.submit(ex, [block_job({:k, 1}, {1, 1})])
    [{{:k, 1}, busy}] = started(1)
    ex_ref = Process.monitor(ex)
    # Its job is reported as a crash; capacity is now 1, not 2.
    assert capture_log(fn ->
             Process.exit(busy, :kill)

             assert_receive {:script_exec, {:k, 1}, {:crash, {:exit, {:worker_exit, :killed}}, _},
                             _},
                            2_000
           end) =~ "worker died running a job"

    s = ScriptExec.stats(ex)
    assert s.workers == 1 and s.lost == 1

    # Kill the idle survivor: it is replaced (no native work was running).
    [idle] = :sys.get_state(ex).idle
    Process.exit(idle, :kill)
    _ = ScriptExec.stats(ex)
    s = ScriptExec.stats(ex)
    assert s.workers == 1 and s.lost == 1
    refute_received {:DOWN, ^ex_ref, _, _, _}
  end

  test "a named executor restarted after being killed waits for the old workers' running jobs" do
    Process.flag(:trap_exit, true)
    name = :"exec_fence_#{System.unique_integer([:positive])}"
    {ex, _counter} = start(workers: 1, name: name)
    ScriptExec.submit(ex, [block_job({:f, 1}, {1, 1})])
    [{{:f, 1}, worker}] = started(1)
    Process.exit(ex, :kill)
    assert_receive {:EXIT, ^ex, :killed}
    # The worker traps exits: it is still in its job, not interrupted.
    assert Process.alive?(worker)

    test = self()

    restarter =
      spawn(fn ->
        {:ok, ex2} = ScriptExec.start_link(name: name, workers: 1, run: fn _ -> :ok end)
        send(test, {:restarted, ex2})
        receive do: (:stop -> GenServer.stop(ex2))
      end)

    # The new executor is held at init until the old job returns.
    refute_receive {:restarted, _}, 200
    send(worker, {:release, {:f, 1}})
    assert_receive {:restarted, _ex2}, 2_000
    refute Process.alive?(worker)
    send(restarter, :stop)
  end

  test "GenServer.stop waits for running jobs to return" do
    {ex, _counter} = start(workers: 1)
    Process.unlink(ex)
    ScriptExec.submit(ex, [block_job({:s, 1}, {1, 1})])
    [{{:s, 1}, worker}] = started(1)
    stopper = Task.async(fn -> GenServer.stop(ex, :shutdown, :infinity) end)
    refute Task.yield(stopper, 200)
    assert Process.alive?(worker)
    send(worker, {:release, {:s, 1}})
    assert Task.await(stopper) == :ok
    refute Process.alive?(worker)
  end

  test "two executors are independent: each enforces its own cap" do
    {ex1, c1} = start(workers: 1)
    {ex2, c2} = start(workers: 1)
    ScriptExec.submit(ex1, [block_job({:a, 1}, {1, 1}), block_job({:a, 2}, {1, 2})])
    ScriptExec.submit(ex2, [block_job({:b, 1}, {1, 1}), block_job({:b, 2}, {1, 2})])
    first = started(2)
    assert first |> Enum.map(&elem(&1, 0)) |> Enum.sort() == [{:a, 1}, {:b, 1}]
    refute_receive {:started, _, _}, 100
    for ex <- [ex1, ex2], do: assert(ScriptExec.stats(ex).running == 1)
    for {_id, pid} <- first, do: send(pid, :release_all)
    for {_id, pid} <- started(2), do: send(pid, :release_all)
    assert :atomics.get(c1, 2) == 1 and :atomics.get(c2, 2) == 1
  end

  test "real kernel jobs: a valid and an invalid chunk are classified" do
    {:ok, ex} = ScriptExec.start_link(workers: 2)
    # OP_TRUE spends verify; OP_FALSE ones do not. A minimal tx: one input, one output.
    tx = Exnode.Test.BlockBuilder.spend_op_true(<<1::256>>, 0, 1_000)
    ok = [{tx.raw, [{<<0x51>>, 2_000}]}]
    bad = [{tx.raw, [{<<0x00>>, 2_000}]}]

    ScriptExec.submit(ex, [
      block_job({:ok, 0}, {1, 0}, %{checks: ok}),
      block_job({:bad, 0}, {1, 1}, %{checks: bad})
    ])

    assert_receive {:script_exec, {:ok, 0}, :ok, %{txs: 1}}, 5_000

    assert_receive {:script_exec, {:bad, 0}, {:invalid, "block-script-verify-flag-failed"}, _},
                   5_000

    # A kernel API error is local, not invalid (wrong number of spent outputs).
    ScriptExec.submit(ex, [block_job({:api, 0}, {1, 2}, %{checks: [{tx.raw, []}]})])

    assert_receive {:script_exec, {:api, 0}, {:local, {:kernel_api, :input_count_mismatch}}, _},
                   5_000
  end
end
