defmodule Exnode.Chain.PrepWorkerTest do
  @moduledoc """
  The asynchronous preparation worker (`prep_mode: :worker`), driven
  deterministically: the worker runs a test hook before each check that can
  hold a chosen block until the test releases it, or raise; script jobs can
  be held through `script_run:`. Blocks go in deferred so the test keeps
  control while work is held.
  """
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog
  import Exnode.Test.Wait

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Validation.ScriptExec

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  defp control, do: :ets.new(:control, [:public, :set])

  # In the worker, for every job: {:prep_started, hash, tag} to the test;
  # then `{:hold_prep, hash}` waits for {:release_prep, hash};
  # `{:raise_prep, hash}` raises.
  defp prep_hook(test, ctl) do
    fn tag, block ->
      h = block.header.hash
      send(test, {:prep_started, h, tag})

      cond do
        :ets.member(ctl, {:raise_prep, h}) ->
          raise "injected preparation bug"

        :ets.member(ctl, {:hold_prep, h}) ->
          send(test, {:prep_held, h, self()})
          receive do: ({:release_prep, ^h} -> :ok)

        true ->
          :ok
      end
    end
  end

  # Script jobs: `{:hold_script, raw}` waits; `{:fail_script, raw}` is invalid.
  defp script_run(test, ctl) do
    fn job ->
      raws = for {raw, _} <- job.checks, do: raw

      cond do
        r = Enum.find(raws, &:ets.member(ctl, {:hold_script, &1})) ->
          send(test, {:script_held, r, self()})
          receive do: ({:release_script, ^r} -> :ok)

          if :ets.member(ctl, {:fail_script, r}),
            do: {:invalid, "block-script-verify-flag-failed"},
            else: ScriptExec.run_job(job)

        true ->
          ScriptExec.run_job(job)
      end
    end
  end

  defp start(dir, name, ctl, opts \\ []) do
    {:ok, kv} = KV.open(Path.join([dir, name, "kv"]))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs = start_cs(dir, name, kv, hs, ctl, opts)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    flush()
    %{cs: cs, hs: hs, kv: kv, bs: bs, tip: List.last(bs).header}
  end

  defp start_cs(dir, name, kv, hs, ctl, opts) do
    {:ok, cs} =
      State.start_link(
        [
          params: @p,
          headers: hs,
          kv: kv,
          hot: Path.join([dir, name, "hot"]),
          crash_dir: Path.join([dir, name, "crashes"]),
          listeners: [self()],
          prep_mode: :worker,
          test_prep_hook: prep_hook(self(), ctl),
          script_run: script_run(self(), ctl),
          script_workers: 4
        ] ++ opts
      )

    cs
  end

  defp flush do
    receive do
      {:block_connected, _, _} -> flush()
    after
      0 -> :ok
    end
  end

  defp cb(n, h), do: hd(Enum.at(n.bs, h - 1).txs).txid
  defp spend(txid, value), do: BB.spend_op_true(txid, 0, value)

  defp chain(prev, start_h, specs) do
    {blocks, _} =
      Enum.map_reduce(Enum.with_index(specs, 1), prev, fn {txs, i}, prev ->
        b = BB.build(prev, [BB.coinbase(start_h + i, 25 * @coin) | txs])
        {b, b.header}
      end)

    blocks
  end

  defp deferred(n, blocks) do
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(blocks, & &1.header))

    for b <- blocks,
        do:
          {:ok, :stored} =
            State.submit_block(n.cs, b, defer: true, requested: true, source: self())
  end

  defp tip(n), do: State.tip(n.cs).hash
  defp status(n, b), do: HeaderIndex.lookup(Headers.index(n.hs), b.header.hash).status
  defp pstat(n, k), do: Map.get(State.work_stats(n.cs).pipeline, k, 0)

  test "held preparation: earlier blocks retire, calls are served, the held block and successors wait",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "a", ctl)
    [b1, b2, b3] = blocks = chain(n.tip, 150, for(h <- 1..3, do: [spend(cb(n, h), 50 * @coin)]))
    :ets.insert(ctl, {{:hold_prep, b2.header.hash}})
    jobs0 = pstat(n, :prep_jobs)
    deferred(n, blocks)
    h2 = b2.header.hash
    assert_receive {:prep_held, ^h2, worker}, 5_000
    wait_until(fn -> tip(n) == b1.header.hash end)

    # Served while the worker holds b2; b3 is not prepared (it needs b2's delta).
    assert State.precheck_block(n.cs, b3.header, true) == {:ok, :duplicate}
    assert pstat(n, :prep_jobs) - jobs0 == 2
    assert tip(n) == b1.header.hash

    send(worker, {:release_prep, h2})
    wait_until(fn -> tip(n) == b3.header.hash end)
    assert pstat(n, :prep_jobs) - jobs0 == 3
  end

  test "a spender is prepared while its predecessor's scripts are held; success stays contingent",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "b", ctl)
    t1 = spend(cb(n, 1), 50 * @coin)
    t2 = spend(t1.txid, 50 * @coin)
    [b1, b2] = blocks = chain(n.tip, 150, [[t1], [t2]])
    :ets.insert(ctl, {{:hold_script, t1.raw}})
    :ets.insert(ctl, {{:fail_script, t1.raw}})
    jobs0 = pstat(n, :prep_jobs)
    deferred(n, blocks)
    assert_receive {:script_held, _, sworker}, 5_000
    # b2 (spending b1's output) gets prepared while b1's scripts are held:
    # its own scripts are submitted (a script job for t2 runs).
    wait_until(fn -> pstat(n, :prep_jobs) - jobs0 == 2 end)
    wait_until(fn -> pstat(n, :prep_stale) == 0 and pstat(n, :script_jobs) >= 1 end)
    assert tip(n) == n.tip.hash

    # b1's scripts turn out invalid: b2, though prepared, is never published.
    h1 = b1.header.hash

    capture_log(fn ->
      send(sworker, {:release_script, t1.raw})

      assert_receive {:block_checked, ^h1,
                      {:error, {:consensus, "block-script-verify-flag-failed"}}},
                     5_000
    end)

    assert tip(n) == n.tip.hash
    assert status(n, b1) == :failed
    h2 = b2.header.hash
    refute_received {:block_connected, ^h2, _}
  end

  test "commits of earlier blocks while the worker runs do not void its result",
       %{tmp_dir: dir} do
    ctl = control()
    # Commit after every retirement.
    n = start(dir, "c", ctl, batch_blocks: 1)
    [_b1, _b2, b3] = blocks = chain(n.tip, 150, for(h <- 1..3, do: [spend(cb(n, h), 50 * @coin)]))
    :ets.insert(ctl, {{:hold_prep, b3.header.hash}})
    deferred(n, blocks)
    h3 = b3.header.hash
    assert_receive {:prep_held, ^h3, worker}, 5_000
    wait_until(fn -> tip(n) == Enum.at(blocks, 1).header.hash end)
    stale0 = pstat(n, :prep_stale)
    send(worker, {:release_prep, h3})
    wait_until(fn -> tip(n) == h3 end)
    assert pstat(n, :prep_stale) == stale0
  end

  test "an ancestor failure during preparation: the old result is stale and the replacement plan proceeds",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "d", ctl)
    ta = spend(cb(n, 1), 50 * @coin)
    [a1, a2] = chain(n.tip, 150, [[ta], [spend(cb(n, 2), 50 * @coin)]])
    :ets.insert(ctl, {{:hold_script, ta.raw}})
    :ets.insert(ctl, {{:fail_script, ta.raw}})
    :ets.insert(ctl, {{:hold_prep, a2.header.hash}})
    deferred(n, [a1, a2])
    assert_receive {:script_held, _, sworker}, 5_000
    h2 = a2.header.hash
    assert_receive {:prep_held, ^h2, pworker}, 5_000

    # a1 fails while a2 is being prepared: the plan is dropped.
    capture_log(fn ->
      send(sworker, {:release_script, ta.raw})
      h1 = a1.header.hash
      assert_receive {:block_checked, ^h1, _}, 5_000
    end)

    # A heavier fork from 150 is submitted; it waits for the obsolete job
    # (one job at a time), whose result is then discarded.
    fork = chain(n.tip, 150, for(h <- 3..5, do: [spend(cb(n, h), 50 * @coin)]))
    deferred(n, fork)
    stale0 = pstat(n, :prep_stale)
    send(pworker, {:release_prep, h2})
    wait_until(fn -> tip(n) == List.last(fork).header.hash end)
    assert pstat(n, :prep_stale) == stale0 + 1
    refute_received {:block_connected, ^h2, _}
  end

  test "a worker crash or death is a local failure: quarantined, not invalid; a new worker continues",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "e", ctl)
    [b1, b2] = chain(n.tip, 150, for(h <- 1..2, do: [spend(cb(n, h), 50 * @coin)]))
    :ets.insert(ctl, {{:raise_prep, b1.header.hash}})

    capture_log(fn ->
      deferred(n, [b1, b2])
      h1 = b1.header.hash
      assert_receive {:block_checked, ^h1, {:error, {:crash, _}}}, 5_000
    end)

    assert State.poisoned(n.cs) == [b1.header.hash]
    assert status(n, b1) != :failed

    # Worker killed while holding a job: quarantined too, and a new worker
    # prepares the next block once the first is reconsidered.
    :ets.delete(ctl, {:raise_prep, b1.header.hash})
    :ets.insert(ctl, {{:hold_prep, b1.header.hash}})
    reconsider = Task.async(fn -> State.reconsider_poisoned(n.cs, b1.header.hash) end)
    h1 = b1.header.hash
    assert_receive {:prep_held, ^h1, worker}, 5_000

    capture_log(fn ->
      Process.exit(worker, :kill)
      assert Task.await(reconsider, 5_000) == [h1]
    end)

    assert State.poisoned(n.cs) == [h1]
    :ets.delete(ctl, {:hold_prep, h1})
    assert State.reconsider_poisoned(n.cs, h1) == [h1]
    assert tip(n) == b2.header.hash
  end

  test "halt during preparation publishes nothing; shutdown is prompt and a restart recovers",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "f", ctl)
    [b1, b2] = blocks = chain(n.tip, 150, for(h <- 1..2, do: [spend(cb(n, h), 50 * @coin)]))
    :ets.insert(ctl, {{:hold_prep, b2.header.hash}})
    deferred(n, blocks)
    h2 = b2.header.hash
    assert_receive {:prep_held, ^h2, worker}, 5_000
    wait_until(fn -> tip(n) == b1.header.hash end)

    # Shutdown with the worker holding a job: the worker is pure BEAM code,
    # killed at once; the retired prefix is committed.
    Process.unlink(n.cs)
    wref = Process.monitor(worker)
    assert :ok = GenServer.stop(n.cs, :shutdown, 5_000)
    # The worker does not outlive its owner.
    assert_receive {:DOWN, ^wref, _, _, _}, 5_000

    :ets.delete_all_objects(ctl)
    cs2 = start_cs(dir, "f", n.kv, n.hs, ctl, [])
    assert State.tip(cs2).hash == b2.header.hash
  end

  # Both messages already sent to the chain state, and any :drive turn they
  # queued, are processed when this returns (two round trips).
  defp barrier(n) do
    _ = State.work_stats(n.cs)
    _ = State.work_stats(n.cs)
    :ok
  end

  defp queued(pid), do: elem(Process.info(pid, :message_queue_len), 1)

  defp forged(n, tag),
    do: send(n.cs, {:prep_done, tag, {:ok, :forged}, %{worker_us: 1_000_000_000}})

  test "only the outstanding job's own completion releases the worker, exactly once",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "h", ctl)
    ta = spend(cb(n, 1), 50 * @coin)
    [a1, a2] = chain(n.tip, 150, [[ta], [spend(cb(n, 2), 50 * @coin)]])
    {h1, h2} = {a1.header.hash, a2.header.hash}
    :ets.insert(ctl, {{:hold_script, ta.raw}})
    :ets.insert(ctl, {{:fail_script, ta.raw}})
    :ets.insert(ctl, {{:hold_prep, h2}})
    deferred(n, [a1, a2])
    # a1's job completed and was accepted (its scripts are held); job A
    # (a2) is held in the worker.
    assert_receive {:prep_started, ^h1, tag1}, 5_000
    assert_receive {:prep_started, ^h2, tag_a}, 5_000
    assert_receive {:prep_held, ^h2, worker}, 5_000
    assert_receive {:script_held, _, sworker}, 5_000

    # a1 fails: the plan is dropped while job A is still outstanding.
    capture_log(fn ->
      send(sworker, {:release_script, ta.raw})
      assert_receive {:block_checked, ^h1, _}, 5_000
    end)

    # A heavier fork: B (its first block) is held when it gets its turn.
    [f1 | _] = fork = chain(n.tip, 150, for(h <- 3..5, do: [spend(cb(n, h), 50 * @coin)]))
    hb = f1.header.hash
    :ets.insert(ctl, {{:hold_prep, hb}})
    jobs0 = pstat(n, :prep_jobs)
    {worker_us0, unknown0} = {pstat(n, :prep_worker_us), pstat(n, :prep_unknown)}
    deferred(n, fork)

    # A duplicate of a1's accepted completion and a tag never sent: neither
    # releases job A's slot, so B is not dispatched while A runs.
    {:prep, gen, _} = tag1
    forged(n, tag1)
    forged(n, {:prep, gen, make_ref()})
    barrier(n)
    assert queued(worker) == 0
    assert pstat(n, :prep_jobs) == jobs0
    assert pstat(n, :prep_unknown) == unknown0 + 2
    assert pstat(n, :prep_worker_us) == worker_us0

    # A's own (cancelled but outstanding) completion: stale, releases its
    # slot once; B is then dispatched and held.
    stale0 = pstat(n, :prep_stale)
    send(worker, {:release_prep, h2})
    assert_receive {:prep_started, ^hb, tag_b}, 5_000
    assert_receive {:prep_held, ^hb, ^worker}, 5_000
    assert pstat(n, :prep_stale) == stale0 + 1
    assert pstat(n, :prep_jobs) == jobs0 + 1

    # A's completion delivered again while B is held: not B's, so it
    # neither settles B nor releases it; B's latency is not charged to it.
    worker_us1 = pstat(n, :prep_worker_us)
    forged(n, tag_a)
    barrier(n)
    assert queued(worker) == 0
    assert pstat(n, :prep_stale) == stale0 + 1
    assert pstat(n, :prep_unknown) == unknown0 + 3
    assert pstat(n, :prep_worker_us) == worker_us1
    assert tip(n) == n.tip.hash
    refute tag_b == tag_a

    # B's own completion settles it; the fork connects, a2 never does.
    send(worker, {:release_prep, hb})
    wait_until(fn -> tip(n) == List.last(fork).header.hash end)
    refute_received {:block_connected, ^h2, _}
    # A duplicate after acceptance changes nothing.
    forged(n, tag_b)
    barrier(n)
    assert tip(n) == List.last(fork).header.hash
    assert pstat(n, :prep_unknown) == unknown0 + 4
  end

  test "an old worker dying with an obsolete job quarantines nothing; its replacement prepares the new plan",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "i", ctl)
    ta = spend(cb(n, 1), 50 * @coin)
    [a1, a2] = chain(n.tip, 150, [[ta], [spend(cb(n, 2), 50 * @coin)]])
    {h1, h2} = {a1.header.hash, a2.header.hash}
    :ets.insert(ctl, {{:hold_script, ta.raw}})
    :ets.insert(ctl, {{:fail_script, ta.raw}})
    :ets.insert(ctl, {{:hold_prep, h2}})
    deferred(n, [a1, a2])
    assert_receive {:prep_held, ^h2, old}, 5_000
    assert_receive {:script_held, _, sworker}, 5_000

    capture_log(fn ->
      send(sworker, {:release_script, ta.raw})
      assert_receive {:block_checked, ^h1, _}, 5_000
    end)

    fork = chain(n.tip, 150, for(h <- 3..5, do: [spend(cb(n, h), 50 * @coin)]))
    jobs0 = pstat(n, :prep_jobs)
    deferred(n, fork)
    barrier(n)
    # Waiting for the obsolete job.
    assert pstat(n, :prep_jobs) == jobs0
    assert queued(old) == 0
    Process.exit(old, :kill)
    wait_until(fn -> tip(n) == List.last(fork).header.hash end)
    assert State.poisoned(n.cs) == []
    assert for(b <- fork, do: status(n, b)) |> Enum.all?(&(&1 != :failed))
    # The replacement prepared every fork block.
    for b <- fork, h = b.header.hash, do: assert_received({:prep_started, ^h, _})
    refute_received {:block_connected, ^h2, _}
  end

  test "a one-byte budget still progresses (single-item admission)", %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "g", ctl, pipeline_bytes: 1)
    blocks = chain(n.tip, 150, for(h <- 1..5, do: [spend(cb(n, h), 50 * @coin)]))
    deferred(n, blocks)
    wait_until(fn -> tip(n) == List.last(blocks).header.hash end)
    assert State.work_stats(n.cs).pipeline.items_hwm == 1
  end
end
