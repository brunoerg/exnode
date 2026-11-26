defmodule Exnode.Chain.ActivationPlanTest do
  @moduledoc """
  The persistent asynchronous activation plan,
  driven deterministically: the chain state's private script executor runs
  a test function (`script_run:`) that can hold a block's script job until
  the test releases it, fail it, or let it verify for real. No sleeps decide
  an ordering; timeouts only bound waits for messages.

  Blocks go in deferred (as in IBD), so the test keeps control while jobs
  are held: a synchronous submission would wait for the activation.
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

  # The test's control over script jobs, by raw tx: `{:hold, raw}` waits for
  # `{:release, ...}`; `{:fail, raw, outcome}` returns `outcome` (once
  # unless `:always`). Everything else verifies for real.
  defp control, do: :ets.new(:control, [:public, :set])

  defp run_fun(test, ctl) do
    fn job ->
      raws = for {raw, _} <- job.checks, do: raw
      {:blk, _gen, ref, chunk} = job.tag

      cond do
        hold = Enum.find(raws, &:ets.member(ctl, {:hold, &1})) ->
          send(test, {:held, hold, {ref, chunk}, self()})
          receive do: ({:release, ^hold} -> :ok)
          send(test, {:released_ran, hold, {ref, chunk}})
          # Released into an injected failure, if one is set for this tx.
          lookup_fail(ctl, hold) || ScriptExec.run_job(job)

        fail = Enum.find_value(raws, &lookup_fail(ctl, &1)) ->
          fail

        true ->
          r = ScriptExec.run_job(job)
          for raw <- raws, do: send(test, {:ran, raw})
          r
      end
    end
  end

  defp lookup_fail(ctl, raw) do
    case :ets.lookup(ctl, {:fail, raw}) do
      [{_, outcome, :always}] ->
        outcome

      [{k, outcome, :once}] ->
        :ets.delete(ctl, k)
        outcome

      [] ->
        nil
    end
  end

  defp start(dir, name, ctl, opts \\ []) do
    {:ok, kv} = KV.open(Path.join([dir, name, "kv"]))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs = start_cs(dir, name, kv, hs, ctl, opts)
    %{cs: cs, hs: hs, kv: kv}
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
          script_run: run_fun(self(), ctl),
          script_workers: 4
        ] ++ opts
      )

    cs
  end

  defp base(n) do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    # The fixture's blocks have no non-coinbase txs: no script jobs.
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)
    flush()
    bs
  end

  defp flush do
    receive do
      {:block_connected, _, _} -> flush()
    after
      0 -> :ok
    end
  end

  defp good_tx(cb), do: BB.spend_op_true(cb, 0, 50 * @coin)

  defp chain(prev, start_h, specs) do
    {blocks, _} =
      Enum.map_reduce(Enum.with_index(specs, 1), prev, fn {txs, i}, prev ->
        b = BB.build(prev, [BB.coinbase(start_h + i, 25 * @coin) | txs])
        {b, b.header}
      end)

    blocks
  end

  defp headers(n, blocks),
    do: {:ok, _} = Headers.process_headers(n.hs, Enum.map(blocks, & &1.header))

  defp deferred(n, b),
    do: {:ok, :stored} = State.submit_block(n.cs, b, defer: true, requested: true, source: self())

  defp status(n, b), do: HeaderIndex.lookup(Headers.index(n.hs), b.header.hash).status
  defp tip(n), do: State.tip(n.cs).hash

  defp await_tip(n, hash) do
    unless until?(fn -> tip(n) == hash end),
      do: flunk("tip never reached #{Exnode.Crypto.Hash.to_hex(hash)}")
  end

  defp raw(b), do: Enum.at(b.txs, 1).raw

  defp cbs(bs), do: fn h -> hd(Enum.at(bs, h - 1).txs).txid end

  test "N held: N+1, N+2 finish first and nothing after N is published; calls are served, " <>
         "a new block joins the same plan, and releasing N finishes it all",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "a", ctl)
    bs = base(n)
    cb = cbs(bs)

    blocks =
      [b1, b2, b3, b4] = chain(List.last(bs).header, 150, for(i <- 1..4, do: [good_tx(cb.(i))]))

    :ets.insert(ctl, {{:hold, raw(b1)}})
    headers(n, blocks)
    for b <- [b1, b2, b3], do: deferred(n, b)

    assert_receive {:held, _, _, w1}, 5_000
    r2 = raw(b2)
    r3 = raw(b3)
    assert_receive {:ran, ^r2}, 5_000
    assert_receive {:ran, ^r3}, 5_000

    # Successors complete, N is held: the tip has not moved, and the chain
    # state answers calls (no callback is waiting on the executor).
    assert tip(n) == List.last(bs).header.hash
    refute_received {:block_connected, _, _}
    assert State.precheck_block(n.cs, b4.header, true) == :check
    stats = State.work_stats(n.cs)
    assert stats.pipeline.items_hwm >= 3

    # A newly available next block is prepared on the same plan while N is held.
    deferred(n, b4)
    r4 = raw(b4)
    assert_receive {:ran, ^r4}, 5_000
    assert State.work_stats(n.cs).pipeline.extensions >= 1
    assert tip(n) == List.last(bs).header.hash

    # Release N: everything retires in order, nothing resubmitted.
    send(w1, {:release, raw(b1)})
    await_tip(n, b4.header.hash)

    for b <- blocks do
      h = b.header.hash
      assert_receive {:block_connected, ^h, _}
    end

    refute_received {:block_checked, _, _}
  end

  test "N fails locally (kernel API error): quarantined, header not failed, source not punished, " <>
         "dependents not published",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "b", ctl)
    bs = base(n)
    cb = cbs(bs)
    [b1, b2, b3] = chain(List.last(bs).header, 150, for(i <- 1..3, do: [good_tx(cb.(i))]))
    :ets.insert(ctl, {{:fail, raw(b2)}, {:local, {:kernel_api, :injected}}, :always})
    headers(n, [b1, b2, b3])

    log =
      capture_log(fn ->
        for b <- [b1, b2, b3], do: deferred(n, b)
        h2 = b2.header.hash
        # Peers never punish :crash (Peer.maybe_punish_for_block).
        assert_receive {:block_checked, ^h2, {:error, {:crash, _}}}, 5_000
      end)

    assert log =~ "quarantined"
    await_tip(n, b1.header.hash)
    assert State.poisoned(n.cs) == [b2.header.hash]
    assert status(n, b2) != :failed
    assert status(n, b3) != :failed
    h3 = b3.header.hash
    refute_received {:block_connected, ^h3, _}
    refute_received {:block_invalid, _, _}
    assert tip(n) == b1.header.hash
  end

  test "N fails scripts while N+1, N+2 jobs still run: completions after the plan is dropped " <>
         "are ignored, and a heavier fork connects",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "c", ctl)
    bs = base(n)
    cb = cbs(bs)
    tip150 = List.last(bs).header
    [a1, a2, a3] = chain(tip150, 150, for(i <- 1..3, do: [good_tx(cb.(i))]))
    for b <- [a1, a2, a3], do: :ets.insert(ctl, {{:hold, raw(b)}})
    :ets.insert(ctl, {{:fail, raw(a1)}, {:invalid, "block-script-verify-flag-failed"}, :always})
    headers(n, [a1, a2, a3])
    for b <- [a1, a2, a3], do: deferred(n, b)

    held =
      for _ <- 1..3,
          do:
            (
              assert_receive({:held, r, _, w}, 5_000)
              {r, w}
            )

    held = Map.new(held)

    # a1 is released into a proven script failure while a2's and a3's jobs run.
    h1 = a1.header.hash
    send(held[raw(a1)], {:release, raw(a1)})
    capture_log(fn -> assert_receive({:block_checked, ^h1, {:error, {:consensus, _}}}, 5_000) end)
    {w2, w3} = {held[raw(a2)], held[raw(a3)]}
    assert status(n, a1) == :failed

    # A heavier fork from 150 activates while a2/a3's jobs are still running.
    fork = chain(tip150, 150, for(i <- 1..4, do: [good_tx(cb.(10 + i))]))
    headers(n, fork)
    for b <- fork, do: deferred(n, b)
    await_tip(n, List.last(fork).header.hash)

    # The dropped plan's jobs complete now: their results are discarded (the
    # executor marked them cancelled; the chain state would also ignore them
    # by generation), and they held their workers until they returned.
    exec = :sys.get_state(n.cs).exec
    d0 = ScriptExec.stats(exec).discarded
    send(w2, {:release, raw(a2)})
    send(w3, {:release, raw(a3)})
    assert_receive {:released_ran, _, _}, 5_000
    assert_receive {:released_ran, _, _}, 5_000
    wait_until(fn -> ScriptExec.stats(exec).discarded == d0 + 2 end)
    assert ScriptExec.stats(exec).running == 0
    assert tip(n) == List.last(fork).header.hash
    for b <- [a2, a3], h = b.header.hash, do: refute_received({:block_connected, ^h, _})
  end

  test "a stale completion for the same header from an earlier preparation is not credited",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "d", ctl)
    bs = base(n)
    cb = cbs(bs)
    [b1, b2] = chain(List.last(bs).header, 150, for(i <- 1..2, do: [good_tx(cb.(i))]))
    {h1, h2} = {b1.header.hash, b2.header.hash}
    for b <- [b1, b2], do: :ets.insert(ctl, {{:hold, raw(b)}})
    # b1 fails locally once (its chunk is released into it): quarantined.
    :ets.insert(ctl, {{:fail, raw(b1)}, {:local, {:kernel_api, :injected_once}}, :once})
    headers(n, [b1, b2])
    for b <- [b1, b2], do: deferred(n, b)

    held =
      Map.new(
        for _ <- 1..2,
            do:
              (
                assert_receive({:held, r, {ref, _}, w}, 5_000)
                {r, {ref, w}}
              )
      )

    {ref_old, w_old} = held[raw(b2)]

    capture_log(fn ->
      send(elem(held[raw(b1)], 1), {:release, raw(b1)})
      assert_receive {:block_checked, ^h1, {:error, {:crash, _}}}, 5_000
    end)

    assert State.poisoned(n.cs) == [h1]
    exec = :sys.get_state(n.cs).exec

    # Reconsidered (answered when activation is idle): b1 verifies for real
    # now, and b2 (same header, same body) is prepared again as a new item,
    # whose job is held again.
    :ets.delete(ctl, {:hold, raw(b1)})
    reconsider = Task.async(fn -> State.reconsider_poisoned(n.cs, h1) end)
    b2raw = raw(b2)
    assert_receive {:held, ^b2raw, {ref_new, _}, w_new}, 5_000
    assert ref_new != ref_old
    await_tip(n, h1)

    # The old preparation's job returns now: discarded, not credited to the
    # new item, which is still pending: the tip stays at b1.
    d0 = ScriptExec.stats(exec).discarded
    send(w_old, {:release, b2raw})
    assert_receive {:released_ran, ^b2raw, {^ref_old, _}}, 5_000
    wait_until(fn -> ScriptExec.stats(exec).discarded == d0 + 1 end)
    assert tip(n) == h1
    send(w_new, {:release, b2raw})
    await_tip(n, h2)
    assert Task.await(reconsider) == [h1]
  end

  test "a one-byte budget still progresses one block at a time (single-item admission)",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "e", ctl, pipeline_bytes: 1)
    bs = base(n)
    cb = cbs(bs)
    blocks = chain(List.last(bs).header, 150, for(i <- 1..6, do: [good_tx(cb.(i))]))
    headers(n, blocks)
    for b <- blocks, do: deferred(n, b)
    await_tip(n, List.last(blocks).header.hash)
    assert State.work_stats(n.cs).pipeline.items_hwm == 1
  end

  test "shutdown with scripts in flight waits for the native call; restart recovers the same tip " <>
         "with nothing provisional published",
       %{tmp_dir: dir} do
    ctl = control()
    n = start(dir, "f", ctl)
    bs = base(n)
    cb = cbs(bs)

    blocks =
      [b1, b2, b3] = chain(List.last(bs).header, 150, for(i <- 1..3, do: [good_tx(cb.(i))]))

    :ets.insert(ctl, {{:hold, raw(b2)}})
    headers(n, blocks)
    for b <- blocks, do: deferred(n, b)
    assert_receive {:held, _, _, w2}, 5_000
    await_tip(n, b1.header.hash)
    # b3 is prepared (provisional) behind the held b2: not published.
    r3 = raw(b3)
    assert_receive {:ran, ^r3}, 5_000
    assert tip(n) == b1.header.hash

    Process.unlink(n.cs)
    stopper = Task.async(fn -> GenServer.stop(n.cs, :shutdown, :infinity) end)
    # terminate/2 waits for the running native job.
    refute Task.yield(stopper, 200)
    send(w2, {:release, raw(b2)})
    assert Task.await(stopper, 5_000) == :ok

    # Restart with nothing held: b1 was retired (committed at shutdown), b2
    # and b3 replay from pending asynchronously after init.
    :ets.delete_all_objects(ctl)
    cs2 = start_cs(dir, "f", n.kv, n.hs, ctl, [])
    :ok = State.await_idle(cs2)
    assert State.tip(cs2).hash == b3.header.hash
  end
end
