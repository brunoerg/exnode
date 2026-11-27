defmodule Exnode.Validation.ScriptExec do
  @moduledoc """
  The node's shared, bounded executor for native script work (the role of
  Core's `CCheckQueue` worker threads, shared by every block in flight and
  by the mempool).

  **Capacity.** A fixed set of `workers` stable processes, each running one
  native job at a time: a job is a chunk of a block's txs
  (`Scripts.check_chunk/2`, one kernel NIF call per tx) or one mempool tx
  (`verify/4`). So at most `workers` kernel calls issued through the
  executor run at once, whatever the number of blocks in flight or callers.
  Default `default_workers/0`: `max(1, min(dirty_cpu_schedulers_online,
  schedulers_online - 1))`, a starting point to tune, not a measured optimum
  (`:script_workers` node option).

  **Order.** Block jobs run by priority (`prio`, lowest first): the chain
  state gives the oldest unretired block the lowest, so the head of its
  retirement FIFO is never starved by later blocks (progress reservation).
  Other jobs (the mempool's) are FIFO and, while any wait, get up to
  `other_reserve` workers (default 1) ahead of block jobs; with no block work
  they may use every worker.

  **Permit lifetime.** A worker's permit is released only when the worker
  itself reports that its native call returned. Killing a process does not
  stop a dirty NIF it is running, and its `:DOWN`/`EXIT` arrives *before*
  the native call returns (measured: a killed caller's DOWN came after 102
  ms of a 1,000 ms dirty job, and 24 killed callers kept every dirty CPU
  scheduler busy for another ~1.3 s). So:
  * a cancelled job still holds its worker until the native call returns;
    queued jobs of a cancelled group are dropped, a running one's result is
    discarded;
  * a worker that dies while running a job is NOT replaced (its native call
    may still be running): capacity drops by one, logged as `lost`; one
    that dies idle is replaced (no native work was running);
  * workers trap exits, so the executor's own death (crash, or a supervisor
    kill after the shutdown timeout) does not interrupt a native call: each
    worker finishes its job, then sees the exit and leaves. A restarted
    executor with the same name first waits for the previous executor's
    workers to exit (their pids are kept in `Exnode.Node.Runtime`), so a
    restart never adds capacity while old native work still runs;
  * `terminate/2` (normal shutdown) asks every worker to stop after its
    current job and waits for all of them.
  The one gap: a worker killed with `:kill` mid-job is gone while its
  native call continues; the slot is then retired rather than reused.

  **Results.** Block jobs are asynchronous: `submit/2` returns at once and
  the outcome arrives as `{:script_exec, tag, outcome, stats}` in the owner's
  mailbox, where `outcome` is `:ok | {:invalid, r} | {:local, r} |
  {:crash, error, stack}` and `stats` the worker's `%{native_us, txs}`.
  The executor never calls its owners, so no call cycle exists. Owners are
  monitored: an owner's death cancels its queued jobs.

  Per node (`Exnode.Node` starts one before the chain state, passed by
  name); a chain state started without one starts a private executor.
  Instances are independent: several nodes in one VM do not share a cap.
  """
  use GenServer
  require Logger

  alias Exnode.Kernel
  alias Exnode.Node.Runtime
  alias Exnode.Validation.Scripts

  def default_workers do
    dirty = :erlang.system_info(:dirty_cpu_schedulers_online)
    max(1, min(dirty, max(1, System.schedulers_online() - 1)))
  end

  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :id, __MODULE__),
      start: {__MODULE__, :start_link, [opts]},
      # Waits for running native calls to return (bounded by one job each).
      shutdown: 60_000
    }
  end

  @doc """
  Options: `name`, `workers` (default `default_workers/0`), `other_reserve`
  (default 1), `run` (test seam: `fun(job) -> outcome`, run in the worker
  instead of the kernel).
  """
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  An executor private to `owner` (unlinked): it stops, with `{:shutdown,
  :owner_down}`, when the owner goes, after its running native calls return.
  """
  def start_private(owner, opts),
    do: GenServer.start(__MODULE__, Keyword.put(opts, :owner, owner))

  @doc """
  Queues block jobs (asynchronous). Each job: `%{tag, group, prio, checks,
  flags}` plus an optional `pre` (a zero-arity fun run first in the worker,
  test hook). The outcome is sent to the caller as `{:script_exec, tag,
  outcome, stats}`.
  """
  def submit(exec, jobs) when is_list(jobs), do: GenServer.cast(exec, {:submit, self(), jobs})

  @doc "Cancels the caller's jobs in `groups`: queued ones are dropped, running ones' results discarded."
  def cancel(exec, groups) when is_list(groups),
    do: GenServer.cast(exec, {:cancel, self(), groups})

  @doc """
  One tx, synchronously (the mempool's script check): the
  `Exnode.Kernel.verify_tx_all/3` result, run on an executor worker. Waits
  with no timeout (bounded by the queue and one native call).
  """
  def verify(exec, raw, spent, flags) do
    case GenServer.call(exec, {:verify, raw, spent, flags}, :infinity) do
      # The direct kernel call would have raised in the caller: so does this.
      {:executor_crash, error} -> exit({:script_check_crashed, error})
      result -> result
    end
  end

  @doc "Counters and occupancy: workers, running, queued, high-water marks, done, native time."
  def stats(exec), do: GenServer.call(exec, :stats, 5_000)

  # --- server ------------------------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    name = opts[:name]
    # Fence: the previous executor's workers finish their native jobs first.
    if name, do: await_old_workers(Runtime.get_handle({__MODULE__, :workers, name}, []))
    n = Keyword.get(opts, :workers) || default_workers()
    run = Keyword.get(opts, :run, &run_job/1)
    exec = self()
    workers = for _ <- 1..n, into: %{}, do: {spawn_worker(exec, run), nil}

    st = %{
      name: name,
      run: run,
      workers: workers,
      idle: Map.keys(workers),
      other_reserve: Keyword.get(opts, :other_reserve, 1),
      next_id: 0,
      jobs: %{},
      block_q: :gb_sets.new(),
      other_q: :queue.new(),
      groups: %{},
      owners: %{},
      stats: %{
        workers: n,
        lost: 0,
        running_hwm: 0,
        queued_hwm: 0,
        done_block: 0,
        done_other: 0,
        native_us_block: 0,
        native_us_other: 0,
        cancelled_queued: 0,
        discarded: 0
      }
    }

    st =
      case opts[:owner] do
        nil -> st
        owner -> Map.put(st, :private_owner, Process.monitor(owner))
      end

    publish_workers(st)
    {:ok, st}
  end

  defp await_old_workers(pids) do
    refs = for p <- pids, Process.alive?(p), do: Process.monitor(p)
    for r <- refs, do: receive(do: ({:DOWN, ^r, _, _, _} -> :ok))
    :ok
  end

  defp publish_workers(%{name: nil}), do: :ok

  defp publish_workers(st),
    do: Runtime.put_handle({__MODULE__, :workers, st.name}, Map.keys(st.workers))

  defp spawn_worker(exec, run) do
    spawn_link(fn ->
      Process.flag(:trap_exit, true)
      worker_loop(exec, run)
    end)
  end

  # Stops only between jobs: a native call always returns before the worker
  # leaves (an exit signal from the executor is a message here).
  defp worker_loop(exec, run) do
    receive do
      {:run, id, job} ->
        t0 = System.monotonic_time(:microsecond)

        outcome =
          try do
            if pre = job[:pre], do: pre.()
            run.(job)
          catch
            kind, reason -> {:crash, {kind, reason}, __STACKTRACE__}
          end

        stats = %{native_us: System.monotonic_time(:microsecond) - t0, txs: job_txs(job)}
        send(exec, {:done, self(), id, outcome, stats})
        worker_loop(exec, run)

      :stop ->
        :ok

      {:EXIT, ^exec, _} ->
        :ok

      _ ->
        worker_loop(exec, run)
    end
  end

  defp job_txs(%{checks: c}), do: length(c)
  defp job_txs(_), do: 1

  @doc false
  def run_job(%{kind: :tx, raw: raw, spent: spent, flags: flags}),
    do: Kernel.verify_tx_all(raw, spent, flags)

  def run_job(%{checks: checks, flags: flags}), do: Scripts.check_chunk(checks, flags)

  @impl true
  def handle_cast({:submit, owner, jobs}, st) do
    st = monitor_owner(st, owner)

    st =
      Enum.reduce(jobs, st, fn job, st ->
        {id, st} = new_id(st)
        key = {owner, job.group}

        %{
          st
          | jobs:
              Map.put(st.jobs, id, %{owner: owner, class: :block, job: job, cancelled: false}),
            block_q: :gb_sets.add({job.prio, id}, st.block_q),
            groups: Map.update(st.groups, key, [id], &[id | &1])
        }
      end)

    {:noreply, st |> note_queued() |> dispatch()}
  end

  def handle_cast({:cancel, owner, groups}, st), do: {:noreply, cancel_groups(st, owner, groups)}

  @impl true
  def handle_call({:verify, raw, spent, flags}, from, st) do
    {id, st} = new_id(st)
    job = %{kind: :tx, raw: raw, spent: spent, flags: flags}

    st = %{
      st
      | jobs:
          Map.put(st.jobs, id, %{
            owner: nil,
            from: from,
            class: :other,
            job: job,
            cancelled: false
          }),
        other_q: :queue.in(id, st.other_q)
    }

    {:noreply, st |> note_queued() |> dispatch()}
  end

  def handle_call(:stats, _from, st) do
    {:reply,
     Map.merge(st.stats, %{
       workers: map_size(st.workers),
       running: map_size(st.workers) - length(st.idle),
       queued_block: :gb_sets.size(st.block_q),
       queued_other: :queue.len(st.other_q)
     }), st}
  end

  @impl true
  def handle_info({:done, w, id, outcome, wstats}, st) do
    st = %{st | workers: Map.put(st.workers, w, nil), idle: [w | st.idle]}
    {:noreply, st |> finish(id, outcome, wstats) |> dispatch()}
  end

  def handle_info({:DOWN, ref, :process, _, _}, %{private_owner: ref} = st),
    do: {:stop, {:shutdown, :owner_down}, st}

  def handle_info({:DOWN, _ref, :process, owner, _}, st) do
    groups = for {{^owner, g}, _} <- st.groups, do: g
    st = cancel_groups(st, owner, groups)
    {:noreply, %{st | owners: Map.delete(st.owners, owner)}}
  end

  def handle_info({:EXIT, w, reason}, st) when is_map_key(st.workers, w) do
    {job_id, workers} = Map.pop(st.workers, w)
    st = %{st | workers: workers, idle: List.delete(st.idle, w)}

    st =
      if job_id do
        # Its native call may still be running: the slot is retired, not reused.
        Logger.error(
          "script executor: worker died running a job (#{inspect(reason)}); capacity now #{map_size(workers)}"
        )

        st = update_in(st.stats.lost, &(&1 + 1))
        finish(st, job_id, {:crash, {:exit, {:worker_exit, reason}}, []}, %{native_us: 0, txs: 0})
      else
        # Died idle: no native work was running, so a replacement adds no overlap.
        w2 = spawn_worker(self(), st.run)
        %{st | workers: Map.put(st.workers, w2, nil), idle: [w2 | st.idle]}
      end

    publish_workers(st)

    if map_size(st.workers) == 0,
      do: {:stop, :no_script_workers, st},
      else: {:noreply, dispatch(st)}
  end

  def handle_info({:EXIT, _pid, reason}, st) when reason in [:normal, :shutdown],
    do: {:noreply, st}

  def handle_info({:EXIT, _pid, {:shutdown, _}}, st), do: {:noreply, st}
  def handle_info({:EXIT, _pid, reason}, st), do: {:stop, reason, st}
  def handle_info(_msg, st), do: {:noreply, st}

  @impl true
  def terminate(_reason, st) do
    # Each worker leaves after its current native call; wait for all.
    for w <- Map.keys(st.workers), do: send(w, :stop)

    for w <- Map.keys(st.workers) do
      ref = Process.monitor(w)
      receive do: ({:DOWN, ^ref, _, _, _} -> :ok)
    end

    # Only erase the fence once every worker has exited; a crash or shutdown
    # timeout skips this so the restarted executor still awaits lingering work.
    if st.name, do: Runtime.delete_handle({__MODULE__, :workers, st.name})
    :ok
  end

  # --- internals -----------------------------------------------------------------

  defp new_id(st), do: {st.next_id, %{st | next_id: st.next_id + 1}}

  defp monitor_owner(st, owner) do
    if Map.has_key?(st.owners, owner),
      do: st,
      else: %{st | owners: Map.put(st.owners, owner, Process.monitor(owner))}
  end

  defp note_queued(st) do
    q = :gb_sets.size(st.block_q) + :queue.len(st.other_q)
    update_in(st.stats.queued_hwm, &max(&1, q))
  end

  defp cancel_groups(st, owner, groups) do
    Enum.reduce(groups, st, fn g, st ->
      {ids, groups} = Map.pop(st.groups, {owner, g}, [])

      Enum.reduce(ids, %{st | groups: groups}, fn id, st ->
        case st.jobs[id] do
          nil ->
            st

          %{} = j ->
            if running?(st, id) do
              # Holds its worker until the native call returns; result discarded.
              %{st | jobs: Map.put(st.jobs, id, %{j | cancelled: true})}
            else
              st = update_in(st.stats.cancelled_queued, &(&1 + 1))

              %{
                st
                | jobs: Map.delete(st.jobs, id),
                  block_q: :gb_sets.delete_any({j.job.prio, id}, st.block_q)
              }
            end
        end
      end)
    end)
  end

  defp running?(st, id), do: Enum.any?(st.workers, fn {_, j} -> j == id end)

  defp dispatch(%{idle: []} = st), do: st

  defp dispatch(%{idle: [w | rest]} = st) do
    case next_job(st) do
      nil ->
        st

      {id, st} ->
        send(w, {:run, id, st.jobs[id].job})
        st = %{st | idle: rest, workers: Map.put(st.workers, w, id)}
        running = map_size(st.workers) - length(st.idle)
        dispatch(update_in(st.stats.running_hwm, &max(&1, running)))
    end
  end

  # Other (mempool) jobs first while fewer than `other_reserve` of them run,
  # or when no block job waits; otherwise the lowest-priority block job.
  defp next_job(st) do
    other_running =
      Enum.count(st.workers, fn {_, j} -> j != nil and st.jobs[j].class == :other end)

    other_waiting = not :queue.is_empty(st.other_q)
    block_waiting = not :gb_sets.is_empty(st.block_q)

    cond do
      other_waiting and (other_running < st.other_reserve or not block_waiting) ->
        {{:value, id}, q} = :queue.out(st.other_q)
        {id, %{st | other_q: q}}

      block_waiting ->
        {{_prio, id}, q} = :gb_sets.take_smallest(st.block_q)
        {id, %{st | block_q: q}}

      true ->
        nil
    end
  end

  defp finish(st, id, outcome, wstats) do
    {j, jobs} = Map.pop(st.jobs, id)
    st = %{st | jobs: jobs}

    case j do
      nil ->
        st

      %{class: :other, from: from} ->
        # A crash is not a kernel verdict: verify/4 exits in the caller.
        reply =
          case outcome do
            {:crash, error, _} -> {:executor_crash, error}
            r -> r
          end

        GenServer.reply(from, reply)

        st
        |> update_in([:stats, :done_other], &(&1 + 1))
        |> update_in([:stats, :native_us_other], &(&1 + wstats.native_us))

      %{class: :block, owner: owner, job: job, cancelled: cancelled} ->
        st =
          st
          |> update_in([:stats, :done_block], &(&1 + 1))
          |> update_in([:stats, :native_us_block], &(&1 + wstats.native_us))
          |> Map.update!(:groups, fn gs ->
            case gs[{owner, job.group}] do
              nil ->
                gs

              ids ->
                if ids == [id],
                  do: Map.delete(gs, {owner, job.group}),
                  else: Map.put(gs, {owner, job.group}, List.delete(ids, id))
            end
          end)

        if cancelled do
          update_in(st.stats.discarded, &(&1 + 1))
        else
          send(owner, {:script_exec, job.tag, outcome, wstats})
          st
        end
    end
  end
end
