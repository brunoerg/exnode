defmodule Exnode.P2P.DecodeBudget do
  @moduledoc """
  A node-wide budget of payload bytes being decoded and handled at once.

  Core processes every peer's messages on one thread (`ThreadMessageHandler`),
  so at most one message is ever decoded at a time. exnode decodes in each
  Peer process, in parallel. A decoded message is several times its wire size
  (a realistic block ~6.5×, a block of tiny outputs ~11×, a witness stack of
  empty items ~19× held and ~45× at peak), so without a bound ~190 inbound
  peers releasing one 4 MB message each reach tens of GB: a remote OOM.

  A peer takes `byte_size(payload)` from the budget before it decodes and
  handles a large message, and gives it back afterwards (after a GC, so the
  decoded term is gone). A request larger than the whole budget is charged
  the whole budget. Requests are granted in FIFO order; a waiting peer reads
  nothing more from its socket meanwhile (backpressure, as Core's
  per-peer receive flood limit). A holder or waiter that dies is released.

  Messages below `min_bytes/0` are not charged: their decoded size is small,
  and they are the bulk of normal traffic.
  """
  use GenServer

  # 64 KiB: below this a message decodes freely (≤ ~3 MB peak each).
  @min_bytes 65_536
  # 32 MiB: eight maximum-size messages at once.
  @default_bytes 32 * 1024 * 1024

  def min_bytes, do: @min_bytes
  def default_bytes, do: @default_bytes

  def start_link(opts) do
    GenServer.start_link(__MODULE__, Keyword.get(opts, :bytes, @default_bytes),
      name: Keyword.fetch!(opts, :name)
    )
  end

  @doc """
  Runs `fun` holding `n` bytes of the budget (no budget is taken when
  `server` is nil or `n` is below `min_bytes/0`). Blocks until granted.
  The caller holds at most one grant at a time. Returns fun's result, or
  `:unavailable` (fun not run) if the budget server is not running: it sits
  before the connections in the P2P subtree, so the peers are being
  restarted with it anyway.

  Options:
    * `:gc` — whether to run `:erlang.garbage_collect/0` after `fun` returns
      (default `true`). Pass `gc: false` when `fun` delegates its large
      allocations to a short-lived worker process via `with_worker/4`.
  """
  def with_budget(server, n, fun, opts \\ [])
  def with_budget(nil, _n, fun, _opts), do: fun.()
  def with_budget(_server, n, fun, _opts) when n < @min_bytes, do: fun.()

  def with_budget(server, n, fun, opts) do
    case acquire(server, n) do
      :ok ->
        try do
          fun.()
        after
          if Keyword.get(opts, :gc, true) do
            # The decoded term is garbage once fun returns: collect it before
            # the bytes are handed to another peer.
            :erlang.garbage_collect()
          end

          GenServer.cast(server, {:release, self()})
        end

      :unavailable ->
        :unavailable
    end
  end

  @doc """
  Runs `fun` inside a short-lived worker under `task_sup` while holding `n`
  bytes of `budget`. When the worker exits, BEAM reclaims its entire heap
  in O(1) without growing or GC-scanning the caller's heap.

  Falls back to running `fun` inline via `with_budget/3` when `task_sup` is
  `nil` or not running.
  """
  def with_worker(budget, nil, n, fun), do: with_budget(budget, n, fun)

  def with_worker(budget, task_sup, n, fun) do
    with_budget(
      budget,
      n,
      fn ->
        case run_in_worker(task_sup, fun) do
          {:ok, result} -> result
          :fallback -> fun.()
        end
      end,
      gc: false
    )
  end

  defp run_in_worker(task_sup, fun) do
    if GenServer.whereis(task_sup) != nil do
      task = Task.Supervisor.async_nolink(task_sup, fun)

      case Task.yield(task, :infinity) do
        {:ok, result} ->
          {:ok, result}

        {:exit, reason} ->
          exit(reason)
      end
    else
      :fallback
    end
  catch
    :exit, {:noproc, _} -> :fallback
  end

  defp acquire(server, n) do
    GenServer.call(server, {:acquire, n}, :infinity)
  catch
    :exit, _ -> :unavailable
  end

  @doc "`%{total, available, holders, waiting}` (tests, diagnostics)."
  def info(server), do: GenServer.call(server, :info)

  @impl true
  def init(total) when is_integer(total) and total > 0 do
    {:ok, %{total: total, available: total, holders: %{}, waiting: :queue.new()}}
  end

  @impl true
  def handle_call({:acquire, n}, {pid, _} = from, st) do
    n = min(n, st.total)
    ref = Process.monitor(pid)
    st = %{st | waiting: :queue.in({from, pid, n, ref}, st.waiting)}
    {:noreply, grant(st)}
  end

  def handle_call(:info, _from, st) do
    {:reply,
     %{
       total: st.total,
       available: st.available,
       holders: map_size(st.holders),
       waiting: :queue.len(st.waiting)
     }, st}
  end

  @impl true
  def handle_cast({:release, pid}, st), do: {:noreply, release(st, pid)}

  @impl true
  def handle_info({:DOWN, ref, :process, pid, _}, st) do
    case st.holders do
      %{^pid => {_, ^ref}} ->
        {:noreply, release(st, pid)}

      _ ->
        waiting = :queue.filter(fn {_, _, _, r} -> r != ref end, st.waiting)
        {:noreply, grant(%{st | waiting: waiting})}
    end
  end

  defp release(st, pid) do
    case Map.pop(st.holders, pid) do
      {nil, _} ->
        st

      {{n, ref}, holders} ->
        Process.demonitor(ref, [:flush])
        grant(%{st | holders: holders, available: st.available + n})
    end
  end

  # FIFO: the head waits until it fits, so a large request is not starved.
  defp grant(st) do
    case :queue.peek(st.waiting) do
      {:value, {from, pid, n, ref}} when n <= st.available ->
        GenServer.reply(from, :ok)

        grant(%{
          st
          | waiting: :queue.drop(st.waiting),
            available: st.available - n,
            holders: Map.put(st.holders, pid, {n, ref})
        })

      _ ->
        st
    end
  end
end
