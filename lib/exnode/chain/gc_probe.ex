defmodule Exnode.Chain.GcProbe do
  @moduledoc """
  Measures one process's garbage collection (the chain state's, for the
  perf log): every minor and major collection is traced
  (`:erlang.trace/3` with `:garbage_collection`), so the totals are exact,
  not sampled. Also counts long schedules node-wide
  (`:erlang.system_monitor/2`, `long_schedule`): a process or port that
  ran 20 ms or more without yielding, which delays others on its scheduler.

  The probe is a linked process that receives the trace messages and sums
  them in a `:counters` array; `take/1` reads and resets it. Tracing and the
  system monitor are VM-wide settings with one tracer per traced process and
  one system monitor per node, so only the node starts a probe.
  """

  @long_schedule_ms 20

  # Counter slots.
  @minor_n 1
  @minor_us 2
  @major_n 3
  @major_us 4
  @heap_max 5
  @sched_n 6
  @sched_ms 7
  @own_sched_n 8
  @own_sched_ms 9
  @size 9

  @doc "Starts probing `target`'s collections; returns the counters to `take/1`."
  def start(target \\ self()) do
    c = :counters.new(@size, [:write_concurrency])
    parent = self()

    pid =
      spawn_link(fn ->
        :erlang.trace(target, true, [
          :garbage_collection,
          :monotonic_timestamp,
          {:tracer, self()}
        ])

        :erlang.system_monitor(self(), [{:long_schedule, @long_schedule_ms}])
        send(parent, {__MODULE__, :started})
        loop(target, c, nil)
      end)

    receive do
      {__MODULE__, :started} -> :ok
    after
      5_000 -> :ok
    end

    {pid, c}
  end

  @doc """
  The collections since the last call: counts and times (µs) of minor and
  major collections, the largest heap seen after one (words, young plus
  old), and long schedules elsewhere and of the target itself (count, ms).
  """
  def take({_pid, c}) do
    m = %{
      minor_n: :counters.get(c, @minor_n),
      minor_us: :counters.get(c, @minor_us),
      major_n: :counters.get(c, @major_n),
      major_us: :counters.get(c, @major_us),
      heap_max_words: :counters.get(c, @heap_max),
      sched_n: :counters.get(c, @sched_n),
      sched_ms: :counters.get(c, @sched_ms),
      own_sched_n: :counters.get(c, @own_sched_n),
      own_sched_ms: :counters.get(c, @own_sched_ms)
    }

    for {k, v} <- m, k != :heap_max_words, do: :counters.sub(c, slot(k), v)
    :counters.put(c, @heap_max, 0)
    m
  end

  defp slot(:minor_n), do: @minor_n
  defp slot(:minor_us), do: @minor_us
  defp slot(:major_n), do: @major_n
  defp slot(:major_us), do: @major_us
  defp slot(:sched_n), do: @sched_n
  defp slot(:sched_ms), do: @sched_ms
  defp slot(:own_sched_n), do: @own_sched_n
  defp slot(:own_sched_ms), do: @own_sched_ms

  # `start`: the monotonic timestamp (ns) of the collection in progress.
  defp loop(target, c, start) do
    receive do
      {:trace_ts, ^target, ev, _info, ts} when ev in [:gc_minor_start, :gc_major_start] ->
        loop(target, c, ts)

      {:trace_ts, ^target, ev, info, ts} when ev in [:gc_minor_end, :gc_major_end] ->
        if start do
          us = div(ts - start, 1000)

          if ev == :gc_minor_end do
            :counters.add(c, @minor_n, 1)
            :counters.add(c, @minor_us, us)
          else
            :counters.add(c, @major_n, 1)
            :counters.add(c, @major_us, us)
          end
        end

        words = Keyword.get(info, :heap_size, 0) + Keyword.get(info, :old_heap_size, 0)
        if words > :counters.get(c, @heap_max), do: :counters.put(c, @heap_max, words)
        loop(target, c, nil)

      {:monitor, who, :long_schedule, info} ->
        ms = Keyword.get(info, :timeout, 0)

        if who == target do
          :counters.add(c, @own_sched_n, 1)
          :counters.add(c, @own_sched_ms, ms)
        else
          :counters.add(c, @sched_n, 1)
          :counters.add(c, @sched_ms, ms)
        end

        loop(target, c, start)

      _ ->
        loop(target, c, start)
    end
  end
end
