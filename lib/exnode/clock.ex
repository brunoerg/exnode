defmodule Exnode.Clock do
  @moduledoc """
  The node's mockable clock (Core: `SetMockTime` / `NodeClock` in
  util/time.cpp, the `setmocktime` RPC, and `mockscheduler` for the
  periodic work).

  One per node, not one per VM as in Core: tests run many nodes in one VM
  and a global mock time would leak between them. The node creates it
  (`Exnode.Node` option `:clock`) and hands it to every component whose
  decisions depend on time: peer timeouts, eviction and inactivity, address
  timestamps, discouragement expiry, trickle and request timers, mempool
  expiry, the headers' future-time check, the IBD flag.

  * `now/1`: unix seconds; the mock time when one is set (Core `GetTime`).
  * `mono/2`: monotonic time. The first `advance/2` freezes it (Core
    `MockableSteadyClock::SetMockTime`): from then on only `advance/2`
    moves it, so a timeout boundary does not depend on how fast the test
    runs. `set/2` does not touch it (a monotonic clock does not jump to a
    wall time; Core's `setmocktime` leaves the steady clock alone too).
  * `set/2` (0: back to the system time), `advance/2`.
  * `tick/2`: the periodic work of the given processes runs now, against the
    current time, and has finished when it returns (Core `mockscheduler`
    plus the message handler's `SendMessages` pass). Each process handles
    `{Exnode.Clock, :tick, from, ref}` by running its tick and calling
    `ticked/1`.

  A `nil` clock is the system clock.
  """

  defstruct [:ref]

  @type t :: %__MODULE__{ref: :atomics.atomics_ref()} | nil

  # Slot 1: the mock unix time in seconds (0: none). Slot 2: the frozen
  # monotonic time in milliseconds, when slot 3 is 1.
  @doc "A clock on the system time."
  def new, do: %__MODULE__{ref: :atomics.new(3, signed: true)}

  @doc "Unix seconds: the mock time if one is set."
  def now(nil), do: System.os_time(:second)

  def now(%__MODULE__{ref: r}) do
    case :atomics.get(r, 1) do
      0 -> System.os_time(:second)
      t -> t
    end
  end

  @doc """
  Unix milliseconds: the mock time if one is set (Core `NodeClock::now()`,
  as `GetTime<std::chrono::microseconds>()` reads it). With a mock time it
  moves only by `set/2` and `advance/2`, in whole seconds.
  """
  def now_ms(nil), do: System.os_time(:millisecond)

  def now_ms(%__MODULE__{ref: r}) do
    case :atomics.get(r, 1) do
      0 -> System.os_time(:millisecond)
      t -> t * 1000
    end
  end

  @doc "Monotonic time in `unit`: frozen once `advance/2` was called, then moved only by it."
  def mono(clock, unit \\ :millisecond)
  def mono(nil, unit), do: System.monotonic_time(unit)

  def mono(%__MODULE__{ref: r}, unit) do
    case :atomics.get(r, 3) do
      0 -> System.monotonic_time(unit)
      1 -> System.convert_time_unit(:atomics.get(r, 2), :millisecond, unit)
    end
  end

  @doc "The mock time, or 0 when the system time is used."
  def mocktime(%__MODULE__{ref: r}), do: :atomics.get(r, 1)

  @doc "Sets the mock unix time in seconds; 0 goes back to the system time (Core `SetMockTime`)."
  def set(%__MODULE__{ref: r}, t) when is_integer(t) and t >= 0, do: :atomics.put(r, 1, t)

  @doc """
  Moves the clock `s` seconds forward: the mock time (set to the system time
  first if none is set) and the monotonic clock (frozen at its current
  value first if it runs). `advance(clock, 0)` freezes both now.
  """
  def advance(%__MODULE__{ref: r} = c, s) when is_integer(s) and s >= 0 do
    if :atomics.get(r, 1) == 0, do: set(c, System.os_time(:second))

    if :atomics.get(r, 3) == 0 do
      :atomics.put(r, 2, System.monotonic_time(:millisecond))
      :atomics.put(r, 3, 1)
    end

    :atomics.add(r, 1, s)
    :atomics.add(r, 2, s * 1000)
  end

  @doc """
  Runs the periodic work of `servers` (pids or registered names; absent ones
  are skipped) one after another and waits for each to finish it. A server
  that exits meanwhile counts as done.
  """
  def tick(servers, timeout \\ 5_000) do
    for s <- List.wrap(servers), pid = GenServer.whereis(s), is_pid(pid) do
      ref = Process.monitor(pid)
      send(pid, {__MODULE__, :tick, self(), ref})

      receive do
        {^ref, :ticked} -> Process.demonitor(ref, [:flush])
        {:DOWN, ^ref, :process, _, _} -> :ok
      after
        timeout -> exit({:tick_timeout, pid})
      end
    end

    :ok
  end

  @doc "Called by a ticked process once its tick has run (`tick/2`)."
  def ticked({from, ref}), do: send(from, {ref, :ticked})
end
