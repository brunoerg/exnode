defmodule Exnode.Util.TokenBucket do
  @moduledoc """
  Port of Core v32.1 `util/tokenbucket.h` `TokenBucket`. Times are
  milliseconds (Core: a clock's time points).
  """

  defstruct [:rate, :cap, :value, last: nil]

  @doc "`rate` tokens per second; `value` (clamped to `cap`) is the initial balance."
  def new(rate, value, cap), do: %__MODULE__{rate: rate, cap: cap, value: min(value, cap)}

  @doc """
  Refills for the time since the last call. The first call only sets the
  baseline. Time going backwards adds nothing, but (as in Core) the
  baseline still moves to `now`.
  """
  def increment(%__MODULE__{last: last} = t, now) do
    value =
      if last != nil and now > last and t.value < t.cap,
        do: min(t.cap, t.value + t.rate * (now - last) / 1000),
        else: t.value

    %{t | value: value, last: now}
  end

  @doc "Consumes `n`; `{bucket, ok}` with ok false once the balance is at or below `floor`."
  def decrement(%__MODULE__{} = t, n \\ 1.0, floor \\ 0.0),
    do: {%{t | value: t.value - n}, t.value - n > floor}

  def value(%__MODULE__{value: v}), do: v
end
