defmodule Exnode.Test.Wait do
  @moduledoc "Test helper: polling for a condition."

  @doc """
  Polls `f` every `interval` ms until it returns truthy; fails the test
  after `timeout` ms. Returns `:ok`.
  """
  def wait_until(f, timeout \\ 5_000, interval \\ 20) do
    if until?(f, timeout, interval),
      do: :ok,
      else: ExUnit.Assertions.flunk("condition not met within #{timeout} ms")
  end

  @doc "Like `wait_until/3`, but returns whether `f` became truthy in time."
  def until?(f, timeout \\ 5_000, interval \\ 20) do
    deadline = System.monotonic_time(:millisecond) + timeout
    poll(f, deadline, interval)
  end

  defp poll(f, deadline, interval) do
    cond do
      f.() -> true
      System.monotonic_time(:millisecond) >= deadline -> false
      true -> Process.sleep(interval) && poll(f, deadline, interval)
    end
  end
end
