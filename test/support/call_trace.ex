defmodule Exnode.Test.CallTrace do
  @moduledoc """
  Test helper: the calls to some functions made by the calling process
  while a function runs.

  Each use gets its own trace session (OTP `trace` module): its function
  patterns and process flags are not seen by other sessions, so async
  tests tracing at the same time (or `:tprof`) neither add calls to each
  other's counts nor switch each other's patterns off.
  """
  import ExUnit.Assertions

  @doc """
  Runs `fun` with calls to `mfas` traced (`flags`: `[:local]` for every
  call, `[:global]` for calls from other modules only). Returns
  `{result, calls}`, `calls` as `{module, function, args}` in call order.
  """
  def calls(mfas, fun, flags \\ [:local]) do
    me = self()
    tracer = spawn_link(fn -> collect(me, []) end)
    session = :trace.session_create(__MODULE__, tracer, [])

    try do
      # A module not loaded yet matches nothing (code is loaded lazily), and
      # its calls would go uncounted: load it, and require a match.
      for {m, _, _} = mfa <- mfas do
        Code.ensure_loaded!(m)

        assert :trace.function(session, mfa, true, flags) > 0,
               "no function matches #{inspect(mfa)}"
      end

      :trace.process(session, me, true, [:call])

      result =
        try do
          fun.()
        after
          :trace.process(session, me, false, [:call])
        end

      # Every trace message has reached the tracer.
      ref = :trace.delivered(session, me)
      assert_receive {:trace_delivered, ^me, ^ref}, 5_000
      send(tracer, {:done, me})
      assert_receive {:calls, ^tracer, calls}, 5_000
      {result, calls}
    after
      :trace.session_destroy(session)
    end
  end

  defp collect(me, acc) do
    receive do
      {:trace, ^me, :call, mfa} -> collect(me, [mfa | acc])
      {:done, ^me} -> send(me, {:calls, self(), Enum.reverse(acc)})
    end
  end
end
