defmodule Exnode.NodeCase do
  @moduledoc """
  Case template for tests that run a whole node (`Exnode.Node`) and talk to
  it over TCP, without bitcoind. Not async (real sockets, real timers);
  every test gets a `tmp_dir`. Imports `Exnode.Test.Wait`; aliases
  `Exnode.Test.FakePeer`, `Exnode.Test.Node` (as `TestNode`) and
  `Exnode.Test.Coins`.
  """
  use ExUnit.CaseTemplate

  using do
    quote do
      @moduletag :tmp_dir
      import Exnode.Test.Wait
      alias Exnode.Test.{Coins, FakePeer}
      alias Exnode.Test.Node, as: TestNode
    end
  end
end

defmodule Exnode.InteropCase do
  @moduledoc """
  Case template for tests against the pinned bitcoind v32.1. Like
  `Exnode.NodeCase`, plus:
  * every test is tagged `:interop`; `test_helper.exs` excludes the tag
    when bitcoind is not built, and `mix test --exclude interop` skips them;
  * aliases `Exnode.Test.Bitcoind`;
  * with `@moduletag :bitcoind` (or `@tag :bitcoind`), a bitcoind is
    started in `<tmp_dir>/btc` before each test, stopped after, and put
    in the context as `btc`. `@moduletag bitcoind: [args]` passes extra
    arguments.
  """
  use ExUnit.CaseTemplate

  alias Exnode.Test.Bitcoind

  using do
    quote do
      @moduletag :tmp_dir
      @moduletag :interop
      import Exnode.Test.Wait
      alias Exnode.Test.{Bitcoind, Coins, FakePeer}
      alias Exnode.Test.Node, as: TestNode
    end
  end

  setup ctx do
    case ctx[:bitcoind] do
      nil ->
        :ok

      args ->
        btc = Bitcoind.start(Path.join(ctx.tmp_dir, "btc"), if(args == true, do: [], else: args))
        on_exit(fn -> Bitcoind.stop(btc) end)
        {:ok, btc: btc}
    end
  end
end
