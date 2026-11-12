defmodule Exnode.RPC.ComponentRestartTest do
  @moduledoc """
  SVC-4 (STATE_MACHINES.md): `Methods.call` rescued exceptions but not
  exits, so a method reaching a process that was restarting (a Relay or
  Services subtree restart) exited the HTTP handler: the client lost the
  connection, and with it every answer of a batch.
  """
  use ExUnit.Case, async: true

  alias Exnode.RPC.Methods

  test "a method whose process is gone answers an internal error instead of exiting" do
    ctx = %{mempool: :no_such_mempool_for_rpc}
    assert {:error, -32603, msg} = Methods.call("getmempoolinfo", [], ctx)
    assert msg =~ "unavailable"
    assert {:error, -32603, _} = Methods.call("getrawmempool", [], ctx)
  end
end
