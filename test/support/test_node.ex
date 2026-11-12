defmodule Exnode.Test.Node do
  @moduledoc """
  Test helper: a whole exnode node (`Exnode.Node`) under the test's supervisor.
  """
  import ExUnit.Callbacks, only: [start_supervised!: 1]

  @doc """
  Starts a regtest node in `dir` under the test supervisor (stopped when
  the test ends). Returns `%{name: prefix, n: Exnode.Node.names(prefix),
  port: listen port or nil, clock: the node's Exnode.Clock}`.

  `opts` go to `Exnode.Node` with these defaults: `chain: :regtest`, a
  unique `name`, and `connect: [{"127.0.0.1", 1}]` (manual mode with a
  dead address: no outbound peers, no DNS or fixed seeds). `listen: 0`
  binds a free port, returned as `port`. The clock is a new one unless
  given (`:clock`): `Exnode.Clock.advance/2` it, then `Exnode.Node.tick/1`
  the node's name, instead of sleeping. The child id is the name, so
  several nodes can run in one test (`stop_supervised(node.name)`).
  """
  def start(dir, opts \\ []) do
    name = Keyword.get_lazy(opts, :name, fn -> unique_name() end)

    clock = Keyword.get_lazy(opts, :clock, &Exnode.Clock.new/0)

    opts =
      Keyword.merge([chain: :regtest, datadir: dir, connect: [{"127.0.0.1", 1}]], opts)
      |> Keyword.merge(name: name, clock: clock)

    start_supervised!(Supervisor.child_spec({Exnode.Node, opts}, id: name))

    %{
      name: name,
      n: Exnode.Node.names(name),
      port: Exnode.Node.listen_port(name),
      clock: clock
    }
  end

  @doc """
  A port free right now, for listeners that cannot bind port 0 and report
  it (RPC, REST, bitcoind). Another process may take it before it is bound;
  prefer `listen: 0` for the P2P listener.
  """
  def free_port do
    {:ok, s} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(s)
    :gen_tcp.close(s)
    port
  end

  @doc "A fresh node name (registered-name prefix)."
  def unique_name, do: :"Exnode.TestNode#{System.unique_integer([:positive])}"

  @doc "The node's chain tip hash, display hex."
  def tip_hex(%{n: n}), do: Exnode.Crypto.Hash.to_hex(Exnode.Chain.State.tip(n.chain_state).hash)
end
