defmodule Exnode.DoS.ListenerAcceptTest do
  @moduledoc """
  Regression: `{:ok, sock} = :gen_tcp.accept(lsock)` made
  any accept error (EMFILE/ENFILE under fd exhaustion) crash the acceptor
  and the Listener; repeated restarts could take the P2P subtree, then the
  node, down. Now the loop logs, backs off and goes on, as Core's
  AcceptConnection does. Also: max connections are trimmed to the fd limit
  (Core init).
  """
  use ExUnit.Case, async: false
  @moduletag :dos

  alias Exnode.P2P.{Connman, Listener}

  defmodule RefuseAll do
    use GenServer
    def init(test), do: {:ok, test}

    def handle_call({:accept_inbound?, target}, _f, test) do
      send(test, {:asked, target})
      {:reply, false, test}
    end
  end

  test "accept errors do not crash the listener" do
    {:ok, cm} = GenServer.start_link(RefuseAll, self())
    {:ok, fails} = Agent.start_link(fn -> 20 end)

    accept = fn lsock ->
      if Agent.get_and_update(fails, &{&1, max(&1 - 1, 0)}) > 0,
        do: {:error, :emfile},
        else: :gen_tcp.accept(lsock)
    end

    Process.flag(:trap_exit, true)

    {:ok, l} =
      Listener.start_link(
        port: 0,
        ip: {127, 0, 0, 1},
        connman: cm,
        node: %{},
        peer_sup: nil,
        accept: accept
      )

    port = Listener.port(l)
    # 20 errors at 100 ms back-off each, then accepts again.
    {:ok, c} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    assert_receive {:asked, {"127.0.0.1", _}}, 5_000
    assert {:error, :closed} = :gen_tcp.recv(c, 0, 2_000)
    assert Agent.get(fails, & &1) == 0
    refute_received {:EXIT, ^l, _}
    assert Process.alive?(l)
  end

  # Accepts, then exits before the registration: Connman crashing in the
  # window between the Listener's accept_inbound? and register_inbound.
  defmodule AcceptThenDie do
    use GenServer
    def init(test), do: {:ok, test}
    def handle_call({:accept_inbound?, _}, _f, test), do: {:stop, :normal, true, test}
  end

  # Regression: registration was a cast, dropped while
  # Connman restarted, and the peer then ran untracked (outside the inbound
  # limit and eviction). Now it is a call; with no Connman the connection
  # is refused.
  test "an inbound peer that cannot be registered is refused, not left untracked" do
    {:ok, cm} = GenServer.start(AcceptThenDie, self())
    {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)
    node = %{params: Exnode.ChainParams.get(:regtest), services: 9, nonce: 1, user_agent: "/t/"}

    {:ok, l} =
      Listener.start_link(port: 0, ip: {127, 0, 0, 1}, connman: cm, node: node, peer_sup: sup)

    {:ok, c} = :gen_tcp.connect({127, 0, 0, 1}, Listener.port(l), [:binary, active: false])
    assert {:error, :closed} = :gen_tcp.recv(c, 0, 2_000)
    Exnode.Test.Wait.wait_until(fn -> DynamicSupervisor.count_children(sup).active == 0 end)
    assert Process.alive?(l)
  end

  test "max connections are trimmed to the fd limit" do
    assert Connman.fit_fds(200, 1_048_576) == 200
    assert Connman.fit_fds(200, 600) == 100
    assert Connman.fit_fds(200, 100) == 0
    assert Connman.fit_fds(200, nil) == 200
  end
end
