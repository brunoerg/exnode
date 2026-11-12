defmodule Exnode.P2P.InboundLimitsTest do
  @moduledoc """
  Integration: inbound slots, eviction and the
  tx-relay limit on a running node, with fake v1 peers over TCP.
  * Slots full and every inbound peer protected: the new connection is
    dropped (Core: "failed to find an eviction candidate").
  * Slots full with enough unprotected peers: one existing inbound peer is
    evicted and the new one is served.
  * At most half the inbound slots relay txs: a further tx-relaying peer is
    dropped after its version when no tx-relaying peer can be evicted,
    while a non-relaying one is accepted.
  """
  use Exnode.NodeCase

  alias Exnode.P2P.{Connman, Frame}

  @p Exnode.ChainParams.get(:regtest)

  # 8 full-relay + 2 block-relay + 1 feeler slots are outbound: inbound = max - 11.
  defp start_node(dir, max_inbound) do
    %{n: n, port: port} = TestNode.start(dir, listen: 0, max_connections: 11 + max_inbound)
    {n, port}
  end

  # Our local ports of the inbound peers the node holds (live peer processes):
  # a test socket is connected iff its port is here.
  defp held(n) do
    for {pid, %{type: :inbound, target: {_, port}}} <- Connman.peers(n.connman),
        Process.alive?(pid),
        into: MapSet.new(),
        do: port
  end

  defp port_of(sock), do: sock |> :inet.sockname() |> elem(1) |> elem(1)

  # A fake v1 peer: version (with the relay flag) and verack. A rejected
  # connection is closed by the node right after accept, possibly before or
  # between these sends: `dial` does not assert them, `outcome/1` reports it.
  defp fake_peer(port, relay), do: FakePeer.dial(port, version: %{relay: relay})

  # Reads until the node's verack arrives (handshake served) or the socket closes.
  defp outcome(sock, buf \\ <<>>, deadline \\ System.monotonic_time(:millisecond) + 5_000) do
    case Frame.decode(@p.magic, buf) do
      {:ok, "verack", _, _} ->
        :served

      {:ok, _, _, rest} ->
        outcome(sock, rest, deadline)

      {:reject, _, rest} ->
        outcome(sock, rest, deadline)

      _ ->
        left = deadline - System.monotonic_time(:millisecond)

        if left <= 0 do
          :timeout
        else
          case :gen_tcp.recv(sock, 0, left) do
            {:ok, data} -> outcome(sock, buf <> data, deadline)
            {:error, :closed} -> :closed
            {:error, :timeout} -> :timeout
          end
        end
    end
  end

  # The node closes `sock`: reads until it does (bounded, not a sleep).
  defp closed?(sock) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:error, :closed} -> true
      {:ok, _} -> closed?(sock)
      {:error, :timeout} -> false
    end
  end

  test "full inbound slots with all peers protected: the new connection is dropped", %{
    tmp_dir: dir
  } do
    {n, port} = start_node(dir, 4)
    socks = for _ <- 1..4, do: fake_peer(port, false)
    for s <- socks, do: assert(outcome(s) == :served)
    assert outcome(fake_peer(port, false)) == :closed
    # The four are still connected: the node holds them.
    assert held(n) == MapSet.new(socks, &port_of/1)
  end

  test "full inbound slots with unprotected peers: one is evicted for the new peer", %{
    tmp_dir: dir
  } do
    # Eviction protects at most 4 + 8 + 4 + 8 + 4 peers by fixed rules, then
    # half the rest: with 40 slots some peers are unprotected.
    {n, port} = start_node(dir, 40)

    socks =
      for _ <- 1..40,
          do:
            (
              s = fake_peer(port, false)
              assert(outcome(s) == :served)
              s
            )

    new = fake_peer(port, false)
    assert outcome(new) == :served
    # Once the evicted peer is gone the node holds the new one and 39 others.
    wait_until(fn -> MapSet.size(held(n)) == 40 end)
    assert MapSet.member?(held(n), port_of(new))
    [evicted] = Enum.reject(socks, &MapSet.member?(held(n), port_of(&1)))
    assert closed?(evicted)
  end

  test "at most half the inbound slots relay txs", %{tmp_dir: dir} do
    {n, port} = start_node(dir, 4)

    relaying =
      for _ <- 1..2,
          do:
            (
              s = fake_peer(port, true)
              assert(outcome(s) == :served)
              s
            )

    # A third tx-relaying peer: over 50% of 4; the two relaying are protected, so it goes.
    assert outcome(fake_peer(port, true)) == :closed
    # A non-relaying peer still gets a slot.
    other = fake_peer(port, false)
    assert outcome(other) == :served
    wait_until(fn -> MapSet.size(held(n)) == 3 end)
    assert held(n) == MapSet.new([other | relaying], &port_of/1)
  end
end
