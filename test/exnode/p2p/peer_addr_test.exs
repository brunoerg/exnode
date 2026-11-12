defmodule Exnode.P2P.PeerAddrTest do
  @moduledoc """
  `Peer` address relay with a real `AddrMan` (Core `ProcessAddrs`,
  `GETADDR`):

  * a peer we sent getaddr to may answer with many addresses, which reach
    the address book; an unsolicited inbound peer gets only its token
    bucket (1 address);
  * addrv2 carries networks addr cannot (here TorV3);
  * a block-relay-only peer's addresses are ignored;
  * an inbound getaddr is answered once, with addrv2 to a peer that sent
    sendaddrv2, and otherwise with addr filtered to IPv4/IPv6.
  """
  use Exnode.NodeCase

  alias Exnode.P2P.{AddrMan, Frame, Message}

  @p Exnode.ChainParams.get(:regtest)

  setup %{tmp_dir: dir} do
    node = TestNode.start(dir, listen: 0)
    %{n: node.n, port: node.port}
  end

  # Routable IPv4 addresses, each in its own /16 group.
  defp ipv4s(count, now),
    do:
      for(
        i <- 1..count,
        do: %{time: now - 3600, services: 9, net: :ipv4, addr: <<1, i, 0, 1>>, port: 18444}
      )

  defp torv3s(count, now),
    do:
      for(
        i <- 1..count,
        do: %{
          time: now - 3600,
          services: 9,
          net: :torv3,
          addr: :crypto.hash(:sha256, <<i>>),
          port: 18444
        }
      )

  # A ping/pong round trip: every message sent before it has been handled.
  defp barrier(sock) do
    nonce = System.unique_integer([:positive])
    :ok = FakePeer.send_msgs(sock, {:ping, nonce})
    wait_pong(sock, nonce)
  end

  defp wait_pong(sock, nonce) do
    [{"pong", <<n::little-64>>}] = FakePeer.recv(sock, ["pong"], 1)
    if n == nonce, do: :ok, else: wait_pong(sock, nonce)
  end

  defp handshaked(pid), do: wait_until(fn -> :sys.get_state(pid).verack_received end)

  test "a reply to our getaddr reaches the address book; it is not limited to 1 token", %{n: n} do
    {pid, sock} = FakePeer.connect_from(n, node: %{addrman: n.addrman})
    handshaked(pid)
    # A manual outbound peer was sent getaddr at verack.
    assert [{"getaddr", _}] = FakePeer.recv(sock, ["getaddr"], 1)
    :ok = FakePeer.send_msgs(sock, {:addr, ipv4s(20, System.os_time(:second))})
    barrier(sock)
    wait_until(fn -> AddrMan.size(n.addrman, :ipv4) > 1 end)
  end

  test "an unsolicited inbound peer's addresses are limited to its token bucket",
       %{n: n, port: port} do
    sock = FakePeer.dial(port)
    FakePeer.recv(sock, ["verack"], 1)
    :ok = FakePeer.send_msgs(sock, {:addr, ipv4s(20, System.os_time(:second))})
    barrier(sock)
    # AddrMan.add is a cast: a call after it sees its effect.
    assert AddrMan.size(n.addrman) <= 1
  end

  test "addrv2 carries TorV3 addresses", %{n: n} do
    {pid, sock} = FakePeer.connect_from(n, node: %{addrman: n.addrman})
    handshaked(pid)
    :ok = FakePeer.send_msgs(sock, {:addrv2, torv3s(1, System.os_time(:second))})
    barrier(sock)
    wait_until(fn -> AddrMan.size(n.addrman, :torv3) == 1 end)
  end

  test "a block-relay-only peer's addresses are ignored", %{n: n} do
    {pid, sock} =
      FakePeer.connect_from(n, conn_type: :block_relay, node: %{addrman: n.addrman})

    handshaked(pid)
    :ok = FakePeer.send_msgs(sock, {:addr, ipv4s(5, System.os_time(:second))})
    barrier(sock)
    assert AddrMan.size(n.addrman) == 0
  end

  test "inbound getaddr: addrv2 with every network, or addr with IPv4/IPv6 only, once",
       %{n: n, port: port} do
    now = System.os_time(:second)
    AddrMan.add(n.addrman, ipv4s(60, now) ++ torv3s(60, now), :seed)
    wait_until(fn -> AddrMan.size(n.addrman) >= 100 end)

    # A v1 peer (no sendaddrv2).
    v1 = FakePeer.dial(port)
    FakePeer.recv(v1, ["verack"], 1)
    :ok = FakePeer.send_msgs(v1, :getaddr)
    [{"addr", payload}] = FakePeer.recv(v1, ["addr"], 1)
    {:ok, {:addr, v1_addrs}} = Message.decode("addr", payload)

    # A peer that sent sendaddrv2 before verack. Both get the same cached
    # answer (one per requester network, here IPv4).
    v2 = FakePeer.dial(port, handshake: false)
    :ok = FakePeer.send_msgs(v2, [{:version, FakePeer.version()}, :sendaddrv2, :verack, :getaddr])
    [{"addrv2", payload}] = FakePeer.recv(v2, ["addrv2"], 1)
    {:ok, {:addrv2, v2_addrs}} = Message.decode("addrv2", payload)

    assert Enum.any?(v2_addrs, &(&1.net == :torv3))
    assert v1_addrs != [] and Enum.all?(v1_addrs, &(&1.net in [:ipv4, :ipv6]))

    assert MapSet.new(v1_addrs, & &1.addr) ==
             MapSet.new(for a <- v2_addrs, a.net == :ipv4, do: a.addr)

    # Answered once per connection.
    :ok = FakePeer.send_msgs(v1, :getaddr)
    :ok = FakePeer.send_msgs(v1, {:ping, 9})
    msgs = recv_until_pong(v1, 9)
    refute "addr" in msgs
  end

  # Commands read until the pong for `nonce`.
  defp recv_until_pong(sock, nonce, buf \\ <<>>, acc \\ []) do
    case Frame.decode(@p.magic, buf) do
      {:ok, "pong", <<^nonce::little-64>>, _} ->
        Enum.reverse(acc)

      {:ok, cmd, _payload, rest} ->
        recv_until_pong(sock, nonce, rest, [cmd | acc])

      _ ->
        {:ok, data} = :gen_tcp.recv(sock, 0, 5_000)
        recv_until_pong(sock, nonce, buf <> data, acc)
    end
  end
end
