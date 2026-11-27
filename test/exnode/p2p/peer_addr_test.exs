defmodule Exnode.P2P.PeerAddrTest do
  @moduledoc """
  `Peer` address relay with a real `AddrMan` (Core `ProcessAddrs`,
  `GETADDR`):

  * a peer we sent getaddr to may answer with many addresses, which reach
    the address book; an unsolicited inbound peer gets only its token
    bucket (1 address);
  * addrv2 carries networks addr cannot (here TorV3), but only reachable
    networks are stored (IPv4, IPv6), as in Core;
  * (regression) each address is sanitised as in Core
    `ProcessAddrs` before the address book sees it: a time before 1973 or
    more than 10 minutes ahead becomes 5 days ago (a future time made an
    entry, even a tried one, `terrible?` and evictable), addresses without
    NODE_NETWORK or NODE_NETWORK_LIMITED and discouraged ones are dropped;
  * a block-relay-only peer's addresses are ignored;
  * an inbound getaddr is answered once, with addrv2 to a peer that sent
    sendaddrv2, and otherwise with addr filtered to IPv4/IPv6.
  """
  use Exnode.NodeCase

  alias Exnode.P2P.{AddrMan, Discouraged, Frame, Message}
  alias Exnode.P2P.AddrMan.Table

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

  defp handshaked(pid), do: wait_until(fn -> match?({{:ready, _}, _}, :sys.get_state(pid)) end)

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

  test "addrv2 carries TorV3 addresses; without onion reachability they are not stored",
       %{n: n} do
    now = System.os_time(:second)
    {pid, sock} = FakePeer.connect_from(n, node: %{addrman: n.addrman})
    handshaked(pid)
    :ok = FakePeer.send_msgs(sock, {:addrv2, torv3s(1, now) ++ ipv4s(1, now)})
    barrier(sock)
    # The IPv4 one in the same message is stored: the TorV3 one was decoded.
    wait_until(fn -> AddrMan.size(n.addrman, :ipv4) == 1 end)
    assert AddrMan.size(n.addrman, :torv3) == 0
  end

  # Regression: an addrv2 IPv6 address carrying an IPv4 one (::ffff:a.b.c.d)
  # was stored as IPv6. It escaped the local/private checks (so ::ffff:127.0.0.1
  # or ::ffff:10.0.0.1 could be dialled), sat in a single IPv6 netgroup apart
  # from its IPv4 /16, and counted as an IPv6 address. Core reads it as
  # invalid, as it does TORv2 and internal addresses embedded in IPv6.
  test "addrv2 IPv6 with an embedded IPv4, TORv2 or internal prefix is not stored", %{n: n} do
    now = System.os_time(:second)
    {pid, sock} = FakePeer.connect_from(n, node: %{addrman: n.addrman})
    handshaked(pid)
    assert [{"getaddr", _}] = FakePeer.recv(sock, ["getaddr"], 1)

    embedded =
      for a <- [
            <<0::80, 0xFF, 0xFF, 127, 0, 0, 1>>,
            <<0::80, 0xFF, 0xFF, 10, 0, 0, 1>>,
            <<0::80, 0xFF, 0xFF, 8, 8, 8, 8>>,
            <<0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43, 1::80>>,
            <<0xFD, 0x6B, 0x88, 0xC0, 0x87, 0x24, 1::80>>
          ],
          do: %{time: now - 3600, services: 9, net: :ipv6, addr: a, port: 18444}

    :ok = FakePeer.send_msgs(sock, {:addrv2, embedded ++ ipv4s(1, now)})
    barrier(sock)
    wait_until(fn -> AddrMan.size(n.addrman, :ipv4) == 1 end)
    assert AddrMan.size(n.addrman, :ipv6) == 0
  end

  # The address book's entry for `a` (time, services, ...), or nil.
  defp entry(addrman, a) do
    t = :sys.get_state(addrman).t

    case t.ids[AddrMan.key(a)] do
      nil -> nil
      id -> t.info[id]
    end
  end

  defp addr(i, time, services \\ 9),
    do: %{time: time, services: services, net: :ipv4, addr: <<2, i, 0, 1>>, port: 18444}

  test "a far-future or ancient time is clamped to 5 days ago; a known entry stays usable",
       %{n: n} do
    now = System.os_time(:second)
    known = addr(1, now - 3600)
    AddrMan.add(n.addrman, [known], :seed)
    wait_until(fn -> AddrMan.find_entry(n.addrman, AddrMan.key(known)) != nil end)

    {pid, sock} = FakePeer.connect_from(n, node: %{addrman: n.addrman})
    handshaked(pid)
    assert [{"getaddr", _}] = FakePeer.recv(sock, ["getaddr"], 1)

    msg = [%{known | time: 0xFFFFFFFF}, addr(2, 0xFFFFFFFF), addr(3, 5)]
    :ok = FakePeer.send_msgs(sock, {:addr, msg})
    barrier(sock)
    wait_until(fn -> AddrMan.size(n.addrman, :ipv4) == 3 end)

    k = entry(n.addrman, known)
    # Unchanged (its time is newer than 5 days ago); before, 2^32 - 2 h.
    assert k.time == now - 3600
    refute Table.terrible?(k, now)

    for i <- [2, 3] do
      e = entry(n.addrman, addr(i, 0))
      # 5 days ago, minus the 2 h gossip penalty.
      assert_in_delta e.time, now - 5 * 86_400 - 2 * 3600, 60
      refute Table.terrible?(e, now)
    end
  end

  test "addresses without NODE_NETWORK or NODE_NETWORK_LIMITED are not stored",
       %{n: n} do
    now = System.os_time(:second)
    {pid, sock} = FakePeer.connect_from(n, node: %{addrman: n.addrman})
    handshaked(pid)
    assert [{"getaddr", _}] = FakePeer.recv(sock, ["getaddr"], 1)

    # 0: nothing; 8: NODE_WITNESS only; 1024: NODE_NETWORK_LIMITED; 9: NETWORK | WITNESS.
    msg = [addr(1, now, 0), addr(2, now, 8), addr(3, now, 1024), addr(4, now, 9)]
    :ok = FakePeer.send_msgs(sock, {:addr, msg})
    barrier(sock)
    wait_until(fn -> AddrMan.size(n.addrman, :ipv4) >= 2 end)

    stored = for i <- 1..4, AddrMan.find_entry(n.addrman, AddrMan.key(addr(i, 0))), do: i
    assert stored == [3, 4]
  end

  test "discouraged addresses are not stored", %{n: n} do
    now = System.os_time(:second)
    bad = addr(1, now)

    :sys.replace_state(n.connman, fn st ->
      %{st | discouraged: Discouraged.put(st.discouraged, Discouraged.key(bad), now)}
    end)

    {pid, sock} = FakePeer.connect_from(n, node: %{addrman: n.addrman, connman: n.connman})
    handshaked(pid)
    assert [{"getaddr", _}] = FakePeer.recv(sock, ["getaddr"], 1)
    :ok = FakePeer.send_msgs(sock, {:addr, [bad, addr(2, now)]})
    barrier(sock)
    wait_until(fn -> AddrMan.size(n.addrman, :ipv4) >= 1 end)

    assert AddrMan.find_entry(n.addrman, AddrMan.key(bad)) == nil
    assert AddrMan.find_entry(n.addrman, AddrMan.key(addr(2, 0))) != nil
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
