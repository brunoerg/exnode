defmodule Exnode.P2P.PeerProtocolTest do
  @moduledoc """
  `Peer` protocol rules and timeouts, over real sockets (Core
  `ProcessMessage` / `SendMessages`):

  * version: a full-relay outbound peer without NETWORK | WITNESS, a
    version below MIN_PEER_PROTO_VERSION, and an inbound connection to
    ourselves (our nonce) are disconnected; a second version or verack is
    ignored, as is anything before version;
  * wtxidrelay or sendaddrv2 after verack disconnects;
  * after the handshake, oversized headers (by the count alone), oversized
    complete inv / getdata / addr / addrv2 and a non-continuous headers
    sequence are misbehaviour; a truncated oversized vector and an
    oversized notfound are dropped, and a manual peer is never
    disconnected for misbehaving (Core; AUD-A1-5 / A2-5); a tx from a
    block-relay-only peer disconnects it;
  * timeouts on a mock clock, run by explicit ticks: no handshake within
    60 s, no pong within 20 min, and the headers-sync deadline: a peer
    that leaves our best header old past it is disconnected once another
    preferred peer could sync instead.
  """
  use Exnode.NodeCase

  alias Exnode.Clock
  alias Exnode.Codec.CompactSize
  alias Exnode.P2P.{Frame, Message}
  alias Exnode.Test.BlockBuilder, as: BB

  @p Exnode.ChainParams.get(:regtest)

  setup %{tmp_dir: dir} do
    node = TestNode.start(dir, listen: 0)
    %{n: node.n, port: node.port}
  end

  # The node dials us. Only explicit ticks on `clock` (set to now) run the
  # peer's periodic pass. The peer is monitored from its start, and the
  # handshake (`version:` overrides; none with `handshake: false`) is sent
  # after, so every exit is seen with its reason. Returns {pid, socket,
  # clock, monitor ref}.
  defp connect(n, opts \\ []) do
    clock = Clock.new()
    Clock.set(clock, System.os_time(:second))
    node = Map.merge(%{clock: clock, tick_ms: nil}, Map.new(Keyword.get(opts, :node, %{})))

    {pid, sock, ref} =
      FakePeer.connect_from(n, Keyword.merge(opts, node: node, handshake: false, monitor: true))

    if Keyword.get(opts, :handshake, true) do
      v = FakePeer.version(Keyword.get(opts, :version, %{}))
      :ok = FakePeer.send_msgs(sock, [{:version, v}, :verack])
    end

    {pid, sock, clock, ref}
  end

  defp handshaked(pid), do: wait_until(fn -> :sys.get_state(pid).verack_received end)

  # Ticks every 5 min up to `deadline`, answering a ping each time, so only
  # the headers-sync deadline can end the peer.
  defp responsive_until(pid, sock, clock, deadline) do
    Stream.iterate(Clock.now(clock), &(&1 + 300))
    |> Enum.take_while(&(&1 + 300 <= deadline))
    |> Enum.each(fn _ ->
      Clock.advance(clock, 300)
      :ok = Clock.tick(pid)
      until_pong(sock, System.unique_integer([:positive]))
      assert Process.alive?(pid)
    end)
  end

  defp assert_stopped(ref, reason),
    do: assert_receive({:DOWN, ^ref, :process, _, {:shutdown, ^reason}}, 5_000)

  defp send_raw(sock, cmd, payload),
    do: :ok = :gen_tcp.send(sock, IO.iodata_to_binary(Frame.encode(@p.magic, cmd, payload)))

  # Decoded messages read until a pong with `nonce` (sent here): everything
  # the peer did before handling the ping. Answers its pings meanwhile.
  defp until_pong(sock, nonce) do
    :ok = FakePeer.send_msgs(sock, {:ping, nonce})
    read_until_pong(sock, nonce, <<>>, [])
  end

  defp read_until_pong(sock, nonce, buf, acc) do
    case Frame.decode(@p.magic, buf) do
      {:ok, cmd, payload, rest} ->
        case Message.decode(cmd, payload) do
          {:ok, {:pong, ^nonce}} ->
            Enum.reverse(acc)

          {:ok, {:ping, n} = m} ->
            :ok = FakePeer.send_msgs(sock, {:pong, n})
            read_until_pong(sock, nonce, rest, [m | acc])

          {:ok, m} ->
            read_until_pong(sock, nonce, rest, [m | acc])

          _ ->
            read_until_pong(sock, nonce, rest, acc)
        end

      _ ->
        {:ok, data} = :gen_tcp.recv(sock, 0, 5_000)
        read_until_pong(sock, nonce, buf <> data, acc)
    end
  end

  describe "version and verack" do
    test "a full-relay outbound peer without NETWORK | WITNESS is disconnected", %{n: n} do
      {_pid, _sock, _clock, ref} =
        connect(n, conn_type: :outbound_full_relay, version: %{services: 1})

      assert_stopped(ref, {:missing_services, 1})
    end

    test "a version below MIN_PEER_PROTO_VERSION is disconnected", %{n: n} do
      old = Message.min_peer_proto_version() - 1
      {_pid, _sock, _clock, ref} = connect(n, version: %{version: old})
      assert_stopped(ref, {:obsolete_version, old})
    end

    test "an inbound connection carrying our own nonce is a connection to ourselves",
         %{n: n, port: port} do
      before = for {_, p, _, _} <- DynamicSupervisor.which_children(n.peer_sup), do: p
      sock = FakePeer.dial(port, handshake: false)

      new_peers = fn ->
        for({_, p, _, _} <- DynamicSupervisor.which_children(n.peer_sup), do: p) -- before
      end

      wait_until(fn -> length(new_peers.()) == 1 end)
      [pid] = new_peers.()

      ref = Process.monitor(pid)
      nonce = :sys.get_state(pid).node.nonce
      :ok = FakePeer.send_msgs(sock, {:version, FakePeer.version(nonce: nonce)})
      assert_stopped(ref, :connected_to_self)
    end

    test "a second version is ignored", %{n: n} do
      {pid, sock, _clock, _ref} = connect(n)
      handshaked(pid)
      :ok = FakePeer.send_msgs(sock, {:version, FakePeer.version(user_agent: "/second/")})
      until_pong(sock, 41)
      assert :sys.get_state(pid).version.user_agent == "/fake/"
    end

    test "a second verack is ignored: the verack replies are sent once", %{n: n} do
      {pid, sock, _clock, _ref} = connect(n)
      handshaked(pid)
      first = until_pong(sock, 42)
      :ok = FakePeer.send_msgs(sock, :verack)
      second = until_pong(sock, 43)
      # A manual outbound peer gets getaddr (and sendcmpct) at verack, once.
      assert Enum.count(first ++ second, &(&1 == :getaddr)) == 1
      assert Enum.count(second, &match?({:sendcmpct, _}, &1)) == 0
      assert Process.alive?(pid)
    end

    test "messages before version are ignored", %{n: n} do
      {pid, sock, _clock, _ref} = connect(n, handshake: false)
      :ok = FakePeer.send_msgs(sock, [{:ping, 5}, {:version, FakePeer.version()}, :verack])
      handshaked(pid)
      msgs = until_pong(sock, 6)
      refute {:pong, 5} in msgs
    end

    test "wtxidrelay after verack disconnects", %{n: n} do
      {pid, sock, _clock, ref} = connect(n)
      handshaked(pid)
      :ok = FakePeer.send_msgs(sock, :wtxidrelay)
      assert_stopped(ref, :wtxidrelay_after_verack)
    end

    test "sendaddrv2 after verack disconnects", %{n: n} do
      {pid, sock, _clock, ref} = connect(n)
      handshaked(pid)
      :ok = FakePeer.send_msgs(sock, :sendaddrv2)
      assert_stopped(ref, :sendaddrv2_after_verack)
    end
  end

  describe "after the handshake" do
    # Core reads the headers count and checks it before any header.
    test "an oversized headers is misbehaviour from its count alone", %{n: n} do
      {pid, sock, _clock, ref} = connect(n)
      handshaked(pid)
      send_raw(sock, "headers", CompactSize.encode(2_001))
      assert_stopped(ref, {:misbehaving, "headers message size = 2001"})
    end

    # Core deserializes the whole vector before checking its size: a
    # complete oversized one is misbehaviour (AUD-A1-5).
    for {cmd, n, item, why} <- [
          {"inv", 50_001, <<1::little-32, 0::256>>, "inv message size = 50001"},
          {"getdata", 50_001, <<1::little-32, 0::256>>, "inv message size = 50001"},
          {"addr", 1_001, <<0::32, 1::little-64, 0::80, 0xFFFF::16, 1, 2, 3, 4, 8333::16>>,
           "addr message size = 1001"},
          {"addrv2", 1_001, <<0::32, 1, 1, 4, 1, 2, 3, 4, 8333::16>>, "addr message size = 1001"}
        ] do
      test "a complete oversized #{cmd} is misbehaviour", %{n: n} do
        {pid, sock, _clock, ref} = connect(n)
        handshaked(pid)
        payload = [CompactSize.encode(unquote(n)), :binary.copy(unquote(item), unquote(n))]
        send_raw(sock, unquote(cmd), payload)
        assert_stopped(ref, {:misbehaving, unquote(why)})
      end
    end

    # A truncated oversized vector throws in Core's deserialization: the
    # message is dropped, the peer kept. Before, the count alone was
    # misbehaviour. An oversized notfound is ignored by Core even complete.
    test "a truncated oversized vector, or an oversized notfound, is dropped", %{n: n} do
      {pid, sock, _clock, ref} = connect(n)
      handshaked(pid)
      inv = <<1::little-32, 0::256>>

      for {cmd, payload} <- [
            {"inv", CompactSize.encode(50_001)},
            {"getdata", CompactSize.encode(50_001)},
            {"addr", CompactSize.encode(1_001)},
            {"addrv2", CompactSize.encode(1_001)},
            {"notfound", [CompactSize.encode(50_001), :binary.copy(inv, 50_001)]}
          ] do
        send_raw(sock, cmd, payload)
        until_pong(sock, System.unique_integer([:positive]))
        refute_received {:DOWN, ^ref, _, _, _}, cmd
      end

      assert Process.alive?(pid)
    end

    # Core MaybeDiscourageAndDisconnect: a manual peer is never disconnected
    # (nor discouraged) for misbehaving (AUD-A2-5).
    test "a misbehaving manual peer is kept", %{n: n} do
      {pid, sock, _clock, ref} = connect(n, conn_type: :manual)
      handshaked(pid)
      send_raw(sock, "headers", CompactSize.encode(2_001))
      until_pong(sock, System.unique_integer([:positive]))
      refute_received {:DOWN, ^ref, _, _, _}
      assert Process.alive?(pid)
    end

    test "a non-continuous headers sequence is misbehaviour", %{n: n} do
      h1 = BB.next_header(@p.genesis.header)
      h2 = BB.next_header(h1)
      h3 = BB.next_header(h2)
      {pid, sock, _clock, ref} = connect(n)
      handshaked(pid)
      :ok = FakePeer.send_msgs(sock, {:headers, [h1, h3]})
      assert_stopped(ref, {:misbehaving, "non-continuous headers sequence"})
    end

    test "a tx from a block-relay-only peer disconnects it", %{n: n} do
      {pid, sock, _clock, ref} = connect(n, conn_type: :block_relay)
      handshaked(pid)
      :ok = FakePeer.send_msgs(sock, {:tx, BB.coinbase(1, 1).raw})
      assert_stopped(ref, :tx_from_block_relay_peer)
    end
  end

  describe "timeouts" do
    test "no handshake within 60 s", %{n: n} do
      {pid, _sock, clock, ref} = connect(n, handshake: false)
      wait_until(fn -> :sys.get_state(pid).connected_at != nil end)
      Clock.advance(clock, 60)
      :ok = Clock.tick(pid)
      assert Process.alive?(pid)
      Clock.advance(clock, 1)
      :ok = Clock.tick(pid)
      assert_stopped(ref, :handshake_timeout)
    end

    test "no pong within 20 minutes", %{n: n} do
      {pid, sock, clock, ref} = connect(n)
      handshaked(pid)
      # The first pass pings; the test never answers.
      :ok = Clock.tick(pid)
      [{"ping", _}] = FakePeer.recv(sock, ["ping"], 1)
      Clock.advance(clock, 20 * 60)
      :ok = Clock.tick(pid)
      assert Process.alive?(pid)
      Clock.advance(clock, 1)
      :ok = Clock.tick(pid)
      assert_stopped(ref, :ping_timeout)
    end

    test "a stalled sync peer is kept while no other preferred peer could take over",
         %{n: n} do
      bd = %{block_download: n.block_download}
      {pid, sock, clock, ref} = connect(n, node: bd)
      handshaked(pid)
      # The first pass starts headers sync (regtest genesis is years old,
      # deadline = now + 15 min + 1 ms per expected header) and registers
      # the peer as preferred with BlockDownload.
      :ok = Clock.tick(pid)
      deadline = :sys.get_state(pid).headers_sync_timeout
      assert is_integer(deadline)

      # Past the deadline, the only preferred peer: kept, deadline kept.
      responsive_until(pid, sock, clock, deadline)
      Clock.advance(clock, deadline - Clock.now(clock) + 1)
      :ok = Clock.tick(pid)
      assert Process.alive?(pid)
      assert :sys.get_state(pid).headers_sync_timeout == deadline

      # A second outbound peer connects (not syncing: one sync at a time
      # while our best header is old): the next pass disconnects the first.
      {pid2, _sock2, _clock2, _ref2} = connect(n, node: bd)
      handshaked(pid2)
      :ok = Clock.tick(pid2)
      refute :sys.get_state(pid2).sync_started
      :ok = Clock.tick(pid)
      assert_stopped(ref, :headers_sync_timeout)
    end

    test "a sync peer that gets us a recent best header has no deadline left", %{n: n} do
      {pid, sock, clock, _ref} = connect(n, node: %{block_download: n.block_download})
      handshaked(pid)
      :ok = Clock.tick(pid)
      deadline = :sys.get_state(pid).headers_sync_timeout

      # One header timed at the deadline makes our best header recent.
      {tip, ""} = Exnode.Codec.Header.decode(Exnode.Chain.Headers.best_header(n.headers).raw)
      h = BB.next_header(tip, time: deadline)
      :ok = FakePeer.send_msgs(sock, {:headers, [h]})
      wait_until(fn -> Exnode.Chain.Headers.best_header(n.headers).hash == h.hash end)

      responsive_until(pid, sock, clock, deadline)
      Clock.advance(clock, deadline - Clock.now(clock) + 1)
      :ok = Clock.tick(pid)
      assert Process.alive?(pid)
      assert :sys.get_state(pid).headers_sync_timeout == nil
    end
  end
end
