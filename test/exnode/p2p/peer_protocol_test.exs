defmodule Exnode.P2P.PeerProtocolTest do
  @moduledoc """
  `Peer` protocol rules and timeouts, over real sockets (Core
  `ProcessMessage` / `SendMessages`):

  * version: a full-relay outbound peer without NETWORK | WITNESS, a
    version below MIN_PEER_PROTO_VERSION, and an inbound connection to
    ourselves (the nonce of one of our outbound connections still in the
    handshake) are disconnected; every connection sends its own nonce; a
    second version or verack is ignored, as is anything before version;
  * wtxidrelay or sendaddrv2 after verack disconnects;
  * after the handshake, oversized headers (by the count alone), oversized
    complete inv / getdata / addr / addrv2 and a non-continuous headers
    sequence are misbehaviour; a truncated oversized vector and an
    oversized notfound are dropped, and a manual peer is never
    disconnected for misbehaving (Core); a tx from a
    block-relay-only peer disconnects it;
  * timeouts on a mock clock, run by explicit ticks: no handshake within
    60 s, no pong within 20 min, and the headers-sync deadline: a peer
    that leaves our best header old past it is disconnected once another
    preferred peer could sync instead;
  * chain-sync eviction (Core ConsiderEviction): an outbound peer whose
    best known block stays below our tip's work is probed with getheaders
    after 20 min and disconnected 2 min later; up to 4 outbound full-relay
    peers with our tip's work are protected.
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

    # Regression: the node sent one static version nonce on every connection,
    # linking them (block-relay-only ones too) to each other and to the node,
    # and the self-connection check compared against that one value. Core
    # sends a per-connection nLocalHostNonce and CheckIncomingNonce matches
    # an inbound version against outbound connections still in the handshake.
    test "every connection sends its own version nonce", %{n: n, port: port} do
      nonce_of = fn sock ->
        [{"version", pl}] = FakePeer.recv(sock, "version", 1)
        {:ok, {:version, v}} = Message.decode("version", pl)
        v.nonce
      end

      inbound =
        for _ <- 1..2 do
          sock = FakePeer.dial(port, handshake: false)
          :ok = FakePeer.send_msgs(sock, {:version, FakePeer.version()})
          nonce_of.(sock)
        end

      {_pid, sock, _clock, _ref} = connect(n, handshake: false)
      nonces = [nonce_of.(sock) | inbound]
      assert length(Enum.uniq(nonces)) == 3
    end

    test "an inbound version carrying the nonce of our outbound handshake is a connection to ourselves",
         %{n: n, port: port} do
      {_pid, out_sock, _clock, _ref} = connect(n, handshake: false)
      [{"version", pl}] = FakePeer.recv(out_sock, "version", 1)
      {:ok, {:version, %{nonce: nonce}}} = Message.decode("version", pl)

      self_conn = fn ->
        before = for {_, p, _, _} <- DynamicSupervisor.which_children(n.peer_sup), do: p
        sock = FakePeer.dial(port, handshake: false)

        new_peers = fn ->
          for({_, p, _, _} <- DynamicSupervisor.which_children(n.peer_sup), do: p) -- before
        end

        wait_until(fn -> length(new_peers.()) == 1 end)
        [pid] = new_peers.()
        ref = Process.monitor(pid)
        :ok = FakePeer.send_msgs(sock, {:version, FakePeer.version(nonce: nonce)})
        {pid, ref}
      end

      {_, ref} = self_conn.()
      assert_stopped(ref, :connected_to_self)

      # Core fSuccessfullyConnected: once the outbound handshake completes
      # its nonce no longer counts.
      :ok = FakePeer.send_msgs(out_sock, [{:version, FakePeer.version()}, :verack])
      wait_until(fn -> Registry.lookup(n.local_nonces, nonce) == [] end)
      {pid, ref} = self_conn.()
      wait_until(fn -> :sys.get_state(pid).version != nil end)
      refute_received {:DOWN, ^ref, _, _, _}
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
    # complete oversized one is misbehaviour.
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
    # (nor discouraged) for misbehaving.
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

  # The peer announces our active tip (genesis): its best known block then
  # has our tip's work.
  defp announce_tip(n, pid, sock) do
    tip = Exnode.Chain.State.view_tip(Exnode.Chain.State.view(n.chain_state))
    :ok = FakePeer.send_msgs(sock, {:inv, [%{type: :block, hash: tip.hash}]})
    wait_until(fn -> :sys.get_state(pid).best_known != nil end)
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
      # The peer has our tip, so chain-sync eviction leaves it alone.
      announce_tip(n, pid, sock)
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

  describe "chain-sync eviction" do
    # Regression: outbound peers were never checked for chain work. A peer
    # that completed the handshake and answered pings, but never announced
    # a block with our tip's work, held its outbound slot forever.
    for ct <- [:outbound_full_relay, :block_relay] do
      test "a #{ct} peer that never reaches our tip's work is disconnected", %{n: n} do
        {pid, sock, clock, ref} = connect(n, conn_type: unquote(ct))
        handshaked(pid)
        # The first pass starts sync and sets the 20 min chain-sync deadline.
        :ok = Clock.tick(pid)
        deadline = Clock.now(clock) + 20 * 60

        responsive_until(pid, sock, clock, deadline)
        Clock.advance(clock, deadline - Clock.now(clock))
        :ok = Clock.tick(pid)
        msgs = until_pong(sock, System.unique_integer([:positive]))
        refute Enum.any?(msgs, &match?({:getheaders, _}, &1))

        # Past it: one getheaders probe and 2 more minutes.
        Clock.advance(clock, 1)
        :ok = Clock.tick(pid)
        msgs = until_pong(sock, System.unique_integer([:positive]))
        assert Enum.any?(msgs, &match?({:getheaders, _}, &1))

        Clock.advance(clock, 120)
        :ok = Clock.tick(pid)
        assert Process.alive?(pid)
        Clock.advance(clock, 1)
        :ok = Clock.tick(pid)
        assert_stopped(ref, :chain_sync_timeout)
      end
    end

    test "a peer that answers the probe with our tip's work is kept", %{n: n} do
      {pid, sock, clock, _ref} = connect(n, conn_type: :block_relay)
      handshaked(pid)
      :ok = Clock.tick(pid)
      deadline = :sys.get_state(pid).chain_sync.timeout
      responsive_until(pid, sock, clock, deadline)
      Clock.advance(clock, deadline - Clock.now(clock) + 1)
      :ok = Clock.tick(pid)
      assert :sys.get_state(pid).chain_sync.sent_getheaders

      announce_tip(n, pid, sock)
      Clock.advance(clock, 121)
      :ok = Clock.tick(pid)
      until_pong(sock, System.unique_integer([:positive]))
      assert Process.alive?(pid)
      assert :sys.get_state(pid).chain_sync.timeout == nil
    end

    test "a manual peer is not checked", %{n: n} do
      {pid, sock, clock, _ref} = connect(n, conn_type: :manual)
      handshaked(pid)
      :ok = Clock.tick(pid)
      assert :sys.get_state(pid).sync_started
      assert :sys.get_state(pid).chain_sync.timeout == nil
      responsive_until(pid, sock, clock, Clock.now(clock) + 30 * 60)
      assert :sys.get_state(pid).chain_sync.timeout == nil
    end

    test "at most 4 outbound full-relay peers with our tip's work are protected", %{n: n} do
      {tip, ""} = Exnode.Codec.Header.decode(Exnode.Chain.Headers.best_header(n.headers).raw)
      h = BB.next_header(tip)

      peers =
        for ct <- [:block_relay | List.duplicate(:outbound_full_relay, 5)] do
          {pid, sock, _clock, _ref} = connect(n, conn_type: ct)
          handshaked(pid)
          :ok = FakePeer.send_msgs(sock, {:headers, [h]})
          wait_until(fn -> :sys.get_state(pid).best_known != nil end)
          {ct, pid}
        end

      protected = for {ct, pid} <- peers, :sys.get_state(pid).chain_sync.protect, do: ct
      assert protected == List.duplicate(:outbound_full_relay, 4)
    end
  end
end
