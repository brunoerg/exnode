defmodule Exnode.P2P.OutboundSelectionTest do
  @moduledoc """
  Outbound use of the address book (Core `ThreadOpenConnections`):
  * Connman's selection rules, with a stand-in address book serving a fixed
    list of candidates: it skips a bad port, missing services, a recently
    tried address and a discouraged one, and dials the first acceptable
    address after recording the attempt;
  * a feeler connection reports the peer (Core: `AddrMan::Good` at VERSION)
    and disconnects at once.
  """
  use Exnode.NodeCase
  import ExUnit.CaptureLog

  alias Exnode.P2P.{Connman, Peer}

  @p Exnode.ChainParams.get(:regtest)

  # A stand-in address book: answers select from a list, records attempts.
  defmodule FakeBook do
    use GenServer
    def init({cands, test}), do: {:ok, %{cands: cands, test: test}}
    def handle_call(:size, _f, st), do: {:reply, 1, st}
    def handle_call({:size, _net}, _f, st), do: {:reply, 1, st}
    def handle_call(:select_tried_collision, _f, st), do: {:reply, nil, st}

    def handle_call({:select, opts}, _f, %{cands: [c | rest]} = st) do
      send(st.test, {:selected, c.port, opts})
      {:reply, c, %{st | cands: rest}}
    end

    def handle_call({:select, _}, _f, st), do: {:reply, nil, st}

    def handle_cast({:attempt, key, cf}, st),
      do:
        (
          send(st.test, {:attempt, key, cf})
          {:noreply, st}
        )

    def handle_cast(_, st), do: {:noreply, st}
  end

  defp cand(port, opts \\ []) do
    services = Keyword.get(opts, :services, 1 + 8)

    %{
      net: :ipv4,
      addr: <<250, 0, rem(port, 250), 1>>,
      port: port,
      key: {:ipv4, <<250, 0, rem(port, 250), 1>>, port},
      services: services,
      last_try: Keyword.get(opts, :last_try, 0),
      attempts: 0,
      in_tried: false
    }
  end

  test "Connman skips bad ports, missing services and recent tries, then dials and records the attempt" do
    now = System.os_time(:second)
    cands = [cand(22), cand(18_001, services: 1), cand(18_002, last_try: now - 60), cand(18_003)]
    {:ok, book} = GenServer.start_link(FakeBook, {cands, self()})
    {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)

    node = %{
      params: @p,
      addrman: book,
      services: 9,
      nonce: 1,
      user_agent: "/t/",
      headers: nil,
      sync: nil
    }

    {:ok, cm} =
      Connman.start_link(
        node: node,
        peer_sup: sup,
        max_outbound_full_relay: 1,
        max_block_relay: 0
      )

    for port <- [22, 18_001, 18_002, 18_003], do: assert_receive({:selected, ^port, _}, 3_000)
    # Only the acceptable address is attempted; failures do not count while offline.
    assert_receive {:attempt, {:ipv4, _, 18_003}, false}, 3_000
    for p <- [22, 18_001, 18_002], do: refute_received({:attempt, {:ipv4, _, ^p}, _})
    assert Enum.any?(Connman.peers(cm), fn {_, p} -> p.target == {"250.0.3.1", 18_003} end)
  end

  # Regression: "already connected" compared (IP, port),
  # and an inbound peer carries an ephemeral port, so the node dialled out to
  # a peer already connected to it (Core AlreadyConnectedToAddress also
  # matches the IP alone).
  test "an address whose IP is already connected inbound is not dialled" do
    # Empty until the inbound peer is registered (Connman ticks at once).
    {:ok, book} = GenServer.start_link(FakeBook, {[], self()})
    {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)

    node = %{
      params: @p,
      addrman: book,
      services: 9,
      nonce: 1,
      user_agent: "/t/",
      headers: nil,
      sync: nil
    }

    {:ok, cm} =
      Connman.start_link(
        node: node,
        peer_sup: sup,
        max_outbound_full_relay: 1,
        max_block_relay: 0
      )

    inbound = spawn(fn -> Process.sleep(:infinity) end)
    Connman.register_inbound(cm, inbound, {"250.0.4.1", 55_555})
    _ = Connman.peers(cm)
    :sys.replace_state(book, &%{&1 | cands: [cand(18_004), cand(18_005)]})

    for port <- [18_004, 18_005], do: assert_receive({:selected, ^port, _}, 3_000)
    assert_receive {:attempt, {:ipv4, _, 18_005}, _}, 3_000
    refute_received {:attempt, {:ipv4, _, 18_004}, _}
  end

  test "anchors: reconnected first as block-relay, file removed after reading, rewritten at shutdown",
       %{tmp_dir: dir} do
    path = Path.join(dir, "anchors.dat")

    anchor = %{
      net: :ipv4,
      addr: <<250, 9, 9, 9>>,
      port: 18_444,
      services: 9,
      time: System.os_time(:second)
    }

    :ok = Exnode.P2P.PeerFile.write(path, @p.magic, [anchor])
    {:ok, book} = GenServer.start_link(FakeBook, {[], self()})
    {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)

    node = %{
      params: @p,
      addrman: book,
      services: 9,
      nonce: 1,
      user_agent: "/t/",
      headers: nil,
      sync: nil
    }

    {:ok, cm} =
      Connman.start_link(
        node: node,
        peer_sup: sup,
        anchors_path: path,
        magic: @p.magic,
        max_outbound_full_relay: 0,
        max_block_relay: 1
      )

    Process.unlink(cm)
    refute File.exists?(path)
    assert_receive {:attempt, {:ipv4, <<250, 9, 9, 9>>, 18_444}, _}, 3_000

    [{pid, %{type: :block_relay, target: {"250.9.9.9", 18_444}}}] =
      Enum.to_list(Connman.peers(cm))

    # Once that peer is up, a shutdown saves it as an anchor again.
    send(cm, {:peer_ready, pid, {"250.9.9.9", 18_444}, :block_relay, 9})
    _ = Connman.peers(cm)
    GenServer.stop(cm)

    assert {:ok, [%{net: :ipv4, addr: <<250, 9, 9, 9>>, port: 18_444, services: 9}]} =
             Exnode.P2P.PeerFile.read(path, @p.magic)
  end

  # Regression: terminate/2 also runs when Connman
  # crashes; anchors written then are redialled by the restart, every time.
  test "anchors are not written when Connman stops abnormally", %{tmp_dir: dir} do
    path = Path.join(dir, "anchors.dat")
    {:ok, book} = GenServer.start_link(FakeBook, {[], self()})
    {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)

    node = %{
      params: @p,
      addrman: book,
      services: 9,
      nonce: 1,
      user_agent: "/t/",
      headers: nil,
      sync: nil
    }

    node_name = :"p2p3_node_#{System.unique_integer([:positive])}"

    start = fn ->
      {:ok, cm} =
        Connman.start_link(
          node: node,
          node_name: node_name,
          peer_sup: sup,
          anchors_path: path,
          magic: @p.magic,
          max_outbound_full_relay: 0,
          max_block_relay: 0
        )

      Process.unlink(cm)
      # A ready block-relay peer: what an anchor is made of.
      peer = spawn(fn -> Process.sleep(:infinity) end)
      send(cm, {:peer_ready, peer, {"250.9.9.9", 18_444}, :block_relay, 9})

      :sys.replace_state(cm, fn st ->
        put_in(st.peers[peer], %{
          type: :block_relay,
          target: {"250.9.9.9", 18_444},
          ready: true,
          services: 9,
          group: nil,
          v2: false,
          evicting: false,
          evict_deadline: nil,
          prefer_evict: false,
          stats: %{}
        })
      end)

      cm
    end

    cm = start.()
    capture_log(fn -> GenServer.stop(cm, {:crashed, :boom}) end)
    refute File.exists?(path)

    # Regression: a supervisor restart cascade (a crash of
    # ChainState, Headers or a P2P sibling) stops Connman with :shutdown,
    # as a node stop does; anchors were written then too.
    cm = start.()
    GenServer.stop(cm, :shutdown)
    refute File.exists?(path)

    # The node is stopping (Exnode.Node.stop/2, or the application): written.
    cm = start.()
    Exnode.Node.mark_stopping(node_name)
    GenServer.stop(cm, :shutdown)
    assert {:ok, [%{port: 18_444}]} = Exnode.P2P.PeerFile.read(path, @p.magic)
  end

  test "a feeler reports the peer at version and disconnects", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(lsock)

    node = %{
      params: @p,
      headers: n.headers,
      addrman: nil,
      sync: n.sync,
      nonce: 1,
      services: 9,
      user_agent: "/t/",
      connman: self()
    }

    {:ok, pid} = Peer.start_link(%{node: node, conn_type: :feeler, connect: {"127.0.0.1", port}})
    Process.unlink(pid)
    ref = Process.monitor(pid)
    {:ok, sock} = :gen_tcp.accept(lsock, 5000)

    :ok = FakePeer.send_msgs(sock, {:version, FakePeer.version(services: 1033)})
    assert_receive {:peer_ready, ^pid, {"127.0.0.1", ^port}, :feeler, 1033}, 5_000
    assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, :feeler_done}}, 5_000
  end

  # Regression (mainnet): fe80:2::225:90ff:fe47:9570 from addr gossip is
  # routable by Core's rules (IsRFC4862 is fe80::/64 only), so it is tried;
  # :gen_tcp.connect exited with badarg (EINVAL) for it and the peer process
  # crashed with an error report instead of failing to connect.
  test "a connect that exits with badarg is a failed connect, not a crash", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)

    node = %{
      params: @p,
      headers: n.headers,
      addrman: nil,
      sync: n.sync,
      nonce: 1,
      services: 9,
      user_agent: "/t/",
      connman: self()
    }

    host = to_string(:inet.ntoa({0xFE80, 2, 0, 0, 0x225, 0x90FF, 0xFE47, 0x9570}))

    {:ok, pid} =
      Peer.start_link(%{node: node, conn_type: :outbound_full_relay, connect: {host, 8333}})

    Process.unlink(pid)
    ref = Process.monitor(pid)

    assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, {:connect_failed, :einval}}},
                   5_000
  end

  # Regression: an oversized inv/headers/addr before the
  # handshake was decoded and punished (misbehaving: disconnect and a 24 h
  # discouragement of the IP); Core ignores any such message before verack.
  test "an oversized message before the handshake is ignored, not punished", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(lsock)

    node = %{
      params: @p,
      headers: n.headers,
      addrman: nil,
      sync: n.sync,
      nonce: 1,
      services: 9,
      user_agent: "/t/",
      connman: self()
    }

    {:ok, pid} = Peer.start_link(%{node: node, conn_type: :feeler, connect: {"127.0.0.1", port}})
    Process.unlink(pid)
    ref = Process.monitor(pid)
    {:ok, sock} = :gen_tcp.accept(lsock, 5000)

    items = for i <- 1..50_001, do: %{type: :tx, hash: <<i::256>>}
    :ok = FakePeer.send_msgs(sock, [{:inv, items}, {:version, FakePeer.version(services: 1033)}])
    assert_receive {:DOWN, ^ref, :process, ^pid, reason}, 5_000
    assert reason == {:shutdown, :feeler_done}
  end
end
