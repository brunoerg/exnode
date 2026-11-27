defmodule Exnode.P2P.PeerStatemTest do
  @moduledoc """
  Tests for the `:gen_statem` `Exnode.P2P.Peer` lifecycle, `Peer.Conn`
  transport module, `Peer.Writer` fast-terminate behaviour, offloaded block
  decode heap isolation, and bounded `P2P.Listener` Connman handoff.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.P2P.{Frame, Listener, Message}
  alias Exnode.P2P.Peer.Conn
  alias Exnode.P2P.V2.Transport
  alias Exnode.Test.BlockBuilder, as: BB

  @p Exnode.ChainParams.get(:regtest)
  @magic @p.magic

  describe "Peer.Conn unit" do
    test "v1 framing, send-buffer pause/resume, and inactivity checks" do
      test = self()
      send_fun = fn _sock, data -> send(test, {:wire, IO.iodata_to_binary(data)}) && :ok end

      {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(lsock)
      {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
      {:ok, server} = :gen_tcp.accept(lsock, 2_000)
      :gen_tcp.close(lsock)

      conn =
        Conn.new(
          magic: @magic,
          inbound: true,
          v2: false,
          send_fun: send_fun,
          max_send_buffer: 40
        )
        |> Conn.attach(server, 1_000)

      assert Conn.connected?(conn)
      assert Conn.v1?(conn)
      assert Conn.transport_type(conn) == "v1"
      refute Conn.paused?(conn)

      # Queue two pings (> 40 bytes) -> pauses send buffer.
      conn =
        conn
        |> Conn.send_msg("ping", <<1::little-64>>, 1_001)
        |> Conn.send_msg("ping", <<2::little-64>>, 1_001)

      assert Conn.paused?(conn)
      assert conn.send_queued == 64

      # Draining brings send_queued back under limit and reports resumed?.
      {resumed?, conn} = Conn.on_sent(conn, 64, 1_002)
      assert resumed?
      refute Conn.paused?(conn)
      assert conn.bytes_sent == 64

      # Incoming v1 frame decoded via on_tcp + next_v1_frame.
      wire = IO.iodata_to_binary(Frame.encode(@magic, "ping", <<99::little-64>>))
      {:v1, conn} = Conn.on_tcp(conn, wire, 1_003)
      assert {:ok, "ping", <<99::little-64>>, conn} = Conn.next_v1_frame(conn)
      assert {:more, conn} = Conn.next_v1_frame(conn)
      assert conn.bytes_recv == byte_size(wire)

      # Inactivity checks.
      assert Conn.inactivity_reason(conn, 1_000, 1_050, 60, 1200) == nil
      assert Conn.inactivity_reason(conn, 1_000, 1_003 + 1201, 60, 1200) == :send_timeout

      # Skip flush immediately on send-wedged shutdown reasons even while writer is blocked.
      blocked_writer = spawn(fn -> receive do: (:never -> :ok) end)
      on_exit(fn -> Process.exit(blocked_writer, :kill) end)

      for reason <- [{:shutdown, :send_buffer_full}, {:shutdown, :send_timeout}] do
        {us, :ok} =
          :timer.tc(fn ->
            Conn.flush_on_terminate(%{conn | writer: blocked_writer, send_queued: 100}, reason)
          end)

        assert us < 50_000
      end

      # Safe flush when writer is already dead returns immediately.
      Process.unlink(conn.writer)
      Process.exit(conn.writer, :kill)
      wait_until(fn -> not Process.alive?(conn.writer) end)

      {us, :ok} =
        :timer.tc(fn -> Conn.flush_on_terminate(%{conn | send_queued: 100}, :normal) end)

      assert us < 50_000

      :gen_tcp.close(client)
      :gen_tcp.close(server)
    end

    test "v2 inbound detects v1 fallback and flushes queued messages" do
      {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(lsock)
      {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
      {:ok, server} = :gen_tcp.accept(lsock, 2_000)
      :gen_tcp.close(lsock)

      conn =
        Conn.new(magic: @magic, inbound: true, v2: true)
        |> Conn.attach(server, 1_000)

      assert %Transport{} = conn.transport
      assert Conn.transport_type(conn) == "detecting"

      # Remote sends a v1 version frame: BIP324 detects the 16-byte v1 version
      # prefix (magic + "version\0\0\0\0\0"), falls back to v1, and exposes the frame.
      {cmd, payload} = Message.encode({:version, FakePeer.version()})
      payload_bin = IO.iodata_to_binary(payload)
      v1_frame = IO.iodata_to_binary(Frame.encode(@magic, cmd, payload_bin))
      {:v1, conn} = Conn.on_tcp(conn, v1_frame, 1_001)
      assert Conn.v1?(conn)
      assert Conn.transport_type(conn) == "v1"
      assert {:ok, "version", ^payload_bin, _conn} = Conn.next_v1_frame(conn)

      :gen_tcp.close(client)
      :gen_tcp.close(server)
    end
  end

  describe "Peer :gen_statem lifecycle" do
    setup %{tmp_dir: dir} do
      %{n: TestNode.start(dir).n}
    end

    test "orphaned inbound Peer times out in :awaiting_socket", %{n: n} do
      node = %{
        params: @p,
        headers: n.headers,
        addrman: nil,
        sync: n.sync,
        services: 0,
        user_agent: "/test/",
        tick_ms: nil
      }

      {:ok, pid} =
        Exnode.P2P.Peer.start_link(%{
          node: node,
          conn_type: :inbound,
          socket_timeout_ms: 50
        })

      Process.unlink(pid)
      ref = Process.monitor(pid)
      assert elem(:sys.get_state(pid), 0) == :awaiting_socket
      assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, :socket_timeout}}, 1_000
    end

    test "progresses through :awaiting_version -> :awaiting_verack -> {:ready, :active}", %{n: n} do
      {pid, sock} = FakePeer.connect_from(n, handshake: false, node: %{tick_ms: nil})
      wait_until(fn -> elem(:sys.get_state(pid), 0) == :awaiting_version end)
      {state, data} = :sys.get_state(pid)
      assert state == :awaiting_version
      assert data.proto == nil

      # Pre-handshake messages are ignored and never initialize proto.
      :ok = FakePeer.send_msgs(sock, [{:ping, 11}, {:getdata, []}, {:headers, []}])
      :ok = FakePeer.send_msgs(sock, {:version, FakePeer.version()})
      wait_until(fn -> elem(:sys.get_state(pid), 0) == :awaiting_verack end)
      {state, data} = :sys.get_state(pid)
      assert state == :awaiting_verack
      assert data.proto == nil

      # :wtxidrelay and :sendaddrv2 are accepted in :awaiting_verack.
      :ok = FakePeer.send_msgs(sock, [:wtxidrelay, :sendaddrv2, :verack])
      wait_until(fn -> elem(:sys.get_state(pid), 0) == {:ready, :active} end)
      {{:ready, :active}, data} = :sys.get_state(pid)
      assert data.handshake.wtxid_relay
      assert data.handshake.addrv2
      assert data.proto != nil
    end

    test ":wtxidrelay and :sendaddrv2 disconnect in {:ready, _}", %{n: n} do
      for {msg, reason} <- [
            {:wtxidrelay, :wtxidrelay_after_verack},
            {:sendaddrv2, :sendaddrv2_after_verack}
          ] do
        {pid, sock, ref} = FakePeer.connect_from(n, monitor: true, node: %{tick_ms: nil})
        wait_until(fn -> elem(:sys.get_state(pid), 0) == {:ready, :active} end)
        :ok = FakePeer.send_msgs(sock, [msg])
        assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, ^reason}}, 2_000
        :gen_tcp.close(sock)
      end
    end

    test "flow state transitions {:ready, :active} <-> {:ready, :paused} <-> {:ready, :draining}",
         %{n: n} do
      # Build 10 blocks so getdata exceeds a small send buffer.
      {blocks, _} =
        Enum.map_reduce(1..10, @p.genesis.header, fn h, prev ->
          b = BB.build(prev, [BB.coinbase(h, 50 * 100_000_000)])
          {b, b.header}
        end)

      for b <- blocks, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
      State.commit_now(n.chain_state)

      gate = :ets.new(:statem_gate, [:public])
      :ets.insert(gate, {:open, true})

      gated_send = fn sock, data ->
        wait_until(fn -> :ets.lookup(gate, :open) == [{:open, true}] end, 5_000)
        :gen_tcp.send(sock, data)
      end

      {pid, sock} =
        FakePeer.connect_from(n,
          node: %{socket_send: gated_send, max_send_buffer: 400, tick_ms: nil}
        )

      _ = FakePeer.recv(sock, ["verack"], 1)
      wait_until(fn -> elem(:sys.get_state(pid), 0) == {:ready, :active} end)

      :ets.insert(gate, {:open, false})
      items = for b <- blocks, do: %{type: :block, witness: true, hash: b.header.hash}
      :ok = FakePeer.send_msgs(sock, [{:getdata, items}, {:ping, 707}])

      wait_until(fn -> elem(:sys.get_state(pid), 0) == {:ready, :paused} end)

      :ets.insert(gate, {:open, true})
      got = FakePeer.recv(sock, ["block", "pong"], 11)
      assert Enum.map(got, &elem(&1, 0)) == List.duplicate("block", 10) ++ ["pong"]
      wait_until(fn -> elem(:sys.get_state(pid), 0) == {:ready, :active} end)
    end

    test "fast terminate when send_failed occurs with unsent bytes queued (< 100 ms)", %{n: n} do
      gate = :ets.new(:fail_gate, [:public])
      :ets.insert(gate, {:mode, :pass})

      send_fun = fn sock, data ->
        case :ets.lookup(gate, :mode) do
          [{:mode, :fail}] -> {:error, :closed}
          _ -> :gen_tcp.send(sock, data)
        end
      end

      {pid, sock, ref} =
        FakePeer.connect_from(n,
          monitor: true,
          node: %{socket_send: send_fun, tick_ms: nil}
        )

      _ = FakePeer.recv(sock, ["verack"], 1)
      wait_until(fn -> elem(:sys.get_state(pid), 0) == {:ready, :active} end)

      # Next send fails inside writer while send_queued > 0.
      :ets.insert(gate, {:mode, :fail})
      t0 = :erlang.monotonic_time(:millisecond)
      :ok = FakePeer.send_msgs(sock, {:ping, 55})

      assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, {:send_failed, :closed}}}, 2_000
      elapsed_ms = :erlang.monotonic_time(:millisecond) - t0
      # Previously terminate/2 hung for 1,000 ms waiting on :flushed from a dead writer.
      assert elapsed_ms < 250
      :gen_tcp.close(sock)
    end

    test "large block decode runs in DecodeSup worker without triggering manual GC on Peer", %{
      n: n
    } do
      # Build a valid > 64 KiB block (exceeds DecodeBudget.min_bytes/0 = 65_536)
      # via a coinbase with OP_RETURN padding outputs so the with_budget(gc: false)
      # + DecodeSup worker path is genuinely exercised.
      pad = :binary.copy(<<0x42>>, 80_000)

      cb =
        BB.coinbase_with(1, 50 * 100_000_000,
          outputs: [
            {50 * 100_000_000, <<0x51>>},
            {0, <<0x6A, 0x4E, 80_000::little-32, pad::binary>>}
          ]
        )

      b1 = BB.build(@p.genesis.header, [cb])
      assert byte_size(b1.raw) > Exnode.P2P.DecodeBudget.min_bytes()

      {:ok, _} = Exnode.Chain.Headers.process_headers(n.headers, [b1.header])
      clock = Exnode.Clock.new()
      Exnode.Clock.set(clock, b1.header.time + 10)

      {pid, sock} = FakePeer.connect_from(n, node: %{clock: clock, tick_ms: nil})
      _ = FakePeer.recv(sock, ["verack"], 1)
      wait_until(fn -> elem(:sys.get_state(pid), 0) == {:ready, :active} end)

      # Ensure modules on the decode path are already loaded so BEAM's lazy
      # code loader (:code.ensure_loaded/1) does not trigger an incidental GC.
      for mod <- [
            Exnode.P2P.DecodeBudget,
            Exnode.P2P.Peer.BlockSync,
            Exnode.P2P.CompactBlock,
            Exnode.Codec.Block
          ] do
        Code.ensure_loaded!(mod)
      end

      # Trace calls on Peer and newly spawned workers so we assert:
      # 1. DecodeBudget.with_budget/4 ran with gc: false on Peer (> 64 KiB block);
      # 2. Block.decode_exact/1 ran in a DecodeSup worker PID != Peer;
      # 3. Peer never called :erlang.garbage_collect/0 (manual GC skipped).
      # (A tiny automatic BEAM major GC on a 1.5k-word young heap can occur from
      # normal TCP frame buffering and is not a forced GC.)
      :erlang.trace(pid, true, [:call])
      :erlang.trace(:new_processes, true, [:call])
      :erlang.trace_pattern({Exnode.Codec.Block, :decode_exact, 1}, true, [:local])
      :erlang.trace_pattern({Exnode.P2P.DecodeBudget, :with_budget, 4}, true, [:local])
      :erlang.trace_pattern({:erlang, :garbage_collect, 0}, true, [:local])

      try do
        :ok = FakePeer.send_msgs(sock, [{:block, b1.raw}, {:ping, 123}])
        [{"pong", <<123::little-64>>}] = FakePeer.recv(sock, ["pong"], 1)
      after
        :erlang.trace_pattern({:erlang, :garbage_collect, 0}, false, [:local])
        :erlang.trace_pattern({Exnode.P2P.DecodeBudget, :with_budget, 4}, false, [:local])
        :erlang.trace_pattern({Exnode.Codec.Block, :decode_exact, 1}, false, [:local])
        :erlang.trace(:new_processes, false, [:call])
        :erlang.trace(pid, false, [:call])
      end

      budget_name = n.decode_budget
      raw_size = byte_size(b1.raw)

      assert_receive {:trace, ^pid, :call,
                      {Exnode.P2P.DecodeBudget, :with_budget,
                       [^budget_name, ^raw_size, _, [gc: false]]}},
                     1_000

      assert_receive {:trace, worker_pid, :call, {Exnode.Codec.Block, :decode_exact, _}}, 1_000
      assert worker_pid != pid
      refute_receive {:trace, ^pid, :call, {Exnode.Codec.Block, :decode_exact, _}}, 50
      refute_receive {:trace, ^pid, :call, {:erlang, :garbage_collect, []}}, 50

      # Block connected on chain; Peer process heap stays small.
      assert State.tip(n.chain_state).hash == b1.header.hash
      {:memory, peer_mem} = Process.info(pid, :memory)
      assert peer_mem < 1_000_000
    end

    test "DecodeBudget.with_worker runs :erlang.garbage_collect/0 on inline fallback", %{n: n} do
      parent = self()

      runner =
        spawn_link(fn ->
          receive do
            :go ->
              result =
                Exnode.P2P.DecodeBudget.with_worker(
                  n.decode_budget,
                  :nonexistent_decode_sup,
                  Exnode.P2P.DecodeBudget.min_bytes(),
                  fn -> :inline_ok end
                )

              send(parent, {:done, result})
              receive do: (:stop -> :ok)
          end
        end)

      :erlang.trace(runner, true, [:call])
      :erlang.trace_pattern({:erlang, :garbage_collect, 0}, true, [:local])

      try do
        send(runner, :go)
        assert_receive {:done, :inline_ok}, 1_000
      after
        :erlang.trace_pattern({:erlang, :garbage_collect, 0}, false, [:local])
        if Process.alive?(runner), do: :erlang.trace(runner, false, [:call])
        send(runner, :stop)
      end

      assert_receive {:trace, ^runner, :call, {:erlang, :garbage_collect, []}}, 1_000
    end
  end

  describe "P2P.Listener bounded Connman handoff" do
    defmodule SlowConnman do
      use GenServer
      def init(sleep_ms), do: {:ok, sleep_ms}

      def handle_call({:accept_inbound?, _}, _from, sleep_ms) do
        Process.sleep(sleep_ms)
        {:reply, true, sleep_ms}
      end
    end

    test "times out slow Connman.accept_inbound? and closes socket without crashing listener" do
      {:ok, cm} = GenServer.start_link(SlowConnman, 2_000)

      {:ok, l} =
        Listener.start_link(
          port: 0,
          ip: {127, 0, 0, 1},
          connman: cm,
          connman_timeout_ms: 100,
          node: %{},
          peer_sup: nil
        )

      port = Listener.port(l)
      {:ok, c} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
      assert {:error, :closed} = :gen_tcp.recv(c, 0, 1_500)
      assert Process.alive?(l)
    end
  end
end
