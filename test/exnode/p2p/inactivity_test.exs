defmodule Exnode.P2P.InactivityTest do
  @moduledoc """
  Send side and inactivity, Core `InactivityCheck`
  and the send buffer limit:
  * a peer that stops sending is disconnected once nothing has been received
    for TIMEOUT_INTERVAL (20 min, on a mock clock, checked by explicit ticks);
  * a peer that floods pings but never reads our pongs: our sends block
    once the socket buffers are full, then fail after the send timeout,
    and the peer process ends; it does not hang or grow without bound.
  """
  use Exnode.NodeCase

  alias Exnode.Clock
  alias Exnode.P2P.{Frame, Message}

  @p Exnode.ChainParams.get(:regtest)

  setup %{tmp_dir: dir} do
    %{n: TestNode.start(dir).n}
  end

  # The node dials us; the test sends the handshake itself.
  defp connect_peer(n, extra), do: FakePeer.connect_from(n, node: extra, handshake: false)

  # Reads frames until `pred` matches one; returns it.
  defp read_until(sock, pred, buf \\ <<>>) do
    case Frame.decode(@p.magic, buf) do
      {:ok, cmd, payload, rest} ->
        {:ok, m} = Message.decode(cmd, payload)
        if pred.(m), do: m, else: read_until(sock, pred, rest)

      _ ->
        {:ok, data} = :gen_tcp.recv(sock, 0, 5000)
        read_until(sock, pred, buf <> data)
    end
  end

  test "nothing received for 20 minutes: receive timeout", %{n: n} do
    clock = Clock.new()
    Clock.set(clock, 1_000_000)
    # Only explicit ticks (no 1 s timer): each pass runs when the test says.
    {pid, sock} = connect_peer(n, %{clock: clock, tick_ms: nil})
    ref = Process.monitor(pid)
    :ok = FakePeer.send_msgs(sock, {:version, FakePeer.version()})
    :ok = FakePeer.send_msgs(sock, :verack)
    wait_until(fn -> :sys.get_state(pid).verack_received end)
    # The first pass pings; answer it, then go silent.
    :ok = Clock.tick(pid)
    {:ping, nonce} = read_until(sock, &match?({:ping, _}, &1))
    :ok = FakePeer.send_msgs(sock, {:pong, nonce})
    # The pong is processed (a call is answered after it).
    wait_until(fn -> :sys.get_state(pid).ping_nonce == nil end)

    # 19 minutes: still connected.
    Clock.advance(clock, 19 * 60)
    :ok = Clock.tick(pid)
    assert Process.alive?(pid)
    # That tick pinged (2 min passed): we keep receiving pings, so only the
    # receive side times out. Wait for the writer's report of the send.
    {:ping, _} = read_until(sock, &match?({:ping, _}, &1))
    wait_until(fn -> :sys.get_state(pid).last_send == Clock.now(clock) end)
    # Past 20 minutes since the last bytes from the peer.
    Clock.advance(clock, 60 + 5)
    :ok = Clock.tick(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, :receive_timeout}}
  end

  test "a peer that never reads: sends time out and the process ends", %{n: n} do
    {pid, sock} = connect_peer(n, %{send_timeout_ms: 1_000})
    ref = Process.monitor(pid)
    :ok = FakePeer.send_msgs(sock, {:version, FakePeer.version()})
    :ok = FakePeer.send_msgs(sock, :verack)
    # Flood pings without reading any reply. (No tiny recbuf here: on
    # loopback that stalls both directions in TCP zero-window probing
    # before exnode's own send ever blocks.)
    {c, pl} = Message.encode({:ping, 1})
    ping = Frame.encode(@p.magic, c, pl) |> IO.iodata_to_binary()
    batch = :binary.copy(ping, 2_000)
    flood = spawn(fn -> flood(sock, batch) end)
    # Our pong sends block once the buffers are full, then time out.
    assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, {:send_failed, :timeout}}}, 30_000
    Process.exit(flood, :kill)
  end

  defp flood(sock, batch) do
    case :gen_tcp.send(sock, batch) do
      :ok -> flood(sock, batch)
      _ -> :ok
    end
  end
end
