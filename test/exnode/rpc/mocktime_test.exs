defmodule Exnode.RPC.MocktimeTest do
  @moduledoc """
  `setmocktime` (Core rpc/node.cpp): regtest only, a number in
  [0, 2^32 - 1], 0 back to the system time. It sets the node's clock
  (`Exnode.Clock`), which every time-dependent part reads: here the IBD flag,
  uptime, and a peer's inactivity timeout, run by `Exnode.Node.tick/1`
  instead of waiting for the timers.
  """
  use Exnode.NodeCase

  alias Exnode.Clock
  alias Exnode.P2P.Connman
  alias Exnode.RPC.Methods

  @p Exnode.ChainParams.get(:regtest)

  defp ctx(n, clock, params \\ @p),
    do: %{
      chain_state: n.chain_state,
      headers: n.headers,
      connman: n.connman,
      params: params,
      clock: clock
    }

  test "argument checks and Core's errors", %{tmp_dir: dir} do
    %{n: n, clock: c} = TestNode.start(dir)
    ctx = ctx(n, c)

    assert {:error, -1, "setmocktime is for regression testing (-regtest mode) only"} =
             Methods.call(
               "setmocktime",
               [1_800_000_000],
               ctx(n, c, Exnode.ChainParams.get(:mainnet))
             )

    assert {:error, -3, "JSON value of type string is not of expected type number"} =
             Methods.call("setmocktime", ["1"], ctx)

    assert {:error, -8, "Mocktime must be in the range [0, 4294967295], not -1."} =
             Methods.call("setmocktime", [-1], ctx)

    assert {:error, -8, "Mocktime must be in the range [0, 4294967295], not 4294967296."} =
             Methods.call("setmocktime", [4_294_967_296], ctx)

    assert Clock.mocktime(c) == 0
  end

  test "the node's clock: IBD flag and uptime follow it; 0 restores the system time",
       %{tmp_dir: dir} do
    %{n: n, clock: c} = TestNode.start(dir)
    ctx = Map.put(ctx(n, c), :started_at, Clock.now(c))
    g = @p.genesis.header

    # Real time: the genesis tip is years old.
    assert {:ok, info} = Methods.call("getblockchaininfo", [], ctx)
    assert {"initialblockdownload", true} in info

    # An hour after the genesis block: no longer in IBD.
    assert {:ok, nil} = Methods.call("setmocktime", [g.time + 3600], ctx)
    assert Clock.now(c) == g.time + 3600
    assert {:ok, info} = Methods.call("getblockchaininfo", [], ctx)
    assert {"initialblockdownload", false} in info

    # Uptime is measured on the same clock.
    ctx = %{ctx | started_at: g.time}
    assert {:ok, 3600} = Methods.call("uptime", [], ctx)

    assert {:ok, nil} = Methods.call("setmocktime", [0], ctx)
    assert Clock.mocktime(c) == 0
    assert abs(Clock.now(c) - System.os_time(:second)) <= 1
  end

  test "a peer silent past TIMEOUT_INTERVAL on the mock clock is dropped by the next tick",
       %{tmp_dir: dir} do
    %{n: n, clock: c, name: name, port: port} = TestNode.start(dir, listen: 0)
    t0 = System.os_time(:second)
    {:ok, nil} = Methods.call("setmocktime", [t0], ctx(n, c))

    sock = FakePeer.dial(port)
    _ = FakePeer.recv(sock, ["verack"], 1)
    wait_until(fn -> map_size(Connman.peers(n.connman)) == 1 end)
    [pid] = Map.keys(Connman.peers(n.connman))
    ref = Process.monitor(pid)

    # 19 minutes of silence: still connected after a pass.
    {:ok, nil} = Methods.call("setmocktime", [t0 + 19 * 60], ctx(n, c))
    :ok = Exnode.Node.tick(name)
    assert Process.alive?(pid)

    # Past 20 minutes (Core TIMEOUT_INTERVAL) since anything was received.
    {:ok, nil} = Methods.call("setmocktime", [t0 + 20 * 60 + 5], ctx(n, c))
    :ok = Exnode.Node.tick(name)
    assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, reason}}
    assert reason in [:send_timeout, :receive_timeout]
  end

  # Core times tx requests on NodeClock (GetTime in ProcessMessage "inv" and
  # SendMessages), which setmocktime sets: the request delay passes when the
  # mock time moves past it. (On the monotonic clock, it took 2 s of real
  # time whatever the mock time.)
  test "a tx request delay runs on the mock clock", %{tmp_dir: dir} do
    %{n: n, clock: c, name: name, port: port} = TestNode.start(dir, listen: 0)
    # An hour after genesis: out of IBD, when tx invs are not ignored.
    t0 = @p.genesis.header.time + 3600
    {:ok, nil} = Methods.call("setmocktime", [t0], ctx(n, c))

    # Inbound: not preferred, so the request waits 2 s (Core NONPREF_PEER_TX_DELAY).
    sock = FakePeer.dial(port, version: %{relay: true})
    _ = FakePeer.recv(sock, ["verack"], 1)
    wait_until(fn -> map_size(Connman.peers(n.connman)) == 1 end)

    hash = :crypto.strong_rand_bytes(32)
    :ok = FakePeer.send_msgs(sock, [{:inv, [%{type: :tx, hash: hash}]}])

    # The inv is in once a ping sent after it is answered.
    :ok = FakePeer.send_msgs(sock, [{:ping, 7}])
    [{"pong", <<7::little-64>>}] = FakePeer.recv(sock, ["pong"], 1)

    # 1 s on the mock clock: not yet.
    {:ok, nil} = Methods.call("setmocktime", [t0 + 1], ctx(n, c))
    :ok = Exnode.Node.tick(name)
    refute "getdata" in commands(sock, 200)

    # 2 s: requested at once, long before 2 s of real time have passed.
    {:ok, nil} = Methods.call("setmocktime", [t0 + 2], ctx(n, c))
    :ok = Exnode.Node.tick(name)
    [{"getdata", payload}] = FakePeer.recv(sock, ["getdata"], 1, timeout: 500)
    assert {:ok, {:getdata, [%{hash: ^hash}]}} = Exnode.P2P.Message.decode("getdata", payload)
  end

  # The commands of the messages received within `ms`.
  defp commands(sock, ms, buf \\ <<>>, acc \\ []) do
    magic = @p.magic

    case Exnode.P2P.Frame.decode(magic, buf) do
      {:ok, cmd, _payload, rest} ->
        commands(sock, ms, rest, [cmd | acc])

      _ ->
        case :gen_tcp.recv(sock, 0, ms) do
          {:ok, data} -> commands(sock, ms, buf <> data, acc)
          {:error, :timeout} -> Enum.reverse(acc)
        end
    end
  end
end
