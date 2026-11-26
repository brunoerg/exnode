defmodule Exnode.P2P.LowWorkHeadersTest do
  @moduledoc """
  `Peer` anti-DoS headers handling (Core `TryLowWorkHeadersSync`,
  `IsContinuationOfLowWorkHeadersSync`), over a socket: a headers chain
  whose claimed work stays below the anti-DoS threshold (here
  `minimum_chain_work`, raised in the peer's params) is never stored.

  * A full message (2,000 headers) starts the presync: nothing is stored,
    and the next batch is requested from the last header received.
  * A continuation that ends without enough work aborts the presync; the
    peer is not punished.
  * A short low-work message is ignored outright ("Ignoring low-work
    chain").
  * Control: the same headers with the regtest threshold are stored.
  """
  use Exnode.NodeCase
  import Bitwise

  alias Exnode.Chain.Headers
  alias Exnode.P2P.Message
  alias Exnode.Test.BlockBuilder, as: BB

  @p Exnode.ChainParams.get(:regtest)
  @full Message.max_headers_results()

  setup_all do
    headers =
      Stream.iterate(BB.next_header(@p.genesis.header), &BB.next_header/1)
      |> Enum.take(@full + 10)

    %{headers: headers}
  end

  setup %{tmp_dir: dir} do
    %{n: TestNode.start(dir).n}
  end

  # A peer the node dialed, with `params` (no periodic pass: tick_ms nil,
  # so the only getheaders it sends are answers to our headers).
  defp connect(n, params) do
    {pid, sock} = FakePeer.connect_from(n, params: params, node: %{tick_ms: nil})
    wait_until(fn -> match?({{:ready, _}, _}, :sys.get_state(pid)) end)
    {pid, sock}
  end

  defp low_work_params, do: %{@p | minimum_chain_work: 1 <<< 64}

  defp barrier(sock) do
    nonce = System.unique_integer([:positive])
    :ok = FakePeer.send_msgs(sock, {:ping, nonce})
    wait_pong(sock, nonce)
  end

  defp wait_pong(sock, nonce) do
    [{"pong", <<n::little-64>>}] = FakePeer.recv(sock, ["pong"], 1)
    if n == nonce, do: :ok, else: wait_pong(sock, nonce)
  end

  defp best_height(n), do: Headers.best_header(n.headers).height

  test "a full low-work message starts presync; an insufficient continuation ends it",
       %{n: n, headers: headers} do
    {pid, sock} = connect(n, low_work_params())
    {first, rest} = Enum.split(headers, @full)

    :ok = FakePeer.send_msgs(sock, {:headers, first})
    # The next batch is requested from the last header received.
    [{"getheaders", payload}] = FakePeer.recv(sock, ["getheaders"], 1)
    {:ok, {:getheaders, %{locator: [top | _]}}} = Message.decode("getheaders", payload)
    assert top == List.last(first).hash
    assert elem(:sys.get_state(pid), 1).proto.headers_sync != nil
    assert best_height(n) == 0

    # 10 more, not a full message: the chain ends below the threshold.
    :ok = FakePeer.send_msgs(sock, {:headers, rest})
    barrier(sock)
    assert elem(:sys.get_state(pid), 1).proto.headers_sync == nil
    assert best_height(n) == 0
    assert Process.alive?(pid)
  end

  test "a short low-work message is ignored", %{n: n, headers: headers} do
    {pid, sock} = connect(n, low_work_params())
    :ok = FakePeer.send_msgs(sock, {:headers, Enum.take(headers, 100)})
    barrier(sock)
    assert elem(:sys.get_state(pid), 1).proto.headers_sync == nil
    assert best_height(n) == 0
    assert Process.alive?(pid)
  end

  test "control: with the regtest threshold the same headers are stored", %{
    n: n,
    headers: headers
  } do
    {_pid, sock} = connect(n, @p)
    :ok = FakePeer.send_msgs(sock, {:headers, Enum.take(headers, 100)})
    barrier(sock)
    assert best_height(n) == 100
  end
end
