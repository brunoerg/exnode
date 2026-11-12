defmodule Exnode.TestSupportTest do
  @moduledoc """
  The shared test helpers (test/support) and the node's `listen: 0`: a
  node binds a free port and reports it, a fake peer completes the
  handshake both ways (the node dialling us, and us dialling the node).
  """
  use Exnode.NodeCase

  alias Exnode.P2P.Message

  test "listen: 0 binds a free port, reported by Exnode.Node.listen_port/1", %{tmp_dir: dir} do
    node = TestNode.start(dir, listen: 0)
    assert is_integer(node.port) and node.port > 0
    assert Exnode.Node.listen_port(node.name) == node.port

    # Not listening: nil.
    other = TestNode.start(Path.join(dir, "b"))
    assert other.port == nil
  end

  test "dial: an inbound fake peer is served the handshake", %{tmp_dir: dir} do
    node = TestNode.start(dir, listen: 0)
    sock = FakePeer.dial(node.port)
    assert [{"version", v}, {"verack", _}] = FakePeer.recv(sock, ["version", "verack"], 2)
    assert {:ok, {:version, %{start_height: 0}}} = Message.decode("version", v)
    wait_until(fn -> map_size(Exnode.P2P.Connman.peers(node.n.connman)) == 1 end)
  end

  test "connect_from: the node dials the fake peer and completes the handshake",
       %{tmp_dir: dir} do
    node = TestNode.start(dir)
    {pid, sock} = FakePeer.connect_from(node.n, version: %{start_height: 7})
    assert [{"version", _}, {"verack", _}] = FakePeer.recv(sock, ["version", "verack"], 2)
    wait_until(fn -> Exnode.P2P.Peer.info(pid).version == 70017 end)
  end

  test "wait_until fails the test after its timeout; until? returns false" do
    refute Exnode.Test.Wait.until?(fn -> false end, 50)

    assert_raise ExUnit.AssertionError, ~r/within 50 ms/, fn ->
      wait_until(fn -> false end, 50)
    end

    assert wait_until(fn -> true end) == :ok
  end

  test "Coins.tx builds a decodable P2WSH(OP_TRUE) spend" do
    coin = {:crypto.hash(:sha256, "x"), 1, 10_000}
    tx = Coins.tx([coin], [{9_000, Coins.p2wsh()}])
    assert byte_size(tx.txid) == 32
    assert [%{witness: [<<0x51>>], prev_index: 1}] = tx.inputs
    assert Coins.raw(tx) == tx.raw
  end
end
