defmodule Exnode.Interop.RegtestHeadersTest do
  @moduledoc "Regtest interop with the pinned bitcoind v32.1: handshake, header sync, reorgs, misbehaviour isolation."
  use Exnode.InteropCase

  alias Exnode.Chain.Headers
  alias Exnode.Crypto.Hash
  alias Exnode.P2P.{Connman, Peer}

  @moduletag :bitcoind
  @moduletag timeout: 180_000

  setup %{tmp_dir: dir, btc: btc} do
    %{n: n, name: name} =
      TestNode.start(Path.join(dir, "exnode"), connect: [{"127.0.0.1", btc.p2p}])

    %{n: n, name: name}
  end

  defp best(n), do: Headers.best_header(n.headers)
  defp btc_tip(btc), do: btc |> Bitcoind.cli(["getbestblockhash"]) |> Hash.from_hex()

  defp synced?(n, btc), do: best(n).hash == btc_tip(btc)

  test "handshake, initial header sync, new blocks, and a deep reorg", %{btc: btc, n: n} do
    Bitcoind.mine(btc, 200)
    assert Bitcoind.wait_until(fn -> synced?(n, btc) end), "initial sync: #{best(n).height}"
    assert best(n).height == 200

    # bitcoind sees exnode as a connected inbound peer with our user agent.
    [peer] = Bitcoind.json(btc, ["getpeerinfo"])
    assert peer["subver"] == "/exnode:0.1.0/" and peer["inbound"]

    # New blocks are announced (sendheaders) and followed.
    Bitcoind.mine(btc, 5)
    assert Bitcoind.wait_until(fn -> synced?(n, btc) end)
    assert best(n).height == 205

    # Deep reorg: invalidate back to height 150 and mine a longer fork.
    fork_point = Bitcoind.cli(btc, ["getblockhash", "151"])
    Bitcoind.cli(btc, ["invalidateblock", fork_point])
    # A different payout script, so the first fork block cannot equal the
    # invalidated block 151.
    Bitcoind.mine(btc, 60, "raw(52)")
    assert Bitcoind.json(btc, ["getblockcount"]) == 210
    assert Bitcoind.wait_until(fn -> synced?(n, btc) end), "after reorg: #{best(n).height}"
    assert best(n).height == 210
  end

  test "headers persist: restart resumes without resync", %{
    btc: btc,
    n: n,
    name: name,
    tmp_dir: dir
  } do
    Bitcoind.mine(btc, 50)
    assert Bitcoind.wait_until(fn -> synced?(n, btc) end)
    :ok = stop_supervised(name)
    # Restart pointed at a dead port: the headers can only come from disk.
    TestNode.start(Path.join(dir, "exnode"), name: name, connect: [{"127.0.0.1", 1}])
    assert best(n).height == 50
  end

  describe "isolation" do
    setup %{n: n, btc: btc} do
      Bitcoind.mine(btc, 10)
      assert Bitcoind.wait_until(fn -> synced?(n, btc) end)
      # A fake peer: listen locally, have exnode-style Peer connect to us.
      {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(lsock)

      node = %{
        params: Exnode.ChainParams.get(:regtest),
        headers: n.headers,
        addrman: nil,
        sync: n.sync,
        nonce: 1,
        services: 8,
        user_agent: "/t/"
      }

      {:ok, pid} =
        DynamicSupervisor.start_child(
          n.peer_sup,
          {Peer, %{node: node, conn_type: :manual, connect: {"127.0.0.1", port}}}
        )

      {:ok, sock} = :gen_tcp.accept(lsock, 5000)
      %{pid: pid, sock: sock}
    end

    test "garbage on the wire kills only that peer", %{pid: pid, sock: sock, n: n, btc: btc} do
      ref = Process.monitor(pid)
      :ok = :gen_tcp.send(sock, :crypto.strong_rand_bytes(200))
      assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, {:bad_frame, :bad_magic}}}, 5000
      # The bitcoind peer is unaffected and sync continues.
      assert Enum.any?(Connman.peers(n.connman), fn {p, _} -> Process.alive?(p) end)
      Bitcoind.mine(btc, 1)
      assert Bitcoind.wait_until(fn -> synced?(n, btc) end)
    end

    test "invalid-PoW headers are misbehaviour: that peer is disconnected", %{
      pid: pid,
      sock: sock,
      n: n
    } do
      alias Exnode.P2P.{Frame, Message}
      p = Exnode.ChainParams.get(:regtest)
      ref = Process.monitor(pid)

      send_msg = fn m ->
        {c, pl} = Message.encode(m)
        :gen_tcp.send(sock, Frame.encode(p.magic, c, pl))
      end

      v = %{
        version: 70017,
        services: 9,
        time: System.os_time(:second),
        addr_recv: %{services: 0, net: :ipv4, addr: <<127, 0, 0, 1>>, port: 0},
        nonce: 99,
        user_agent: "/evil/",
        start_height: 0,
        relay: false
      }

      send_msg.({:version, v})
      send_msg.(:verack)

      bad =
        Exnode.Test.BlockBuilder.unmine_header(%{
          Exnode.Test.BlockBuilder.next_header(best(n) |> to_header())
          | nonce: 0
        })

      send_msg.({:headers, [bad]})

      assert_receive {:DOWN, ^ref, :process, ^pid,
                      {:shutdown, {:misbehaving, "header with invalid proof of work"}}},
                     5000
    end
  end

  defp to_header(entry) do
    {h, ""} = Exnode.Codec.Header.decode(entry.raw)
    h
  end
end
