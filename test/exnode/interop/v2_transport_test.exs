defmodule Exnode.Interop.V2TransportTest do
  @moduledoc """
  BIP324 with bitcoind v32.1 (regtest).
  * exnode → bitcoind and bitcoind → exnode run v2; both report it in
    `getpeerinfo` / `Peer.info` with the same session id, and blocks flow.
  * exnode → a v1-only bitcoind (`-v2transport=0`) falls back to v1
    (`ShouldReconnectV1`) and syncs.
  * a v1-only bitcoind → exnode is detected as v1 and served.
  * exnode with v2 off talks v1 to a v2-capable bitcoind.
  """
  use Exnode.InteropCase

  import Exnode.Test.Coins, only: [hex: 1]
  import Exnode.Test.Node, only: [tip_hex: 1]

  alias Exnode.P2P.{Connman, Peer}

  @moduletag timeout: 600_000

  defp start_exnode(dir, connect, extra \\ []),
    do: TestNode.start(dir, [connect: connect, listen: 0] ++ extra)

  defp peer_infos(ex) do
    for {pid, p} <- Connman.peers(ex.n.connman),
        Process.alive?(pid),
        info = safe_info(pid),
        info,
        do: Map.put(info, :type, p.type)
  end

  defp safe_info(pid),
    do:
      (try do
         Peer.info(pid)
       catch
         :exit, _ -> nil
       end)

  defp synced!(ex, btc, what) do
    assert Bitcoind.wait_until(
             fn -> tip_hex(ex) == Bitcoind.cli(btc, ["getbestblockhash"]) end,
             120_000
           ),
           what
  end

  test "v2 both directions with bitcoind; v1 fallback both directions; v2 off", %{tmp_dir: dir} do
    a = Bitcoind.start(Path.join(dir, "a"))
    on_exit(fn -> Bitcoind.stop(a) end)
    Bitcoind.mine(a, 120)

    # exnode -> bitcoind A over v2.
    ex = start_exnode(Path.join(dir, "ex"), [{"127.0.0.1", a.p2p}])
    synced!(ex, a, "exnode did not sync from A over v2")
    [pa] = Bitcoind.json(a, ["getpeerinfo"])
    assert pa["transport_protocol_type"] == "v2"
    [ours] = Enum.filter(peer_infos(ex), &(&1.type == :manual))
    assert ours.transport_protocol_type == "v2"
    assert hex(ours.session_id) == pa["session_id"]

    # bitcoind B -> exnode (inbound) over v2; B syncs from exnode.
    b = Bitcoind.start(Path.join(dir, "b"), ["-connect=127.0.0.1:#{ex.port}"])
    on_exit(fn -> Bitcoind.stop(b) end)

    assert Bitcoind.wait_until(
             fn -> Bitcoind.cli(b, ["getbestblockhash"]) == tip_hex(ex) end,
             120_000
           )

    [pb] = Bitcoind.json(b, ["getpeerinfo"])
    assert pb["transport_protocol_type"] == "v2"
    inbound = Enum.find(peer_infos(ex), &(&1.type == :inbound))
    assert inbound.transport_protocol_type == "v2"
    assert hex(inbound.session_id) == pb["session_id"]

    # New blocks flow over v2 to both.
    Bitcoind.mine(a, 3)
    synced!(ex, a, "exnode did not follow A")

    assert Bitcoind.wait_until(
             fn ->
               Bitcoind.cli(b, ["getbestblockhash"]) == Bitcoind.cli(a, ["getbestblockhash"])
             end,
             60_000
           )

    # exnode -> v1-only bitcoind C: the v2 attempt is dropped, exnode retries with v1.
    c = Bitcoind.start(Path.join(dir, "c"), ["-v2transport=0", "-connect=127.0.0.1:#{a.p2p}"])
    on_exit(fn -> Bitcoind.stop(c) end)

    assert Bitcoind.wait_until(
             fn ->
               Bitcoind.cli(c, ["getbestblockhash"]) == Bitcoind.cli(a, ["getbestblockhash"])
             end,
             60_000
           )

    ex2 = start_exnode(Path.join(dir, "ex2"), [{"127.0.0.1", c.p2p}])
    synced!(ex2, c, "exnode did not sync from v1-only C")
    # C's only inbound peer is exnode, on v1.
    assert [%{"transport_protocol_type" => "v1", "subver" => "/exnode:0.1.0/"}] =
             Enum.filter(Bitcoind.json(c, ["getpeerinfo"]), & &1["inbound"])

    assert [%{transport_protocol_type: "v1"}] =
             Enum.filter(peer_infos(ex2), &(&1.type == :manual))

    # v1-only bitcoind D -> exnode: exnode detects v1 and serves it.
    d = Bitcoind.start(Path.join(dir, "d"), ["-v2transport=0", "-connect=127.0.0.1:#{ex.port}"])
    on_exit(fn -> Bitcoind.stop(d) end)

    assert Bitcoind.wait_until(
             fn -> Bitcoind.cli(d, ["getbestblockhash"]) == tip_hex(ex) end,
             120_000
           )

    assert [%{"transport_protocol_type" => "v1"}] = Bitcoind.json(d, ["getpeerinfo"])

    assert Enum.count(
             peer_infos(ex),
             &(&1.type == :inbound and &1.transport_protocol_type == "v1")
           ) == 1

    # exnode with v2 off -> bitcoind A: v1, and no NODE_P2P_V2 advertised.
    ex3 = start_exnode(Path.join(dir, "ex3"), [{"127.0.0.1", a.p2p}], v2_transport: false)
    synced!(ex3, a, "v1-only exnode did not sync")
    # A's exnode peers: ex (v2) and ex3, which must be v1 without NODE_P2P_V2.
    ex_peers = Enum.filter(Bitcoind.json(a, ["getpeerinfo"]), &(&1["subver"] == "/exnode:0.1.0/"))
    assert Enum.map(ex_peers, & &1["transport_protocol_type"]) |> Enum.sort() == ["v1", "v2"]
    p3 = Enum.find(ex_peers, &(&1["transport_protocol_type"] == "v1"))
    refute "P2P_V2" in p3["servicesnames"]

    assert "P2P_V2" in Enum.find(ex_peers, &(&1["transport_protocol_type"] == "v2"))[
             "servicesnames"
           ]
  end
end
