defmodule Exnode.Interop.TxRelayTest do
  @moduledoc """
  Transaction relay between exnode and bitcoind v32.1
  over P2P (wtxid relay, BIP339).
  * A tx sent to bitcoind reaches exnode's mempool (inv, getdata, tx).
  * A tx accepted by exnode reaches bitcoind's mempool.
  * An orphan (child before parent) is held, its parent fetched, and both accepted.
  * A 0-fee parent with a fee-paying child (submitpackage on bitcoind) is
    relayed and accepted by exnode as a 1p1c package via the orphanage.
  """
  use Exnode.InteropCase
  import Exnode.Test.Coins, only: [hex: 1, p2wsh: 0, raw: 1]

  alias Exnode.Clock
  alias Exnode.Crypto.Hash
  alias Exnode.Mempool

  @moduletag timeout: 600_000
  @moduletag :bitcoind

  # `coins` into `n_out` equal P2WSH(OP_TRUE) outputs.
  defp spend(coins, fee, n_out \\ 1) do
    total = Enum.reduce(coins, 0, fn {_, _, v}, a -> a + v end)
    Coins.tx(coins, List.duplicate({div(total - fee, n_out), p2wsh()}, n_out))
  end

  defp out0(tx), do: {tx.txid, 0, hd(tx.outputs).value}

  test "relay in both directions, orphans and 1p1c packages", %{tmp_dir: dir, btc: btc} do
    Bitcoind.mine(btc, 20, "raw(#{hex(p2wsh())})")
    Bitcoind.mine(btc, 101)

    %{n: n, name: name, clock: clock} =
      TestNode.start(Path.join(dir, "ex"), connect: [{"127.0.0.1", btc.p2p}])

    tip = Bitcoind.cli(btc, ["getbestblockhash"])

    assert Bitcoind.wait_until(
             fn -> Hash.to_hex(Exnode.Chain.State.tip(n.chain_state).hash) == tip end,
             60_000
           ),
           "exnode did not sync"

    coin = fn h ->
      b = Bitcoind.block(btc, h)
      {hd(b.txs).txid, 0, hd(hd(b.txs).outputs).value}
    end

    in_core? = fn tx -> Hash.to_hex(tx.txid) in Bitcoind.json(btc, ["getrawmempool"]) end
    in_ex? = fn tx -> Mempool.has?(n.mempool, tx.txid) end

    # bitcoind -> exnode
    t1 = spend([coin.(1)], 1_000)
    Bitcoind.cli(btc, ["sendrawtransaction", hex(raw(t1))])

    assert Bitcoind.wait_until(fn -> in_ex?.(t1) end, 60_000),
           "tx from bitcoind did not reach exnode"

    # exnode -> bitcoind
    t2 = spend([coin.(2)], 2_000)
    assert {:ok, _} = Mempool.accept(n.mempool, t2)

    assert Bitcoind.wait_until(fn -> in_core?.(t2) end, 60_000),
           "tx from exnode did not reach bitcoind"

    # A chain relays in order (parent before child).
    t3 = spend([out0(t2)], 1_500)
    assert {:ok, _} = Mempool.accept(n.mempool, t3)
    assert Bitcoind.wait_until(fn -> in_core?.(t3) end, 60_000)

    # Orphan: the child arrives at exnode (from the bitcoind peer) before its parent.
    parent = spend([coin.(3)], 1_000)
    child = spend([out0(parent)], 1_000)
    Bitcoind.cli(btc, ["sendrawtransaction", hex(raw(parent))])
    [{peer, _}] = Exnode.P2P.Connman.peers(n.connman) |> Enum.to_list()
    Exnode.P2P.TxRelay.received_tx(n.tx_relay, peer, child)

    assert Bitcoind.wait_until(fn -> in_ex?.(parent) and in_ex?.(child) end, 60_000),
           "orphan not resolved: parent #{in_ex?.(parent)}, child #{in_ex?.(child)}, orphans #{inspect(Exnode.P2P.TxRelay.orphans(n.tx_relay))}"

    # 1p1c: 0-fee parent, fee-paying child, submitted to bitcoind as a package.
    p0 = spend([coin.(4)], 0)
    c0 = spend([out0(p0)], 20_000)
    res = Bitcoind.json(btc, ["submitpackage", Jason.encode!([hex(raw(p0)), hex(raw(c0))])])
    assert res["package_msg"] == "success"

    assert Bitcoind.wait_until(fn -> in_ex?.(p0) and in_ex?.(c0) end, 90_000),
           "1p1c package not relayed: parent #{in_ex?.(p0)}, child #{in_ex?.(c0)}"

    # The orphan child was injected at exnode as if bitcoind had sent it, so it
    # is not announced back to bitcoind (as Core: never to the tx's source).
    # The mempools are equal apart from it.
    same_but = fn missing ->
      MapSet.new(Bitcoind.json(btc, ["getrawmempool"])) ==
        MapSet.new(Mempool.txids(n.mempool) -- missing, &Hash.to_hex/1)
    end

    assert Bitcoind.wait_until(fn -> same_but.([child.txid]) end, 60_000), "mempools differ"

    # Several outbound trickle intervals (2 s mean) pass on exnode's clock,
    # each with a pass: anything queued for bitcoind is announced now.
    trickle = fn -> Clock.advance(clock, 5) && Exnode.Node.tick(name) end
    for _ <- 1..5, do: trickle.()
    # A marker announced after them. bitcoind requests one peer's
    # announcements in order and processes the txs in order: once the marker
    # is in its mempool, the child would be too, had it been announced.
    marker = spend([coin.(5)], 1_000)
    assert {:ok, _} = Mempool.accept(n.mempool, marker)
    assert Bitcoind.wait_until(fn -> trickle.() && in_core?.(marker) end, 60_000)
    refute in_core?.(child), "the orphan child was announced back to its source"

    # bitcoind gets it directly; the mempools converge.
    Bitcoind.cli(btc, ["sendrawtransaction", hex(raw(child))])
    assert Bitcoind.wait_until(fn -> same_but.([]) end, 60_000), "mempools differ"

    # A block clears both.
    Bitcoind.mine(btc, 1)
    assert Bitcoind.wait_until(fn -> Mempool.size(n.mempool) == 0 end, 60_000)
  end
end
