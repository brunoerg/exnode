defmodule Exnode.Interop.BlockServingTest do
  @moduledoc """
  Peers sync from exnode.
  * bitcoind A mines a chain with segwit txs; exnode syncs from A.
  * A fresh bitcoind B, connected only to exnode, syncs to the tip; its
    blocks are byte-identical to exnode's archive.
  * New blocks are announced to B (headers / cmpctblock) and B follows.
  * Witness-pruned exnode (NODE_NETWORK_LIMITED): bitcoind C, which already
    has all but the last blocks, syncs the rest from it.
  """
  use Exnode.InteropCase

  import Exnode.Test.Coins, only: [hex: 1, p2wsh: 0]
  import Exnode.Test.Node, only: [tip_hex: 1]

  @moduletag timeout: 900_000

  # Two equal P2WSH(OP_TRUE) outputs.
  defp spend({_, _, value} = coin, fee),
    do: Coins.tx([coin], List.duplicate({div(value - fee, 2), p2wsh()}, 2))

  defp start_exnode(dir, btc, extra),
    do: TestNode.start(dir, [connect: [{"127.0.0.1", btc.p2p}], listen: 0] ++ extra)

  defp same_blocks!(btc, ex, heights) do
    for h <- heights do
      hash = Bitcoind.cli(btc, ["getblockhash", "#{h}"])

      ours =
        Exnode.Chain.State.with_archive(
          ex.n.chain_state,
          &Exnode.Archive.read_block(&1, Exnode.Archive.id_at(&1, h))
        )

      assert hex(ours) == Bitcoind.cli(btc, ["getblock", hash, "0"]), "block #{h}"
    end
  end

  test "bitcoind syncs from exnode (full and NODE_NETWORK_LIMITED), and follows announcements", %{
    tmp_dir: dir
  } do
    a = Bitcoind.start(Path.join(dir, "a"))
    on_exit(fn -> Bitcoind.stop(a) end)
    Bitcoind.mine(a, 40, "raw(#{hex(p2wsh())})")
    Bitcoind.mine(a, 101)

    # Blocks with segwit spends.
    coins =
      for h <- 1..40,
          do:
            (
              b = Bitcoind.block(a, h)
              {hd(b.txs).txid, 0, hd(hd(b.txs).outputs).value}
            )

    Enum.each(Enum.chunk_every(coins, 4), fn chunk ->
      Bitcoind.generate_block(a, Enum.map(chunk, &spend(&1, 1_000)), "raw(51)")
    end)

    Bitcoind.mine(a, 50)
    height = Bitcoind.json(a, ["getblockcount"])

    ex = start_exnode(Path.join(dir, "ex"), a, [])

    assert Bitcoind.wait_until(
             fn -> tip_hex(ex) == Bitcoind.cli(a, ["getbestblockhash"]) end,
             120_000
           ),
           "exnode did not sync from A"

    # B syncs from exnode only.
    b = Bitcoind.start(Path.join(dir, "b"), ["-connect=127.0.0.1:#{ex.port}"])
    on_exit(fn -> Bitcoind.stop(b) end)

    assert Bitcoind.wait_until(fn -> Bitcoind.json(b, ["getblockcount"]) == height end, 180_000),
           "B reached #{Bitcoind.json(b, ["getblockcount"])} of #{height}"

    assert Bitcoind.cli(b, ["getbestblockhash"]) == tip_hex(ex)
    same_blocks!(b, ex, [1, 100, 141, 142, 150, height])

    # Announcements: A mines; exnode connects and announces to B.
    Bitcoind.mine(a, 1)

    assert Bitcoind.wait_until(
             fn ->
               Bitcoind.cli(b, ["getbestblockhash"]) == Bitcoind.cli(a, ["getbestblockhash"])
             end,
             60_000
           ),
           "B #{Bitcoind.json(b, ["getblockcount"])}, exnode #{Exnode.Chain.State.tip(ex.n.chain_state).height}, A #{Bitcoind.json(a, ["getblockcount"])}"

    Bitcoind.mine(a, 3)

    assert Bitcoind.wait_until(
             fn ->
               Bitcoind.cli(b, ["getbestblockhash"]) == Bitcoind.cli(a, ["getbestblockhash"])
             end,
             60_000
           )

    # NODE_NETWORK_LIMITED: a witness-pruned exnode serving C, which already has
    # the chain up to 20 blocks below the tip (synced from A, then cut off).
    ex2 = start_exnode(Path.join(dir, "ex2"), a, prune_witness: true)
    tip_a = Bitcoind.cli(a, ["getbestblockhash"])
    assert Bitcoind.wait_until(fn -> tip_hex(ex2) == tip_a end, 120_000)

    # C syncs from A and shuts itself down at `target` (-stopatheight).
    target = Bitcoind.json(a, ["getblockcount"]) - 20
    cdir = Path.join(dir, "c")
    _ = Bitcoind.start(cdir, ["-connect=127.0.0.1:#{a.p2p}", "-stopatheight=#{target}"])

    assert Bitcoind.wait_until(
             fn -> not File.exists?(Path.join([cdir, "regtest", "bitcoind.pid"])) end,
             120_000
           )

    c = Bitcoind.start(cdir, ["-connect=127.0.0.1:#{ex2.port}"])
    on_exit(fn -> Bitcoind.stop(c) end)
    start_h = Bitcoind.json(c, ["getblockcount"])
    assert start_h < target + 5, "C should start near #{target}, is at #{start_h}"

    assert Bitcoind.wait_until(
             fn -> match?([%{"version" => v}] when v > 0, Bitcoind.json(c, ["getpeerinfo"])) end,
             30_000
           )

    [peer] = Bitcoind.json(c, ["getpeerinfo"])

    assert Bitwise.band(String.to_integer(peer["services"], 16), 1024) != 0,
           "exnode2 should advertise NODE_NETWORK_LIMITED: #{inspect(peer)}"

    assert Bitwise.band(String.to_integer(peer["services"], 16), 1) == 0

    assert Bitcoind.wait_until(fn -> Bitcoind.cli(c, ["getbestblockhash"]) == tip_a end, 120_000),
           "C reached #{Bitcoind.json(c, ["getblockcount"])}"
  end
end
