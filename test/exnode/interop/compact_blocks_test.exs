defmodule Exnode.Interop.CompactBlocksTest do
  @moduledoc """
  Compact blocks (BIP152 v2) from bitcoind v32.1.
  exnode makes bitcoind a high-bandwidth peer once it delivers a new block.
  bitcoind then announces each new block as `cmpctblock`, and exnode
  rebuilds it:
  * from its mempool alone, when it already relayed every tx;
  * with `getblocktxn` / `blocktxn`, when a tx was mined before reaching exnode.
  Each rebuilt block must match `getblock <hash> 0` byte for byte.
  """
  use Exnode.InteropCase
  import ExUnit.CaptureLog
  import Exnode.Test.Coins, only: [hex: 1, p2wsh: 0, raw: 1]

  alias Exnode.Crypto.Hash
  alias Exnode.Mempool

  @moduletag timeout: 600_000
  @moduletag :bitcoind

  defp spend({_, _, value} = coin, fee), do: Coins.tx([coin], [{value - fee, p2wsh()}])

  test "blocks announced as cmpctblock are rebuilt from the mempool, with getblocktxn when needed",
       %{tmp_dir: dir, btc: btc} do
    Bitcoind.mine(btc, 30, "raw(#{hex(p2wsh())})")
    Bitcoind.mine(btc, 101)

    %{n: n} = TestNode.start(Path.join(dir, "ex"), connect: [{"127.0.0.1", btc.p2p}])

    synced = fn ->
      Hash.to_hex(Exnode.Chain.State.tip(n.chain_state).hash) ==
        Bitcoind.cli(btc, ["getbestblockhash"])
    end

    assert Bitcoind.wait_until(synced, 60_000)

    # A new block from bitcoind (not in IBD) makes it high-bandwidth.
    Bitcoind.mine(btc, 1)
    assert Bitcoind.wait_until(synced, 30_000)

    assert Bitcoind.wait_until(
             fn -> Exnode.P2P.HighBandwidth.peers(n.high_bandwidth) != [] end,
             10_000
           )

    coin = fn h ->
      b = Bitcoind.block(btc, h)
      {hd(b.txs).txid, 0, hd(hd(b.txs).outputs).value}
    end

    same_block = fn ->
      hash = Bitcoind.cli(btc, ["getbestblockhash"])

      ours =
        Exnode.Chain.State.with_archive(n.chain_state, fn a ->
          Exnode.Archive.read_block(a, Exnode.Archive.tip(a).id)
        end)

      hex(ours) == Bitcoind.cli(btc, ["getblock", hash, "0"])
    end

    # 1) Every tx relayed to exnode first: rebuilt from the mempool alone.
    txs = for h <- 1..8, do: spend(coin.(h), 1_000)
    for t <- txs, do: Bitcoind.cli(btc, ["sendrawtransaction", hex(raw(t))])

    assert Bitcoind.wait_until(
             fn -> Enum.all?(txs, &Mempool.has?(n.mempool, &1.txid)) end,
             60_000
           )

    log1 =
      capture_log(fn ->
        Bitcoind.mine(btc, 1)
        assert Bitcoind.wait_until(synced, 30_000)
      end)

    assert log1 =~ ~r/compact block [0-9a-f]{64} rebuilt: 9 txs, 0 requested/, log1
    assert same_block.()
    assert Mempool.size(n.mempool) == 0

    # 2) Two txs mined before reaching exnode: fetched with getblocktxn.
    relayed = for h <- 9..12, do: spend(coin.(h), 1_000)
    for t <- relayed, do: Bitcoind.cli(btc, ["sendrawtransaction", hex(raw(t))])

    assert Bitcoind.wait_until(
             fn -> Enum.all?(relayed, &Mempool.has?(n.mempool, &1.txid)) end,
             60_000
           )

    late = for h <- 13..14, do: spend(coin.(h), 1_000)

    log2 =
      capture_log(fn ->
        # Mine them immediately with the relayed ones: exnode has not seen `late`.
        Bitcoind.generate_block(btc, relayed ++ late, "raw(51)")
        assert Bitcoind.wait_until(synced, 30_000)
      end)

    assert log2 =~ ~r/compact block [0-9a-f]{64} rebuilt: 7 txs, 2 requested/, log2
    assert same_block.()
  end
end
