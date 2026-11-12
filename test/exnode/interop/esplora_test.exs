defmodule Exnode.Interop.EsploraTest do
  @moduledoc """
  The scripthash index and the Esplora REST API,
  checked against bitcoind v32.1.

  Ten anyone-can-spend P2WSH scripts (`OP_(i+1) OP_DROP OP_1`) receive and spend
  value over many blocks; then a reorg replaces the last blocks with other
  transactions. For every script:
  * `/scripthash/:sh/utxo` equals bitcoind `scantxoutset raw(spk)`;
  * the full history (`/txs` and `/txs/chain/:last` paging) equals a scan of
    bitcoind's blocks (txs paying to or spending from the script);
  * `chain_stats` counts and sums agree with that scan.
  Also: tx fee and status (vs `getrawtransaction 2`), outspends (vs
  `gettxout`), merkle proofs (recomputed to the block's merkle root),
  `/block/:hash` and `/raw`, `POST /tx` broadcast, and mempool entries in
  address stats and UTXOs.
  """
  use Exnode.InteropCase
  import Exnode.Test.Coins, only: [hex: 1, raw: 1]

  alias Exnode.Codec.Tx
  alias Exnode.Crypto.Hash

  @moduletag timeout: 900_000
  @moduletag bitcoind: ["-txindex=1"]

  # OP_(i+1) OP_DROP OP_1: minimal pushes (a 1-byte data push of a small
  # number violates Core's MINIMALDATA policy, the documented policy-script
  # gap: bitcoind would refuse to re-add such spends to its mempool after a
  # reorg while exnode accepts them).
  defp ws(i), do: <<0x51 + i, 0x75, 0x51>>
  defp spk(i), do: <<0, 32>> <> :crypto.hash(:sha256, ws(i))
  defp sh_hex(i), do: Base.encode16(:crypto.hash(:sha256, spk(i)), case: :lower)

  # coins: [{txid, vout, value, script_index}]
  defp spend(coins, outs) do
    ins =
      for {t, v, _, i} <- coins,
          do: %Tx.In{
            prev_hash: t,
            prev_index: v,
            script_sig: <<>>,
            sequence: 0xFFFFFFFD,
            witness: [ws(i)]
          }

    tx = %Tx{
      version: 2,
      locktime: 0,
      inputs: ins,
      outputs: for({value, i} <- outs, do: %Tx.Out{value: value, script_pubkey: spk(i)})
    }

    tx |> raw() |> Tx.decode_exact() |> elem(1)
  end

  defp get(port, path) do
    :inets.start()

    {:ok, {{_, status, _}, _, body}} =
      :httpc.request(:get, {~c"http://127.0.0.1:#{port}#{path}", []}, [timeout: 60_000],
        body_format: :binary
      )

    {status, body}
  end

  defp get_json(port, path) do
    {200, body} = get(port, path)
    Jason.decode!(body)
  end

  # Full confirmed history of a scripthash through Esplora paging (newest first).
  defp all_confirmed(port, sh) do
    first = get_json(port, "/scripthash/#{sh}/txs") |> Enum.filter(& &1["status"]["confirmed"])
    page(port, sh, first, first)
  end

  defp page(_port, _sh, [], acc), do: acc

  defp page(port, sh, last_page, acc) do
    if length(last_page) < 25 do
      acc
    else
      next = get_json(port, "/scripthash/#{sh}/txs/chain/#{List.last(last_page)["txid"]}")
      page(port, sh, next, acc ++ next)
    end
  end

  # From bitcoind's blocks: txids touching script i, newest first; funded/spent counts and sums.
  defp expected(btc, i) do
    target = hex(spk(i))
    height = Bitcoind.json(btc, ["getblockcount"])

    rows =
      for h <- height..0//-1,
          b = Bitcoind.json(btc, ["getblock", Bitcoind.cli(btc, ["getblockhash", "#{h}"]), "3"]),
          tx <- Enum.reverse(b["tx"]) do
        funded =
          for o <- tx["vout"],
              o["scriptPubKey"]["hex"] == target,
              do: round(o["value"] * 100_000_000)

        spent =
          for v <- tx["vin"],
              v["prevout"] && v["prevout"]["scriptPubKey"]["hex"] == target,
              do: round(v["prevout"]["value"] * 100_000_000)

        {tx["txid"], funded, spent}
      end
      |> Enum.reject(fn {_, f, s} -> f == [] and s == [] end)

    funded = Enum.flat_map(rows, &elem(&1, 1))
    spent = Enum.flat_map(rows, &elem(&1, 2))

    %{
      txids: Enum.map(rows, &elem(&1, 0)),
      stats: %{
        "funded_txo_count" => length(funded),
        "funded_txo_sum" => Enum.sum(funded),
        "spent_txo_count" => length(spent),
        "spent_txo_sum" => Enum.sum(spent),
        "tx_count" => length(rows)
      }
    }
  end

  defp check_scripts(btc, port) do
    for i <- 0..9 do
      sh = sh_hex(i)
      exp = expected(btc, i)
      ours = all_confirmed(port, sh)
      assert Enum.map(ours, & &1["txid"]) == exp.txids, "history of script #{i}"

      assert get_json(port, "/scripthash/#{sh}")["chain_stats"] == exp.stats,
             "stats of script #{i}"

      scan = Bitcoind.json(btc, ["scantxoutset", "start", Jason.encode!(["raw(#{hex(spk(i))})"])])
      # Esplora (electrs) leaves out outputs that mempool txs spend.
      mem_spent =
        for t <- Bitcoind.json(btc, ["getrawmempool"]),
            v <- Bitcoind.json(btc, ["getrawtransaction", t, "1"])["vin"],
            into: MapSet.new(),
            do: {v["txid"], v["vout"]}

      core_utxos =
        for u <- scan["unspents"],
            not MapSet.member?(mem_spent, {u["txid"], u["vout"]}),
            into: MapSet.new(),
            do: {u["txid"], u["vout"], round(u["amount"] * 100_000_000)}

      our_utxos =
        for u <- get_json(port, "/scripthash/#{sh}/utxo"),
            u["status"]["confirmed"],
            into: MapSet.new(),
            do: {u["txid"], u["vout"], u["value"]}

      assert our_utxos == core_utxos,
             "utxos of script #{i}: core-only #{inspect(MapSet.difference(core_utxos, our_utxos))} ours-only #{inspect(MapSet.difference(our_utxos, core_utxos))}"
    end
  end

  test "scripthash histories, balances and UTXOs equal bitcoind's; REST endpoints", %{
    tmp_dir: dir,
    btc: btc
  } do
    for i <- 0..9, do: Bitcoind.mine(btc, 3, "raw(#{hex(spk(i))})")
    Bitcoind.mine(btc, 101)

    coins =
      for h <- 1..30,
          do:
            (
              b = Bitcoind.block(btc, h)
              {hd(b.txs).txid, 0, hd(hd(b.txs).outputs).value, div(h - 1, 3)}
            )

    :rand.seed(:exsss, {9, 9, 9})

    # Random moves between scripts, a few txs per block.
    {_pool, _} =
      Enum.reduce(1..12, {coins, 0}, fn _, {pool, n} ->
        {picked, rest} = Enum.split(Enum.shuffle(pool), 3)

        {txs, new} =
          Enum.map_reduce(picked, [], fn {_, _, v, _} = c, acc ->
            a = :rand.uniform(10) - 1
            b = :rand.uniform(10) - 1
            tx = spend([c], [{div(v - 2_000, 2), a}, {div(v - 2_000, 2), b}])
            {tx, acc ++ [{tx.txid, 0, div(v - 2_000, 2), a}, {tx.txid, 1, div(v - 2_000, 2), b}]}
          end)

        Bitcoind.generate_block(btc, txs, "raw(51)")
        {rest ++ new, n + 1}
      end)

    rest_port = TestNode.free_port()

    %{n: n} =
      TestNode.start(Path.join(dir, "ex"),
        connect: [{"127.0.0.1", btc.p2p}],
        index_scripthash: true,
        rest_port: rest_port
      )

    synced = fn ->
      tip = Bitcoind.cli(btc, ["getbestblockhash"])

      Hash.to_hex(Exnode.Chain.State.tip(n.chain_state).hash) == tip and
        Exnode.Index.Scripthash.sync_to(n.scripthash_index, Hash.from_hex(tip), 30_000) == :ok
    end

    assert Bitcoind.wait_until(synced, 120_000)
    check_scripts(btc, rest_port)

    # Reorg: drop the last 3 blocks, mine 4 others moving different coins.
    height = Bitcoind.json(btc, ["getblockcount"])
    Bitcoind.cli(btc, ["invalidateblock", Bitcoind.cli(btc, ["getblockhash", "#{height - 2}"])])
    # (The disconnected blocks' txs return to both mempools.)
    for _ <- 1..4, do: Bitcoind.json(btc, ["generateblock", "raw(52)", "[]"])
    assert Bitcoind.wait_until(synced, 120_000)
    # The mempool has re-added the disconnected txs too (UTXOs exclude mempool spends).
    assert Bitcoind.wait_until(
             fn ->
               MapSet.new(Bitcoind.json(btc, ["getrawmempool"])) ==
                 MapSet.new(Exnode.Mempool.txids(n.mempool), &Hash.to_hex/1)
             end,
             60_000
           ),
           (fn ->
              c = MapSet.new(Bitcoind.json(btc, ["getrawmempool"]))
              o = MapSet.new(Exnode.Mempool.txids(n.mempool), &Hash.to_hex/1)

              "mempools differ after the reorg: core-only #{inspect(MapSet.difference(c, o))} ours-only #{inspect(MapSet.difference(o, c))}"
            end).()

    check_scripts(btc, rest_port)

    # Transactions: fee and status; outspends; merkle proof.
    b = Bitcoind.json(btc, ["getblock", Bitcoind.cli(btc, ["getblockhash", "135"]), "2"])
    tx = Enum.at(b["tx"], 1)
    ours = get_json(rest_port, "/tx/#{tx["txid"]}")
    assert ours["fee"] == round(tx["fee"] * 100_000_000)

    assert ours["status"] == %{
             "confirmed" => true,
             "block_height" => 135,
             "block_hash" => b["hash"],
             "block_time" => b["time"]
           }

    assert ours["vin"] |> hd() |> Map.get("inner_witnessscript_asm") != nil
    assert get(rest_port, "/tx/#{tx["txid"]}/hex") == {200, tx["hex"]}

    for {o, v} <- Enum.with_index(get_json(rest_port, "/tx/#{tx["txid"]}/outspends")) do
      unspent = Bitcoind.cli(btc, ["gettxout", tx["txid"], "#{v}"]) != ""
      assert o["spent"] == not unspent, "outspend #{v}"
    end

    proof = get_json(rest_port, "/tx/#{tx["txid"]}/merkle-proof")

    root =
      Enum.reduce(Enum.with_index(proof["merkle"]), Hash.from_hex(tx["txid"]), fn {sib, level},
                                                                                  acc ->
        s = Hash.from_hex(sib)

        if Bitwise.band(Bitwise.bsr(proof["pos"], level), 1) == 0,
          do: Hash.hash256(acc <> s),
          else: Hash.hash256(s <> acc)
      end)

    assert Hash.to_hex(root) == b["merkleroot"]

    # Blocks.
    blk = get_json(rest_port, "/block/#{b["hash"]}")

    assert blk["height"] == 135 and blk["tx_count"] == length(b["tx"]) and
             blk["weight"] == b["weight"] and blk["size"] == b["size"]

    {200, rawb} = get(rest_port, "/block/#{b["hash"]}/raw")
    assert hex(rawb) == Bitcoind.cli(btc, ["getblock", b["hash"], "0"])
    assert get(rest_port, "/blocks/tip/hash") == {200, Bitcoind.cli(btc, ["getbestblockhash"])}

    # Broadcast and mempool: POST /tx spends a UTXO of script 0; it shows as
    # an unconfirmed spend/funding in stats and utxos, and reaches bitcoind.
    [u | _] =
      get_json(rest_port, "/scripthash/#{sh_hex(0)}/utxo")
      |> Enum.filter(& &1["status"]["confirmed"])

    before0 = get_json(rest_port, "/scripthash/#{sh_hex(0)}")["mempool_stats"]
    mempool_before = get_json(rest_port, "/mempool")["count"]
    t = spend([{Hash.from_hex(u["txid"]), u["vout"], u["value"], 0}], [{u["value"] - 1_000, 1}])
    :inets.start()

    {:ok, {{_, 200, _}, _, txid}} =
      :httpc.request(
        :post,
        {~c"http://127.0.0.1:#{rest_port}/tx", [], ~c"text/plain", hex(raw(t))},
        [],
        body_format: :binary
      )

    assert txid == Hash.to_hex(t.txid)
    stats0 = get_json(rest_port, "/scripthash/#{sh_hex(0)}")["mempool_stats"]

    assert stats0["spent_txo_count"] == before0["spent_txo_count"] + 1 and
             stats0["tx_count"] == before0["tx_count"] + 1

    assert Enum.any?(
             get_json(rest_port, "/scripthash/#{sh_hex(1)}/utxo"),
             &(&1["txid"] == txid and &1["status"] == %{"confirmed" => false})
           )

    refute Enum.any?(
             get_json(rest_port, "/scripthash/#{sh_hex(0)}/utxo"),
             &(&1["txid"] == u["txid"] and &1["vout"] == u["vout"])
           )

    assert Bitcoind.wait_until(fn -> txid in Bitcoind.json(btc, ["getrawmempool"]) end, 60_000)
    assert get_json(rest_port, "/mempool")["count"] == mempool_before + 1
    # Both mempools hold the same txs.
    assert Bitcoind.wait_until(
             fn ->
               MapSet.new(Bitcoind.json(btc, ["getrawmempool"])) ==
                 MapSet.new(Exnode.Mempool.txids(n.mempool), &Hash.to_hex/1)
             end,
             60_000
           )
  end
end
