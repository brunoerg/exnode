defmodule Exnode.Interop.RegtestBlocksTest do
  @moduledoc """
  Regtest interop over P2P. bitcoind v32.1 mines blocks with
  transactions; exnode downloads, validates (non-script rules) and archives
  them. After each step: same tip, the archive's unspent set equals
  bitcoind's (`gettxout` on every outpoint ever created), and every block's
  reconstructed bytes equal `getblock <hash> 0`.
  """
  use Exnode.InteropCase

  alias Exnode.Archive
  alias Exnode.Chain.State
  alias Exnode.Crypto.Hash
  alias Exnode.Test.{BlockBuilder, ScriptAsm}

  @moduletag :bitcoind
  @moduletag timeout: 600_000
  @coin 100_000_000
  @op_true <<0x51>>
  @p2sh_true <<0xA9, 0x14>> <> Exnode.Crypto.Hash.hash160(<<0x51>>) <> <<0x87>>
  @p2wsh_true <<0x00, 0x20>> <> :crypto.hash(:sha256, <<0x51>>)

  setup %{tmp_dir: dir, btc: btc} do
    %{n: TestNode.start(Path.join(dir, "ex"), connect: [{"127.0.0.1", btc.p2p}]).n}
  end

  defp synced?(n, btc),
    do: State.tip(n.chain_state).hash == Hash.from_hex(Bitcoind.cli(btc, ["getbestblockhash"]))

  defp wait_synced(n, btc) do
    ok = Bitcoind.wait_until(fn -> synced?(n, btc) end, 60_000)

    unless ok do
      peers = for {pid, _} <- Exnode.P2P.Connman.peers(n.connman), do: Exnode.P2P.Peer.info(pid)
      best = Exnode.Chain.Headers.best_header(n.headers)

      inflight =
        Exnode.P2P.BlockDownload.in_flight(n.block_download)
        |> Map.values()
        |> Enum.map(&elem(&1, 2))
        |> Enum.sort()

      flunk(
        "exnode tip #{State.tip(n.chain_state).height}, best header #{best.height}, inflight #{inspect(inflight)}, " <>
          "state #{inspect(GenServer.call(n.chain_state, :debug))}, peers #{inspect(peers)}, " <>
          "bitcoind #{Bitcoind.cli(btc, ["getblockcount"])} peerinfo synced_headers=" <>
          inspect(
            Enum.map(
              Bitcoind.json(btc, ["getpeerinfo"]),
              &{&1["synced_headers"], &1["synced_blocks"]}
            )
          )
      )
    end
  end

  # Every outpoint of every block on bitcoind's active chain.
  defp all_outpoints(btc) do
    height = Bitcoind.json(btc, ["getblockcount"])

    for h <- 0..height,
        b = Bitcoind.block(btc, h),
        tx <- b.txs,
        {_, v} <- Enum.with_index(tx.outputs),
        do: {tx.txid, v}
  end

  defp assert_same_utxos(n, btc, extra_outpoints \\ []) do
    outpoints = Enum.uniq(all_outpoints(btc) ++ extra_outpoints)

    btc_res =
      Bitcoind.rpc_batch(
        btc,
        for({t, v} <- outpoints, do: {"gettxout", [Hash.to_hex(t), v, false]})
      )

    mismatches =
      State.with_archive(n.chain_state, fn a ->
        for {{t, v}, b} <- Enum.zip(outpoints, btc_res),
            ex = Archive.resolve(a, t, v),
            not same?(ex, b),
            do: {Hash.to_hex(t), v, ex, b}
      end)

    assert mismatches == [],
           "#{length(mismatches)} of #{length(outpoints)} outpoints differ: #{inspect(Enum.take(mismatches, 3))}"

    length(outpoints)
  end

  defp same?(:missing, nil), do: true

  defp same?({:ok, c}, %{"value" => value, "scriptPubKey" => %{"hex" => hex}, "coinbase" => cb}) do
    c.value == round(value * @coin) and Base.encode16(c.script_pubkey, case: :lower) == hex and
      c.coinbase == cb
  end

  defp same?(_, _), do: false

  defp assert_blocks_byte_exact(n, btc) do
    height = Bitcoind.json(btc, ["getblockcount"])

    State.with_archive(n.chain_state, fn a ->
      for h <- 0..height do
        assert Archive.read_block(a, Archive.id_at(a, h)) == Bitcoind.block(btc, h).raw,
               "block #{h}"
      end
    end)
  end

  test "sync blocks with transactions, deep reorg with double spends; utxos and bytes match", %{
    btc: btc,
    n: n
  } do
    # Coins at heights 1..60 must be mature (depth >= 100) when spent.
    Bitcoind.mine(btc, 170)
    wait_synced(n, btc)

    coins = for h <- 1..60, do: hd(Bitcoind.block(btc, h).txs).txid
    {first, coins} = Enum.split(coins, 30)

    # 20 blocks, each with a chain of spends, OP_RETURN, P2SH and P2WSH outputs; later blocks spend those.
    {created, _} =
      Enum.reduce(Enum.chunk_every(first, 3), {[], nil}, fn [c1, c2, c3], {acc, carry} ->
        a =
          BlockBuilder.tx([{c1, 0}], [
            {20 * @coin, @op_true},
            {10 * @coin, @p2sh_true},
            {10 * @coin, @p2wsh_true},
            {0, <<0x6A, 4, "test">>},
            {9 * @coin, @op_true}
          ])

        b = BlockBuilder.tx([{a.txid, 0}, {c2, 0}], [{69 * @coin, @op_true}])

        spends =
          case carry do
            nil ->
              []

            prev ->
              [
                BlockBuilder.tx(
                  [
                    {prev.txid, 1, script_sig: ScriptAsm.push_data(@op_true)},
                    {prev.txid, 2, witness: [@op_true]}
                  ],
                  [{19 * @coin, @op_true}]
                )
              ]
          end

        Bitcoind.generate_block(
          btc,
          [a, b | spends] ++ [BlockBuilder.spend_op_true(c3, 0, 49 * @coin)]
        )

        {acc ++ [a, b], a}
      end)

    wait_synced(n, btc)
    count = assert_same_utxos(n, btc)
    assert count > 200
    assert_blocks_byte_exact(n, btc)

    # Deep reorg: invalidate the last 25 blocks and build a longer branch that
    # double-spends some of the same coins differently.
    tip_h = Bitcoind.json(btc, ["getblockcount"])
    old_outpoints = all_outpoints(btc)
    Bitcoind.cli(btc, ["invalidateblock", Bitcoind.cli(btc, ["getblockhash", "#{tip_h - 24}"])])

    for c <- Enum.take(first, 6) do
      Bitcoind.generate_block(
        btc,
        [BlockBuilder.tx([{c, 0}], [{25 * @coin, @op_true}, {24 * @coin, @op_true}])],
        "raw(52)"
      )
    end

    Bitcoind.mine(btc, 25, "raw(52)")

    for c <- Enum.take(coins, 5),
        do:
          Bitcoind.generate_block(btc, [BlockBuilder.spend_op_true(c, 0, 50 * @coin)], "raw(52)")

    assert Bitcoind.json(btc, ["getblockcount"]) > tip_h
    wait_synced(n, btc)

    # Outpoints from the abandoned branch must now be missing in both.
    assert_same_utxos(n, btc, old_outpoints)
    assert_blocks_byte_exact(n, btc)
    _ = created
  end
end
