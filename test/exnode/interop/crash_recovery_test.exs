defmodule Exnode.Interop.CrashRecoveryTest do
  @moduledoc """
  `kill -9` crash recovery. exnode runs as its own OS process
  (`mix exnode.node`) connected to bitcoind v32.1. While bitcoind mines
  blocks with transactions and performs reorgs, exnode is SIGKILLed at random
  moments and restarted. In the end:
  * exnode reaches bitcoind's tip
  * the reopened archive's unspent set equals bitcoind's (gettxout)
  * every block reconstructs byte-exactly
  """
  use Exnode.InteropCase

  alias Exnode.Archive
  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Crypto.Hash
  alias Exnode.Store.{Guard, KV, Snapshot}
  alias Exnode.Test.BlockBuilder

  @moduletag :bitcoind
  @moduletag timeout: 1_200_000
  @kills 20
  @coin 100_000_000
  @project Path.expand("../../..", __DIR__)

  defp start_node(dir, btc, extra \\ []) do
    mix = System.find_executable("mix")
    status = Path.join(dir, "status.json")
    File.rm(status)

    port =
      Port.open({:spawn_executable, mix}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        cd: @project,
        env: [{~c"MIX_ENV", ~c"dev"}],
        args:
          [
            "exnode.node",
            "--chain",
            "regtest",
            "--datadir",
            Path.join(dir, "ex"),
            "--connect",
            "127.0.0.1:#{btc.p2p}",
            "--status-file",
            status,
            "--status-interval",
            "300"
          ] ++ extra
      ])

    {:os_pid, pid} = Port.info(port, :os_pid)
    {port, pid, status}
  end

  defp kill9({port, pid, _}) do
    System.cmd("kill", ["-9", "#{pid}"])

    receive do
      {^port, {:exit_status, _}} -> :ok
    after
      10_000 -> flunk("node did not die")
    end

    flush(port)
  end

  defp flush(port) do
    receive do
      {^port, _} -> flush(port)
    after
      0 -> :ok
    end
  end

  defp status({_, _, file}) do
    with {:ok, bin} <- File.read(file), {:ok, s} <- Jason.decode(bin), do: s, else: (_ -> nil)
  end

  defp btc_tip(btc), do: Bitcoind.cli(btc, ["getbestblockhash"])

  # bitcoind keeps changing the chain: blocks with spends, and periodic reorgs.
  defp churn(btc, coins, i) do
    if rem(i, 4) == 3 do
      h = Bitcoind.json(btc, ["getblockcount"])
      Bitcoind.cli(btc, ["invalidateblock", Bitcoind.cli(btc, ["getblockhash", "#{h - 3}"])])
      # A unique payout script (push of a unique 4-byte counter), so the
      # new branch can never reproduce an invalidated block byte-for-byte.
      for _ <- 1..6 do
        tag =
          System.unique_integer([:positive])
          |> rem(0xFFFFFFFF)
          |> then(&Base.encode16(<<&1::32>>, case: :lower))

        Bitcoind.mine(btc, 1, "raw(04#{tag})")
      end

      _ = i
      coins
    else
      [c | rest] = coins
      t1 = BlockBuilder.tx([{c, 0}], [{25 * @coin, <<0x51>>}, {24 * @coin, <<0x51>>}])
      t2 = BlockBuilder.spend_op_true(t1.txid, 1, 23 * @coin)
      Bitcoind.generate_block(btc, [t1, t2])
      rest
    end
  end

  test "random kill -9 during sync and reorgs, then consistent", %{tmp_dir: dir, btc: btc} do
    # The node's own build must be ready before timing kills.
    {_, 0} =
      System.cmd("mix", ["compile"],
        cd: @project,
        env: [{"MIX_ENV", "dev"}],
        stderr_to_stdout: true
      )

    Bitcoind.mine(btc, 220)
    coins = for h <- 1..100, do: hd(Bitcoind.block(btc, h).txs).txid

    :rand.seed(:exsss, {1, 2, 3})

    chain_dir = Path.join([dir, "ex", "regtest"])

    # Each round: restart, wait until the node is past the previous kill
    # point (actively syncing), change bitcoind's chain, kill at a random moment.
    {coins, kill_heights, _} =
      Enum.reduce(1..@kills, {coins, [], -1}, fn i, {coins, acc, last} ->
        coins = Enum.reduce(1..3, coins, fn _, c -> churn(btc, c, i) end)
        # Odd rounds keep blocks batched even at the tip, so the kill lands
        # inside an uncommitted batch.
        node = start_node(dir, btc, if(rem(i, 2) == 1, do: ["--no-commit-at-tip"], else: []))

        assert Bitcoind.wait_until(
                 fn -> (s = status(node)) && s["tip_height"] > last end,
                 60_000
               ),
               "round #{i}: node made no progress past #{last}"

        Process.sleep(:rand.uniform(300))
        s = status(node)
        kill9(node)

        # Invariant 2 & 4: crashed store MUST leave flush.lock on disk, refuse
        # direct open, and restore cleanly to an exact prior quiescent snapshot.
        assert {:dirty, _} = Guard.inspect_lock(chain_dir)

        if i == 1 do
          # Verify the CLI binary itself refuses to open a dirty store directly.
          {out, code} =
            System.cmd(
              System.find_executable("mix"),
              ["exnode.node", "--chain", "regtest", "--datadir", Path.join(dir, "ex")],
              cd: @project,
              env: [{"MIX_ENV", "dev"}],
              stderr_to_stdout: true
            )

          assert code != 0
          assert out =~ "did not close cleanly"
        end

        {:ok, restored} = Snapshot.restore!(chain_dir)
        assert Guard.inspect_lock(chain_dir) == :clean
        assert is_integer(restored.tip.height)

        h = s && s["tip_height"]
        {coins, [{h, s && s["committed_height"]} | acc], h || last}
      end)

    # Final restart: must catch up with bitcoind.
    node = start_node(dir, btc)

    ok =
      Bitcoind.wait_until(fn -> (s = status(node)) && s["tip_hash"] == btc_tip(btc) end, 180_000)

    final = status(node)
    kill9(node)
    assert ok, "final status #{inspect(final)} vs bitcoind #{btc_tip(btc)}"
    IO.puts("\n  kill -9 at {tip, committed} heights: #{inspect(Enum.reverse(kill_heights))}")
    # Batched commits: some kills hit an uncommitted batch (tip above the durable tip).
    assert Enum.any?(kill_heights, fn {t, c} -> t && c && t > c end),
           "no kill landed inside a batch"

    _ = coins

    # Restore from the final snapshot after the final kill -9, then reopen cleanly.
    {:ok, _} = Snapshot.restore!(chain_dir)
    assert Guard.inspect_lock(chain_dir) == :clean

    p = ChainParams.get(:regtest)
    {:ok, kv} = KV.open(Path.join(chain_dir, "index"), mode: :canonical)
    {:ok, stg} = KV.open(Path.join(chain_dir, "staging"), mode: :staging)
    {:ok, hs} = Headers.start_link(params: p, kv: kv, staging_kv: stg)

    {:ok, cs} =
      State.start_link(
        params: p,
        headers: hs,
        kv: kv,
        staging_kv: stg,
        strict_clean: true,
        hot: Path.join(chain_dir, "archive")
      )

    assert Hash.to_hex(State.tip(cs).hash) == btc_tip(btc)

    height = Bitcoind.json(btc, ["getblockcount"])
    blocks = for h <- 0..height, do: Bitcoind.block(btc, h)

    outpoints =
      for b <- blocks, tx <- b.txs, {_, v} <- Enum.with_index(tx.outputs), do: {tx.txid, v}

    res =
      Bitcoind.rpc_batch(
        btc,
        for({t, v} <- outpoints, do: {"gettxout", [Hash.to_hex(t), v, false]})
      )

    State.with_archive(cs, fn a ->
      for {b, h} <- Enum.with_index(blocks),
          do: assert(Archive.read_block(a, Archive.id_at(a, h)) == b.raw, "block #{h}")

      bad =
        for {{t, v}, r} <- Enum.zip(outpoints, res),
            ex = Archive.resolve(a, t, v),
            ex == :missing != (r == nil) or
              (r != nil and elem(ex, 1).value != round(r["value"] * @coin)),
            do: {Hash.to_hex(t), v}

      assert bad == [], "#{length(bad)} outpoints differ"
    end)
  end
end
