defmodule Exnode.DoS.OrphanFanoutTest do
  @moduledoc """
  Regression (real sockets, full node):   orphanage fan-out against the shared TxRelay.

  Before the fix the orphanage had no global announcement bound (only an
  orphan count cap and a per-peer weight cap), and `limit_orphans/1` walked
  every (orphan, announcer) pair on each new orphan and each `inv` adding an
  announcer: with 1,000 orphans x 200 announcers, one ~94-byte orphan `tx`
  cost ~127 ms of the shared process, and a few connections streaming
  trivial orphans delayed every peer's tx relay (and the blocks queued
  behind it in those peers' mailboxes) indefinitely: 755 ms vs 20 ms
  control at the default parameters, 4.6 s at 1000 x 120 x 40.

  Now the total latency score is capped as Core v32.1's
  `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000`, the per-peer accounting is
  incremental, and the limits cost O(evictions). This test builds the same
  fan-out over real sockets, streams fresh orphans, and checks that an
  honest peer's tx and block are not meaningfully delayed.

  Tunables: `FANOUT_ORPHANS` (400), `FANOUT_ANN` (100), `FANOUT_SENDERS` (24).
  Full scale: `FANOUT_ORPHANS=1000 FANOUT_ANN=200 FANOUT_SENDERS=40`.
  """
  use ExUnit.Case, async: false

  alias Exnode.Chain.State
  alias Exnode.Codec.Tx
  alias Exnode.Mempool
  alias Exnode.P2P.TxRelay
  alias Exnode.Test.{BlockBuilder, Coins, FakePeer}

  @moduletag :dos
  @moduletag :bench
  @moduletag :tmp_dir
  @moduletag timeout: 600_000

  @coin 100_000_000

  # An orphan: spends an outpoint that will never exist.
  defp orphan_tx(tag, n) do
    prev = :crypto.hash(:sha256, <<tag::32, n::32>>)

    Coins.finalize(%Tx{
      version: 2,
      locktime: 0,
      inputs: [
        %Tx.In{
          prev_hash: prev,
          prev_index: 0,
          script_sig: <<>>,
          sequence: 0xFFFFFFFD,
          witness: []
        }
      ],
      outputs: [%Tx.Out{value: 1_000, script_pubkey: Coins.p2wsh()}]
    })
  end

  # Mines `n` blocks paying P2WSH(OP_TRUE) with recent-enough timestamps
  # that the node leaves IBD. Returns {mature coinbase coins, tip header}.
  defp mine(n, node) do
    now = System.os_time(:second)
    genesis = Exnode.ChainParams.get(:regtest).genesis

    {blocks, _} =
      Enum.map_reduce(1..n, genesis.header, fn h, prev ->
        b =
          BlockBuilder.build(
            prev,
            [BlockBuilder.coinbase_with(h, 50 * @coin, outputs: [{50 * @coin, Coins.p2wsh()}])],
            time: now - n + h
          )

        {b, b.header}
      end)

    for b <- blocks, do: {:ok, _} = State.submit_block(node.n.chain_state, b)

    coins =
      for b <- Enum.take(blocks, n - 100) do
        tx = hd(b.txs)
        {tx.txid, 0, 50 * @coin}
      end

    {coins, List.last(blocks).header}
  end

  defp dial_peers(port, k) do
    for _ <- 1..k do
      sock = FakePeer.dial(port, handshake: false)
      # version, wtxidrelay (so the node treats us as a wtxid-relay peer), verack
      _ = FakePeer.send_msgs(sock, [{:version, FakePeer.version()}, :wtxidrelay, :verack])
      _ = FakePeer.recv(sock, ["version", "verack"], 2, timeout: 5_000)
      sock
    end
  end

  defp orphan_count(node), do: length(TxRelay.orphans(node.n.tx_relay))

  defp fanout_entries(node) do
    :sys.get_state(node.n.tx_relay).orphans
    |> Enum.reduce(0, fn {_, o}, acc -> acc + MapSet.size(o.announcers) end)
  catch
    _, _ -> 0
  end

  # The fan-out invs have been handled: the announcer count is stable and
  # TxRelay's mailbox is empty for a few consecutive polls.
  defp fanout_settled?(node) do
    Exnode.Test.Wait.until?(
      fn ->
        a = fanout_entries(node)
        Process.sleep(200)

        {:message_queue_len, q} =
          Process.info(Process.whereis(node.n.tx_relay), :message_queue_len)

        q == 0 and fanout_entries(node) == a
      end,
      120_000,
      100
    )
  end

  @tag :bench
  test "orphan fan-out does not stall the shared TxRelay", %{tmp_dir: dir} do
    node = Exnode.Test.Node.start(dir, listen: 0)
    port = node.port
    n_orphans = String.to_integer(System.get_env("FANOUT_ORPHANS", "400"))
    n_ann = String.to_integer(System.get_env("FANOUT_ANN", "100"))
    n_senders = String.to_integer(System.get_env("FANOUT_SENDERS", "24"))

    {coins, tip_header} = mine(111, node)
    assert orphan_count(node) == 0

    senders = dial_peers(port, n_senders)
    announcers = dial_peers(port, n_ann)
    {{:input, attacker_bytes_start}, _} = :erlang.statistics(:io)

    # 1. Setup: orphans (round-robin over 4 sender peers).
    for {sock, i} <- Enum.with_index(Stream.cycle(senders) |> Enum.take(n_orphans)) do
      FakePeer.send_msgs(sock, [{:tx, orphan_tx(1, i).raw}])
    end

    assert Exnode.Test.Wait.until?(fn -> orphan_count(node) == n_orphans end, 30_000, 50)

    # 2. Fan-out: every announcer invs every orphan wtxid.
    items = for i <- 1..n_orphans, do: %{type: :wtx, hash: orphan_tx(1, i).wtxid}

    {setup_us, _} =
      :timer.tc(fn ->
        for sock <- announcers, do: FakePeer.send_msgs(sock, [{:inv, items}])
        assert fanout_settled?(node)
      end)

    # Capped as Core's latency score, not orphans x announcers.
    assert :sys.get_state(node.n.tx_relay).orphan_score <= 3_000

    IO.puts(
      "setup done: #{n_orphans} orphans, #{fanout_entries(node)} announcer entries, fan-out processed in #{div(setup_us, 1000)} ms"
    )

    # Honest peer + control measurement (no attack traffic). The peer relays
    # a tx, then a new block: both messages are handled in order by its peer
    # process, so the block waits behind the tx's TxRelay call.
    honest = FakePeer.dial(port, handshake: false)
    _ = FakePeer.send_msgs(honest, [{:version, FakePeer.version()}, :wtxidrelay, :verack])
    _ = FakePeer.recv(honest, ["version", "verack"], 2, timeout: 5_000)
    honest_tx = Coins.tx([Enum.at(coins, 0)], [{25 * @coin, Coins.p2wsh()}])
    b0 = next_block(tip_header, 112)

    {control_us, _} =
      :timer.tc(fn ->
        FakePeer.send_msgs(honest, [{:tx, honest_tx.raw}, {:block, b0.raw}])

        true =
          Exnode.Test.Wait.until?(
            fn -> Mempool.has?(node.n.mempool, honest_tx.txid) end,
            20_000,
            20
          )

        true =
          Exnode.Test.Wait.until?(
            fn -> State.tip(node.n.chain_state).hash == b0.header.hash end,
            20_000,
            20
          )
      end)

    IO.puts("control: honest tx accepted + block connected in #{div(control_us, 1000)} ms")

    # 3. Attack: the sender peers stream fresh orphan txs continuously. Each
    # used to cost TxRelay a full limit_orphans pass over every announcer
    # entry; now it costs O(evictions).
    stop = :counters.new(1, [])
    sent = :counters.new(1, [])

    attack_pids =
      for {sock, k} <- Enum.with_index(senders) do
        spawn(fn -> trigger_loop(sock, k * 1_000_000, stop, sent) end)
      end

    # While the triggers are being processed, the honest peer relays a tx.
    # Give the attackers' calls a moment to pile up in TxRelay's mailbox.
    Process.sleep(String.to_integer(System.get_env("FANOUT_WARMUP_MS", "2500")))
    honest_tx2 = Coins.tx([Enum.at(coins, 1)], [{25 * @coin, Coins.p2wsh()}])
    b1 = next_block(b0.header, 113)

    {attack_us, _} =
      :timer.tc(fn ->
        FakePeer.send_msgs(honest, [{:tx, honest_tx2.raw}, {:block, b1.raw}])

        true =
          Exnode.Test.Wait.until?(
            fn -> Mempool.has?(node.n.mempool, honest_tx2.txid) end,
            300_000,
            20
          )

        true =
          Exnode.Test.Wait.until?(
            fn -> State.tip(node.n.chain_state).hash == b1.header.hash end,
            300_000,
            20
          )
      end)

    :counters.put(stop, 1, 1)
    for p <- attack_pids, do: Process.exit(p, :kill)

    trigger_count = :counters.get(sent, 1)

    {{:input, in_bytes}, _} = :erlang.statistics(:io)
    attacker_bytes = in_bytes - attacker_bytes_start

    IO.puts(
      "attack: #{trigger_count} orphan txs streamed -> " <>
        "honest tx accepted + block connected in #{div(attack_us, 1000)} ms (control #{div(control_us, 1000)} ms); " <>
        "attacker in-bytes total #{div(attacker_bytes, 1024)} KiB"
    )

    # Before the fix: 755 ms vs 20 ms control at these defaults, growing
    # with the fan-out. Now within a small margin of the control.
    assert attack_us < max(10 * control_us, 500_000)
    assert :sys.get_state(node.n.tx_relay).orphan_score <= 3_000
  end

  # A valid block extending `prev` (a header), spending nothing.
  defp next_block(prev, height) do
    BlockBuilder.build(prev, [BlockBuilder.coinbase(height, 50 * @coin)], time: prev.time + 1)
  end

  # Streams fresh orphan txs (each a new wtxid spending a never-existing
  # outpoint) until `stop` is set.
  defp trigger_loop(sock, base, stop, sent) do
    if :counters.get(stop, 1) == 1 do
      :ok
    else
      n = base + :counters.get(sent, 1) * 4
      FakePeer.send_msgs(sock, [{:tx, orphan_tx(2, n).raw}])
      :counters.add(sent, 1, 1)
      trigger_loop(sock, base, stop, sent)
    end
  end
end
