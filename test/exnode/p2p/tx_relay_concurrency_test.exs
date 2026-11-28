defmodule Exnode.P2P.TxRelayConcurrencyTest do
  @moduledoc """
  Concurrency, backpressure, and monitor-hygiene tests for the async
  `TxRelay` ↔ `Mempool` ↔ `Peer` boundary (Plan 02).
  """
  use Exnode.NodeCase

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Tx
  alias Exnode.Mempool
  alias Exnode.P2P.{HighBandwidth, SyncState, TxRelay}
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @p ChainParams.get(:regtest)
  @spk <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)

  defp spend({txid, vout, value}, fee \\ 2_000) do
    ins = [
      %Tx.In{
        prev_hash: txid,
        prev_index: vout,
        script_sig: <<>>,
        sequence: 0xFFFFFFFD,
        witness: [<<0x51>>]
      }
    ]

    outs = [%Tx.Out{value: value - fee, script_pubkey: @spk}]
    BB.finalize(%Tx{version: 2, inputs: ins, outputs: outs, locktime: 0})
  end

  defp setup_chain_with_coins(dir, n_coins) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs_name = :"cs_#{System.unique_integer([:positive])}"
    mp_name = :"mp_#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(
        name: cs_name,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        mempool: mp_name
      )

    total = 100 + n_coins

    {blocks, _} =
      Enum.map_reduce(1..total, @p.genesis.header, fn h, prev ->
        b =
          BB.build(
            prev,
            [BB.coinbase_with(h, 50 * 100_000_000, outputs: [{50 * 100_000_000, @spk}])],
            time: System.os_time(:second) - (total - h) * 60
          )

        {b, b.header}
      end)

    for b <- blocks, do: {:ok, :connected} = State.submit_block(cs, b)
    coins = for b <- Enum.take(blocks, n_coins), do: {hd(b.txs).txid, 0, 50 * 100_000_000}

    %{
      kv: kv,
      hs: hs,
      cs: cs_name,
      mp_name: mp_name,
      tip: List.last(blocks).header.hash,
      coins: coins
    }
  end

  test "TxRelay serves inv/lookup while multiple peers verify slow txs concurrently", %{
    tmp_dir: dir
  } do
    env = setup_chain_with_coins(dir, 4)
    test_pid = self()

    # Barrier verify function: notifies test_pid and waits for :go before returning :ok.
    verify = fn _raw, _spent, _flags ->
      send(test_pid, {:verifying, self()})
      receive do: (:go -> :ok)
    end

    {:ok, mp} =
      Mempool.start_link(
        name: env.mp_name,
        chain_state: env.cs,
        headers: env.hs,
        params: @p,
        verify: verify
      )

    {:ok, relay} = TxRelay.start_link(mempool: mp, async_mempool: true, tick_ms: nil)

    p1 = spawn_link(fn -> Process.sleep(:infinity) end)
    p2 = spawn_link(fn -> Process.sleep(:infinity) end)
    p3 = spawn_link(fn -> Process.sleep(:infinity) end)

    info = %{wtxid_relay: true, preferred: false, relay_txs: true, inbound: true}
    for p <- [p1, p2, p3], do: TxRelay.connected(relay, p, info)
    wait_until(fn -> map_size(:sys.get_state(relay).peers) == 3 end)

    tx1 = spend(Enum.at(env.coins, 0))
    tx2 = spend(Enum.at(env.coins, 1))
    ref1 = make_ref()
    ref2 = make_ref()

    TxRelay.submit_tx(relay, p1, ref1, tx1)
    TxRelay.submit_tx(relay, p2, ref2, tx2)

    # Both script verification tasks start concurrently without blocking TxRelay.
    assert_receive {:verifying, w1}, 2_000
    assert_receive {:verifying, w2}, 2_000
    assert w1 != w2

    # Meanwhile TxRelay immediately serves inv and lookup calls from p3.
    {inv_us, :ok} =
      :timer.tc(fn ->
        TxRelay.inv(relay, p3, [%{type: :wtx, hash: :crypto.strong_rand_bytes(32)}])
      end)

    {lookup_us, {[], _}} =
      :timer.tc(fn ->
        TxRelay.lookup(relay, [%{type: :wtx, hash: :crypto.strong_rand_bytes(32)}])
      end)

    assert inv_us < 200_000
    assert lookup_us < 200_000

    # Release both verifications and confirm both txs land in the mempool.
    send(w1, :go)
    send(w2, :go)

    wait_until(fn -> Mempool.has?(mp, tx1.txid) and Mempool.has?(mp, tx2.txid) end)
  end

  test "Peer pauses socket reads at max_tx_in_flight and resumes on :tx_done", %{tmp_dir: dir} do
    env = setup_chain_with_coins(dir, 6)
    test_pid = self()

    verify = fn _raw, _spent, _flags ->
      send(test_pid, {:verifying, self()})
      receive do: (:go -> :ok)
    end

    {:ok, mp} =
      Mempool.start_link(
        name: env.mp_name,
        chain_state: env.cs,
        headers: env.hs,
        params: @p,
        verify: verify
      )

    {:ok, relay} = TxRelay.start_link(mempool: mp, async_mempool: true, tick_ms: nil)
    {:ok, sync} = SyncState.start_link([])
    {:ok, peer_sup} = DynamicSupervisor.start_link(strategy: :one_for_one)

    node = %{
      params: @p,
      headers: env.hs,
      chain_state: env.cs,
      tx_relay: relay,
      sync: sync,
      peer_sup: peer_sup,
      max_tx_in_flight: 2
    }

    {peer_pid, sock} =
      FakePeer.connect_from(node,
        node: %{tx_relay: relay, max_tx_in_flight: 2},
        version: %{relay: true}
      )

    FakePeer.recv(sock, ["verack"], 1)
    wait_until(fn -> Map.has_key?(:sys.get_state(relay).peers, peer_pid) end)

    tx1 = spend(Enum.at(env.coins, 0))
    tx2 = spend(Enum.at(env.coins, 1))
    tx3 = spend(Enum.at(env.coins, 2))

    # Send 3 txs; cap is 2, so peer enters {:ready, :paused} after 2 and holds tx3 unread.
    :ok = FakePeer.send_msgs(sock, [{:tx, tx1.raw}, {:tx, tx2.raw}, {:tx, tx3.raw}])

    assert_receive {:verifying, w1}, 2_000
    assert_receive {:verifying, w2}, 2_000
    refute_receive {:verifying, _}, 150

    {state, data} = :sys.get_state(peer_pid)
    assert state == {:ready, :paused}
    assert data.proto.tx_in_flight == 2

    # Releasing w1 sends {:tx_done, ref} -> peer resumes and submits tx3.
    send(w1, :go)
    assert_receive {:verifying, w3}, 2_000

    # Release remaining verifications -> peer returns to {:ready, :active} with 0 in flight.
    send(w2, :go)
    send(w3, :go)

    wait_until(fn ->
      {st, d} = :sys.get_state(peer_pid)
      st == {:ready, :active} and d.proto.tx_in_flight == 0
    end)

    assert Mempool.has?(mp, tx1.txid)
    assert Mempool.has?(mp, tx2.txid)
    assert Mempool.has?(mp, tx3.txid)
  end

  test "monitor idempotency: duplicate SyncState, TxRelay, HighBandwidth registrations keep 1 monitor" do
    {:ok, sync} = SyncState.start_link([])
    {:ok, hb} = HighBandwidth.start_link([])
    {:ok, mp} = Agent.start_link(fn -> :ok end)
    {:ok, relay} = TxRelay.start_link(mempool: mp, tick_ms: nil)

    p = spawn_link(fn -> Process.sleep(:infinity) end)

    assert SyncState.try_start(sync, p, true, false)
    assert SyncState.try_protect(sync, p)
    refute SyncState.try_start(sync, p, true, true)

    info = %{wtxid_relay: true, preferred: false, relay_txs: true, inbound: true}
    TxRelay.connected(relay, p, info)
    TxRelay.connected(relay, p, info)
    TxRelay.connected(relay, p, info)
    _ = :sys.get_state(relay)

    HighBandwidth.select(hb, p, false)
    HighBandwidth.select(hb, p, false)
    _ = :sys.get_state(hb)

    {:monitored_by, monitors} = Process.info(p, :monitored_by)
    assert Enum.count(monitors, &(&1 == sync)) == 1
    assert Enum.count(monitors, &(&1 == relay)) == 1
    assert Enum.count(monitors, &(&1 == hb)) == 1
  end
end
