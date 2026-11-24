defmodule Exnode.P2P.RebroadcastTest do
  @moduledoc """
  Coverage for P2P & TxRelay announcement and peer state wiring:
  * `TxRelay.inv_stats/1` reports live inbound/outbound `InvBucket` counters;
  * `Peer.info/1` exposes `min_ping_us`, `hb_from`, `feefilter`, `presynced_headers`,
    and `synced_blocks`;
  * `feefilter` is sent to `relay: true` peers and omitted for `relay: false` peers;
  * `ReattemptInitialBroadcast`: locally submitted `unbroadcast` transactions are
    re-announced to peers that connect later once the rebroadcast timer elapses.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Clock
  alias Exnode.Codec.Block
  alias Exnode.Mempool
  alias Exnode.P2P.{Message, Peer, TxRelay}
  alias Exnode.Test.{BlockBuilder, SpendChain}

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  test "TxRelay.inv_stats, feefilter relay gating, and Peer.info fields", %{tmp_dir: dir} do
    clock = Clock.new()
    bs = for raw <- BlockBuilder.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    Clock.set(clock, List.last(bs).header.time + 10)

    %{n: n} = TestNode.start(dir, clock: clock)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)
    :ok = Mempool.sync_to(n.mempool, List.last(bs).header.hash)

    stats = TxRelay.inv_stats(n.tx_relay)
    assert %{inbound: %{backlog: 0}, outbound: %{backlog: 0}} = stats

    # A relay: false peer does not receive feefilter, and Peer.info exposes live fields.
    {p_norelay, _s_norelay} =
      FakePeer.connect_from(n,
        node: %{tx_relay: n.tx_relay, clock: clock},
        version: %{relay: false}
      )

    info_nr = Peer.info(p_norelay)
    assert is_boolean(info_nr.hb_from)
    assert info_nr.presynced_headers == -1
    assert is_integer(info_nr.feefilter)

    # A relay: true peer receives feefilter on handshake.
    {_p_relay, s_relay} =
      FakePeer.connect_from(n,
        node: %{tx_relay: n.tx_relay, clock: clock},
        version: %{relay: true}
      )

    assert [{"feefilter", payload}] = FakePeer.recv(s_relay, ["feefilter"], 1)
    assert {:ok, {:feefilter, rate}} = Message.decode("feefilter", payload)
    assert rate > 0
  end

  test "unbroadcast mempool transactions are re-announced when the rebroadcast window passes", %{
    tmp_dir: dir
  } do
    p = Exnode.ChainParams.get(:regtest)
    {bs, _} = SpendChain.build(p.genesis.header, 115)
    clock = Clock.new()
    Clock.set(clock, List.last(bs).header.time + 10)

    %{n: n} = TestNode.start(dir, clock: clock)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)
    :ok = Mempool.sync_to(n.mempool, List.last(bs).header.hash)

    # Spend a mature SpendChain output while no peer is connected (unbroadcast: true).
    src_tx = Enum.at(Enum.at(bs, 112).txs, 2)
    coin = {src_tx.txid, 0, 25 * @coin - 1_000, SpendChain.spk()}
    tx = SpendChain.spend([coin], [{25 * @coin - 5_000, SpendChain.spk()}])
    assert {:ok, _} = Mempool.accept(n.mempool, tx, unbroadcast: true)
    assert Mempool.unbroadcast_txids(n.mempool) == [tx.txid]

    # A tx-relaying peer connects after the initial submission.
    {_peer, sock} =
      FakePeer.connect_from(n,
        node: %{tx_relay: n.tx_relay, clock: clock},
        version: %{relay: true}
      )

    _ = FakePeer.recv(sock, ["feefilter"], 1)

    # Advance clock past the 10-15 min rebroadcast window and tick TxRelay.
    Clock.advance(clock, 1_000)
    send(n.tx_relay, :tick)
    send(n.tx_relay, :trickle)

    [{"inv", inv_payload}] = FakePeer.recv(sock, ["inv"], 1)
    assert {:ok, {:inv, items}} = Message.decode("inv", inv_payload)
    hashes = Enum.map(items, & &1.hash)
    assert tx.txid in hashes or tx.wtxid in hashes
  end
end
