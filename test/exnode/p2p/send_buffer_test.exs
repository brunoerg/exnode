defmodule Exnode.P2P.SendBufferTest do
  @moduledoc """
  A per-peer send buffer, as Core's `-maxsendbuffer`
  (`m_send_memusage`, `fPauseSend`). Bytes go to a writer process that owns
  the blocking socket send. While more than the limit is unsent the peer is
  paused: no block and no further tx of a getdata is served
  (`if (pfrom.fPauseSend) break;`), no later message is processed, and the
  socket is not read. It resumes when the writer drains. Paused for
  `TIMEOUT_INTERVAL` (20 min), it is disconnected ("send buffer full").

  The remote's reading is simulated by a gate around the socket send
  (`node.socket_send`): closed, the writer blocks, as in `send` on a peer
  that does not read. Time is a mock clock, and the peer's periodic pass
  runs only when the test ticks it (`Exnode.Clock.tick/2`).
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Clock
  alias Exnode.Codec.Tx
  alias Exnode.P2P.{Message, Peer}
  alias Exnode.Test.BlockBuilder, as: BB

  @p Exnode.ChainParams.get(:regtest)
  @spk <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)
  @limit 1_000

  setup %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)

    # 120 blocks; coinbases pay to P2WSH(OP_TRUE), so 1..20 are spendable.
    {blocks, _} =
      Enum.map_reduce(1..120, @p.genesis.header, fn h, prev ->
        b =
          BB.build(prev, [
            BB.coinbase_with(h, 50 * 100_000_000, outputs: [{50 * 100_000_000, @spk}])
          ])

        {b, b.header}
      end)

    for b <- blocks, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)

    gate = :ets.new(:gate, [:public])
    :ets.insert(gate, {:open, true})
    clock = Clock.new()
    Clock.set(clock, 1_800_000_000)
    %{n: n, blocks: blocks, gate: gate, clock: clock}
  end

  defp close(gate), do: :ets.insert(gate, {:open, false})
  defp open(gate), do: :ets.insert(gate, {:open, true})

  defp gated_send(gate) do
    fn sock, data ->
      wait_open(gate)
      :gen_tcp.send(sock, data)
    end
  end

  defp wait_open(gate) do
    case :ets.lookup(gate, :open) do
      [{:open, true}] -> :ok
      _ -> Process.sleep(5) && wait_open(gate)
    end
  end

  defp connect(%{n: n, gate: gate, clock: clock}, relay \\ false) do
    {pid, sock} =
      FakePeer.connect_from(n,
        node: %{
          tx_relay: n.tx_relay,
          socket_send: gated_send(gate),
          max_send_buffer: @limit,
          clock: clock,
          # Only the test's explicit ticks: no pass lands mid-assertion.
          tick_ms: nil
        },
        # No tx announcements to this peer (unless a test needs them: a tx
        # is served only after it was announced, Core m_last_inv_sequence).
        version: %{start_height: 120, relay: relay}
      )

    _ = FakePeer.recv(sock, ["verack"], 1)
    {pid, sock}
  end

  defp peer_state(pid), do: elem(:sys.get_state(pid), 1)

  # Reads invs until every tx of `txs` was announced (by txid or wtxid,
  # whichever the peer negotiated).
  defp await_announced(_sock, []), do: :ok

  defp await_announced(sock, txs) do
    [{"inv", payload}] = FakePeer.recv(sock, ["inv"], 1)
    {:ok, {:inv, items}} = Message.decode("inv", payload)
    hashes = MapSet.new(items, & &1.hash)
    await_announced(sock, Enum.reject(txs, &(&1.txid in hashes or &1.wtxid in hashes)))
  end

  test "paused over the limit: getdata stops, later messages wait, the peer still answers calls; " <>
         "draining resumes everything in order",
       %{blocks: blocks, gate: gate} = ctx do
    {pid, sock} = connect(ctx)
    close(gate)

    items =
      for b <- Enum.slice(blocks, 99, 10), do: %{type: :block, witness: true, hash: b.header.hash}

    :ok = FakePeer.send_msgs(sock, [{:getdata, items}, {:ping, 4242}])

    wait_until(fn -> peer_state(pid).conn.paused_since != nil end)
    st = peer_state(pid)
    assert st.conn.send_queued > @limit
    left = :queue.len(st.proto.getdata_queue)
    assert left > 0 and left < 10

    # No progress while paused, through a full pass of the peer.
    :ok = Clock.tick(pid)
    assert :queue.len(peer_state(pid).proto.getdata_queue) == left
    # The peer process is not blocked in a socket send: calls are answered.
    assert %{conn_type: :outbound_full_relay} =
             Task.await(Task.async(fn -> Peer.info(pid) end), 1_000)

    open(gate)
    got = FakePeer.recv(sock, ["block", "pong"], 11)
    assert Enum.map(got, &elem(&1, 0)) == List.duplicate("block", 10) ++ ["pong"]
    assert for({"block", raw} <- got, do: raw) == for(b <- Enum.slice(blocks, 99, 10), do: b.raw)

    wait_until(fn -> peer_state(pid).conn.send_queued == 0 end)
    st = peer_state(pid)
    assert st.conn.paused_since == nil
    assert :queue.is_empty(st.proto.getdata_queue)
  end

  test "paused with nothing queued: the next message waits until the buffer drains",
       %{blocks: blocks, gate: gate} = ctx do
    {pid, sock} = connect(ctx)
    wait_until(fn -> peer_state(pid).conn.send_queued == 0 end)
    close(gate)

    # The fewest blocks whose frames exceed the limit: the last one pauses
    # the peer just as its getdata queue empties.
    frame = fn b -> byte_size(b.raw) + 24 end
    sizes = Enum.scan(blocks, 0, &(frame.(&1) + &2))
    k = Enum.find_index(sizes, &(&1 > @limit)) + 1
    asked = Enum.take(blocks, k)
    items = for b <- asked, do: %{type: :block, witness: true, hash: b.header.hash}
    :ok = FakePeer.send_msgs(sock, [{:getdata, items}, {:ping, 77}])

    wait_until(fn -> peer_state(pid).conn.paused_since != nil end)
    st = peer_state(pid)
    assert :queue.is_empty(st.proto.getdata_queue)
    # Only the blocks are queued: the ping was not processed (no pong).
    assert st.conn.send_queued == Enum.at(sizes, k - 1)
    # A periodic pass still runs while paused (Core SendMessages: it may
    # queue a ping or getheaders) but processes no message.
    :ok = Clock.tick(pid)

    open(gate)
    got = FakePeer.recv(sock, ["block", "pong"], k + 1)
    assert Enum.map(got, &elem(&1, 0)) == List.duplicate("block", k) ++ ["pong"]
  end

  test "tx getdata: no tx is served once paused; the rest are served after, notfound only for misses",
       %{n: n, blocks: blocks, gate: gate} = ctx do
    # Txs are served only once announced to the peer: connect
    # first, then wait for every announcement.
    {pid, sock} = connect(ctx, true)
    # Registered with TxRelay (at verack) before any tx is accepted.
    wait_until(fn -> Map.has_key?(:sys.get_state(n.tx_relay).peers, pid) end)

    # 20 txs of ~350 bytes each (8 outputs), spending coinbases 1..20.
    txs =
      for b <- Enum.take(blocks, 20) do
        cb = hd(b.txs)

        ins = [
          %Tx.In{
            prev_hash: cb.txid,
            prev_index: 0,
            script_sig: <<>>,
            sequence: 0xFFFFFFFD,
            witness: [<<0x51>>]
          }
        ]

        outs =
          for _ <- 1..8,
              do: %Tx.Out{value: div(50 * 100_000_000 - 10_000, 8), script_pubkey: @spk}

        tx = BB.finalize(%Tx{version: 2, inputs: ins, outputs: outs, locktime: 0})
        {:ok, _} = Exnode.Mempool.accept(n.mempool, tx)
        tx
      end

    await_announced(sock, txs)
    close(gate)
    unknown = %{type: :wtx, witness: false, hash: :crypto.hash(:sha256, "nope")}
    items = [unknown | for(t <- txs, do: %{type: :wtx, witness: false, hash: t.wtxid})]
    :ok = FakePeer.send_msgs(sock, [{:getdata, items}])

    wait_until(fn -> peer_state(pid).conn.paused_since != nil end)
    :ok = Clock.tick(pid)
    st = peer_state(pid)
    # Core breaks out of the tx loop at the pause: only a few were pushed, the
    # rest are back in the queue, in order.
    left = :queue.to_list(st.proto.getdata_queue)
    assert length(left) > 0 and length(left) < 20
    assert left == Enum.take(items, -length(left))

    open(gate)
    got = FakePeer.recv(sock, ["tx", "notfound"], 21)
    assert for({"tx", raw} <- got, do: raw) == for(t <- txs, do: t.raw)
    assert [{"notfound", nf}] = for({"notfound", _} = m <- got, do: m)
    assert {:ok, {:notfound, [%{hash: h}]}} = Message.decode("notfound", nf)
    assert h == unknown.hash
  end

  test "paused for 20 minutes: disconnected with send_buffer_full (Core \"send buffer full\")",
       %{blocks: blocks, gate: gate, clock: clock} = ctx do
    {pid, sock} = connect(ctx)
    ref = Process.monitor(pid)
    close(gate)

    items =
      for b <- Enum.slice(blocks, 0, 10), do: %{type: :block, witness: true, hash: b.header.hash}

    :ok = FakePeer.send_msgs(sock, [{:getdata, items}])
    wait_until(fn -> peer_state(pid).conn.paused_since != nil end)

    # 20 min later; something was still sent and received meanwhile, so the
    # plain send and receive timeouts do not apply: only the pause does.
    Clock.advance(clock, 20 * 60)
    :ok = Clock.tick(pid)
    assert Process.alive?(pid)

    Clock.advance(clock, 1)

    :sys.replace_state(pid, fn {s, st} ->
      {s,
       %{
         st
         | conn: %{
             st.conn
             | last_send: st.conn.paused_since + 20 * 60,
               last_recv: st.conn.paused_since + 20 * 60
           }
       }}
    end)

    :ok = Clock.tick(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, :send_buffer_full}}, 2_000
  end

  test "the writer and the peer live and die together", ctx do
    {pid, _sock} = connect(ctx)
    w = peer_state(pid).conn.writer
    ref = Process.monitor(pid)
    wref = Process.monitor(w)
    # The peer stops: its writer goes too (it monitors the peer).
    send(pid, {:disconnect, :test})
    assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, :test}}, 2_000
    assert_receive {:DOWN, ^wref, :process, ^w, _}, 2_000

    # The writer dies: the peer goes too (linked).
    {pid, _sock} = connect(ctx)
    ref = Process.monitor(pid)
    Process.exit(peer_state(pid).conn.writer, :kill)
    assert_receive {:DOWN, ^ref, :process, ^pid, :killed}, 2_000
  end
end
