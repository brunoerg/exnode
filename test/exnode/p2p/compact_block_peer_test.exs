defmodule Exnode.P2P.CompactBlockPeerTest do
  @moduledoc """
  `Peer` compact-block handling past the happy path (Core
  `ProcessMessage` CMPCTBLOCK / BLOCKTXN, `PartiallyDownloadedBlock`),
  over a socket, with a high-bandwidth peer and a stub mempool:

  * a malformed cmpctblock or blocktxn is dropped, the peer kept (Core
    drops a message that fails to deserialize); a compact block
    whose prefilled index is out of range is invalid (misbehaviour);
  * a compact block on an unknown parent makes us sync headers instead;
  * an invalid header via cmpctblock is punished; a cached-invalid header
    via cmpctblock is not, from an inbound or an outbound peer, and neither
    is an invalid block rebuilt from a compact block (Core
    `MaybePunishNodeForBlock` with `via_compact_block`: BIP152 lets a
    high-bandwidth peer relay a block after checking only its header);
  * a reconstruction that cannot start (duplicate short ids), a blocktxn
    that fills it wrongly (merkle mismatch) or a partial that times out
    (60 s) falls back to requesting the full block; a wrong number of
    blocktxn txs is misbehaviour; the right ones connect the block;
  * a block we already hold, or one that arrives another way while being
    rebuilt, ends the reconstruction without a request.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Clock
  alias Exnode.Codec.Block
  alias Exnode.P2P.{CompactBlock, Frame, Message}
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @p Exnode.ChainParams.get(:regtest)

  # A mempool that knows `txs` (Mempool.match_short_ids).
  defmodule StubMempool do
    use GenServer
    def start_link(txs), do: GenServer.start_link(__MODULE__, txs)
    def init(txs), do: {:ok, txs}

    def handle_call({:match_short_ids, {k0, k1}, wanted}, _f, txs) do
      w = MapSet.new(wanted)

      found =
        for tx <- txs,
            id = CompactBlock.short_id(k0, k1, tx.wtxid),
            MapSet.member?(w, id),
            into: %{},
            do: {id, tx}

      {:reply, found, txs}
    end

    def handle_call(_, _f, txs), do: {:reply, nil, txs}
  end

  setup_all do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    # Block 151: a coinbase and two spends of mature chain coinbases.
    spends = for b <- Enum.take(bs, 2), do: BB.spend_op_true(hd(b.txs).txid, 0, 49 * 100_000_000)
    b151 = BB.build(List.last(bs).header, [BB.coinbase(151, 25 * 100_000_000) | spends])
    %{bs: bs, b151: b151}
  end

  setup %{tmp_dir: dir, bs: bs} do
    node = TestNode.start(dir, listen: 0)
    for b <- bs, do: {:ok, :connected} = State.submit_block(node.n.chain_state, b)
    %{n: node.n, port: node.port}
  end

  # A peer that provides compact blocks, selected by us as high-bandwidth,
  # with a mempool knowing `known` and a clock just after the tip (Core
  # CanDirectFetch). Only explicit ticks run its periodic pass.
  defp hb_peer(n, bs, known \\ [], node \\ %{}) do
    {:ok, mp} = StubMempool.start_link(known)
    clock = Clock.new()
    Clock.set(clock, List.last(bs).header.time + 10)

    {pid, sock, ref} =
      FakePeer.connect_from(n,
        node: Map.merge(%{mempool: mp, clock: clock, tick_ms: nil}, node),
        after_handshake: [{:sendcmpct, %{announce: false, version: 2}}],
        monitor: true
      )

    send(pid, {:send, {:sendcmpct, %{announce: true, version: 2}}})
    wait_until(fn -> :sys.get_state(pid).hb_selected and :sys.get_state(pid).provides_cmpct end)
    {pid, sock, clock, ref}
  end

  defp cmpct(b, nonce \\ 7),
    do: {:cmpctblock, CompactBlock.encode(CompactBlock.from_block(b, nonce))}

  defp send_raw(sock, cmd, payload),
    do: :ok = :gen_tcp.send(sock, IO.iodata_to_binary(Frame.encode(@p.magic, cmd, payload)))

  defp assert_stopped(ref, reason),
    do: assert_receive({:DOWN, ^ref, :process, _, {:shutdown, ^reason}}, 5_000)

  # Commands the node sent before answering a ping sent now.
  defp before_pong(sock) do
    nonce = System.unique_integer([:positive])
    :ok = FakePeer.send_msgs(sock, {:ping, nonce})
    collect(sock, nonce, <<>>, [])
  end

  defp collect(sock, nonce, buf, acc) do
    case Frame.decode(@p.magic, buf) do
      {:ok, "pong", <<^nonce::little-64>>, _} ->
        Enum.reverse(acc)

      {:ok, cmd, payload, rest} ->
        {:ok, m} = Message.decode(cmd, payload)
        collect(sock, nonce, rest, [m | acc])

      _ ->
        {:ok, data} = :gen_tcp.recv(sock, 0, 5_000)
        collect(sock, nonce, buf <> data, acc)
    end
  end

  defp getdata_block?(msgs, hash),
    do: Enum.any?(msgs, &match?({:getdata, [%{type: :block, hash: ^hash}]}, &1))

  defp tip(n), do: State.tip(n.chain_state)

  test "a malformed cmpctblock is dropped, the peer kept", %{n: n, bs: bs} do
    {pid, sock, _clock, ref} = hb_peer(n, bs)
    send_raw(sock, "cmpctblock", <<1, 2, 3>>)
    before_pong(sock)
    refute_received {:DOWN, ^ref, _, _, _}
    assert Process.alive?(pid)
  end

  test "a compact block on an unknown parent: headers are synced instead", %{n: n, bs: bs} do
    {pid, sock, _clock, _ref} = hb_peer(n, bs)
    orphan = BB.next_header(%{List.last(bs).header | hash: <<1::256>>})

    c = %CompactBlock{
      header: orphan,
      nonce: 1,
      short_ids: [],
      prefilled: [{0, BB.coinbase(151, 1)}]
    }

    :ok = FakePeer.send_msgs(sock, {:cmpctblock, CompactBlock.encode(c)})
    assert [{"getheaders", _}] = FakePeer.recv(sock, ["getheaders"], 1)
    assert Process.alive?(pid)
  end

  test "an invalid header via cmpctblock is punished", %{n: n, bs: bs} do
    # Wrong difficulty for regtest (no retargeting: bits must equal the
    # parent's). Rejected before it is stored, so a resend gets the same verdict.
    bad = BB.next_header(List.last(bs).header, bits: 0x207FFFFE)
    c = %CompactBlock{header: bad, nonce: 1, short_ids: [], prefilled: [{0, BB.coinbase(151, 1)}]}
    {_pid, sock, _clock, ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, {:cmpctblock, CompactBlock.encode(c)})
    assert_stopped(ref, {:misbehaving, "invalid header via cmpctblock: bad-diffbits"})
  end

  test "a cached-invalid header via cmpctblock punishes neither an inbound nor an outbound peer",
       %{n: n, bs: bs, port: port} do
    # A valid header whose block is invalid (coinbase pays too much): the
    # header is stored, then marked failed.
    bad = BB.build(List.last(bs).header, [BB.coinbase(151, 100 * 100_000_000)])
    assert {:error, _} = State.submit_block(n.chain_state, bad)
    payload = CompactBlock.encode(CompactBlock.from_block(bad, 1))

    inbound = FakePeer.dial(port)
    FakePeer.recv(inbound, ["verack"], 1)

    :ok =
      FakePeer.send_msgs(inbound, [
        {:sendcmpct, %{announce: false, version: 2}},
        {:cmpctblock, payload}
      ])

    # Still connected: it answers the ping.
    before_pong(inbound)

    # Core exempts it (via_compact_block) from an outbound peer too.
    {_pid, sock, _clock, ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, {:cmpctblock, payload})
    before_pong(sock)
    refute_received {:DOWN, ^ref, _, _, _}
  end

  test "an invalid block rebuilt from a compact block does not punish its peer; it is marked failed",
       %{n: n, bs: bs} do
    # Core's NewPoWValidBlock announces a block to high-bandwidth
    # peers before ConnectBlock, so honest peers relay blocks with valid PoW
    # that turn out invalid. Every tx is prefilled: it is rebuilt at once.
    bad = BB.build(List.last(bs).header, [BB.coinbase(151, 100 * 100_000_000)])
    {_pid, sock, _clock, ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, cmpct(bad))
    before_pong(sock)
    refute_received {:DOWN, ^ref, _, _, _}

    assert {:error, {:cached_invalid, _}} = State.submit_block(n.chain_state, bad)
    assert tip(n).hash == List.last(bs).header.hash
  end

  test "a deferred verdict on a rebuilt block is not punished; on a full block it is",
       %{n: n, bs: bs} do
    # In IBD the chain state stores a block and answers later with
    # {:block_checked, ...} (Core BlockChecked, with via_compact_block =
    # !fMayBan from mapBlockSource).
    rebuilt = :crypto.strong_rand_bytes(32)
    {pid, sock, _clock, ref} = hb_peer(n, bs)
    :sys.replace_state(pid, &%{&1 | rebuilt_deferred: [rebuilt]})
    send(pid, {:block_checked, rebuilt, {:error, {:consensus, "bad-cb-amount"}}})
    before_pong(sock)
    refute_received {:DOWN, ^ref, _, _, _}
    assert :sys.get_state(pid).rebuilt_deferred == []

    send(
      pid,
      {:block_checked, :crypto.strong_rand_bytes(32), {:error, {:consensus, "bad-cb-amount"}}}
    )

    assert_stopped(ref, {:misbehaving, "invalid block: bad-cb-amount"})
  end

  test "a prefilled index out of range is an invalid compact block", %{n: n, bs: bs, b151: b} do
    {_pid, sock, _clock, ref} = hb_peer(n, bs)
    c = CompactBlock.from_block(b, 3)

    :ok =
      FakePeer.send_msgs(
        sock,
        {:cmpctblock, CompactBlock.encode(%{c | prefilled: [{99, hd(b.txs)}]})}
      )

    assert_stopped(ref, {:misbehaving, "invalid compact block"})
  end

  test "duplicate short ids: the full block is requested", %{n: n, bs: bs, b151: b} do
    {_pid, sock, _clock, _ref} = hb_peer(n, bs)
    c = CompactBlock.from_block(b, 3)
    [id | _] = c.short_ids
    :ok = FakePeer.send_msgs(sock, {:cmpctblock, CompactBlock.encode(%{c | short_ids: [id, id]})})
    assert getdata_block?(before_pong(sock), b.header.hash)
  end

  test "missing txs: getblocktxn, then the right blocktxn connects the block",
       %{n: n, bs: bs, b151: b} do
    {_pid, sock, _clock, _ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, cmpct(b))
    [{"getblocktxn", payload}] = FakePeer.recv(sock, ["getblocktxn"], 1)
    assert {:ok, hash, [1, 2]} = CompactBlock.decode_getblocktxn(payload)
    assert hash == b.header.hash

    :ok = FakePeer.send_msgs(sock, {:blocktxn, CompactBlock.encode_blocktxn(hash, tl(b.txs))})
    wait_until(fn -> tip(n).hash == b.header.hash end)
  end

  test "a malformed blocktxn is dropped, the peer kept", %{n: n, bs: bs, b151: b} do
    {pid, sock, _clock, ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, cmpct(b))
    FakePeer.recv(sock, ["getblocktxn"], 1)
    send_raw(sock, "blocktxn", <<1, 2, 3>>)
    before_pong(sock)
    refute_received {:DOWN, ^ref, _, _, _}
    assert Process.alive?(pid)
  end

  test "a blocktxn with the wrong number of txs is misbehaviour", %{n: n, bs: bs, b151: b} do
    {_pid, sock, _clock, ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, cmpct(b))
    FakePeer.recv(sock, ["getblocktxn"], 1)

    :ok =
      FakePeer.send_msgs(
        sock,
        {:blocktxn, CompactBlock.encode_blocktxn(b.header.hash, [Enum.at(b.txs, 1)])}
      )

    assert_stopped(ref, {:misbehaving, "invalid compact block txns"})
  end

  test "a blocktxn with the wrong txs (merkle mismatch): the full block is requested",
       %{n: n, bs: bs, b151: b} do
    {pid, sock, _clock, _ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, cmpct(b))
    FakePeer.recv(sock, ["getblocktxn"], 1)
    wrong = for i <- 1..2, do: BB.spend_op_true(<<i::256>>, 0, 1)

    :ok =
      FakePeer.send_msgs(sock, {:blocktxn, CompactBlock.encode_blocktxn(b.header.hash, wrong)})

    assert getdata_block?(before_pong(sock), b.header.hash)
    assert Process.alive?(pid)
  end

  test "a reconstruction not completed within 60 s: the full block is requested",
       %{n: n, bs: bs, b151: b} do
    {pid, sock, clock, _ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, cmpct(b))
    FakePeer.recv(sock, ["getblocktxn"], 1)
    Clock.advance(clock, 59)
    :ok = Clock.tick(pid)
    refute getdata_block?(before_pong(sock), b.header.hash)
    Clock.advance(clock, 1)
    :ok = Clock.tick(pid)
    assert getdata_block?(before_pong(sock), b.header.hash)
    assert :sys.get_state(pid).partials == %{}
  end

  test "a block that arrives another way ends its reconstruction without a request",
       %{n: n, bs: bs, b151: b} do
    {pid, sock, clock, _ref} = hb_peer(n, bs)
    :ok = FakePeer.send_msgs(sock, cmpct(b))
    FakePeer.recv(sock, ["getblocktxn"], 1)
    {:ok, :connected} = State.submit_block(n.chain_state, b)
    Clock.advance(clock, 1)
    :ok = Clock.tick(pid)
    assert :sys.get_state(pid).partials == %{}
    refute getdata_block?(before_pong(sock), b.header.hash)
  end

  test "a compact block we already hold is ignored", %{n: n, bs: bs} do
    {pid, sock, _clock, _ref} = hb_peer(n, bs)
    held = List.last(bs)
    :ok = FakePeer.send_msgs(sock, cmpct(held))
    msgs = before_pong(sock)
    refute Enum.any?(msgs, &match?({:getdata, _}, &1))
    assert :sys.get_state(pid).partials == %{}
  end

  # Regression: a reconstruction was not registered with
  # BlockDownload, so parallel download requested the same block whole
  # from another peer (Core BlockRequested with a partial block); a rebuilt
  # block now takes over any other request for it.
  test "a reconstruction is in flight from its peer: not handed to another peer, released when rebuilt",
       %{n: n, bs: bs, b151: b} do
    alias Exnode.P2P.BlockDownload
    {pid, sock, _clock, _ref} = hb_peer(n, bs, [], %{block_download: n.block_download})
    :ok = FakePeer.send_msgs(sock, cmpct(b))
    FakePeer.recv(sock, ["getblocktxn"], 1)
    hash = b.header.hash
    assert %{^hash => {^pid, _, 151}} = BlockDownload.in_flight(n.block_download)

    other = spawn(fn -> Process.sleep(:infinity) end)
    refute hash in BlockDownload.request(n.block_download, other, hash)

    :ok = FakePeer.send_msgs(sock, {:blocktxn, CompactBlock.encode_blocktxn(hash, tl(b.txs))})
    wait_until(fn -> tip(n).hash == b.header.hash end)

    wait_until(fn ->
      not Map.has_key?(BlockDownload.in_flight(n.block_download), hash) and
        not Map.has_key?(BlockDownload.checking(n.block_download), hash)
    end)
  end

  test "a reconstruction ended by the block arriving another way gives its request back",
       %{n: n, bs: bs, b151: b} do
    alias Exnode.P2P.BlockDownload
    {pid, sock, clock, _ref} = hb_peer(n, bs, [], %{block_download: n.block_download})
    :ok = FakePeer.send_msgs(sock, cmpct(b))
    FakePeer.recv(sock, ["getblocktxn"], 1)
    assert Map.has_key?(BlockDownload.in_flight(n.block_download), b.header.hash)
    {:ok, :connected} = State.submit_block(n.chain_state, b)
    Clock.advance(clock, 1)
    :ok = Clock.tick(pid)

    wait_until(fn ->
      not Map.has_key?(BlockDownload.in_flight(n.block_download), b.header.hash)
    end)
  end

  # Regression: every compact block that failed to initialise put its full
  # block in flight from its peer, past MAX_BLOCKS_IN_TRANSIT_PER_PEER and
  # each with a byte estimate, so one high-bandwidth peer could hold
  # hundreds of requests (cheap sibling headers) and exhaust the byte
  # budget. Core CMPCTBLOCK calls BlockRequested, and so falls back to
  # getdata, only while the peer has fewer than 16 blocks in flight.
  test "failed compact blocks put at most MAX_BLOCKS_IN_TRANSIT_PER_PEER requests on their peer",
       %{n: n, bs: bs} do
    alias Exnode.P2P.BlockDownload
    {pid, sock, _clock, _ref} = hb_peer(n, bs, [], %{block_download: n.block_download})
    spend = BB.spend_op_true(hd(hd(bs).txs).txid, 0, 49 * 100_000_000)

    siblings =
      for i <- 1..17,
          do:
            BB.build(List.last(bs).header, [
              BB.coinbase(151, 25 * 100_000_000, <<i, 0x51>>),
              spend
            ])

    fake = fn b ->
      c = CompactBlock.from_block(b, 3)
      [id] = c.short_ids
      {:cmpctblock, CompactBlock.encode(%{c | short_ids: [id, id]})}
    end

    :ok = FakePeer.send_msgs(sock, Enum.map(siblings, fake))
    msgs = before_pong(sock)
    requested = Enum.filter(siblings, &getdata_block?(msgs, &1.header.hash))
    assert length(requested) == 16
    refute getdata_block?(msgs, List.last(siblings).header.hash)

    mine = for {_, {^pid, _, _}} <- BlockDownload.in_flight(n.block_download), do: 1
    assert length(mine) == 16
  end
end
