defmodule Exnode.P2P.PeerServingTest do
  @moduledoc """
  `Peer` serving past the happy path (Core `ProcessGetBlockData`,
  `ProcessGetBlockTxn`, GETHEADERS, `PrepareBlockFilterRequest`), over a
  socket, against a node holding the 150-block regtest chain:

  * getdata for a block we do not have, or one off the active chain: notfound;
  * a NODE_NETWORK_LIMITED node serves its last 288 (+2) blocks and
    disconnects a peer asking below them;
  * getblocktxn: the txs of a recent block, the whole block when it is
    10 or more deep, nothing for an unknown block, misbehaviour for an
    index past the block's txs;
  * getheaders with a locator over 101 entries disconnects;
  * BIP157: a filter type other than basic, a start above the stop
    height, or too wide a range disconnects; a range the index has not
    reached gets no answer; getcfheaders from height 0 has an all-zero
    previous header.
  """
  use Exnode.NodeCase
  import Bitwise

  alias Exnode.Chain.{Headers, State}
  alias Exnode.Clock
  alias Exnode.Codec.Block
  alias Exnode.Index.BlockFilter, as: Index
  alias Exnode.P2P.{CompactBlock, Frame, Message}
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @p Exnode.ChainParams.get(:regtest)
  @coin 100_000_000

  setup_all do
    %{bs: for(raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1))}
  end

  setup %{tmp_dir: dir, bs: bs} do
    node = TestNode.start(dir, block_filter_index: true, peer_block_filters: true)
    for b <- bs, do: {:ok, :connected} = State.submit_block(node.n.chain_state, b)
    State.commit_now(node.n.chain_state)
    :ok = Index.sync_to(node.n.filter_index, List.last(bs).header.hash)
    %{n: node.n}
  end

  # A peer the node dialed, serving with `services` (default NETWORK |
  # WITNESS | COMPACT_FILTERS), its clock just after `tip_time` (not in IBD).
  defp peer(n, tip_time, services \\ 9 ||| Message.service(:compact_filters)) do
    clock = Clock.new()
    Clock.set(clock, tip_time + 10)

    {pid, sock, ref} =
      FakePeer.connect_from(n,
        node: %{clock: clock, tick_ms: nil, filter_index: n.filter_index, services: services},
        monitor: true
      )

    wait_until(fn -> :sys.get_state(pid).verack_received end)
    {pid, sock, ref}
  end

  defp assert_stopped(ref, reason),
    do: assert_receive({:DOWN, ^ref, :process, _, {:shutdown, ^reason}}, 5_000)

  # Decoded messages the node sent before answering a ping sent now.
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
        m =
          case Message.decode(cmd, payload) do
            {:ok, m} -> m
            _ -> {String.to_atom(cmd), payload}
          end

        collect(sock, nonce, rest, [m | acc])

      _ ->
        {:ok, data} = :gen_tcp.recv(sock, 0, 5_000)
        collect(sock, nonce, buf <> data, acc)
    end
  end

  defp block_item(hash), do: %{type: :block, witness: true, hash: hash}
  defp tip_time(bs), do: List.last(bs).header.time

  describe "getdata" do
    test "a block we do not have, or one off the active chain: notfound", %{n: n, bs: bs} do
      # A competing 150 (equal work: stored, not active).
      fork = BB.build(Enum.at(bs, 148).header, [BB.coinbase(150, 25 * @coin, <<0x52>>)])
      {:ok, _} = State.submit_block(n.chain_state, fork)
      {_pid, sock, _ref} = peer(n, tip_time(bs))

      for hash <- [<<5::256>>, fork.header.hash] do
        :ok = FakePeer.send_msgs(sock, {:getdata, [block_item(hash)]})
        assert {:notfound, [%{hash: ^hash}]} = List.last(before_pong(sock))
      end
    end

    test "NODE_NETWORK_LIMITED: the last 288 (+2) blocks are served, older ones disconnect",
         %{n: n, bs: bs} do
      {extra, _} =
        Enum.map_reduce(151..295, List.last(bs).header, fn h, prev ->
          b = BB.build(prev, [BB.coinbase(h, 25 * @coin)])
          {b, b.header}
        end)

      for b <- extra, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
      State.commit_now(n.chain_state)
      all = bs ++ extra
      limited = Message.service(:network_limited) ||| Message.service(:witness)
      {_pid, sock, ref} = peer(n, List.last(all).header.time, limited)

      # Height 5: 290 below the tip, the edge of the window.
      b5 = Enum.at(all, 4)
      :ok = FakePeer.send_msgs(sock, {:getdata, [block_item(b5.header.hash)]})
      [{"block", raw}] = FakePeer.recv(sock, ["block"], 1)
      assert raw == b5.raw

      :ok = FakePeer.send_msgs(sock, {:getdata, [block_item(Enum.at(all, 3).header.hash)]})
      assert_stopped(ref, :request_below_network_limited_threshold)
    end
  end

  describe "getblocktxn" do
    defp getblocktxn(hash, indexes),
      do: {:getblocktxn, CompactBlock.encode_getblocktxn(hash, indexes)}

    test "a recent block: the requested txs", %{n: n, bs: bs} do
      b = List.last(bs)
      {_pid, sock, _ref} = peer(n, tip_time(bs))
      :ok = FakePeer.send_msgs(sock, getblocktxn(b.header.hash, [0]))
      [{"blocktxn", payload}] = FakePeer.recv(sock, ["blocktxn"], 1)
      {:ok, hash, [tx]} = CompactBlock.decode_blocktxn(payload)
      assert hash == b.header.hash and tx.txid == hd(b.txs).txid
    end

    test "a block 10 deep: the whole block", %{n: n, bs: bs} do
      b = Enum.at(bs, 139)
      {_pid, sock, _ref} = peer(n, tip_time(bs))
      :ok = FakePeer.send_msgs(sock, getblocktxn(b.header.hash, [0]))
      [{"block", raw}] = FakePeer.recv(sock, ["block"], 1)
      assert raw == b.raw
    end

    test "an unknown block: no answer", %{n: n, bs: bs} do
      {pid, sock, _ref} = peer(n, tip_time(bs))
      :ok = FakePeer.send_msgs(sock, getblocktxn(<<5::256>>, [0]))
      refute Enum.any?(before_pong(sock), &match?({k, _} when k in [:blocktxn, :block], &1))
      assert Process.alive?(pid)
    end

    test "an index past the block's txs is misbehaviour", %{n: n, bs: bs} do
      b = List.last(bs)
      {_pid, sock, ref} = peer(n, tip_time(bs))
      :ok = FakePeer.send_msgs(sock, getblocktxn(b.header.hash, [length(b.txs)]))
      assert_stopped(ref, {:misbehaving, "getblocktxn with out-of-bounds tx indices"})
    end
  end

  test "getheaders with a locator over 101 entries disconnects (post-IBD and during IBD)", %{
    n: n,
    bs: bs
  } do
    {_pid, sock, ref} = peer(n, tip_time(bs))
    locator = for i <- 1..(Message.max_locator_sz() + 1), do: <<i::256>>
    :ok = FakePeer.send_msgs(sock, {:getheaders, %{locator: locator, hash_stop: <<0::256>>}})
    assert_stopped(ref, :locator_too_large)

    # During IBD (clock 48 h ahead of tip), oversized getheaders and getblocks still disconnect.
    {_pid2, sock2, ref2} = peer(n, tip_time(bs) + 48 * 3600)
    :ok = FakePeer.send_msgs(sock2, {:getheaders, %{locator: locator, hash_stop: <<0::256>>}})
    assert_stopped(ref2, :locator_too_large)

    {_pid3, sock3, ref3} = peer(n, tip_time(bs))
    cnt = Message.max_locator_sz() + 1

    pl =
      IO.iodata_to_binary([
        <<Message.protocol_version()::little-32>>,
        Exnode.Codec.CompactSize.encode(cnt),
        :binary.copy(<<0>>, cnt * 32 + 32)
      ])

    :ok = :gen_tcp.send(sock3, Frame.encode(@p.magic, "getblocks", pl))
    assert_stopped(ref3, :locator_too_large)
  end

  describe "BIP157" do
    test "a filter type other than basic disconnects", %{n: n, bs: bs} do
      {_pid, sock, ref} = peer(n, tip_time(bs))
      stop = List.last(bs).header.hash

      :ok =
        FakePeer.send_msgs(
          sock,
          {:getcfilters, %{filter_type: 1, start_height: 0, stop_hash: stop}}
        )

      assert_stopped(ref, :unsupported_filter_type)
    end

    test "a start above the stop height disconnects", %{n: n, bs: bs} do
      {_pid, sock, ref} = peer(n, tip_time(bs))
      stop = List.last(bs).header.hash

      :ok =
        FakePeer.send_msgs(
          sock,
          {:getcfilters, %{filter_type: 0, start_height: 151, stop_hash: stop}}
        )

      assert_stopped(ref, :invalid_filter_range)
    end

    test "1,000 or more filters in one getcfilters disconnects; an unindexed range is not answered",
         %{n: n, bs: bs} do
      # 1,000 headers past the indexed chain (heights 151..1150), no blocks.
      headers =
        Stream.iterate(BB.next_header(List.last(bs).header), &BB.next_header/1)
        |> Enum.take(1_000)

      {:ok, _} = Headers.process_headers(n.headers, headers)
      stop = List.last(headers).hash
      {pid, sock, ref} = peer(n, tip_time(bs))

      :ok =
        FakePeer.send_msgs(sock, [
          {:getcfilters, %{filter_type: 0, start_height: 1_100, stop_hash: stop}},
          {:getcfheaders, %{filter_type: 0, start_height: 1_100, stop_hash: stop}},
          {:getcfcheckpt, %{filter_type: 0, stop_hash: stop}}
        ])

      msgs = before_pong(sock)
      refute Enum.any?(msgs, &match?({k, _} when k in [:cfilter, :cfheaders, :cfcheckpt], &1))
      assert Process.alive?(pid)

      :ok =
        FakePeer.send_msgs(
          sock,
          {:getcfilters, %{filter_type: 0, start_height: 150, stop_hash: stop}}
        )

      assert_stopped(ref, :too_many_filters_requested)
    end

    test "getcfheaders from height 0: the previous header is all zeros", %{n: n, bs: bs} do
      {_pid, sock, _ref} = peer(n, tip_time(bs))
      stop = List.last(bs).header.hash

      :ok =
        FakePeer.send_msgs(
          sock,
          {:getcfheaders, %{filter_type: 0, start_height: 0, stop_hash: stop}}
        )

      [{"cfheaders", payload}] = FakePeer.recv(sock, ["cfheaders"], 1)
      # filter type, stop hash, previous header, then the filter hashes
      # (Message only encodes cfheaders).
      <<0, ^stop::binary-32, prev::binary-32, rest::binary>> = payload
      {151, hashes} = Exnode.Codec.CompactSize.decode(rest)
      assert prev == <<0::256>>
      assert byte_size(hashes) == 151 * 32
    end
  end
end
