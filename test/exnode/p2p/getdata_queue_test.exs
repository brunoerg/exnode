defmodule Exnode.P2P.GetdataQueueTest do
  @moduledoc """
  Getdata items are queued per peer and served as Core's
  ProcessGetData does: per pass the leading tx items, then at most one block;
  further passes run on `:continue_getdata`. While items remain, later
  messages from the peer wait (Core: "this maintains the order of responses
  and prevents m_getdata_requests to grow unbounded"). Blocks are decoded
  only when re-encoded (cmpctblock, no witness), not when the stored bytes
  are forwarded. Plus the O(1) tx lookup for getblocktxn.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Codec.Block
  alias Exnode.P2P.Peer
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  setup %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)
    %{n: n, bs: bs}
  end

  defp connect(n, node \\ %{}),
    do: FakePeer.connect_from(n, node: node, version: %{start_height: 150})

  defp items(bs, heights, witness),
    do:
      for(
        h <- heights,
        do: %{type: :block, witness: witness, hash: Enum.at(bs, h - 1).header.hash}
      )

  test "one block per pass, responses in order, a ping after the getdata answered after the blocks",
       %{n: n, bs: bs} do
    {pid, sock} = connect(n)
    _ = FakePeer.recv(sock, ["verack"], 1)
    :erlang.trace(pid, true, [:receive])
    heights = Enum.to_list(100..109)
    :ok = FakePeer.send_msgs(sock, [{:getdata, items(bs, heights, true)}, {:ping, 4242}])

    got = FakePeer.recv(sock, ["block", "pong"], 11)
    # Ten blocks, in request order, then the pong (Core keeps responses in order).
    assert Enum.map(got, &elem(&1, 0)) == List.duplicate("block", 10) ++ ["pong"]
    assert for({"block", raw} <- got, do: raw) == for(h <- heights, do: Enum.at(bs, h - 1).raw)
    assert {"pong", <<4242::little-64>>} = List.last(got)

    # Ten passes: the first on the getdata, nine on :continue_getdata.
    passes = count_continue(pid)
    :erlang.trace(pid, false, [:receive])
    assert passes == 9
  end

  defp count_continue(pid, n \\ 0) do
    receive do
      {:trace, ^pid, :receive, :continue_getdata} -> count_continue(pid, n + 1)
      {:trace, ^pid, :receive, _} -> count_continue(pid, n)
    after
      200 -> n
    end
  end

  test "witness blocks are forwarded without decoding; only re-encodes decode", %{n: n, bs: bs} do
    test = self()

    decode = fn raw ->
      send(test, :decoded)
      Block.decode_exact(raw)
    end

    {_pid, sock} = connect(n, %{decode_block: decode})
    _ = FakePeer.recv(sock, ["verack"], 1)

    :ok = FakePeer.send_msgs(sock, [{:getdata, items(bs, [10, 11, 12], true)}])
    _ = FakePeer.recv(sock, ["block"], 3)
    refute_received :decoded

    # Without witness the block is re-encoded, so decoded: once per block.
    :ok = FakePeer.send_msgs(sock, [{:getdata, items(bs, [13, 14], false)}])
    _ = FakePeer.recv(sock, ["block"], 2)
    assert_received :decoded
    assert_received :decoded
    refute_received :decoded
  end

  test "unknown blocks get notfound, still one item per pass", %{n: n, bs: bs} do
    {_pid, sock} = connect(n)
    _ = FakePeer.recv(sock, ["verack"], 1)
    unknown = %{type: :block, witness: true, hash: :crypto.hash(:sha256, "nope")}
    :ok = FakePeer.send_msgs(sock, [{:getdata, [unknown | items(bs, [5], true)]}])
    got = FakePeer.recv(sock, ["notfound", "block"], 2)
    assert Enum.map(got, &elem(&1, 0)) == ["notfound", "block"]
  end

  test "repeated compact and stripped requests share one build, across peers", %{n: n, bs: bs} do
    test = self()

    decode = fn raw ->
      send(test, :cache_decode)
      Block.decode_exact(raw)
    end

    {_, sock} = connect(n, %{decode_block: decode})
    _ = FakePeer.recv(sock, ["verack"], 1)
    hash = List.last(bs).header.hash
    compact = %{type: :cmpct_block, hash: hash}
    stripped = %{type: :block, witness: false, hash: hash}

    :ok =
      FakePeer.send_msgs(
        sock,
        {:getdata, List.duplicate(compact, 20) ++ List.duplicate(stripped, 20)}
      )

    got = FakePeer.recv(sock, ["cmpctblock", "block"], 40)
    assert got |> Enum.take(20) |> Enum.uniq() |> length() == 1
    assert got |> Enum.drop(20) |> Enum.uniq() |> length() == 1
    assert_received :cache_decode
    assert_received :cache_decode
    refute_received :cache_decode

    {_, sock2} = connect(n, %{decode_block: decode})
    _ = FakePeer.recv(sock2, ["verack"], 1)
    :ok = FakePeer.send_msgs(sock2, {:getdata, [compact, stripped]})
    assert FakePeer.recv(sock2, ["cmpctblock", "block"], 2) == [hd(got), List.last(got)]
    refute_received :cache_decode

    # Historical requests may churn the general LRU, but cannot evict the
    # recent compact responses and re-enable the small-request CPU attack.
    :ok = FakePeer.send_msgs(sock2, {:getdata, items(bs, Enum.to_list(1..20), true)})
    _ = FakePeer.recv(sock2, ["block"], 20)
    :ok = FakePeer.send_msgs(sock2, {:getdata, [compact]})
    assert [hd(got)] == FakePeer.recv(sock2, ["cmpctblock"], 1)
    refute_received :cache_decode

    # A cache hit never authorizes serving a disconnected block.
    prev = Enum.at(bs, -2).header
    fork = BB.build(prev, [BB.coinbase(150, 25 * 100_000_000, <<0x52>>)])
    child = BB.build(fork.header, [BB.coinbase(151, 25 * 100_000_000)])
    State.submit_block(n.chain_state, fork)
    assert {:ok, :connected} = State.submit_block(n.chain_state, child)
    :ok = FakePeer.send_msgs(sock, {:getdata, [compact]})
    assert [{"notfound", _}] = FakePeer.recv(sock, ["notfound", "cmpctblock"], 1)
  end

  test "the shared response cache is bounded by bytes and entry count", %{n: n, bs: bs} do
    bytes = byte_size(hd(bs).raw) * 3
    cache = start_supervised!({Exnode.P2P.BlockServing, max_entries: 2, max_bytes: bytes})
    reader = State.reader(n.chain_state)

    for b <- Enum.take(bs, 10) do
      id = Exnode.Archive.block_id(reader, b.header.hash)

      assert {:ok, {:block, raw}} =
               Exnode.P2P.BlockServing.get(cache, reader, id, b.header.hash, :witness)

      assert raw == b.raw
      st = :sys.get_state(cache)
      assert st.bytes <= bytes
      assert map_size(st.entries) <= 2
    end
  end

  test "select_txs: 16k indexes into a 16k-tx block in linear time" do
    txs = Enum.to_list(1..16_384)
    idx = Enum.shuffle(0..16_383)
    {us, got} = :timer.tc(fn -> Peer.select_txs(txs, idx) end)
    assert got == Enum.map(idx, &(&1 + 1))
    assert us < 2_000_000
  end
end
