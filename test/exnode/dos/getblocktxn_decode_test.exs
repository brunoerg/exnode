defmodule Exnode.DoS.GetblocktxnDecodeTest do
  @moduledoc """
  Regression: `getblocktxn` indexes are `uint16_t` in Core
  (blockencodings.h, DifferenceFormatter throws once an index passes 65535).
  Before the fix one 3 MB message decoded into a list of millions of
  integers (~126 MB) in the peer process and was then silently ignored.
  Now such a payload is refused before anything is built, and an empty
  index list disconnects, as in Core.

  Regression (found by fuzzamoto): a payload shorter than the block hash
  matched no clause of `decode_getblocktxn/1`, so the peer process crashed.
  Such a payload, like an index overflow, fails Core's deserialization: the
  message is dropped and the peer kept (it used to be misbehaviour).

  Regression: a getblocktxn for a block within 10 of the tip decoded the
  whole block in the peer process, outside the DecodeBudget (the request is
  34 bytes). ~190 peers asking for the coinbase of a recent block at once
  each held the decoded block, several times its size: tens of MB each, a
  remote OOM. The txs are now sliced from the stored bytes by their extents
  (`Block.tx_ranges/1`): nothing is decoded.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Chain.State
  alias Exnode.Codec.{Block, CompactSize}
  alias Exnode.Clock
  alias Exnode.P2P.CompactBlock
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  @n 3_000_000

  defp payload(n, diffs),
    do:
      <<:crypto.strong_rand_bytes(32)::binary, IO.iodata_to_binary(CompactSize.encode(n))::binary,
        diffs::binary>>

  test "decode refuses a count or an index beyond uint16" do
    # 3M zero diffs: the count alone is over the bound.
    assert {:error, :malformed} =
             CompactBlock.decode_getblocktxn(payload(@n, :binary.copy(<<0>>, @n)))

    # 65,537 indexes would need index 65,536.
    assert {:error, :malformed} =
             CompactBlock.decode_getblocktxn(payload(65_537, :binary.copy(<<0>>, 65_537)))

    # A single index past 65,535.
    big = IO.iodata_to_binary(CompactSize.encode(65_536))
    assert {:error, :malformed} = CompactBlock.decode_getblocktxn(payload(1, big))

    # The bounds themselves still decode.
    {:ok, _, idx} = CompactBlock.decode_getblocktxn(payload(65_536, :binary.copy(<<0>>, 65_536)))
    assert length(idx) == 65_536 and List.last(idx) == 65_535
    top = IO.iodata_to_binary(CompactSize.encode(65_535))
    assert {:ok, _, [65_535]} = CompactBlock.decode_getblocktxn(payload(1, top))
  end

  # The fuzzer's payload: 15 bytes, no room for the 32-byte block hash.
  @short "***888x#c8c888x"

  test "decode refuses a payload shorter than the block hash" do
    for p <- [<<>>, @short, :binary.copy(<<0>>, 31)] do
      assert CompactBlock.decode_getblocktxn(p) == {:error, :malformed}
    end
  end

  test "a getblocktxn shorter than the block hash is dropped, not a crash", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    {pid, sock} = FakePeer.connect_from(n)
    FakePeer.recv(sock, ["verack"], 1)
    ref = Process.monitor(pid)
    :ok = FakePeer.send_msgs(sock, [{:getblocktxn, @short}, {:ping, 1}])
    FakePeer.recv(sock, ["pong"], 1)
    refute_received {:DOWN, ^ref, _, _, _}
    assert Process.alive?(pid)
  end

  test "an oversized getblocktxn costs no memory spike and is dropped; an empty one disconnects",
       %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    {pid, sock} = FakePeer.connect_from(n)
    FakePeer.recv(sock, ["verack"], 1)

    test = self()
    sampler = spawn(fn -> sample(pid, 0, test) end)
    ref = Process.monitor(pid)

    :ok =
      FakePeer.send_msgs(sock, [{:getblocktxn, payload(@n, :binary.copy(<<0>>, @n))}, {:ping, 1}])

    FakePeer.recv(sock, ["pong"], 1)
    refute_received {:DOWN, ^ref, _, _, _}
    send(sampler, :stop)
    assert_receive {:peak, peak}, 2_000
    IO.puts("peer process peak memory on a 3 MB getblocktxn: #{div(peak, 1_000_000)} MB")
    assert peak < 40_000_000

    {pid2, sock2} = FakePeer.connect_from(n)
    FakePeer.recv(sock2, ["verack"], 1)
    ref2 = Process.monitor(pid2)
    :ok = FakePeer.send_msgs(sock2, [{:getblocktxn, payload(0, <<>>)}])
    assert_receive {:DOWN, ^ref2, _, _, {:shutdown, :empty_getblocktxn}}, 5_000
  end

  # ~110k empty outputs: a ~1 MB block that decodes to ~11 MB.
  @outputs 110_000

  test "getblocktxn for a recent block does not decode it in the peer", %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    %{n: n} = TestNode.start(dir)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    cb1 = hd(hd(bs).txs)
    fan = BB.tx([{cb1.txid, 0}], List.duplicate({0, <<>>}, @outputs))
    big = BB.build(List.last(bs).header, [BB.coinbase(151, 25 * @coin), fan])
    {:ok, :connected} = State.submit_block(n.chain_state, big)
    State.commit_now(n.chain_state)
    assert byte_size(big.raw) > 900_000

    peers =
      for _ <- 1..4 do
        clock = Clock.new()
        Clock.set(clock, big.header.time + 10)
        {pid, sock} = FakePeer.connect_from(n, node: %{clock: clock, tick_ms: nil})
        FakePeer.recv(sock, ["verack"], 1)
        {pid, sock}
      end

    test = self()
    samplers = for {pid, _} <- peers, do: spawn(fn -> sample(pid, 0, test) end)
    req = {:getblocktxn, CompactBlock.encode_getblocktxn(big.header.hash, [0])}

    for {_, sock} <- peers,
        do: :ok = FakePeer.send_msgs(sock, List.duplicate(req, 20))

    for {_, sock} <- peers do
      replies = FakePeer.recv(sock, ["blocktxn"], 20)
      assert length(replies) == 20

      for {"blocktxn", payload} <- replies do
        {:ok, hash, [tx]} = CompactBlock.decode_blocktxn(payload)
        assert hash == big.header.hash and tx.txid == hd(big.txs).txid
      end
    end

    for s <- samplers, do: send(s, :stop)

    peaks =
      for _ <- samplers do
        assert_receive {:peak, peak}, 2_000
        peak
      end

    IO.puts(
      "peer peaks serving getblocktxn of a 1 MB block: #{inspect(Enum.map(peaks, &div(&1, 1_000)), charlists: :as_lists)} KB"
    )

    # A decoded copy of the block alone is ~11 MB.
    assert Enum.max(peaks) < 4_000_000
  end

  defp sample(pid, peak, test) do
    receive do
      :stop -> send(test, {:peak, peak})
    after
      1 ->
        m =
          case :erlang.process_info(pid, :memory) do
            {:memory, m} -> m
            _ -> 0
          end

        sample(pid, max(m, peak), test)
    end
  end
end
