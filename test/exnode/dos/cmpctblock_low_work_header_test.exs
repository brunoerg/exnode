defmodule Exnode.DoS.CmpctblockLowWorkHeaderTest do
  @moduledoc """
  Regression: a `cmpctblock` header is checked against
  Core's anti-DoS work threshold before `Headers.process_headers`
  (net_processing.cpp "Ignoring low-work compact block"). Before the fix,
  low-work headers forking from genesis were stored (ETS + RocksDB) one per
  ~200-byte message, while the same headers in a `headers` message were
  refused by the low-work gate.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.P2P.CompactBlock
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @k 200

  # Regtest: tip 150, threshold = tip work - 144 proofs = 14; a header at
  # height 1-5 off genesis has less work than that (2 per header).
  defp fork_from_genesis(k, salt) do
    g = Exnode.ChainParams.get(:regtest).genesis.header

    {hs, _} =
      Enum.map_reduce(1..k, g, fn _, prev ->
        h = BB.next_header(prev, merkle_root: <<salt::256>>)
        {h, h}
      end)

    hs
  end

  # `k` distinct low-work siblings at height 1 (any number of these exist).
  defp siblings(k) do
    g = Exnode.ChainParams.get(:regtest).genesis.header
    for i <- 1..k, do: BB.next_header(g, merkle_root: <<1_000_000 + i::256>>)
  end

  test "low-work headers are stored neither via headers nor via cmpctblock", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)

    for raw <- BB.read_chain(@chain),
        do:
          {:ok, :connected} = State.submit_block(n.chain_state, elem(Block.decode_exact(raw), 1))

    size = fn -> HeaderIndex.size(Headers.index(n.headers)) end
    base = size.()

    mem = fn ->
      idx = Headers.index(n.headers)
      :ets.info(idx.entries, :memory) * :erlang.system_info(:wordsize)
    end

    mem0 = mem.()

    # Control: a low-work fork in a `headers` message is ignored (TryLowWorkHeadersSync).
    {_p1, s1} = FakePeer.connect_from(n)
    :ok = FakePeer.send_msgs(s1, [{:headers, fork_from_genesis(5, 1)}, {:ping, 1}])
    FakePeer.recv(s1, ["pong"], 1)
    assert size.() == base

    cb = BB.coinbase(1, 50)

    {p2, s2} =
      FakePeer.connect_from(n, after_handshake: [{:sendcmpct, %{announce: false, version: 2}}])

    msgs =
      for h <- siblings(@k),
          do:
            {:cmpctblock,
             CompactBlock.encode(%CompactBlock{
               header: h,
               nonce: 0,
               short_ids: [],
               prefilled: [{0, cb}]
             })}

    bytes = msgs |> Enum.map(fn {_, p} -> byte_size(p) + 24 end) |> Enum.sum()
    :ok = FakePeer.send_msgs(s2, msgs ++ [{:ping, 2}])
    FakePeer.recv(s2, ["pong"], 1)

    grown = size.() - base

    IO.puts(
      "cmpctblock low-work spam: #{@k} msgs (#{bytes} B) -> #{grown} new header entries stored, entries ETS +#{mem.() - mem0} B; peer alive: #{Process.alive?(p2)}"
    )

    assert grown == 0
    assert Process.alive?(p2)
  end
end
