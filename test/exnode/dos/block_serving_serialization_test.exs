defmodule Exnode.DoS.BlockServingSerializationTest do
  @moduledoc """
  Regression: every block-serving request goes through the
  one BlockServing GenServer. A cache miss used to be built inside it
  (Archive.read_block -> reconstruct: rebuild, encode, decode, merkle and
  witness-root re-check; :stripped / :compact decode again), so a cache hit
  from another peer waited behind all queued misses. Misses now build in
  worker processes (bounded, near-tip requests first): hits answer at once
  and misses run in parallel.

  A miss's decode is injected (the existing `decode_block` hook) and held
  until the test releases it, so the topology is shown without large
  blocks and without timing; a third test measures
  the reconstruct-like CPU (encode + decode + merkle + witness root) of a
  ~1 MB block as a lower bound of the real per-miss cost.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Chain.State
  alias Exnode.Codec.Block
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Validation.Block, as: BlockRules

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  # A miss's decode that reports it started and waits for the test to
  # release it: builders are held busy exactly as long as the test needs, so
  # nothing depends on how long a decode takes here.
  defp gated(test) do
    fn raw ->
      send(test, {:building, self()})

      receive do
        :release -> Block.decode_exact(raw)
      after
        60_000 -> Block.decode_exact(raw)
      end
    end
  end

  # The `k` builders now held in `gated/1`.
  defp building(k), do: for(_ <- 1..k//1, do: assert_receive({:building, pid}, 5_000) && pid)

  # Releases the next `k` builds as each starts (queued ones start as
  # builders free up).
  defp release_next(k),
    do: for(_ <- 1..k//1, do: assert_receive({:building, pid}, 5_000) && send(pid, :release))

  defp queued(serving), do: :queue.len(:sys.get_state(serving).queue)

  test "a cache hit for an honest peer does not wait behind other peers' misses", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    tip = List.last(bs).header.hash

    {_h, honest} = FakePeer.connect_from(n)
    FakePeer.recv(honest, ["verack"], 1)
    # Warm the cache for the tip (witness form).
    :ok = FakePeer.send_msgs(honest, {:getdata, [%{type: :block, witness: true, hash: tip}]})
    FakePeer.recv(honest, ["block"], 1)

    attackers =
      for i <- 1..6 do
        {_p, s} = FakePeer.connect_from(n, node: %{decode_block: gated(self())})
        FakePeer.recv(s, ["verack"], 1)
        {s, Enum.at(bs, 10 + i).header.hash}
      end

    # Each attacker asks for a distinct old block without witness (a miss, then a decode).
    for {s, h} <- attackers,
        do: :ok = FakePeer.send_msgs(s, {:getdata, [%{type: :block, witness: false, hash: h}]})

    # Built in parallel: every builder (at least 2) holds a miss at once,
    # the rest are queued.
    k = min(6, :sys.get_state(n.block_serving).max_builders)
    assert k >= 2
    held = building(k)
    wait_until(fn -> queued(n.block_serving) == 6 - k end)

    # With every builder busy, the cached block is still served (it used to
    # wait behind all the misses, built inside the server).
    :ok = FakePeer.send_msgs(honest, {:getdata, [%{type: :block, witness: true, hash: tip}]})
    assert [{"block", _}] = FakePeer.recv(honest, ["block"], 1)
    assert Enum.all?(held, &Process.alive?/1)

    # Released, the misses are all served (the queued ones in turn).
    for pid <- held, do: send(pid, :release)
    release_next(6 - k)
    for {s, _} <- attackers, do: FakePeer.recv(s, ["block"], 1)
  end

  test "with every builder busy on old blocks, a near-tip miss skips the queue", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    # One builder: old-block misses run one after another.
    {:ok, serving} = Exnode.P2P.BlockServing.start_link(max_builders: 1)

    attackers =
      for i <- 1..4 do
        {_p, s} =
          FakePeer.connect_from(n, node: %{block_serving: serving, decode_block: gated(self())})

        FakePeer.recv(s, ["verack"], 1)
        {s, Enum.at(bs, 10 + i).header.hash}
      end

    {_h, honest} = FakePeer.connect_from(n, node: %{block_serving: serving})
    FakePeer.recv(honest, ["verack"], 1)

    for {s, h} <- attackers,
        do: :ok = FakePeer.send_msgs(s, {:getdata, [%{type: :block, witness: false, hash: h}]})

    # The one builder holds the first miss; three wait behind it.
    [first] = building(1)
    wait_until(fn -> queued(serving) == 3 end)

    # Block 145: within 10 of the tip, not cached. Served while the builder
    # is still held, so it did not queue behind the old blocks.
    near = Enum.at(bs, 145).header.hash
    :ok = FakePeer.send_msgs(honest, {:getdata, [%{type: :block, witness: false, hash: near}]})
    assert [{"block", _}] = FakePeer.recv(honest, ["block"], 1)
    assert Process.alive?(first) and queued(serving) == 3

    send(first, :release)
    release_next(3)
    for {s, _} <- attackers, do: FakePeer.recv(s, ["block"], 1)
  end

  test "reconstruct-like CPU per miss for a ~1 MB block" do
    g = Exnode.ChainParams.get(:regtest).genesis.header
    spk = <<0, 32, 0::256>>

    txs =
      for i <- 1..2_500 do
        BB.tx(
          [
            {:crypto.hash(:sha256, <<i::32>>), 0,
             witness: [:binary.copy(<<i>>, 72), :binary.copy(<<1>>, 33)]},
            {:crypto.hash(:sha256, <<i::32, 1>>), 1,
             witness: [:binary.copy(<<i>>, 72), :binary.copy(<<1>>, 33)]}
          ],
          [{1000, spk}, {2000, spk}]
        )
      end

    b = BB.build(g, [BB.coinbase(1, 50) | txs])
    raw = IO.iodata_to_binary(Block.encode(b))

    {us, _} =
      :timer.tc(fn ->
        r = IO.iodata_to_binary(Block.encode(b))
        {:ok, d} = Block.decode_exact(r)
        BlockRules.check_merkle_root(d)
        BlockRules.check_witness_malleation(d, false)
        {:ok, d2} = Block.decode_exact(r)
        IO.iodata_to_binary(Block.encode(d2, witness: false))
      end)

    IO.puts(
      "block serving: encode+decode+merkle+witness-root+stripped re-encode of a #{byte_size(raw)} B block: #{div(us, 1000)} ms (excludes record reads and struct rebuild)"
    )

    assert byte_size(raw) > 900_000
  end
end
