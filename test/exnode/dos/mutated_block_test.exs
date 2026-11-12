defmodule Exnode.DoS.MutatedBlockTest do
  @moduledoc """
  Regression: a `block` whose header connects to a
  known block but whose body does not match it (Core IsBlockMutated) is
  punished before it reaches block download state or the storage gates,
  as in Core's BLOCK handler. Before the fix a garbage body under a header
  that failed the unrequested-block gates was skipped unpunished, so the
  stream could go on forever.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Chain.State
  alias Exnode.Codec.Block
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  test "a known header with a garbage body is punished as a mutated block", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)

    # An old block's real header (fails the unrequested-block gates) with another body.
    old = Enum.at(bs, 100)
    garbage = %{old | txs: [BB.coinbase(101, 1)]}

    {pid, sock} = FakePeer.connect_from(n)
    FakePeer.recv(sock, ["verack"], 1)
    ref = Process.monitor(pid)
    :ok = FakePeer.send_msgs(sock, {:block, IO.iodata_to_binary(Block.encode(garbage))})
    assert_receive {:DOWN, ^ref, _, _, {:shutdown, {:misbehaving, "mutated block"}}}, 5_000

    # The real block from another peer is still accepted as a duplicate, unpunished.
    {pid2, sock2} = FakePeer.connect_from(n)
    FakePeer.recv(sock2, ["verack"], 1)

    :ok =
      FakePeer.send_msgs(sock2, [{:block, IO.iodata_to_binary(Block.encode(old))}, {:ping, 1}])

    FakePeer.recv(sock2, ["pong"], 1)
    assert Process.alive?(pid2)
  end
end
