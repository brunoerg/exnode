defmodule Exnode.P2P.PartialLimitsTest do
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Codec.Block
  alias Exnode.P2P.CompactBlock, as: CB
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  test "partial reconstructions are capped, duplicates do not renew them, and timeouts fall back",
       %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    clock = Exnode.Clock.new()
    Exnode.Clock.set(clock, List.last(bs).header.time + 10)
    {pid, sock} = FakePeer.connect_from(n, node: %{clock: clock})
    _ = FakePeer.recv(sock, ["verack"], 1)
    # Selected as a high-bandwidth peer (HighBandwidth's sendcmpct): only then
    # are its unsolicited compact blocks rebuilt (Core).
    send(pid, {:send, {:sendcmpct, %{announce: true, version: 2}}})
    spend = BB.spend_op_true(hd(hd(bs).txs).txid, 0, 49 * 100_000_000)

    blocks =
      for i <- 1..17 do
        BB.build(List.last(bs).header, [BB.coinbase(151, 25 * 100_000_000, <<i, 0x51>>), spend])
      end

    compact = fn b -> {:cmpctblock, CB.encode(CB.from_block(b, 7))} end

    :ok =
      FakePeer.send_msgs(sock, [
        {:sendcmpct, %{announce: true, version: 2}}
        | Enum.map(Enum.take(blocks, 16), compact)
      ])

    _ = FakePeer.recv(sock, ["getblocktxn"], 16)
    before = :sys.get_state(pid).partials
    assert map_size(before) == 16

    :ok = FakePeer.send_msgs(sock, [compact.(hd(blocks)), {:ping, 81}])
    _ = FakePeer.recv(sock, ["pong"], 1)
    assert :sys.get_state(pid).partials == before
    :ok = FakePeer.send_msgs(sock, compact.(List.last(blocks)))
    assert [{"getdata", _}] = FakePeer.recv(sock, ["getdata"], 1)
    assert map_size(:sys.get_state(pid).partials) == 16

    Exnode.Clock.advance(clock, 61)
    :ok = Exnode.Clock.tick(pid)
    fallbacks = FakePeer.recv(sock, ["getdata"], 16)

    assert Enum.map(fallbacks, fn {"getdata", payload} ->
             {:ok, {:getdata, [item]}} = Exnode.P2P.Message.decode("getdata", payload)
             item.hash
           end)
           |> MapSet.new() == MapSet.new(Map.keys(before))

    assert :sys.get_state(pid).partials == %{}

    # A late blocktxn no longer holds or connects a partial.
    :ok =
      FakePeer.send_msgs(sock, [
        {:blocktxn, CB.encode_blocktxn(hd(blocks).header.hash, [spend])},
        {:ping, 82}
      ])

    _ = FakePeer.recv(sock, ["pong"], 1)
    assert State.tip(n.chain_state).height == 150
    assert Process.alive?(pid)
  end
end
