defmodule Exnode.DoS.UnsolicitedCmpctblockTest do
  @moduledoc """
  Regression: reconstructing a compact block costs a pass
  over the whole mempool (`Mempool.match_short_ids`, a SipHash of every
  mempool wtxid inside the single Mempool GenServer). Before the fix any
  peer could trigger it again and again with a ~200-byte message. As in
  Core, a `cmpctblock` from a peer we never selected as high-bandwidth, for
  a block we never requested from it, is now ignored before InitData ("not
  marked as high-bandwidth, sent us an unsolicited compact block",
  net_processing.cpp), and a high-bandwidth peer's resend of a block already
  being rebuilt is ignored too.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.P2P.CompactBlock
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @msgs 50

  defmodule CountingMempool do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call({:match_short_ids, _keys, wanted}, _f, test) do
      send(test, {:scan, length(wanted)})
      {:reply, %{}, test}
    end

    def handle_call(_, _f, test), do: {:reply, nil, test}
  end

  test "an unsolicited cmpctblock is ignored; a high-bandwidth peer's costs one scan per block",
       %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    # The next block's header is known (announced by the network), its body not yet held.
    b151 = BB.build(List.last(bs).header, [BB.coinbase(151, 25 * 100_000_000)])
    {:ok, _} = Headers.process_headers(n.headers, [b151.header])

    {:ok, mp} = CountingMempool.start_link(self())
    # The tip is recent: Core's CanDirectFetch holds.
    clock = Exnode.Clock.new()
    Exnode.Clock.set(clock, List.last(bs).header.time + 10)

    {pid, sock} =
      FakePeer.connect_from(n,
        node: %{mempool: mp, clock: clock},
        after_handshake: [{:sendcmpct, %{announce: false, version: 2}}]
      )

    junk = BB.coinbase(999, 1)

    msgs =
      for i <- 1..@msgs,
          do:
            {:cmpctblock,
             CompactBlock.encode(%CompactBlock{
               header: b151.header,
               nonce: i,
               short_ids: [12_345],
               prefilled: [{0, junk}]
             })}

    :ok = FakePeer.send_msgs(sock, msgs ++ [{:ping, 7}])
    FakePeer.recv(sock, ["pong"], 1)
    unsolicited = count_scans(0)

    # Selected as high-bandwidth (HighBandwidth's sendcmpct announce = true).
    send(pid, {:send, {:sendcmpct, %{announce: true, version: 2}}})
    :ok = FakePeer.send_msgs(sock, msgs ++ [{:ping, 8}])
    FakePeer.recv(sock, ["pong"], 1)
    hb = count_scans(0)

    IO.puts(
      "cmpctblock: #{@msgs} msgs from a non-HB peer -> #{unsolicited} mempool scans; #{@msgs} from an HB peer -> #{hb}"
    )

    assert unsolicited == 0
    assert hb == 1
    assert Process.alive?(pid)
  end

  defp count_scans(acc) do
    receive do
      {:scan, _} -> count_scans(acc + 1)
    after
      200 -> acc
    end
  end
end
