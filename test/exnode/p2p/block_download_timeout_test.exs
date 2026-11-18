defmodule Exnode.P2P.BlockDownloadTimeoutTest do
  @moduledoc """
  BlockDownload's network timeouts on a mock clock (`Exnode.Clock`), run by
  explicit ticks:

  * download timeout (Core `BLOCK_DOWNLOAD_TIMEOUT_BASE` 1 and `_PER_PEER`
    0.5 target spacings): a block requested and not delivered within the
    limit disconnects its peer and frees its requests;
  * stalling (Core `BLOCK_STALLING_TIMEOUT_DEFAULT` 2 s, `m_stalling_since`):
    the peer holding the window's first block in transit, once a peer with
    nothing in flight has run out of window, is disconnected when that mark
    is older than the stall timeout, whatever its own state (audit
    2026-11-11, F1); a block it delivers clears the mark;
  * preferred download: in IBD an inbound peer gets blocks only while no
    outbound peer is connected or nothing is in flight.
  """
  use ExUnit.Case, async: true
  import Bitwise

  alias Exnode.Chain.HeaderIndex
  alias Exnode.Clock
  alias Exnode.Codec.Header
  alias Exnode.P2P.BlockDownload

  defmodule StubHeaders do
    use GenServer
    def init(idx), do: {:ok, idx}
    def handle_call(:index, _f, idx), do: {:reply, idx, idx}
  end

  defmodule StubChain do
    use GenServer
    def init(tip), do: {:ok, tip}
    def handle_call(:tip, _f, tip), do: {:reply, tip, tip}
    def handle_call({:have_many, _}, _f, tip), do: {:reply, MapSet.new(), tip}
  end

  # A header chain of `n` + 1 entries (genesis first), held by the stubs.
  defp start(n, opts \\ []) do
    {idx, entries} =
      Enum.reduce(0..n, {HeaderIndex.new(), []}, fn h, {idx, acc} ->
        prev = List.first(acc)

        hdr = %Header{
          version: 1,
          prev_hash: (prev && prev.hash) || <<0::256>>,
          merkle_root: <<h::256>>,
          time: h,
          bits: 0x207FFFFF,
          nonce: 0,
          hash: :crypto.hash(:sha256, <<h::32>>),
          raw: <<h::32>>
        }

        e = HeaderIndex.make_entry(hdr, prev)
        {HeaderIndex.insert(idx, e), [e | acc]}
      end)

    entries = Enum.reverse(entries)
    {:ok, headers} = GenServer.start_link(StubHeaders, idx)
    {:ok, chain} = GenServer.start_link(StubChain, hd(entries))
    # Frozen from the start: request times and ticks see exact offsets.
    clock = Clock.new()
    Clock.advance(clock, 0)

    {:ok, bd} =
      BlockDownload.start_link(
        [headers: headers, chain: chain, params: %{pow_target_spacing: 600}, clock: clock] ++
          opts
      )

    %{bd: bd, clock: clock, best: List.last(entries).hash}
  end

  # A stand-in peer process that forwards what it is sent to the test.
  defp peer do
    test = self()

    spawn_link(fn ->
      Stream.repeatedly(fn -> receive do: (m -> send(test, {self(), m})) end) |> Stream.run()
    end)
  end

  test "a block not delivered within 10 minutes (one peer downloading) disconnects its peer" do
    %{bd: bd, clock: c, best: best} = start(20)
    p = peer()
    assert [_ | _] = BlockDownload.request(bd, p, best)

    Clock.advance(c, 600)
    :ok = Clock.tick(bd)
    refute_received {^p, {:disconnect, _}}

    Clock.advance(c, 1)
    :ok = Clock.tick(bd)
    assert_receive {^p, {:disconnect, :block_download_timeout}}
    assert BlockDownload.in_flight(bd) == %{}
  end

  test "the peer holding the window's lowest block stalls the others: disconnected after 2 s" do
    # 2,000 blocks: a 1,024-block window, 16 requests per peer (no byte
    # budget in the way: the window is what runs out).
    %{bd: bd, clock: c, best: best} = start(2_000, max_bytes: 1 <<< 40)
    staller = peer()
    picked = BlockDownload.request(bd, staller, best)
    assert length(picked) == 16

    # Other peers take the rest of the window; the next finds nothing left.
    others = for _ <- 1..63, do: peer()
    for o <- others, do: assert(length(BlockDownload.request(bd, o, best)) == 16)
    blocked = peer()
    assert BlockDownload.request(bd, blocked, best) == []

    # At the stall timeout (not past it): nobody is disconnected.
    Clock.advance(c, 2)
    :ok = Clock.tick(bd)
    refute_received {_, {:disconnect, _}}

    Clock.advance(c, 1)
    :ok = Clock.tick(bd)
    assert_receive {^staller, {:disconnect, :block_stalling}}
    refute_received {_, {:disconnect, _}}
  end

  # Fills the rest of the 1,024-block window after `first` took 16: 63 more
  # peers with 16 requests each.
  defp fill_window(bd, best) do
    others = for _ <- 1..63, do: peer()
    for o <- others, do: assert(length(BlockDownload.request(bd, o, best)) == 16)
    others
  end

  test "F1: a staller that is itself window-blocked (free slots, one block withheld) is still disconnected" do
    %{bd: bd, clock: c, best: best} = start(2_000, max_bytes: 1 <<< 40)
    staller = peer()
    [first | rest] = BlockDownload.request(bd, staller, best)
    fill_window(bd, best)

    # The staller delivers all but the window's first block, then asks for
    # more with 15 free slots and finds nothing: it is window-blocked too.
    for h <- rest, do: assert(BlockDownload.received(bd, staller, h, 1))
    assert BlockDownload.request(bd, staller, best) == []

    blocked = peer()
    assert BlockDownload.request(bd, blocked, best) == []

    for _ <- 1..2 do
      Clock.advance(c, 1)
      :ok = Clock.tick(bd)
    end

    refute_received {_, {:disconnect, _}}
    Clock.advance(c, 1)
    :ok = Clock.tick(bd)
    assert_receive {^staller, {:disconnect, :block_stalling}}
    refute_received {_, {:disconnect, _}}
    assert BlockDownload.stats(bd).stallers == 1

    # The withheld block is selectable again, by the peer that was blocked.
    refute Map.has_key?(BlockDownload.in_flight(bd), first)
    assert first in BlockDownload.request(bd, blocked, best)
  end

  test "a requested block delivered by the staller clears its stalling mark" do
    %{bd: bd, clock: c, best: best} = start(2_000, max_bytes: 1 <<< 40)
    staller = peer()
    [_first, second | _] = BlockDownload.request(bd, staller, best)
    fill_window(bd, best)
    blocked = peer()
    assert BlockDownload.request(bd, blocked, best) == []

    Clock.advance(c, 2)
    assert BlockDownload.received(bd, staller, second, 1)
    Clock.advance(c, 2)
    :ok = Clock.tick(bd)
    refute_received {_, {:disconnect, _}}

    # Marked again from the next empty request; disconnected 2 s after that.
    assert BlockDownload.request(bd, blocked, best) == []
    Clock.advance(c, 3)
    :ok = Clock.tick(bd)
    assert_receive {^staller, {:disconnect, :block_stalling}}
  end

  test "a peer that still has blocks in flight does not mark a staller" do
    %{bd: bd, clock: c, best: best} = start(2_000, max_bytes: 1 <<< 40)
    staller = peer()
    assert length(BlockDownload.request(bd, staller, best)) == 16
    [o | _] = fill_window(bd, best)

    # `o` has 15 in flight and a free slot, and finds nothing.
    [h | _] = Map.keys(Map.filter(BlockDownload.in_flight(bd), fn {_, {p, _, _}} -> p == o end))
    assert BlockDownload.received(bd, o, h, 1)
    assert BlockDownload.request(bd, o, best) == []

    Clock.advance(c, 10)
    :ok = Clock.tick(bd)
    refute_received {_, {:disconnect, _}}
  end

  test "in IBD an inbound peer gets blocks only with no outbound peer or nothing in flight" do
    %{bd: bd, best: best} = start(100)
    inbound = peer()
    ibd = [preferred: false, ibd: true]

    # An outbound peer registered (no best header yet), nothing in flight.
    out = peer()
    assert BlockDownload.request(bd, out, nil) == []
    assert [_ | _] = BlockDownload.request(bd, inbound, best, ibd)

    # Something in flight and an outbound peer connected: none for inbound,
    # unless out of IBD.
    assert [_ | _] = BlockDownload.request(bd, out, best)
    assert BlockDownload.request(bd, peer(), best, ibd) == []
    assert [_ | _] = BlockDownload.request(bd, peer(), best, preferred: false, ibd: false)

    # The outbound peer gone: inbound peers are used again.
    ref = Process.monitor(out)
    Process.unlink(out)
    Process.exit(out, :kill)
    assert_receive {:DOWN, ^ref, _, _, _}
    # Three inbound peers remain registered once `out` is gone.
    Exnode.Test.Wait.wait_until(fn -> BlockDownload.stats(bd).peers == 3 end)
    assert [_ | _] = BlockDownload.request(bd, peer(), best, ibd)
  end

  # Regression: every delivered block decayed the stall
  # timeout ×0.85, so five deliveries undid a doubling while the window's
  # first block was still missing and slow honest holders were dropped
  # every ~2 s. Core decays it only in BlockConnected.
  test "the doubled stall timeout holds while blocks are delivered but none connects; a connect decays it" do
    %{bd: bd, clock: c, best: best} = start(2_000, max_bytes: 1 <<< 40)
    s1 = peer()
    assert length(BlockDownload.request(bd, s1, best)) == 16
    others = fill_window(bd, best)
    p = peer()
    assert BlockDownload.request(bd, p, best) == []
    Clock.advance(c, 3)
    :ok = Clock.tick(bd)
    assert_receive {^s1, {:disconnect, :block_stalling}}

    # The timeout is 4 s now. p takes s1's released blocks (the window's first).
    assert length(BlockDownload.request(bd, p, best)) == 16
    r = peer()
    assert BlockDownload.request(bd, r, best) == []
    inflight = BlockDownload.in_flight(bd)

    for o <- Enum.take(others, 5) do
      {h, _} = Enum.find(inflight, fn {_, {q, _, _}} -> q == o end)
      assert BlockDownload.received(bd, o, h, 1)
    end

    Clock.advance(c, 3)
    :ok = Clock.tick(bd)
    refute_received {^p, {:disconnect, :block_stalling}}

    # Five connected blocks: 4000 → 3400 → 2890 → 2457 → 2088 → 2000.
    for i <- 1..5, do: send(bd, {:block_connected, <<i::256>>, i})
    Clock.advance(c, 0)
    :ok = Clock.tick(bd)
    assert_receive {^p, {:disconnect, :block_stalling}}
  end
end
