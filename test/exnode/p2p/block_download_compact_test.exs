defmodule Exnode.P2P.BlockDownloadCompactTest do
  @moduledoc """
  Regression: compact-block requests (`BlockDownload.mark/3`) ignored
  MAX_BLOCKS_IN_TRANSIT_PER_PEER, and a valid block delivered by a peer
  that did not hold the request left the holder's request in flight (its
  slot and byte estimate) until that peer's download timeout. Core
  CMPCTBLOCK calls BlockRequested only while the peer has fewer than 16
  blocks in flight, and ProcessBlock calls `RemoveBlockRequest(hash,
  nullopt)` for a new block whoever sent it. Against stub headers and
  chain-state processes (as `RefillTest`).
  """
  use ExUnit.Case, async: true

  alias Exnode.Chain.HeaderIndex
  alias Exnode.Codec.Header
  alias Exnode.P2P.BlockDownload

  defmodule StubHeaders do
    use GenServer
    def start_link(idx), do: GenServer.start_link(__MODULE__, idx)
    def init(idx), do: {:ok, idx}
    def handle_call(:index, _f, idx), do: {:reply, idx, idx}
  end

  defmodule StubChain do
    use GenServer
    def start_link(tip), do: GenServer.start_link(__MODULE__, tip)
    def init(tip), do: {:ok, tip}
    def handle_call(:tip, _f, tip), do: {:reply, tip, tip}
    def handle_call({:have_many, _}, _f, tip), do: {:reply, MapSet.new(), tip}
  end

  defp chain(n) do
    g = HeaderIndex.make_entry(header(0, <<0::256>>), nil)
    idx = HeaderIndex.insert(HeaderIndex.new(), g)

    {idx, acc} =
      Enum.reduce(1..n, {idx, [g]}, fn h, {idx, [p | _] = acc} ->
        e = HeaderIndex.make_entry(header(h, p.hash), p)
        {HeaderIndex.insert(idx, e), [e | acc]}
      end)

    {idx, Enum.reverse(acc)}
  end

  defp header(h, prev_hash),
    do: %Header{
      version: 1,
      prev_hash: prev_hash,
      merkle_root: <<h::256>>,
      time: h,
      bits: 0x207FFFFF,
      nonce: 0,
      hash: :crypto.hash(:sha256, <<h::32>>),
      raw: <<h::32>>
    }

  defp start(n) do
    {idx, entries} = chain(n)
    {:ok, headers} = StubHeaders.start_link(idx)
    {:ok, chain} = StubChain.start_link(hd(entries))

    {:ok, bd} =
      BlockDownload.start_link(
        headers: headers,
        chain: chain,
        params: %{pow_target_spacing: 600},
        initial_estimate: 1_000
      )

    {bd, entries}
  end

  defp peer, do: spawn(fn -> Process.sleep(:infinity) end)

  test "mark stops at MAX_BLOCKS_IN_TRANSIT_PER_PEER, counting parallel-download requests" do
    {bd, entries} = start(40)
    a = peer()
    picks = BlockDownload.request(bd, a, List.last(entries).hash)
    assert length(picks) == 16

    [h | _] = for e <- entries, e.height > 16, do: e.hash
    refute BlockDownload.mark(bd, a, h)
    assert BlockDownload.mark(bd, a, hd(picks))
    s = BlockDownload.stats(bd)
    assert s.in_flight == 16 and s.bytes == 16 * 1_000

    # Another peer with free slots still can.
    assert BlockDownload.mark(bd, peer(), h)
  end

  test "mark alone fills at most 16 slots" do
    {bd, entries} = start(40)
    a = peer()
    marked = for e <- tl(entries), do: BlockDownload.mark(bd, a, e.hash)
    assert Enum.count(marked, & &1) == 16
    assert BlockDownload.stats(bd).bytes == 16 * 1_000
  end

  test "a valid block from a peer that did not hold the request releases the holder's request" do
    {bd, entries} = start(20)
    a = peer()
    b = peer()
    [h | _] = BlockDownload.request(bd, a, List.last(entries).hash)

    # Garbage from b changes nothing.
    assert BlockDownload.received(bd, b, h, 500)
    BlockDownload.checked(bd, b, h, false)
    assert {^a, _, 1} = BlockDownload.in_flight(bd)[h]

    # A valid copy from b frees a's slot and byte estimate.
    assert BlockDownload.received(bd, b, h, 500)
    BlockDownload.checked(bd, b, h, true)
    s = BlockDownload.stats(bd)
    refute Map.has_key?(BlockDownload.in_flight(bd), h)
    assert s.in_flight == 15 and s.bytes == 15 * 1_000 and s.released_delivered == 1
  end
end
