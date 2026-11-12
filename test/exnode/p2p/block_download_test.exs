defmodule Exnode.P2P.BlockDownloadTest do
  @moduledoc """
  `BlockDownload.request/3` (Core `FindNextBlocksToDownload`), with stub
  headers and chain-state processes:
  * blocks we already hold are never picked, wherever they are in the window;
  * picks are the lowest-height blocks not held and not in flight, at most 16;
  * only as many candidates are checked as needed to pick them, not the whole
    1,024-block window (each check may be a disk read, and every peer waits
    on this process).
  """
  use ExUnit.Case, async: true

  alias Exnode.Chain.HeaderIndex
  alias Exnode.Codec.Header
  alias Exnode.P2P.BlockDownload

  # Stands in for Chain.Headers: replies with the index.
  defmodule StubHeaders do
    use GenServer
    def start_link(idx), do: GenServer.start_link(__MODULE__, idx)
    def init(idx), do: {:ok, idx}
    def handle_call(:index, _f, idx), do: {:reply, idx, idx}
  end

  # Stands in for Chain.State: a fixed tip, a set of held blocks, and it
  # reports how many hashes each have_many call checked.
  defmodule StubChain do
    use GenServer
    def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
    def init({test, tip, held}), do: {:ok, %{test: test, tip: tip, held: held}}
    def handle_call(:tip, _f, st), do: {:reply, st.tip, st}

    def handle_call({:have_many, hashes}, _f, st) do
      send(st.test, {:checked, length(hashes)})
      {:reply, hashes |> Enum.filter(&MapSet.member?(st.held, &1)) |> MapSet.new(), st}
    end
  end

  # A header chain of `n` blocks above genesis, in the test-owned index.
  defp chain(n) do
    idx = HeaderIndex.new()

    {idx, entries} =
      Enum.reduce(0..n, {idx, []}, fn h, {idx, acc} ->
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

    {idx, Enum.reverse(entries)}
  end

  defp start(entries, idx, held_heights) do
    held = MapSet.new(held_heights, &Enum.at(entries, &1).hash)
    {:ok, headers} = StubHeaders.start_link(idx)
    {:ok, chain} = StubChain.start_link({self(), hd(entries), held})

    {:ok, bd} =
      BlockDownload.start_link(headers: headers, chain: chain, params: %{pow_target_spacing: 600})

    bd
  end

  defp checked(acc \\ 0) do
    receive do
      {:checked, n} -> checked(acc + n)
    after
      0 -> acc
    end
  end

  defp heights(entries, hashes) do
    by_hash = Map.new(entries, &{&1.hash, &1.height})
    Enum.map(hashes, &by_hash[&1])
  end

  test "picks the 16 lowest blocks not held, checking only as many as needed" do
    {idx, entries} = chain(2_000)
    # Held: a run at the start of the window and scattered ones after it.
    bd = start(entries, idx, Enum.to_list(1..20) ++ [25, 30, 31])
    best = List.last(entries)

    picked = BlockDownload.request(bd, self(), best.hash)
    assert heights(entries, picked) == Enum.to_list(21..39) -- [25, 30, 31]
    # 39 candidates hold the 16 picks: 3 chunks of 16, not the 1,024 window.
    assert checked() == 48

    # The next request starts after the blocks now in flight, for another peer.
    peer2 = spawn(fn -> Process.sleep(:infinity) end)
    picked2 = BlockDownload.request(bd, peer2, best.hash)
    assert heights(entries, picked2) == Enum.to_list(40..55)
    # The 23 held blocks are still in the window (not connected here), so they
    # are checked again: 23 + 16 picks = 39, again 3 chunks.
    assert checked() == 48
  end

  test "received: says whether the block was in flight, and removes it" do
    {idx, entries} = chain(100)
    bd = start(entries, idx, [])
    [h | _] = BlockDownload.request(bd, self(), List.last(entries).hash)
    other = Enum.at(entries, 90).hash

    # Core IsBlockRequested then RemoveBlockRequest: true once, then false.
    assert BlockDownload.received(bd, self(), h) == true
    assert BlockDownload.received(bd, self(), h) == false
    refute Map.has_key?(BlockDownload.in_flight(bd), h)
    # Never requested (height 90 is beyond the 16 picked).
    assert BlockDownload.received(bd, self(), other) == false
  end

  test "held blocks are never picked, even when most of the window is held" do
    {idx, entries} = chain(1_100)
    bd = start(entries, idx, Enum.to_list(1..1_000))
    picked = BlockDownload.request(bd, self(), List.last(entries).hash)
    # The window ends at 1,024 above the fork: 24 blocks left, 16 picked.
    assert heights(entries, picked) == Enum.to_list(1_001..1_016)
  end
end
