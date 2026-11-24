defmodule Exnode.P2P.RefillTest do
  @moduledoc """
  Continuous download refill, against stub headers
  and chain-state processes (as `BlockDownloadTest`), with the test and
  spawned processes as peers:

  * the received→checked gap: a block being checked is never selected again;
    a failed check makes it selectable; garbage from a non-owner changes
    nothing; disconnects release every reservation and byte;
  * cursors follow the peer's best chain and reset on a fork, and below a
    block that is disconnected or fails;
  * the byte budget gates requests, never data, and always lets the
    earliest missing block through;
  * wakeups are coalesced and go only to peers that found nothing;
  * checking reservations are not subject to network timeouts;
  * the best-header height table read from another process stays coherent
    while the writer switches branches.
  """
  use ExUnit.Case, async: true
  import Exnode.Test.Wait

  alias Exnode.Chain.HeaderIndex
  alias Exnode.Codec.Header
  alias Exnode.P2P.BlockDownload

  defmodule StubHeaders do
    use GenServer
    def start_link(idx), do: GenServer.start_link(__MODULE__, idx)
    def init(idx), do: {:ok, idx}
    def handle_call(:index, _f, idx), do: {:reply, idx, idx}
  end

  # A chain state: a fixed tip and a held set the test changes.
  defmodule StubChain do
    use GenServer
    def start_link(tip), do: GenServer.start_link(__MODULE__, tip)
    def init(tip), do: {:ok, %{tip: tip, held: MapSet.new()}}
    def handle_call(:tip, _f, st), do: {:reply, st.tip, st}

    def handle_call({:hold, hs}, _f, st),
      do: {:reply, :ok, %{st | held: MapSet.union(st.held, MapSet.new(hs))}}

    def handle_call({:unhold, h}, _f, st),
      do: {:reply, :ok, %{st | held: MapSet.delete(st.held, h)}}

    def handle_call({:have_many, hashes}, _f, st),
      do: {:reply, hashes |> Enum.filter(&MapSet.member?(st.held, &1)) |> MapSet.new(), st}
  end

  defp header(h, prev_hash, salt),
    do: %Header{
      version: 1,
      prev_hash: prev_hash,
      merkle_root: <<h::256>>,
      time: h,
      bits: 0x207FFFFF,
      nonce: salt,
      hash: :crypto.hash(:sha256, <<h::32, salt::32>>),
      raw: <<h::32, salt::32>>
    }

  # Inserts `n` entries on top of `prev` (salted branch); returns {idx, entries}.
  defp extend(idx, prev, n, salt) do
    {idx, acc} =
      Enum.reduce(1..n//1, {idx, [prev]}, fn _, {idx, [p | _] = acc} ->
        e = HeaderIndex.make_entry(header(p.height + 1, p.hash, salt), p)
        {HeaderIndex.insert(idx, e), [e | acc]}
      end)

    {idx, tl(Enum.reverse(acc))}
  end

  defp chain(n) do
    idx = HeaderIndex.new()
    g = HeaderIndex.make_entry(header(0, <<0::256>>, 0), nil)
    idx = HeaderIndex.insert(idx, g)
    {idx, rest} = extend(idx, g, n, 0)
    {idx, [g | rest]}
  end

  defp start(entries, idx, opts \\ []) do
    {:ok, headers} = StubHeaders.start_link(idx)
    {:ok, chain} = StubChain.start_link(hd(entries))

    {:ok, bd} =
      BlockDownload.start_link(
        [headers: headers, chain: chain, params: %{pow_target_spacing: 600}] ++ opts
      )

    %{bd: bd, chain: chain, headers: headers}
  end

  defp hold(t, hashes), do: GenServer.call(t.chain, {:hold, hashes})

  # A peer process that forwards what it receives to the test.
  defp peer do
    test = self()
    spawn(fn -> forward(test) end)
  end

  defp forward(test) do
    receive do
      m -> send(test, {:to_peer, self(), m}) && forward(test)
    end
  end

  defp heights(entries, hashes) do
    by = Map.new(entries, &{&1.hash, &1.height})
    Enum.map(hashes, &by[&1])
  end

  test "a block being checked is not selected again; a failed check makes it selectable", _ do
    {idx, entries} = chain(40)
    t = start(entries, idx)
    best = List.last(entries).hash
    a = self()
    b = peer()

    picks_a = BlockDownload.request(t.bd, a, best)
    assert heights(entries, picks_a) == Enum.to_list(1..16)
    [h1, h2 | _] = picks_a

    # A receives block 1: it is not held yet (being checked), and B must not pick it.
    assert BlockDownload.received(t.bd, a, h1, 500) == true
    assert BlockDownload.checking(t.bd) |> Map.keys() == [h1]
    picks_b = BlockDownload.request(t.bd, b, best)
    assert heights(entries, picks_b) == Enum.to_list(17..32)
    refute h1 in picks_b

    # Stored: released, and held from now on.
    hold(t, [h1])
    BlockDownload.checked(t.bd, a, h1, true)
    assert BlockDownload.checking(t.bd) == %{}

    # Block 2's check fails: selectable again, from anyone (here C).
    assert BlockDownload.received(t.bd, a, h2, 500)
    BlockDownload.checked(t.bd, a, h2, false)
    c = peer()
    assert heights(entries, BlockDownload.request(t.bd, c, best)) |> hd() == 2

    s = BlockDownload.stats(t.bd)
    assert s.checked_ok == 1 and s.checked_failed == 1 and s.checking == 0
  end

  test "garbage from a non-owner changes nothing; its checked report is a no-op" do
    {idx, entries} = chain(20)
    t = start(entries, idx)
    a = self()
    attacker = peer()
    [h | _] = BlockDownload.request(t.bd, a, List.last(entries).hash)

    assert BlockDownload.received(t.bd, attacker, h, 999) == true
    BlockDownload.checked(t.bd, attacker, h, false)
    assert {^a, _, 1} = BlockDownload.in_flight(t.bd)[h]
    assert BlockDownload.checking(t.bd) == %{}
    # The honest peer's slot is still taken (16 in flight), its request intact.
    assert BlockDownload.request(t.bd, a, List.last(entries).hash) == []
  end

  test "a disconnect releases every request, reservation and byte (no orphans)" do
    {idx, entries} = chain(40)
    t = start(entries, idx, initial_estimate: 1_000)
    best = List.last(entries).hash
    a = peer()
    picks = BlockDownload.request(t.bd, a, best)
    # Two received and being checked, the rest in transit.
    for h <- Enum.take(picks, 2), do: assert(BlockDownload.received(t.bd, a, h, 2_000))
    s = BlockDownload.stats(t.bd)
    assert s.in_flight == 14 and s.checking == 2 and s.bytes == 14 * 1_000 + 2 * 2_000

    Process.exit(a, :kill)
    wait_until(fn -> BlockDownload.stats(t.bd).peers == 0 end)
    s = BlockDownload.stats(t.bd)
    assert s.in_flight == 0 and s.checking == 0 and s.bytes == 0 and s.released_peer == 16

    # All selectable again.
    b = peer()
    assert heights(entries, BlockDownload.request(t.bd, b, best)) == Enum.to_list(1..16)
  end

  test "the cursor skips held blocks on later requests and resets when the peer's best forks below it" do
    {idx, entries} = chain(100)
    t = start(entries, idx)
    a = self()
    best = List.last(entries)
    hold(t, Enum.map(Enum.slice(entries, 1..50), & &1.hash))

    assert heights(entries, BlockDownload.request(t.bd, a, best.hash)) == Enum.to_list(51..66)
    p1 = BlockDownload.stats(t.bd).probes

    # Release them as failed (selectable again): the next walk starts at the cursor (50).
    for h <- Map.keys(BlockDownload.in_flight(t.bd)) do
      BlockDownload.received(t.bd, a, h, 1)
      BlockDownload.checked(t.bd, a, h, false)
    end

    assert heights(entries, BlockDownload.request(t.bd, a, best.hash)) == Enum.to_list(51..66)
    assert BlockDownload.stats(t.bd).probes - p1 == 16

    # A heavier fork from height 30 becomes this peer's best: blocks 31.. of the fork.
    for h <- Map.keys(BlockDownload.in_flight(t.bd)),
        do: BlockDownload.received(t.bd, a, h, 1) && BlockDownload.checked(t.bd, a, h, false)

    {idx2, fork} = extend(idx, Enum.at(entries, 30), 100, 7)
    assert HeaderIndex.best(idx2).hash == List.last(fork).hash
    picks = BlockDownload.request(t.bd, a, List.last(fork).hash)
    fork_heights = Map.new(fork, &{&1.hash, &1.height})
    assert Enum.map(picks, &fork_heights[&1]) == Enum.to_list(31..46)
  end

  test "the byte budget gates requests, not data, and lets the earliest missing block through" do
    {idx, entries} = chain(40)
    t = start(entries, idx, max_bytes: 3_000, initial_estimate: 1_000)
    best = List.last(entries).hash
    a = self()

    # 3 fit the budget.
    assert heights(entries, BlockDownload.request(t.bd, a, best)) == [1, 2, 3]
    assert BlockDownload.stats(t.bd).budget_gated > 0

    # A block far larger than its estimate is still accepted, and accounted.
    [h1 | _] = Map.keys(BlockDownload.in_flight(t.bd)) |> Enum.sort_by(&heights(entries, [&1]))
    assert BlockDownload.received(t.bd, a, h1, 50_000) == true
    s = BlockDownload.stats(t.bd)
    assert s.over_estimate == 1 and s.bytes == 50_000 + 2 * 1_000

    # Regression: over budget, with the earliest blocks
    # already progressing (1 checking, 2 and 3 in transit), other peers get
    # nothing. Each walk's first missing block used to be exempt: one block
    # past the budget per woken peer.
    b = peer()
    assert BlockDownload.request(t.bd, b, best) == []
    assert BlockDownload.request(t.bd, peer(), best) == []

    # The earliest missing block with nothing below it in flight is still
    # let through, to one peer: block 1 failed its check (selectable again).
    BlockDownload.checked(t.bd, a, h1, false)
    assert heights(entries, BlockDownload.request(t.bd, b, best)) == [1]
    assert BlockDownload.request(t.bd, peer(), best) == []
  end

  test "wakeups are coalesced and go only to peers that found nothing" do
    {idx, entries} = chain(16)
    t = start(entries, idx)
    best = List.last(entries).hash
    a = peer()
    picks = BlockDownload.request(t.bd, a, best)
    assert length(picks) == 16
    b = peer()
    # Everything is in flight from A: B waits.
    assert BlockDownload.request(t.bd, b, best) == []
    assert BlockDownload.stats(t.bd).waiting == 1

    # Several triggers before the wake runs: one :request_blocks to B, none to A.
    send(t.bd, {:block_connected, <<0::256>>, 1})
    BlockDownload.received(t.bd, a, hd(picks), 1)
    BlockDownload.checked(t.bd, a, hd(picks), false)
    assert_receive {:to_peer, ^b, :request_blocks}, 1_000
    refute_receive {:to_peer, _, :request_blocks}, 100
    s = BlockDownload.stats(t.bd)
    assert s.wakes == 1 and s.woken == 1 and s.waiting == 0

    # B's next request picks the released block: one refill measured.
    assert heights(entries, BlockDownload.request(t.bd, b, best)) == [1]
    assert BlockDownload.stats(t.bd).refills == 1
  end

  test "a block being checked is not a network timeout or a stall" do
    {idx, entries} = chain(2)
    # Target spacing 0: anything in transit times out at the next tick.
    {:ok, headers} = StubHeaders.start_link(idx)
    {:ok, chain} = StubChain.start_link(hd(entries))
    clock = Exnode.Clock.new()
    Exnode.Clock.advance(clock, 0)

    {:ok, bd} =
      BlockDownload.start_link(
        headers: headers,
        chain: chain,
        params: %{pow_target_spacing: 0},
        clock: clock
      )

    a = self()
    picks = BlockDownload.request(bd, a, List.last(entries).hash)
    for h <- picks, do: BlockDownload.received(bd, a, h, 1)
    Exnode.Clock.advance(clock, 1)
    Exnode.Clock.tick(bd)
    refute_received {:disconnect, _}
    assert BlockDownload.stats(bd).checking == 2
  end

  test "ancestor lookups from another process stay coherent while the best branch switches" do
    {idx, entries} = chain(100)
    base = List.last(entries)
    {idx, a} = extend(idx, base, 150, 1)
    {idx, b} = extend(idx, base, 150, 2)
    tops = [List.last(a), List.last(b)]
    stop = :atomics.new(1, [])

    # Reader (another process): ancestors of both branch tips, every height
    # above the fork, checked against parent links.
    reader =
      Task.async(fn ->
        Stream.repeatedly(fn -> :atomics.get(stop, 1) end)
        |> Enum.reduce_while({0, 0}, fn
          1, acc ->
            {:halt, acc}

          _, {n, bad} ->
            top = Enum.at(tops, rem(n, 2))
            h = 101 + rem(n * 13, 150)
            ok = HeaderIndex.ancestor(idx, top, h) == by_links(idx, top, h)
            {:cont, {n + 1, if(ok, do: bad, else: bad + 1)}}
        end)
      end)

    # Writer (this process owns the tables): 1,000 switches, each making the
    # other branch heavier, so the heights table is rewritten back to the fork.
    {idx, _} =
      Enum.reduce(1..1_000, {idx, %{0 => List.last(a), 1 => List.last(b)}}, fn i, {idx, tips} ->
        k = rem(i, 2)
        other = tips[1 - k]
        {idx, ext} = extend(idx, tips[k], other.height - tips[k].height + 1, 1_000 + i)
        assert HeaderIndex.best(idx).hash == List.last(ext).hash
        {idx, Map.put(tips, k, List.last(ext))}
      end)

    :atomics.put(stop, 1, 1)
    {reads, bad} = Task.await(reader, 30_000)
    assert reads > 100
    assert bad == 0
    # Two bumps per branch switch, plus the first insert (genesis, no best
    # yet); extending the best chain by one entry bumps nothing.
    assert HeaderIndex.generation(idx) == 2 + 2 * 1_000
  end

  defp by_links(_idx, %{height: h} = e, h), do: e
  defp by_links(idx, e, h), do: by_links(idx, HeaderIndex.prev(idx, e), h)

  # Regression: a block found mutated on connect is un-held
  # without its header being invalidated. Peers whose cursor had passed it
  # never selected it again.
  test "a held block failed as mutated is selected again by a peer whose cursor passed it" do
    {idx, entries} = chain(100)
    t = start(entries, idx)
    a = self()
    best = List.last(entries)
    hold(t, Enum.map(Enum.slice(entries, 1..50), & &1.hash))
    assert heights(entries, BlockDownload.request(t.bd, a, best.hash)) == Enum.to_list(51..66)

    for h <- Map.keys(BlockDownload.in_flight(t.bd)) do
      BlockDownload.received(t.bd, a, h, 1)
      BlockDownload.checked(t.bd, a, h, false)
    end

    # Block 20 is un-held by the chain state (mutated at connect).
    b20 = Enum.at(entries, 20)
    :ok = GenServer.call(t.chain, {:unhold, b20.hash})
    send(t.bd, {:block_invalid, b20.hash, {:mutated, "bad-txnmrklroot"}})
    assert 20 in heights(entries, BlockDownload.request(t.bd, a, best.hash))
  end

  # Regression: a block a reorg disconnects below the witness-pruning
  # horizon is no longer held. Peers whose cursor had passed it never
  # selected it again, and the old branch could not be reconnected.
  test "a held block disconnected and no longer held is selected again by a peer whose cursor passed it" do
    {idx, entries} = chain(100)
    t = start(entries, idx)
    a = self()
    best = List.last(entries)
    hold(t, Enum.map(Enum.slice(entries, 1..50), & &1.hash))
    assert heights(entries, BlockDownload.request(t.bd, a, best.hash)) == Enum.to_list(51..66)

    for h <- Map.keys(BlockDownload.in_flight(t.bd)) do
      BlockDownload.received(t.bd, a, h, 1)
      BlockDownload.checked(t.bd, a, h, false)
    end

    b20 = Enum.at(entries, 20)
    :ok = GenServer.call(t.chain, {:unhold, b20.hash})
    send(t.bd, {:block_disconnected, b20.hash})
    assert 20 in heights(entries, BlockDownload.request(t.bd, a, best.hash))
  end
end
