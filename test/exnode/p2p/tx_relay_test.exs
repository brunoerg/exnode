defmodule Exnode.P2P.TxRelayTest do
  @moduledoc """
  TxRelay resource bounds (per-peer state and per-item work on `inv` are
  bounded, not unbounded and O(global)), with a stub mempool that counts calls and an
  injected clock:
  * the per-peer known-inventory filter is Core's rolling bloom filter
    (`m_tx_inventory_known_filter`, 50,000 at 10⁻⁶): fixed size, the last
    50,000 always known, older generations forgotten;
  * announcements per peer are capped (Core `MAX_PEER_TX_ANNOUNCEMENTS`),
    also on the orphan-parent path;
  * in-flight accounting still applies the overloaded delay;
  * getdata lookups and inv membership checks are batched mempool calls;
  * a 50,000-item inv completes quickly with bounded state;
  * remote-DoS fixes (fix-03 WS1): calls into a busy mempool wait (no 5 s
    timeout), a tick costs the work due rather than the announcements
    held (checked against the previous whole-map implementation), and a
    flooding peer has at most one `inv` waiting in TxRelay's mailbox.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties
  import Exnode.Test.Wait

  alias Exnode.Codec.Tx
  alias Exnode.P2P.TxRelay
  alias Exnode.Util.RollingBloom

  @known_cap 50_000
  @max_announcements 5_000
  @max_in_flight 100

  # A stand-in mempool: reports every call to the test; `present` hashes are in the pool.
  defmodule StubMempool do
    use GenServer
    def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
    def init({test, present, txs}), do: {:ok, %{test: test, present: present, txs: txs}}

    def handle_call({:has_many, hashes, kind}, _f, st) do
      send(st.test, {:mp, :has_many, kind, length(hashes)})
      {:reply, hashes |> Enum.filter(&MapSet.member?(st.present, &1)) |> MapSet.new(), st}
    end

    def handle_call({:has, h, kind}, _f, st) do
      send(st.test, {:mp, :has, kind})
      {:reply, MapSet.member?(st.present, h), st}
    end

    def handle_call({:get_tx, _, _}, _f, st),
      do:
        (
          send(st.test, {:mp, :get_tx})
          {:reply, nil, st}
        )

    def handle_call({:get_txs, items, _before}, f, st), do: handle_call({:get_txs, items}, f, st)

    def handle_call({:get_txs, items}, _f, st) do
      send(st.test, {:mp, :get_txs, length(items)})
      {found, missing} = Enum.split_with(items, &Map.has_key?(st.txs, &1.hash))
      {:reply, {Enum.map(found, &st.txs[&1.hash]), missing}, st}
    end

    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}

    def handle_call({:accept, _tx, _}, _f, st),
      do: {:reply, {:error, %{result: :missing_inputs}}, st}

    def handle_cast({:remove_unbroadcast, txids}, st),
      do:
        (
          send(st.test, {:mp, :remove_unbroadcast, txids})
          {:noreply, st}
        )
  end

  # A stand-in mempool that accepts every tx and, like `Exnode.Mempool`,
  # notifies its listener (the relay) besides replying.
  defmodule AcceptingMempool do
    use GenServer
    def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
    def init(_), do: {:ok, %{relay: nil, txs: %{}}}

    def handle_cast({:listener, relay}, st), do: {:noreply, %{st | relay: relay}}

    def handle_call(:sequence, _f, st), do: {:reply, map_size(st.txs), st}
    def handle_call({:has, _, _}, _f, st), do: {:reply, false, st}
    def handle_call({:has_many, _, _}, _f, st), do: {:reply, MapSet.new(), st}

    def handle_call({:accept, tx, _}, {origin, _}, st) do
      send(st.relay, {:mempool_accepted, tx, %{}, origin})
      {:reply, {:ok, %{}}, %{st | txs: Map.put(st.txs, tx.txid, tx)}}
    end

    def handle_call({:extract_best, txids, _n}, _f, st) do
      {found, rest} = Enum.split_with(txids, &Map.has_key?(st.txs, &1))

      entries =
        for t <- found,
            tx = st.txs[t],
            do: %{txid: tx.txid, wtxid: tx.wtxid, tx: tx, fee: 1_000, vsize: 100}

      {:reply, {entries, rest}, st}
    end
  end

  defp start(opts \\ []) do
    clock = :atomics.new(1, [])
    :atomics.put(clock, 1, 1_000_000)

    {:ok, mp} =
      StubMempool.start_link(
        {self(), Keyword.get(opts, :present, MapSet.new()), Keyword.get(opts, :txs, %{})}
      )

    {:ok, relay} = TxRelay.start_link(mempool: mp, clock: fn -> :atomics.get(clock, 1) end)
    %{relay: relay, mp: mp, clock: clock}
  end

  # A fake peer process: forwards what TxRelay sends it to the test.
  defp peer(relay, info) do
    test = self()
    pid = spawn_link(fn -> forward(test) end)

    TxRelay.connected(
      relay,
      pid,
      Map.merge(%{wtxid_relay: true, preferred: false, relay_txs: true, inbound: true}, info)
    )

    pid
  end

  defp forward(test) do
    receive do
      m ->
        send(test, {:peer, self(), m})
        forward(test)
    end
  end

  defp hashes(n, tag), do: for(i <- 1..n, do: :crypto.hash(:sha256, <<tag::32, i::32>>))

  defp inv(relay, peer, hs, type \\ :wtx),
    do: TxRelay.inv(relay, peer, Enum.map(hs, &%{type: type, hash: &1}))

  defp state(relay), do: :sys.get_state(relay)
  defp ann(relay, peer), do: Map.get(state(relay).ann, peer, %{})
  defp known(relay, peer), do: state(relay).peers[peer].known_in

  test "known: a fixed-size rolling filter; the last 50,000 known, older generations forgotten" do
    %{relay: r} = start()
    p = peer(r, %{})
    # 90,000: past the start of a fourth generation of 25,000 (at 75,000),
    # which clears the first.
    hs = hashes(@known_cap + 40_000, 1)
    for chunk <- Enum.chunk_every(hs, @known_cap), do: inv(r, p, chunk)
    k = known(r, p)
    assert RollingBloom.bytes(k) == 539_168
    # Core's guarantee: the newest 50,000 are always known.
    assert Enum.all?(Enum.take(hs, -@known_cap), &RollingBloom.contains?(k, &1))
    # The first generation is gone (a false positive or two at 10^-6 is
    # possible in principle): such a hash may be announced to the peer again
    # (extra bandwidth only).
    assert Enum.count(Enum.take(hs, 25_000), &RollingBloom.contains?(k, &1)) <= 1
  end

  test "announcements: capped at 5,000 per peer; another peer is unaffected" do
    %{relay: r} = start()
    a = peer(r, %{})
    b = peer(r, %{})
    inv(r, a, hashes(6_000, 2))
    inv(r, b, hashes(10, 3))
    assert map_size(ann(r, a)) == @max_announcements
    assert map_size(ann(r, b)) == 10
  end

  test "orphan parents cannot push a peer past the announcement cap" do
    %{relay: r} = start()
    p = peer(r, %{})
    inv(r, p, hashes(@max_announcements - 3, 4))
    assert map_size(ann(r, p)) == @max_announcements - 3

    # A tx with 10 missing parents becomes an orphan; only 3 parents fit.
    parents = hashes(10, 5)

    {:ok, tx} =
      %Tx{
        version: 2,
        locktime: 0,
        inputs:
          for(
            h <- parents,
            do: %Tx.In{prev_hash: h, prev_index: 0, script_sig: <<>>, sequence: 0xFFFFFFFF}
          ),
        outputs: [%Tx.Out{value: 1000, script_pubkey: <<0x51>>}]
      }
      |> Tx.encode()
      |> IO.iodata_to_binary()
      |> Tx.decode_exact()

    TxRelay.received_tx(r, p, tx)
    assert TxRelay.orphans(r) == [tx.wtxid]
    assert map_size(ann(r, p)) == @max_announcements
  end

  test "in-flight: requested entries make the next inv overloaded; one batch gets one decision" do
    %{relay: r, clock: clock} = start()
    p = peer(r, %{preferred: true})
    t0 = :atomics.get(clock, 1)
    # A preferred peer's announcements are ready at once, all with the same decision.
    first = hashes(@max_in_flight + 50, 6)
    inv(r, p, first)
    assert Enum.all?(Map.values(ann(r, p)), &(&1.ready_at == t0))
    # A tick requests them (one getdata each; at most one in flight per hash).
    send(r, :tick)
    assert_receive {:peer, ^p, {:send, {:getdata, items}}}, 2_000
    assert length(items) == length(first)
    assert Enum.count(ann(r, p), fn {_, a} -> a.state == :requested end) == length(first)
    # Now in flight >= @max_in_flight: the next inv gets the overloaded delay.
    later = hashes(5, 7)
    inv(r, p, later)
    m = ann(r, p)
    assert Enum.all?(later, &(m[&1].ready_at == t0 + 2_000))
  end

  test "lookup: one get_txs call, same {txs, missing} shape, unbroadcast removal" do
    tx = %{txid: :crypto.hash(:sha256, "t1"), wtxid: :crypto.hash(:sha256, "w1")}
    %{relay: r} = start(txs: %{tx.wtxid => tx})
    items = [%{type: :wtx, hash: tx.wtxid}, %{type: :wtx, hash: :crypto.hash(:sha256, "none")}]
    assert {[^tx], [%{type: :wtx}]} = TxRelay.lookup(r, items)
    assert_received {:mp, :get_txs, 2}
    refute_received {:mp, :has, _}
    refute_received {:mp, :get_tx}
    txid = tx.txid
    assert_receive {:mp, :remove_unbroadcast, [^txid]}
  end

  test "scale: a 50,000-item inv is processed with one mempool call and bounded state" do
    %{relay: r} = start()
    p = peer(r, %{})
    hs = hashes(50_000, 8)

    {us, _} =
      :timer.tc(fn ->
        inv(r, p, hs)
        _ = state(r)
      end)

    assert us < 5_000_000
    assert_received {:mp, :has_many, :wtxid, 50_000}
    refute_received {:mp, :has_many, :txid, _}
    refute_received {:mp, :has, _}
    assert RollingBloom.bytes(known(r, p)) == 539_168
    assert map_size(ann(r, p)) <= @max_announcements
  end

  test "a tx from a peer is queued for announcement once, and never announced back to it" do
    clock = :atomics.new(1, [])
    :atomics.put(clock, 1, 1_000_000)
    {:ok, mp} = AcceptingMempool.start_link(self())
    {:ok, r} = TxRelay.start_link(mempool: mp, clock: fn -> :atomics.get(clock, 1) end)
    GenServer.cast(mp, {:listener, r})
    source = peer(r, %{})
    other = peer(r, %{})

    tx = Exnode.Test.Coins.tx([{<<1::256>>, 0, 10_000}], [{9_000, Exnode.Test.Coins.p2wsh()}])
    # Unsolicited: the source never announced it, so it is not in its known set.
    TxRelay.received_tx(r, source, tx)
    # The relay handles the tx, then the mempool's notification of it.
    _ = state(r)
    st = state(r)
    # Queued once for the other peer, not at all for the source.
    assert st.peers[other].to_send == [tx.txid]
    assert st.peers[source].to_send == []

    # Past every peer's trickle delay: only the other peer gets an inv.
    :atomics.add(clock, 1, 600_000)
    send(r, :tick)
    # Each fake peer forwards on its own process: wait for the message rather
    # than draining the mailbox right after the tick (that raced).
    assert_receive {:peer, ^other, {:send, {:inv, items}}}, 2_000
    assert Enum.map(items, & &1.hash) == [tx.wtxid]
    refute_receive {:peer, ^source, {:send, {:inv, _}}}, 300
  end

  test "AUD-A4-3: a peer's own known filter is read, not written, and keeps its txs from being announced back" do
    clock = :atomics.new(1, [])
    :atomics.put(clock, 1, 1_000_000)
    {:ok, mp} = AcceptingMempool.start_link(self())
    {:ok, r} = TxRelay.start_link(mempool: mp, clock: fn -> :atomics.get(clock, 1) end)
    GenServer.cast(mp, {:listener, r})
    announcer = peer(r, %{})
    other = peer(r, %{})

    tx = Exnode.Test.Coins.tx([{<<2::256>>, 0, 10_000}], [{9_000, Exnode.Test.Coins.p2wsh()}])

    # As Peer does: the hash goes into the peer's own filter, which comes
    # with the inv; TxRelay adds nothing to it.
    known = TxRelay.new_known_filter()
    RollingBloom.insert(known, tx.wtxid)
    :ok = TxRelay.inv(r, announcer, [%{type: :wtx, hash: tx.wtxid}], known)
    assert state(r).peers[announcer].known_in == known
    assert :atomics.get(known.a, 1) == 1

    # The tx then arrives from elsewhere (RPC): queued for both peers, but
    # the announcer, which announced it, is not sent an inv for it.
    {:ok, _} = GenServer.call(mp, {:accept, tx, nil})
    _ = state(r)
    :atomics.add(clock, 1, 600_000)
    send(r, :tick)
    assert_receive {:peer, ^other, {:send, {:inv, items}}}, 2_000
    assert Enum.map(items, & &1.hash) == [tx.wtxid]
    refute_receive {:peer, ^announcer, {:send, {:inv, _}}}, 300
  end

  test "hashes already in the mempool are not announced" do
    present = MapSet.new(hashes(5, 9))
    %{relay: r} = start(present: present)
    p = peer(r, %{})
    inv(r, p, hashes(10, 9))
    assert map_size(ann(r, p)) == 5
    refute Enum.any?(present, &Map.has_key?(ann(r, p), &1))
  end

  # --- fix-03 WS1 ---------------------------------------------------------------

  # A mempool whose `get_txs` waits for `:open` (fix-02 latch).
  defmodule LatchMempool do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil)
    def init(_), do: {:ok, nil}

    def handle_call({:get_txs, items, _before}, _f, st) do
      receive do
        :open -> {:reply, {[], items}, st}
      end
    end

    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}
  end

  # fix-02 also suggests the same latch for `Connman.accept_inbound?/2`; a
  # Connman busy for >5 s cannot be built without production test hooks, so
  # that case relies on the explicit `:infinity` in connman.ex.
  test "lookup waits on a busy mempool past 5 s instead of exiting (fix-02 latch)" do
    {:ok, mp} = LatchMempool.start_link(nil)
    {:ok, r} = TxRelay.start_link(mempool: mp)
    item = %{type: :wtx, hash: :crypto.hash(:sha256, "x")}
    task = Task.async(fn -> TxRelay.lookup(r, [item]) end)
    Process.sleep(5_500)
    # Before fix-02 the task (and TxRelay) exited at 5 s.
    assert Process.info(task.pid) != nil
    assert Process.alive?(r)
    send(mp, :open)
    assert Task.await(task) == {[], [item]}
  end

  # A mempool with a mutable `present` set; `accept` succeeds for hashes in
  # `accepts` (then present) and rejects the others as consensus-invalid.
  defmodule FlipMempool do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil)
    def init(_), do: {:ok, %{present: MapSet.new(), accepts: MapSet.new(), gate: nil}}

    def handle_call({:flip, h}, _f, st) do
      p =
        if MapSet.member?(st.present, h),
          do: MapSet.delete(st.present, h),
          else: MapSet.put(st.present, h)

      {:reply, :ok, %{st | present: p}}
    end

    def handle_call({:set, k, v}, _f, st), do: {:reply, :ok, Map.put(st, k, v)}

    def handle_call({:has_many, hashes, _kind}, _f, st) do
      # A gated mempool is busy until the test lets each call through.
      if st.gate do
        send(st.gate, {:mempool_busy, self()})

        receive do
          :go -> :ok
        end
      end

      {:reply, hashes |> Enum.filter(&MapSet.member?(st.present, &1)) |> MapSet.new(), st}
    end

    def handle_call({:has, h, _kind}, _f, st), do: {:reply, MapSet.member?(st.present, h), st}
    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}

    def handle_call({:accept, tx, _}, _f, st) do
      if MapSet.member?(st.accepts, tx.txid),
        do: {:reply, {:ok, %{}}, %{st | present: MapSet.put(st.present, tx.txid)}},
        else: {:reply, {:error, %{result: :consensus}}, st}
    end
  end

  # The pre-fix tick (`expire_requests/2` then `send_requests/2`), copied
  # verbatim with its helpers, as the oracle. `send_requests` returns the
  # getdata per peer instead of sending it.
  defmodule OldTick do
    alias Exnode.Mempool

    def run(st, now) do
      st |> expire_requests(now) |> send_requests(now)
    end

    defp f_has?(f, h), do: MapSet.member?(f.set, h)

    defp already_have?(st, {kind, h}, include_reconsiderable, in_mempool) do
      Map.has_key?(st.orphans, h) or (include_reconsiderable and f_has?(st.reconsiderable, h)) or
        f_has?(st.confirmed, h) or f_has?(st.rejects, h) or
        if(in_mempool,
          do: MapSet.member?(in_mempool[kind], h),
          else: Mempool.has?(st.mempool, h, kind)
        )
    end

    defp prefetch_mempool(st, gtxids) do
      by_kind = Enum.group_by(gtxids, &elem(&1, 0), &elem(&1, 1))

      Map.new([:txid, :wtxid], fn kind ->
        case Map.get(by_kind, kind, []) do
          [] -> {kind, MapSet.new()}
          hs -> {kind, Mempool.has_many?(st.mempool, Enum.uniq(hs), kind)}
        end
      end)
    end

    defp ann_put(ann, peer, h, a), do: Map.update(ann, peer, %{h => a}, &Map.put(&1, h, a))

    defp ann_delete_hashes(ann, hashes) do
      Enum.reduce(ann, ann, fn {peer, m}, acc ->
        put_peer(acc, peer, Map.drop(m, Enum.to_list(hashes)))
      end)
    end

    defp put_peer(ann, peer, m) when map_size(m) == 0, do: Map.delete(ann, peer)
    defp put_peer(ann, peer, m), do: Map.put(ann, peer, m)

    # Core: an expired request becomes COMPLETED; a hash with no uncompleted
    # announcement left is forgotten (AUD-A4-1).
    defp expire_requests(st, now) do
      ann =
        for {peer, m} <- st.ann, into: %{} do
          {peer,
           Map.new(m, fn {h, a} ->
             if a.state == :requested and a.expiry < now,
               do: {h, %{a | state: :completed}},
               else: {h, a}
           end)}
        end

      done =
        for({_, m} <- ann, {h, _} <- m, do: h)
        |> Enum.uniq()
        |> Enum.filter(fn h ->
          Enum.all?(ann, fn {_, m} -> not Map.has_key?(m, h) or m[h].state == :completed end)
        end)

      %{st | ann: ann_delete_hashes(ann, done)}
    end

    @getdata_interval 60_000

    defp send_requests(st, now) do
      by_hash =
        for {p, m} <- st.ann,
            {h, a} <- m,
            reduce: %{},
            do: (acc -> Map.update(acc, h, [{p, a}], &[{p, a} | &1]))

      picks =
        for {h, anns} <- by_hash,
            not Enum.any?(anns, fn {_, a} -> a.state == :requested end),
            ready =
              for(
                {p, a} <- anns,
                a.state == :candidate,
                a.ready_at <= now,
                Map.has_key?(st.peers, p),
                do: {p, a}
              ),
            ready != [] do
          {peer, a} = Enum.min_by(ready, fn {_, a} -> {not a.preferred, a.seq} end)
          {h, peer, a}
        end

      in_mempool = prefetch_mempool(st, Enum.map(picks, fn {h, _, a} -> {a.kind, h} end))

      {st, per_peer} =
        Enum.reduce(picks, {st, %{}}, fn {h, peer, a}, {st, per_peer} ->
          if already_have?(st, {a.kind, h}, false, in_mempool) do
            {%{st | ann: ann_delete_hashes(st.ann, [h])}, per_peer}
          else
            ann =
              ann_put(st.ann, peer, h, %{a | state: :requested, expiry: now + @getdata_interval})

            item = %{
              type: if(a.kind == :wtxid, do: :wtx, else: :tx),
              witness: a.kind == :txid,
              hash: h
            }

            {%{st | ann: ann}, Map.update(per_peer, peer, [item], &[item | &1])}
          end
        end)

      {st, per_peer}
    end
  end

  # A fake peer that forwards to the test and answers `{:flush, ref}` once
  # everything sent to it before has been forwarded.
  defp flush_peer(test) do
    receive do
      {:flush, ref} ->
        send(test, {:flushed, ref})
        flush_peer(test)

      m ->
        send(test, {:peer, self(), m})
        flush_peer(test)
    end
  end

  # The getdata each peer received since the last call, as a set of {peer, item}.
  defp collect_getdata(peers) do
    for p <- peers do
      ref = make_ref()
      send(p, {:flush, ref})
      assert_receive {:flushed, ^ref}, 2_000
    end

    collect = fn collect, acc ->
      receive do
        {:peer, p, {:send, {:getdata, items}}} ->
          collect.(collect, acc ++ Enum.map(items, &{p, &1}))

        {:peer, _, _} ->
          collect.(collect, acc)
      after
        0 -> MapSet.new(acc)
      end
    end

    collect.(collect, [])
  end

  # The new bookkeeping agrees with `ann` (the source of truth).
  defp assert_counters(st) do
    for {p, m} <- st.ann do
      assert Map.get(st.in_flight, p, 0) == Enum.count(m, fn {_, a} -> a.state == :requested end)
    end

    assert Enum.all?(Map.keys(st.in_flight), &Map.has_key?(st.ann, &1))

    assert st.requested ==
             for({p, m} <- st.ann, {h, %{state: :requested}} <- m, into: %{}, do: {h, p})

    assert Enum.all?(Map.keys(st.waiting), &Map.has_key?(st.requested, &1))

    # AUD-A4-1: the by-hash index matches `ann`, and no hash is kept with
    # every announcement completed (Core forgets it).
    by_hash =
      for {p, m} <- st.ann, {h, _} <- m, reduce: %{} do
        acc -> Map.update(acc, h, MapSet.new([p]), &MapSet.put(&1, p))
      end

    assert st.ann_peers == by_hash

    for {h, ps} <- by_hash do
      refute Enum.all?(ps, &(st.ann[&1][h].state == :completed)),
             "every announcement of a hash is completed"
    end
  end

  defp op_gen do
    h = integer(0..7)

    one_of([
      tuple({constant(:connect), boolean(), boolean()}),
      tuple({constant(:disconnect), integer(0..5)}),
      tuple(
        {constant(:inv), integer(0..5), list_of(h, min_length: 1, max_length: 4),
         member_of([:wtx, :tx])}
      ),
      tuple({constant(:advance), member_of([0, 100, 1_000, 2_000, 4_000, 30_000, 61_000])}),
      constant(:tick),
      constant(:tick),
      tuple({constant(:tx), integer(0..5), h, boolean()}),
      tuple({constant(:notfound), integer(0..5), h}),
      tuple({constant(:flip), h})
    ])
  end

  property "tick: same getdata per peer and same announcements as the previous implementation" do
    pool = for i <- 0..7, do: :crypto.hash(:sha256, <<i>>)

    check all(ops <- list_of(op_gen(), min_length: 5, max_length: 60), max_runs: 150) do
      clock = :atomics.new(1, [])
      :atomics.put(clock, 1, 1_000_000)
      {:ok, mp} = FlipMempool.start_link(nil)

      {:ok, r} =
        TxRelay.start_link(mempool: mp, clock: fn -> :atomics.get(clock, 1) end, tick_ms: nil)

      test = self()

      Enum.reduce(ops, [], fn op, peers ->
        pick = fn i -> if peers == [], do: nil, else: Enum.at(peers, rem(i, length(peers))) end

        peers =
          case op do
            {:connect, preferred, wtxid_relay} ->
              pid = spawn_link(fn -> flush_peer(test) end)

              info = %{
                wtxid_relay: wtxid_relay,
                preferred: preferred,
                relay_txs: true,
                inbound: not preferred
              }

              TxRelay.connected(r, pid, info)
              peers ++ [pid]

            {:disconnect, i} ->
              if p = pick.(i) do
                # The relay's monitor would deliver this; sent directly to stay in order.
                send(r, {:DOWN, make_ref(), :process, p, :gone})
                List.delete(peers, p)
              else
                peers
              end

            {:inv, i, hs, type} ->
              if p = pick.(i),
                do: TxRelay.inv(r, p, Enum.map(hs, &%{type: type, hash: Enum.at(pool, &1)}))

              peers

            {:advance, ms} ->
              :atomics.add(clock, 1, ms)
              peers

            :tick ->
              pre = :sys.get_state(r)
              now = :atomics.get(clock, 1)
              {oracle, oracle_getdata} = OldTick.run(pre, now)
              _ = collect_getdata(peers)
              send(r, :tick)
              post = :sys.get_state(r)
              got = collect_getdata(peers)
              want = MapSet.new(for {p, items} <- oracle_getdata, i <- items, do: {p, i})
              assert got == want
              assert post.ann == oracle.ann
              peers

            {:tx, i, j, accept} ->
              if p = pick.(i) do
                h = Enum.at(pool, j)
                if accept, do: GenServer.call(mp, {:set, :accepts, MapSet.new([h])})

                TxRelay.received_tx(r, p, %Tx{txid: h, wtxid: h, inputs: [], has_witness: false})

                GenServer.call(mp, {:set, :accepts, MapSet.new()})
              end

              peers

            {:notfound, i, j} ->
              if p = pick.(i), do: TxRelay.notfound(r, p, [%{type: :wtx, hash: Enum.at(pool, j)}])
              peers

            {:flip, j} ->
              GenServer.call(mp, {:flip, Enum.at(pool, j)})
              peers
          end

        assert_counters(:sys.get_state(r))
        peers
      end)

      GenServer.stop(r)
      GenServer.stop(mp)
    end
  end

  test "tick: 125 peers x 5,000 announcements, none due, cost no global scan" do
    clock = :atomics.new(1, [])
    :atomics.put(clock, 1, 1_000_000)
    {:ok, mp} = FlipMempool.start_link(nil)

    {:ok, r} =
      TxRelay.start_link(mempool: mp, clock: fn -> :atomics.get(clock, 1) end, tick_ms: nil)

    for i <- 1..125 do
      p = peer(r, %{})
      inv(r, p, hashes(@max_announcements, 100 + i))
    end

    st = state(r)
    assert map_size(st.ann) == 125
    assert Enum.all?(st.ann, fn {_, m} -> map_size(m) == @max_announcements end)

    # Inbound announcements are ready 2 s from now: no work is due. The
    # pre-fix tick rebuilt a by-hash map of all 625,000 (~92 ms).
    times =
      for _ <- 1..5 do
        # A small call waits for the tick (`:sys.get_state` would copy 625k entries).
        {us, _} = :timer.tc(fn -> send(r, :tick) && TxRelay.orphans(r) end)
        us
      end

    assert Enum.min(times) < 5_000, "tick took #{inspect(times)} us"
  end

  test "backpressure: a flooding peer has at most one inv waiting in TxRelay" do
    {:ok, mp} = FlipMempool.start_link(nil)
    # Every mempool call waits for the test: TxRelay is busy exactly while
    # the test looks at its mailbox.
    GenServer.call(mp, {:set, :gate, self()})
    {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)
    test = self()

    flooder =
      spawn_link(fn ->
        TxRelay.connected(r, self(), %{
          wtxid_relay: true,
          preferred: false,
          relay_txs: true,
          inbound: true
        })

        for i <- 1..40,
            do: TxRelay.inv(r, self(), Enum.map(hashes(5, 1_000 + i), &%{type: :wtx, hash: &1}))

        send(test, :flood_done)

        receive do
          :stop -> :ok
        end
      end)

    # At each point TxRelay is held in a mempool call, the flooder is blocked
    # (in its inv call, or done): whatever it could queue is queued. Casts
    # (pre-fix) queued all 40 at once behind the busy TxRelay.
    calls =
      Stream.repeatedly(fn ->
        wait_until(fn -> Process.info(flooder, :status) == {:status, :waiting} end)
        {:message_queue_len, n} = Process.info(r, :message_queue_len)
        assert n <= 1, "#{n} messages waiting in TxRelay"

        receive do
          {:mempool_busy, from} -> send(from, :go) && :call
          :flood_done -> :done
        end
      end)
      |> Enum.take_while(&(&1 == :call))

    assert length(calls) >= 40
    assert map_size(state(r).ann[flooder]) == 200
  end
end
