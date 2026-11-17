defmodule Exnode.DoS.OrphanageTest do
  @moduledoc """
  TxRelay orphan handling (stub mempool that counts calls):

  * #2 (regression): an inv naming an orphan, however often repeated, costs
    no per-parent `Mempool.has?` calls: items are deduplicated, a peer that
    already announces the orphan is skipped, and parents are looked up in
    one batched `has_many?`;
  * #7 (regression): children of an accepted tx (`add_children_to_work_set`) and
    of a resent reconsiderable tx (`try_1p1c`) are found through an index of
    orphans by parent txid, as Core's m_outpoint_to_orphan_wtxids, not by
    scanning every input of every orphan;
  * #6 (regression): only registered (monitored) peers own orphans, so a
    disconnect always erases them (Core EraseForPeer), and every announcer
    is charged an orphan's weight against its per-peer budget;
  * AUD-H1 (regression): the total latency score is capped as Core's, and
    the per-peer accounting is incremental, so the limits cost O(evictions).
  """
  use ExUnit.Case, async: false
  @moduletag :dos

  alias Exnode.Codec.Tx
  alias Exnode.P2P.TxRelay

  defmodule StubMempool do
    use GenServer
    def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
    def init({ctr, ok, recon}), do: {:ok, %{ctr: ctr, ok: ok, recon: recon}}

    # Counter 1: has? calls; counter 2: has_many? calls.

    def handle_call({:has, _h, _k}, _f, st) do
      :counters.add(st.ctr, 1, 1)
      {:reply, false, st}
    end

    def handle_call({:has_many, _hs, _k}, _f, st) do
      :counters.add(st.ctr, 2, 1)
      {:reply, MapSet.new(), st}
    end

    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}
    def handle_call({:submit_package, _}, _f, st), do: {:reply, %{state: :error}, st}

    def handle_call({:accept, tx, _}, _f, st) do
      cond do
        MapSet.member?(st.ok, tx.wtxid) -> {:reply, {:ok, %{}}, st}
        MapSet.member?(st.recon, tx.wtxid) -> {:reply, {:error, %{result: :reconsiderable}}, st}
        true -> {:reply, {:error, %{result: :missing_inputs}}, st}
      end
    end
  end

  defp tx(parents, tag) do
    {:ok, tx} =
      %Tx{
        version: 2,
        locktime: tag,
        inputs:
          for(
            h <- parents,
            do: %Tx.In{prev_hash: h, prev_index: 0, script_sig: <<>>, sequence: 0xFFFFFFFF}
          ),
        outputs: [%Tx.Out{value: 10_000, script_pubkey: <<0, 20, 0::160>>}]
      }
      |> Tx.encode()
      |> IO.iodata_to_binary()
      |> Tx.decode_exact()

    tx
  end

  defp hashes(n, tag), do: for(i <- 1..n, do: :crypto.hash(:sha256, <<tag::32, i::32>>))

  defp start(ok \\ [], recon \\ []) do
    ctr = :counters.new(2, [])

    {:ok, mp} =
      StubMempool.start_link({ctr, MapSet.new(ok, & &1.wtxid), MapSet.new(recon, & &1.wtxid)})

    {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)
    %{relay: r, ctr: ctr}
  end

  defp peer(relay, register? \\ true) do
    pid = spawn(fn -> Process.sleep(:infinity) end)

    if register?,
      do:
        TxRelay.connected(relay, pid, %{
          wtxid_relay: true,
          preferred: false,
          relay_txs: true,
          inbound: true
        })

    pid
  end

  test "inv of one orphan wtxid repeated: no per-parent mempool calls" do
    %{relay: r, ctr: ctr} = start()
    p = peer(r)
    q = peer(r)
    orphan = tx(hashes(2_000, 1), 0)
    :ok = TxRelay.received_tx(r, p, orphan)
    assert TxRelay.orphans(r) == [orphan.wtxid]
    base = {:counters.get(ctr, 1), :counters.get(ctr, 2)}

    items = List.duplicate(%{type: :wtx, hash: orphan.wtxid}, 100)
    # The orphan's own sender: already an announcer, nothing to do.
    {us_p, :ok} = :timer.tc(fn -> TxRelay.inv(r, p, items) end)
    # A new announcer: becomes a resolution candidate once.
    {us_q, :ok} = :timer.tc(fn -> TxRelay.inv(r, q, items) end)
    has = :counters.get(ctr, 1) - elem(base, 0)
    many = :counters.get(ctr, 2) - elem(base, 1)

    IO.puts(
      "orphan inv: 2 x 100 items x 2000 parents -> #{has} has? / #{many} has_many? calls, #{div(us_p, 1000)} + #{div(us_q, 1000)} ms"
    )

    assert has == 0
    # At most one batched call per kind per inv.
    assert many <= 4
    assert MapSet.equal?(:sys.get_state(r).orphans[orphan.wtxid].announcers, MapSet.new([p, q]))
  end

  test "an accepted tx and a resent reconsiderable tx cost O(children), not O(all orphan inputs)" do
    parent = tx(hashes(1, 99), 1)
    unrelated = tx(hashes(1, 98), 2)
    %{relay: r} = start([unrelated], [parent])
    attacker = peer(r)

    # 1000 orphans of 400 inputs (400k inputs; Core's whole orphanage holds
    # at most 3000 latency score, i.e. about 12 such orphans). Built directly,
    # past the per-peer budget, to stress the lookup.
    orphans = for i <- 1..1_000, do: tx(hashes(400, 1_000 + i), i)

    :sys.replace_state(r, fn st ->
      os =
        for {o, i} <- Enum.with_index(orphans),
            into: %{},
            do: {o.wtxid, %{tx: o, announcers: MapSet.new([attacker]), seq: i, weight: 0}}

      by_parent =
        for o <- orphans, h <- Enum.uniq(Enum.map(o.inputs, & &1.prev_hash)), reduce: %{} do
          acc -> Map.update(acc, h, MapSet.new([o.wtxid]), &MapSet.put(&1, o.wtxid))
        end

      # The incremental accounting kept beside `orphans` (weight 0, so no
      # budget is exceeded; the score is past the global cap, unchecked here).
      order = :gb_sets.from_list(for {w, o} <- os, do: {o.seq, w})
      score = Enum.sum(for {_, o} <- os, do: 1 + div(length(o.tx.inputs), 10))

      %{
        st
        | orphans: os,
          orphan_by_parent: by_parent,
          orphan_seq: 1_000,
          orphan_order: order,
          orphan_peers: %{attacker => %{weight: 0, score: score, anns: order}},
          orphan_score: score
      }
    end)

    {us_acc, :ok} = :timer.tc(fn -> TxRelay.received_tx(r, peer(r), unrelated) end)

    # First send puts `parent` in the reconsiderable filter; resends go to try_1p1c.
    :ok = TxRelay.received_tx(r, attacker, parent)

    {us_re, _} =
      :timer.tc(fn -> for _ <- 1..10, do: :ok = TxRelay.received_tx(r, attacker, parent) end)

    IO.puts(
      "orphan lookup, 1000 orphans x 400 inputs: one accepted tx #{div(us_acc, 1000)} ms in TxRelay; one resent ~#{byte_size(parent.raw)}-byte reconsiderable tx #{div(us_re, 10_000)} ms"
    )

    assert length(TxRelay.orphans(r)) == 1_000
    # Was 24-58 ms with the full scan.
    assert us_acc < 5_000
    assert us_re < 10 * 5_000
  end

  test "the parent index stays in step with the orphanage" do
    # p1 is accepted later and resolves its child; p2's child is erased on disconnect.
    p1 = tx(hashes(1, 7), 7)
    %{relay: r} = start([p1])
    a = peer(r)
    b = peer(r)
    c1 = tx([p1.txid | hashes(1, 70)], 1)
    c2 = tx(hashes(3, 71), 2)
    c3 = tx([p1.txid | hashes(2, 72)], 3)
    :ok = TxRelay.received_tx(r, a, c1)
    :ok = TxRelay.received_tx(r, b, c2)
    :ok = TxRelay.received_tx(r, b, c3)
    assert consistent?(r)
    # p1 (shared by c1 and c3), 1 + 3 + 2 others.
    assert map_size(:sys.get_state(r).orphan_by_parent) == 7

    # p1 accepted: c1 and c3 are retried (still missing inputs: kept).
    :ok = TxRelay.received_tx(r, a, p1)
    assert consistent?(r)
    assert length(TxRelay.orphans(r)) == 3

    ref = Process.monitor(b)
    Process.exit(b, :kill)
    assert_receive {:DOWN, ^ref, _, _, _}
    assert TxRelay.orphans(r) == [c1.wtxid]
    assert consistent?(r)
  end

  defp consistent?(r) do
    st = :sys.get_state(r)

    expected =
      for {w, o} <- st.orphans,
          h <- Enum.uniq(Enum.map(o.tx.inputs, & &1.prev_hash)),
          reduce: %{} do
        acc -> Map.update(acc, h, MapSet.new([w]), &MapSet.put(&1, w))
      end

    st.orphan_by_parent == expected
  end

  # The incremental accounting (order, per-peer weight/score/announcements,
  # total score) equals a recomputation from the orphans themselves.
  defp accounting_ok?(r) do
    st = :sys.get_state(r)
    input_score = fn o -> div(length(o.tx.inputs), 10) end

    peers =
      for {w, o} <- st.orphans, p <- o.announcers, reduce: %{} do
        acc ->
          Map.update(
            acc,
            p,
            %{weight: o.weight, score: 1 + input_score.(o), anns: [{o.seq, w}]},
            &%{
              &1
              | weight: &1.weight + o.weight,
                score: &1.score + 1 + input_score.(o),
                anns: [{o.seq, w} | &1.anns]
            }
          )
      end

    got =
      Map.new(st.orphan_peers, fn {p, i} ->
        {p, %{i | anns: Enum.sort(:gb_sets.to_list(i.anns))}}
      end)

    want = Map.new(peers, fn {p, i} -> {p, %{i | anns: Enum.sort(i.anns)}} end)

    score =
      Enum.sum(for {_, o} <- st.orphans, do: MapSet.size(o.announcers) + input_score.(o))

    got == want and st.orphan_score == score and
      Enum.sort(:gb_sets.to_list(st.orphan_order)) ==
        Enum.sort(for {w, o} <- st.orphans, do: {o.seq, w})
  end

  test "AUD-H1: announcements fanned out by many peers are capped by the global latency score" do
    %{relay: r} = start()
    sender = peer(r)
    orphans = for i <- 1..200, do: tx(hashes(1, 10_000 + i), i)
    for o <- orphans, do: :ok = TxRelay.received_tx(r, sender, o)
    items = for o <- orphans, do: %{type: :wtx, hash: o.wtxid}

    # 60 more peers announce every orphan: 12,200 announcements uncapped.
    announcers = for _ <- 1..60, do: peer(r)
    for p <- announcers, do: :ok = TxRelay.inv(r, p, items)

    st = :sys.get_state(r)
    assert st.orphan_score <= 3_000
    assert map_size(st.orphans) <= 200
    assert accounting_ok?(r)

    # The peer with the highest score is trimmed first: no peer is left far
    # above the others (the latest announcers are not starved by the first).
    scores = for {_, i} <- st.orphan_peers, do: i.score
    assert Enum.max(scores) - Enum.min(scores) <= 200

    # A new orphan and a new announcement cost O(evictions), not O(orphans x
    # announcers): both stay cheap at the cap.
    {us_tx, :ok} = :timer.tc(fn -> TxRelay.received_tx(r, sender, tx(hashes(1, 20_000), 1)) end)
    {us_inv, :ok} = :timer.tc(fn -> TxRelay.inv(r, peer(r), items) end)
    assert us_tx < 20_000
    assert us_inv < 100_000
    assert :sys.get_state(r).orphan_score <= 3_000
    assert accounting_ok?(r)

    # Disconnects release exactly the peers' announcements.
    for p <- Enum.take(announcers, 30) do
      ref = Process.monitor(p)
      Process.exit(p, :kill)
      assert_receive {:DOWN, ^ref, _, _, _}
    end

    _ = TxRelay.orphans(r)
    assert accounting_ok?(r)
  end

  test "AUD-H1: count-cap and weight-cap evictions keep the accounting in step" do
    %{relay: r} = start()
    a = peer(r)
    b = peer(r)
    # 1,100 orphans from `a` (count cap 1,000), each also announced by `b`.
    for i <- 1..1_100 do
      o = tx(hashes(1, 30_000 + i), i)
      :ok = TxRelay.received_tx(r, a, o)
      :ok = TxRelay.inv(r, b, [%{type: :wtx, hash: o.wtxid}])
    end

    st = :sys.get_state(r)
    assert map_size(st.orphans) <= 1_000
    assert accounting_ok?(r)
    for {_, i} <- st.orphan_peers, do: assert(i.weight <= 404_000)

    ref = Process.monitor(a)
    Process.exit(a, :kill)
    assert_receive {:DOWN, ^ref, _, _, _}
    _ = TxRelay.orphans(r)
    assert accounting_ok?(r)
  end

  test "orphans are kept only for registered peers, and erased when they disconnect" do
    %{relay: r} = start()

    reg = peer(r, true)
    o1 = tx(hashes(1, 1), 1)
    :ok = TxRelay.received_tx(r, reg, o1)

    unreg = for i <- 1..50, do: {peer(r, false), tx(hashes(2_000, 100 + i), i)}
    for {p, o} <- unreg, do: :ok = TxRelay.received_tx(r, p, o)
    assert TxRelay.orphans(r) == [o1.wtxid]

    ref = Process.monitor(reg)
    Process.exit(reg, :kill)
    assert_receive {:DOWN, ^ref, _, _, _}
    assert TxRelay.orphans(r) == []
  end

  test "every announcer is charged an orphan's weight" do
    %{relay: r} = start()
    a = peer(r)
    b = peer(r)
    # ~330k weight each: one fits a peer's 404k budget, two do not.
    o1 = tx(hashes(2_000, 1), 1)
    o2 = tx(hashes(2_000, 2), 2)
    :ok = TxRelay.received_tx(r, a, o1)
    :ok = TxRelay.received_tx(r, b, o2)
    assert Enum.sort(TxRelay.orphans(r)) == Enum.sort([o1.wtxid, o2.wtxid])

    # `a` also announces o2: now over budget, it loses its older announcement
    # (o1, which then has no announcer left); o2 keeps both.
    :ok = TxRelay.inv(r, a, [%{type: :wtx, hash: o2.wtxid}])
    st = :sys.get_state(r)
    assert Map.keys(st.orphans) == [o2.wtxid]
    assert MapSet.equal?(st.orphans[o2.wtxid].announcers, MapSet.new([a, b]))
  end

  # MP-4 (STATE_MACHINES.md): accepting a 1p1c package used to accept the
  # parent while the child was still an orphan; the parent's reconsideration
  # then resubmitted the child (already in the mempool) and put its wtxid in
  # `rejects`, blocking it until the next block.
  defmodule PackageMempool do
    use GenServer
    def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
    def init({test, parent}), do: {:ok, %{test: test, parent: parent, pool: MapSet.new()}}
    def handle_call({:has, h, _k}, _f, st), do: {:reply, MapSet.member?(st.pool, h), st}

    def handle_call({:has_many, hs, _k}, _f, st),
      do: {:reply, MapSet.new(Enum.filter(hs, &MapSet.member?(st.pool, &1))), st}

    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}

    def handle_call({:submit_package, txs}, _f, st),
      do:
        {:reply, %{state: :ok},
         %{
           st
           | pool: Enum.reduce(txs, st.pool, &(&2 |> MapSet.put(&1.txid) |> MapSet.put(&1.wtxid)))
         }}

    def handle_call({:accept, tx, _}, _f, st) do
      send(st.test, {:accept, tx.wtxid})

      cond do
        MapSet.member?(st.pool, tx.wtxid) ->
          {:reply, {:error, %{result: :conflict, reason: "txn-already-in-mempool"}}, st}

        tx.txid == st.parent ->
          {:reply, {:error, %{result: :reconsiderable, reason: "min relay fee not met"}}, st}

        true ->
          {:reply, {:error, %{result: :missing_inputs}}, st}
      end
    end
  end

  test "a 1p1c package: the accepted child is not resubmitted nor put in rejects" do
    parent = tx(hashes(1, 7), 1)
    child = tx([parent.txid], 2)
    {:ok, mp} = PackageMempool.start_link({self(), parent.txid})
    {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)
    p = peer(r)

    :ok = TxRelay.received_tx(r, p, child)
    assert TxRelay.orphans(r) == [child.wtxid]
    :ok = TxRelay.received_tx(r, p, parent)
    _ = TxRelay.orphans(r)

    assert TxRelay.orphans(r) == []
    accepts = collect_accepts([])
    assert Enum.count(accepts, &(&1 == child.wtxid)) == 1, "child resubmitted after the package"
    st = :sys.get_state(r)
    refute MapSet.member?(st.rejects.set, child.wtxid)
  end

  defp collect_accepts(acc) do
    receive do
      {:accept, w} -> collect_accepts([w | acc])
    after
      0 -> acc
    end
  end

  # A mempool stub whose answers come from the test: `accept` and `package`
  # are functions of the tx (list); calls are reported to the test.
  defmodule ScriptedMempool do
    use GenServer
    def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
    def init({test, accept, package}), do: {:ok, %{test: test, accept: accept, package: package}}
    def handle_call({:has, _h, _k}, _f, st), do: {:reply, false, st}
    def handle_call({:has_many, _hs, _k}, _f, st), do: {:reply, MapSet.new(), st}

    def handle_call({:extract_best, txids, _n}, _f, st) do
      send(st.test, {:extract, txids})
      {:reply, {[], txids}, st}
    end

    def handle_call({:submit_package, txs}, _f, st) do
      send(st.test, {:package, Enum.map(txs, & &1.wtxid)})
      {:reply, st.package.(txs), st}
    end

    def handle_call({:accept, tx, _}, _f, st) do
      send(st.test, {:accept, tx.wtxid})
      {:reply, st.accept.(tx), st}
    end
  end

  defp scripted(
         accept,
         package \\ fn _ -> %{state: {:tx, "transaction failed", nil}, txs: %{}} end
       ) do
    {:ok, mp} = ScriptedMempool.start_link({self(), accept, package})
    {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)
    r
  end

  defp extracted?(txid) do
    receive do
      {:extract, txids} -> txid in txids or extracted?(txid)
    after
      0 -> false
    end
  end

  # TXR-1 (STATE_MACHINES.md): a failed 1p1c package can still have accepted
  # the parent alone (the child then fails on its own). TxRelay looked only
  # at the package state: the parent sat in the mempool unannounced (the
  # mempool's notification names TxRelay as origin, which TxRelay ignores)
  # and the invalid child stayed in the orphanage.
  test "a failed 1p1c package: the parent accepted alone is announced, the invalid child leaves the orphanage" do
    parent = tx(hashes(1, 21), 1)
    child = tx([parent.txid], 2)

    accept = fn
      %{txid: t} when t == parent.txid ->
        {:error, %{result: :reconsiderable, reason: "min relay fee not met"}}

      _ ->
        {:error, %{result: :missing_inputs}}
    end

    package = fn _ ->
      %{
        state: {:tx, "transaction failed", nil},
        txs: %{
          parent.wtxid => {:valid, %{}},
          child.wtxid =>
            {:invalid, %{result: :consensus, reason: "mandatory-script-verify-flag-failed"}}
        }
      }
    end

    r = scripted(accept, package)
    p = peer(r)
    :ok = TxRelay.received_tx(r, p, child)
    assert TxRelay.orphans(r) == [child.wtxid]
    :ok = TxRelay.received_tx(r, p, parent)
    assert_received {:package, _}

    assert TxRelay.orphans(r) == []
    assert extracted?(parent.txid), "the accepted parent was not queued for announcement"
    assert MapSet.member?(:sys.get_state(r).rejects.set, child.wtxid)
  end

  # MP-7 (STATE_MACHINES.md): an accept that finds its tx already added by
  # another submitter (RPC submitpackage during the script check) answers
  # txn-already-in-mempool; TxRelay put the in-mempool tx in `rejects`.
  test "txn-already-in-mempool is not a rejection" do
    a = tx(hashes(1, 22), 1)
    r = scripted(fn _ -> {:error, %{result: :conflict, reason: "txn-already-in-mempool"}} end)
    :ok = TxRelay.received_tx(r, peer(r), a)
    refute MapSet.member?(:sys.get_state(r).rejects.set, a.wtxid)
  end

  # MP-5 (STATE_MACHINES.md): "mempool busy" (and "tip-changed",
  # "script-check-crashed") describe the mempool at that moment. They were
  # cached as fee failures, so the tx was not fetched again until the next
  # block, and 128 pending REST submissions blacked out tx relay.
  test "a transient mempool answer is not cached: the tx is accepted when it comes again" do
    t = tx(hashes(1, 23), 1)
    child = tx([t.txid], 2)
    ctr = :counters.new(1, [])

    accept = fn
      %{txid: id} when id == t.txid ->
        :counters.add(ctr, 1, 1)

        if :counters.get(ctr, 1) == 1,
          do: {:error, %{result: :reconsiderable, reason: "mempool busy"}},
          else: {:ok, %{}}

      _ ->
        {:error, %{result: :missing_inputs}}
    end

    r = scripted(accept)
    p = peer(r)
    :ok = TxRelay.received_tx(r, p, child)
    :ok = TxRelay.received_tx(r, p, t)
    st = :sys.get_state(r)
    refute MapSet.member?(st.reconsiderable.set, t.wtxid)
    # No synchronous package evaluation either: that would skip the cap.
    refute_received {:package, _}

    :ok = TxRelay.received_tx(r, peer(r), t)
    assert extracted?(t.txid)
  end

  test "an orphan whose reconsideration gets a transient answer stays an orphan" do
    parent = tx(hashes(1, 24), 1)
    child = tx([parent.txid], 2)
    ctr = :counters.new(1, [])

    accept = fn
      %{txid: id} when id == parent.txid ->
        {:ok, %{}}

      _ ->
        :counters.add(ctr, 1, 1)

        if :counters.get(ctr, 1) == 1,
          do: {:error, %{result: :missing_inputs}},
          else: {:error, %{result: :reconsiderable, reason: "mempool busy"}}
    end

    r = scripted(accept)
    p = peer(r)
    :ok = TxRelay.received_tx(r, p, child)
    :ok = TxRelay.received_tx(r, p, parent)
    assert TxRelay.orphans(r) == [child.wtxid]
  end

  # MP-3 (STATE_MACHINES.md): a Mempool or TxRelay crash restarts only the
  # Relay subtree, so peers should stay connected; but a peer blocked in a
  # TxRelay call (or calling while the name is unregistered) exited with it.
  test "a peer blocked in a TxRelay call survives the relay's death; calls to a missing relay are neutral" do
    test = self()
    r = scripted(fn _ -> Process.sleep(:infinity) end)
    Process.unlink(r)
    t = tx(hashes(1, 25), 1)

    caller = spawn(fn -> send(test, {:result, TxRelay.received_tx(r, self(), t)}) end)
    ref = Process.monitor(caller)
    assert_receive {:accept, _}
    Process.exit(r, :kill)
    assert_receive {:result, :ok}
    assert_receive {:DOWN, ^ref, :process, _, :normal}

    item = %{type: :wtx, hash: t.wtxid}
    assert TxRelay.inv(:no_such_tx_relay, self(), [item]) == :ok
    assert TxRelay.notfound(:no_such_tx_relay, self(), [item]) == :ok
    assert TxRelay.feefilter(:no_such_tx_relay, self(), 1_000) == :ok
    assert TxRelay.lookup(:no_such_tx_relay, [item]) == {[], [item]}
    assert Exnode.Mempool.match_short_ids(:no_such_mempool, {0, 0}, MapSet.new()) == %{}
  end
end
