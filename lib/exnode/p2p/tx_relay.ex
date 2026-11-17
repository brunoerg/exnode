defmodule Exnode.P2P.TxRelay do
  @moduledoc """
  Transaction relay. The roles of Core v32.1 `node/txdownloadman_impl.cpp`
  (with `txrequest.cpp` and `node/txorphanage.cpp`) and of the tx-inventory
  part of `PeerManagerImpl::SendMessages` (net_processing.cpp).

  Receiving:
  * Announcements are tracked per peer (`AddTxAnnouncement`). Delays are 2 s
    for non-preferred (inbound) peers and 2 s for txid announcements while
    any wtxid-relay peer exists. Only one getdata per tx is in flight;
    another announcer is tried after `GETDATA_TX_INTERVAL` (60 s).
  * A received tx goes to the mempool. If it is accepted, it is announced to
    the other peers, and orphans waiting on it are reconsidered. If its
    inputs are missing, it becomes an orphan and its parents are requested
    from the announcers (`MempoolRejectedTx`). If it is rejected but
    reconsiderable (fee), it goes in the reconsiderable filter, and a child
    in the orphanage from the same peer is tried as a 1p1c package
    (`Find1P1CPackage`). Other rejections go in the recent-rejects filter
    (wtxid; also txid for non-standard inputs with a witness).
  * Recent rejects reset on every tip change. Recently confirmed txs are
    remembered until a disconnect.

  Sending (trickle): each peer's queued txs are announced at exponentially
  spaced intervals (2 s outbound, 5 s inbound), parents first, skipping txs
  below the peer's feefilter and txs it already knows (`MSG_WTX` to
  wtxid-relay peers, `MSG_TX` to the others).

  Approximations: the orphanage limits are a count cap, a per-peer weight
  cap and Core's global latency score cap (`DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE`),
  trimmed from the peer with the highest latency score rather than Core's
  DoS-score heap, and the
  filters are exact sets bounded by FIFO eviction rather than rolling bloom
  filters. That includes each peer's known-inventory set (Core
  `m_tx_inventory_known_filter`, 50,000 entries): when it is full the
  oldest hash is forgotten, so an old tx may be announced to that peer again
  (extra bandwidth only).

  Cost per message: announcements are kept per peer (`ann`: peer => hash =>
  entry), so the per-peer cap is an O(1) check; the in-flight count is a
  per-peer counter (Core `CountInFlight`), and the mempool membership of all
  announced hashes is computed once per `inv` (one mempool call per hash
  kind), not once per item.

  Cost per tick: proportional to the work due, not to the announcements
  held (Core's txrequest.cpp indexes by time for the same reason). `ann` is
  the source of truth; beside it, a time-ordered `ready` queue of candidates
  and an `expiry` queue of requests. Queue entries are checked against `ann`
  when popped (stale ones are skipped). A ready candidate whose hash is
  already requested from another peer waits under that hash (`waiting`) and
  is queued again when the request ends.

  Backpressure: `inv/3` and `received_tx/3` are calls, so a peer handles one
  such message at a time and does not read its socket meanwhile; TCP's
  receive window then holds back the sender, as Core's `fPauseRecv` does
  (net.cpp, `DEFAULT_MAXRECEIVEBUFFER`) while `ProcessMessage` runs inline.
  """
  use GenServer

  alias Exnode.P2P.InvBucket
  require Logger

  alias Exnode.Mempool

  @tick_ms 100
  @nonpref_delay 2_000
  @txid_relay_delay 2_000
  @overloaded_delay 2_000
  @getdata_interval 60_000
  @max_announcements 5_000
  @max_in_flight 100
  @inbound_interval_ms 5_000
  @outbound_interval_ms 2_000
  @max_inv_sz 50_000
  @max_orphans 1_000
  @orphan_peer_weight 404_000
  # Core DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE: one per announcement plus one
  # per 10 inputs of each unique orphan (TxOrphanageImpl latency score).
  @max_orphan_score 3_000
  @filter_cap 120_000
  # Core: m_tx_inventory_known_filter{50000, 0.000001} (net_processing.cpp).
  @known_cap 50_000

  # Mempool answers about its own state at that moment (MP-5 in
  # STATE_MACHINES.md), not about the tx: caching them as fee failures
  # suppressed the tx until the next block, and 128 pending REST
  # submissions made every relayed tx "busy". Core has no such answers.
  @transient ["mempool busy", "tip-changed", "script-check-crashed"]

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  # --- API used by peers -------------------------------------------------------

  @doc "`info`: `%{wtxid_relay, preferred, relay_txs, inbound}`."
  def connected(server, peer, info), do: GenServer.cast(server, {:connected, peer, info})

  @doc """
  A peer's tx announcements. A call (`:ok`), so the peer waits as Core's
  `ProcessMessage` runs inline (no timeout; the peer's inactivity timeout
  bounds it).
  """
  def inv(server, peer, items), do: peer_call(server, {:inv, peer, items}, :ok)

  @doc "A tx a peer sent: `ProcessTransaction` inline, as `inv/3` (`:ok`)."
  def received_tx(server, peer, tx), do: peer_call(server, {:tx, peer, tx}, :ok)

  @doc """
  A peer's notfound tx items (Core ReceivedNotFound). A call, as `inv/3`: the
  peer waits, so a flood cannot pile up in TxRelay's mailbox while it is busy.
  """
  def notfound(server, peer, items),
    do: peer_call(server, {:notfound, peer, items}, :ok)

  @doc "A peer's feefilter (already MoneyRange-checked). A call, as `notfound/3`."
  def feefilter(server, peer, rate),
    do: peer_call(server, {:feefilter, peer, rate}, :ok)

  @doc """
  For getdata: the mempool txs among `items` (`%{type: :tx | :wtx, hash}`), `{found, missing}`.
  Waits like Core's peer thread on `cs_main` (no timeout); the peer's inactivity timeout bounds it.
  """
  def lookup(server, items), do: peer_call(server, {:lookup, items}, {[], items})

  # A Mempool or TxRelay crash restarts only the Relay subtree and peers stay
  # connected (they register again on `:tx_relay_resync`). A peer blocked in
  # one of these calls, or calling while the name is unregistered, used to
  # exit with the server: every busy peer was dropped (MP-3 in
  # STATE_MACHINES.md). It gets a neutral answer instead: the tx, inv or
  # notfound is lost, as when Core drops a message, and getdata items are
  # answered notfound. A late reply cannot arrive (calls use an alias).
  defp peer_call(server, msg, fallback) do
    GenServer.call(server, msg, :infinity)
  catch
    :exit, _ -> fallback
  end

  @doc "Announce a tx accepted outside P2P (e.g. RPC) to every peer."
  def announce(server, tx), do: GenServer.cast(server, {:announce, tx, nil})

  def orphans(server), do: GenServer.call(server, :orphans, 5_000)

  @impl true
  def init(opts) do
    {:ok,
     %{
       mempool: Keyword.fetch!(opts, :mempool),
       peers: %{},
       # peer => %{hash => %{kind, preferred, ready_at, seq, state, expiry}};
       # state :candidate, :requested or :completed (Core COMPLETED: answered,
       # notfound or expired; kept so the peer's re-announcement is a no-op).
       ann: %{},
       # hash => MapSet of the peers with an announcement of it, any state
       # (Core's ByTxHash index: is this the last uncompleted one?).
       ann_peers: %{},
       ann_seq: 0,
       # {ready_at, seq} => {peer, hash}: candidates by the time they become ready.
       ready: :gb_trees.empty(),
       # {expiry, seq} => {peer, hash}: requests by the time they expire.
       expiry: :gb_trees.empty(),
       # hash => peer: the one request in flight per hash (Core REQUESTED).
       requested: %{},
       # hash => [{ready_at, seq, peer}]: ready candidates behind that request.
       waiting: %{},
       # peer => requests in flight (Core CountInFlight), absent when 0.
       in_flight: %{},
       tick_ms: Keyword.get(opts, :tick_ms, @tick_ms),
       rejects: new_filter(),
       reconsiderable: new_filter(),
       confirmed: new_filter(),
       # wtxid => %{tx, announcers, seq, weight}
       orphans: %{},
       # parent txid => MapSet of orphan wtxids spending it (Core
       # m_outpoint_to_orphan_wtxids, by txid): children are found without
       # scanning every orphan input. Only orphan_put/3 and
       # orphans_drop/2 change `orphans`, and they keep this in step.
       orphan_by_parent: %{},
       orphan_seq: 0,
       # Kept in step with `orphans` by orphan_put/3, orphans_drop/2 and the
       # announcer helpers, so the limits are checked without walking every
       # (orphan, announcer) pair (Core m_peer_orphanage_info):
       # {seq, wtxid} of every orphan, oldest first.
       orphan_order: :gb_sets.empty(),
       # peer => %{weight, score, anns: gb_set of {seq, wtxid}}, absent when empty.
       orphan_peers: %{},
       # Core TotalLatencyScore: announcements + unique orphans' input scores.
       orphan_score: 0,
       # Orphans to reconsider (Core AddChildrenToWorkSet / ProcessOrphanTx):
       # peer => queue of wtxids assigned to it, the peers with work in
       # round-robin order, and every queued wtxid (Core
       # m_reconsiderable_wtxids: queued at most once). Drained one step at a
       # time by :orphan_work messages, so the calls TxRelay serves interleave.
       orphan_work: %{},
       orphan_work_peers: :queue.new(),
       orphan_work_set: MapSet.new(),
       orphan_work_scheduled: false,
       now: Keyword.get(opts, :clock, fn -> System.monotonic_time(:millisecond) end),
       # Core InvToSendBucket: global announcement backlogs and token buckets,
       # one for inbound peers and one for outbound (rate x 2.5).
       inv_in: InvBucket.new(Keyword.get(opts, :tx_send_rate, InvBucket.default_rate()), 1.0),
       inv_out:
         InvBucket.new(
           Keyword.get(opts, :tx_send_rate, InvBucket.default_rate()),
           InvBucket.outbound_mult()
         ),
       # txid => the peer it came from (not announced back to it)
       inv_source: %{},
       tip: nil
     }
     |> tap(&schedule_tick/1)
     |> tap(fn _ -> resync_peers(Keyword.get(opts, :peer_sup)) end)}
  end

  # Request expiry, getdata, the inv backlog and the trickle, at the clock's now.
  defp tick(st) do
    now = st.now.()
    st |> expire_requests(now) |> send_requests(now) |> process_inv_backlog(now) |> trickle(now)
  end

  # `tick_ms: nil` (tests) leaves ticks to the caller.
  defp schedule_tick(%{tick_ms: nil}), do: :ok
  defp schedule_tick(st), do: Process.send_after(self(), :tick, st.tick_ms)

  # TxRelay restarts without the peers (its own subtree, with the
  # mempool), so after a restart it knows none of them. Every live peer is
  # asked to register again (`:tx_relay_resync`); peers that have not
  # finished the handshake ignore it and register when they do. At boot the
  # peer supervisor does not exist yet.
  defp resync_peers(nil), do: :ok

  defp resync_peers(peer_sup) do
    if GenServer.whereis(peer_sup) do
      for {_, pid, _, _} <- DynamicSupervisor.which_children(peer_sup),
          is_pid(pid),
          do: send(pid, :tx_relay_resync)
    end

    :ok
  catch
    # The peer supervisor is itself restarting: its new peers register at handshake.
    :exit, _ -> :ok
  end

  # --- filters (bounded sets) ---------------------------------------------------

  defp new_filter, do: %{set: MapSet.new(), queue: :queue.new()}

  defp f_insert(f, h, cap \\ @filter_cap) do
    if MapSet.member?(f.set, h) do
      f
    else
      f = %{set: MapSet.put(f.set, h), queue: :queue.in(h, f.queue)}

      if MapSet.size(f.set) > cap do
        {{:value, old}, q} = :queue.out(f.queue)
        %{set: MapSet.delete(f.set, old), queue: q}
      else
        f
      end
    end
  end

  defp f_has?(f, h), do: MapSet.member?(f.set, h)

  # --- casts ---------------------------------------------------------------------

  @impl true
  def handle_cast({:connected, peer, info}, st) do
    Process.monitor(peer)
    now = st.now.()

    p =
      Map.merge(
        %{known: new_filter(), to_send: [], feefilter: 0, next_inv_at: now + inv_delay(info)},
        info
      )

    send(peer, {:send, {:feefilter, Exnode.Mempool.Policy.default_min_relay_tx_fee()}})
    {:noreply, %{st | peers: Map.put(st.peers, peer, p)}}
  end

  def handle_cast({:announce, tx, source}, st), do: {:noreply, queue_announce(st, tx, source)}

  @impl true
  def handle_call({:inv, peer, items}, _from, st) do
    case st.peers[peer] do
      nil ->
        {:reply, :ok, st}

      p ->
        # Core: wtxid-relay peers announce MSG_WTX only; the others MSG_TX only.
        # A repeated item changes nothing after its first occurrence (Core's
        # ReceivedInv / AddAnnouncer are idempotent per peer), so duplicates
        # are dropped up front rather than re-running the orphan-parent work
        # for each copy.
        items =
          items
          |> Enum.filter(fn i ->
            (p.wtxid_relay and i.type == :wtx) or (not p.wtxid_relay and i.type == :tx)
          end)
          |> Enum.uniq_by(&{&1.type, &1.hash})

        # Bounded (Core m_tx_inventory_known_filter): oldest hashes are forgotten.
        peers =
          put_in(
            st.peers,
            [peer, :known],
            Enum.reduce(items, p.known, &f_insert(&2, &1.hash, @known_cap))
          )

        st = %{st | peers: peers}

        # Invariant over one inv, so computed once: the peer's in-flight count
        # (only send_requests/2, on the tick, marks entries :requested), whether
        # any wtxid-relay peer exists, and mempool membership of the announced
        # hashes (one call per kind). The membership view may be slightly stale
        # against concurrent accepts: at worst one superfluous getdata, which is
        # answered or expires.
        ctx = %{
          in_flight: Map.get(st.in_flight, peer, 0),
          any_wtxid_relay: Enum.any?(st.peers, fn {_, q} -> q.wtxid_relay end),
          # Also the parents of announced orphans this peer is not yet an
          # announcer of: one batched lookup instead of a call per parent.
          in_mempool:
            prefetch_mempool(
              st,
              Enum.map(items, &{kind(&1.type), &1.hash}) ++
                orphan_parent_gtxids(st, peer, items)
            )
        }

        score_before = st.orphan_score
        st = Enum.reduce(items, st, &add_announcement(&2, peer, {kind(&1.type), &1.hash}, ctx))

        # Core AddAnnouncer -> LimitOrphans: a new announcer is charged the
        # orphan's weight and score, so the limits are re-checked (once per inv).
        st = if st.orphan_score == score_before, do: st, else: limit_orphans(st)
        {:reply, :ok, st}
    end
  end

  def handle_call({:tx, peer, tx}, _from, st), do: {:reply, :ok, received_tx_impl(st, peer, tx)}

  # Core ReceivedNotFound -> TxRequestTracker::ReceivedResponse.
  def handle_call({:notfound, peer, items}, _from, st),
    do: {:reply, :ok, Enum.reduce(items, st, &ann_complete(&2, peer, &1.hash))}

  def handle_call({:feefilter, peer, rate}, _from, st) do
    if Map.has_key?(st.peers, peer),
      do: {:reply, :ok, put_in(st.peers[peer].feefilter, rate)},
      else: {:reply, :ok, st}
  end

  def handle_call({:lookup, items}, _from, st) do
    # One mempool call for the whole getdata.
    {txs, missing} = Mempool.get_txs(st.mempool, items)
    # Core ProcessGetData: a tx requested by a peer leaves the unbroadcast set.
    if txs != [], do: Mempool.remove_unbroadcast(st.mempool, Enum.map(txs, & &1.txid))
    {:reply, {txs, missing}, st}
  end

  def handle_call(:orphans, _from, st), do: {:reply, Map.keys(st.orphans), st}

  @impl true
  def handle_info(:tick, st) do
    schedule_tick(st)
    {:noreply, tick(st)}
  end

  # Exnode.Clock.tick/2: the same pass, now.
  def handle_info({Exnode.Clock, :tick, from, ref}, st) do
    st = tick(st)
    Exnode.Clock.ticked({from, ref})
    {:noreply, st}
  end

  # Mempool listener: a tx entered the mempool (from anywhere).
  # `origin` is the process that submitted the tx. Ours were already queued,
  # with their source peer, by `accepted/3`.
  def handle_info({:mempool_accepted, _tx, _res, origin}, st) when origin == self(),
    do: {:noreply, st}

  def handle_info({:mempool_accepted, tx, _res, _origin}, st),
    do: {:noreply, queue_announce(st, tx, nil)}

  # Mempool listener: block events.
  def handle_info({:mempool_block, :connected, txs, tip}, st) do
    st =
      if tip != st.tip,
        do: %{st | rejects: new_filter(), reconsiderable: new_filter(), tip: tip},
        else: st

    confirmed =
      Enum.reduce(txs, st.confirmed, fn t, f -> f |> f_insert(t.txid) |> f_insert(t.wtxid) end)

    hashes = MapSet.new(Enum.flat_map(txs, &[&1.txid, &1.wtxid]))
    spent = MapSet.new(Enum.flat_map(txs, & &1.prevouts))

    # EraseForBlock: orphans confirmed or conflicting with the block. The
    # conflicting ones are found through the index of their parents.
    conflicting =
      for {prev, _} = op <- spent,
          w <- Map.get(st.orphan_by_parent, prev, []),
          Enum.any?(st.orphans[w].tx.inputs, &({&1.prev_hash, &1.prev_index} == op)),
          do: w

    confirmed_orphans = Enum.filter(hashes, &Map.has_key?(st.orphans, &1))
    st = orphans_drop(%{st | confirmed: confirmed}, Enum.uniq(conflicting ++ confirmed_orphans))
    st = ann_delete_hashes(st, hashes)
    # AddChildrenToWorkSet: orphans spending the block's txs.
    {:noreply, add_children_to_work_set(st, Enum.map(txs, & &1.txid))}
  end

  def handle_info({:mempool_block, :disconnected}, st),
    do:
      {:noreply,
       %{st | confirmed: new_filter(), rejects: new_filter(), reconsiderable: new_filter()}}

  # Core EraseForPeer: the peer's announcements go; orphans left with none go too.
  def handle_info(:orphan_work, st) do
    st = %{st | orphan_work_scheduled: false}
    {:noreply, st |> orphan_work_step() |> schedule_orphan_work()}
  end

  def handle_info({:DOWN, _, :process, peer, _}, st) do
    st =
      case st.orphan_peers do
        %{^peer => %{anns: anns}} ->
          anns
          |> :gb_sets.to_list()
          |> Enum.reduce(st, fn {_, w}, st -> orphan_announcer_del(st, w, peer) end)

        _ ->
          st
      end

    {:noreply, st |> drop_orphan_work(peer) |> drop_peer(peer)}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  # --- announcements and requests (txrequest.cpp role) ---------------------------

  defp kind(:wtx), do: :wtxid
  defp kind(_), do: :txid

  # Core: AlreadyHaveTx. `in_mempool`: a prefetched membership view
  # (`prefetch_mempool/2`), else one mempool call.
  defp already_have?(st, {kind, h}, include_reconsiderable, in_mempool \\ nil) do
    Map.has_key?(st.orphans, h) or (include_reconsiderable and f_has?(st.reconsiderable, h)) or
      f_has?(st.confirmed, h) or f_has?(st.rejects, h) or
      if(in_mempool,
        do: MapSet.member?(in_mempool[kind], h),
        else: Mempool.has?(st.mempool, h, kind)
      )
  end

  # Mempool membership of `{kind, hash}` pairs: at most one call per kind.
  defp prefetch_mempool(st, gtxids) do
    by_kind = Enum.group_by(gtxids, &elem(&1, 0), &elem(&1, 1))

    Map.new([:txid, :wtxid], fn kind ->
      case Map.get(by_kind, kind, []) do
        [] -> {kind, MapSet.new()}
        hs -> {kind, Mempool.has_many?(st.mempool, Enum.uniq(hs), kind)}
      end
    end)
  end

  defp unique_parents(tx), do: tx.inputs |> Enum.map(& &1.prev_hash) |> Enum.uniq()

  # `{:txid, parent}` for every orphan named in `items` (MSG_WTX) that `peer`
  # is not already an announcer of: the only parents add_announcement/4 looks up.
  defp orphan_parent_gtxids(st, peer, items) do
    for %{type: :wtx, hash: h} <- items,
        o = st.orphans[h],
        o != nil and not MapSet.member?(o.announcers, peer),
        parent <- unique_parents(o.tx),
        uniq: true,
        do: {:txid, parent}
  end

  # Core: AddTxAnnouncement
  defp add_announcement(st, peer, {kind, h} = gtxid, ctx) do
    cond do
      kind == :wtxid and Map.has_key?(st.orphans, h) ->
        o = st.orphans[h]

        cond do
          # Core MaybeAddOrphanResolutionCandidate: HaveTxFromPeer -> nothing
          # to add; and Count + parents > MAX_PEER_TX_ANNOUNCEMENTS -> refused.
          # Both outcomes leave the state unchanged whatever the parents are,
          # so they are decided before any parent lookup.
          MapSet.member?(o.announcers, peer) or ann_count(st, peer) >= @max_announcements ->
            st

          true ->
            parents =
              o.tx
              |> unique_parents()
              |> Enum.reject(&already_have?(st, {:txid, &1}, false, ctx.in_mempool))

            cond do
              parents == [] ->
                st

              ann_count(st, peer) + length(parents) > @max_announcements ->
                st

              true ->
                st
                |> add_parent_requests(peer, parents)
                |> orphan_announcer_add(h, peer)
            end
        end

      already_have?(st, gtxid, true, ctx.in_mempool) ->
        st

      true ->
        p = st.peers[peer]

        # Core: MAX_PEER_TX_ANNOUNCEMENTS (an O(1) count per peer).
        if ann_count(st, peer) >= @max_announcements do
          st
        else
          delay =
            if(p.preferred, do: 0, else: @nonpref_delay) +
              if(kind == :txid and ctx.any_wtxid_relay, do: @txid_relay_delay, else: 0) +
              if(ctx.in_flight >= @max_in_flight, do: @overloaded_delay, else: 0)

          put_ann(st, peer, gtxid, p.preferred, st.now.() + delay)
        end
    end
  end

  defp put_ann(st, peer, {kind, h}, preferred, ready_at) do
    if Map.has_key?(Map.get(st.ann, peer, %{}), h) do
      st
    else
      a = %{
        kind: kind,
        preferred: preferred,
        ready_at: ready_at,
        seq: st.ann_seq,
        state: :candidate,
        expiry: nil
      }

      %{
        st
        | ann: ann_put(st.ann, peer, h, a),
          ann_peers: Map.update(st.ann_peers, h, MapSet.new([peer]), &MapSet.put(&1, peer)),
          ann_seq: st.ann_seq + 1,
          ready: :gb_trees.enter({ready_at, a.seq}, {peer, h}, st.ready)
      }
    end
  end

  # --- the announcement map: peer => %{hash => entry} -------------------------

  defp ann_count(st, peer), do: map_size(Map.get(st.ann, peer, %{}))

  defp ann_put(ann, peer, h, a), do: Map.update(ann, peer, %{h => a}, &Map.put(&1, h, a))

  # Core MakeCompleted (a response, a notfound, an expired request): the
  # peer's announcement of `h` becomes :completed, so its re-announcement is a
  # no-op (Core ReceivedInv), and a request it held frees the hash for
  # another announcer. If it was the last uncompleted announcement of `h`,
  # every announcement of `h` is forgotten. An absent one is a no-op.
  defp ann_complete(st, peer, h) do
    case st.ann do
      %{^peer => %{^h => %{state: :completed}}} ->
        st

      %{^peer => %{^h => a}} ->
        st = if a.state == :requested, do: release(st, peer, h), else: st
        # Completed before anything else looks at it: a request already
        # released must not be counted again by ann_delete_hashes/2.
        st = %{st | ann: ann_put(st.ann, peer, h, %{a | state: :completed})}
        if only_uncompleted?(st, peer, h), do: ann_delete_hashes(st, [h]), else: st

      _ ->
        st
    end
  end

  # Core IsOnlyNonCompleted: every other announcement of `h` is :completed.
  defp only_uncompleted?(st, peer, h) do
    st.ann_peers
    |> Map.get(h, MapSet.new())
    |> Enum.all?(fn p ->
      p == peer or match?(%{^h => %{state: :completed}}, Map.get(st.ann, p, %{}))
    end)
  end

  # Removes one announcement, whatever its state.
  defp ann_erase(st, peer, h) do
    case st.ann do
      %{^peer => %{^h => _} = m} ->
        peers = MapSet.delete(Map.get(st.ann_peers, h, MapSet.new()), peer)

        %{
          st
          | ann: put_peer(st.ann, peer, Map.delete(m, h)),
            ann_peers:
              if(MapSet.size(peers) == 0,
                do: Map.delete(st.ann_peers, h),
                else: Map.put(st.ann_peers, h, peers)
              )
        }

      _ ->
        st
    end
  end

  # Across all peers. No announcement of these hashes is left, so nothing
  # waits on their requests.
  defp ann_delete_hashes(st, hashes) do
    # Unique: a non-witness tx's txid is its wtxid.
    hs = Enum.uniq(hashes)

    {ann, in_flight} =
      Enum.reduce(st.ann, {st.ann, st.in_flight}, fn {peer, m}, {acc, inf} ->
        n = Enum.count(hs, &match?(%{state: :requested}, Map.get(m, &1)))
        {put_peer(acc, peer, Map.drop(m, hs)), dec_in_flight(inf, peer, n)}
      end)

    %{
      st
      | ann: ann,
        ann_peers: Map.drop(st.ann_peers, hs),
        in_flight: in_flight,
        requested: Map.drop(st.requested, hs),
        waiting: Map.drop(st.waiting, hs)
    }
  end

  defp put_peer(ann, peer, m) when map_size(m) == 0, do: Map.delete(ann, peer)
  defp put_peer(ann, peer, m), do: Map.put(ann, peer, m)

  # Core DisconnectedPeer: each announcement is completed (a request it held
  # frees its hash; the last uncompleted one of a hash forgets them all),
  # then removed.
  defp drop_peer(st, peer) do
    st =
      Map.get(st.ann, peer, %{})
      |> Map.keys()
      |> Enum.reduce(st, fn h, st -> st |> ann_complete(peer, h) |> ann_erase(peer, h) end)

    %{
      st
      | peers: Map.delete(st.peers, peer),
        ann: Map.delete(st.ann, peer),
        in_flight: Map.delete(st.in_flight, peer)
    }
  end

  # A request ends (answered, notfound, expired, peer gone; the caller drops
  # the `ann` entry): the hash may be requested again, so the candidates
  # waiting on it are ready again (at their own ready_at, already past).
  defp release(st, peer, h) do
    ready =
      Enum.reduce(Map.get(st.waiting, h, []), st.ready, fn {ready_at, seq, p}, t ->
        :gb_trees.enter({ready_at, seq}, {p, h}, t)
      end)

    %{
      st
      | requested: Map.delete(st.requested, h),
        waiting: Map.delete(st.waiting, h),
        ready: ready,
        in_flight: dec_in_flight(st.in_flight, peer, 1)
    }
  end

  defp dec_in_flight(inf, _peer, 0), do: inf

  defp dec_in_flight(inf, peer, n) do
    case Map.get(inf, peer, 0) - n do
      c when c <= 0 -> Map.delete(inf, peer)
      c -> Map.put(inf, peer, c)
    end
  end

  # Core: MaybeAddOrphanResolutionCandidate: request the orphan's parents (by txid).
  defp add_parent_requests(st, peer, parents) do
    case st.peers[peer] do
      nil ->
        st

      p ->
        delay =
          if(p.preferred, do: 0, else: @nonpref_delay) +
            if(Enum.any?(st.peers, fn {_, q} -> q.wtxid_relay end),
              do: @txid_relay_delay,
              else: 0
            )

        # Core routes these through AddTxAnnouncement, so the same per-peer cap
        # (MAX_PEER_TX_ANNOUNCEMENTS) applies; parents beyond it are skipped
        # (the orphan stays and may get them requested later).
        Enum.reduce(parents, st, fn h, st ->
          if ann_count(st, peer) >= @max_announcements,
            do: st,
            else: put_ann(st, peer, {:txid, h}, p.preferred, st.now.() + delay)
        end)
    end
  end

  # Requests that went unanswered past GETDATA_TX_INTERVAL are dropped, so
  # another announcer becomes eligible (in this same tick: its candidates are
  # queued again before `send_requests/2`). Only due entries are visited.
  defp expire_requests(st, now) do
    case pop_before(st.expiry, fn {expiry, _} -> expiry < now end) do
      nil ->
        st

      {{_, seq}, {peer, h}, expiry} ->
        st = %{st | expiry: expiry}

        case st.ann do
          # Core: an expired REQUESTED announcement becomes COMPLETED.
          %{^peer => %{^h => %{state: :requested, seq: ^seq}}} ->
            expire_requests(ann_complete(st, peer, h), now)

          _ ->
            expire_requests(st, now)
        end
    end
  end

  # The smallest entry of `tree` if `due?.(key)`: `{key, value, rest}`, else nil.
  defp pop_before(tree, due?) do
    if :gb_trees.is_empty(tree) do
      nil
    else
      {k, _} = :gb_trees.smallest(tree)
      if due?.(k), do: :gb_trees.take_smallest(tree), else: nil
    end
  end

  # The candidates ready by `now` that are still current: `{hash, peer, entry}`.
  defp pop_ready(st, now, acc \\ []) do
    case pop_before(st.ready, fn {ready_at, _} -> ready_at <= now end) do
      nil ->
        {st, acc}

      {{_, seq}, {peer, h}, ready} ->
        st = %{st | ready: ready}

        case st.ann do
          %{^peer => %{^h => %{state: :candidate, seq: ^seq} = a}}
          when is_map_key(st.peers, peer) ->
            pop_ready(st, now, [{h, peer, a} | acc])

          _ ->
            pop_ready(st, now, acc)
        end
    end
  end

  # Core: GetRequestsToSend. Per tx hash: nothing if a request is in flight;
  # else the best ready candidate: preferred first, then first announced.
  # Every ready candidate of a hash is either popped now or waiting on its
  # request, so choosing among the popped ones is choosing among all.
  defp send_requests(st, now) do
    {st, due} = pop_ready(st, now)

    # Per tx hash, the best ready announcement; the others (and all of them
    # when a request is in flight) wait on that hash's request.
    {picks, st} =
      due
      |> Enum.group_by(&elem(&1, 0), fn {_, p, a} -> {p, a} end)
      |> Enum.reduce({[], st}, fn {h, anns}, {picks, st} ->
        if Map.has_key?(st.requested, h) do
          {picks, wait(st, h, anns)}
        else
          {peer, a} = best = Enum.min_by(anns, fn {_, a} -> {not a.preferred, a.seq} end)
          {[{h, peer, a} | picks], wait(st, h, List.delete(anns, best))}
        end
      end)

    # One mempool call per kind for all candidates of this tick.
    in_mempool = prefetch_mempool(st, Enum.map(picks, fn {h, _, a} -> {a.kind, h} end))

    {st, per_peer} =
      Enum.reduce(picks, {st, %{}}, fn {h, peer, a}, {st, per_peer} ->
        if already_have?(st, {a.kind, h}, false, in_mempool) do
          {ann_delete_hashes(st, [h]), per_peer}
        else
          expiry = now + @getdata_interval

          st = %{
            st
            | ann: ann_put(st.ann, peer, h, %{a | state: :requested, expiry: expiry}),
              requested: Map.put(st.requested, h, peer),
              in_flight: Map.update(st.in_flight, peer, 1, &(&1 + 1)),
              expiry: :gb_trees.enter({expiry, a.seq}, {peer, h}, st.expiry)
          }

          # Core: MSG_WTX for wtxids; MSG_WITNESS_TX for txids.
          item = %{
            type: if(a.kind == :wtxid, do: :wtx, else: :tx),
            witness: a.kind == :txid,
            hash: h
          }

          {st, Map.update(per_peer, peer, [item], &[item | &1])}
        end
      end)

    for {peer, items} <- per_peer, do: send(peer, {:send, {:getdata, Enum.reverse(items)}})
    st
  end

  defp wait(st, _h, []), do: st

  defp wait(st, h, anns) do
    parked = for {p, a} <- anns, do: {a.ready_at, a.seq, p}
    %{st | waiting: Map.update(st.waiting, h, parked, &(parked ++ &1))}
  end

  # --- receiving a tx -------------------------------------------------------------

  # Core: ReceivedTx, then ProcessTransaction and MempoolAcceptedTx / MempoolRejectedTx.
  defp received_tx_impl(st, peer, tx) do
    # ReceivedResponse: the request is answered.
    st = st |> ann_complete(peer, tx.txid) |> ann_complete(peer, tx.wtxid)

    cond do
      already_have?(st, {:wtxid, tx.wtxid}, false) ->
        st

      f_has?(st.reconsiderable, tx.wtxid) ->
        try_1p1c(st, tx, peer)

      true ->
        process_tx(st, peer, tx, true)
    end
  end

  defp process_tx(st, peer, tx, first_time) do
    case Mempool.accept(st.mempool, tx) do
      # Core: pfrom.m_last_tx_time for a tx from this peer's own TX message (eviction).
      {:ok, _res} ->
        if is_pid(peer), do: send(peer, :novel_tx)
        accepted(st, tx, peer)

      {:error, e} ->
        rejected(st, tx, e, peer, first_time)
    end
  end

  # Core: MempoolAcceptedTx
  defp accepted(st, tx, peer) do
    st = ann_delete_hashes(orphans_drop(st, [tx.wtxid]), [tx.txid, tx.wtxid])
    st = queue_announce(st, tx, peer)
    add_children_to_work_set(st, [tx.txid])
  end

  # Core AddChildrenToWorkSet: each orphan spending `txids` goes to the work
  # set of one of its announcers, chosen at random, unless already queued.
  # Reconsidering it costs a mempool accept with script checks, so nothing
  # is reconsidered here: the work is drained by :orphan_work steps (AUD-A4-2).
  defp add_children_to_work_set(st, txids) do
    st
    |> orphan_children(txids)
    |> Enum.sort_by(fn {_, o} -> o.seq end)
    |> Enum.reduce(st, fn {w, o}, st ->
      if MapSet.member?(st.orphan_work_set, w),
        do: st,
        else: enqueue_orphan_work(st, w, random_announcer(o))
    end)
    |> schedule_orphan_work()
  end

  defp random_announcer(o) do
    case MapSet.to_list(o.announcers) do
      [] -> nil
      peers -> Enum.random(peers)
    end
  end

  defp enqueue_orphan_work(st, w, peer) do
    {q, peers} =
      case st.orphan_work do
        %{^peer => q} -> {q, st.orphan_work_peers}
        _ -> {:queue.new(), :queue.in(peer, st.orphan_work_peers)}
      end

    %{
      st
      | orphan_work: Map.put(st.orphan_work, peer, :queue.in(w, q)),
        orphan_work_peers: peers,
        orphan_work_set: MapSet.put(st.orphan_work_set, w)
    }
  end

  # One :orphan_work message in the mailbox at a time, behind the calls
  # already waiting.
  defp schedule_orphan_work(%{orphan_work_scheduled: false, orphan_work: work} = st)
       when map_size(work) > 0 do
    send(self(), :orphan_work)
    %{st | orphan_work_scheduled: true}
  end

  defp schedule_orphan_work(st), do: st

  # Core ProcessOrphanTx for the next peer in turn: its work set until one
  # orphan gets a decisive answer (a missing-inputs one is cheap, and the
  # loop goes on). The peer goes to the back of the line if work remains.
  defp orphan_work_step(st) do
    case :queue.out(st.orphan_work_peers) do
      {:empty, _} ->
        st

      {{:value, peer}, rest} ->
        st = process_peer_orphan_work(%{st | orphan_work_peers: rest}, peer)

        if Map.has_key?(st.orphan_work, peer) and not :queue.member(peer, st.orphan_work_peers),
          do: %{st | orphan_work_peers: :queue.in(peer, st.orphan_work_peers)},
          else: st
    end
  end

  defp process_peer_orphan_work(st, peer) do
    case :queue.out(Map.get(st.orphan_work, peer, :queue.new())) do
      {:empty, _} ->
        %{st | orphan_work: Map.delete(st.orphan_work, peer)}

      {{:value, w}, rest} ->
        work =
          if :queue.is_empty(rest),
            do: Map.delete(st.orphan_work, peer),
            else: Map.put(st.orphan_work, peer, rest)

        st = %{st | orphan_work: work, orphan_work_set: MapSet.delete(st.orphan_work_set, w)}

        case reconsider_orphan(st, w, peer) do
          {:decisive, st} -> st
          {:continue, st} -> process_peer_orphan_work(st, peer)
        end
    end
  end

  # One orphan of the work set. Gone meanwhile (accepted another way,
  # evicted, confirmed): nothing to do.
  defp reconsider_orphan(st, w, peer) do
    case st.orphans do
      %{^w => o} ->
        st = orphans_drop(st, [w])

        case Mempool.accept(st.mempool, o.tx) do
          {:ok, _} ->
            {:decisive, accepted(st, o.tx, peer)}

          {:error, %{result: :missing_inputs}} ->
            {:continue, orphan_put(st, w, o)}

          # Not a verdict on the orphan: keep it for the next parent or retry (MP-5).
          {:error, e} when e.result == :reconsiderable and e.reason in @transient ->
            {:decisive, orphan_put(st, w, o)}

          {:error, e} ->
            {:decisive, rejected(st, o.tx, e, peer, false)}
        end

      _ ->
        {:continue, st}
    end
  end

  # Core EraseForPeer: a peer's reconsideration marks go with it.
  defp drop_orphan_work(st, peer) do
    case Map.pop(st.orphan_work, peer) do
      {nil, _} ->
        st

      {q, work} ->
        %{
          st
          | orphan_work: work,
            orphan_work_set:
              Enum.reduce(:queue.to_list(q), st.orphan_work_set, &MapSet.delete(&2, &1)),
            orphan_work_peers: :queue.filter(&(&1 != peer), st.orphan_work_peers)
        }
    end
  end

  # Core: MempoolRejectedTx
  # A transient answer leaves no trace: the tx is fetched again on its next
  # announcement (MP-5).
  defp rejected(st, _tx, e, _peer, _first_time)
       when e.result == :reconsiderable and e.reason in @transient,
       do: st

  # Another submitter (RPC submitpackage, REST) added it while this accept
  # was pending: it is had, not rejected (MP-7). Its submitter's
  # :mempool_accepted notification announces it.
  defp rejected(st, tx, %{reason: "txn-already-in-mempool"}, _peer, _first_time),
    do: orphans_drop(st, [tx.wtxid])

  defp rejected(st, tx, e, peer, first_time) do
    st =
      case e.result do
        :missing_inputs ->
          if first_time and not f_has?(st.rejects, tx.wtxid),
            do: add_orphan(st, tx, peer),
            else: st

        :witness_stripped ->
          st

        :reconsiderable ->
          st = %{st | reconsiderable: f_insert(st.reconsiderable, tx.wtxid)}
          if first_time, do: try_1p1c(st, tx, peer), else: st

        other ->
          rejects = f_insert(st.rejects, tx.wtxid)

          rejects =
            if other == :inputs_not_standard and tx.has_witness,
              do: f_insert(rejects, tx.txid),
              else: rejects

          %{st | rejects: rejects}
      end

    if e.result != :missing_inputs,
      do: orphans_drop(st, [tx.wtxid]),
      else: st
  end

  defp add_orphan(st, tx, peer) do
    parents = tx.inputs |> Enum.map(& &1.prev_hash) |> Enum.uniq() |> Enum.sort()

    rejected_parent =
      Enum.any?(parents, &f_has?(st.rejects, &1)) or
        Enum.count(
          parents,
          &(f_has?(st.reconsiderable, &1) and not Mempool.has?(st.mempool, &1, :txid))
        ) > 1

    cond do
      rejected_parent ->
        %{st | rejects: st.rejects |> f_insert(tx.txid) |> f_insert(tx.wtxid)}

      # Only a registered (monitored) peer may own orphans: its DOWN is what
      # erases them (Core EraseForPeer). Peers register at verack, so this
      # only refuses a tx from a pid TxRelay does not track.
      not Map.has_key?(st.peers, peer) ->
        st

      true ->
        store_orphan(st, tx, peer, parents)
    end
  end

  defp store_orphan(st, tx, peer, parents) do
    missing = Enum.reject(parents, &already_have?(st, {:txid, &1}, false))
    st = add_parent_requests(st, peer, missing)

    st =
      if Map.has_key?(st.orphans, tx.wtxid),
        do: orphan_announcer_add(st, tx.wtxid, peer),
        else:
          orphan_put(st, tx.wtxid, %{
            tx: tx,
            announcers: MapSet.new([peer]),
            seq: st.orphan_seq,
            weight: Exnode.Codec.Tx.weight(tx)
          })

    st = %{st | orphan_seq: st.orphan_seq + 1}
    limit_orphans(ann_delete_hashes(st, [tx.txid, tx.wtxid]))
  end

  # Core LimitOrphans. Each limit is tested in O(1) per peer from the
  # incremental accounting, and the work done is proportional to the
  # evictions, never to orphans x announcers (AUD-H1):
  # 1. the oldest orphans go beyond the count cap;
  # 2. per announcer, a weight budget (Core DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER
  #    = 404,000): like Core's per-peer usage, every announcer of an orphan is
  #    charged its full weight, and a peer over budget loses its oldest
  #    announcements (charging only the first announcer let other peers park
  #    orphans for free);
  # 3. while the total latency score exceeds Core's global cap, the peer with
  #    the highest score loses its oldest announcement.
  # An orphan with no announcer left is erased.
  defp limit_orphans(st) do
    st = trim_count(st)
    st = st.orphan_peers |> Map.keys() |> Enum.reduce(st, &trim_peer_weight(&2, &1))
    trim_score(st)
  end

  defp trim_count(st) do
    if map_size(st.orphans) > @max_orphans do
      {_, w} = :gb_sets.smallest(st.orphan_order)
      trim_count(orphans_drop(st, [w]))
    else
      st
    end
  end

  defp trim_peer_weight(st, peer) do
    case st.orphan_peers do
      %{^peer => %{weight: weight, anns: anns}} when weight > @orphan_peer_weight ->
        {_, w} = :gb_sets.smallest(anns)
        trim_peer_weight(orphan_announcer_del(st, w, peer), peer)

      _ ->
        st
    end
  end

  defp trim_score(st) do
    if st.orphan_score > @max_orphan_score and st.orphan_peers != %{} do
      {peer, %{anns: anns}} = Enum.max_by(st.orphan_peers, fn {_, i} -> i.score end)
      {_, w} = :gb_sets.smallest(anns)
      trim_score(orphan_announcer_del(st, w, peer))
    else
      st
    end
  end

  # Core Announcement::GetLatencyScore minus the announcement itself.
  defp orphan_input_score(o), do: div(length(o.tx.inputs), 10)

  # Adds an orphan, indexing it by its parents, its age and its announcers.
  # An orphan already present is replaced (its accounting redone).
  defp orphan_put(st, w, o) do
    st = orphans_drop(st, [w])

    by_parent =
      Enum.reduce(unique_parents(o.tx), st.orphan_by_parent, fn p, acc ->
        Map.update(acc, p, MapSet.new([w]), &MapSet.put(&1, w))
      end)

    st = %{
      st
      | orphans: Map.put(st.orphans, w, o),
        orphan_by_parent: by_parent,
        orphan_order: :gb_sets.add({o.seq, w}, st.orphan_order),
        orphan_score: st.orphan_score + orphan_input_score(o)
    }

    Enum.reduce(o.announcers, st, &peer_charge(&2, &1, w, o, 1))
  end

  # Removes orphans (absent ones are ignored) and their index entries.
  defp orphans_drop(st, ws) do
    Enum.reduce(ws, st, fn w, st ->
      case Map.pop(st.orphans, w) do
        {nil, _} ->
          st

        {o, orphans} ->
          by_parent =
            Enum.reduce(unique_parents(o.tx), st.orphan_by_parent, fn p, acc ->
              case acc do
                %{^p => set} ->
                  set = MapSet.delete(set, w)
                  if MapSet.size(set) == 0, do: Map.delete(acc, p), else: Map.put(acc, p, set)

                _ ->
                  acc
              end
            end)

          st = %{
            st
            | orphans: orphans,
              orphan_by_parent: by_parent,
              orphan_order: :gb_sets.delete_any({o.seq, w}, st.orphan_order),
              orphan_score: st.orphan_score - orphan_input_score(o)
          }

          Enum.reduce(o.announcers, st, &peer_charge(&2, &1, w, o, -1))
      end
    end)
  end

  # Core AddAnnouncer: `peer` also announces orphan `w`.
  defp orphan_announcer_add(st, w, peer) do
    o = st.orphans[w]

    if MapSet.member?(o.announcers, peer) do
      st
    else
      o = %{o | announcers: MapSet.put(o.announcers, peer)}
      peer_charge(put_in(st.orphans[w], o), peer, w, o, 1)
    end
  end

  # Removes one announcement; an orphan left without announcers is erased.
  defp orphan_announcer_del(st, w, peer) do
    case st.orphans do
      %{^w => o} ->
        cond do
          not MapSet.member?(o.announcers, peer) ->
            st

          MapSet.size(o.announcers) == 1 ->
            orphans_drop(st, [w])

          true ->
            o = %{o | announcers: MapSet.delete(o.announcers, peer)}
            peer_charge(put_in(st.orphans[w], o), peer, w, o, -1)
        end

      _ ->
        st
    end
  end

  # Adds (sign 1) or removes (sign -1) one announcement of orphan `w` from
  # `peer`'s accounting and the global score.
  defp peer_charge(st, peer, w, o, sign) do
    info = Map.get(st.orphan_peers, peer, %{weight: 0, score: 0, anns: :gb_sets.empty()})
    score = 1 + orphan_input_score(o)

    anns =
      if sign > 0,
        do: :gb_sets.add({o.seq, w}, info.anns),
        else: :gb_sets.delete_any({o.seq, w}, info.anns)

    info = %{
      info
      | weight: info.weight + sign * orphan_weight(o),
        score: info.score + sign * score,
        anns: anns
    }

    peers =
      if :gb_sets.is_empty(anns),
        do: Map.delete(st.orphan_peers, peer),
        else: Map.put(st.orphan_peers, peer, info)

    %{st | orphan_peers: peers, orphan_score: st.orphan_score + sign}
  end

  # `{wtxid, orphan}` for the orphans spending any of `txids` (Core
  # AddChildrenToWorkSet / GetChildrenFromSamePeer): O(children), not O(all inputs).
  defp orphan_children(st, txids) do
    txids
    |> Enum.flat_map(&Enum.to_list(Map.get(st.orphan_by_parent, &1, MapSet.new())))
    |> Enum.uniq()
    |> Enum.map(&{&1, st.orphans[&1]})
  end

  defp orphan_weight(%{weight: w}), do: w
  defp orphan_weight(o), do: Exnode.Codec.Tx.weight(o.tx)

  # Core: Find1P1CPackage + ProcessPackageResult.
  defp try_1p1c(st, parent, peer) do
    child =
      st
      |> orphan_children([parent.txid])
      |> Enum.filter(fn {_, o} -> MapSet.member?(o.announcers, peer) end)
      |> Enum.sort_by(fn {_, o} -> o.seq end)
      |> Enum.map(fn {_, o} -> o.tx end)
      |> Enum.find(fn c ->
        not f_has?(st.reconsiderable, package_hash([parent, c])) and
          not f_has?(st.rejects, c.txid)
      end)

    case child do
      nil ->
        st

      child ->
        res = Mempool.submit_package(st.mempool, [parent, child])

        if res.state == :ok do
          # The child leaves the orphanage first (Core erases it before the
          # parent's workset is processed): otherwise accepting the parent
          # reconsiders it, the mempool answers txn-already-in-mempool, and
          # the accepted child lands in `rejects`.
          st = orphans_drop(st, [child.wtxid])
          st = accepted(st, parent, peer)
          accepted(st, child, peer)
        else
          # Core ProcessPackageResult handles each tx even when the package
          # failed: a parent accepted on its own is in the mempool (and only
          # TxRelay would announce it: the mempool's notification names us
          # as origin), and a child that failed for a reason of its own
          # leaves the orphanage (TXR-1 in STATE_MACHINES.md). The child
          # goes first, so the parent's orphan reconsideration skips it.
          st = %{st | reconsiderable: f_insert(st.reconsiderable, package_hash([parent, child]))}

          st =
            case res.txs[child.wtxid] do
              {:valid, _} ->
                accepted(orphans_drop(st, [child.wtxid]), child, peer)

              {:invalid, %{result: r} = e} when r != :missing_inputs ->
                rejected(st, child, e, peer, false)

              _ ->
                st
            end

          if match?({:valid, _}, res.txs[parent.wtxid]), do: accepted(st, parent, peer), else: st
        end
    end
  end

  # Core GetPackageHash: SHA256 of the sorted wtxids.
  defp package_hash(txs), do: :crypto.hash(:sha256, txs |> Enum.map(& &1.wtxid) |> Enum.sort())

  # --- announcing (trickle) -------------------------------------------------------

  # Core InitiateTxBroadcastToAll: into both global backlogs, then
  # ProcessInvBacklog (backlog_bumped).
  defp queue_announce(st, tx, source) do
    st = %{
      st
      | inv_in: InvBucket.push(st.inv_in, tx.txid),
        inv_out: InvBucket.push(st.inv_out, tx.txid),
        inv_source:
          if(is_pid(source), do: Map.put(st.inv_source, tx.txid, source), else: st.inv_source)
    }

    process_inv_backlog(st, st.now.())
  end

  # Core ProcessInvBacklog: refill, take what the buckets allow, and queue it
  # on every relaying peer of that direction (not back to its source).
  defp process_inv_backlog(st, now) do
    extract = fn txids, n ->
      {entries, rest} = Mempool.extract_best(st.mempool, txids, n)
      {Enum.map(entries, &{&1.txid, byte_size(&1.tx.raw)}), rest}
    end

    {inv_in, for_in} = st.inv_in |> InvBucket.increment(now) |> InvBucket.take(extract)
    {inv_out, for_out} = st.inv_out |> InvBucket.increment(now) |> InvBucket.take(extract)
    st = %{st | inv_in: inv_in, inv_out: inv_out}

    if for_in == [] and for_out == [] do
      st
    else
      {peers, any_in, any_out} =
        Enum.reduce(st.peers, {%{}, false, false}, fn {pid, p}, {acc, any_in, any_out} ->
          inbound = Map.get(p, :inbound, false)
          txids = if inbound, do: for_in, else: for_out
          txids = Enum.reject(txids, &(st.inv_source[&1] == pid))
          p = if p.relay_txs, do: %{p | to_send: Enum.reverse(txids) ++ p.to_send}, else: p
          {Map.put(acc, pid, p), any_in or inbound, any_out or not inbound}
        end)

      # No peers of a direction: drop that backlog (Core clears it).
      st = %{
        st
        | peers: peers,
          inv_in: if(any_in, do: st.inv_in, else: InvBucket.clear(st.inv_in)),
          inv_out: if(any_out, do: st.inv_out, else: InvBucket.clear(st.inv_out))
      }

      pending = MapSet.new(InvBucket.backlog(st.inv_in) ++ InvBucket.backlog(st.inv_out))
      %{st | inv_source: Map.filter(st.inv_source, fn {t, _} -> MapSet.member?(pending, t) end)}
    end
  end

  defp inv_delay(%{inbound: true}), do: exp_delay(@inbound_interval_ms)
  defp inv_delay(_), do: exp_delay(@outbound_interval_ms)
  defp exp_delay(mean), do: round(-mean * :math.log(1.0 - :rand.uniform()))

  defp trickle(st, now) do
    peers =
      Map.new(st.peers, fn {pid, p} ->
        if p.next_inv_at <= now and p.to_send != [] do
          {items, known} = inventory(st, p)
          items |> Enum.chunk_every(@max_inv_sz) |> Enum.each(&send(pid, {:send, {:inv, &1}}))
          {pid, %{p | to_send: [], known: known, next_inv_at: now + inv_delay(p)}}
        else
          {pid, if(p.next_inv_at <= now, do: %{p | next_inv_at: now + inv_delay(p)}, else: p)}
        end
      end)

    %{st | peers: peers}
  end

  # Core SendMessages (fSendTrickle): the queued txs still in the mempool,
  # in mining order (ExtractBestByMiningScoreWithTopology), above the peer's
  # feefilter and not already known to it.
  defp inventory(st, p) do
    {entries, _} = Mempool.extract_best(st.mempool, p.to_send, length(p.to_send))

    entries
    |> Enum.reduce({[], p.known}, fn e, {items, known} ->
      hash = if p.wtxid_relay, do: e.wtxid, else: e.txid

      cond do
        e.fee < Exnode.Mempool.Policy.fee_for(p.feefilter, e.vsize) ->
          {items, known}

        f_has?(known, hash) ->
          {items, known}

        true ->
          {[%{type: if(p.wtxid_relay, do: :wtx, else: :tx), witness: false, hash: hash} | items],
           f_insert(known, hash, @known_cap)}
      end
    end)
    |> then(fn {items, known} -> {Enum.reverse(items), known} end)
  end
end
