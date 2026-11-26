defmodule Exnode.P2P.TxRelay do
  @moduledoc """
  Transaction relay. The roles of Core v32.1 `node/txdownloadman_impl.cpp`
  (with `Exnode.P2P.TxRelay.RequestTracker` for `txrequest.cpp` and
  `Exnode.P2P.TxRelay.Orphanage` for `node/txorphanage.cpp`) and of the
  tx-inventory, dynamic `feefilter`, and unbroadcast re-announcement parts of
  `PeerManagerImpl::SendMessages` (`net_processing.cpp`).

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

  Sending (trickle, feefilter, unbroadcast):
  * Each tx-relaying peer's queued txs are announced at exponentially spaced
    intervals (2 s outbound, 5 s inbound), parents first, skipping txs below
    the peer's feefilter and txs it already knows (`MSG_WTX` to wtxid-relay
    peers, `MSG_TX` to the others).
  * `feefilter` is sent only to peers with `relay_txs: true` (never to
    block-relay-only or `fRelay = false` peers), and updated on periodic ticks
    when `max(min_fee, opts.min_relay)` from `Mempool.fee_info/1` changes
    materially.
  * Every 10–15 minutes (`ReattemptInitialBroadcast`), locally-submitted txs
    still in `Mempool.unbroadcast_txids/1` are queued again for `inv`
    announcement to connected `relay_txs` peers.

  Backpressure: `inv/3` and `received_tx/3` are calls, so a peer handles one
  such message at a time and does not read its socket meanwhile; TCP's
  receive window then holds back the sender, as Core's `fPauseRecv` does
  (net.cpp, `DEFAULT_MAXRECEIVEBUFFER`) while `ProcessMessage` runs inline.
  """
  use GenServer

  alias Exnode.Mempool
  alias Exnode.Mempool.Policy
  alias Exnode.P2P.InvBucket
  alias Exnode.P2P.TxRelay.{Orphanage, RequestTracker}
  alias Exnode.Util.RollingBloom

  @tick_ms 100
  @inbound_interval_ms 5_000
  @outbound_interval_ms 2_000
  # Core AVG_FEEFILTER_BROADCAST_INTERVAL (10 min).
  @feefilter_interval_ms 600_000
  @feefilter_check_ms 1_000
  # Core ReattemptInitialBroadcast: 10..15 min on NodeClock.
  @min_rebroadcast_s 600
  @rebroadcast_jitter_s 300
  @max_rebroadcast_ms (@min_rebroadcast_s + @rebroadcast_jitter_s) * 1_000
  @max_inv_sz 50_000
  @filter_cap 120_000
  # Core: m_tx_inventory_known_filter{50000, 0.000001} (net_processing.cpp).
  @known_cap 50_000
  @known_fp 1.0e-6
  # Max concurrent async orphan reconsiderations in flight at once.
  @max_orphan_in_flight 4

  @transient ["mempool busy", "tip-changed", "script-check-crashed"]

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  # --- API used by peers & RPC -------------------------------------------------

  @doc "`info`: `%{wtxid_relay, preferred, relay_txs, inbound}`."
  def connected(server, peer, info), do: GenServer.cast(server, {:connected, peer, info})

  @doc """
  A peer's tx announcements. A call (`:ok`), so the peer waits as Core's
  `ProcessMessage` runs inline (no timeout; the peer's inactivity timeout
  bounds it).
  """
  def inv(server, peer, items), do: peer_call(server, {:inv, peer, items, nil}, :ok)

  @doc """
  `inv/3` from a peer that already put the announced tx hashes in its own
  known filter (`new_known_filter/0`, Core AddKnownTx): TxRelay keeps the
  handle and reads it, so the inserts run in the peer's process, not here.
  """
  def inv(server, peer, items, known),
    do: peer_call(server, {:inv, peer, items, known}, :ok)

  @doc "A peer's known-inventory filter (Core m_tx_inventory_known_filter{50000, 0.000001})."
  def new_known_filter, do: RollingBloom.new(@known_cap, @known_fp)

  @doc "A tx a peer sent: `ProcessTransaction` inline, as `inv/3` (`:ok`)."
  def received_tx(server, peer, tx), do: peer_call(server, {:tx, peer, tx}, :ok)

  @doc """
  Non-blocking tx submission from a `Peer`. `TxRelay` dispatches verification
  asynchronously and sends `{:tx_done, ref}` back to `peer` when validation
  completes (immediately if already known or rejected synchronously), plus
  `:novel_tx` when accepted.
  """
  def submit_tx(server, peer, ref, tx),
    do: GenServer.cast(server, {:submit_tx, peer, ref, tx})

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

  @doc "Announce a tx accepted outside P2P (e.g. RPC) to every peer."
  def announce(server, tx), do: GenServer.cast(server, {:announce, tx, nil})

  def orphans(server), do: GenServer.call(server, :orphans, 5_000)

  @doc """
  Inbound and outbound inventory bucket statistics (for `getnetworkinfo`):
  `%{inbound: %{backlog, count_tok, size_tok}, outbound: %{backlog, count_tok, size_tok}}`.
  """
  def inv_stats(server), do: GenServer.call(server, :inv_stats, 5_000)

  defp peer_call(server, msg, fallback) do
    GenServer.call(server, msg, :infinity)
  catch
    :exit, _ -> fallback
  end

  @impl true
  def init(opts) do
    now_fn = Keyword.get(opts, :clock, fn -> Exnode.Clock.now_ms(nil) end)
    now = now_fn.()
    rate = Keyword.get(opts, :tx_send_rate, InvBucket.default_rate())

    base = %{
      mempool: Keyword.fetch!(opts, :mempool),
      mempool_policies: Keyword.get(opts, :mempool_policies, false),
      async_mempool: Keyword.get(opts, :async_mempool, false),
      peers: %{},
      monitors: %{},
      # ref => pending async mempool acceptance/package/orphan job
      pending_jobs: %{},
      orphan_in_flight: 0,
      ann: %{},
      ann_peers: %{},
      ann_seq: 0,
      ready: :gb_trees.empty(),
      expiry: :gb_trees.empty(),
      requested: %{},
      waiting: %{},
      in_flight: %{},
      tick_ms: Keyword.get(opts, :tick_ms, @tick_ms),
      rejects: new_filter(),
      reconsiderable: new_filter(),
      confirmed: new_filter(),
      orphans: %{},
      orphan_by_parent: %{},
      orphan_seq: 0,
      orphan_order: :gb_sets.empty(),
      orphan_peers: %{},
      orphan_score: 0,
      orphan_work: %{},
      orphan_work_peers: :queue.new(),
      orphan_work_set: MapSet.new(),
      orphan_work_scheduled: false,
      now: now_fn,
      inv_in: InvBucket.new(rate, 1.0),
      inv_out: InvBucket.new(rate, InvBucket.outbound_mult()),
      inv_source: %{},
      our_feefilter: Policy.default_min_relay_tx_fee(),
      last_feefilter_check: nil,
      next_rebroadcast: now + rebroadcast_delay_ms(),
      tip: nil
    }

    st =
      RequestTracker.new()
      |> RequestTracker.into_state(base)
      |> then(&Orphanage.into_state(Orphanage.new(), &1))

    schedule_tick(st)
    resync_peers(Keyword.get(opts, :peer_sup))
    {:ok, st}
  end

  defp tick(st, force_check?) do
    now = st.now.()

    st
    |> expire_requests(now)
    |> send_requests(now)
    |> maybe_rebroadcast(now)
    |> process_inv_backlog(now)
    |> trickle(now)
    |> maybe_update_feefilter(now, force_check?)
  end

  defp schedule_tick(%{tick_ms: nil}), do: :ok
  defp schedule_tick(st), do: Process.send_after(self(), :tick, st.tick_ms)

  defp resync_peers(nil), do: :ok

  defp resync_peers(peer_sup) do
    if GenServer.whereis(peer_sup) do
      for {_, pid, _, _} <- DynamicSupervisor.which_children(peer_sup),
          is_pid(pid),
          do: send(pid, :tx_relay_resync)
    end

    :ok
  catch
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

  defp known_to?(out, inn, h),
    do:
      (out != nil and RollingBloom.contains?(out, h)) or
        (inn != nil and RollingBloom.contains?(inn, h))

  # --- casts ---------------------------------------------------------------------

  @impl true
  def handle_cast({:connected, peer, info}, st) do
    if Map.has_key?(st.peers, peer) do
      {:noreply, update_in(st.peers[peer], &Map.merge(&1, info))}
    else
      st =
        if Map.has_key?(st.monitors, peer),
          do: st,
          else: %{st | monitors: Map.put(st.monitors, peer, Process.monitor(peer))}

      now = st.now.()
      st = refresh_our_feefilter(st, now)
      relay_txs = Map.get(info, :relay_txs, false)
      sent_rate = if relay_txs, do: st.our_feefilter, else: 0

      p =
        Map.merge(
          %{
            known: nil,
            known_in: nil,
            to_send: [],
            feefilter: 0,
            sent_feefilter: sent_rate,
            next_feefilter_at: now + exp_delay(@feefilter_interval_ms),
            next_inv_at: now + inv_delay(info),
            last_inv_seq: 0
          },
          info
        )

      # Core SendMessages: send feefilter only to peers that relay transactions.
      if relay_txs, do: send(peer, {:send, {:feefilter, sent_rate}})
      {:noreply, %{st | peers: Map.put(st.peers, peer, p)}}
    end
  end

  def handle_cast({:announce, tx, source}, st), do: {:noreply, queue_announce(st, tx, source)}

  def handle_cast({:submit_tx, peer, ref, tx}, st) do
    {:noreply, start_received_tx(st, peer, tx, {:notify, peer, ref})}
  end

  # --- calls ---------------------------------------------------------------------

  @impl true
  def handle_call({:inv, peer, items, ext_known}, _from, st) do
    case st.peers[peer] do
      nil ->
        {:reply, :ok, st}

      p ->
        items =
          items
          |> Enum.filter(fn i ->
            (p.wtxid_relay and i.type == :wtx) or (not p.wtxid_relay and i.type == :tx)
          end)
          |> Enum.uniq_by(&{&1.type, &1.hash})

        st =
          case {ext_known, p.known_in} do
            {nil, nil} ->
              k = new_known_filter()
              Enum.each(items, &RollingBloom.insert(k, &1.hash))
              put_in(st.peers[peer].known_in, k)

            {nil, k} ->
              Enum.each(items, &RollingBloom.insert(k, &1.hash))
              st

            {ext, ext} ->
              st

            {ext, _} ->
              put_in(st.peers[peer].known_in, ext)
          end

        rt = RequestTracker.from_state(st)
        orph = Orphanage.from_state(st)

        ctx = %{
          in_flight: RequestTracker.in_flight_count(rt, peer),
          any_wtxid_relay: Enum.any?(st.peers, fn {_, q} -> q.wtxid_relay end),
          in_mempool:
            prefetch_mempool(
              st,
              Enum.map(items, &{kind(&1.type), &1.hash}) ++
                Orphanage.parent_gtxids(orph, peer, items)
            )
        }

        now = st.now.()
        score_before = orph.orphan_score

        {rt, orph} =
          Enum.reduce(items, {rt, orph}, fn i, {rt_acc, orph_acc} ->
            add_announcement(st, rt_acc, orph_acc, peer, {kind(i.type), i.hash}, ctx, now)
          end)

        orph = if orph.orphan_score == score_before, do: orph, else: Orphanage.limit(orph)
        st = st |> put_tracker(rt) |> put_orphanage(orph)
        {:reply, :ok, st}
    end
  end

  def handle_call({:tx, peer, tx}, from, st) do
    {:noreply, start_received_tx(st, peer, tx, {:reply, from})}
  end

  def handle_call({:notfound, peer, items}, _from, st) do
    rt =
      Enum.reduce(items, RequestTracker.from_state(st), fn i, acc ->
        RequestTracker.complete(acc, peer, i.hash)
      end)

    {:reply, :ok, put_tracker(st, rt)}
  end

  def handle_call({:feefilter, peer, rate}, _from, st) do
    if Map.has_key?(st.peers, peer),
      do: {:reply, :ok, put_in(st.peers[peer].feefilter, rate)},
      else: {:reply, :ok, st}
  end

  def handle_call({:lookup, items}, {peer, _}, st) do
    before = get_in(st.peers, [peer, :last_inv_seq]) || 0
    {txs, missing} = Mempool.get_txs(st.mempool, items, before)
    if txs != [], do: Mempool.remove_unbroadcast(st.mempool, Enum.map(txs, & &1.txid))
    {:reply, {txs, missing}, st}
  end

  def handle_call(:orphans, _from, st),
    do: {:reply, Orphanage.wtxids(Orphanage.from_state(st)), st}

  def handle_call(:inv_stats, _from, st) do
    now = st.now.()
    inv_in = InvBucket.increment(st.inv_in, now)
    inv_out = InvBucket.increment(st.inv_out, now)

    stats = %{
      inbound: bucket_stats(inv_in),
      outbound: bucket_stats(inv_out)
    }

    {:reply, stats, %{st | inv_in: inv_in, inv_out: inv_out}}
  end

  defp bucket_stats(b) do
    {count_tok, size_tok} = InvBucket.tokens(b)
    %{backlog: length(InvBucket.backlog(b)), count_tok: count_tok, size_tok: size_tok}
  end

  # --- infos ---------------------------------------------------------------------

  @impl true
  def handle_info(:tick, st) do
    schedule_tick(st)
    {:noreply, tick(st, false)}
  end

  def handle_info({Exnode.Clock, :tick, from, ref}, st) do
    st = tick(st, true)
    Exnode.Clock.ticked({from, ref})
    {:noreply, st}
  end

  def handle_info({:mempool_accepted, _tx, _res, origin}, st) when origin == self(),
    do: {:noreply, st}

  def handle_info({:mempool_accepted, tx, _res, _origin}, st),
    do: {:noreply, queue_announce(st, tx, nil)}

  def handle_info({:mempool_block, :connected, txs, tip}, st) do
    st =
      if tip != st.tip,
        do: %{st | rejects: new_filter(), reconsiderable: new_filter(), tip: tip},
        else: st

    confirmed =
      Enum.reduce(txs, st.confirmed, fn t, f -> f |> f_insert(t.txid) |> f_insert(t.wtxid) end)

    hashes = MapSet.new(Enum.flat_map(txs, &[&1.txid, &1.wtxid]))
    spent = MapSet.new(Enum.flat_map(txs, & &1.prevouts))

    orph = Orphanage.erase_for_block(Orphanage.from_state(st), hashes, spent)
    rt = RequestTracker.delete_hashes(RequestTracker.from_state(st), hashes)

    st =
      %{st | confirmed: confirmed}
      |> put_orphanage(orph)
      |> put_tracker(rt)
      |> add_children_to_work_set(Enum.map(txs, & &1.txid))

    {:noreply, st}
  end

  def handle_info({:mempool_block, :disconnected}, st),
    do:
      {:noreply,
       %{st | confirmed: new_filter(), rejects: new_filter(), reconsiderable: new_filter()}}

  def handle_info(:orphan_work, st) do
    st = update_orphanage(st, &Orphanage.clear_scheduled/1)
    {:noreply, st |> orphan_work_step() |> schedule_orphan_work()}
  end

  def handle_info({{:tx_verdict, ref}, result}, st) do
    case Map.pop(st.pending_jobs, ref) do
      {nil, _} ->
        {:noreply, st}

      {job, jobs} ->
        st = %{st | pending_jobs: jobs}
        {:noreply, handle_verdict(st, job, result)}
    end
  end

  def handle_info({{:pkg_verdict, ref}, result}, st) do
    case Map.pop(st.pending_jobs, ref) do
      {nil, _} ->
        {:noreply, st}

      {job, jobs} ->
        st = %{st | pending_jobs: jobs}
        {:noreply, handle_package_verdict(st, job, result)}
    end
  end

  def handle_info({{:orphan_verdict, ref}, result}, st) do
    case Map.pop(st.pending_jobs, ref) do
      {nil, _} ->
        {:noreply, st}

      {job, jobs} ->
        st = %{st | pending_jobs: jobs, orphan_in_flight: max(st.orphan_in_flight - 1, 0)}
        {:noreply, handle_orphan_verdict(st, job, result)}
    end
  end

  def handle_info({:DOWN, ref, :process, peer, _}, st) do
    case Map.get(st.monitors, peer) do
      ^ref ->
        drop_peer(st, peer)

      nil ->
        {:noreply, st}

      other_ref ->
        # A test may inject a synthetic {:DOWN, make_ref(), :process, peer, _}
        # to simulate an ordered disconnect without killing the peer process.
        if Map.has_key?(st.peers, peer) do
          Process.demonitor(other_ref, [:flush])
          drop_peer(st, peer)
        else
          {:noreply, st}
        end
    end
  end

  def handle_info(_msg, st), do: {:noreply, st}

  defp drop_peer(st, peer) do
    orph = Orphanage.erase_for_peer(Orphanage.from_state(st), peer)
    rt = RequestTracker.drop_peer(RequestTracker.from_state(st), peer)

    st =
      %{st | peers: Map.delete(st.peers, peer), monitors: Map.delete(st.monitors, peer)}
      |> put_orphanage(orph)
      |> put_tracker(rt)

    {:noreply, st}
  end

  # --- state adapters -----------------------------------------------------------

  defp put_tracker(st, rt), do: RequestTracker.into_state(rt, st)
  defp put_orphanage(st, orph), do: Orphanage.into_state(orph, st)
  defp update_tracker(st, fun), do: put_tracker(st, fun.(RequestTracker.from_state(st)))
  defp update_orphanage(st, fun), do: put_orphanage(st, fun.(Orphanage.from_state(st)))

  # --- announcements and requests -----------------------------------------------

  defp kind(:wtx), do: :wtxid
  defp kind(_), do: :txid

  defp already_have?(st, {kind, h}, include_reconsiderable, in_mempool \\ nil) do
    Map.has_key?(st.orphans, h) or (include_reconsiderable and f_has?(st.reconsiderable, h)) or
      f_has?(st.confirmed, h) or f_has?(st.rejects, h) or
      if(in_mempool,
        do: MapSet.member?(in_mempool[kind], h),
        else: Mempool.has?(st.mempool, h, kind)
      )
  end

  defp prefetch_mempool(st, gtxids) do
    by_kind = Enum.group_by(gtxids, &elem(&1, 0), &elem(&1, 1))

    Map.new([:txid, :wtxid], fn k ->
      case Map.get(by_kind, k, []) do
        [] -> {k, MapSet.new()}
        hs -> {k, Mempool.has_many?(st.mempool, Enum.uniq(hs), k)}
      end
    end)
  end

  defp add_announcement(st, rt, orph, peer, {kind, h} = gtxid, ctx, now) do
    cond do
      kind == :wtxid and Orphanage.has?(orph, h) ->
        entry = Orphanage.get(orph, h)

        cond do
          MapSet.member?(entry.announcers, peer) or
              RequestTracker.count(rt, peer) >= RequestTracker.max_announcements() ->
            {rt, orph}

          true ->
            parents =
              entry.tx
              |> Orphanage.unique_parents()
              |> Enum.reject(&already_have?(st, {:txid, &1}, false, ctx.in_mempool))

            cond do
              parents == [] ->
                {rt, orph}

              RequestTracker.count(rt, peer) + length(parents) >
                  RequestTracker.max_announcements() ->
                {rt, orph}

              true ->
                p = st.peers[peer]

                rt =
                  RequestTracker.add_parent_requests(
                    rt,
                    peer,
                    parents,
                    p.preferred,
                    ctx.any_wtxid_relay,
                    now
                  )

                {rt, Orphanage.add_announcer(orph, h, peer)}
            end
        end

      already_have?(st, gtxid, true, ctx.in_mempool) ->
        {rt, orph}

      true ->
        p = st.peers[peer]
        {RequestTracker.add_candidate(rt, peer, gtxid, p.preferred, ctx, now), orph}
    end
  end

  defp add_parent_requests(st, peer, parents) do
    case st.peers[peer] do
      nil ->
        st

      p ->
        any_wtxid = Enum.any?(st.peers, fn {_, q} -> q.wtxid_relay end)
        now = st.now.()

        update_tracker(
          st,
          &RequestTracker.add_parent_requests(&1, peer, parents, p.preferred, any_wtxid, now)
        )
    end
  end

  defp expire_requests(st, now), do: update_tracker(st, &RequestTracker.expire(&1, now))

  defp send_requests(st, now) do
    {rt, picks} = RequestTracker.take_picks(RequestTracker.from_state(st), st.peers, now)
    in_mempool = prefetch_mempool(st, Enum.map(picks, fn {h, _, a} -> {a.kind, h} end))

    {rt, per_peer} =
      RequestTracker.finalize_picks(rt, picks, &already_have?(st, &1, false, in_mempool), now)

    for {peer, items} <- per_peer, do: send(peer, {:send, {:getdata, items}})
    put_tracker(st, rt)
  end

  # --- receiving a tx -----------------------------------------------------------

  defp finish_tx_caller({:reply, from}), do: GenServer.reply(from, :ok)

  defp finish_tx_caller({:notify, peer, ref}) do
    if is_pid(peer), do: send(peer, {:tx_done, ref})
    :ok
  end

  defp finish_tx_caller(:none), do: :ok

  defp start_received_tx(st, peer, tx, caller) do
    st =
      update_tracker(st, fn rt ->
        rt |> RequestTracker.complete(peer, tx.txid) |> RequestTracker.complete(peer, tx.wtxid)
      end)

    cond do
      already_have?(st, {:wtxid, tx.wtxid}, false) ->
        finish_tx_caller(caller)
        st

      f_has?(st.reconsiderable, tx.wtxid) ->
        try_1p1c(st, tx, peer, caller)

      true ->
        process_tx(st, peer, tx, true, caller)
    end
  end

  defp process_tx(%{async_mempool: true} = st, peer, tx, first_time, caller) do
    ref = make_ref()

    case Mempool.accept_async(st.mempool, tx, self(), {:tx_verdict, ref}) do
      :ok ->
        job = %{peer: peer, tx: tx, first_time: first_time, caller: caller}
        %{st | pending_jobs: Map.put(st.pending_jobs, ref, job)}

      {:error, e} ->
        handle_verdict(
          st,
          %{peer: peer, tx: tx, first_time: first_time, caller: caller},
          {:error, e}
        )
    end
  end

  defp process_tx(st, peer, tx, first_time, caller) do
    result = Mempool.accept(st.mempool, tx)
    handle_verdict(st, %{peer: peer, tx: tx, first_time: first_time, caller: caller}, result)
  end

  defp handle_verdict(st, %{peer: peer, tx: tx, first_time: first_time, caller: caller}, result) do
    case result do
      {:ok, _res} ->
        if is_pid(peer), do: send(peer, :novel_tx)
        finish_tx_caller(caller)
        accepted(st, tx, peer)

      {:error, e} ->
        rejected(st, tx, e, peer, first_time, caller)
    end
  end

  defp accepted(st, tx, peer) do
    st =
      st
      |> update_orphanage(&Orphanage.drop(&1, [tx.wtxid]))
      |> update_tracker(&RequestTracker.delete_hashes(&1, [tx.txid, tx.wtxid]))
      |> queue_announce(tx, peer)

    add_children_to_work_set(st, [tx.txid])
  end

  defp add_children_to_work_set(st, txids) do
    {orph, send_msg?} = Orphanage.enqueue_children(Orphanage.from_state(st), txids)
    if send_msg?, do: send(self(), :orphan_work)
    put_orphanage(st, orph)
  end

  defp schedule_orphan_work(st) do
    {orph, send_msg?} = Orphanage.ensure_scheduled(Orphanage.from_state(st))
    if send_msg?, do: send(self(), :orphan_work)
    put_orphanage(st, orph)
  end

  defp orphan_work_step(%{async_mempool: true, orphan_in_flight: n} = st)
       when n >= @max_orphan_in_flight,
       do: st

  defp orphan_work_step(st) do
    case Orphanage.pop_next_work_peer(Orphanage.from_state(st)) do
      {:empty, orph} ->
        put_orphanage(st, orph)

      {:ok, peer, orph} ->
        st = process_peer_orphan_work(put_orphanage(st, orph), peer)
        st = update_orphanage(st, &Orphanage.requeue_work_peer(&1, peer))

        if st.async_mempool and st.orphan_in_flight < @max_orphan_in_flight and
             not :queue.is_empty(st.orphan_work_peers) do
          orphan_work_step(st)
        else
          st
        end
    end
  end

  defp process_peer_orphan_work(st, peer) do
    case Orphanage.pop_peer_work(Orphanage.from_state(st), peer) do
      {:empty, orph} ->
        put_orphanage(st, orph)

      {:ok, w, orph} ->
        st = put_orphanage(st, orph)

        case reconsider_orphan(st, w, peer) do
          {:decisive, st} -> st
          {:continue, st} -> process_peer_orphan_work(st, peer)
        end
    end
  end

  defp reconsider_orphan(%{async_mempool: true} = st, w, peer) do
    case st.orphans do
      %{^w => o} ->
        st = update_orphanage(st, &Orphanage.drop(&1, [w]))
        ref = make_ref()

        case Mempool.accept_async(st.mempool, o.tx, self(), {:orphan_verdict, ref}) do
          :ok ->
            job = %{peer: peer, w: w, orphan: o}

            st = %{
              st
              | pending_jobs: Map.put(st.pending_jobs, ref, job),
                orphan_in_flight: st.orphan_in_flight + 1
            }

            {:decisive, st}

          {:error, e} ->
            handle_orphan_result(st, w, o, peer, {:error, e})
        end

      _ ->
        {:continue, st}
    end
  end

  defp reconsider_orphan(st, w, peer) do
    case st.orphans do
      %{^w => o} ->
        st = update_orphanage(st, &Orphanage.drop(&1, [w]))
        handle_orphan_result(st, w, o, peer, Mempool.accept(st.mempool, o.tx))

      _ ->
        {:continue, st}
    end
  end

  defp handle_orphan_verdict(st, %{peer: peer, w: w, orphan: o}, result) do
    case handle_orphan_result(st, w, o, peer, result) do
      {:decisive, st} ->
        st |> orphan_work_step() |> schedule_orphan_work()

      {:continue, st} ->
        st |> process_peer_orphan_work(peer) |> orphan_work_step() |> schedule_orphan_work()
    end
  end

  defp handle_orphan_result(st, w, o, peer, result) do
    case result do
      {:ok, _} ->
        {:decisive, accepted(st, o.tx, peer)}

      {:error, %{result: :missing_inputs}} ->
        {:continue, update_orphanage(st, &Orphanage.put(&1, w, o))}

      {:error, e} when e.result == :reconsiderable and e.reason in @transient ->
        {:decisive, update_orphanage(st, &Orphanage.put(&1, w, o))}

      {:error, e} ->
        {:decisive, rejected(st, o.tx, e, peer, false, :none)}
    end
  end

  defp rejected(st, _tx, e, _peer, _first_time, caller)
       when e.result == :reconsiderable and e.reason in @transient do
    finish_tx_caller(caller)
    st
  end

  defp rejected(st, tx, %{reason: "txn-already-in-mempool"}, _peer, _first_time, caller) do
    finish_tx_caller(caller)
    update_orphanage(st, &Orphanage.drop(&1, [tx.wtxid]))
  end

  defp rejected(st, tx, e, peer, first_time, caller) do
    case e.result do
      :missing_inputs ->
        finish_tx_caller(caller)

        if first_time and not f_has?(st.rejects, tx.wtxid),
          do: add_orphan(st, tx, peer),
          else: st

      :witness_stripped ->
        finish_tx_caller(caller)
        update_orphanage(st, &Orphanage.drop(&1, [tx.wtxid]))

      :reconsiderable ->
        st =
          %{st | reconsiderable: f_insert(st.reconsiderable, tx.wtxid)}
          |> update_orphanage(&Orphanage.drop(&1, [tx.wtxid]))

        if first_time do
          try_1p1c(st, tx, peer, caller)
        else
          finish_tx_caller(caller)
          st
        end

      other ->
        finish_tx_caller(caller)
        rejects = f_insert(st.rejects, tx.wtxid)

        rejects =
          if other == :inputs_not_standard and tx.has_witness,
            do: f_insert(rejects, tx.txid),
            else: rejects

        %{st | rejects: rejects}
        |> update_orphanage(&Orphanage.drop(&1, [tx.wtxid]))
    end
  end

  defp add_orphan(st, tx, peer) do
    parents = tx |> Orphanage.unique_parents() |> Enum.sort()

    rejected_parent =
      Enum.any?(parents, &f_has?(st.rejects, &1)) or
        Enum.count(
          parents,
          &(f_has?(st.reconsiderable, &1) and not Mempool.has?(st.mempool, &1, :txid))
        ) > 1

    cond do
      rejected_parent ->
        %{st | rejects: st.rejects |> f_insert(tx.txid) |> f_insert(tx.wtxid)}

      not Map.has_key?(st.peers, peer) ->
        st

      true ->
        store_orphan(st, tx, peer, parents)
    end
  end

  defp store_orphan(st, tx, peer, parents) do
    missing = Enum.reject(parents, &already_have?(st, {:txid, &1}, false))

    st
    |> add_parent_requests(peer, missing)
    |> update_orphanage(&Orphanage.store(&1, tx, peer))
    |> update_tracker(&RequestTracker.delete_hashes(&1, [tx.txid, tx.wtxid]))
  end

  defp try_1p1c(st, parent, peer, caller) do
    child =
      st
      |> Orphanage.from_state()
      |> Orphanage.children([parent.txid])
      |> Enum.filter(fn {_, o} -> MapSet.member?(o.announcers, peer) end)
      |> Enum.sort_by(fn {_, o} -> o.seq end)
      |> Enum.map(fn {_, o} -> o.tx end)
      |> Enum.find(fn c ->
        not f_has?(st.reconsiderable, package_hash([parent, c])) and
          not f_has?(st.rejects, c.txid)
      end)

    case child do
      nil ->
        finish_tx_caller(caller)
        st

      child ->
        if st.async_mempool do
          ref = make_ref()
          Mempool.submit_package_async(st.mempool, [parent, child], self(), {:pkg_verdict, ref})
          job = %{peer: peer, parent: parent, child: child, caller: caller}
          %{st | pending_jobs: Map.put(st.pending_jobs, ref, job)}
        else
          res = Mempool.submit_package(st.mempool, [parent, child])

          handle_package_verdict(
            st,
            %{peer: peer, parent: parent, child: child, caller: caller},
            res
          )
        end
    end
  end

  defp handle_package_verdict(
         st,
         %{peer: peer, parent: parent, child: child, caller: caller},
         res
       ) do
    finish_tx_caller(caller)

    if res.state == :ok do
      st = update_orphanage(st, &Orphanage.drop(&1, [child.wtxid]))
      st = accepted(st, parent, peer)
      accepted(st, child, peer)
    else
      st = %{st | reconsiderable: f_insert(st.reconsiderable, package_hash([parent, child]))}

      st
      |> package_tx_result(child, res.txs[child.wtxid], peer)
      |> package_tx_result(parent, res.txs[parent.wtxid], peer)
    end
  end

  defp package_tx_result(st, tx, {:valid, _}, peer),
    do: accepted(update_orphanage(st, &Orphanage.drop(&1, [tx.wtxid])), tx, peer)

  defp package_tx_result(st, tx, {:invalid, %{result: r} = e}, peer) when r != :missing_inputs,
    do: rejected(st, tx, e, peer, false, :none)

  defp package_tx_result(st, _tx, _result, _peer), do: st

  defp package_hash(txs), do: :crypto.hash(:sha256, txs |> Enum.map(& &1.wtxid) |> Enum.sort())

  # --- announcing (trickle, unbroadcast, feefilter) -----------------------------

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

  # Core PeerManagerImpl::ReattemptInitialBroadcast: every 10..15 min on the
  # node clock, re-queue unbroadcast mempool txids for inv announcement.
  defp maybe_rebroadcast(%{mempool_policies: false} = st, _now), do: st

  defp maybe_rebroadcast(st, now) do
    cond do
      # Clock moved backwards (e.g. setmocktime after node startup): rebase timer.
      st.next_rebroadcast - now > @max_rebroadcast_ms ->
        %{st | next_rebroadcast: now + rebroadcast_delay_ms()}

      now >= st.next_rebroadcast ->
        txids = fetch_unbroadcast_txids(st.mempool)
        st = %{st | next_rebroadcast: now + rebroadcast_delay_ms()}
        push_unbroadcast_txids(st, txids)

      true ->
        st
    end
  end

  defp rebroadcast_delay_ms,
    do: (@min_rebroadcast_s + :rand.uniform(@rebroadcast_jitter_s)) * 1_000

  defp push_unbroadcast_txids(st, []), do: st

  defp push_unbroadcast_txids(st, txids) do
    in_set = MapSet.new(InvBucket.backlog(st.inv_in))
    out_set = MapSet.new(InvBucket.backlog(st.inv_out))

    inv_in =
      Enum.reduce(txids, st.inv_in, fn t, b ->
        if MapSet.member?(in_set, t), do: b, else: InvBucket.push(b, t)
      end)

    inv_out =
      Enum.reduce(txids, st.inv_out, fn t, b ->
        if MapSet.member?(out_set, t), do: b, else: InvBucket.push(b, t)
      end)

    %{st | inv_in: inv_in, inv_out: inv_out}
  end

  defp fetch_unbroadcast_txids(mempool) do
    case GenServer.call(mempool, :unbroadcast_txids, 5_000) do
      txids when is_list(txids) -> txids
      _ -> []
    end
  catch
    :exit, _ -> []
  end

  # Core BIP133 dynamic feefilter: update `relay_txs` peers when
  # `max(min_fee, opts.min_relay)` changes materially (< 3/4 or > 4/3) or on
  # the periodic broadcast timer.
  defp maybe_update_feefilter(st, now, force_check?) do
    due? =
      force_check? or st.last_feefilter_check == nil or now < st.last_feefilter_check or
        now - st.last_feefilter_check >= @feefilter_check_ms

    if due? and Enum.any?(st.peers, fn {_, p} -> p.relay_txs end) do
      st = refresh_our_feefilter(st, now)
      rate = st.our_feefilter

      peers =
        Map.new(st.peers, fn {pid, p} ->
          sent = Map.get(p, :sent_feefilter, 0)
          next_at = Map.get(p, :next_feefilter_at, 0)

          if p.relay_txs and
               (material_feefilter_change?(rate, sent) or (now >= next_at and rate != sent)) do
            send(pid, {:send, {:feefilter, rate}})

            {pid,
             %{
               p
               | sent_feefilter: rate,
                 next_feefilter_at: now + exp_delay(@feefilter_interval_ms)
             }}
          else
            {pid, p}
          end
        end)

      %{st | peers: peers}
    else
      st
    end
  end

  defp material_feefilter_change?(rate, sent), do: 4 * rate < 3 * sent or 3 * rate > 4 * sent

  defp refresh_our_feefilter(%{mempool_policies: false} = st, now),
    do: %{st | last_feefilter_check: now}

  defp refresh_our_feefilter(st, now) do
    rate =
      try do
        case Mempool.fee_info(st.mempool) do
          {min_fee, %{min_relay: min_relay}} -> max(min_fee, min_relay)
          _ -> st.our_feefilter
        end
      catch
        :exit, _ -> st.our_feefilter
      end

    %{st | our_feefilter: rate, last_feefilter_check: now}
  end

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
    seq =
      if Enum.any?(st.peers, fn {_, p} -> p.next_inv_at <= now and p.to_send != [] end),
        do: Mempool.sequence(st.mempool)

    peers =
      Map.new(st.peers, fn {pid, p} ->
        if p.next_inv_at <= now and p.to_send != [] do
          {items, known} = inventory(st, p)
          items |> Enum.chunk_every(@max_inv_sz) |> Enum.each(&send(pid, {:send, {:inv, &1}}))

          {pid,
           %{p | to_send: [], known: known, next_inv_at: now + inv_delay(p), last_inv_seq: seq}}
        else
          {pid, if(p.next_inv_at <= now, do: %{p | next_inv_at: now + inv_delay(p)}, else: p)}
        end
      end)

    %{st | peers: peers}
  end

  defp inventory(st, p) do
    {entries, _} = Mempool.extract_best(st.mempool, p.to_send, length(p.to_send))

    entries
    |> Enum.reduce({[], p.known}, fn e, {items, known} ->
      hash = if p.wtxid_relay, do: e.wtxid, else: e.txid

      cond do
        e.fee < Policy.fee_for(p.feefilter, e.vsize) ->
          {items, known}

        known_to?(known, p.known_in, hash) ->
          {items, known}

        true ->
          known = known || new_known_filter()

          {[%{type: if(p.wtxid_relay, do: :wtx, else: :tx), witness: false, hash: hash} | items],
           RollingBloom.insert(known, hash)}
      end
    end)
    |> then(fn {items, known} -> {Enum.reverse(items), known} end)
  end
end
