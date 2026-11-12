defmodule Exnode.P2P.BlockDownload do
  @moduledoc """
  Shared block-download state. Mirrors Core v32.1 net_processing.cpp:

  * `FindNextBlocksToDownload`: for a peer whose best known header is `B`,
    request blocks from `LastCommonAncestor(tip, B) + 1` up to
    `min(B.height, last_common + BLOCK_DOWNLOAD_WINDOW)`, skipping blocks
    we have, blocks already in flight, and failed ones.
  * MAX_BLOCKS_IN_TRANSIT_PER_PEER (16) per peer.
  * Stalling (Core `m_stalling_since`): when a peer with nothing in flight
    asks and gets nothing only because the window is exhausted, the holder
    of the window's first in-flight block (if another peer) is marked as
    stalling, from then. A marked peer is disconnected once the mark is
    older than the stall timeout (2 s, doubled on each stall up to 64 s,
    decayed ×0.85 on each connected block, as Core's `BlockConnected`; a
    delivery alone does not decay it, BD-7 in STATE_MACHINES.md); any
    requested block it delivers clears the mark. The staller's own state
    does not matter: it used to be exempt while it was itself
    window-blocked, so a peer withholding one block while it had free slots
    stalled IBD until the 600 s download timeout (AUD-F1).
  * Preferred download (Core `sync_blocks_and_headers_from_peer`): in IBD, a
    peer that is not preferred (inbound) gets blocks only while no preferred
    peer is connected or nothing is in flight.
  * Download timeout: a block in flight longer than
    (1 + 0.5 × other downloading peers) × target spacing disconnects its peer.

  Continuous refill:

  * **Checking reservation.** When the peer that requested a block receives
    it (`received/4`), the request becomes a *checking* reservation: it no
    longer counts against the peer's 16 in transit (Core RemoveBlockRequest
    frees the slot) or against network timeouts and stall detection (it is
    local processing, not the network), but nobody can select the block
    until the peer reports the outcome (`checked/4`): stored or connected
    (the block is now held, which selection sees) or failed (the block is
    selectable again, from anyone). This closes the gap in which the block
    was neither in flight nor held and another peer could request it again.
    A reservation goes on disconnect too. Only the requesting peer can
    move its own request (owner-only removal); another
    peer's copy of the block, garbage or not, changes nothing.
  * **Selection cursor.** Per peer, the highest height on its best chain up
    to which every block is held (`{height, hash}`, Core's
    `pindexLastCommonBlock` role). A request walks the window from there,
    lazily (entries in chunks, presence probed per chunk) and stops once the
    peer's free slots are filled, instead of building all ~1,024 window
    entries per request. The cursor is used only if its hash is still the
    peer's best chain at that height and above the fork, so a reorg or a new
    best header resets it (the branch check is the generation).
  * **Byte budget.** Each request reserves an estimate of the block's size
    (a moving average of received sizes); on receipt the estimate is
    replaced by the actual size until the reservation is released. Requests
    are gated when in-flight plus checking bytes reach `max_bytes`; data is
    never rejected for exceeding its estimate. The lowest missing block of
    the walk is allowed while nothing below it is in flight (the earliest
    missing ancestor must progress; one exempt block at a time).
  * **Wakeups.** A peer that asked and got nothing while it had free slots
    waits for a wakeup instead of its 1 s tick: when the tip advances
    (`{:block_connected, ...}` from the chain state), or bytes or
    reservations are released, one coalesced `:wake` sends `:request_blocks`
    to each waiting peer once.

  Request times, stall and download timeouts are on `:clock` (the node's
  `Exnode.Clock`, nil: the system clock); the 500 ms check also runs on
  `Exnode.Clock.tick/2`.
  """
  use GenServer

  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Clock

  @window 1024
  @max_per_peer 16
  @stall_default_ms 2_000
  @stall_max_ms 64_000
  @tick_ms 500
  # In-flight plus checking bytes (estimates until received).
  @max_bytes 256 * 1024 * 1024
  # Initial per-block estimate, before any block was received.
  @initial_estimate 1024 * 1024

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  Returns block hashes (in height order) for `peer` to request; registers them as in flight.
  Waits like Core's peer thread on `cs_main` (no timeout); the peer's inactivity timeout bounds it.

  Options: `preferred:` (Core fPreferredDownload: outbound; default true)
  and `ibd:` (default false); see the preferred-download rule above. Every
  call registers the peer, also with a nil `best_known_hash`, so preferred
  peers are counted from their handshake on.
  """
  def request(server, peer, best_known_hash, opts \\ []),
    do:
      GenServer.call(
        server,
        {:request, peer, best_known_hash, Keyword.get(opts, :preferred, true),
         Keyword.get(opts, :ibd, false)},
        :infinity
      )

  @doc """
  A block received from `peer`. Returns whether it was in flight from any
  peer (Core `IsBlockRequested(hash)`). If `peer` held the request (Core
  `RemoveBlockRequest(hash, from_peer)`), it becomes a checking reservation
  until `checked/4`; another peer sending the same block, e.g. with a
  garbage body, cannot cancel an honest peer's download.
  `bytes` is the block's actual size (reconciles the estimate).
  Waits like Core's peer thread on `cs_main` (no timeout); the peer's inactivity timeout bounds it.
  """
  def received(server, peer, hash, bytes \\ nil),
    do: GenServer.call(server, {:received, peer, hash, bytes}, :infinity)

  @doc """
  A block `peer` rebuilt from a compact block (Core ProcessCompactBlockTxns:
  `RemoveBlockRequest(hash, nullopt)`): whoever held the request, it becomes
  `peer`'s checking reservation until `checked/4`, so the block is not
  downloaded again while it is processed. Returns true.
  """
  def rebuilt(server, peer, hash, bytes),
    do: GenServer.call(server, {:rebuilt, peer, hash, bytes}, :infinity)

  @doc """
  Registers `hash` as in flight from `peer` for a compact-block
  reconstruction or its full-block fallback (Core `BlockRequested` with a
  partial block). Returns true if `peer` now holds the request, false if
  another peer does or the header is unknown. It counts as one of the
  peer's blocks in transit and is subject to the download timeout. Without
  it a reconstruction was invisible here and the block was also requested
  whole by parallel download (BD-4 in STATE_MACHINES.md).
  """
  def mark(server, peer, hash), do: GenServer.call(server, {:mark, peer, hash}, :infinity)

  @doc "Drops `peer`'s request for `hash` (no-op unless `peer` holds it in transit)."
  def cancel(server, peer, hash), do: GenServer.cast(server, {:cancel, peer, hash})

  @doc """
  The outcome of a block `peer` received: `true` (stored, connected or
  already held) releases its checking reservation; `false` (any failure)
  releases it and makes the block selectable again. No-op unless `peer`
  holds a checking reservation for `hash`.
  """
  def checked(server, peer, hash, ok?), do: GenServer.cast(server, {:checked, peer, hash, ok?})

  @doc "Blocks in transit: `hash => {peer, since_ms, height}` (checking reservations excluded)."
  def in_flight(server), do: GenServer.call(server, :in_flight, 5_000)

  @doc "Checking reservations: `hash => {peer, since_ms, height}`."
  def checking(server), do: GenServer.call(server, :checking, 5_000)

  @doc """
  Counters: requests, picks, selection time, wakeups and refill delay,
  releases, bytes, stalls and timeouts.
  """
  def stats(server), do: GenServer.call(server, :stats, 5_000)

  @doc """
  `{:requested | :checking, peer}` for `hash`, or nil. A checking block is
  being processed by its peer (Core has its data already).
  """
  def in_flight_state(server, hash),
    do: GenServer.call(server, {:in_flight_state, hash}, :infinity)

  @doc """
  Whether a preferred download peer other than `peer` is registered (Core
  `m_num_preferred_download_peers - state.fPreferredDownload >= 1`). Waits
  like `received/3` (no timeout).
  """
  def other_preferred?(server, peer),
    do: GenServer.call(server, {:other_preferred?, peer}, :infinity)

  @impl true
  def init(opts) do
    Process.send_after(self(), :tick, @tick_ms)

    {:ok,
     %{
       headers: Keyword.fetch!(opts, :headers),
       chain: Keyword.fetch!(opts, :chain),
       params: Keyword.fetch!(opts, :params),
       clock: Keyword.get(opts, :clock),
       # hash => %{peer, since, height, state: :requested | :checking, bytes}
       in_flight: %{},
       # Requests in transit per peer (the 16-slot count).
       per_peer: %{},
       # Checking reservations per peer.
       checking: %{},
       monitors: %{},
       stall_ms: @stall_default_ms,
       # Core m_stalling_since: peer => monotonic ms it was found stalling.
       stalling_since: %{},
       # Peers registered as preferred for download (Core m_num_preferred_download_peers).
       preferred: MapSet.new(),
       cursors: %{},
       # peer => monotonic ms when it found nothing to request.
       waiting: %{},
       # peer => monotonic ms of the wake sent to it (refill delay).
       woken: %{},
       wake_queued: false,
       max_bytes: Keyword.get(opts, :max_bytes, @max_bytes),
       bytes: 0,
       estimate: Keyword.get(opts, :initial_estimate, @initial_estimate),
       stats: %{}
     }}
  end

  @impl true
  def handle_call(:in_flight, _from, st),
    do:
      {:reply,
       for(
         {h, %{state: :requested} = r} <- st.in_flight,
         into: %{},
         do: {h, {r.peer, r.since, r.height}}
       ), st}

  def handle_call(:checking, _from, st),
    do:
      {:reply,
       for(
         {h, %{state: :checking} = r} <- st.in_flight,
         into: %{},
         do: {h, {r.peer, r.since, r.height}}
       ), st}

  def handle_call(:stats, _from, st) do
    {:reply,
     Map.merge(st.stats, %{
       in_flight: Enum.count(st.in_flight, fn {_, r} -> r.state == :requested end),
       checking: Enum.count(st.in_flight, fn {_, r} -> r.state == :checking end),
       bytes: st.bytes,
       estimate: st.estimate,
       waiting: map_size(st.waiting),
       peers: map_size(st.monitors)
     }), st}
  end

  def handle_call({:other_preferred?, peer}, _from, st),
    do: {:reply, Enum.any?(st.preferred, &(&1 != peer)), st}

  def handle_call({:in_flight_state, hash}, _from, st) do
    case st.in_flight do
      %{^hash => %{state: state, peer: peer}} -> {:reply, {state, peer}, st}
      _ -> {:reply, nil, st}
    end
  end

  def handle_call({:mark, peer, hash}, _from, st) do
    case st.in_flight do
      %{^hash => %{peer: ^peer}} ->
        {:reply, true, st}

      %{^hash => _} ->
        {:reply, false, st}

      _ ->
        case HeaderIndex.lookup(Headers.index(st.headers), hash) do
          nil ->
            {:reply, false, st}

          e ->
            st = monitor(st, peer)

            r = %{
              peer: peer,
              since: now_ms(st),
              height: e.height,
              state: :requested,
              bytes: st.estimate
            }

            st = %{
              st
              | in_flight: Map.put(st.in_flight, hash, r),
                per_peer:
                  Map.update(st.per_peer, peer, MapSet.new([hash]), &MapSet.put(&1, hash)),
                bytes: st.bytes + st.estimate
            }

            {:reply, true, count(st, %{marked: 1})}
        end
    end
  end

  def handle_call({:rebuilt, peer, hash, bytes}, _from, st) do
    # Whoever held it (this peer's partial, another peer's full request) or
    # nobody: it is now this peer's checking reservation.
    st = release(st, hash)
    now = now_ms(st)

    height =
      case HeaderIndex.lookup(Headers.index(st.headers), hash) do
        %{height: h} -> h
        nil -> nil
      end

    st = monitor(st, peer)

    st = %{
      st
      | in_flight:
          Map.put(st.in_flight, hash, %{
            peer: peer,
            since: now,
            height: height,
            state: :checking,
            bytes: bytes
          }),
        checking: Map.update(st.checking, peer, MapSet.new([hash]), &MapSet.put(&1, hash)),
        stalling_since: Map.delete(st.stalling_since, peer),
        bytes: st.bytes + bytes
    }

    {:reply, true, st |> count(%{rebuilt: 1}) |> maybe_wake()}
  end

  def handle_call({:request, peer, best_hash, preferred?, ibd?}, _from, st) do
    t0 = System.monotonic_time(:microsecond)
    st = monitor(st, peer)
    st = if preferred?, do: %{st | preferred: MapSet.put(st.preferred, peer)}, else: st

    {picks, st} =
      if preferred? or not ibd? or may_use_non_preferred?(st),
        do: select(st, peer, best_hash),
        else: {[], count(st, %{not_preferred: 1})}

    us = System.monotonic_time(:microsecond) - t0

    st =
      st
      |> count(%{requests: 1, request_us: us, picked: length(picks)})
      |> max_stat(:request_max_us, us)

    {:reply, picks, st}
  end

  def handle_call({:received, peer, hash, bytes}, _from, st) do
    case st.in_flight do
      %{^hash => %{state: :requested, peer: ^peer} = r} ->
        actual = bytes || r.bytes
        per_peer = delete_in(st.per_peer, peer, hash)
        checking = Map.update(st.checking, peer, MapSet.new([hash]), &MapSet.put(&1, hash))
        now = now_ms(st)

        st =
          %{
            st
            | in_flight:
                Map.put(st.in_flight, hash, %{r | state: :checking, since: now, bytes: actual}),
              per_peer: per_peer,
              checking: checking,
              # Core RemoveBlockRequest: a delivered request clears the stall mark.
              stalling_since: Map.delete(st.stalling_since, peer),
              bytes: st.bytes - r.bytes + actual,
              estimate: if(bytes, do: div(st.estimate * 7 + bytes, 8), else: st.estimate)
          }
          |> count(%{received: 1, received_bytes: actual || 0})
          |> count(if bytes && bytes > r.bytes, do: %{over_estimate: 1}, else: %{})

        # A slot freed: the peer itself asks again after this block; others may be waiting.
        {:reply, true, maybe_wake(st)}

      %{^hash => %{state: :requested}} ->
        # Requested from another peer: forceProcessing, nothing changes.
        {:reply, true, count(st, %{received_not_owner: 1})}

      _ ->
        {:reply, false, count(st, %{received_unrequested: 1})}
    end
  end

  @impl true
  def handle_cast({:cancel, peer, hash}, st) do
    case st.in_flight do
      %{^hash => %{state: :requested, peer: ^peer}} ->
        {:noreply, st |> release(hash) |> maybe_wake()}

      _ ->
        {:noreply, st}
    end
  end

  def handle_cast({:checked, peer, hash, ok?}, st) do
    case st.in_flight do
      %{^hash => %{state: :checking, peer: ^peer}} ->
        st = release(st, hash)
        st = count(st, if(ok?, do: %{checked_ok: 1}, else: %{checked_failed: 1}))
        {:noreply, maybe_wake(st)}

      _ ->
        {:noreply, st}
    end
  end

  @impl true
  def handle_info(:tick, st) do
    Process.send_after(self(), :tick, @tick_ms)
    {:noreply, tick(st)}
  end

  def handle_info({Clock, :tick, from, ref}, st) do
    st = tick(st)
    Clock.ticked({from, ref})
    {:noreply, st}
  end

  # The chain state's tip moved (it lists this process as a listener): the
  # window may have advanced.
  # Core BlockConnected also decays the stall timeout: a block connecting
  # means the window moved. Deliveries while the window's first block is
  # missing do not, or the doubled timeout falls back to 2 s and slow
  # honest holders of that block are disconnected one after another (BD-7).
  def handle_info({:block_connected, _hash, _height}, st),
    do:
      {:noreply, maybe_wake(%{st | stall_ms: max(round(st.stall_ms * 0.85), @stall_default_ms)})}

  def handle_info({:block_disconnected, _hash}, st), do: {:noreply, maybe_wake(st)}
  # A block that failed on connect is no longer held. With `:mutated` its
  # header is not invalidated (the data was wrong, not the block), so it
  # must be downloaded again; a cursor at or above it would skip it forever
  # (BD-5 in STATE_MACHINES.md). Cursors there restart from below.
  def handle_info({:block_invalid, hash, _r}, st) do
    cursors =
      case HeaderIndex.lookup(Headers.index(st.headers), hash) do
        %{height: h} -> Map.reject(st.cursors, fn {_, {ch, _}} -> ch >= h end)
        nil -> %{}
      end

    {:noreply, maybe_wake(%{st | cursors: cursors})}
  end

  def handle_info(:wake, st) do
    now = now_ms(st)
    for {peer, _} <- st.waiting, do: send(peer, :request_blocks)
    # How long the woken peers had nothing to request (waiting for work).
    idle = Enum.reduce(st.waiting, 0, fn {_, since}, a -> a + now - since end)
    woken = Enum.reduce(st.waiting, st.woken, fn {peer, _}, w -> Map.put(w, peer, now) end)
    st = count(st, %{wakes: 1, woken: map_size(st.waiting), waited_ms: idle})
    {:noreply, %{st | waiting: %{}, woken: woken, wake_queued: false}}
  end

  def handle_info({:DOWN, _ref, :process, peer, _}, st) do
    st = drop_peer(st, peer)

    {:noreply,
     maybe_wake(%{
       st
       | monitors: Map.delete(st.monitors, peer),
         preferred: MapSet.delete(st.preferred, peer),
         cursors: Map.delete(st.cursors, peer),
         waiting: Map.delete(st.waiting, peer),
         woken: Map.delete(st.woken, peer)
     })}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  # --- selection -----------------------------------------------------------

  defp select(st, peer, best_hash) do
    mine = Map.get(st.per_peer, peer, MapSet.new())
    free = @max_per_peer - MapSet.size(mine)
    idx = Headers.index(st.headers)
    best = best_hash && HeaderIndex.lookup(idx, best_hash)

    cond do
      free <= 0 or best == nil ->
        {[], st}

      true ->
        tip_e = HeaderIndex.lookup(idx, tip(st).hash)

        if best.chain_work <= tip_e.chain_work do
          {[], st}
        else
          walk(st, idx, peer, best, tip_e, free, mine)
        end
    end
  end

  defp walk(st, idx, peer, best, tip_e, free, mine) do
    fork = HeaderIndex.last_common_ancestor(idx, tip_e, best)
    window_end = min(best.height, fork.height + @window)

    # The cursor, if still on this peer's best chain and above the fork.
    start =
      case st.cursors[peer] do
        {h, hash} when h > fork.height and h <= window_end ->
          case HeaderIndex.ancestor(idx, best, h) do
            %{hash: ^hash} -> h
            _ -> fork.height
          end

        _ ->
          fork.height
      end

    acc = %{
      picks: [],
      cursor: nil,
      done_prefix: true,
      saw_in_flight: false,
      waiting_for: nil,
      bytes: st.bytes,
      probes: 0,
      gated: 0,
      first_missing: nil
    }

    acc = walk_chunks(st, idx, best, start + 1, window_end, free, acc)

    st =
      case acc.cursor do
        nil -> st
        e -> %{st | cursors: Map.put(st.cursors, peer, {e.height, e.hash})}
      end

    pick = Enum.reverse(acc.picks)
    now = now_ms(st)
    est = st.estimate

    in_flight =
      Enum.reduce(pick, st.in_flight, fn e, m ->
        Map.put(m, e.hash, %{
          peer: peer,
          since: now,
          height: e.height,
          state: :requested,
          bytes: est
        })
      end)

    per_peer = Map.put(st.per_peer, peer, Enum.reduce(pick, mine, &MapSet.put(&2, &1.hash)))

    # Core FindNextBlocksToDownload + SendMessages: the window is exhausted
    # (nothing to pick, though there would be with a larger window), this
    # peer has nothing in flight, and the window's first in-flight block is
    # held by another peer: that peer is stalling the download, from now.
    staller = acc.waiting_for

    stalling_since =
      if pick == [] and window_end < best.height and MapSet.size(mine) == 0 and staller != nil and
           staller != peer,
         do: Map.put_new(st.stalling_since, staller, now),
         else: st.stalling_since

    # Nothing (or less than it could take) to request now: wake it when that changes.
    waiting =
      if length(pick) < free,
        do: Map.put_new(st.waiting, peer, now),
        else: Map.delete(st.waiting, peer)

    st =
      %{
        st
        | in_flight: in_flight,
          per_peer: per_peer,
          stalling_since: stalling_since,
          waiting: waiting,
          bytes: st.bytes + est * length(pick)
      }
      |> count(%{
        probes: acc.probes,
        budget_gated: acc.gated,
        empty: if(pick == [], do: 1, else: 0)
      })
      |> refill_delay(peer, pick != [], now)

    {Enum.map(pick, & &1.hash), st}
  end

  # Walks heights `from..to` of `best`'s chain in chunks of `free` entries
  # (one ancestor lookup, then parent links), probing presence once per
  # chunk, until `free` blocks are picked: at most as many probes as needed,
  # in chunks the size of what can be picked.
  defp walk_chunks(_st, _idx, _best, from, to, _free, acc) when from > to, do: acc

  defp walk_chunks(_st, _idx, _best, _from, _to, free, acc) when length(acc.picks) >= free,
    do: acc

  defp walk_chunks(st, idx, best, from, to, free, acc) do
    last = min(to, from + free - 1)
    entries = chunk_entries(idx, best, from, last)

    candidates =
      Enum.reject(entries, &(&1.status == :failed or Map.has_key?(st.in_flight, &1.hash)))

    have = have_many(st, Enum.map(candidates, & &1.hash))

    acc =
      Enum.reduce_while(entries, %{acc | probes: acc.probes + length(candidates)}, fn e, acc ->
        cond do
          length(acc.picks) >= free ->
            {:halt, acc}

          MapSet.member?(have, e.hash) ->
            # Held: extends the cursor while everything below it is held too.
            {:cont, if(acc.done_prefix, do: %{acc | cursor: e}, else: acc)}

          e.status == :failed ->
            {:cont, %{acc | done_prefix: false}}

          Map.has_key?(st.in_flight, e.hash) ->
            # Core `waitingfor`: the holder of the first block in transit
            # (a checking block is received, not waited for).
            waiting_for =
              case {acc.waiting_for, st.in_flight[e.hash]} do
                {nil, %{state: :requested, peer: p}} -> p
                {w, _} -> w
              end

            {:cont, %{acc | done_prefix: false, saw_in_flight: true, waiting_for: waiting_for}}

          true ->
            first = acc.first_missing || e.height
            acc = %{acc | done_prefix: false, first_missing: first}

            # The byte budget gates every pick but the earliest missing
            # block, and that one only while nothing below it is in flight:
            # once requested, it is progressing, and the next peer's walk
            # sees it in flight. Exempting each walk's first missing block
            # let every woken peer take one block past the budget (BD-3 in
            # STATE_MACHINES.md).
            exempt = e.height == first and not acc.saw_in_flight

            if not exempt and acc.bytes + st.estimate > st.max_bytes do
              {:cont, %{acc | gated: acc.gated + 1}}
            else
              {:cont, %{acc | picks: [e | acc.picks], bytes: acc.bytes + st.estimate}}
            end
        end
      end)

    walk_chunks(st, idx, best, last + 1, to, free, acc)
  end

  # Entries at heights from..last on best's chain, ascending.
  defp chunk_entries(idx, best, from, last) do
    case HeaderIndex.ancestor(idx, best, last) do
      nil -> []
      top -> down(idx, top, from, [top])
    end
  end

  defp down(_idx, %{height: h}, from, acc) when h <= from, do: acc

  defp down(idx, e, from, acc) do
    p = HeaderIndex.prev(idx, e)
    down(idx, p, from, [p | acc])
  end

  # Refill delay: from the wake sent to `peer` to its next request that
  # picks something (a woken peer that still finds nothing keeps its mark).
  defp refill_delay(st, _peer, false, _now), do: st

  defp refill_delay(st, peer, true, now) do
    case Map.pop(st.woken, peer) do
      {nil, _} ->
        st

      {at, woken} ->
        d = now - at

        %{st | woken: woken}
        |> count(%{refills: 1, refill_delay_ms: d})
        |> max_stat(:refill_delay_max_ms, d)
    end
  end

  defp maybe_wake(%{wake_queued: true} = st), do: st
  defp maybe_wake(st) when map_size(st.waiting) == 0, do: st

  defp maybe_wake(st) do
    send(self(), :wake)
    %{st | wake_queued: true}
  end

  defp release(st, hash) do
    case Map.pop(st.in_flight, hash) do
      {nil, _} ->
        st

      {r, in_flight} ->
        %{
          st
          | in_flight: in_flight,
            bytes: st.bytes - r.bytes,
            per_peer: delete_in(st.per_peer, r.peer, hash),
            checking: delete_in(st.checking, r.peer, hash)
        }
    end
  end

  # Removes `hash` from `peer`'s set, without creating an entry for a peer
  # that has none (a dropped peer stays dropped).
  defp delete_in(m, peer, hash) do
    case m do
      %{^peer => set} -> Map.put(m, peer, MapSet.delete(set, hash))
      _ -> m
    end
  end

  defp count(st, m), do: %{st | stats: Map.merge(st.stats, m, fn _k, a, b -> a + b end)}
  defp max_stat(st, k, v), do: %{st | stats: Map.update(st.stats, k, v, &max(&1, v))}

  # --- network timeouts (requests only: checking is local work) --------------

  defp tick(st) do
    now = now_ms(st)
    st |> check_stalling(now) |> check_timeouts(now)
  end

  defp now_ms(st), do: Clock.mono(st.clock, :millisecond)

  # Core SendMessages: a peer marked stalling for longer than the stall
  # timeout is disconnected, and the timeout doubles (up to 64 s).
  defp check_stalling(st, now) do
    Enum.reduce(st.stalling_since, st, fn {staller, since}, st ->
      if now - since > st.stall_ms and Map.has_key?(st.stalling_since, staller) do
        send(staller, {:disconnect, :block_stalling})
        st = drop_peer(st, staller) |> count(%{stallers: 1})
        maybe_wake(%{st | stall_ms: min(st.stall_ms * 2, @stall_max_ms)})
      else
        st
      end
    end)
  end

  # Core: in IBD a non-preferred peer downloads blocks only if no preferred
  # peer is connected or no block is in flight at all.
  defp may_use_non_preferred?(st),
    do:
      MapSet.size(st.preferred) == 0 or
        not Enum.any?(st.in_flight, fn {_, r} -> r.state == :requested end)

  defp check_timeouts(st, now) do
    downloading = st.per_peer |> Enum.count(fn {_, s} -> MapSet.size(s) > 0 end)
    limit_ms = round((1 + 0.5 * max(downloading - 1, 0)) * st.params.pow_target_spacing * 1000)

    Enum.reduce(st.in_flight, st, fn
      {_h, %{state: :requested, peer: peer, since: since}}, st ->
        if now - since > limit_ms and Map.has_key?(st.per_peer, peer) do
          send(peer, {:disconnect, :block_download_timeout})
          st |> drop_peer(peer) |> count(%{timeouts: 1}) |> maybe_wake()
        else
          st
        end

      _, st ->
        st
    end)
  end

  # Read the chain view (ETS) instead of calling the chain-state process,
  # which may be busy validating a large block.
  defp tip(st) do
    case is_atom(st.chain) && State.view(st.chain) do
      v when v not in [nil, false] -> State.view_tip(v)
      _ -> State.tip(st.chain)
    end
  end

  defp have_many(st, hashes) do
    case is_atom(st.chain) && State.view(st.chain) do
      v when v not in [nil, false] -> State.view_have_many(v, hashes)
      _ -> State.have_many(st.chain, hashes)
    end
  end

  defp monitor(st, peer) do
    if Map.has_key?(st.monitors, peer),
      do: st,
      else: %{st | monitors: Map.put(st.monitors, peer, Process.monitor(peer))}
  end

  # Releases every request and checking reservation of `peer`.
  defp drop_peer(st, peer) do
    {requested, per_peer} = Map.pop(st.per_peer, peer, MapSet.new())
    {checking, checking_m} = Map.pop(st.checking, peer, MapSet.new())
    hashes = MapSet.union(requested, checking) |> MapSet.to_list()
    st = Enum.reduce(hashes, %{st | per_peer: per_peer, checking: checking_m}, &release(&2, &1))
    n = length(hashes)

    %{st | stalling_since: Map.delete(st.stalling_since, peer)}
    |> count(if n > 0, do: %{released_peer: n}, else: %{})
  end
end
