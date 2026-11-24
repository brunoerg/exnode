defmodule Exnode.P2P.TxRelay.RequestTracker do
  @moduledoc """
  Per-peer transaction announcement and in-flight request tracker. Port of the
  `TxRequestTracker` (`txrequest.cpp`) role used by `Exnode.P2P.TxRelay`.

  `ann` (`peer => %{hash => entry}`) is the source of truth; beside it:
  * `ann_peers`: `hash => MapSet` of peers holding an announcement of `hash`
  * `ready`: `:gb_trees` keyed by `{ready_at, seq}` of candidate announcements
  * `expiry`: `:gb_trees` keyed by `{expiry, seq}` of in-flight requests
  * `requested`: `hash => peer` for the single request in flight per hash
  * `waiting`: `hash => [{ready_at, seq, peer}]` of ready candidates parked
    behind an in-flight request
  * `in_flight`: `peer => pos_integer()` count of requests in flight
  """

  @nonpref_delay 2_000
  @txid_relay_delay 2_000
  @overloaded_delay 2_000
  @getdata_interval 60_000
  @max_announcements 5_000
  @max_in_flight 100

  defstruct ann: %{},
            ann_peers: %{},
            ann_seq: 0,
            ready: :gb_trees.empty(),
            expiry: :gb_trees.empty(),
            requested: %{},
            waiting: %{},
            in_flight: %{}

  @type t :: %__MODULE__{}

  def new, do: %__MODULE__{}

  def max_announcements, do: @max_announcements
  def max_in_flight, do: @max_in_flight

  @doc "Extracts a `%RequestTracker{}` from a `TxRelay` state map."
  def from_state(st) do
    %__MODULE__{
      ann: st.ann,
      ann_peers: st.ann_peers,
      ann_seq: st.ann_seq,
      ready: st.ready,
      expiry: st.expiry,
      requested: st.requested,
      waiting: st.waiting,
      in_flight: st.in_flight
    }
  end

  @doc "Writes a `%RequestTracker{}`'s fields back into a `TxRelay` state map."
  def into_state(%__MODULE__{} = rt, st) do
    %{
      st
      | ann: rt.ann,
        ann_peers: rt.ann_peers,
        ann_seq: rt.ann_seq,
        ready: rt.ready,
        expiry: rt.expiry,
        requested: rt.requested,
        waiting: rt.waiting,
        in_flight: rt.in_flight
    }
  end

  @doc "Number of announcements currently tracked for `peer`."
  def count(%__MODULE__{ann: ann}, peer), do: map_size(Map.get(ann, peer, %{}))

  @doc "Number of in-flight requests currently tracked for `peer`."
  def in_flight_count(%__MODULE__{in_flight: inf}, peer), do: Map.get(inf, peer, 0)

  @doc "Inserts a candidate announcement if `peer` does not already hold `h`."
  def put(%__MODULE__{} = rt, peer, {kind, h}, preferred, ready_at) do
    if Map.has_key?(Map.get(rt.ann, peer, %{}), h) do
      rt
    else
      a = %{
        kind: kind,
        preferred: preferred,
        ready_at: ready_at,
        seq: rt.ann_seq,
        state: :candidate,
        expiry: nil
      }

      %{
        rt
        | ann: ann_put(rt.ann, peer, h, a),
          ann_peers: Map.update(rt.ann_peers, h, MapSet.new([peer]), &MapSet.put(&1, peer)),
          ann_seq: rt.ann_seq + 1,
          ready: :gb_trees.enter({ready_at, a.seq}, {peer, h}, rt.ready)
      }
    end
  end

  @doc "Core `AddTxAnnouncement` candidate path with preference, wtxid, and overload delays."
  def add_candidate(%__MODULE__{} = rt, peer, {kind, _h} = gtxid, preferred, ctx, now) do
    if count(rt, peer) >= @max_announcements do
      rt
    else
      delay =
        if(preferred, do: 0, else: @nonpref_delay) +
          if(kind == :txid and ctx.any_wtxid_relay, do: @txid_relay_delay, else: 0) +
          if(ctx.in_flight >= @max_in_flight, do: @overloaded_delay, else: 0)

      put(rt, peer, gtxid, preferred, now + delay)
    end
  end

  @doc "Core `MaybeAddOrphanResolutionCandidate`: requests missing orphan parents (by txid)."
  def add_parent_requests(%__MODULE__{} = rt, peer, parents, preferred, any_wtxid_relay, now) do
    delay =
      if(preferred, do: 0, else: @nonpref_delay) +
        if(any_wtxid_relay, do: @txid_relay_delay, else: 0)

    Enum.reduce(parents, rt, fn h, acc ->
      if count(acc, peer) >= @max_announcements,
        do: acc,
        else: put(acc, peer, {:txid, h}, preferred, now + delay)
    end)
  end

  @doc """
  Core `MakeCompleted` (a response, a `notfound`, or an expired request):
  marks `peer`'s announcement of `h` `:completed`, releasing any in-flight
  request and forgetting `h` altogether once no uncompleted announcement remains.
  """
  def complete(%__MODULE__{} = rt, peer, h) do
    case rt.ann do
      %{^peer => %{^h => %{state: :completed}}} ->
        rt

      %{^peer => %{^h => a}} ->
        rt = if a.state == :requested, do: release(rt, peer, h), else: rt
        rt = %{rt | ann: ann_put(rt.ann, peer, h, %{a | state: :completed})}
        if only_uncompleted?(rt, peer, h), do: delete_hashes(rt, [h]), else: rt

      _ ->
        rt
    end
  end

  @doc "Removes one announcement of `h` for `peer`, whatever its state."
  def erase(%__MODULE__{} = rt, peer, h) do
    case rt.ann do
      %{^peer => %{^h => _} = m} ->
        peers = MapSet.delete(Map.get(rt.ann_peers, h, MapSet.new()), peer)

        %{
          rt
          | ann: put_peer(rt.ann, peer, Map.delete(m, h)),
            ann_peers:
              if(MapSet.size(peers) == 0,
                do: Map.delete(rt.ann_peers, h),
                else: Map.put(rt.ann_peers, h, peers)
              )
        }

      _ ->
        rt
    end
  end

  @doc "Deletes all announcements of `hashes` across every peer."
  def delete_hashes(%__MODULE__{} = rt, hashes) do
    hs = Enum.uniq(hashes)

    {ann, in_flight} =
      Enum.reduce(rt.ann, {rt.ann, rt.in_flight}, fn {peer, m}, {acc, inf} ->
        n = Enum.count(hs, &match?(%{state: :requested}, Map.get(m, &1)))
        {put_peer(acc, peer, Map.drop(m, hs)), dec_in_flight(inf, peer, n)}
      end)

    %{
      rt
      | ann: ann,
        ann_peers: Map.drop(rt.ann_peers, hs),
        in_flight: in_flight,
        requested: Map.drop(rt.requested, hs),
        waiting: Map.drop(rt.waiting, hs)
    }
  end

  @doc "Core `DisconnectedPeer`: completes and removes all announcements of `peer`."
  def drop_peer(%__MODULE__{} = rt, peer) do
    %__MODULE__{} =
      rt =
      Map.get(rt.ann, peer, %{})
      |> Map.keys()
      |> Enum.reduce(rt, fn h, acc -> acc |> complete(peer, h) |> erase(peer, h) end)

    %{
      rt
      | ann: Map.delete(rt.ann, peer),
        in_flight: Map.delete(rt.in_flight, peer)
    }
  end

  @doc "Completes any `:requested` announcements whose `GETDATA_TX_INTERVAL` has elapsed."
  def expire(%__MODULE__{} = rt, now) do
    case pop_before(rt.expiry, fn {exp, _} -> exp < now end) do
      nil ->
        rt

      {{_, seq}, {peer, h}, expiry} ->
        rt = %{rt | expiry: expiry}

        case rt.ann do
          %{^peer => %{^h => %{state: :requested, seq: ^seq}}} ->
            expire(complete(rt, peer, h), now)

          _ ->
            expire(rt, now)
        end
    end
  end

  @doc """
  Pops candidates ready by `now` for live `peers` and chooses at most one best
  candidate (`preferred` first, then lowest `seq`) per unrequested hash,
  parking the remaining candidates in `waiting`. Returns `{rt, picks}`.
  """
  def take_picks(%__MODULE__{} = rt, peers, now) do
    {rt, due} = pop_ready(rt, peers, now, [])

    {picks, rt} =
      due
      |> Enum.group_by(&elem(&1, 0), fn {_, p, a} -> {p, a} end)
      |> Enum.reduce({[], rt}, fn {h, anns}, {picks, %__MODULE__{} = acc} ->
        if Map.has_key?(acc.requested, h) do
          {picks, wait(acc, h, anns)}
        else
          {peer, a} = best = Enum.min_by(anns, fn {_, a} -> {not a.preferred, a.seq} end)
          {[{h, peer, a} | picks], wait(acc, h, List.delete(anns, best))}
        end
      end)

    {rt, picks}
  end

  @doc """
  Finalizes `picks` from `take_picks/3`: hashes for which `already_have?.({kind, h})`
  is true are forgotten; the rest become `:requested` and are returned grouped by
  peer as `{rt, %{peer => [getdata_item]}}`.
  """
  def finalize_picks(%__MODULE__{} = rt, picks, already_have?, now) do
    {rt, per_peer} =
      Enum.reduce(picks, {rt, %{}}, fn {h, peer, a}, {%__MODULE__{} = acc, per_peer} ->
        if already_have?.({a.kind, h}) do
          {delete_hashes(acc, [h]), per_peer}
        else
          exp = now + @getdata_interval

          acc = %{
            acc
            | ann: ann_put(acc.ann, peer, h, %{a | state: :requested, expiry: exp}),
              requested: Map.put(acc.requested, h, peer),
              in_flight: Map.update(acc.in_flight, peer, 1, &(&1 + 1)),
              expiry: :gb_trees.enter({exp, a.seq}, {peer, h}, acc.expiry)
          }

          item = %{
            type: if(a.kind == :wtxid, do: :wtx, else: :tx),
            witness: a.kind == :txid,
            hash: h
          }

          {acc, Map.update(per_peer, peer, [item], &[item | &1])}
        end
      end)

    {rt, Map.new(per_peer, fn {peer, items} -> {peer, Enum.reverse(items)} end)}
  end

  # --- internal helpers -------------------------------------------------------

  defp ann_put(ann, peer, h, a), do: Map.update(ann, peer, %{h => a}, &Map.put(&1, h, a))

  defp put_peer(ann, peer, m) when map_size(m) == 0, do: Map.delete(ann, peer)
  defp put_peer(ann, peer, m), do: Map.put(ann, peer, m)

  defp only_uncompleted?(%__MODULE__{} = rt, peer, h) do
    rt.ann_peers
    |> Map.get(h, MapSet.new())
    |> Enum.all?(fn p ->
      p == peer or match?(%{^h => %{state: :completed}}, Map.get(rt.ann, p, %{}))
    end)
  end

  defp release(%__MODULE__{} = rt, peer, h) do
    ready =
      Enum.reduce(Map.get(rt.waiting, h, []), rt.ready, fn {ready_at, seq, p}, t ->
        :gb_trees.enter({ready_at, seq}, {p, h}, t)
      end)

    %{
      rt
      | requested: Map.delete(rt.requested, h),
        waiting: Map.delete(rt.waiting, h),
        ready: ready,
        in_flight: dec_in_flight(rt.in_flight, peer, 1)
    }
  end

  defp dec_in_flight(inf, _peer, 0), do: inf

  defp dec_in_flight(inf, peer, n) do
    case Map.get(inf, peer, 0) - n do
      c when c <= 0 -> Map.delete(inf, peer)
      c -> Map.put(inf, peer, c)
    end
  end

  defp pop_before(tree, due?) do
    if :gb_trees.is_empty(tree) do
      nil
    else
      {k, _} = :gb_trees.smallest(tree)
      if due?.(k), do: :gb_trees.take_smallest(tree), else: nil
    end
  end

  defp pop_ready(%__MODULE__{} = rt, peers, now, acc) do
    case pop_before(rt.ready, fn {ready_at, _} -> ready_at <= now end) do
      nil ->
        {rt, acc}

      {{_, seq}, {peer, h}, ready} ->
        rt = %{rt | ready: ready}

        case rt.ann do
          %{^peer => %{^h => %{state: :candidate, seq: ^seq} = a}}
          when is_map_key(peers, peer) ->
            pop_ready(rt, peers, now, [{h, peer, a} | acc])

          _ ->
            pop_ready(rt, peers, now, acc)
        end
    end
  end

  defp wait(rt, _h, []), do: rt

  defp wait(%__MODULE__{} = rt, h, anns) do
    parked = for {p, a} <- anns, do: {a.ready_at, a.seq, p}
    %{rt | waiting: Map.update(rt.waiting, h, parked, &(parked ++ &1))}
  end
end
