defmodule Exnode.P2P.TxRelay.Orphanage do
  @moduledoc """
  Orphan transaction pool, per-peer weight/latency accounting, and stepped
  reconsideration work queues. Port of the `TxOrphanage` (`node/txorphanage.cpp`)
  role used by `Exnode.P2P.TxRelay`.

  Limits enforced incrementally in O(evictions):
  * count cap (`1,000` orphans, oldest evicted first)
  * per-peer weight budget (`404,000` WU, oldest of that peer evicted first)
  * global latency score cap (`3,000`, oldest of the highest-score peer evicted first)
  """

  alias Exnode.Codec.Tx

  @max_orphans 1_000
  @orphan_peer_weight 404_000
  @max_orphan_score 3_000

  defstruct orphans: %{},
            orphan_by_parent: %{},
            orphan_seq: 0,
            orphan_order: :gb_sets.empty(),
            orphan_peers: %{},
            orphan_score: 0,
            orphan_work: %{},
            orphan_work_peers: :queue.new(),
            orphan_work_set: MapSet.new(),
            orphan_work_scheduled: false

  @type t :: %__MODULE__{}

  def new, do: %__MODULE__{}

  @doc "Extracts an `%Orphanage{}` from a `TxRelay` state map."
  def from_state(st) do
    %__MODULE__{
      orphans: st.orphans,
      orphan_by_parent: st.orphan_by_parent,
      orphan_seq: st.orphan_seq,
      orphan_order: st.orphan_order,
      orphan_peers: st.orphan_peers,
      orphan_score: st.orphan_score,
      orphan_work: st.orphan_work,
      orphan_work_peers: st.orphan_work_peers,
      orphan_work_set: st.orphan_work_set,
      orphan_work_scheduled: st.orphan_work_scheduled
    }
  end

  @doc "Writes an `%Orphanage{}`'s fields back into a `TxRelay` state map."
  def into_state(%__MODULE__{} = o, st) do
    %{
      st
      | orphans: o.orphans,
        orphan_by_parent: o.orphan_by_parent,
        orphan_seq: o.orphan_seq,
        orphan_order: o.orphan_order,
        orphan_peers: o.orphan_peers,
        orphan_score: o.orphan_score,
        orphan_work: o.orphan_work,
        orphan_work_peers: o.orphan_work_peers,
        orphan_work_set: o.orphan_work_set,
        orphan_work_scheduled: o.orphan_work_scheduled
    }
  end

  def has?(%__MODULE__{orphans: os}, wtxid), do: Map.has_key?(os, wtxid)
  def get(%__MODULE__{orphans: os}, wtxid), do: os[wtxid]
  def wtxids(%__MODULE__{orphans: os}), do: Map.keys(os)

  def unique_parents(tx), do: tx.inputs |> Enum.map(& &1.prev_hash) |> Enum.uniq()

  @doc "`{:txid, parent}` for every MSG_WTX item naming an orphan `peer` does not yet announce."
  def parent_gtxids(%__MODULE__{orphans: orphans}, peer, items) do
    for %{type: :wtx, hash: h} <- items,
        entry = orphans[h],
        entry != nil and not MapSet.member?(entry.announcers, peer),
        parent <- unique_parents(entry.tx),
        uniq: true,
        do: {:txid, parent}
  end

  @doc "Stores `tx` from `peer` (or adds `peer` as an announcer) and enforces limits."
  def store(%__MODULE__{} = o, tx, peer) do
    %__MODULE__{} =
      o =
      if Map.has_key?(o.orphans, tx.wtxid) do
        add_announcer(o, tx.wtxid, peer)
      else
        put(o, tx.wtxid, %{
          tx: tx,
          announcers: MapSet.new([peer]),
          seq: o.orphan_seq,
          weight: Tx.weight(tx)
        })
      end

    limit(%{o | orphan_seq: o.orphan_seq + 1})
  end

  @doc "Inserts or replaces orphan `w`, indexing by parent, age, and announcers."
  def put(%__MODULE__{} = o, w, entry) do
    %__MODULE__{} = o = drop(o, [w])

    by_parent =
      Enum.reduce(unique_parents(entry.tx), o.orphan_by_parent, fn p, acc ->
        Map.update(acc, p, MapSet.new([w]), &MapSet.put(&1, w))
      end)

    o = %{
      o
      | orphans: Map.put(o.orphans, w, entry),
        orphan_by_parent: by_parent,
        orphan_order: :gb_sets.add({entry.seq, w}, o.orphan_order),
        orphan_score: o.orphan_score + orphan_input_score(entry)
    }

    Enum.reduce(entry.announcers, o, &peer_charge(&2, &1, w, entry, 1))
  end

  @doc "Removes `ws` (absent ones ignored) and updates parent, order, and peer indexes."
  def drop(%__MODULE__{} = o, ws) do
    Enum.reduce(ws, o, fn w, %__MODULE__{} = acc ->
      case Map.pop(acc.orphans, w) do
        {nil, _} ->
          acc

        {entry, orphans} ->
          by_parent =
            Enum.reduce(unique_parents(entry.tx), acc.orphan_by_parent, fn p, bp ->
              case bp do
                %{^p => set} ->
                  set = MapSet.delete(set, w)
                  if MapSet.size(set) == 0, do: Map.delete(bp, p), else: Map.put(bp, p, set)

                _ ->
                  bp
              end
            end)

          acc = %{
            acc
            | orphans: orphans,
              orphan_by_parent: by_parent,
              orphan_order: :gb_sets.delete_any({entry.seq, w}, acc.orphan_order),
              orphan_score: acc.orphan_score - orphan_input_score(entry)
          }

          Enum.reduce(entry.announcers, acc, &peer_charge(&2, &1, w, entry, -1))
      end
    end)
  end

  @doc "Core `EraseForBlock`: removes orphans confirmed in `hashes` or conflicting with `spent`."
  def erase_for_block(%__MODULE__{} = o, hashes, spent) do
    conflicting =
      for {prev, _} = op <- spent,
          w <- Map.get(o.orphan_by_parent, prev, []),
          Enum.any?(o.orphans[w].tx.inputs, &({&1.prev_hash, &1.prev_index} == op)),
          do: w

    confirmed_orphans = Enum.filter(hashes, &Map.has_key?(o.orphans, &1))
    drop(o, Enum.uniq(conflicting ++ confirmed_orphans))
  end

  @doc "Core `AddAnnouncer`: `peer` also announces orphan `w`."
  def add_announcer(%__MODULE__{} = o, w, peer) do
    entry = o.orphans[w]

    if MapSet.member?(entry.announcers, peer) do
      o
    else
      entry = %{entry | announcers: MapSet.put(entry.announcers, peer)}
      peer_charge(%{o | orphans: Map.put(o.orphans, w, entry)}, peer, w, entry, 1)
    end
  end

  @doc "Removes `peer`'s announcement of `w`; erases `w` if no announcers remain."
  def del_announcer(%__MODULE__{} = o, w, peer) do
    case o.orphans do
      %{^w => entry} ->
        cond do
          not MapSet.member?(entry.announcers, peer) ->
            o

          MapSet.size(entry.announcers) == 1 ->
            drop(o, [w])

          true ->
            entry = %{entry | announcers: MapSet.delete(entry.announcers, peer)}
            peer_charge(%{o | orphans: Map.put(o.orphans, w, entry)}, peer, w, entry, -1)
        end

      _ ->
        o
    end
  end

  @doc "Core `EraseForPeer`: removes `peer`'s orphan announcements and queued work."
  def erase_for_peer(%__MODULE__{} = o, peer) do
    o =
      case o.orphan_peers do
        %{^peer => %{anns: anns}} ->
          anns
          |> :gb_sets.to_list()
          |> Enum.reduce(o, fn {_, w}, acc -> del_announcer(acc, w, peer) end)

        _ ->
          o
      end

    drop_work(o, peer)
  end

  @doc "Core `LimitOrphans`: enforces count, per-peer weight, and global latency score caps."
  def limit(%__MODULE__{} = o) do
    %__MODULE__{} = o = trim_count(o)
    o = o.orphan_peers |> Map.keys() |> Enum.reduce(o, &trim_peer_weight(&2, &1))
    trim_score(o)
  end

  @doc "`{wtxid, orphan}` pairs spending any of `txids`, in O(children)."
  def children(%__MODULE__{} = o, txids) do
    txids
    |> Enum.flat_map(&Enum.to_list(Map.get(o.orphan_by_parent, &1, MapSet.new())))
    |> Enum.uniq()
    |> Enum.map(&{&1, o.orphans[&1]})
  end

  @doc """
  Core `AddChildrenToWorkSet`: assigns each unqueued orphan spending `txids`
  to a random announcer's work queue. Returns `{orphanage, send_work_msg?}`.
  """
  def enqueue_children(%__MODULE__{} = o, txids) do
    o
    |> children(txids)
    |> Enum.sort_by(fn {_, entry} -> entry.seq end)
    |> Enum.reduce(o, fn {w, entry}, %__MODULE__{} = acc ->
      if MapSet.member?(acc.orphan_work_set, w),
        do: acc,
        else: enqueue_work(acc, w, random_announcer(entry))
    end)
    |> ensure_scheduled()
  end

  def clear_scheduled(%__MODULE__{} = o), do: %{o | orphan_work_scheduled: false}

  def ensure_scheduled(%__MODULE__{orphan_work_scheduled: false, orphan_work: work} = o)
      when map_size(work) > 0,
      do: {%{o | orphan_work_scheduled: true}, true}

  def ensure_scheduled(%__MODULE__{} = o), do: {o, false}

  @doc "Pops the next peer in round-robin work order: `{:empty, o}` | `{:ok, peer, o}`."
  def pop_next_work_peer(%__MODULE__{} = o) do
    case :queue.out(o.orphan_work_peers) do
      {:empty, _} -> {:empty, o}
      {{:value, peer}, rest} -> {:ok, peer, %{o | orphan_work_peers: rest}}
    end
  end

  @doc "Pops the next queued orphan wtxid for `peer`: `{:empty, o}` | `{:ok, wtxid, o}`."
  def pop_peer_work(%__MODULE__{} = o, peer) do
    case :queue.out(Map.get(o.orphan_work, peer, :queue.new())) do
      {:empty, _} ->
        {:empty, %{o | orphan_work: Map.delete(o.orphan_work, peer)}}

      {{:value, w}, rest} ->
        work =
          if :queue.is_empty(rest),
            do: Map.delete(o.orphan_work, peer),
            else: Map.put(o.orphan_work, peer, rest)

        {:ok, w, %{o | orphan_work: work, orphan_work_set: MapSet.delete(o.orphan_work_set, w)}}
    end
  end

  @doc "Requeues `peer` at the back of `orphan_work_peers` if work remains for it."
  def requeue_work_peer(%__MODULE__{} = o, peer) do
    if Map.has_key?(o.orphan_work, peer) and not :queue.member(peer, o.orphan_work_peers),
      do: %{o | orphan_work_peers: :queue.in(peer, o.orphan_work_peers)},
      else: o
  end

  # --- internal helpers -------------------------------------------------------

  defp trim_count(%__MODULE__{} = o) do
    if map_size(o.orphans) > @max_orphans do
      {_, w} = :gb_sets.smallest(o.orphan_order)
      trim_count(drop(o, [w]))
    else
      o
    end
  end

  defp trim_peer_weight(%__MODULE__{} = o, peer) do
    case o.orphan_peers do
      %{^peer => %{weight: weight, anns: anns}} when weight > @orphan_peer_weight ->
        {_, w} = :gb_sets.smallest(anns)
        trim_peer_weight(del_announcer(o, w, peer), peer)

      _ ->
        o
    end
  end

  defp trim_score(%__MODULE__{} = o) do
    if o.orphan_score > @max_orphan_score and o.orphan_peers != %{} do
      {peer, %{anns: anns}} = Enum.max_by(o.orphan_peers, fn {_, i} -> i.score end)
      {_, w} = :gb_sets.smallest(anns)
      trim_score(del_announcer(o, w, peer))
    else
      o
    end
  end

  defp orphan_input_score(entry), do: div(length(entry.tx.inputs), 10)

  defp orphan_weight(%{weight: w}), do: w
  defp orphan_weight(entry), do: Tx.weight(entry.tx)

  defp peer_charge(%__MODULE__{} = o, peer, w, entry, sign) do
    info = Map.get(o.orphan_peers, peer, %{weight: 0, score: 0, anns: :gb_sets.empty()})
    score = 1 + orphan_input_score(entry)

    anns =
      if sign > 0,
        do: :gb_sets.add({entry.seq, w}, info.anns),
        else: :gb_sets.delete_any({entry.seq, w}, info.anns)

    info = %{
      info
      | weight: info.weight + sign * orphan_weight(entry),
        score: info.score + sign * score,
        anns: anns
    }

    peers =
      if :gb_sets.is_empty(anns),
        do: Map.delete(o.orphan_peers, peer),
        else: Map.put(o.orphan_peers, peer, info)

    %{o | orphan_peers: peers, orphan_score: o.orphan_score + sign}
  end

  defp random_announcer(entry) do
    case MapSet.to_list(entry.announcers) do
      [] -> nil
      peers -> Enum.random(peers)
    end
  end

  defp enqueue_work(%__MODULE__{} = o, w, peer) do
    {q, peers} =
      case o.orphan_work do
        %{^peer => q} -> {q, o.orphan_work_peers}
        _ -> {:queue.new(), :queue.in(peer, o.orphan_work_peers)}
      end

    %{
      o
      | orphan_work: Map.put(o.orphan_work, peer, :queue.in(w, q)),
        orphan_work_peers: peers,
        orphan_work_set: MapSet.put(o.orphan_work_set, w)
    }
  end

  defp drop_work(%__MODULE__{} = o, peer) do
    case Map.pop(o.orphan_work, peer) do
      {nil, _} ->
        o

      {q, work} ->
        %{
          o
          | orphan_work: work,
            orphan_work_set:
              Enum.reduce(:queue.to_list(q), o.orphan_work_set, &MapSet.delete(&2, &1)),
            orphan_work_peers: :queue.filter(&(&1 != peer), o.orphan_work_peers)
        }
    end
  end
end
