defmodule Exnode.Mempool.Pool do
  @moduledoc """
  The mempool's transaction graph. This is the role of Core v32.1
  `CTxMemPool`'s `mapTx`, `mapNextTx` and `TxGraph`, as a functional
  structure owned by the `Exnode.Mempool` process.

  * `entries`: txid => `%Entry{}`
  * `by_wtxid`: wtxid => txid
  * `spenders`: `{txid, vout}` => spending txid (Core `mapNextTx`)
  * `by_script` (only with `new(index_scripts: true)`, else nil):
    scripthash => the txids paying to that script or spending an output
    of it, for the Esplora address endpoints; scripthash is
    `sha256(scriptPubKey)`, as the scripthash index keys it. An entry's
    `spent` (`{value, scripthash}` per input) gives the spent side.

  Clusters are connected components of the parent/child graph. Feerates in
  clusters use the sigop-adjusted weight (Core `FeePerWeight`). Cluster
  limits (Core `DEFAULT_CLUSTER_LIMIT` 64, `DEFAULT_CLUSTER_SIZE_LIMIT_KVB`
  101 kvB, i.e. 404,000 weight) are checked on a staged change, without
  modifying the pool.
  """

  alias Exnode.Codec.Tx
  import Bitwise

  alias Exnode.Mempool.Linearize

  @cluster_count 64
  @cluster_weight 101_000 * 4

  defmodule Entry do
    @moduledoc false
    # weight: sigop-adjusted weight (GetSigOpsAdjustedWeight); vsize: (weight + 3) div 4.
    # spent: {value, scripthash} of each spent output, in input order, when
    # the pool indexes scripts (else nil).
    defstruct [
      :tx,
      :txid,
      :wtxid,
      :fee,
      :vsize,
      :weight,
      :sigops,
      :time,
      :height,
      :spends_coinbase,
      :sequence,
      :spent,
      parents: MapSet.new(),
      children: MapSet.new()
    ]
  end

  # by_time: {entry time, txid} index (gb_tree) for Core CTxMemPool::Expire.
  # lin: the cluster linearization cache (Core TxGraph keeps linearizations
  # up to date incrementally; here they are recomputed lazily, per cluster):
  #   cluster_of: txid => cid; clusters: cid => %{members, chunks}, `chunks`
  #   nil while stale; stale: the cids of stale records. Each record's
  #   members are a union of whole current clusters; a record with chunks is
  #   exactly one current cluster and its chunks are Linearize.chunks of it.
  #   The mempool process refreshes stale records when idle
  #   (`refresh_stale/2`), so RBF diagrams and mining order read current
  #   clusters from here instead of linearizing them on every request.
  # Both are kept in step with `entries` by add/2 and remove/2, the only
  # mutation sites.
  defstruct entries: %{},
            by_wtxid: %{},
            spenders: %{},
            sequence: 0,
            total_vsize: 0,
            total_usage: 0,
            by_time: :gb_trees.empty(),
            lin: %{cluster_of: %{}, clusters: %{}, stale: MapSet.new(), next: 0},
            by_script: nil

  @doc "An empty pool. `index_scripts: true` keeps the `by_script` index."
  def new(opts \\ []),
    do: %__MODULE__{by_script: if(Keyword.get(opts, :index_scripts, false), do: %{})}

  @doc "Whether the pool keeps the `by_script` index."
  def indexes_scripts?(%__MODULE__{by_script: b}), do: b != nil

  @doc "The txids touching scripthash `sh` (needs `index_scripts: true`)."
  def script_txids(%__MODULE__{by_script: b}, sh) when b != nil, do: Map.get(b, sh, MapSet.new())

  def cluster_count_limit, do: @cluster_count
  def cluster_weight_limit, do: @cluster_weight

  def size(%__MODULE__{entries: e}), do: map_size(e)
  def get(%__MODULE__{entries: e}, txid), do: Map.get(e, txid)
  def exists?(%__MODULE__{entries: e}, txid), do: Map.has_key?(e, txid)
  def exists_wtxid?(%__MODULE__{by_wtxid: w}, wtxid), do: Map.has_key?(w, wtxid)
  def by_wtxid(%__MODULE__{by_wtxid: w} = p, wtxid), do: (t = Map.get(w, wtxid)) && get(p, t)

  @doc "Core `GetConflictTx`: the mempool tx spending `outpoint`, or nil."
  def spender(%__MODULE__{spenders: s}, outpoint), do: Map.get(s, outpoint)

  # The scripthashes an entry is indexed under: its outputs' and, when
  # known, the outputs it spends.
  defp entry_scripts(%Entry{tx: tx, spent: spent}) do
    outs = for o <- tx.outputs, do: :crypto.hash(:sha256, o.script_pubkey)
    Enum.uniq(outs ++ for({_, sh} <- spent || [], do: sh))
  end

  defp index_scripts(%__MODULE__{by_script: nil} = p, _e, _op), do: p

  defp index_scripts(%__MODULE__{by_script: b} = p, e, :add) do
    b =
      Enum.reduce(entry_scripts(e), b, fn sh, b ->
        Map.update(b, sh, MapSet.new([e.txid]), &MapSet.put(&1, e.txid))
      end)

    %{p | by_script: b}
  end

  defp index_scripts(%__MODULE__{by_script: b} = p, e, :remove) do
    b =
      Enum.reduce(entry_scripts(e), b, fn sh, b ->
        case Map.get(b, sh) do
          nil ->
            b

          set ->
            set = MapSet.delete(set, e.txid)
            if MapSet.size(set) == 0, do: Map.delete(b, sh), else: Map.put(b, sh, set)
        end
      end)

    %{p | by_script: b}
  end

  @doc "Output `vout` of mempool tx `txid`, or nil."
  def output(%__MODULE__{} = p, txid, vout) do
    case get(p, txid) do
      %Entry{tx: %Tx{outputs: outs}} -> Enum.at(outs, vout)
      nil -> nil
    end
  end

  @doc """
  Adds an entry. Its in-mempool parents are derived from its inputs, and its
  in-mempool children from `spenders`: a tx re-added after a reorg can
  already have children in the pool (Core: UpdateTransactionsFromBlock).
  """
  def add(%__MODULE__{} = p, %Entry{} = e) do
    parents =
      for i <- e.tx.inputs,
          Map.has_key?(p.entries, i.prev_hash),
          into: MapSet.new(),
          do: i.prev_hash

    children =
      for v <- 0..(length(e.tx.outputs) - 1)//1,
          (c = Map.get(p.spenders, {e.txid, v})) != nil,
          into: MapSet.new(),
          do: c

    e = %{e | parents: parents, children: children, sequence: p.sequence}

    entries =
      Enum.reduce(parents, p.entries, fn par, acc ->
        Map.update!(acc, par, &%{&1 | children: MapSet.put(&1.children, e.txid)})
      end)

    entries =
      Enum.reduce(children, entries, fn ch, acc ->
        Map.update!(acc, ch, &%{&1 | parents: MapSet.put(&1.parents, e.txid)})
      end)

    spenders =
      Enum.reduce(e.tx.inputs, p.spenders, &Map.put(&2, {&1.prev_hash, &1.prev_index}, e.txid))

    p = %{
      p
      | entries: Map.put(entries, e.txid, e),
        by_wtxid: Map.put(p.by_wtxid, e.wtxid, e.txid),
        spenders: spenders,
        sequence: p.sequence + 1,
        total_vsize: p.total_vsize + e.vsize,
        total_usage: p.total_usage + usage(e),
        by_time: :gb_trees.enter({e.time, e.txid}, true, p.by_time),
        lin: lin_add(p.lin, e.txid, MapSet.union(parents, children))
    }

    index_scripts(p, e, :add)
  end

  @doc """
  Removes `txids`, without cascading. Callers pass descendant-closed sets
  (eviction, replacement) or confirmed txs (`removeForBlock`), whose
  in-mempool children stay and lose their parent links.
  """
  def remove(%__MODULE__{} = p, txids) do
    Enum.reduce(txids, p, fn txid, p ->
      case p.entries[txid] do
        nil ->
          p

        e ->
          entries =
            Enum.reduce(e.parents, p.entries, fn par, acc ->
              if Map.has_key?(acc, par),
                do: Map.update!(acc, par, &%{&1 | children: MapSet.delete(&1.children, txid)}),
                else: acc
            end)

          entries =
            Enum.reduce(e.children, entries, fn ch, acc ->
              if Map.has_key?(acc, ch),
                do: Map.update!(acc, ch, &%{&1 | parents: MapSet.delete(&1.parents, txid)}),
                else: acc
            end)

          spenders =
            Enum.reduce(e.tx.inputs, p.spenders, fn i, acc ->
              op = {i.prev_hash, i.prev_index}
              if Map.get(acc, op) == txid, do: Map.delete(acc, op), else: acc
            end)

          p = %{
            p
            | entries: Map.delete(entries, txid),
              by_wtxid: Map.delete(p.by_wtxid, e.wtxid),
              spenders: spenders,
              total_vsize: p.total_vsize - e.vsize,
              total_usage: p.total_usage - usage(e),
              by_time: :gb_trees.delete_any({e.time, txid}, p.by_time),
              lin: lin_remove(p.lin, txid)
          }

          index_scripts(p, e, :remove)
      end
    end)
  end

  # The new tx joins its relatives' clusters (parents, and children when a
  # reorg re-adds it): their records merge into one, stale (nothing is
  # linearized here).
  defp lin_add(lin, txid, parents) do
    cids = parents |> Enum.map(&lin.cluster_of[&1]) |> Enum.reject(&is_nil/1) |> Enum.uniq()
    members = Enum.reduce(cids, MapSet.new([txid]), &MapSet.union(&2, lin.clusters[&1].members))
    cid = lin.next

    %{
      lin
      | cluster_of: Enum.reduce(members, lin.cluster_of, &Map.put(&2, &1, cid)),
        clusters:
          lin.clusters |> Map.drop(cids) |> Map.put(cid, %{members: members, chunks: nil}),
        stale: lin.stale |> MapSet.difference(MapSet.new(cids)) |> MapSet.put(cid),
        next: cid + 1
    }
  end

  # The tx leaves its record, which goes stale (it may have split).
  defp lin_remove(lin, txid) do
    case lin.cluster_of[txid] do
      nil ->
        lin

      cid ->
        members = MapSet.delete(lin.clusters[cid].members, txid)

        {clusters, stale} =
          if MapSet.size(members) == 0,
            do: {Map.delete(lin.clusters, cid), MapSet.delete(lin.stale, cid)},
            else:
              {Map.put(lin.clusters, cid, %{members: members, chunks: nil}),
               MapSet.put(lin.stale, cid)}

        %{lin | cluster_of: Map.delete(lin.cluster_of, txid), clusters: clusters, stale: stale}
    end
  end

  # Linearizes a stale record: one fresh record per current cluster in it.
  # Returns {pool, new cids}.
  defp lin_refresh(p, cid) do
    rec = p.lin.clusters[cid]

    lin = %{
      p.lin
      | clusters: Map.delete(p.lin.clusters, cid),
        stale: MapSet.delete(p.lin.stale, cid)
    }

    {lin, cids, _} =
      Enum.reduce(rec.members, {lin, [], MapSet.new()}, fn t, {lin, cids, seen} ->
        if MapSet.member?(seen, t) do
          {lin, cids, seen}
        else
          c = cluster(p, t)
          new = lin.next
          chunks = for {f, w, ids} <- Linearize.chunks(cluster_input(p, c)), do: {{f, w}, ids}

          lin = %{
            lin
            | cluster_of: Enum.reduce(c, lin.cluster_of, &Map.put(&2, &1, new)),
              clusters: Map.put(lin.clusters, new, %{members: c, chunks: chunks}),
              next: new + 1
          }

          {lin, [new | cids], MapSet.union(seen, c)}
        end
      end)

    {%{p | lin: lin}, cids}
  end

  @doc """
  The chunks of every cluster, `[{{fee, weight}, txids}]` per cluster, from
  the linearization cache (only clusters changed since their last
  linearization are linearized). Returns the pool with the cache refreshed.
  """
  def cluster_chunks(%__MODULE__{} = p) do
    p = Enum.reduce(p.lin.stale, p, fn cid, p -> elem(lin_refresh(p, cid), 0) end)
    {p, for({_cid, %{chunks: ch}} <- p.lin.clusters, do: ch)}
  end

  @doc """
  Linearizes stale cache records (oldest cids first) until about
  `max_txs` txs were linearized (at least one record). Returns
  `{pool, more_stale?}`. The mempool process calls it when idle.
  """
  def refresh_stale(%__MODULE__{} = p, max_txs) do
    p.lin.stale
    |> Enum.sort()
    |> Enum.reduce_while({p, 0}, fn cid, {p, n} ->
      if n >= max_txs do
        {:halt, {p, n}}
      else
        size = MapSet.size(p.lin.clusters[cid].members)
        {:cont, {elem(lin_refresh(p, cid), 0), n + size}}
      end
    end)
    |> then(fn {p, _} -> {p, MapSet.size(p.lin.stale) > 0} end)
  end

  @doc "Whether some cluster's cached linearization is stale."
  def stale?(%__MODULE__{lin: lin}), do: MapSet.size(lin.stale) > 0

  # The cached chunks `[{{fee, weight}, txids}]` of `cluster` (a current
  # cluster, as a txid set), or nil while its record is stale.
  defp cached_chunks(p, cluster) do
    with t when t != nil <- Enum.at(cluster, 0),
         cid when cid != nil <- p.lin.cluster_of[t],
         %{chunks: chunks} when chunks != nil <- p.lin.clusters[cid] do
      chunks
    else
      _ -> nil
    end
  end

  # Approximation of Core's per-entry DynamicMemoryUsage (C++ allocation
  # accounting): trimming starts at a somewhat different point than Core's;
  # the order (worst chunk first) and the rolling fee rules are Core's.
  defp usage(%Entry{tx: tx}),
    do: 3 * byte_size(tx.raw) + 400 + 64 * (length(tx.inputs) + length(tx.outputs))

  @doc "Core `CalculateDescendants`: `txids` and all their in-mempool descendants."
  def with_descendants(%__MODULE__{} = p, txids), do: closure(p, txids, :children)

  @doc "All in-mempool ancestors of `txid` (excluding itself)."
  def ancestors(%__MODULE__{} = p, txid),
    do: p |> closure([txid], :parents) |> MapSet.delete(txid)

  def descendants(%__MODULE__{} = p, txid),
    do: p |> closure([txid], :children) |> MapSet.delete(txid)

  defp closure(p, start, dir) do
    walk(p, Enum.filter(start, &Map.has_key?(p.entries, &1)), MapSet.new(), dir)
  end

  defp walk(_p, [], seen, _dir), do: seen

  defp walk(p, [t | rest], seen, dir) do
    if MapSet.member?(seen, t) do
      walk(p, rest, seen, dir)
    else
      next = p.entries[t] |> Map.fetch!(dir) |> Enum.filter(&Map.has_key?(p.entries, &1))
      walk(p, next ++ rest, MapSet.put(seen, t), dir)
    end
  end

  @doc "The cluster (connected component) containing `txid`, as a set of txids."
  def cluster(%__MODULE__{} = p, txid) do
    # A current cache record is exactly one cluster: no graph walk needed.
    with cid when cid != nil <- p.lin.cluster_of[txid],
         %{chunks: chunks, members: members} when chunks != nil <- p.lin.clusters[cid] do
      members
    else
      _ -> component(p.entries, [txid], MapSet.new())
    end
  end

  defp component(_entries, [], seen), do: seen

  defp component(entries, [t | rest], seen) do
    if MapSet.member?(seen, t) or not Map.has_key?(entries, t) do
      component(entries, rest, seen)
    else
      e = entries[t]

      component(
        entries,
        MapSet.to_list(e.parents) ++ MapSet.to_list(e.children) ++ rest,
        MapSet.put(seen, t)
      )
    end
  end

  @doc """
  Core `TxGraph::Trim` after a reorg re-add (`UpdateTransactionsFromBlock`):
  a re-added tx joins the clusters of its in-pool children with no limit
  check, so one disconnected tx with many spent outputs can merge any number
  of full clusters (MP-1b in STATE_MACHINES.md). Linearizing such a cluster
  takes seconds to hours and blocks the mempool process.

  For every cluster containing one of `txids` that exceeds the count or
  weight limit, txs are taken in topological order, highest individual
  feerate first. A tx is kept while it fits and all its parents were kept;
  the rest (descendant-closed) are removed. Nothing is linearized. Returns
  `{pool, removed txids}`.
  """
  def trim_oversized(%__MODULE__{} = p, txids) do
    {p, removed, _seen} =
      Enum.reduce(txids, {p, [], MapSet.new()}, fn t, {p, removed, seen} ->
        if MapSet.member?(seen, t) or not exists?(p, t) do
          {p, removed, seen}
        else
          c = component(p.entries, [t], MapSet.new())
          seen = MapSet.union(seen, c)

          if within_limits?(p, c) do
            {p, removed, seen}
          else
            drop = trim_drop(p, c)
            {remove(p, drop), drop ++ removed, seen}
          end
        end
      end)

    {p, removed}
  end

  defp within_limits?(p, c) do
    MapSet.size(c) <= @cluster_count and
      Enum.reduce_while(c, 0, fn t, w ->
        w = w + p.entries[t].weight
        if w > @cluster_weight, do: {:halt, :over}, else: {:cont, w}
      end) != :over
  end

  defp trim_drop(p, c) do
    in_c = fn ids -> Enum.filter(ids, &MapSet.member?(c, &1)) end
    indeg = Map.new(c, fn t -> {t, length(in_c.(p.entries[t].parents))} end)

    key = fn t ->
      e = p.entries[t]
      {-div(e.fee * (1 <<< 64), max(e.weight, 1)), t}
    end

    ready = for({t, 0} <- indeg, into: [], do: key.(t)) |> :gb_sets.from_list()
    trim_walk(p, in_c, key, ready, indeg, MapSet.new(), 0, [])
  end

  defp trim_walk(p, in_c, key, ready, indeg, kept, weight, drop) do
    if :gb_sets.is_empty(ready) do
      drop
    else
      {{_, t}, ready} = :gb_sets.take_smallest(ready)
      e = p.entries[t]

      fits =
        MapSet.size(kept) < @cluster_count and weight + e.weight <= @cluster_weight and
          Enum.all?(in_c.(e.parents), &MapSet.member?(kept, &1))

      {kept, weight, drop} =
        if fits,
          do: {MapSet.put(kept, t), weight + e.weight, drop},
          else: {kept, weight, [t | drop]}

      {ready, indeg} =
        Enum.reduce(in_c.(e.children), {ready, indeg}, fn ch, {r, d} ->
          n = d[ch] - 1
          {if(n == 0, do: :gb_sets.add(key.(ch), r), else: r), Map.put(d, ch, n)}
        end)

      trim_walk(p, in_c, key, ready, indeg, kept, weight, drop)
    end
  end

  @doc "Linearization input for a set of txids: `%{txid => {fee, weight, in-set parents}}`."
  def cluster_input(%__MODULE__{} = p, txids) do
    set = MapSet.new(txids)

    Map.new(txids, fn t ->
      e = p.entries[t]
      {t, {e.fee, e.weight, Enum.filter(e.parents, &MapSet.member?(set, &1))}}
    end)
  end

  @doc "Optimal chunks of the cluster of `txid`: `[{fee, weight, [txids]}]`."
  def chunks(%__MODULE__{} = p, txid), do: Linearize.chunks(cluster_input(p, cluster(p, txid)))

  @doc """
  Core `CTxMemPool::ExtractBestByMiningScoreWithTopology`: of `txids`
  (duplicates and txids not in the pool dropped), the best `n` entries in
  mining order, and the remaining txids. Mining order (Core
  `TxGraph::CompareMainOrder`): higher chunk feerate first; within a cluster,
  linearization order (so parents come before children); between clusters
  with equal chunk feerates, the chunk whose newest entry is older first
  (Core uses an equal-feerate-prefix size, then its mempool fallback order;
  this tie-break is the one difference).
  """
  def extract_best(%__MODULE__{} = p, txids, n) do
    present = txids |> Enum.uniq() |> Enum.filter(&Map.has_key?(p.entries, &1))

    if present == [] or n <= 0 do
      {[], present}
    else
      keys = mining_keys(p, present)
      sorted = Enum.sort(present, fn a, b -> not main_order_less?(keys[b], keys[a]) end)
      {best, rest} = Enum.split(sorted, n)
      {Enum.map(best, &p.entries[&1]), rest}
    end
  end

  # Per txid: chunk feerate, cluster id, position in the cluster's linearization,
  # newest sequence in its chunk. One linearization per cluster.
  defp mining_keys(p, txids) do
    Enum.reduce(txids, %{}, fn t, acc ->
      if Map.has_key?(acc, t) do
        acc
      else
        cluster = cluster(p, t)
        cid = Enum.min(cluster)

        chunks =
          case cached_chunks(p, cluster) do
            nil -> Linearize.chunks(cluster_input(p, cluster))
            cached -> for {{f, w}, ids} <- cached, do: {f, w, ids}
          end

        {acc, _} =
          Enum.reduce(chunks, {acc, 0}, fn {fee, w, txs}, {acc, pos} ->
            newest = txs |> Enum.map(&p.entries[&1].sequence) |> Enum.max()

            txs
            |> Enum.with_index(pos)
            |> Enum.reduce({acc, pos + length(txs)}, fn {tx, i}, {acc, next} ->
              {Map.put(acc, tx, %{
                 fee: fee,
                 weight: w,
                 cluster: cid,
                 lin: i,
                 newest: newest,
                 txid: tx
               }), next}
            end)
          end)

        acc
      end
    end)
  end

  defp main_order_less?(a, b) do
    r = a.fee * b.weight - b.fee * a.weight

    cond do
      r != 0 -> r > 0
      a.cluster == b.cluster -> a.lin < b.lin
      a.newest != b.newest -> a.newest < b.newest
      true -> a.txid < b.txid
    end
  end

  # --- staged changes (Core ChangeSet / TxGraph staging) -------------------------

  @doc """
  Stages `adds` (entries) and `removes` (txids) without changing the pool.
  Returns `%{main_clusters, staging_clusters, oversized}`:

  * `main_clusters`: the pool's clusters touched by the change (containing a
    removed tx, or a parent of an added tx), as txid sets;
  * `staging_clusters`: the components that replace them after the change,
    each as a linearization input map;
  * `oversized`: whether any staging cluster exceeds the cluster limits
    (Core `TxGraph::IsOversized`).
  """
  def stage(%__MODULE__{} = p, adds, removes) do
    removes = MapSet.new(removes)
    add_ids = MapSet.new(adds, & &1.txid)

    seeds =
      MapSet.to_list(removes) ++
        for(e <- adds, i <- e.tx.inputs, Map.has_key?(p.entries, i.prev_hash), do: i.prev_hash)

    main = seeds |> Enum.map(&cluster(p, &1)) |> Enum.uniq()
    touched = Enum.reduce(main, MapSet.new(), &MapSet.union/2)

    # The staging graph: touched txs minus removals, plus additions.
    nodes =
      for(t <- touched, not MapSet.member?(removes, t), into: %{}, do: {t, p.entries[t]})
      |> Map.merge(Map.new(adds, &{&1.txid, &1}))

    # In-staging parents. A pool tx's in-pool parents are on its entry; an
    # added tx's come from its inputs; a pool tx spending an added tx's
    # output (a reorg re-add) is found through the spenders index. Reading
    # the entries instead of every input of every touched tx keeps this
    # cheap for the ~6,400 txs of 100 full clusters (AUD-F2).
    added_children =
      for e <- adds,
          vout <- 0..(length(e.tx.outputs) - 1)//1,
          c = p.spenders[{e.txid, vout}],
          c != nil and Map.has_key?(nodes, c),
          reduce: %{} do
        acc -> Map.update(acc, c, [e.txid], &[e.txid | &1])
      end

    parents =
      Map.new(nodes, fn {t, e} ->
        ps =
          if MapSet.member?(add_ids, t),
            do:
              for(i <- e.tx.inputs, Map.has_key?(nodes, i.prev_hash), uniq: true, do: i.prev_hash),
            else:
              for(q <- e.parents, Map.has_key?(nodes, q), do: q) ++
                Enum.uniq(Map.get(added_children, t, []))

        {t, ps}
      end)

    children =
      Enum.reduce(parents, Map.new(nodes, &{elem(&1, 0), []}), fn {t, ps}, acc ->
        Enum.reduce(ps, acc, &Map.update!(&2, &1, fn l -> [t | l] end))
      end)

    staging = components(Map.keys(nodes), parents, children)

    staging_inputs =
      for comp <- staging do
        Map.new(comp, fn t ->
          e = nodes[t]
          {t, {e.fee, e.weight, parents[t]}}
        end)
      end

    oversized =
      Enum.any?(staging_inputs, fn c ->
        map_size(c) > @cluster_count or
          Enum.reduce(c, 0, fn {_, {_, w, _}}, a -> a + w end) > @cluster_weight
      end)

    %{main_clusters: main, staging_clusters: staging_inputs, oversized: oversized, added: add_ids}
  end

  defp components(ids, parents, children) do
    {comps, _} =
      Enum.reduce(ids, {[], MapSet.new()}, fn id, {comps, seen} ->
        if MapSet.member?(seen, id) do
          {comps, seen}
        else
          comp = flood([id], MapSet.new(), parents, children)
          {[comp | comps], MapSet.union(seen, comp)}
        end
      end)

    comps
  end

  defp flood([], seen, _p, _c), do: seen

  defp flood([t | rest], seen, p, c) do
    if MapSet.member?(seen, t),
      do: flood(rest, seen, p, c),
      else: flood(p[t] ++ c[t] ++ rest, MapSet.put(seen, t), p, c)
  end

  # Linearization work allowed per diagram pair (`Linearize.chunks_bounded/3`
  # units, ~25-100 ns each: a few ms). An optimal linearization of a dense
  # 64-tx cluster takes ~0.3-1.6M units; a few-tx cluster, hundreds.
  @diagram_budget 100_000

  @doc """
  Core `GetMainStagingDiagrams`: chunk feerates of the touched main clusters
  and of the staging clusters, each sorted by decreasing feerate.

  The work is bounded, as Core's TxGraph bounds it (AUD-F2 in
  STATE_MACHINES.md: invalid-witness RBF attempts made the mempool process
  linearize ~200 64-tx clusters from scratch per attempt, seconds each,
  before the scripts were checked). Main clusters come from the
  linearization cache; a stale one is linearized within `budget`. Staging
  clusters are linearized optimally while the budget lasts, then in the
  order of the main linearizations they come from (restricted to what
  stays, additions last): valid but maybe not optimal, which can only make
  the staging diagram worse, so a replacement is rejected rather than
  wrongly accepted.
  """
  def diagrams(%__MODULE__{} = p, staged, budget \\ @diagram_budget) do
    {main, budget} =
      Enum.map_reduce(staged.main_clusters, budget, fn c, budget ->
        case cached_chunks(p, c) do
          nil ->
            {chunks, budget} = Linearize.chunks_bounded(cluster_input(p, c), budget)
            {for({f, w, ids} <- chunks, do: {{f, w}, ids}), budget}

          chunks ->
            {chunks, budget}
        end
      end)

    # Positions in the main linearizations, concatenated: restricted to a
    # staging cluster, a topological order of its old txs.
    pos =
      for(chunks <- main, {_, ids} <- chunks, id <- ids, do: id)
      |> Enum.with_index()
      |> Map.new()

    {staging, _} =
      Enum.map_reduce(staged.staging_clusters, budget, fn c, budget ->
        {old, added} = c |> Map.keys() |> Enum.split_with(&Map.has_key?(pos, &1))
        fallback = Enum.sort_by(old, &pos[&1]) ++ Linearize.topological_order(c, added)
        Linearize.chunks_bounded(c, budget, fallback)
      end)

    {
      Linearize.sort_desc(for chunks <- main, {fr, _} <- chunks, do: fr),
      Linearize.sort_desc(for chunks <- staging, {f, w, _} <- chunks, do: {f, w})
    }
  end

  @doc """
  Core `CTxMemPool::Expire` lookup: the txids whose entry time is before
  `cutoff`, walked from the oldest in the time index (not a scan of the pool).
  """
  def expired(%__MODULE__{by_time: t}, cutoff),
    do: take_expired(:gb_trees.next(:gb_trees.iterator(t)), cutoff, [])

  defp take_expired({{time, txid}, _, it}, cutoff, acc) when is_number(time) and time < cutoff,
    do: take_expired(:gb_trees.next(it), cutoff, [txid | acc])

  defp take_expired(_, _cutoff, acc), do: Enum.reverse(acc)

  @doc """
  Core `TxGraph::GetWorstMainChunk`: the lowest-feerate chunk over all
  clusters, as `{{fee, weight}, txids}`. Ties go to the larger chunk,
  matching `ByRatioNegSize` ordering, then to the chunk with the smallest
  txid (a deterministic stand-in for Core's fallback order).
  """
  def worst_chunk(%__MODULE__{} = p) do
    p
    |> all_clusters()
    |> Enum.flat_map(fn c ->
      for {f, w, ids} <- Linearize.chunks(cluster_input(p, c)), do: {{f, w}, ids}
    end)
    |> Enum.min_by(fn {fr, ids} -> chunk_key(fr, ids) end, fn -> nil end)
  end

  # Every cluster of the pool, as txid sets.
  defp all_clusters(p) do
    p.entries
    |> Map.keys()
    |> Enum.reduce({MapSet.new(), []}, fn t, {seen, acc} ->
      if MapSet.member?(seen, t),
        do: {seen, acc},
        else:
          (
            c = cluster(p, t)
            {MapSet.union(seen, c), [c | acc]}
          )
    end)
    |> elem(1)
  end

  # Eviction order, ascending: lower feerate first, then the larger chunk
  # (Core ByRatioNegSize), then the smallest txid. The feerate is encoded as
  # floor(fee * 2^128 / weight): for weights below 2^64 two different ratios
  # never share a floor and equal ratios always do, so the term order of the
  # key is exactly Linearize.ratio_cmp's order.
  defp chunk_key({fee, weight}, ids), do: {div(fee * (1 <<< 128), weight), -weight, Enum.min(ids)}

  @doc """
  Core `CTxMemPool::TrimToSize`, the evictions: while the pool is over
  `limit` bytes, remove its worst chunk (`worst_chunk/1` order). Returns
  `{pool, evicted}`, `evicted` being the removed chunks in order as
  `{{fee, weight}, txids}`.

  Chunks come from the linearization cache (`cluster_chunks/1`): only
  clusters changed since they were last linearized are linearized again.
  After an eviction only the cluster that lost the chunk can change (its
  remainder may split into several clusters), so each step sees exactly the
  chunks a full recomputation would (`Linearize` is deterministic and other
  clusters are untouched) and picks the same chunk as `worst_chunk/1` on the
  current pool. When the evicted
  chunk was its cluster's last and the remainder stays one cluster, the
  remaining chunks are reused unchanged (what a fresh linearization of that
  ancestor-closed remainder gives); only a split cluster is linearized again.
  A precomputed order alone is not enough: equal-feerate parts of one
  cluster can share a chunk and become separate chunks once it splits.
  """
  def trim(%__MODULE__{} = p, limit) do
    if size(p) > 0 and p.total_usage > limit do
      {p, _} = cluster_chunks(p)

      set =
        for {cid, %{chunks: chunks}} <- p.lin.clusters,
            {fr, ids} <- chunks,
            reduce: :gb_sets.new() do
          set -> :gb_sets.add_element({chunk_key(fr, ids), cid}, set)
        end

      trim_loop(p, set, limit, [])
    else
      {p, []}
    end
  end

  defp index_cids(set, p, cids) do
    for cid <- cids, {fr, ids} <- p.lin.clusters[cid].chunks, reduce: set do
      set -> :gb_sets.add_element({chunk_key(fr, ids), cid}, set)
    end
  end

  defp trim_loop(p, set, limit, evicted) do
    if size(p) > 0 and p.total_usage > limit and not :gb_sets.is_empty(set) do
      {{key, cid}, set} = :gb_sets.take_smallest(set)
      list = p.lin.clusters[cid].chunks

      {others, [{_fr, ids} = chunk]} =
        Enum.split_with(list, fn {fr, ids} -> chunk_key(fr, ids) != key end)

      last? = chunk == List.last(list)
      # remove/2 takes the txs out of the cache record and marks it stale.
      p = remove(p, ids)
      rest = Enum.flat_map(others, &elem(&1, 1))

      {p, set} =
        cond do
          rest == [] ->
            {p, set}

          # The cluster's last (worst) chunk went and the rest is still one
          # cluster: its remaining chunks are what a fresh linearization gives
          # (the remainder is ancestor-closed, so its best closures are the old
          # ones); they stay, and the record is current again.
          last? and MapSet.size(cluster(p, hd(rest))) == length(rest) ->
            p = put_in(p.lin.clusters[cid].chunks, others)
            {put_in(p.lin.stale, MapSet.delete(p.lin.stale, cid)), set}

          # Otherwise (the cluster split): its other chunks leave the index and
          # each new cluster is linearized.
          true ->
            set =
              Enum.reduce(others, set, fn {fr, ids}, s ->
                :gb_sets.del_element({chunk_key(fr, ids), cid}, s)
              end)

            {p, cids} = lin_refresh(p, cid)
            {p, index_cids(set, p, cids)}
        end

      trim_loop(p, set, limit, [chunk | evicted])
    else
      {p, Enum.reverse(evicted)}
    end
  end
end
