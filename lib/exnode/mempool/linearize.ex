defmodule Exnode.Mempool.Linearize do
  @moduledoc """
  Optimal cluster linearization and chunking. This is the role of Core
  v32.1's `cluster_linearize.h` and `TxGraph`, used for the RBF
  feerate-diagram check (`ImprovesFeerateDiagram`) and for eviction.

  Core uses an iterative algorithm that reaches an optimal linearization for
  realistic clusters (at most 64 txs). exnode computes an optimal one
  directly: it repeatedly takes the highest-feerate topologically closed
  subset of what remains. Each such subset comes from Dinkelbach iteration
  over a max-weight-closure min-cut. The chunk feerate diagram of an optimal
  linearization is unique, so diagram comparisons match Core's whenever
  Core's linearization is optimal.

  Fee rates are `{fee, size}` pairs compared by cross-multiplication
  (`ByRatio`). In the mempool, `size` is the sigop-adjusted weight, as in
  Core's `FeePerWeight`.

  A cluster is given as `%{id => {fee, size, parent_ids}}`, where parent_ids
  are direct in-cluster parents.
  """

  @doc """
  Optimal linearization. Returns the chunks, highest feerate first:
  `[{fee, size, [ids in topological order]}]`. Equal-feerate neighbours are
  not merged, matching Core's `ChunkLinearization`, which merges only on a
  strictly higher feerate.
  """
  def chunks(cluster) when map_size(cluster) == 0, do: []

  def chunks(cluster) do
    {set, _} = best_closure(cluster, :infinity)
    {fee, size} = totals(cluster, set)
    rest = Map.drop(cluster, set)
    rest = Map.new(rest, fn {id, {f, s, ps}} -> {id, {f, s, Enum.reject(ps, &(&1 in set))}} end)
    [{fee, size, topo(cluster, set)} | chunks(rest)]
  end

  @doc """
  `chunks/1` with bounded work (Core's TxGraph bounds its linearization
  work the same way, so a linearization can be non-optimal). `budget` is
  in work units (residual-graph edges scanned by the min-cuts, some
  25-50 ns each). Optimal chunks are taken while the budget lasts; the
  rest is chunked in the order of `fallback`, a linearization (topological
  order) of the cluster's ids, restricted to what is left (nil: a plain
  topological order). Returns `{chunks, budget_left}`, `budget_left` 0
  once the budget ran out.

  The optimal prefix and the fallback remainder need no merging: each
  optimal chunk is the best closed subset of what followed it, so no later
  chunk has a higher feerate.
  """
  def chunks_bounded(cluster, budget, fallback \\ nil) do
    bounded(cluster, budget, fallback, [])
  end

  defp bounded(cluster, budget, _fallback, acc) when map_size(cluster) == 0,
    do: {Enum.reverse(acc), budget}

  defp bounded(cluster, budget, fallback, acc) do
    result =
      if budget > 0, do: catch_budget(fn -> best_closure(cluster, budget) end), else: :exhausted

    case result do
      {:ok, {set, budget}} ->
        {fee, size} = totals(cluster, set)
        rest = Map.drop(cluster, set)

        rest =
          Map.new(rest, fn {id, {f, s, ps}} -> {id, {f, s, Enum.reject(ps, &(&1 in set))}} end)

        bounded(rest, budget, fallback, [{fee, size, topo(cluster, set)} | acc])

      :exhausted ->
        order =
          case fallback do
            nil -> topo(cluster, Map.keys(cluster))
            order -> Enum.filter(order, &Map.has_key?(cluster, &1))
          end

        {Enum.reverse(acc, chunk_linearization(cluster, order)), 0}
    end
  end

  defp catch_budget(f) do
    {:ok, f.()}
  catch
    :throw, :linearize_budget -> :exhausted
  end

  @doc """
  Core `ChunkLinearization`: the chunks of the linearization `order` (a
  topological order of all of `cluster`'s ids), merging a tx group into the
  previous chunk while its feerate is strictly higher.
  `[{fee, size, [ids]}]`, highest feerate first.
  """
  def chunk_linearization(cluster, order) do
    order
    |> Enum.reduce([], fn id, chunks ->
      {f, s, _} = Map.fetch!(cluster, id)
      merge([{f, s, [id]} | chunks])
    end)
    |> Enum.reverse()
    |> Enum.map(fn {f, s, ids} -> {f, s, Enum.reverse(ids)} end)
  end

  # Chunks are kept newest first, each chunk's ids reversed.
  defp merge([{f1, s1, ids1}, {f0, s0, ids0} | rest] = chunks) do
    if ratio_cmp({f1, s1}, {f0, s0}) == :gt,
      do: merge([{f0 + f1, s0 + s1, ids1 ++ ids0} | rest]),
      else: chunks
  end

  defp merge(chunks), do: chunks

  @doc "Chunk feerates only: `[{fee, size}]`, highest first."
  def chunk_feerates(cluster), do: for({f, s, _} <- chunks(cluster), do: {f, s})

  @doc """
  Core `CompareChunks`: compares two feerate diagrams, each given as chunk
  feerates sorted by decreasing feerate. Returns `:gt`, `:lt`, `:eq` or
  `:unordered`.
  """
  # Core: CompareChunks (util/feefrac.cpp)
  def compare_chunks(c0, c1), do: cmp_loop({c0, c1}, {{0, 0}, {0, 0}}, {false, false})

  defp cmp_loop({c0, c1} = c, {a0, a1} = acc, {b0, b1} = better) do
    done0 = c0 == []
    done1 = c1 == []

    cond do
      done0 and done1 ->
        cond do
          b0 and not b1 -> :gt
          b1 and not b0 -> :lt
          true -> :eq
        end

      true ->
        next = fn
          0 -> add(hd(c0), a0)
          1 -> add(hd(c1), a1)
        end

        side =
          cond do
            done0 -> 1
            done1 -> 0
            true -> if elem(next.(0), 1) > elem(next.(1), 1), do: 1, else: 0
          end

        other = 1 - side
        p = next.(side)
        a = if other == 0, do: a0, else: a1
        slope_ap = sub(p, a)

        {cmp, c, acc} =
          if done0 or done1 do
            {ratio_cmp(slope_ap, {0, 1}), c, acc}
          else
            b = next.(other)
            r = ratio_cmp(slope_ap, sub(b, a))
            # Same size: B is processed too.
            if elem(b, 1) == elem(p, 1), do: advance(r, c, acc, other), else: {r, c, acc}
          end

        better =
          case cmp do
            :gt -> put_elem(better, side, true)
            :lt -> put_elem(better, other, true)
            :eq -> better
          end

        {_, c, acc} = advance(cmp, c, acc, side)

        if elem(better, 0) and elem(better, 1),
          do: :unordered,
          else: cmp_loop(c, acc, better)
    end
  end

  defp advance(r, {c0, c1}, {a0, a1}, 0), do: {r, {tl(c0), c1}, {add(hd(c0), a0), a1}}
  defp advance(r, {c0, c1}, {a0, a1}, 1), do: {r, {c0, tl(c1)}, {a0, add(hd(c1), a1)}}

  defp add({f1, s1}, {f2, s2}), do: {f1 + f2, s1 + s2}
  defp sub({f1, s1}, {f2, s2}), do: {f1 - f2, s1 - s2}

  @doc "ByRatio comparison of `{fee, size}` feerates: `:gt | :eq | :lt`."
  def ratio_cmp({f1, s1}, {f2, s2}) do
    a = f1 * s2
    b = f2 * s1

    cond do
      a > b -> :gt
      a < b -> :lt
      true -> :eq
    end
  end

  @doc "Sort chunk feerates by decreasing feerate, ties by increasing size (Core `ByRatioNegSize`, descending)."
  def sort_desc(feerates) do
    Enum.sort(feerates, fn {_, s1} = x, {_, s2} = y ->
      case ratio_cmp(x, y) do
        :gt -> true
        :lt -> false
        :eq -> s1 <= s2
      end
    end)
  end

  # --- best closure (Dinkelbach + max-weight closure) --------------------------

  # The highest-feerate non-empty closed subset (closed under in-cluster
  # parents). Starts from the whole set (closed) and improves.
  # `budget`: work units left, or :infinity; throws :linearize_budget when
  # it runs out. Returns {set, budget left}.
  defp best_closure(cluster, budget) do
    all = Map.keys(cluster)
    improve(cluster, all, totals(cluster, all), budget)
  end

  defp improve(cluster, set, {n, d}, budget) do
    # Maximize sum(fee_i * d - n * size_i) over closed sets.
    weights = Map.new(cluster, fn {id, {f, s, _}} -> {id, f * d - n * s} end)
    {value, closure, budget} = max_weight_closure(cluster, weights, budget)

    if value > 0 and closure != [] do
      improve(cluster, closure, totals(cluster, closure), budget)
    else
      # Prefer the smallest optimal set: the minimal closure at this ratio,
      # if non-empty and equally good; otherwise keep the current set.
      {set, budget}
    end
  end

  defp spend(:infinity, _n), do: :infinity
  defp spend(budget, n) when budget >= n, do: budget - n
  defp spend(_budget, _n), do: throw(:linearize_budget)

  defp totals(cluster, ids) do
    Enum.reduce(ids, {0, 0}, fn id, {f, s} ->
      {fi, si, _} = Map.fetch!(cluster, id)
      {f + fi, s + si}
    end)
  end

  # Max-weight closure by min-cut (project selection). Returns
  # {max_value, minimal optimal closure, budget left}.
  defp max_weight_closure(cluster, weights, budget) do
    ids = Map.keys(cluster)
    inf = Enum.reduce(weights, 1, fn {_, w}, acc -> acc + abs(w) end)

    cap0 =
      Enum.reduce(ids, %{}, fn id, cap ->
        w = weights[id]
        cap = if w > 0, do: put_cap(cap, :s, id, w), else: cap
        cap = if w < 0, do: put_cap(cap, id, :t, -w), else: cap
        {_, _, parents} = cluster[id]
        # Taking a child requires taking its parents.
        Enum.reduce(parents, cap, fn p, cap -> put_cap(cap, id, p, inf) end)
      end)

    adj =
      Enum.reduce(Map.keys(cap0), %{}, fn {u, v}, adj ->
        adj |> Map.update(u, [v], &[v | &1]) |> Map.update(v, [u], &[u | &1])
      end)

    positive = Enum.reduce(weights, 0, fn {_, w}, acc -> if w > 0, do: acc + w, else: acc end)
    # Building the graph and the final reachability scan: two passes over it.
    edges = map_size(cap0)
    budget = spend(budget, 2 * edges)
    {flow, residual, budget} = max_flow(cap0, adj, 0, edges, budget)
    reach = reachable(residual, adj, :s)
    closure = for id <- ids, MapSet.member?(reach, id), do: id
    {positive - flow, closure, budget}
  end

  defp put_cap(cap, u, v, c), do: Map.update(cap, {u, v}, c, &(&1 + c))

  # Edmonds-Karp. `cap` holds residual capacities. Each BFS is charged as a
  # scan of the graph's `edges` (residual reverse edges at most double it).
  defp max_flow(cap, adj, flow, edges, budget) do
    budget = spend(budget, 2 * edges)

    case bfs_path(cap, adj) do
      nil ->
        {flow, cap, budget}

      path ->
        bottleneck = path |> Enum.map(&Map.get(cap, &1, 0)) |> Enum.min()

        cap =
          Enum.reduce(path, cap, fn {u, v}, cap ->
            cap
            |> Map.update!({u, v}, &(&1 - bottleneck))
            |> Map.update({v, u}, bottleneck, &(&1 + bottleneck))
          end)

        max_flow(cap, adj, flow + bottleneck, edges, budget)
    end
  end

  defp bfs_path(cap, adj) do
    bfs(:queue.from_list([:s]), %{s: nil}, cap, adj)
  end

  defp bfs(q, prev, cap, adj) do
    case :queue.out(q) do
      {:empty, _} ->
        nil

      {{:value, :t}, _} ->
        build_path(prev, :t, [])

      {{:value, u}, q} ->
        {q, prev} =
          Enum.reduce(Map.get(adj, u, []), {q, prev}, fn v, {q, prev} ->
            if not Map.has_key?(prev, v) and Map.get(cap, {u, v}, 0) > 0,
              do: {:queue.in(v, q), Map.put(prev, v, u)},
              else: {q, prev}
          end)

        bfs(q, prev, cap, adj)
    end
  end

  defp build_path(_prev, :s, acc), do: acc
  defp build_path(prev, v, acc), do: build_path(prev, prev[v], [{prev[v], v} | acc])

  defp reachable(cap, adj, from) do
    walk([from], MapSet.new([from]), cap, adj)
  end

  defp walk([], seen, _cap, _adj), do: seen

  defp walk([u | rest], seen, cap, adj) do
    next =
      for v <- Map.get(adj, u, []),
          not MapSet.member?(seen, v),
          Map.get(cap, {u, v}, 0) > 0,
          uniq: true,
          do: v

    walk(next ++ rest, Enum.reduce(next, seen, &MapSet.put(&2, &1)), cap, adj)
  end

  @doc "A topological order (parents first) of `ids`, a subset of `cluster`; ties by id."
  def topological_order(cluster, ids), do: topo(cluster, ids)

  # Topological order of `set` (parents first); ties by id order for determinism.
  defp topo(cluster, set) do
    members = MapSet.new(set)

    deps =
      Map.new(set, fn id ->
        {id, Enum.filter(elem(cluster[id], 2), &MapSet.member?(members, &1))}
      end)

    topo_loop(deps, [])
  end

  defp topo_loop(deps, acc) when map_size(deps) == 0, do: Enum.reverse(acc)

  defp topo_loop(deps, acc) do
    ready =
      deps |> Enum.filter(fn {_, ps} -> ps == [] end) |> Enum.map(&elem(&1, 0)) |> Enum.sort()

    deps = Map.drop(deps, ready)
    deps = Map.new(deps, fn {id, ps} -> {id, Enum.reject(ps, &(&1 in ready))} end)
    topo_loop(deps, Enum.reverse(ready) ++ acc)
  end
end
