defmodule Exnode.Mempool.LinearizeTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Mempool.Linearize, as: L

  # Core ChunkLinearization: append each tx as a chunk, merging with the
  # previous chunk while the new one has a strictly higher feerate.
  defp chunk_order(cluster, order) do
    Enum.reduce(order, [], fn id, acc ->
      {f, s, _} = cluster[id]
      merge([{f, s} | acc])
    end)
    |> Enum.reverse()
  end

  defp merge([new, prev | rest]) do
    if L.ratio_cmp(new, prev) == :gt,
      do: merge([{elem(new, 0) + elem(prev, 0), elem(new, 1) + elem(prev, 1)} | rest]),
      else: [new, prev | rest]
  end

  defp merge(l), do: l

  defp topo_orders(cluster) do
    topo_orders(cluster, MapSet.new(), [])
  end

  defp topo_orders(cluster, done, acc) do
    if MapSet.size(done) == map_size(cluster) do
      [Enum.reverse(acc)]
    else
      for {id, {_, _, ps}} <- cluster,
          not MapSet.member?(done, id),
          Enum.all?(ps, &MapSet.member?(done, &1)),
          order <- topo_orders(cluster, MapSet.put(done, id), [id | acc]),
          do: order
    end
  end

  # A random DAG on 1..n: each node picks parents among lower ids.
  defp cluster_gen do
    gen all(
          n <- integer(1..7),
          fees <- list_of(integer(0..5000), length: n),
          sizes <- list_of(integer(1..400), length: n),
          edges <- list_of(list_of(boolean(), length: n), length: n)
        ) do
      for i <- 0..(n - 1), into: %{} do
        parents = for j <- 0..(n - 1), j < i, Enum.at(Enum.at(edges, i), j), do: j
        {i, {Enum.at(fees, i), Enum.at(sizes, i), parents}}
      end
    end
  end

  property "the diagram is optimal: at least as good as every topological order's, and equal to the best" do
    check all(cluster <- cluster_gen(), max_runs: 300) do
      ours = L.chunk_feerates(cluster)
      diagrams = for o <- topo_orders(cluster), do: chunk_order(cluster, o)

      for d <- diagrams,
          do: assert(L.compare_chunks(ours, d) in [:gt, :eq], "#{inspect(ours)} vs #{inspect(d)}")

      assert Enum.any?(diagrams, &(L.compare_chunks(ours, &1) == :eq))

      # Chunks partition the cluster, are topologically closed in order, and
      # have non-increasing feerates.
      ids = for {_, _, ids} <- L.chunks(cluster), id <- ids, do: id
      assert Enum.sort(ids) == Enum.sort(Map.keys(cluster))

      ids
      |> Enum.with_index()
      |> Enum.each(fn {id, i} ->
        for p <- elem(cluster[id], 2), do: assert(Enum.find_index(ids, &(&1 == p)) < i)
      end)

      ours
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.each(fn [a, b] -> assert L.ratio_cmp(a, b) != :lt end)
    end
  end

  # Chunks as {fee, size} pairs, checked to be a valid chunking: a partition
  # of the cluster, each prefix closed under parents, feerates non-increasing.
  defp valid_chunks!(cluster, chunks) do
    ids = Enum.flat_map(chunks, fn {_, _, ids} -> ids end)
    assert Enum.sort(ids) == Enum.sort(Map.keys(cluster))

    Enum.reduce(ids, MapSet.new(), fn id, seen ->
      {_, _, ps} = cluster[id]
      assert Enum.all?(ps, &MapSet.member?(seen, &1)), "not topological: #{inspect(ids)}"
      MapSet.put(seen, id)
    end)

    frs = for {f, s, _} <- chunks, do: {f, s}

    for [a, b] <- Enum.chunk_every(frs, 2, 1, :discard),
        do: assert(L.ratio_cmp(a, b) != :lt, "increasing feerates: #{inspect(frs)}")

    frs
  end

  property "bounded chunks: optimal with enough budget; any budget gives a valid, never better, diagram" do
    check all(
            cluster <- cluster_gen(),
            budget <- integer(0..3_000),
            fallback_seed <- integer(),
            max_runs: 300
          ) do
      assert {chunks, left} = L.chunks_bounded(cluster, 1_000_000_000)
      assert chunks == L.chunks(cluster) and left > 0

      orders = topo_orders(cluster)
      fallback = Enum.at(orders, rem(abs(fallback_seed), length(orders)))
      {chunks, _} = L.chunks_bounded(cluster, budget, fallback)
      frs = valid_chunks!(cluster, chunks)
      assert L.compare_chunks(L.chunk_feerates(cluster), frs) in [:gt, :eq]

      # No budget at all: exactly the fallback order's chunking.
      {chunks, 0} = L.chunks_bounded(cluster, 0, fallback)
      assert valid_chunks!(cluster, chunks) == chunk_order(cluster, fallback)
      assert L.chunk_linearization(cluster, fallback) == chunks
    end
  end

  test "bounded chunks stop at the budget on a large dense cluster" do
    :rand.seed(:exsss, {7, 7, 7})

    cluster =
      Map.new(0..63, fn i ->
        {i,
         {:rand.uniform(100_000), 400 + :rand.uniform(2_000),
          for(j <- 0..(i - 1)//1, :rand.uniform() < 0.3, do: j)}}
      end)

    {us_full, _} = :timer.tc(fn -> L.chunks(cluster) end)
    {us, {chunks, 0}} = :timer.tc(fn -> L.chunks_bounded(cluster, 50_000) end)
    valid_chunks!(cluster, chunks)

    IO.puts(
      "dense 64-tx cluster: optimal #{div(us_full, 1000)} ms, bounded (50k units) #{div(us, 1000)} ms"
    )

    assert us * 4 < us_full
  end

  test "child pays for parent: one chunk" do
    c = %{a: {100, 100, []}, b: {1000, 100, [:a]}}
    assert L.chunks(c) == [{1100, 200, [:a, :b]}]
  end

  test "independent txs: separate chunks by feerate" do
    c = %{a: {100, 100, []}, b: {1000, 100, []}}
    assert L.chunk_feerates(c) == [{1000, 100}, {100, 100}]
  end

  test "CompareChunks cases" do
    assert L.compare_chunks([], []) == :eq
    assert L.compare_chunks([{10, 1}], []) == :gt
    assert L.compare_chunks([], [{10, 1}]) == :lt
    assert L.compare_chunks([{10, 2}], [{10, 2}]) == :eq
    # Higher everywhere.
    assert L.compare_chunks([{20, 2}], [{10, 2}]) == :gt
    # Crossing diagrams: unordered.
    assert L.compare_chunks([{10, 1}, {0, 10}], [{15, 5}]) == :unordered
  end
end
