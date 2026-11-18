defmodule Exnode.DoS.RbfLinearizeTest do
  @moduledoc """
  Regression (Pool level): an RBF attempt
  that conflicts with a low-fee leaf in each of 100 dense 64-tx clusters
  (and then fails its scripts, so it can be repeated for free) used to make
  the mempool process linearize all 100 main and 100 staging clusters from
  scratch, seconds per attempt. Now:

  * main clusters come from the linearization cache (none linearized);
  * staging linearization is bounded, then falls back to the main order:
    a valid diagram, never better than the optimal one, at a fraction of
    the old cost;
  * a small replacement still gets exact (optimal) diagrams;
  * cached cluster lookups agree with a graph walk, and idle refresh
    leaves nothing stale.

  End to end (real sockets, K=100) the repro went from ~2-3 s to ~45 ms of
  mempool time per attempt.
  """
  # Not async: call counting and timing.
  use ExUnit.Case, async: false
  use ExUnitProperties
  @moduletag :dos

  # :tprof is in OTP's tools app, put on the code path at run time (main_linearizations/1).
  @compile {:no_warn_undefined, :tprof}

  alias Exnode.Codec.Tx
  alias Exnode.Mempool.{Linearize, Pool}

  defp hash(tag, i), do: :crypto.hash(:sha256, <<tag::binary, i::64>>)

  # A Pool-level entry: `inputs` are outpoints, `nout` outputs.
  defp entry(txid, inputs, nout, fee, weight) do
    tx = %Tx{
      version: 2,
      locktime: 0,
      raw: :binary.copy(<<0>>, 200),
      txid: txid,
      wtxid: txid,
      has_witness: false,
      inputs:
        for(
          {h, v} <- inputs,
          do: %Tx.In{prev_hash: h, prev_index: v, script_sig: <<>>, sequence: 0}
        ),
      outputs: for(_ <- 1..nout, do: %Tx.Out{value: 1, script_pubkey: <<0x51>>})
    }

    %Pool.Entry{
      tx: tx,
      txid: txid,
      wtxid: txid,
      fee: fee,
      weight: weight,
      vsize: div(weight + 3, 4),
      sigops: 0,
      time: 0,
      height: 0,
      spends_coinbase: false
    }
  end

  # Cluster k: 63 txs, each spending outputs of up to 8 earlier ones (a
  # root first), then a low-fee leaf that also spends confirmed coin u_k.
  defp cluster(pool, k) do
    root = entry(hash("root", k), [{hash("coin", k), 0}], 64, 5_000, 800)

    {pool, txs} =
      Enum.reduce(1..62, {Pool.add(pool, root), [root]}, fn j, {pool, txs} ->
        parents = Enum.take_random(txs, 1 + :rand.uniform(7))

        e =
          entry(
            hash("tx#{k}", j),
            for(p <- parents, do: {p.txid, j}),
            64,
            :rand.uniform(200) * 500,
            400 + :rand.uniform(1_600)
          )

        {Pool.add(pool, e), [e | txs]}
      end)

    leaf = entry(hash("leaf", k), [{hd(txs).txid, 63}, {hash("u", k), 0}], 1, 400, 800)
    Pool.add(pool, leaf)
  end

  defp attack_pool(k) do
    :rand.seed(:exsss, {1, 2, 3})
    pool = Enum.reduce(1..k, Pool.new(), &cluster(&2, &1))
    {pool, _} = Pool.cluster_chunks(pool)
    refute Pool.stale?(pool)
    pool
  end

  # The pre-fix diagrams: every main and staging cluster linearized optimally.
  defp optimal_diagrams(pool, staged) do
    main =
      for c <- staged.main_clusters,
          fr <- Linearize.chunk_feerates(Pool.cluster_input(pool, c)),
          do: fr

    staging = for c <- staged.staging_clusters, fr <- Linearize.chunk_feerates(c), do: fr
    {Linearize.sort_desc(main), Linearize.sort_desc(staging)}
  end

  defp main_linearizations(fun) do
    :code.add_paths(
      Path.wildcard(Path.join(:code.root_dir(), "lib/tools-*/ebin"))
      |> Enum.map(&to_charlist/1)
    )

    {result, {:call_count, rows}} = :tprof.profile(fun, %{type: :call_count, report: :return})

    n =
      Enum.find_value(rows, 0, fn
        {Pool, :cluster_input, 2, [{_, n, _} | _]} -> n
        _ -> nil
      end)

    {result, n}
  end

  @tag timeout: 300_000
  test "100 conflicting dense clusters: no main linearization, bounded staging work, a never-better diagram" do
    k = 100
    pool = attack_pool(k)
    leaves = for i <- 1..k, do: hash("leaf", i)
    repl = entry(hash("repl", 0), for(i <- 1..k, do: {hash("u", i), 0}), 1, 10_000_000, 4 * 4_555)
    staged = Pool.stage(pool, [repl], leaves)
    assert length(staged.main_clusters) == k

    {{main, staging}, n} = main_linearizations(fn -> Pool.diagrams(pool, staged) end)
    # Timed without the tracer.
    {us_ours, _} = :timer.tc(fn -> Pool.diagrams(pool, staged) end)
    {us_old, {opt_main, opt_staging}} = :timer.tc(fn -> optimal_diagrams(pool, staged) end)

    IO.puts(
      "RBF diagrams over #{k} x 64-tx clusters: #{div(us_ours, 1000)} ms bounded vs #{div(us_old, 1000)} ms optimal (pre-fix)"
    )

    assert n == 0, "main clusters were linearized #{n} times"
    assert main == opt_main
    assert Linearize.compare_chunks(opt_staging, staging) in [:gt, :eq]
    assert us_ours * 10 < us_old
  end

  test "a small replacement gets the exact diagrams" do
    # P -> C (low fee); a replacement of C pays more.
    p = entry(hash("p", 0), [{hash("coin", 0), 0}], 2, 1_000, 800)
    c = entry(hash("c", 0), [{p.txid, 0}], 1, 500, 800)
    pool = Pool.new() |> Pool.add(p) |> Pool.add(c)
    r = entry(hash("r", 0), [{p.txid, 0}], 1, 5_000, 800)

    # Stale cache (linearized on the spot) and fresh cache: same, optimal.
    staged = Pool.stage(pool, [r], [c.txid])
    assert Pool.diagrams(pool, staged) == optimal_diagrams(pool, staged)
    {fresh, _} = Pool.cluster_chunks(pool)
    assert Pool.diagrams(fresh, staged) == optimal_diagrams(pool, staged)
  end

  property "cached cluster lookups equal a graph walk; refresh_stale leaves nothing stale" do
    check all(
            specs <-
              list_of({list_of(integer(0..40), max_length: 3), integer(1..1_000)},
                min_length: 1,
                max_length: 40
              ),
            removes <- list_of(integer(0..40), max_length: 5),
            slice <- integer(1..80),
            max_runs: 100
          ) do
      {pool, ids} =
        specs
        |> Enum.with_index()
        |> Enum.reduce({Pool.new(), []}, fn {{ps, fee}, i}, {pool, ids} ->
          parents = for p <- Enum.uniq(ps), p < i, do: {Enum.at(ids, p), i}
          e = entry(hash("g", i), [{hash("coin", i), 0} | parents], 64, fee, 400)
          {Pool.add(pool, e), ids ++ [e.txid]}
        end)

      # Partly refreshed, then changed again.
      {pool, _} = Pool.refresh_stale(pool, slice)
      gone = for r <- removes, r < length(ids), do: Enum.at(ids, r)
      pool = Pool.remove(pool, Pool.with_descendants(pool, gone))
      {pool, _} = Pool.refresh_stale(pool, slice)

      walk = %{pool | lin: %{cluster_of: %{}, clusters: %{}, stale: MapSet.new(), next: 0}}
      for t <- Map.keys(pool.entries), do: assert(Pool.cluster(pool, t) == Pool.cluster(walk, t))

      pool =
        Stream.iterate({pool, true}, fn {p, _} -> Pool.refresh_stale(p, slice) end)
        |> Enum.find(&(not elem(&1, 1)))
        |> elem(0)

      refute Pool.stale?(pool)

      for t <- Map.keys(pool.entries),
          do: assert(Pool.cluster(pool, t) == Pool.cluster(walk, t))
    end
  end
end
