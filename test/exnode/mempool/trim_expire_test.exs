defmodule Exnode.Mempool.TrimExpireTest do
  @moduledoc """
  `trim_to_size` no longer re-linearizes the whole pool per evicted
  chunk, and `expire` no longer scans the pool.
  * Differential: on random pools over the limit, the new `trim_to_size`
    evicts exactly the chunks, in the same order, and leaves the same
    `fees`, as the old loop (re-run `Pool.worst_chunk/1` after each
    eviction), kept here as the reference.
  * The case that rules out a purely precomputed order: equal-feerate
    parents sharing a chunk split once their child is evicted.
  * Expiry: `Pool.expired/2` equals a full scan; removal includes
    descendants.
  * Scale: 1,000 clusters of 64 txs trimmed far past the old cost.
  """
  # Not async: the tracing-based call counts would also count other modules running concurrently.
  use ExUnit.Case, async: false
  use ExUnitProperties
  import Bitwise

  # :tprof is in OTP's tools app, put on the code path at run time (linearizations/1).
  @compile {:no_warn_undefined, :tprof}

  alias Exnode.Codec.Tx
  alias Exnode.Mempool.{Accept, Linearize, Pool}

  # A pool entry at the Pool level: Pool reads inputs, outputs and the raw size.
  defp entry(id, parents, fee, weight, time, raw_size \\ 200) do
    txid = :crypto.hash(:sha256, <<id::32>>)

    tx = %Tx{
      version: 2,
      locktime: 0,
      raw: :binary.copy(<<0>>, raw_size),
      txid: txid,
      wtxid: txid,
      has_witness: false,
      inputs:
        for(
          {p, vout} <- parents,
          do: %Tx.In{prev_hash: p, prev_index: vout, script_sig: <<>>, sequence: 0}
        ),
      outputs: [%Tx.Out{value: 1, script_pubkey: <<0x51>>}]
    }

    %Pool.Entry{
      tx: tx,
      txid: txid,
      wtxid: txid,
      fee: fee,
      weight: weight,
      vsize: div(weight + 3, 4),
      sigops: 0,
      time: time,
      height: 0,
      spends_coinbase: false
    }
  end

  # Builds a pool from specs `{parent_indexes, fee, weight, time}`; tx i
  # spends output i of each parent, so outpoints never collide.
  defp build(specs) do
    {pool, _} =
      Enum.reduce(Enum.with_index(specs), {Pool.new(), %{}}, fn {{ps, fee, w, time}, i},
                                                                {pool, ids} ->
        e = entry(i, for(p <- ps, do: {ids[p], i}), fee, w, time)
        {Pool.add(pool, e), Map.put(ids, i, e.txid)}
      end)

    pool
  end

  defp state(pool, rolling \\ 0.0),
    do: %{
      pool: pool,
      fees: %{rolling: rolling, block_since_bump: true, last_update: 0},
      opts: %{incremental: 100}
    }

  # The worst chunk computed independently of Pool's ordering key: every
  # cluster's chunks, compared with Linearize.ratio_cmp; ties to the larger
  # chunk (Core ByRatioNegSize), then to the smallest txid.
  defp reference_worst(pool) do
    clusters = pool.entries |> Map.keys() |> Enum.map(&Pool.cluster(pool, &1)) |> Enum.uniq()

    clusters
    |> Enum.flat_map(fn c ->
      for {f, w, ids} <- Linearize.chunks(Pool.cluster_input(pool, c)), do: {{f, w}, ids}
    end)
    |> Enum.reduce(fn {fr, ids} = x, {bfr, bids} = best ->
      case Linearize.ratio_cmp(fr, bfr) do
        :lt ->
          x

        :gt ->
          best

        :eq ->
          cond do
            elem(fr, 1) > elem(bfr, 1) -> x
            elem(fr, 1) < elem(bfr, 1) -> best
            Enum.min(ids) < Enum.min(bids) -> x
            true -> best
          end
      end
    end)
  end

  # The pre-fix algorithm: recompute the worst chunk of the whole pool after every eviction.
  defp reference_trim(state, limit, evicted \\ []) do
    if Pool.size(state.pool) > 0 and state.pool.total_usage > limit do
      {{fee, weight}, ids} = chunk = reference_worst(state.pool)
      removed_rate = div(fee * 1000, div(weight + 3, 4)) + state.opts.incremental

      fees =
        if removed_rate > state.fees.rolling,
          do: %{state.fees | rolling: removed_rate * 1.0, block_since_bump: false},
          else: state.fees

      reference_trim(%{state | pool: Pool.remove(state.pool, ids), fees: fees}, limit, [
        chunk | evicted
      ])
    else
      {state, Enum.reverse(evicted)}
    end
  end

  # Random pools: up to 60 txs, each spending up to 2 earlier txs; fees and
  # weights from small sets so equal feerates (and merged chunks) are common.
  defp pool_spec do
    gen all(
          n <- integer(2..60),
          specs <-
            fixed_list(
              for i <- 0..(n - 1) do
                gen all(
                      parents <- list_of(integer(0..max(i - 1, 0)), max_length: 2),
                      fee <- member_of([0, 100, 200, 400, 1000, 5000]),
                      w <- member_of([400, 800, 1200]),
                      time <- integer(0..100)
                    ) do
                  {if(i == 0, do: [], else: Enum.uniq(parents)), fee, w, time}
                end
              end
            )
        ) do
      specs
    end
  end

  property "trim_to_size evicts the same chunks in the same order, with the same fees, as the reference" do
    check all(
            specs <- pool_spec(),
            frac <- integer(0..100),
            rolling <- member_of([0.0, 500.0, 5_000_000.0]),
            # 2000 runs took ~37-39 s alone on a fast machine (the reference
            # linearizes every cluster) and passed the 60 s ExUnit timeout on
            # CI runners alongside the rest of the suite.
            max_runs: 500
          ) do
      pool = build(specs)
      limit = div(pool.total_usage * frac, 100)
      {ref_state, ref_evicted} = reference_trim(state(pool, rolling), limit)
      {new_pool, new_evicted} = Pool.trim(pool, limit)
      new_state = Accept.trim_to_size(state(pool, rolling), limit)

      assert new_evicted == ref_evicted
      if Pool.size(pool) > 0, do: assert(Pool.worst_chunk(pool) == reference_worst(pool))
      assert new_state.fees == ref_state.fees

      assert Map.keys(new_pool.entries) |> Enum.sort() ==
               Map.keys(ref_state.pool.entries) |> Enum.sort()

      assert new_state.pool.entries == new_pool.entries
      assert new_pool.total_usage <= limit or Pool.size(new_pool) == 0
    end
  end

  # Fresh chunks of every cluster, as a comparable set.
  defp fresh_chunks(pool) do
    pool.entries
    |> Map.keys()
    |> Enum.map(&Pool.cluster(pool, &1))
    |> Enum.uniq()
    |> Enum.map(fn c ->
      for {f, w, ids} <- Linearize.chunks(Pool.cluster_input(pool, c)), do: {{f, w}, ids}
    end)
    |> MapSet.new()
  end

  defp add_specs(pool, specs, offset) do
    Enum.reduce(Enum.with_index(specs, offset), pool, fn {{ps, fee, w, time}, i}, pool ->
      parents =
        for p <- ps,
            txid = :crypto.hash(:sha256, <<p::32>>),
            Pool.exists?(pool, txid),
            do: {txid, i}

      Pool.add(pool, entry(i, parents, fee, w, time))
    end)
  end

  property "the linearization cache equals a fresh linearization after adds, removes and trims" do
    check all(
            a <- pool_spec(),
            b <- pool_spec(),
            drop <- list_of(integer(0..200), max_length: 10),
            f1 <- integer(0..100),
            f2 <- integer(0..100),
            max_runs: 500
          ) do
      # Step 1: a pool, trimmed (the cache is filled and kept by trim).
      pool = build(a)
      l1 = div(pool.total_usage * f1, 100)
      {p1, e1} = Pool.trim(pool, l1)
      {r1, re1} = reference_trim(state(pool), l1)
      assert e1 == re1
      assert p1.entries == r1.pool.entries

      # Step 2: more txs (some spending survivors), some removed with descendants; trim again.
      # New txs spend each other and, through low indexes, step-1 survivors.
      p2 =
        add_specs(
          p1,
          Enum.map(b, fn {ps, f, w, t} ->
            {Enum.map(ps, &if(rem(&1, 3) == 0, do: &1, else: &1 + 1000)), f, w, t}
          end),
          1000
        )

      gone =
        for i <- drop,
            txid = :crypto.hash(:sha256, <<i + 1000::32>>),
            Pool.exists?(p2, txid),
            do: txid

      p2 = Pool.remove(p2, Pool.with_descendants(p2, gone))
      # Also from clusters cached since step 1: some with descendants (eviction,
      # replacement), some alone so children stay (removeForBlock).
      old =
        for i <- drop,
            txid = :crypto.hash(:sha256, <<rem(i, 60)::32>>),
            Pool.exists?(p2, txid),
            do: txid

      {with_desc, alone} = Enum.split(old, div(length(old), 2))
      p2 = p2 |> Pool.remove(Pool.with_descendants(p2, with_desc)) |> Pool.remove(alone)
      {_, cached} = Pool.cluster_chunks(p2)
      assert MapSet.new(cached) == fresh_chunks(p2)

      l2 = div(p2.total_usage * f2, 100)
      {p3, e2} = Pool.trim(p2, l2)
      {r2, re2} = reference_trim(state(p2), l2)
      assert e2 == re2
      assert p3.entries == r2.pool.entries
      {_, cached3} = Pool.cluster_chunks(p3)
      assert MapSet.new(cached3) == fresh_chunks(p3)
    end
  end

  test "equal-feerate parents share a chunk until their child is evicted, then split (why order is not precomputed)" do
    # A and B: same feerate, independent; T spends both with a low fee.
    pool = build([{[], 1000, 400, 0}, {[], 1000, 400, 0}, {[0, 1], 10, 400, 0}])
    [a, b, t] = for i <- 0..2, do: :crypto.hash(:sha256, <<i::32>>)
    # Room for exactly one of A and B after T goes: usage of a single entry.
    single = div(pool.total_usage, 3)
    {_p, evicted} = Pool.trim(pool, single)
    {_s, ref} = reference_trim(state(pool), single)
    assert evicted == ref
    # T first, then A or B alone (smallest txid), not {A, B} together.
    [{{10, 400}, [^t]}, {{1000, 400}, [first]}] = evicted
    assert first == Enum.min([a, b])
  end

  describe "expiry" do
    property "Pool.expired equals a full scan of entry times" do
      check all(specs <- pool_spec(), cutoff <- integer(0..101), max_runs: 200) do
        pool = build(specs)
        scan = for({t, e} <- pool.entries, e.time < cutoff, do: t) |> Enum.sort()
        assert Enum.sort(Pool.expired(pool, cutoff)) == scan
        # The index follows removals.
        gone = scan |> Enum.take(3)
        pool2 = Pool.remove(pool, Pool.with_descendants(pool, gone))

        assert Enum.sort(Pool.expired(pool2, cutoff)) ==
                 for({t, e} <- pool2.entries, e.time < cutoff, do: t) |> Enum.sort()
      end
    end

    test "limit_size expires old txs with their descendants" do
      # 0 (old) <- 1 (new) <- 2 (new); 3 (new) independent.
      pool =
        build([
          {[], 100, 400, 10},
          {[0], 100, 400, 1_000},
          {[1], 100, 400, 1_000},
          {[], 100, 400, 1_000}
        ])

      s = state(pool) |> put_in([:opts, :expiry], 500) |> put_in([:opts, :max_size], 1 <<< 40)
      out = Accept.limit_size(s, 600)
      assert Map.keys(out.pool.entries) == [:crypto.hash(:sha256, <<3::32>>)]
      assert Pool.expired(out.pool, 1 <<< 40) == [:crypto.hash(:sha256, <<3::32>>)]
    end
  end

  # c clusters of 64 txs: a binary tree of parents each, varied fees and weights.
  defp tree_pool(clusters) do
    specs =
      for c <- 0..(clusters - 1), i <- 0..63 do
        parents = if i == 0, do: [], else: [c * 64 + div(i - 1, 2)]
        {parents, rem(c * 7 + i * 13, 997) * 10, 400 + rem(i, 3) * 400, 0}
      end

    build(specs)
  end

  # Cluster linearizations done by `fun` (each goes through Pool.cluster_input/2).
  defp linearizations(fun) do
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

  test "linearization cache: each cluster once per trim; later trims redo only changed clusters" do
    pool = tree_pool(100)
    limit = div(pool.total_usage, 10)
    {{p1, evicted}, n} = linearizations(fn -> Pool.trim(pool, limit) end)
    assert length(evicted) > 1_000
    # The old loop linearized all 100 clusters again for every evicted chunk.
    assert n == 100

    # One new tx in one surviving cluster, then over the limit again: only that cluster.
    survivor = p1.entries |> Map.keys() |> hd()
    p2 = Pool.add(p1, entry(900_000, [{survivor, 99}], 0, 400, 0))
    {{_, ev2}, n2} = linearizations(fn -> Pool.trim(p2, p2.total_usage - 1) end)
    assert ev2 != []
    assert n2 == 1
  end

  @tag timeout: 600_000
  test "scale: 1,000 clusters of 64 txs trimmed to 90%" do
    pool = tree_pool(1_000)
    assert Pool.size(pool) == 64_000
    limit = div(pool.total_usage * 9, 10)
    {us, s} = :timer.tc(fn -> Accept.trim_to_size(state(pool), limit) end)
    assert s.pool.total_usage <= limit
    # About one full-pool linearization. Generous for a shared machine; the old
    # loop did one full-pool linearization per evicted chunk (hours here).
    assert us < 300_000_000, "trim took #{div(us, 1000)} ms"
  end
end
