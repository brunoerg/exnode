defmodule Exnode.Mempool.Package do
  @moduledoc """
  Package acceptance. Ports of Core v32.1 `MemPoolAccept::AcceptPackage`,
  `AcceptMultipleTransactionsInternal`, `PackageRBFChecks`, `SubmitPackage`,
  `ProcessNewPackage` (validation.cpp), `PackageTRUCChecks`
  (policy/truc_policy.cpp), and `IsWellFormedPackage` / `IsChildWithParents`
  (policy/packages.cpp).

  Results are `%{state: :ok | {result, reason, detail}, txs: %{wtxid => tx_result}}`,
  with `tx_result` one of:
  * `{:valid, res}` (accepted here)
  * `{:mempool, res}` (already in the mempool)
  * `{:different_witness, other_wtxid}`
  * `{:invalid, error}`
  """
  alias Exnode.Codec.Tx
  alias Exnode.Mempool.{Accept, Linearize, Policy, Pool}

  @max_package_count 25
  @max_package_weight 404_000
  @truc_version 3
  @mempool_height 0x7FFFFFFF

  # --- context-free checks ---------------------------------------------------

  @doc "Core `IsWellFormedPackage`."
  # Core: IsWellFormedPackage (policy/packages.cpp)
  def well_formed(txs) do
    txids = Enum.map(txs, & &1.txid)

    cond do
      length(txs) > @max_package_count ->
        {:error, "package-too-many-transactions"}

      length(txs) > 1 and Enum.reduce(txs, 0, &(&2 + Tx.weight(&1))) > @max_package_weight ->
        {:error, "package-too-large"}

      length(Enum.uniq(txids)) != length(txids) ->
        {:error, "package-contains-duplicates"}

      not topo_sorted?(txs) ->
        {:error, "package-not-sorted"}

      not consistent?(txs) ->
        {:error, "conflict-in-package"}

      true ->
        :ok
    end
  end

  # Core: IsTopoSortedPackage: no tx spends a later tx.
  defp topo_sorted?(txs) do
    {ok, _} =
      Enum.reduce(txs, {true, MapSet.new(Enum.map(txs, & &1.txid))}, fn tx, {ok, later} ->
        later = MapSet.delete(later, tx.txid)
        {ok and not Enum.any?(tx.inputs, &MapSet.member?(later, &1.prev_hash)), later}
      end)

    ok
  end

  # Core: IsConsistentPackage: no two txs spend the same outpoint; no tx without inputs.
  defp consistent?(txs) do
    Enum.reduce_while(txs, MapSet.new(), fn tx, seen ->
      ops = Enum.map(tx.inputs, &{&1.prev_hash, &1.prev_index})

      cond do
        tx.inputs == [] -> {:halt, false}
        Enum.any?(ops, &MapSet.member?(seen, &1)) -> {:halt, false}
        true -> {:cont, Enum.reduce(ops, seen, &MapSet.put(&2, &1))}
      end
    end) != false
  end

  @doc "Core `IsChildWithParents`: every tx but the last is a parent of the last."
  def child_with_parents?(txs) when length(txs) < 2, do: false

  def child_with_parents?(txs) do
    child = List.last(txs)
    inputs = MapSet.new(child.inputs, & &1.prev_hash)
    Enum.all?(Enum.drop(txs, -1), &MapSet.member?(inputs, &1.txid))
  end

  # --- testmempoolaccept / submitpackage ------------------------------------------

  @doc """
  Core `ProcessNewPackage(test_accept = true)`
  (`AcceptMultipleTransactionsAndCleanup` with `PackageTestAccept` args).
  Returns a package result.
  """
  def test_accept(state, txs, chain) do
    {res, _} =
      multi(
        state,
        txs,
        chain,
        Accept.normalize_args(
          test_accept: true,
          allow_replacement: false,
          allow_sibling_eviction: false
        )
      )

    res
  end

  @doc """
  Core `ProcessNewPackage(test_accept = false)` (`AcceptPackage` with
  `PackageChildWithParents` args). Returns `{package_result, state}`.
  """
  # Core: MemPoolAccept::AcceptPackage (validation.cpp)
  def accept(state, txs, chain) do
    args =
      Accept.normalize_args(
        package_submission: true,
        package_feerates: true,
        allow_sibling_eviction: false
      )

    cond do
      (r = well_formed(txs)) != :ok ->
        {%{state: {:policy, elem(r, 1), nil}, txs: %{}}, state}

      length(txs) > 1 and not child_with_parents?(txs) ->
        {%{state: {:policy, "package-not-child-with-parents", nil}, txs: %{}}, state}

      true ->
        {final, nonfinal, quit_early, to_eval, state} =
          Enum.reduce(txs, {%{}, %{}, false, [], state}, fn tx,
                                                            {final, nonfinal, quit, eval, state} ->
            cond do
              Pool.exists_wtxid?(state.pool, tx.wtxid) ->
                e = Pool.get(state.pool, tx.txid)

                {Map.put(final, tx.wtxid, {:mempool, %{vsize: e.vsize, fee: e.fee}}), nonfinal,
                 quit, eval, state}

              Pool.exists?(state.pool, tx.txid) ->
                e = Pool.get(state.pool, tx.txid)

                {Map.put(final, tx.wtxid, {:different_witness, e.wtxid}), nonfinal, quit, eval,
                 state}

              true ->
                # AcceptSubPackage({tx}) with SingleInPackageAccept args.
                single_args = [
                  test_accept: false,
                  package_submission: true,
                  allow_replacement: true,
                  allow_sibling_eviction: true
                ]

                case Accept.accept(state, tx, chain, single_args) do
                  {:ok, res, state} ->
                    {Map.put(final, tx.wtxid, {:valid, res}), nonfinal, quit, eval, state}

                  {:error, e, state} ->
                    retry = length(txs) > 1 and e.result in [:reconsiderable, :missing_inputs]
                    nonfinal = Map.put(nonfinal, tx.wtxid, {:invalid, e})

                    if retry,
                      do: {final, nonfinal, quit, eval ++ [tx], state},
                      else: {final, nonfinal, true, eval, state}
                end
            end
          end)

        {multi_res, state} =
          cond do
            quit_early -> {%{state: {:tx, "transaction failed", nil}, txs: %{}}, state}
            to_eval == [] -> {%{state: :ok, txs: %{}}, state}
            true -> multi(state, to_eval, chain, args)
          end

        state = Accept.limit_size(state, chain.now)

        {pkg_state, results} =
          Enum.reduce(txs, {multi_res.state, %{}}, fn tx, {ps, acc} ->
            full = Accept.err(:mempool_policy, "mempool full")

            cond do
              Map.has_key?(multi_res.txs, tx.wtxid) ->
                case multi_res.txs[tx.wtxid] do
                  {:valid, _} = r ->
                    if Pool.exists_wtxid?(state.pool, tx.wtxid),
                      do: {ps, Map.put(acc, tx.wtxid, r)},
                      else:
                        {{:tx, "transaction failed", nil},
                         Map.put(acc, tx.wtxid, {:invalid, full})}

                  r ->
                    {ps, Map.put(acc, tx.wtxid, r)}
                end

              Map.has_key?(final, tx.wtxid) ->
                if Pool.exists?(state.pool, tx.txid),
                  do: {ps, Map.put(acc, tx.wtxid, final[tx.wtxid])},
                  else:
                    {{:tx, "transaction failed", nil}, Map.put(acc, tx.wtxid, {:invalid, full})}

              Map.has_key?(nonfinal, tx.wtxid) ->
                {ps, Map.put(acc, tx.wtxid, nonfinal[tx.wtxid])}

              true ->
                {ps, acc}
            end
          end)

        # A tx that failed alone counts as a package failure only if package
        # evaluation did not rescue it: AcceptPackage's quit_early state.
        {%{state: pkg_state, txs: results}, state}
    end
  end

  @doc "`{:ok, tx, result}` for every tx of `txs` newly accepted in `package_result`."
  def accepted(%{txs: results}, txs) do
    for tx <- txs,
        match?({:valid, _}, results[tx.wtxid]),
        {:valid, res} = results[tx.wtxid],
        do: {:ok, tx, res}
  end

  # Core: MemPoolAccept::AcceptMultipleTransactionsInternal
  defp multi(state, txs, chain, args) do
    case well_formed(txs) do
      {:error, reason} ->
        {%{state: {:policy, reason, nil}, txs: %{}}, state}

      :ok ->
        multi_checked(state, txs, chain, args)
    end
  end

  defp multi_checked(state, txs, chain, args) do
    # PreChecks each tx; later txs see earlier package txs' outputs (PackageAddTransaction).
    pre =
      Enum.reduce_while(txs, {[], %{}}, fn tx, {wss, coins} ->
        case Accept.pre_checks(state, tx, chain, %{args | package_coins: coins}) do
          {:ok, ws} ->
            new =
              for {o, v} <- Enum.with_index(tx.outputs),
                  into: %{},
                  do:
                    {{tx.txid, v},
                     %{
                       value: o.value,
                       script_pubkey: o.script_pubkey,
                       height: @mempool_height,
                       coinbase: false
                     }}

            {:cont, {wss ++ [ws], Map.merge(coins, new)}}

          {:error, e} ->
            {:halt, {:failed, tx, e}}
        end
      end)

    case pre do
      {:failed, tx, e} ->
        {%{state: {:tx, "transaction failed", nil}, txs: %{tx.wtxid => {:invalid, e}}}, state}

      {wss, _} ->
        multi_after_prechecks(state, txs, wss, chain, args)
    end
  end

  defp multi_after_prechecks(state, txs, wss, chain, args) do
    total_vsize = Enum.reduce(wss, 0, &(&2 + &1.vsize))
    total_fee = Enum.reduce(wss, 0, &(&2 + &1.fee))
    conflicts = Enum.reduce(wss, MapSet.new(), &MapSet.union(&2, &1.conflicts))

    with :ok <- truc_checks(state.pool, txs, wss),
         :ok <- package_fee_rate(state, args, total_vsize, total_fee, chain, List.last(txs)),
         {:ok, all_conflicts} <-
           if(conflicts != MapSet.new(),
             do: package_rbf(state, txs, wss, conflicts, total_fee, total_vsize),
             else: {:ok, MapSet.new()}
           ),
         :ok <-
           if(Pool.stage(state.pool, Enum.map(wss, & &1.entry), all_conflicts).oversized,
             do: {:pkg_error, {:policy, "too-large-cluster", ""}},
             else: :ok
           ),
         :ok <- unspent_dust(txs, state),
         :ok <- scripts(wss, chain) do
      results =
        Map.new(wss, fn ws ->
          {ws.tx.wtxid,
           {:valid,
            %{
              txid: ws.tx.txid,
              wtxid: ws.tx.wtxid,
              vsize: ws.vsize,
              fee: ws.fee,
              replaced: MapSet.to_list(all_conflicts)
            }}}
        end)

      if args.test_accept do
        {%{state: :ok, txs: results}, state}
      else
        [first | rest] = wss

        state =
          Accept.finalize(state, [
            %{first | all_conflicts: all_conflicts}
            | Enum.map(rest, &%{&1 | all_conflicts: MapSet.new()})
          ])

        {%{state: :ok, txs: results}, state}
      end
    else
      {:pkg_error, pkg_state} -> {%{state: pkg_state, txs: %{}}, state}
      {:pkg_error, pkg_state, txs_res} -> {%{state: pkg_state, txs: txs_res}, state}
    end
  end

  defp package_fee_rate(state, args, vsize, fee, chain, child) do
    if args.package_feerates do
      case Accept.check_fee_rate(state, vsize, fee, chain.now) do
        :ok ->
          :ok

        {:error, e} ->
          {:pkg_error, {:tx, "transaction failed", nil}, %{child.wtxid => {:invalid, e}}}
      end
    else
      :ok
    end
  end

  # Core: CheckEphemeralSpends over the package ("unspent-dust").
  defp unspent_dust(txs, state) do
    case Accept.ephemeral_spends(txs, state.pool, state.opts) do
      :ok ->
        :ok

      {:error, e} ->
        child = Enum.find(txs, fn tx -> String.contains?(e.detail, Accept.hex(tx.txid)) end)
        {:pkg_error, {:tx, "unspent-dust", nil}, %{child.wtxid => {:invalid, e}}}
    end
  end

  defp scripts(wss, chain) do
    Enum.find_value(wss, :ok, fn ws ->
      case Accept.script_checks(ws, chain) do
        :ok ->
          nil

        {:error, e} ->
          {:pkg_error, {:tx, "transaction failed", nil}, %{ws.tx.wtxid => {:invalid, e}}}
      end
    end)
  end

  # Core: MemPoolAccept::PackageRBFChecks
  defp package_rbf(state, txs, wss, conflicts, total_fee, total_vsize) do
    pool = state.pool

    cond do
      length(wss) != 2 or not child_with_parents?(txs) ->
        {:pkg_error, {:policy, "package RBF failed: package must be 1-parent-1-child", nil}}

      Enum.any?(wss, &(&1.parents != [])) ->
        {:pkg_error,
         {:policy, "package RBF failed: new transaction cannot have mempool ancestors", nil}}

      conflicts |> Enum.map(&Pool.cluster(pool, &1)) |> Enum.uniq() |> length() > 100 ->
        {:pkg_error, {:policy, "package RBF failed: too many potential replacements", nil}}

      true ->
        all = Pool.with_descendants(pool, MapSet.to_list(conflicts))
        conflicting_fees = Enum.reduce(all, 0, &(&2 + Pool.get(pool, &1).fee))
        [parent, _child] = wss

        cond do
          total_fee < conflicting_fees or
              total_fee - conflicting_fees < Policy.fee_for(state.opts.incremental, total_vsize) ->
            {:pkg_error, {:policy, "package RBF failed: insufficient anti-DoS fees", nil}}

          # package feerate <= parent feerate (CFeeRate compares the exact fractions).
          total_fee * parent.vsize <= parent.fee * total_vsize ->
            {:pkg_error,
             {:policy,
              "package RBF failed: package feerate is less than or equal to parent feerate", nil}}

          true ->
            staged = Pool.stage(pool, Enum.map(wss, & &1.entry), all)

            cond do
              staged.oversized ->
                {:pkg_error, {:policy, "too-large-cluster", ""}}

              true ->
                {main, staging} = Pool.diagrams(pool, staged)

                if Linearize.compare_chunks(staging, main) == :gt,
                  do: {:ok, all},
                  else:
                    {:pkg_error,
                     {:policy,
                      "package RBF failed: insufficient feerate: does not improve feerate diagram",
                      ""}}
            end
        end
    end
  end

  # Core: PackageTRUCChecks for every tx.
  defp truc_checks(pool, txs, wss) do
    Enum.find_value(Enum.zip(txs, wss), :ok, fn {tx, ws} ->
      case package_truc(pool, tx, ws, txs) do
        nil -> nil
        msg -> {:pkg_error, {:policy, "TRUC-violation", msg}}
      end
    end)
  end

  defp package_truc(pool, tx, ws, package) do
    id = "#{Accept.hex(tx.txid)} (wtxid=#{Accept.hex(tx.wtxid)})"

    in_pkg =
      for p <- package, p.txid != tx.txid, Enum.any?(tx.inputs, &(&1.prev_hash == p.txid)), do: p

    mempool_parents = Enum.map(ws.parents, &Pool.get(pool, &1))

    if tx.version == @truc_version do
      cond do
        ws.vsize > 10_000 ->
          "version=3 tx #{id} is too big: #{ws.vsize} > 10000 virtual bytes"

        length(mempool_parents) + length(in_pkg) + 1 > 2 ->
          "tx #{id} would have too many ancestors"

        mempool_parents != [] and
            MapSet.size(Pool.ancestors(pool, hd(mempool_parents).txid)) + 1 + length(in_pkg) + 1 >
              2 ->
          "tx #{id} would have too many ancestors"

        mempool_parents == [] and in_pkg == [] ->
          nil

        ws.vsize > 1_000 ->
          "version=3 child tx #{id} is too big: #{ws.vsize} > 1000 virtual bytes"

        true ->
          {ptxid, pwtxid, pversion, has_desc} =
            case mempool_parents do
              [p | _] ->
                {p.txid, p.wtxid, p.tx.version,
                 MapSet.size(Pool.descendants(pool, p.txid)) + 1 > 1}

              [] ->
                p = hd(in_pkg)
                {p.txid, p.wtxid, p.version, false}
            end

          pid = "#{Accept.hex(ptxid)} (wtxid=#{Accept.hex(pwtxid)})"

          cond do
            pversion != @truc_version ->
              "version=3 tx #{id} cannot spend from non-version=3 tx #{pid}"

            (other =
               Enum.find_value(package, fn ptx ->
                 if ptx.txid != tx.txid do
                   Enum.find_value(ptx.inputs, fn i ->
                     cond do
                       i.prev_hash == ptxid ->
                         "tx #{pid} would exceed descendant count limit"

                       i.prev_hash == tx.txid ->
                         "tx #{Accept.hex(ptx.txid)} (wtxid=#{Accept.hex(ptx.wtxid)}) would have too many ancestors"

                       true ->
                         nil
                     end
                   end)
                 end
               end)) != nil ->
              other

            has_desc ->
              "tx #{pid} would exceed descendant count limit"

            true ->
              nil
          end
      end
    else
      Enum.find_value(mempool_parents, fn p ->
        if p.tx.version == @truc_version,
          do:
            "non-version=3 tx #{id} cannot spend from version=3 tx #{Accept.hex(p.txid)} (wtxid=#{Accept.hex(p.wtxid)})"
      end) ||
        Enum.find_value(in_pkg, fn p ->
          if p.version == @truc_version,
            do:
              "non-version=3 tx #{id} cannot spend from version=3 tx #{Accept.hex(p.txid)} (wtxid=#{Accept.hex(p.wtxid)})"
        end)
    end
  end
end
