defmodule Exnode.Mempool.Accept do
  @moduledoc """
  Mempool acceptance. A port of Core v32.1 `MemPoolAccept` (validation.cpp):
  `PreChecks`, `ReplacementChecks`, `AcceptSingleTransactionInternal`, and
  `LimitMempoolSize` / `TrimToSize` / `GetMinFee`, using the same check
  order and reject reasons. Package acceptance is in `Exnode.Mempool.Package`.

  It is a pure function of the pool and a chain context:

  * `chain.tip`: `%{height, hash, mtp}` of the active tip
  * `chain.idx`: the header index (for BIP68 ancestors)
  * `chain.flags`: consensus script flags of the tip block (Core
    `ConsensusScriptChecks`). The kernel exposes no policy flags, so these
    also stand in for `STANDARD_SCRIPT_VERIFY_FLAGS` (documented gap).
  * `chain.coins.(outpoints)`: on-chain unspent coins,
    `%{op => {:ok, coin} | :missing}`
  * `chain.now`: seconds, for entry time, expiry and the rolling minimum fee

  Results: `{:ok, %{txid, wtxid, vsize, fee, replaced}, pool}` or
  `{:error, %{result, reason, detail}, pool}`. `result` mirrors Core's
  `TxValidationResult` (`:consensus`, `:not_standard`, `:missing_inputs`,
  `:conflict`, `:premature_spend`, `:reconsiderable`, `:mempool_policy`,
  `:witness_mutated`, `:inputs_not_standard`, `:witness_stripped`).
  """
  import Bitwise

  alias Exnode.Codec.Tx
  alias Exnode.Mempool.{Linearize, Policy, Pool}
  alias Exnode.Mempool.Pool.Entry
  alias Exnode.Validation.{Block, Connect, TxCheck}

  @mempool_height 0x7FFFFFFF
  @max_replacement_candidates 100
  @truc_version 3
  @truc_max_vsize 10_000
  @truc_child_max_vsize 1_000
  @rolling_fee_halflife 60 * 60 * 12

  # Mempool-wide options (Core MemPoolOptions defaults).
  def default_opts do
    %{
      min_relay: Policy.default_min_relay_tx_fee(),
      incremental: Policy.default_incremental_relay_fee(),
      dust: Policy.dust_relay_tx_fee(),
      max_size: 300_000_000,
      expiry: 336 * 3600,
      max_datacarrier: Policy.max_op_return_relay(),
      bare_multisig: true
    }
  end

  @doc """
  Fee state for the rolling minimum (Core `rollingMinimumFeeRate`,
  `lastRollingFeeUpdate`, `blockSinceLastRollingFeeBump`).
  """
  def new_fee_state, do: %{rolling: 0.0, last_update: 0, block_since_bump: false}

  # --- single transaction ------------------------------------------------------

  @doc """
  Core `AcceptToMemoryPool` for one tx. Options: `:test_accept`,
  `:bypass_limits` (re-adding a disconnected block's txs), `:allow_replacement`
  (default true), `:allow_sibling_eviction` (default true).
  `state` is `%{pool, fees, opts}`.
  """
  # Core: MemPoolAccept::AcceptSingleTransactionInternal (validation.cpp)
  def accept(state, %Tx{} = tx, chain, args \\ []) do
    args = normalize_args(args)

    case prepare(state, tx, chain, args) do
      {:ok, ws} -> complete(state, ws, verify_scripts(ws, chain), chain, args)
      {:error, e} -> {:error, e, state}
    end
  end

  @doc """
  `accept/4` up to the script checks (normalized `args`): `{:ok, workspace}`
  or `{:error, e}`. The mempool process runs the scripts of
  `script_input/2` elsewhere, then `complete/5`.
  """
  # Core: AcceptSingleTransactionInternal, PreChecks .. ConsensusScriptChecks (exclusive)
  def prepare(state, tx, chain, args) do
    with {:ok, ws} <- pre_checks(state, tx, chain, args),
         {:ok, ws} <-
           if(ws.conflicts != MapSet.new(), do: replacement_checks(state, ws), else: {:ok, ws}),
         :ok <- cluster_limits(state.pool, ws),
         :ok <- disjoint_ancestors(state.pool, ws),
         :ok <-
           if(not args.bypass_limits,
             do: ephemeral_spends([tx], state.pool, state.opts),
             else: :ok
           ) do
      # Not kept while the scripts run (it holds the staged clusters).
      {:ok, %{ws | staged: nil}}
    end
  end

  @doc """
  `accept/4` after `prepare/4`, given the kernel's answer for
  `script_input/2` (`:ok | {:error, _}`).
  """
  # Core: AcceptSingleTransactionInternal, script checks onward (FinalizeSubpackage, LimitMempoolSize)
  def complete(state, ws, kernel_result, chain, args) do
    tx = ws.tx

    with :ok <- script_verdict(ws, kernel_result) do
      result = %{
        txid: tx.txid,
        wtxid: tx.wtxid,
        vsize: ws.vsize,
        fee: ws.fee,
        replaced: MapSet.to_list(ws.all_conflicts)
      }

      if args.test_accept do
        {:ok, result, state}
      else
        state = finalize(state, [ws])

        # Packages trim once at the end (AcceptPackage).
        if args.bypass_limits or args.package_submission do
          {:ok, result, state}
        else
          state = limit_size(state, chain.now)

          if Pool.exists?(state.pool, tx.txid),
            do: {:ok, result, state},
            else: {:error, err(:reconsiderable, "mempool full"), state}
        end
      end
    else
      {:error, e} -> {:error, e, state}
    end
  end

  @doc false
  def normalize_args(args),
    do:
      Map.merge(
        %{
          test_accept: false,
          bypass_limits: false,
          allow_replacement: true,
          allow_sibling_eviction: true,
          package_feerates: false,
          package_submission: false,
          package_coins: %{}
        },
        Map.new(args)
      )

  @doc false
  def err(result, reason, detail \\ nil), do: %{result: result, reason: reason, detail: detail}

  @doc """
  The checks `pre_checks/4` runs first, which need neither the chain nor
  coins: `:ok` or `{:error, e}`. The mempool process runs them before it
  asks the chain state for anything, so a malformed tx costs no disk read.
  """
  # Core: MemPoolAccept::PreChecks, up to IsFinalTx (CheckTransaction, IsCoinBase, IsStandardTx, MIN_STANDARD_TX_NONWITNESS_SIZE)
  def precheck_context_free(%{opts: opts}, tx) do
    with :ok <- tag(TxCheck.check_transaction(tx), :consensus),
         :ok <- if(Tx.coinbase?(tx), do: {:error, err(:consensus, "coinbase")}, else: :ok),
         :ok <-
           tag(
             Policy.standard_tx(tx,
               max_datacarrier_bytes: opts.max_datacarrier,
               permit_bare_multisig: opts.bare_multisig,
               dust_relay_fee: opts.dust
             ),
             :not_standard
           ) do
      if Tx.base_size(tx) < Policy.min_standard_tx_nonwitness_size(),
        do: {:error, err(:not_standard, "tx-size-small")},
        else: :ok
    end
  end

  # Core: MemPoolAccept::PreChecks (validation.cpp)
  @doc false
  def pre_checks(%{pool: pool, opts: opts} = state, tx, chain, args) do
    with :ok <- precheck_context_free(state, tx),
         :ok <-
           if(Block.final_tx?(tx, chain.tip.height + 1, chain.tip.mtp),
             do: :ok,
             else: {:error, err(:premature_spend, "non-final")}
           ),
         :ok <- already_in_mempool(pool, tx),
         {:ok, conflicts} <- direct_conflicts(pool, tx, args),
         {:ok, coins} <- have_inputs(pool, tx, chain, args.package_coins),
         :ok <-
           if(bip68_final?(tx, coins, chain),
             do: :ok,
             else: {:error, err(:premature_spend, "non-BIP68-final")}
           ),
         {:ok, fee} <- tx_inputs(tx, coins, chain.tip.height + 1),
         spks = Enum.map(coins, & &1.script_pubkey),
         :ok <- inputs_standard(tx, spks),
         :ok <-
           if(tx.has_witness and not Policy.witness_standard?(tx, spks),
             do: {:error, err(:witness_mutated, "bad-witness-nonstandard")},
             else: :ok
           ) do
      kf = Exnode.Kernel.flags()
      sigops = Connect.sigop_cost(tx, coins, kf.p2sh ||| kf.witness, false)
      weight = max(Tx.weight(tx), sigops * Policy.bytes_per_sigop())
      vsize = div(weight + 3, 4)

      entry = %Entry{
        tx: tx,
        txid: tx.txid,
        wtxid: tx.wtxid,
        fee: fee,
        vsize: vsize,
        weight: weight,
        sigops: sigops,
        time: chain.now,
        height: chain.tip.height,
        spends_coinbase: Enum.any?(coins, & &1.coinbase),
        spent:
          if(Pool.indexes_scripts?(pool),
            do: for(c <- coins, do: {c.value, :crypto.hash(:sha256, c.script_pubkey)})
          )
      }

      parents =
        for(i <- tx.inputs, Pool.exists?(pool, i.prev_hash), uniq: true, do: i.prev_hash)
        |> Enum.sort()

      ws = %{
        tx: tx,
        entry: entry,
        fee: fee,
        vsize: vsize,
        coins: coins,
        conflicts: conflicts,
        all_conflicts: MapSet.new(),
        sibling_eviction: false,
        parents: parents,
        # Pool.stage of this tx and all_conflicts, once replacement_checks made it.
        staged: nil
      }

      with :ok <- if(not args.bypass_limits, do: precheck_ephemeral(tx, fee, opts), else: :ok),
           :ok <-
             if(sigops > Policy.max_standard_tx_sigops_cost(),
               do: {:error, err(:not_standard, "bad-txns-too-many-sigops", "#{sigops}")},
               else: :ok
             ),
           :ok <-
             if(not args.bypass_limits and not args.package_feerates,
               do: check_fee_rate(state, vsize, fee, chain.now),
               else: :ok
             ),
           {:ok, ws} <-
             if(not args.bypass_limits, do: single_truc_checks(pool, ws, args), else: {:ok, ws}) do
        {:ok, ws}
      end
    end
  end

  defp tag(:ok, _), do: :ok
  defp tag({:error, reason}, result), do: {:error, err(result, reason)}

  defp already_in_mempool(pool, tx) do
    cond do
      Pool.exists_wtxid?(pool, tx.wtxid) ->
        {:error, err(:conflict, "txn-already-in-mempool")}

      Pool.exists?(pool, tx.txid) ->
        {:error, err(:conflict, "txn-same-nonwitness-data-in-mempool")}

      true ->
        :ok
    end
  end

  defp direct_conflicts(pool, tx, args) do
    conflicts =
      for i <- tx.inputs,
          (s = Pool.spender(pool, {i.prev_hash, i.prev_index})) != nil,
          into: MapSet.new(),
          do: s

    if conflicts != MapSet.new() and not args.allow_replacement,
      do: {:error, err(:mempool_policy, "bip125-replacement-disallowed")},
      else: {:ok, conflicts}
  end

  # View: mempool outputs, then the chain's unspent coins. Coins spent by a
  # mempool tx are still visible here (they are conflicts, handled by RBF).
  defp have_inputs(pool, tx, chain, package_coins \\ %{}) do
    ops = for i <- tx.inputs, do: {i.prev_hash, i.prev_index}

    chain_ops =
      Enum.reject(ops, fn {t, _} = op ->
        Pool.exists?(pool, t) or Map.has_key?(package_coins, op)
      end)

    resolved = if chain_ops == [], do: %{}, else: chain.coins.(chain_ops)

    coins =
      Enum.map(ops, fn {t, v} = op ->
        case Map.get(package_coins, op) || Pool.output(pool, t, v) do
          %{height: _} = c ->
            c

          %Tx.Out{} = o ->
            %{
              value: o.value,
              script_pubkey: o.script_pubkey,
              height: @mempool_height,
              coinbase: false
            }

          nil ->
            if Pool.exists?(pool, t) do
              nil
            else
              case resolved[op] do
                {:ok, c} -> c
                _ -> nil
              end
            end
        end
      end)

    if Enum.any?(coins, &is_nil/1) do
      # Core: "txn-already-known" if any output of this tx is an unspent coin.
      own = for v <- 0..(length(tx.outputs) - 1)//1, do: {tx.txid, v}

      if Enum.any?(chain.coins.(own), fn {_, r} -> match?({:ok, _}, r) end),
        do: {:error, err(:conflict, "txn-already-known")},
        else: {:error, err(:missing_inputs, "bad-txns-inputs-missingorspent")}
    else
      {:ok, coins}
    end
  end

  # Core: CalculateLockPointsAtTip + CheckSequenceLocksAtTip. The next block
  # is a dummy at tip height + 1; mempool coins count as tip height + 1.
  defp bip68_final?(tx, coins, chain) do
    next = %Exnode.Chain.HeaderIndex.Entry{
      height: chain.tip.height + 1,
      prev_hash: chain.tip.hash,
      hash: :next_block
    }

    tip = Exnode.Chain.HeaderIndex.lookup(chain.idx, chain.tip.hash)

    coins =
      for c <- coins,
          do: if(c.height == @mempool_height, do: %{c | height: chain.tip.height + 1}, else: c)

    # Mempool: LOCKTIME_VERIFY_SEQUENCE always (STANDARD_LOCKTIME_VERIFY_FLAGS).
    Connect.sequence_locks?(tx, coins, true, next, tip, chain.idx)
  end

  defp tx_inputs(tx, coins, height) do
    case Connect.check_tx_inputs(tx, coins, height) do
      {:ok, fee} -> {:ok, fee}
      {:error, {:consensus, reason}} -> {:error, err(:consensus, reason)}
    end
  end

  defp inputs_standard(tx, spks) do
    case Policy.inputs_standard(tx, spks) do
      :ok -> :ok
      {:error, reason, detail} -> {:error, err(:inputs_not_standard, reason, detail)}
    end
  end

  # Core: PreCheckEphemeralTx (policy/ephemeral_policy.cpp)
  defp precheck_ephemeral(tx, fee, opts) do
    if fee != 0 and Policy.dust_outputs(tx, opts.dust) != [],
      do: {:error, err(:not_standard, "dust", "tx with dust output must be 0-fee")},
      else: :ok
  end

  @doc "Core `CheckEphemeralSpends`: every tx spends all dust outputs of its in-package or in-mempool parents."
  # Core: CheckEphemeralSpends (policy/ephemeral_policy.cpp)
  def ephemeral_spends(txs, pool, opts) do
    in_package = Map.new(txs, &{&1.txid, &1})

    Enum.find_value(txs, :ok, fn tx ->
      parents = tx.inputs |> Enum.map(& &1.prev_hash) |> Enum.uniq()

      dust =
        for p <- parents,
            ptx = Map.get(in_package, p) || ((e = Pool.get(pool, p)) && e.tx),
            ptx != nil,
            {o, i} <- Enum.with_index(ptx.outputs),
            Policy.dust?(o, opts.dust),
            into: MapSet.new(),
            do: {p, i}

      spent = for i <- tx.inputs, into: MapSet.new(), do: {i.prev_hash, i.prev_index}

      if MapSet.subset?(dust, spent),
        do: nil,
        else:
          {:error,
           err(
             :mempool_policy,
             "missing-ephemeral-spends",
             "tx #{hex(tx.txid)} (wtxid=#{hex(tx.wtxid)}) did not spend parent's ephemeral dust"
           )}
    end)
  end

  @doc "Core `CheckFeeRate`: mempool minimum fee, then minimum relay fee."
  def check_fee_rate(state, vsize, fee, now) do
    {min_rate, _fees} = min_fee(state, now)
    reject_fee = Policy.fee_for(min_rate, vsize)

    cond do
      reject_fee > 0 and fee < reject_fee ->
        {:error, err(:reconsiderable, "mempool min fee not met", "#{fee} < #{reject_fee}")}

      fee < Policy.fee_for(state.opts.min_relay, vsize) ->
        {:error,
         err(
           :reconsiderable,
           "min relay fee not met",
           "#{fee} < #{Policy.fee_for(state.opts.min_relay, vsize)}"
         )}

      true ->
        :ok
    end
  end

  # --- TRUC (policy/truc_policy.cpp) --------------------------------------------

  # Core: SingleTRUCChecks
  defp single_truc_checks(pool, ws, args) do
    tx = ws.tx
    # Core GetParents: in-mempool parents in txid order (std::set<Txid>).
    parents = Enum.map(ws.parents, &Pool.get(pool, &1))
    id = "#{hex(tx.txid)} (wtxid=#{hex(tx.wtxid)})"

    inherit =
      Enum.find_value(parents, fn p ->
        pid = "#{hex(p.txid)} (wtxid=#{hex(p.wtxid)})"

        cond do
          tx.version != @truc_version and p.tx.version == @truc_version ->
            "non-version=3 tx #{id} cannot spend from version=3 tx #{pid}"

          tx.version == @truc_version and p.tx.version != @truc_version ->
            "version=3 tx #{id} cannot spend from non-version=3 tx #{pid}"

          true ->
            nil
        end
      end)

    violation =
      cond do
        inherit ->
          {inherit, nil}

        tx.version != @truc_version ->
          nil

        ws.vsize > @truc_max_vsize ->
          {"version=3 tx #{id} is too big: #{ws.vsize} > #{@truc_max_vsize} virtual bytes", nil}

        length(parents) + 1 > 2 ->
          {"tx #{id} would have too many ancestors", nil}

        parents == [] ->
          nil

        true ->
          truc_parent_checks(pool, ws, hd(parents), id)
      end

    case violation do
      nil ->
        {:ok, ws}

      {_msg, sibling} when sibling != nil and args.allow_sibling_eviction ->
        # Sibling eviction: treat the sibling as a conflict for the RBF checks.
        {:ok, %{ws | conflicts: MapSet.put(ws.conflicts, sibling), sibling_eviction: true}}

      {msg, _} ->
        {:error, err(:mempool_policy, "TRUC-violation", msg)}
    end
  end

  defp truc_parent_checks(pool, ws, parent, id) do
    parent_ancestors = MapSet.size(Pool.ancestors(pool, parent.txid)) + 1

    cond do
      parent_ancestors + 1 > 2 ->
        {"tx #{id} would have too many ancestors", nil}

      ws.vsize > @truc_child_max_vsize ->
        {"version=3 child tx #{id} is too big: #{ws.vsize} > #{@truc_child_max_vsize} virtual bytes",
         nil}

      true ->
        descendants = Pool.descendants(pool, parent.txid)
        child_replaced = Enum.any?(descendants, &MapSet.member?(ws.conflicts, &1))
        desc_count = MapSet.size(descendants) + 1

        if desc_count + 1 > 2 and not child_replaced do
          [first | _] = Enum.sort(MapSet.to_list(descendants))
          sibling_ok = desc_count == 2 and MapSet.size(Pool.ancestors(pool, first)) + 1 == 2

          {"tx #{hex(parent.txid)} (wtxid=#{hex(parent.wtxid)}) would exceed descendant count limit",
           if(sibling_ok, do: first)}
        else
          nil
        end
    end
  end

  # --- RBF (policy/rbf.cpp) ----------------------------------------------------

  # Core: MemPoolAccept::ReplacementChecks
  defp replacement_checks(%{pool: pool, opts: opts}, ws) do
    clusters = ws.conflicts |> Enum.map(&Pool.cluster(pool, &1)) |> Enum.uniq() |> length()
    suffix = if ws.sibling_eviction, do: " (including sibling eviction)", else: ""

    if clusters > @max_replacement_candidates do
      {:error,
       err(
         :mempool_policy,
         "too many potential replacements#{suffix}",
         "rejecting replacement #{hex(ws.tx.txid)}; too many conflicting clusters (#{clusters} > #{@max_replacement_candidates})"
       )}
    else
      all = Pool.with_descendants(pool, MapSet.to_list(ws.conflicts))
      conflicting_fees = Enum.reduce(all, 0, &(&2 + Pool.get(pool, &1).fee))
      ws = %{ws | all_conflicts: all}

      cond do
        ws.fee < conflicting_fees ->
          {:error,
           err(
             :reconsiderable,
             "insufficient fee#{suffix}",
             "rejecting replacement #{hex(ws.tx.txid)}, less fees than conflicting txs"
           )}

        ws.fee - conflicting_fees < Policy.fee_for(opts.incremental, ws.vsize) ->
          {:error,
           err(
             :reconsiderable,
             "insufficient fee#{suffix}",
             "rejecting replacement #{hex(ws.tx.txid)}, not enough additional fees to relay"
           )}

        true ->
          staged = Pool.stage(pool, [ws.entry], all)

          cond do
            staged.oversized ->
              {:error, err(:mempool_policy, "too-large-cluster", "")}

            true ->
              {main, staging} = Pool.diagrams(pool, staged)

              if Linearize.compare_chunks(staging, main) == :gt,
                do: {:ok, %{ws | staged: staged}},
                else:
                  {:error,
                   err(
                     :reconsiderable,
                     "replacement-failed",
                     "insufficient feerate: does not improve feerate diagram"
                   )}
          end
      end
    end
  end

  @doc false
  def cluster_limits(pool, ws) do
    # The same pool, tx and conflicts as replacement_checks' stage, if it ran.
    staged = ws[:staged] || Pool.stage(pool, [ws.entry], ws.all_conflicts)

    if staged.oversized,
      do: {:error, err(:mempool_policy, "too-large-cluster", "")},
      else: :ok
  end

  # Core: EntriesAndTxidsDisjoint: a tx may not spend (through its ancestors)
  # a tx it conflicts with.
  defp disjoint_ancestors(pool, ws) do
    if ws.conflicts == MapSet.new() do
      :ok
    else
      ancestors =
        ws.tx.inputs
        |> Enum.map(& &1.prev_hash)
        |> Enum.filter(&Pool.exists?(pool, &1))
        |> Enum.reduce(MapSet.new(), fn p, acc ->
          acc |> MapSet.put(p) |> MapSet.union(Pool.ancestors(pool, p))
        end)

      case Enum.find(ancestors, &MapSet.member?(ws.conflicts, &1)) do
        nil ->
          :ok

        a ->
          {:error,
           err(
             :consensus,
             "bad-txns-spends-conflicting-tx",
             "#{hex(ws.tx.txid)} spends conflicting transaction #{hex(a)}"
           )}
      end
    end
  end

  # --- scripts -----------------------------------------------------------------

  # Core: PolicyScriptChecks then ConsensusScriptChecks. Both run with the
  # tip's consensus flags here (the kernel has no policy flags).
  @doc false
  def script_checks(ws, chain), do: script_verdict(ws, verify_scripts(ws, chain))

  @doc "The kernel call the script checks make: `{raw_tx, spent_outputs, flags}`."
  def script_input(ws, chain),
    do: {ws.tx.raw, for(c <- ws.coins, do: {c.script_pubkey, c.value}), chain.flags}

  defp verify_scripts(ws, chain) do
    {raw, spent, flags} = script_input(ws, chain)
    Exnode.Kernel.verify_tx_all(raw, spent, flags)
  end

  @doc false
  def script_verdict(ws, kernel_result) do
    case kernel_result do
      :ok ->
        :ok

      {:error, _} ->
        result =
          if not ws.tx.has_witness and
               Policy.spends_non_anchor_witness_prog?(
                 ws.tx,
                 Enum.map(ws.coins, & &1.script_pubkey)
               ),
             do: :witness_stripped,
             else: :not_standard

        {:error, err(result, "mempool-script-verify-flag-failed")}
    end
  end

  # --- applying, trimming --------------------------------------------------------

  @doc "Core `FinalizeSubpackage`: remove all conflicts, add the entries."
  def finalize(state, workspaces) do
    removed = Enum.reduce(workspaces, MapSet.new(), &MapSet.union(&2, &1.all_conflicts))
    pool = Pool.remove(state.pool, removed)
    pool = Enum.reduce(workspaces, pool, &Pool.add(&2, &1.entry))
    %{state | pool: pool}
  end

  @doc "Core `LimitMempoolSize`: expire old txs, then `TrimToSize`."
  def limit_size(state, now) do
    state |> expire(now - state.opts.expiry) |> trim_to_size(state.opts.max_size)
  end

  # Core: CTxMemPool::Expire (time-indexed: Pool.expired/2 walks the oldest entries only).
  defp expire(state, cutoff) do
    old = Pool.expired(state.pool, cutoff)

    if old == [],
      do: state,
      else: %{state | pool: Pool.remove(state.pool, Pool.with_descendants(state.pool, old))}
  end

  # Core: CTxMemPool::TrimToSize. Pool.trim/2 evicts worst chunks (one
  # full linearization, then only the clusters it touches); each evicted
  # chunk bumps the rolling minimum fee as before.
  def trim_to_size(state, limit) do
    {pool, evicted} = Pool.trim(state.pool, limit)

    fees =
      Enum.reduce(evicted, state.fees, fn {{fee, weight}, _ids}, fees ->
        # FeePerWeight -> per-vsize rate in sat/kvB (FeePerVSize(fee, (w + 3) / 4)).
        removed_rate = div(fee * 1000, div(weight + 3, 4)) + state.opts.incremental

        if removed_rate > fees.rolling,
          do: %{fees | rolling: removed_rate * 1.0, block_since_bump: false},
          else: fees
      end)

    %{state | pool: pool, fees: fees}
  end

  @doc "Core `GetMinFee(sizelimit)`: `{rate sat/kvB, fees}` (the decay is applied to the state)."
  # Core: CTxMemPool::GetMinFee (txmempool.cpp)
  def min_fee(%{fees: f, opts: o, pool: pool}, now) do
    if not f.block_since_bump or f.rolling == 0 do
      {round(f.rolling), f}
    else
      if now > f.last_update + 10 do
        halflife =
          cond do
            pool.total_usage < o.max_size / 4 -> @rolling_fee_halflife / 4
            pool.total_usage < o.max_size / 2 -> @rolling_fee_halflife / 2
            true -> @rolling_fee_halflife
          end

        rolling = f.rolling / :math.pow(2.0, (now - f.last_update) / halflife)
        f = %{f | rolling: rolling, last_update: now}

        if rolling < o.incremental / 2,
          do: {0, %{f | rolling: 0.0}},
          else: {max(round(rolling), o.incremental), f}
      else
        {max(round(f.rolling), o.incremental), f}
      end
    end
  end

  @doc """
  After a reorg (Core `filter_final_and_mature`): the entry's BIP68 locks
  still hold at the tip, and any coinbase it spends exists and is mature.
  """
  def still_valid_at_tip?(%{pool: pool}, %Entry{tx: tx} = e, chain) do
    case have_inputs(pool, tx, chain) do
      {:ok, coins} ->
        bip68_final?(tx, coins, chain) and
          (not e.spends_coinbase or
             Enum.all?(coins, fn c ->
               c.height == @mempool_height or not c.coinbase or
                 chain.tip.height + 1 - c.height >= 100
             end))

      {:error, _} ->
        false
    end
  end

  @doc "Core `removeForBlock`: confirmed txs leave; txs conflicting with the block leave with descendants."
  # Core: CTxMemPool::removeForBlock (txmempool.cpp)
  def remove_for_block(state, txs, now) do
    pool =
      Enum.reduce(txs, state.pool, fn tx, pool ->
        pool = Pool.remove(pool, [tx.txid])

        conflicts =
          for {txid, vout} <- tx.prevouts,
              (s = Pool.spender(pool, {txid, vout})) != nil,
              s != tx.txid,
              uniq: true,
              do: s

        if conflicts == [],
          do: pool,
          else: Pool.remove(pool, Pool.with_descendants(pool, conflicts))
      end)

    %{state | pool: pool, fees: %{state.fees | last_update: now, block_since_bump: true}}
  end

  @doc false
  def hex(h), do: Exnode.Crypto.Hash.to_hex(h)
end
