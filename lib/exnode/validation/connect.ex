defmodule Exnode.Validation.Connect do
  @moduledoc """
  Non-script parts of Core v32.1 `Chainstate::ConnectBlock` (validation.cpp),
  in Core's order:

  1. BIP30 (with `IsBIP30Repeat`, the BIP34 skip and BIP34_IMPLIES_BIP30_LIMIT)
  2. per tx: `CheckTxInputs`, accumulated fees, BIP68 `SequenceLocks`, sigop
     cost, then `UpdateCoins` (later txs may spend earlier txs' outputs)
  3. coinbase value ≤ subsidy + fees

  4. scripts (`CheckInputScripts`), unless `scripts: false` (assumevalid).
     Core runs them on its parallel check queue and reports a failure only if
     everything above passed (`parallel_result.has_value() && state.IsValid()`),
     so exnode verifies all txs after step 3, in parallel. With
     `scripts: :defer` they are not run: the result carries `checks` and
     `flags` for the caller to verify (the IBD pipeline runs them while later
     blocks get their non-script checks).

  Options for the pipeline: `view: [delta]` are the coin-view effects of
  blocks connected speculatively on top of the archive (newest first), and
  `base_out` is the block's first output id when the archive has not yet
  assigned it.

  The coin view is the archive (selected chain up to the parent, through its
  overlay) plus an in-block overlay. Returns
  `{:ok, %{spent: [output_id], fees, sigops, scripts_checked, delta}}` or
  `{:error, {:consensus, reason}}`. `delta` is the block's effect on the coin
  view (`created`: unspent outputs it adds; `spent`: outpoints it spends),
  for `Archive.connect/5`.
  """
  import Bitwise

  alias Exnode.Archive
  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex, as: Index
  alias Exnode.Codec.Block
  alias Exnode.Consensus
  alias Exnode.Script
  alias Exnode.Validation.ScriptFlags

  @bip34_implies_bip30_limit 1_983_702

  # primitives/transaction.h CTxIn
  @seq_disable 1 <<< 31
  @seq_type 1 <<< 22
  @seq_mask 0x0000FFFF
  @seq_granularity 9

  @doc """
  `entry` is the header-index entry of the block being connected. Its
  parent must be the archive tip.
  """
  # Core: Chainstate::ConnectBlock (validation.cpp), non-script parts
  def connect_block(
        %Archive{} = a,
        %Block{} = block,
        %Index.Entry{} = entry,
        %ChainParams{} = p,
        %Index{} = idx,
        opts \\ []
      ) do
    height = entry.height
    prev = Index.prev(idx, entry)
    flags = ScriptFlags.block_flags(p, height, block.header.hash)

    base_out =
      Keyword.get_lazy(opts, :base_out, fn -> elem(Archive.base_ids(a, block.header.hash), 0) end)

    scripts? = Keyword.get(opts, :scripts, true)
    view = Keyword.get(opts, :view, [])
    # Prefetched committed-state answers (Chain.Prefetch), already checked for the epoch.
    committed = Keyword.get(opts, :committed)

    # Resolve every input of the block against the archive in one batch.
    # Outputs created inside the block are found in the overlay first.
    prefetch =
      timed(:perf_resolve_us, fn ->
        ops = for tx <- tl(block.txs), i <- tx.inputs, do: {i.prev_hash, i.prev_index}
        Archive.labeled(:inputs, fn -> resolve_view(a, ops, view, committed) end)
      end)

    count_ages(prefetch, height)

    with :ok <- bip30(a, view, block, entry, prev, p, idx, committed) do
      lock_flags_csv = height >= p.csv_height
      # The block's MTP is the same for every tx (Core reads pprev->GetMedianTimePast()
      # inside EvaluateSequenceLocks per tx); computed once here.
      prev_mtp = if prev, do: Index.median_time_past(idx, prev)

      # Script jobs ({raw_tx, spent outputs} per tx) are built only when scripts
      # will run (true or :defer); with scripts: false (assumevalid) they would
      # be discarded, so they are not allocated. Every other check still runs.
      st = %{
        overlay: %{},
        spent_in_block: MapSet.new(),
        next_out: base_out,
        fees: 0,
        sigops: 0,
        spent: [],
        checks: [],
        prefetch: prefetch,
        prepare_checks: scripts? != false
      }

      result =
        block.txs
        |> Enum.with_index()
        |> Enum.reduce_while({:ok, st}, fn {tx, pos}, {:ok, st} ->
          case connect_tx(a, tx, pos, st, entry, {prev, prev_mtp}, idx, flags, lock_flags_csv) do
            {:ok, st} -> {:cont, {:ok, st}}
            {:error, _} = e -> {:halt, e}
          end
        end)

      with {:ok, st} <- result do
        reward = st.fees + subsidy(height, p)
        value_out = Enum.reduce(hd(block.txs).outputs, 0, &(&2 + &1.value))

        cond do
          value_out > reward ->
            {:error, {:consensus, "bad-cb-amount"}}

          scripts? == true and
              timed(:perf_scripts_us, fn ->
                Exnode.Validation.Scripts.verify_all(st.checks, flags)
              end) != :ok ->
            {:error, {:consensus, "block-script-verify-flag-failed"}}

          true ->
            {:ok,
             %{
               spent: Enum.reverse(st.spent),
               fees: st.fees,
               sigops: st.sigops,
               scripts_checked: scripts? != false,
               checks: if(scripts? == :defer, do: st.checks, else: nil),
               flags: flags,
               n_outputs: st.next_out - base_out,
               delta: %{
                 created: st.overlay,
                 spent: st.spent_in_block,
                 txids: MapSet.new(block.txs, & &1.txid)
               }
             }}
        end
      end
    end
  end

  defp connect_tx(a, tx, pos, st, entry, {prev, prev_mtp}, idx, flags, csv) do
    coinbase = pos == 0

    with {:ok, coins} <- if(coinbase, do: {:ok, []}, else: have_inputs(a, tx, st)),
         {:ok, fee} <- if(coinbase, do: {:ok, 0}, else: check_tx_inputs(tx, coins, entry.height)),
         fees = st.fees + fee,
         :ok <-
           if(Consensus.money_range?(fees),
             do: :ok,
             else: {:error, {:consensus, "bad-txns-accumulated-fee-outofrange"}}
           ),
         :ok <-
           if(coinbase or sequence_locks?(tx, coins, csv, entry, prev, idx, prev_mtp),
             do: :ok,
             else: {:error, {:consensus, "bad-txns-nonfinal"}}
           ),
         sigops = st.sigops + sigop_cost(tx, coins, flags, coinbase),
         :ok <-
           if(sigops > Consensus.max_block_sigops_cost(),
             do: {:error, {:consensus, "bad-blk-sigops"}},
             else: :ok
           ) do
      checks =
        if coinbase or not st.prepare_checks,
          do: st.checks,
          else: [{tx.raw, Enum.map(coins, &{&1.script_pubkey, &1.value})} | st.checks]

      {:ok,
       update_coins(tx, coins, coinbase, entry.height, %{
         st
         | fees: fees,
           sigops: sigops,
           checks: checks
       })}
    end
  end

  # --- view ------------------------------------------------------------------

  # Core: CCoinsViewCache::HaveInputs + AccessCoin. Public for the pure
  # preparation engine (Exnode.Validation.Prepare), which shares it.
  @doc false
  def have_inputs(a, tx, st) do
    tx.inputs
    |> Enum.reduce_while([], fn i, acc ->
      key = {i.prev_hash, i.prev_index}

      coin =
        cond do
          MapSet.member?(st.spent_in_block, key) -> nil
          Map.has_key?(st.overlay, key) -> st.overlay[key]
          true -> archive_coin(a, i, st.prefetch)
        end

      if coin, do: {:cont, [coin | acc]}, else: {:halt, :missing}
    end)
    |> case do
      :missing -> {:error, {:consensus, "bad-txns-inputs-missingorspent"}}
      coins -> {:ok, Enum.reverse(coins)}
    end
  end

  defp timed(key, f) do
    t = System.monotonic_time(:microsecond)
    r = f.()
    Process.put(key, (Process.get(key) || 0) + System.monotonic_time(:microsecond) - t)
    r
  end

  defp archive_coin(_a, i, prefetch) do
    case Map.fetch!(prefetch, {i.prev_hash, i.prev_index}) do
      {:ok, c} -> c
      :missing -> nil
    end
  end

  # Core: UpdateCoins / AddCoins. Unspendable outputs are never added.
  @doc false
  def update_coins(tx, coins, coinbase, height, st) do
    spent_keys = for i <- tx.inputs, do: {i.prev_hash, i.prev_index}

    {overlay, next} =
      tx.outputs
      |> Enum.with_index()
      |> Enum.reduce({Map.drop(st.overlay, spent_keys), st.next_out}, fn {o, vout}, {ov, id} ->
        ov =
          if Script.unspendable?(o.script_pubkey),
            do: ov,
            else:
              Map.put(ov, {tx.txid, vout}, %{
                output_id: id,
                value: o.value,
                script_pubkey: o.script_pubkey,
                height: height,
                coinbase: coinbase
              })

        {ov, id + 1}
      end)

    %{
      st
      | overlay: overlay,
        next_out: next,
        spent_in_block: MapSet.union(st.spent_in_block, MapSet.new(spent_keys)),
        spent: Enum.reverse(Enum.map(coins, & &1.output_id)) ++ st.spent
    }
  end

  # --- rules -----------------------------------------------------------------

  # Core: Consensus::CheckTxInputs (consensus/tx_verify.cpp), after HaveInputs.
  @doc false
  def check_tx_inputs(tx, coins, spend_height) do
    Enum.reduce_while(coins, {:ok, 0}, fn c, {:ok, in_sum} ->
      in_sum = in_sum + c.value

      cond do
        c.coinbase and spend_height - c.height < Consensus.coinbase_maturity() ->
          {:halt, {:error, {:consensus, "bad-txns-premature-spend-of-coinbase"}}}

        not Consensus.money_range?(c.value) or not Consensus.money_range?(in_sum) ->
          {:halt, {:error, {:consensus, "bad-txns-inputvalues-outofrange"}}}

        true ->
          {:cont, {:ok, in_sum}}
      end
    end)
    |> case do
      {:ok, value_in} ->
        value_out = Enum.reduce(tx.outputs, 0, &(&2 + &1.value))
        fee = value_in - value_out

        cond do
          value_in < value_out -> {:error, {:consensus, "bad-txns-in-belowout"}}
          not Consensus.money_range?(fee) -> {:error, {:consensus, "bad-txns-fee-outofrange"}}
          true -> {:ok, fee}
        end

      err ->
        err
    end
  end

  # Core: SequenceLocks = EvaluateSequenceLocks(block, CalculateSequenceLocks(...))
  @doc false
  # `block_mtp`, if given, is `median_time_past(prev)`, precomputed by the caller.
  def sequence_locks?(tx, coins, csv, entry, prev, idx, block_mtp \\ nil) do
    {min_height, min_time} =
      if tx.version >= 2 and csv do
        tx.inputs
        |> Enum.zip(coins)
        |> Enum.reduce({-1, -1}, fn {i, c}, {mh, mt} ->
          cond do
            (i.sequence &&& @seq_disable) != 0 ->
              {mh, mt}

            (i.sequence &&& @seq_type) != 0 ->
              anc = Index.ancestor(idx, entry, max(c.height - 1, 0))
              coin_time = Index.median_time_past(idx, anc)
              {mh, max(mt, coin_time + ((i.sequence &&& @seq_mask) <<< @seq_granularity) - 1)}

            true ->
              {max(mh, c.height + (i.sequence &&& @seq_mask) - 1), mt}
          end
        end)
      else
        {-1, -1}
      end

    # Core EvaluateSequenceLocks: `lockPair.first >= block.nHeight ||
    # lockPair.second >= nBlockTime`. With no relative lock (both -1) that is
    # false for any height >= 0 and MTP >= 0, so the MTP need not be read.
    if min_height == -1 and min_time == -1 do
      true
    else
      block_time = block_mtp || Index.median_time_past(idx, prev)
      not (min_height >= entry.height or min_time >= block_time)
    end
  end

  # Core: GetTransactionSigOpCost (consensus/tx_verify.cpp)
  @doc false
  def sigop_cost(tx, coins, flags, coinbase) do
    legacy = Exnode.Validation.Block.legacy_sigop_count(tx) * 4

    if coinbase do
      legacy
    else
      kf = Exnode.Kernel.flags()
      p2sh = if (flags &&& kf.p2sh) != 0, do: p2sh_sigops(tx, coins) * 4, else: 0
      witness = (flags &&& kf.witness) != 0

      wit =
        tx.inputs
        |> Enum.zip(coins)
        |> Enum.reduce(0, fn {i, c}, acc ->
          acc + Script.witness_sigops(i.script_sig, c.script_pubkey, i.witness, witness)
        end)

      legacy + p2sh + wit
    end
  end

  # Core: GetP2SHSigOpCount
  defp p2sh_sigops(tx, coins) do
    tx.inputs
    |> Enum.zip(coins)
    |> Enum.reduce(0, fn {i, c}, acc ->
      if Script.p2sh?(c.script_pubkey),
        do: acc + Script.p2sh_sigop_count(c.script_pubkey, i.script_sig),
        else: acc
    end)
  end

  @doc """
  `Archive.resolve_many/2` seen through speculative deltas (newest first):
  an outpoint created by a delta is that coin; one spent by it, or of a txid
  it contains, is missing; otherwise the archive answers. `committed`:
  prefetched committed-state answers (see `Archive.resolve_many/3`).
  """
  def resolve_view(a, ops, deltas, committed \\ nil)
  def resolve_view(a, ops, [], committed), do: Archive.resolve_many(a, ops, committed)

  def resolve_view(a, ops, deltas, committed) do
    {known, rest} =
      ops
      |> Enum.uniq()
      |> Enum.reduce({%{}, []}, fn op, {k, r} ->
        case view_lookup(deltas, op) do
          :unknown -> {k, [op | r]}
          v -> {Map.put(k, op, v), r}
        end
      end)

    Archive.count_labeled(:view, map_size(known))
    Map.merge(known, Archive.resolve_many(a, rest, committed))
  end

  defp view_lookup([], _op), do: :unknown

  defp view_lookup([d | ds], {txid, _} = op) do
    case d.created do
      %{^op => coin} ->
        {:ok, coin}

      _ ->
        cond do
          MapSet.member?(d.spent, op) -> :missing
          MapSet.member?(d.txids, txid) -> :missing
          true -> view_lookup(ds, op)
        end
    end
  end

  # Core: BIP30 block in ConnectBlock. Public for the preparation engine,
  # which takes its result as a population fact.
  @doc false
  def bip30(a, view, block, entry, prev, p, idx, committed) do
    stat_timed(:perf_bip30_us, fn ->
      case bip30_ops(block, entry, prev, p, idx) do
        [] ->
          :ok

        ops ->
          stat(:bip30_blocks, 1)
          stat(:bip30_ops, length(ops))

          overwrite =
            Archive.labeled(:bip30, fn -> resolve_view(a, ops, view, committed) end)
            |> Enum.any?(fn {_, r} -> r != :missing end)

          if overwrite, do: {:error, {:consensus, "bad-txns-BIP30"}}, else: :ok
      end
    end)
  end

  # --- attribution (per block, never per input) --------------------------------

  @age_buckets [
    {1, :age_le_1},
    {10, :age_le_10},
    {100, :age_le_100},
    {1_000, :age_le_1k},
    {10_000, :age_le_10k}
  ]
  @stat_keys [:perf_bip30_us, :bip30_blocks, :bip30_ops, :inputs_missing, :age_gt_10k] ++
               Enum.map(@age_buckets, &elem(&1, 1))

  @doc false
  # Input answers of one block by prevout age (spending height - coin
  # height): `:missing` answers are counted apart (spends of the block's
  # own outputs, which have no external answer, or missing inputs).
  def count_ages(answers, height) do
    counts =
      Enum.reduce(answers, %{}, fn
        {_, {:ok, c}}, acc ->
          age = height - c.height
          k = Enum.find_value(@age_buckets, :age_gt_10k, fn {lim, k} -> if age <= lim, do: k end)
          Map.update(acc, k, 1, &(&1 + 1))

        {_, :missing}, acc ->
          Map.update(acc, :inputs_missing, 1, &(&1 + 1))
      end)

    Enum.each(counts, fn {k, n} -> stat(k, n) end)
  end

  @doc """
  Takes (and resets) this process's population counters: `perf_bip30_us`
  (BIP30 decision: ancestor, lookups), `bip30_blocks`, `bip30_ops`
  (outpoints looked up), `inputs_missing` and the input-answer prevout age
  histogram `age_le_1` .. `age_gt_10k`.
  """
  def take_stats, do: Map.new(@stat_keys, &{&1, Process.delete({__MODULE__, &1}) || 0})

  defp stat(k, n), do: Process.put({__MODULE__, k}, (Process.get({__MODULE__, k}) || 0) + n)

  defp stat_timed(k, f) do
    t = System.monotonic_time(:microsecond)
    r = f.()
    stat(k, System.monotonic_time(:microsecond) - t)
    r
  end

  @doc """
  The outpoints Core's BIP30 check looks up for `block` (every output of
  every tx), or `[]` where Core does not enforce it (`fEnforceBIP30` false
  and below `BIP34_IMPLIES_BIP30_LIMIT`). A block without outputs also
  gives `[]`, which passes as in Core.
  """
  # Core: ConnectBlock, fEnforceBIP30 / BIP34_IMPLIES_BIP30_LIMIT (validation.cpp)
  def bip30_ops(block, entry, prev, p, idx) do
    # Core: IsBIP30Repeat (height and hash; only matches on mainnet)
    repeat = Consensus.bip30_repeat?(entry.height, block.header.hash)

    bip34_anc = if prev, do: Index.ancestor(idx, prev, p.bip34_height), else: nil
    enforce = not repeat and not (bip34_anc != nil and bip34_anc.hash == p.bip34_hash)

    if enforce or entry.height >= @bip34_implies_bip30_limit,
      do: for(tx <- block.txs, o <- 0..(length(tx.outputs) - 1)//1, do: {tx.txid, o}),
      else: []
  end

  @doc "Every outpoint `connect_block/6` looks up for `block`: its inputs, then the BIP30 outputs."
  def lookup_ops(block, entry, prev, p, idx) do
    for(tx <- tl(block.txs), i <- tx.inputs, do: {i.prev_hash, i.prev_index}) ++
      bip30_ops(block, entry, prev, p, idx)
  end

  @doc "Core `GetBlockSubsidy(nHeight, params)`."
  # Core: GetBlockSubsidy (validation.cpp)
  def subsidy(height, %ChainParams{subsidy_halving_interval: interval}) do
    halvings = div(height, interval)
    if halvings >= 64, do: 0, else: (50 * Consensus.coin()) >>> halvings
  end
end
