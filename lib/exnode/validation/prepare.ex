defmodule Exnode.Validation.Prepare do
  @moduledoc """
  The non-script `ConnectBlock` (as `Exnode.Validation.Connect.connect_block/6`)
  split into two parts:

  * `populate/6`, the **owner** side (the chain state): every authoritative
    read, captured once as immutable facts. Input answers through the
    newest-first speculative deltas, the live overlay and batch, valid
    committed answers and fallback (`Connect.resolve_view/4`, explicit
    `:missing` included); the BIP30 decision (`Connect.bip30/8`, whose
    lookups and BIP34 ancestor are branch-bound); the parent's median time
    past and the MTPs the relative time locks can need; the flags, the
    reserved first output id and the subsidy.
  * `check/2`, the **pure** side: everything else, over the facts and the
    block only (no archive, ETS, file handle or call into another process):
    per tx `HaveInputs` (same-block outputs first, then the facts),
    `CheckTxInputs` (maturity, ranges, fees), accumulated fees, BIP68
    `SequenceLocks`, sigop cost, `UpdateCoins` with the reserved output ids,
    then the coinbase reward. It returns exactly what `connect_block/6`
    returns, failures in the same order. It never runs the kernel: scripts
    are `:defer` (jobs built for the executor) or `false` (assumevalid,
    every other check still runs); `scripts: true` is rejected.

  `Connect.connect_block/6` is unchanged and remains the reference.
  `test/exnode/validation/prepare_test.exs` compares the two over valid,
  invalid and dependency-heavy blocks.

  Rule placement: CheckBlock and
  ContextualCheckBlock stay with the owner before population; input and
  BIP30 population, the BIP34 ancestor and MTPs are owner reads captured
  here; same-block order, values, fees, reward, sigops, maturity, BIP68
  and output ids/deltas are computed by `check/2` from those facts.
  """
  import Bitwise

  alias Exnode.Archive
  alias Exnode.Chain.HeaderIndex, as: Index
  alias Exnode.Codec.Block
  alias Exnode.Consensus
  alias Exnode.Validation.{Connect, ScriptFlags}

  # primitives/transaction.h CTxIn
  @seq_disable 1 <<< 31
  @seq_type 1 <<< 22
  @seq_mask 0x0000FFFF
  @seq_granularity 9

  defmodule Facts do
    @moduledoc """
    Immutable population facts for one block (see `Exnode.Validation.Prepare`).
    `answers` maps every input outpoint to `{:ok, coin}` or `:missing`;
    `mtp` maps a height to the median time past of the candidate branch's
    block at that height (only the heights relative time locks can need).
    """
    defstruct [
      :hash,
      :height,
      :flags,
      :base_out,
      :scripts,
      :answers,
      :bip30,
      :csv,
      :prev_mtp,
      :mtp,
      :subsidy
    ]
  end

  @doc """
  Owner side: the facts `check/2` needs for `block` at `entry`, with the
  same options as `Connect.connect_block/6` (`view`, `committed`,
  `base_out`, `scripts`). Reads the archive, the speculative view and the
  header index; returns plain data.
  """
  def populate(
        %Archive{} = a,
        %Block{} = block,
        %Index.Entry{} = entry,
        p,
        %Index{} = idx,
        opts \\ []
      ) do
    height = entry.height
    prev = Index.prev(idx, entry)
    scripts = Keyword.get(opts, :scripts, true)
    view = Keyword.get(opts, :view, [])
    committed = Keyword.get(opts, :committed)

    base_out =
      Keyword.get_lazy(opts, :base_out, fn -> elem(Archive.base_ids(a, block.header.hash), 0) end)

    ops = for tx <- tl(block.txs), i <- tx.inputs, do: {i.prev_hash, i.prev_index}

    answers =
      timed(:perf_resolve_us, fn ->
        Archive.labeled(:inputs, fn -> Connect.resolve_view(a, ops, view, committed) end)
      end)

    Connect.count_ages(answers, height)
    bip30 = Connect.bip30(a, view, block, entry, prev, p, idx, committed)
    csv = height >= p.csv_height
    t_ctx = System.monotonic_time(:microsecond)
    prev_mtp = if prev, do: Index.median_time_past(idx, prev)
    mtp = if(csv, do: lock_mtps(block, entry, idx, answers), else: %{})

    Process.put(
      :perf_context_us,
      (Process.get(:perf_context_us) || 0) + System.monotonic_time(:microsecond) - t_ctx
    )

    %Facts{
      hash: block.header.hash,
      height: height,
      flags: ScriptFlags.block_flags(p, height, block.header.hash),
      base_out: base_out,
      scripts: scripts,
      answers: answers,
      bip30: bip30,
      csv: csv,
      prev_mtp: prev_mtp,
      mtp: mtp,
      subsidy: Connect.subsidy(height, p)
    }
  end

  # The MTPs a time-based relative lock can read: for every input with the
  # type flag (in a version >= 2 tx), the block at coin height - 1 on this
  # branch. A coin is either an external answer or created in this block
  # (height = the block's own), so both heights are covered.
  defp lock_mtps(block, entry, idx, answers) do
    heights =
      for tx <- tl(block.txs),
          tx.version >= 2,
          i <- tx.inputs,
          (i.sequence &&& @seq_disable) == 0,
          (i.sequence &&& @seq_type) != 0,
          h <- coin_heights(answers, {i.prev_hash, i.prev_index}, entry.height),
          into: MapSet.new(),
          do: max(h - 1, 0)

    Map.new(heights, fn h -> {h, Index.median_time_past(idx, Index.ancestor(idx, entry, h))} end)
  end

  defp coin_heights(answers, op, own) do
    case Map.get(answers, op) do
      {:ok, c} -> [c.height, own]
      _ -> [own]
    end
  end

  @doc """
  Pure side: `connect_block/6`'s result for `block` from `facts`.
  `{:ok, %{spent, fees, sigops, scripts_checked, checks, flags, n_outputs,
  delta}}` or `{:error, {:consensus, reason}}`, the first failure in Core's
  order.
  """
  def check(%Block{} = block, %Facts{scripts: scripts} = f) when scripts in [:defer, false] do
    with :ok <- f.bip30 do
      st = %{
        overlay: %{},
        spent_in_block: MapSet.new(),
        next_out: f.base_out,
        fees: 0,
        sigops: 0,
        spent: [],
        checks: [],
        prefetch: f.answers,
        prepare_checks: scripts != false
      }

      result =
        block.txs
        |> Enum.with_index()
        |> Enum.reduce_while({:ok, st}, fn {tx, pos}, {:ok, st} ->
          case check_tx(tx, pos, st, f) do
            {:ok, st} -> {:cont, {:ok, st}}
            {:error, _} = e -> {:halt, e}
          end
        end)

      with {:ok, st} <- result do
        reward = st.fees + f.subsidy
        value_out = Enum.reduce(hd(block.txs).outputs, 0, &(&2 + &1.value))

        if value_out > reward do
          {:error, {:consensus, "bad-cb-amount"}}
        else
          {:ok,
           %{
             spent: Enum.reverse(st.spent),
             fees: st.fees,
             sigops: st.sigops,
             scripts_checked: scripts != false,
             checks: if(scripts == :defer, do: st.checks, else: nil),
             flags: f.flags,
             n_outputs: st.next_out - f.base_out,
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

  # Connect.connect_tx over facts: same checks, same order.
  defp check_tx(tx, pos, st, f) do
    coinbase = pos == 0

    with {:ok, coins} <- if(coinbase, do: {:ok, []}, else: Connect.have_inputs(nil, tx, st)),
         {:ok, fee} <-
           if(coinbase, do: {:ok, 0}, else: Connect.check_tx_inputs(tx, coins, f.height)),
         fees = st.fees + fee,
         :ok <-
           if(Consensus.money_range?(fees),
             do: :ok,
             else: {:error, {:consensus, "bad-txns-accumulated-fee-outofrange"}}
           ),
         :ok <-
           if(coinbase or sequence_locks?(tx, coins, f),
             do: :ok,
             else: {:error, {:consensus, "bad-txns-nonfinal"}}
           ),
         sigops = st.sigops + Connect.sigop_cost(tx, coins, f.flags, coinbase),
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
       Connect.update_coins(tx, coins, coinbase, f.height, %{
         st
         | fees: fees,
           sigops: sigops,
           checks: checks
       })}
    end
  end

  # Connect.sequence_locks?/7 with the MTPs from the facts.
  defp sequence_locks?(tx, coins, f) do
    {min_height, min_time} =
      if tx.version >= 2 and f.csv do
        tx.inputs
        |> Enum.zip(coins)
        |> Enum.reduce({-1, -1}, fn {i, c}, {mh, mt} ->
          cond do
            (i.sequence &&& @seq_disable) != 0 ->
              {mh, mt}

            (i.sequence &&& @seq_type) != 0 ->
              coin_time = Map.fetch!(f.mtp, max(c.height - 1, 0))
              {mh, max(mt, coin_time + ((i.sequence &&& @seq_mask) <<< @seq_granularity) - 1)}

            true ->
              {max(mh, c.height + (i.sequence &&& @seq_mask) - 1), mt}
          end
        end)
      else
        {-1, -1}
      end

    if min_height == -1 and min_time == -1,
      do: true,
      else: not (min_height >= f.height or min_time >= f.prev_mtp)
  end

  @doc "Approximate retained bytes of `facts` (answers dominate), for admission."
  def facts_bytes(%Facts{answers: a, mtp: m}), do: 200 * map_size(a) + 32 * map_size(m) + 256

  defp timed(key, f) do
    t = System.monotonic_time(:microsecond)
    r = f.()
    Process.put(key, (Process.get(key) || 0) + System.monotonic_time(:microsecond) - t)
    r
  end
end
