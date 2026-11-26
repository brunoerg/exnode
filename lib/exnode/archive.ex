defmodule Exnode.Archive do
  @moduledoc """
  The archive is the store (rbitcoin architecture): headers, outputs, inputs,
  witnesses and spend records. Historical blocks are reconstructed from these
  parts. There is no separate UTXO database.

  Layout, key points:
  * block ids, output ids and input ids are monotonic in archive order
  * `spends`: `<<output_id::64>> => <<block_id::32, input_id::64>>`, so
    spent checks are one batched `multi_get` and rollback deletes a block's
    undo list
  * an output is unspent on the selected chain iff its block is on chain,
    it is not unspendable / overwritten (BIP30), and no spend record with an
    on-chain block exists
  * per commit: segments, then fsync, then one atomic KV batch that also
    advances the persisted tip. With `commit: false`, connected blocks
    accumulate in an in-memory batch (Core `CCoinsViewCache` role) and
    `flush/2` commits them together. Until then, reads see them through the
    batch maps and `Archive.Overlay`.

  Wire codecs live in `Exnode.Archive.Codec`; serving, undo, indexer and
  block-reconstruction queries live in `Exnode.Archive.Query` (re-exported
  here via `defdelegate`).

  This struct is owned by a single writer process (the chain state). The
  segment readers it holds are raw file handles of that process.
  """

  alias Exnode.Archive.{Codec, Overlay, Query, Segments}
  alias Exnode.Codec.{Block, Header}
  alias Exnode.Script
  alias Exnode.Store.KV

  @sparse 64

  # Witness pruning: `prune_keep` (blocks to keep, nil = off), `wpruned` (the
  # highest deleted witness segment) and `wseg_max` (segment => highest block
  # height with witness data in it). `wpruned_live` (atomics, shared with
  # every reader made from this archive) is the same prune point, raised
  # before the files are deleted: readers carry a copy of `wpruned` from
  # their commit, and a read racing a prune used to open a deleted file and
  # crash.
  # `committed_live` (atomics) is the committed tip's height, raised after a
  # commit's KV write and lowered before a disconnect touches the chain
  # tables. Readers get it as `visible`: the chain tables are shared and
  # also hold the uncommitted batch's blocks (above that height), which a
  # reader must not see (their records and spend rows are not in the KV).
  # `epoch` counts changes to the committed archive (each commit and each
  # disconnect): answers computed against the committed state (prefetch)
  # are valid only while it is unchanged.
  defstruct [
    :kv,
    :segs,
    :readers,
    :next,
    :tip,
    :chain,
    :onchain,
    :genesis_hash,
    :overlay,
    batch: nil,
    prune_keep: nil,
    wpruned: -1,
    wpruned_live: nil,
    committed_live: nil,
    visible: nil,
    wseg_max: %{},
    committed: nil,
    committed_next: nil,
    epoch: 0,
    # What the last commit changed in the committed state (see
    # `revalidate/4`): `%{from: epoch before it, txids: its batch's txindex
    # map, spent: MapSet of the output ids its blocks spent}`; nil after a
    # disconnect.
    last_commit: nil,
    overwritten: MapSet.new(),
    # Blocks at or above it are read back expecting their witness
    # commitment (Core DeploymentActiveAfter(SEGWIT)); 0: every block.
    segwit_height: 0
  ]

  # --- query & codec delegations -----------------------------------------------

  defdelegate tx_location(a, txid), to: Query
  defdelegate tx_location_in_block(a, txid, block_id), to: Query
  defdelegate output(a, txid, vout), to: Query
  defdelegate outputs(a, outpoints), to: Query
  defdelegate spenders(a, outpoints), to: Query
  defdelegate read_tx(a, txid), to: Query
  defdelegate read_tx_strict(a, id, pos), to: Query
  defdelegate spent_outputs(a, block_id), to: Query
  defdelegate spent_outputs_slice(a, rec, skip, count), to: Query
  defdelegate read_block_txs(a, id), to: Query
  defdelegate read_block_txs(a, id, rec), to: Query
  defdelegate block_scripts(a, id), to: Query
  defdelegate undo_outputs(a, rec), to: Query
  defdelegate read_index_facts(a, id), to: Query
  defdelegate read_index_facts(a, id, rec), to: Query
  defdelegate output_origin(a, out_id), to: Query
  defdelegate read_block(a, id), to: Query

  defdelegate decode_output(bin), to: Codec
  defdelegate decode_input(bin), to: Codec
  defdelegate decode_witness(bin), to: Codec

  @doc false
  defdelegate encode_txindex(list), to: Codec
  @doc false
  defdelegate decode_txindex(bin), to: Codec

  # The uncommitted batch: KV ops (reversed list of per-block op lists) and
  # the maps reads need before they are committed.
  defp empty_batch,
    do: %{
      ops: [],
      blocks: %{},
      blockhash: %{},
      txindex: %{},
      n: 0,
      bytes: 0,
      since: nil,
      reconnected: false
    }

  # --- open / recovery ---------------------------------------------------------

  @doc """
  Opens the archive. `hot` holds outputs; `cold` (defaults to `hot`) holds
  inputs and witness. Truncates segments to the last committed block and
  rebuilds the in-memory selected chain. A new archive gets `genesis`
  (a decoded block) as block 0.
  """
  def open(kv, hot, cold \\ nil, %Block{} = genesis, opts \\ []) do
    cold = cold || hot
    seg_opts = Keyword.take(opts, [:max])
    cache_bytes = Keyword.get(opts, :cache_bytes, 450 * 1024 * 1024)

    # An existing archive's committed segment ends are checked before any
    # segment file is opened (or created): a missing or short committed
    # segment is corruption, and fails here.
    meta =
      case KV.get(kv, :meta, "archive") do
        {:ok, bin} -> :erlang.binary_to_term(bin)
        :not_found -> nil
      end

    seg_opts_for = fn k ->
      if meta, do: [{:committed, Map.fetch!(meta.ends, k)} | seg_opts], else: seg_opts
    end

    segs = %{
      outputs: Segments.open(hot, :outputs, seg_opts_for.(:outputs)),
      inputs: Segments.open(cold, :inputs, seg_opts_for.(:inputs)),
      witness: Segments.open(cold, :witness, seg_opts_for.(:witness))
    }

    a = %__MODULE__{
      kv: kv,
      segs: segs,
      readers: %{
        outputs: Segments.open_reader(hot, :outputs),
        inputs: Segments.open_reader(cold, :inputs),
        witness: Segments.open_reader(cold, :witness)
      },
      chain: :ets.new(:archive_chain, [:set, :protected, read_concurrency: true]),
      onchain: :ets.new(:archive_onchain, [:set, :protected, read_concurrency: true]),
      genesis_hash: genesis.header.hash,
      overlay: Overlay.new(cache_bytes),
      batch: empty_batch(),
      prune_keep: Keyword.get(opts, :prune_keep),
      wpruned_live: :atomics.new(1, signed: true),
      committed_live: :atomics.new(1, signed: true),
      segwit_height: Keyword.get(opts, :segwit_height, 0)
    }

    :atomics.put(a.wpruned_live, 1, -1)
    :atomics.put(a.committed_live, 1, -1)

    case meta do
      nil ->
        a = %{a | next: %{block: 0, out: 0, inp: 0}, tip: nil}
        archive_genesis(a, genesis)

      %{next: next, ends: ends, tip: tip_id} ->
        segs = Map.new(a.segs, fn {k, s} -> {k, Segments.truncate_to(s, Map.fetch!(ends, k))} end)

        a = %{
          a
          | segs: segs,
            next: next,
            wpruned: Map.get(meta, :wpruned, -1),
            wseg_max: Map.get(meta, :wseg_max, %{}),
            overwritten: MapSet.new(Map.get(meta, :overwritten, []))
        }

        :atomics.put(a.wpruned_live, 1, a.wpruned)
        # A crash between recording a prune and deleting the files leaves them behind.
        for seg <- 0..a.wpruned//1, do: Segments.remove(a.segs.witness, seg)
        rebuild_chain(a, tip_id)
    end
  end

  defp rebuild_chain(a, tip_id) do
    rec = block_record!(a, tip_id)
    walk(a, tip_id, rec)
    sum_chain_tx(a, rec.height)
    tip = %{id: tip_id, height: rec.height, hash: rec.hash}
    :atomics.put(a.committed_live, 1, tip.height)
    %{a | tip: tip, committed: tip}
  end

  # From the tip down; each `chain` row first holds its block's tx count.
  defp walk(a, id, rec) do
    n_tx = Map.get_lazy(rec, :n_tx, fn -> length(rec.txs) end)
    :ets.insert(a.chain, {rec.height, id, n_tx})
    :ets.insert(a.onchain, {id, rec.height})
    if rec.prev_id != nil, do: walk(a, rec.prev_id, block_record!(a, rec.prev_id))
  end

  # Then from genesis up, the counts become running totals (chain_tx_count/2).
  defp sum_chain_tx(a, tip_height) do
    Enum.reduce(0..tip_height//1, 0, fn h, total ->
      total = total + :ets.lookup_element(a.chain, h, 3)
      :ets.update_element(a.chain, h, {3, total})
      total
    end)
  end

  defp archive_genesis(a, genesis) do
    # Core never adds the genesis coinbase to the UTXO set. Its txid is not
    # indexed, so its outputs can never be resolved or spent.
    {a, 0} = append(a, genesis, 0, nil, index_txs: false)
    a = %{a | batch: %{a.batch | n: 1}}

    a
    |> update_chain(%{id: 0, height: 0, hash: genesis.header.hash}, length(genesis.txs))
    |> flush()
  end

  def close(%__MODULE__{segs: segs, readers: rs} = a) do
    if a.batch.n > 0, do: raise("archive closed with #{a.batch.n} uncommitted blocks")
    Overlay.close(a.overlay)
    Enum.each(segs, fn {_, s} -> Segments.close(s) end)
    Enum.each(rs, fn {_, r} -> Segments.close_reader(r) end)
  end

  # --- chain queries -----------------------------------------------------------

  def tip(%__MODULE__{tip: t}), do: t

  def block_id(%__MODULE__{kv: kv, batch: batch}, hash) do
    case batch.blockhash do
      %{^hash => id} ->
        id

      _ ->
        case KV.get(kv, :blockhash, hash) do
          {:ok, <<id::32>>} -> id
          :not_found -> nil
        end
    end
  end

  def on_chain?(a, id), do: match?({:ok, _}, chain_height(a, id))

  # Single atomic ETS lookup returning `{:ok, height}` when `id` is on the
  # visible selected chain, or `:off_chain` (avoids TOCTOU between checking
  # membership and reading height while `disconnect_tip/1` mutates `onchain`).
  @doc false
  def chain_height(%__MODULE__{onchain: t, visible: v}, id) do
    case :ets.lookup(t, id) do
      [{_, h}] -> if visible?(v, h), do: {:ok, h}, else: :off_chain
      [] -> :off_chain
    end
  end

  def id_at(%__MODULE__{chain: t, visible: v}, height) do
    case :ets.lookup(t, height) do
      [{_, id, _}] -> if visible?(v, height), do: id
      [] -> nil
    end
  end

  # The row is read before the committed height: a row above it when read
  # can only fall at or below it later by being committed (a disconnect
  # commits the batch first), so an uncommitted block is never returned.
  defp visible?(nil, _height), do: true
  defp visible?(v, height), do: height <= :atomics.get(v, 1)

  @doc """
  Transactions in the selected chain from genesis to `height`, inclusive
  (Core `CBlockIndex::m_chain_tx_count`); nil above the tip.
  """
  def chain_tx_count(%__MODULE__{chain: t, visible: v}, height) do
    case :ets.lookup(t, height) do
      [{_, _, n}] -> if visible?(v, height), do: n
      [] -> nil
    end
  end

  def block_record!(%__MODULE__{kv: kv, batch: batch}, id) do
    case batch.blocks do
      %{^id => rec} ->
        rec

      _ ->
        case KV.get(kv, :blocks, <<id::32>>) do
          {:ok, bin} ->
            try do
              :erlang.binary_to_term(bin)
            rescue
              e in ArgumentError ->
                raise Exnode.StorageError,
                  source: :archive,
                  reason: {:corrupt_block_record, id, e},
                  message: "corrupt block record #{id}"
            end

          :not_found ->
            raise Exnode.StorageError,
              source: :archive,
              reason: {:missing_block_record, id},
              message: "missing block record #{id}"
        end
    end
  end

  @doc "Transaction count from block metadata, including witness-pruned blocks."
  def block_tx_count(a, hash) do
    case KV.get(a.kv, :meta, "ntx" <> hash) do
      {:ok, <<n::32>>} ->
        n

      :not_found ->
        # Compatible with archives written before the small count record.
        # Even that fallback reads metadata only, never block segments.
        case block_id(a, hash) do
          nil ->
            0

          id ->
            rec = block_record!(a, id)
            Map.get_lazy(rec, :n_tx, fn -> length(rec.txs) end)
        end
    end
  end

  @doc """
  A read-only view for other processes (block serving): KV, segment
  readers, the selected-chain ETS tables and the witness prune point; no
  batch and no writers. Only committed blocks are visible.
  """
  def reader(%__MODULE__{} = a),
    do: %__MODULE__{
      kv: a.kv,
      readers: a.readers,
      chain: a.chain,
      onchain: a.onchain,
      genesis_hash: a.genesis_hash,
      wpruned: a.wpruned,
      wpruned_live: a.wpruned_live,
      visible: a.committed_live,
      batch: empty_batch(),
      tip: a.committed || a.tip,
      next: a.committed_next || a.next,
      epoch: a.epoch,
      overwritten: a.overwritten,
      segwit_height: a.segwit_height
    }

  @doc """
  Only the store and the epoch of `a`: enough for `prepare_append/7` to read
  committed txindex rows (and small to send to another process).
  """
  def kv_reader(%__MODULE__{kv: kv, epoch: e}), do: %__MODULE__{kv: kv, epoch: e}

  @doc "The committed-state epoch (see the struct): bumped by every commit and disconnect."
  def epoch(%__MODULE__{epoch: e}), do: e

  @doc "Next ids the archive will assign: `%{block, out, inp}`."
  def next_ids(%__MODULE__{next: n}), do: n

  @doc """
  True when every archived block is on the selected chain (`next.block == tip.height + 1`),
  so no off-chain (disconnected) block exists in `:txindex`. Works on both the
  owner `%Archive{}` and a `reader/1`.
  """
  def linear?(%__MODULE__{tip: %{height: h}, next: %{block: n}}), do: n == h + 1
  def linear?(%__MODULE__{}), do: false

  @doc "Uncommitted blocks in the batch: `{count, raw bytes}`."
  def batch_size(%__MODULE__{batch: b}), do: {b.n, b.bytes}

  @doc "Monotonic time (ms) the oldest uncommitted block was connected, or nil."
  def batch_since(%__MODULE__{batch: b}), do: b.since

  @doc "Base ids the block would get (or already has) in the archive: `{base_out, base_in}`."
  def base_ids(%__MODULE__{} = a, hash) do
    case block_id(a, hash) do
      nil -> {a.next.out, a.next.inp}
      id -> (fn r -> {r.base_out, r.base_in} end).(block_record!(a, id))
    end
  end

  # --- outpoint resolution -----------------------------------------------------

  @doc """
  Resolves `{txid, vout}` against the selected chain. Returns
  `{:ok, coin}` or `:missing` (unknown, overwritten, unspendable or spent).
  `coin`: `%{output_id, value, script_pubkey, height, coinbase}`.

  Reference path: reads the committed archive only (no overlay), so it
  requires an empty batch. `resolve_many/2` is the fast path.
  """
  def resolve(%__MODULE__{batch: %{n: n}}, _txid, _vout) when n > 0,
    do: raise("resolve/3 with an uncommitted batch")

  def resolve(%__MODULE__{} = a, txid, vout) do
    with {:ok, entry} <- newest_on_chain_entry(a, txid),
         {block_id, pos, base_out, nout, _base_in} = entry,
         true <- (vout >= 0 and vout < nout) || :missing,
         out_id = base_out + vout,
         false <- spent_on_chain?(a, out_id) do
      {value, spk} = read_output(a, out_id)

      if Script.unspendable?(spk) do
        :missing
      else
        [{_, height}] = :ets.lookup(a.onchain, block_id)

        {:ok,
         %{
           output_id: out_id,
           value: value,
           script_pubkey: spk,
           height: height,
           coinbase: pos == 0
         }}
      end
    else
      _ -> :missing
    end
  end

  @doc """
  Batched `resolve/3` for a block's worth of outpoints, with the same
  semantics. The overlay answers first: cached and uncommitted coins, and
  outpoints spent by uncommitted blocks. An outpoint of a txid the batch
  archived is decided by the overlay alone (the newest txindex entry is in
  the batch). The rest is one `multi_get` for the txindex, one iterator for
  all spent checks, and output reads grouped by sparse-index location.
  Returns `%{{txid, vout} => {:ok, coin} | :missing}`.

  `committed`, if given, holds answers `committed_answers/2` computed against
  this archive's committed state in the same epoch (the caller checks it).
  They replace the committed lookups; the overlay and the batch still
  answer first, so uncommitted blocks are seen exactly as without them.
  """
  def resolve_many(%__MODULE__{} = a, outpoints, committed \\ nil) do
    {known, rest} =
      outpoints
      |> Enum.uniq()
      |> Enum.reduce({%{}, []}, fn {txid, _} = op, {known, rest} ->
        case Overlay.lookup(a.overlay, op) do
          {:ok, coin} -> {Map.put(known, op, {:ok, coin}), rest}
          :spent -> {Map.put(known, op, :missing), rest}
          :unknown when is_map_key(a.batch.txindex, txid) -> {Map.put(known, op, :missing), rest}
          :unknown -> {known, [op | rest]}
        end
      end)

    {given, missing} =
      case committed do
        nil ->
          {%{}, rest}

        c ->
          Enum.reduce(rest, {%{}, []}, fn op, {g, m} ->
            if is_map_key(c, op), do: {Map.put(g, op, c[op]), m}, else: {g, [op | m]}
          end)
      end

    if label = Process.get({__MODULE__, :label}) do
      count({label, :overlay}, map_size(known))
      count({label, :given}, map_size(given))
      count({label, :lookup}, length(missing))
    end

    known |> Map.merge(given) |> Map.merge(resolve_committed(a, missing))
  end

  @doc """
  Runs `fun` with resolution counters labelled `label` (`:inputs` or
  `:bip30`): `resolve_many/3` then counts, per label, outpoints answered by
  the overlay or batch (`overlay`), by prefetched committed answers
  (`given`) and by this process's committed lookups (`lookup`); the
  output-read groups of those lookups go to `<label>_output_groups`.
  """
  def labeled(label, fun) when label in [:inputs, :bip30] do
    prev = Process.put({__MODULE__, :label}, label)

    try do
      fun.()
    after
      if prev,
        do: Process.put({__MODULE__, :label}, prev),
        else: Process.delete({__MODULE__, :label})
    end
  end

  @doc false
  # Adds `n` to this process's labelled counter (Connect: `view` answers).
  def count_labeled(kind, n) when kind in [:view] do
    if label = Process.get({__MODULE__, :label}), do: count({label, kind}, n)
    :ok
  end

  @doc """
  The committed-state part of `resolve_many/3` for `outpoints`: what the
  committed archive alone says (txindex, spend records, outputs), ignoring
  the overlay and batch. Read-only; any process may call it on a `reader/1`
  (prefetch). Valid for `resolve_many/3` only in the same `epoch/1`.
  """
  def committed_answers(%__MODULE__{} = a, outpoints),
    do: resolve_committed(a, Enum.uniq(outpoints))

  @doc """
  `committed_answers/2` for the prefetch workers, with an advisory I/O
  filter. Outpoints are deduplicated, then those the overlay `hint`
  (`overlay_hint/1`) answers now are omitted: `resolve_many/3` asks the
  overlay first, so their committed answers would not be used. An omitted
  outpoint is **absent** from the returned map (never `:missing`), and no
  overlay answer is ever put in it, so it stays a committed-only map. `hint`
  nil omits nothing. Returns `{answers, %{considered, omitted, sent}}`.
  """
  def prefetch_answers(%__MODULE__{} = a, outpoints, hint) do
    a = live_chain(a)
    ops = Enum.uniq(outpoints)
    sent = if hint, do: Enum.reject(ops, &Overlay.answerable?(hint, &1)), else: ops
    n = length(ops)
    s = length(sent)
    {resolve_committed(a, sent), %{considered: n, omitted: n - s, sent: s}}
  end

  @doc """
  `prefetch_answers/3` plus the committed txindex rows of `txids` (a
  block's own txids) for `connect/5`'s `:history`: `{answers, stats,
  history}`. One `multi_get` reads the rows of the answers' txids and of
  `txids` together.
  """
  def prefetch_block(%__MODULE__{} = a, outpoints, hint, txids) do
    a = live_chain(a)
    ops = Enum.uniq(outpoints)
    sent = if hint, do: Enum.reject(ops, &Overlay.answerable?(hint, &1)), else: ops
    n = length(ops)
    s = length(sent)
    lookup = sent |> Enum.map(&elem(&1, 0)) |> Enum.sort() |> Enum.dedup()

    {txids_list, all, history} =
      if txids == :unique do
        rows = Map.new(Enum.zip(lookup, KV.multi_get(a.kv, :txindex, lookup)))
        {[], lookup, {:unique, rows}}
      else
        txids_list = txids |> Enum.sort() |> Enum.dedup()
        all = (lookup ++ txids_list) |> Enum.sort() |> Enum.dedup()
        rows = Map.new(Enum.zip(all, KV.multi_get(a.kv, :txindex, all)))
        {txids_list, all, {%{epoch: a.epoch, rows: Map.take(rows, txids_list)}, rows}}
      end

    {hist, rows} = history

    {resolve_committed(a, sent, rows),
     %{
       considered: n,
       omitted: n - s,
       sent: s,
       history_rows: length(txids_list),
       history_extra: length(all) - length(lookup)
     }, hist}
  end

  # The prefetch answers stand in for the chain-state process's own
  # committed lookups, which see the whole chain table (the batch's blocks
  # included), so they read it unbounded too.
  defp live_chain(a), do: %{a | visible: nil}

  @doc """
  Carries `prefetch_block/4` results computed at `epoch` over the one
  commit since, instead of discarding them: `{:ok, answers, history,
  dropped}` valid at the current epoch, or `:stale`.
  """
  def revalidate(%__MODULE__{epoch: cur, last_commit: lc} = a, epoch, answers, history) do
    case lc do
      %{from: ^epoch, txids: txids, spent: spent} when cur == epoch + 1 ->
        kept =
          :maps.filter(
            fn
              {txid, _}, _ when is_map_key(txids, txid) -> false
              _, {:ok, %{output_id: id}} -> not MapSet.member?(spent, id)
              _, _ -> true
            end,
            answers
          )

        history =
          case history do
            :unique ->
              if linear?(a), do: :unique, else: nil

            %{rows: rows} ->
              if Enum.any?(Map.keys(rows), &is_map_key(txids, &1)),
                do: nil,
                else: %{history | epoch: cur}

            nil ->
              nil
          end

        {:ok, kept, history, map_size(answers) - map_size(kept)}

      _ ->
        :stale
    end
  end

  @doc "The overlay's read-only hint for `prefetch_answers/3` (nil without an overlay, as on a `reader/1`)."
  def overlay_hint(%__MODULE__{overlay: nil}), do: nil
  def overlay_hint(%__MODULE__{overlay: ov}), do: Overlay.hint(ov)

  # Commit latency histogram (whole flush, sync included): counts per
  # upper bound in ms.
  @commit_buckets [
    {4, :commit_le_4ms},
    {16, :commit_le_16ms},
    {64, :commit_le_64ms},
    {256, :commit_le_256ms},
    {1024, :commit_le_1s}
  ]

  @plain_counters [
    :committed_ops,
    :output_groups,
    :commits,
    :commit_blocks,
    :commit_sync_us,
    :commit_materialize_us,
    :commit_last_us,
    :commit_kv_us,
    :commit_us,
    :append_encode_us,
    :append_segments_us,
    :append_txindex_us,
    :append_overwritten_us,
    :append_record_us,
    :append_ops,
    :append_repeated,
    :append_prepared,
    :append_prepared_mismatch,
    :txindex_reads,
    :txindex_read_us,
    :txindex_found,
    :txindex_reused,
    :txindex_skipped,
    :txindex_hint_stale,
    :append_tx_ops_us,
    :append_spend_ops_us,
    :append_ops_list_us,
    :append_batch_us,
    :connect_us,
    :connect_lookup_us,
    :connect_overlay_us,
    :connect_chain_us,
    :commit_overlay_us,
    :commit_prune_us,
    :facts_blocks,
    :facts_read_us,
    :facts_txid_us,
    :facts_merkle_us
  ]

  @doc """
  Takes (and resets) this process's archive work counters.
  """
  def take_stats do
    seg = Segments.take_stats()

    labeled =
      for l <- [:inputs, :bip30],
          k <- [:view, :overlay, :given, :lookup, :output_groups],
          into: %{},
          do: {:"#{l}_#{k}", pop_count({l, k})}

    plain =
      Map.new(
        @plain_counters ++ Enum.map(@commit_buckets, &elem(&1, 1)) ++ [:commit_gt_1s],
        &{&1, pop_count(&1)}
      )

    seg
    |> Map.merge(KV.take_stats())
    |> Map.merge(Overlay.take_stats())
    |> Map.merge(labeled)
    |> Map.merge(plain)
  end

  @doc false
  def bump_stat(key, n), do: count(key, n)

  defp count(key, n),
    do: Process.put({__MODULE__, key}, (Process.get({__MODULE__, key}) || 0) + n)

  defp pop_count(key), do: Process.delete({__MODULE__, key}) || 0

  # `rows`: the txindex rows of the outpoints' txids, already read (or nil).
  defp resolve_committed(a, outpoints, rows \\ nil)
  defp resolve_committed(_a, [], _rows), do: %{}

  defp resolve_committed(a, outpoints, rows) do
    count(:committed_ops, length(outpoints))
    txids = outpoints |> Enum.map(&elem(&1, 0)) |> Enum.sort() |> Enum.dedup()

    read =
      if rows,
        do: Enum.map(txids, &Map.fetch!(rows, &1)),
        else: KV.multi_get(a.kv, :txindex, txids)

    entries =
      txids
      |> Enum.zip(read)
      |> Map.new(fn {t, r} -> {t, newest_on_chain_with_height(a, r)} end)

    # outpoint -> {out_id, block_id, pos, height}
    candidates =
      for {t, v} = op <- outpoints,
          {height, {block_id, pos, base_out, nout, _}} <- List.wrap(entries[t]),
          v >= 0 and v < nout,
          into: %{},
          do: {op, {base_out + v, block_id, pos, height}}

    spent = spent_many(a, candidates |> Map.values() |> Enum.map(&elem(&1, 0)))

    live =
      for {op, {id, _, _, _} = c} <- candidates,
          not MapSet.member?(spent, id),
          into: %{},
          do: {op, c}

    outputs = read_outputs(a, live |> Map.values() |> Enum.map(&elem(&1, 0)))

    Map.new(outpoints, fn op ->
      with {id, _block_id, pos, height} <- live[op],
           {value, spk} = Map.fetch!(outputs, id),
           false <- Script.unspendable?(spk) do
        {op,
         {:ok,
          %{output_id: id, value: value, script_pubkey: spk, height: height, coinbase: pos == 0}}}
      else
        _ -> {op, :missing}
      end
    end)
  end

  @doc false
  def newest_on_chain(_a, :not_found), do: nil

  def newest_on_chain(a, {:ok, bin}) do
    case newest_on_chain_with_height(a, {:ok, bin}) do
      nil -> nil
      {_h, e} -> e
    end
  end

  defp newest_on_chain_with_height(_a, :not_found), do: nil

  defp newest_on_chain_with_height(a, {:ok, bin}) do
    on =
      for {b, _, _, _, _} = e <- Codec.decode_txindex(bin),
          {:ok, h} <- [chain_height(a, b)],
          do: {h, e}

    case on do
      [] -> nil
      _ -> Enum.max_by(on, &elem(&1, 0))
    end
  end

  @doc "Output ids (of `ids`) that have a spend record in an on-chain block. Uses a single `multi_get`."
  def spent_many(_a, []), do: MapSet.new()

  def spent_many(a, ids) do
    u = ids |> Enum.sort() |> Enum.dedup()
    keys = for id <- u, do: <<id::64>>
    base = MapSet.intersection(a.overwritten, MapSet.new(u))

    u
    |> Enum.zip(KV.multi_get(a.kv, :spends, keys))
    |> Enum.reduce(base, fn
      {id, {:ok, <<b::32, _::64>>}}, acc ->
        if on_chain?(a, b), do: MapSet.put(acc, id), else: acc

      {_, :not_found}, acc ->
        acc
    end)
  end

  # Reads outputs grouped by their sparse-index base: one pread run per group,
  # the groups in physical order ({segment, offset} ascending) for locality.
  @doc false
  def read_outputs(_a, []), do: %{}

  def read_outputs(a, ids) do
    groups = ids |> Enum.uniq() |> Enum.group_by(&div(&1, @sparse))
    bases = Map.keys(groups)
    count(:output_groups, length(bases))

    if label = Process.get({__MODULE__, :label}),
      do: count({label, :output_groups}, length(bases))

    located =
      bases
      |> Enum.zip(KV.multi_get(a.kv, :locs, Enum.map(bases, &Codec.loc_key(:outputs, &1))))
      |> Enum.map(fn {base, {:ok, bin}} -> {Codec.unpack_loc(bin), base} end)
      |> Enum.sort()

    Enum.reduce(located, %{}, fn {loc, base}, acc ->
      gids = Map.fetch!(groups, base)
      lo = Enum.min(gids) - base * @sparse
      hi = Enum.max(gids) - base * @sparse
      # ~40 bytes per output record; start small, read_run grows the chunk if needed.
      chunk = max(1024, (hi + 1) * 64)

      recs =
        Segments.read_run(
          a.readers.outputs,
          loc,
          lo,
          hi - lo + 1,
          &Codec.decode_output/1,
          chunk
        )

      recs_by_id =
        recs |> Enum.with_index(base * @sparse + lo) |> Map.new(fn {r, i} -> {i, r} end)

      Enum.reduce(gids, acc, &Map.put(&2, &1, Map.fetch!(recs_by_id, &1)))
    end)
  end

  # BIP30 overwrite semantics: the newest on-chain entry of a txid wins.
  defp newest_on_chain_entry(a, txid) do
    case KV.get(a.kv, :txindex, txid) do
      :not_found ->
        :missing

      {:ok, bin} ->
        on =
          for {b, _, _, _, _} = e <- Codec.decode_txindex(bin),
              {:ok, h} <- [chain_height(a, b)],
              do: {h, e}

        case on do
          [] -> :missing
          _ -> {:ok, on |> Enum.max_by(&elem(&1, 0)) |> elem(1)}
        end
    end
  end

  @doc "True if a spend record of `out_id` belongs to a block on the selected chain."
  def spent_on_chain?(a, out_id) do
    MapSet.member?(a.overwritten, out_id) or
      case KV.get(a.kv, :spends, <<out_id::64>>) do
        {:ok, <<b::32, _::64>>} -> on_chain?(a, b)
        :not_found -> false
      end
  end

  @doc "Reads output `id`: `{value, script_pubkey}`."
  def read_output(a, id), do: read_record(a, :outputs, id, &Codec.decode_output/1)

  defp read_record(a, kind, id, decode) do
    {:ok, bin} = KV.get(a.kv, :locs, Codec.loc_key(kind, div(id, @sparse)))
    Segments.read_nth(a.readers[kind], Codec.unpack_loc(bin), rem(id, @sparse), decode)
  end

  @doc false
  def read_records(a, kind, first, count, decode) do
    if count == 0 do
      []
    else
      {:ok, bin} = KV.get(a.kv, :locs, Codec.loc_key(kind, div(first, @sparse)))

      Segments.read_run(
        a.readers[kind],
        Codec.unpack_loc(bin),
        rem(first, @sparse),
        count,
        decode
      )
    end
  end

  # --- connect / disconnect ----------------------------------------------------

  @doc """
  Connects `block` at the tip. `spent` lists, in block input order, the
  output id each non-coinbase input spends (from `resolve_many/2`, or an
  output of an earlier tx in the same block).

  New blocks are archived (segments, KV entries). Blocks archived before
  (disconnected by a reorg) only get their spend records and the tip
  rewritten.
  """
  def connect(%__MODULE__{} = a, %Block{} = block, height, spent, opts \\ []) do
    t0 = System.monotonic_time(:microsecond)
    known = block_id(a, block.header.hash)
    count(:connect_lookup_us, System.monotonic_time(:microsecond) - t0)

    prepared =
      case {known, opts[:prepared]} do
        {nil, %{} = p} ->
          p = usable_prepared(a, block, height, p)
          count(if(p, do: :append_prepared, else: :append_prepared_mismatch), 1)
          p

        _ ->
          nil
      end

    {a, id} =
      case known do
        nil ->
          append(a, block, height, spent,
            index_txs: true,
            history: opts[:history],
            prepared: prepared,
            unique_txids: opts[:unique_txids]
          )

        id ->
          # Core AddCoins adds these outputs anew. Any earlier destruction
          # mark for this exact occurrence no longer applies on reconnect.
          rec = block_record!(a, id)

          ops_to_check =
            for tx <- block.txs, v <- 0..(length(tx.outputs) - 1)//1, do: {tx.txid, v}

          rec = Map.merge(rec, %{undo: spent, overwritten: overwritten_outputs(a, ops_to_check)})

          ops = [
            {:put, :blocks, <<id::32>>, :erlang.term_to_binary(rec)}
            | spend_ops(id, rec.base_in, block, spent)
          ]

          count = Enum.reduce(rec.txs, 0, fn {_, _, _, n, _}, acc -> acc + n end)

          marks =
            MapSet.reject(a.overwritten, &(&1 >= rec.base_out and &1 < rec.base_out + count))

          a = add_to_batch(%{a | overwritten: marks}, id, rec, ops, %{}, nil)
          # Its txids go on chain again without batch txindex lists: the
          # commit's effect is not what `revalidate/4` checks.
          {put_in(a.batch.reconnected, true), id}
      end

    t1 = System.monotonic_time(:microsecond)

    a =
      case opts[:delta] do
        %{created: created, spent: sp} ->
          case prepared do
            %{overlay: %{gen: ^id} = rows} ->
              %{a | overlay: Overlay.apply_prepared(a.overlay, rows)}

            _ ->
              %{a | overlay: Overlay.apply_block(a.overlay, id, created, sp)}
          end

        nil ->
          # Uncommitted spends must stay masked, so batching needs the delta.
          if opts[:commit] == false,
            do: raise(ArgumentError, "connect with commit: false needs :delta")

          %{a | overlay: Overlay.clear(a.overlay)}
      end

    t2 = System.monotonic_time(:microsecond)

    a = %{
      a
      | batch: %{
          a.batch
          | n: a.batch.n + 1,
            bytes: a.batch.bytes + byte_size(block.raw || <<>>),
            since: a.batch.since || System.monotonic_time(:millisecond)
        }
    }

    a = update_chain(a, %{id: id, height: height, hash: block.header.hash}, length(block.txs))
    t3 = System.monotonic_time(:microsecond)
    count(:connect_overlay_us, t2 - t1)
    count(:connect_chain_us, t3 - t2)
    count(:connect_us, t3 - t0)
    if Keyword.get(opts, :commit, true), do: flush(a), else: a
  end

  @doc """
  Commits the batch: fsync segments, then one atomic KV batch with every
  block's entries, `extra_ops` (e.g. deleting their `pending` copies) and the
  persisted tip. A no-op when the batch is empty and `extra_ops` is `[]`.
  """
  def flush(a, extra_ops \\ [])
  def flush(%__MODULE__{batch: %{n: 0}} = a, []), do: a

  def flush(%__MODULE__{} = a, extra_ops) do
    t0 = System.monotonic_time(:microsecond)
    Enum.each(a.segs, fn {_, s} -> :ok = Segments.sync(s) end)
    t1 = System.monotonic_time(:microsecond)
    ops = a.batch.ops |> Enum.reverse() |> Enum.concat()
    ops = with_meta(a, ops ++ extra_ops)
    tm = System.monotonic_time(:microsecond)
    # Key-ordered `spends` and `txindex` runs: an IBD commit's millions of
    # rows insert into the memtable several times faster (Store.PackedSort).
    :ok = KV.write(a.kv, ops, sync: true, stats: true, sort_packed: true)
    :atomics.put(a.committed_live, 1, a.tip.height)
    t2 = System.monotonic_time(:microsecond)
    count(:commit_blocks, a.batch.n)
    count(:commit_materialize_us, tm - t1)
    count(commit_bucket(t2 - t0), 1)

    t_lc = System.monotonic_time(:microsecond)

    last_commit =
      if a.batch.reconnected,
        do: nil,
        else: %{
          from: a.epoch,
          txids: a.batch.txindex,
          spent: MapSet.new(for {_, rec} <- a.batch.blocks, id <- rec.undo, do: id)
        }

    count(:commit_last_us, System.monotonic_time(:microsecond) - t_lc)

    a = %{
      a
      | batch: empty_batch(),
        overlay: Overlay.committed(a.overlay, a.next.block - 1),
        committed: a.tip,
        committed_next: a.next,
        epoch: a.epoch + 1,
        last_commit: last_commit
    }

    t3 = System.monotonic_time(:microsecond)
    a = prune_witness(a)
    count(:commit_overlay_us, t3 - t2)
    count(:commit_prune_us, System.monotonic_time(:microsecond) - t3)
    count(:commits, 1)
    count(:commit_sync_us, t1 - t0)
    count(:commit_kv_us, t2 - t1)
    count(:commit_us, System.monotonic_time(:microsecond) - t0)
    a
  end

  @doc "The durable tip `%{id, height, hash}` (equals `tip/1` when the batch is empty)."
  def committed_tip(%__MODULE__{committed: c, tip: t}), do: c || t

  defp write_with_meta(a, ops), do: :ok = KV.write(a.kv, with_meta(a, ops), sync: true)

  # `ops` then the archive meta (segment ends, next ids, tip), last.
  defp with_meta(a, ops) do
    ends = Map.new(a.segs, fn {k, s} -> {k, Segments.position(s)} end)

    meta =
      :erlang.term_to_binary(%{
        next: a.next,
        ends: ends,
        tip: a.tip.id,
        wpruned: a.wpruned,
        wseg_max: a.wseg_max,
        overwritten: MapSet.to_list(a.overwritten)
      })

    ops ++ [{:put, :meta, "archive", meta}]
  end

  defp commit_bucket(us) do
    ms = div(us, 1000)
    Enum.find_value(@commit_buckets, :commit_gt_1s, fn {lim, k} -> if ms <= lim, do: k end)
  end

  @doc "Disconnects the tip block (commits the batch first). Returns `{archive, block_id}`."
  def disconnect_tip(%__MODULE__{tip: %{height: h}} = a) when h > 0 do
    a = flush(a)
    %{id: id} = a.tip
    rec = block_record!(a, id)
    ops = for out_id <- Enum.uniq(rec.undo), do: {:delete, :spends, <<out_id::64>>}
    # Core AddCoin overwrites without undoing the old coin; DisconnectBlock
    # removes the new occurrence but NEVER restores the overwritten one.
    lost = Map.get_lazy(rec, :overwritten, fn -> legacy_overwritten(a, rec) end)
    a = %{a | overwritten: MapSet.union(a.overwritten, MapSet.new(lost))}
    prev = block_record!(a, rec.prev_id)
    :atomics.put(a.committed_live, 1, prev.height)

    a =
      update_chain(%{a | overlay: Overlay.clear(a.overlay)}, %{
        id: rec.prev_id,
        height: prev.height,
        hash: prev.hash
      })

    write_with_meta(a, ops)
    {%{a | committed: a.tip, epoch: a.epoch + 1, last_commit: nil}, id}
  end

  # Only actual live coins are destroyed. A BIP30-allowed duplicate whose
  # earlier occurrence is already spent must not poison future input undo.
  defp overwritten_outputs(_a, []), do: []

  defp overwritten_outputs(a, ops) do
    for {_op, {:ok, coin}} <- resolve_many(a, ops), do: coin.output_id
  end

  # Archives made before recording per-block overwrites still contain the
  # two historical exceptions. Recover their lost coins lazily if a reorg
  # ever disconnects them (Core IsBIP30Repeat / DisconnectBlock).
  defp legacy_overwritten(a, rec) do
    if Exnode.Consensus.bip30_repeat?(rec.height, rec.hash) do
      {:ok, block} = Query.read_block_txs(a, a.tip.id)
      cb = hd(block.txs)
      {:ok, bin} = KV.get(a.kv, :txindex, cb.txid)
      previous = Codec.decode_txindex(bin) |> Enum.reject(&(elem(&1, 0) == a.tip.id))

      case newest_on_chain(a, {:ok, Codec.encode_txindex(previous)}) do
        nil ->
          []

        {_, _, base, n, _} ->
          for v <- 0..(min(n, length(cb.outputs)) - 1)//1,
              not spent_on_chain?(a, base + v),
              {_value, spk} = read_output(a, base + v),
              not Script.unspendable?(spk),
              do: base + v
      end
    else
      []
    end
  end

  defp add_to_batch(a, id, rec, ops, txindex, hash) do
    b = a.batch

    b = %{
      b
      | ops: [ops | b.ops],
        blocks: Map.put(b.blocks, id, rec),
        txindex: Map.merge(b.txindex, txindex)
    }

    b = if hash, do: %{b | blockhash: Map.put(b.blockhash, hash, id)}, else: b
    %{a | batch: b}
  end

  @doc """
  The part of archiving a new block that depends only on the block, its
  `spent` output ids, its ids (`%{block: id, out: base_out, inp: base_in}`,
  as `next_ids/1` will return just before it is connected) and, optionally,
  its connect `delta`: segment records and their layout, tx metadata, the
  block's own txindex occurrences, its spend records and its overlay rows.
  """
  def prepare_append(
        %Block{} = block,
        height,
        spent,
        ids,
        delta \\ nil,
        reader \\ nil,
        history \\ nil
      ) do
    t0 = System.monotonic_time(:microsecond)
    p = encode_append(block, height, spent, ids)

    p =
      case delta do
        %{created: created, spent: sp} ->
          Map.put(p, :overlay, Overlay.prepare_block(ids.block, created, sp))

        nil ->
          p
      end

    p =
      case {reader, history} do
        {_, :unique} ->
          Map.put(p, :history, :unique)

        {nil, _} ->
          Map.put(p, :history, history)

        {%__MODULE__{epoch: e}, %{epoch: e}} ->
          Map.put(p, :history, history)

        {r, _} ->
          txids = Map.keys(p.own)
          rows = Map.new(Enum.zip(txids, KV.multi_get(r.kv, :txindex, txids)))
          Map.put(p, :history, %{epoch: r.epoch, rows: rows})
      end

    # Records as one binary each: sent between processes by reference.
    segs =
      Map.new(p.segs, fn {k, {recs, rel, total}} ->
        {k, {IO.iodata_to_binary(recs), rel, total}}
      end)

    Map.merge(p, %{segs: segs, prepare_us: System.monotonic_time(:microsecond) - t0})
  end

  # Encoding shared by both paths of append/5.
  defp encode_append(
         %Block{} = block,
         height,
         spent,
         %{block: id, out: base_out, inp: base_in} = ids
       ) do
    out_recs = for tx <- block.txs, o <- tx.outputs, do: Codec.encode_output(o)
    in_recs = for tx <- block.txs, i <- tx.inputs, do: Codec.encode_input(i)
    wit_recs = for tx <- block.txs, i <- tx.inputs, do: Codec.encode_witness(i.witness)

    {tx_meta, {_, _}} =
      Enum.map_reduce(block.txs, {base_out, base_in}, fn tx, {o, i} ->
        {{tx.version, tx.locktime, length(tx.inputs), length(tx.outputs), tx.has_witness},
         {o + length(tx.outputs), i + length(tx.inputs)}}
      end)

    %{
      ids: ids,
      hash: block.header.hash,
      height: height,
      segs: %{
        outputs: Segments.layout(out_recs, base_out, @sparse),
        inputs: Segments.layout(in_recs, base_in, @sparse),
        witness: Segments.layout(wit_recs, base_in, @sparse)
      },
      nouts: length(out_recs),
      nins: length(in_recs),
      tx_meta: tx_meta,
      own: own_txindex(id, block, base_out, base_in),
      spend: if(spent, do: spend_ops(id, base_in, block, spent), else: [])
    }
  end

  # A `prepare_append/7` result for this exact block, height and ids.
  defp usable_prepared(a, block, height, %{ids: ids, hash: hash, height: height} = p) do
    if ids == a.next and hash == block.header.hash, do: p
  end

  defp usable_prepared(_a, _block, _height, _p), do: nil

  defp append(a, %Block{} = block, height, spent, opts) do
    t0 = System.monotonic_time(:microsecond)

    # connect/5 passes :prepared only when it matches this block and a.next.
    p = opts[:prepared] || encode_append(block, height, spent, a.next)

    %{block: id, out: base_out, inp: base_in} = p.ids
    t1 = System.monotonic_time(:microsecond)

    {segs, locs, firsts} =
      Enum.reduce([:outputs, :inputs, :witness], {a.segs, [], %{}}, fn kind,
                                                                       {segs, ops, firsts} ->
        {s, first, sparse} = Segments.append_layout(segs[kind], p.segs[kind])
        {Map.put(segs, kind, s), ops ++ sparse_ops(kind, sparse), Map.put(firsts, kind, first)}
      end)

    # Every block has a coinbase input, so it has witness records, all in one
    # segment. Its exact start is kept: with pruning, the sparse-index entry of
    # its first id may point into a deleted segment.
    {wseg, _} = wloc = firsts.witness
    a = %{a | wseg_max: Map.update(a.wseg_max, wseg, height, &max(&1, height))}
    tx_meta = p.tx_meta
    prev_id = if height == 0, do: nil, else: a.tip.id
    t2 = System.monotonic_time(:microsecond)
    history = if Map.has_key?(p, :history), do: p.history, else: opts[:history]

    txindex =
      if opts[:index_txs],
        do:
          txindex_lists(a, p.own, history, opts[:unique_txids] == true and a.next.block == height),
        else: %{}

    repeated =
      for {txid, [_, _ | _] = entries} <- txindex,
          {_b, _pos, _base, n, _} = List.last(entries),
          v <- 0..(n - 1)//1,
          do: {txid, v}

    t3 = System.monotonic_time(:microsecond)
    overwritten = overwritten_outputs(a, repeated)
    t4 = System.monotonic_time(:microsecond)

    rec = %{
      hash: block.header.hash,
      header: Header.encode(block.header),
      height: height,
      prev_id: prev_id,
      base_out: base_out,
      base_in: base_in,
      txs: tx_meta,
      n_tx: length(tx_meta),
      undo: spent || [],
      wseg: wseg,
      wloc: wloc,
      overwritten: overwritten
    }

    # One packed put (KV.write/3) for the block's txindex rows: 32-byte
    # txid keys, length-prefixed values.
    tx_ops =
      case for {txid, list} <- txindex,
               into: <<>>,
               do:
                 (
                   v = Codec.encode_txindex(list)
                   <<txid::binary-size(32), byte_size(v)::32, v::binary>>
                 ) do
        <<>> -> []
        bin -> [{:put_packed, :txindex, 32, :var, bin}]
      end

    t4a = System.monotonic_time(:microsecond)
    spend = p.spend
    t4b = System.monotonic_time(:microsecond)
    a = %{a | segs: segs, next: %{block: id + 1, out: base_out + p.nouts, inp: base_in + p.nins}}

    ops =
      [
        {:put, :blocks, <<id::32>>, :erlang.term_to_binary(rec)},
        {:put, :blockhash, block.header.hash, <<id::32>>},
        {:put, :meta, "ntx" <> block.header.hash, <<length(tx_meta)::32>>}
      ] ++
        locs ++ tx_ops ++ spend

    t4c = System.monotonic_time(:microsecond)
    a = add_to_batch(a, id, rec, ops, txindex, block.header.hash)
    t5 = System.monotonic_time(:microsecond)
    count(:append_encode_us, t1 - t0)
    count(:append_segments_us, t2 - t1)
    count(:append_txindex_us, t3 - t2)
    count(:append_overwritten_us, t4 - t3)
    count(:append_record_us, t5 - t4)
    count(:append_tx_ops_us, t4a - t4)
    count(:append_spend_ops_us, t4b - t4a)
    count(:append_ops_list_us, t4c - t4b)
    count(:append_batch_us, t5 - t4c)

    count(
      :append_ops,
      length(ops) - length(tx_ops) - length(spend) + map_size(txindex) + spend_count(spend)
    )

    count(:append_repeated, length(repeated))
    {a, id}
  end

  # One location every @sparse ids (ids that are multiples of @sparse).
  defp sparse_ops(kind, sparse) do
    for {id, loc} <- sparse,
        do: {:put, :locs, Codec.loc_key(kind, div(id, @sparse)), Codec.pack_loc(loc)}
  end

  # The block's own occurrences, `txid => [entry]` newest first (a txid
  # twice in the block keeps both).
  defp own_txindex(id, block, base_out, base_in) do
    {own, _, _, _} =
      Enum.reduce(block.txs, {%{}, 0, base_out, base_in}, fn tx, {m, pos, o, i} ->
        no = length(tx.outputs)
        e = {id, pos, o, no, i}
        t = tx.txid

        m =
          case m do
            %{^t => es} -> %{m | t => [e | es]}
            _ -> Map.put(m, t, [e])
          end

        {m, pos + 1, o + no, i + length(tx.inputs)}
      end)

    own
  end

  defp txindex_lists(a, own, _history, true) do
    batch = a.batch.txindex
    count(:txindex_skipped, map_size(own))

    Map.new(own, fn {t, es} ->
      prior = Map.get(batch, t, [])
      {t, prior ++ Enum.reverse(es)}
    end)
  end

  defp txindex_lists(a, own, history, false) do
    batch = a.batch.txindex
    missing = for {t, _} <- own, not is_map_key(batch, t), do: t

    {known, read} =
      case history do
        %{epoch: e, rows: rows} when e == a.epoch ->
          {hinted, read} = Enum.split_with(missing, &is_map_key(rows, &1))
          {Enum.map(hinted, &{&1, Map.fetch!(rows, &1)}), read}

        %{} ->
          count(:txindex_hint_stale, 1)
          {[], missing}

        _ ->
          {[], missing}
      end

    count(:txindex_reads, length(read))
    count(:txindex_reused, length(known))
    t0 = System.monotonic_time(:microsecond)
    rows = Map.new(known ++ Enum.zip(read, KV.multi_get(a.kv, :txindex, read)))
    count(:txindex_read_us, System.monotonic_time(:microsecond) - t0)
    count(:txindex_found, Enum.count(rows, &match?({_, {:ok, _}}, &1)))

    Map.new(own, fn {t, es} ->
      prior =
        case batch do
          %{^t => list} ->
            list

          _ ->
            case Map.fetch!(rows, t) do
              {:ok, bin} -> Codec.decode_txindex(bin)
              :not_found -> []
            end
        end

      {t, prior ++ Enum.reverse(es)}
    end)
  end

  # spent: output ids for each non-coinbase input, in block order. Input ids
  # count every input (the coinbase's too). One walk over the inputs; a
  # `spent` list longer or shorter than the non-coinbase inputs raises.
  defp spend_count([]), do: 0
  defp spend_count([{:put_packed, :spends, 8, 12, bin}]), do: div(byte_size(bin), 20)

  # The block's spend records as one packed put (KV.write/3): in input order,
  # key <<out::64>>, value <<block::32, input::64>>.
  defp spend_ops(block_id, base_in, %Block{txs: [cb | txs]}, spent) do
    case spend_txs(txs, base_in + length(cb.inputs), spent, block_id, <<>>) do
      {<<>>, []} -> []
      {bin, []} -> [{:put_packed, :spends, 8, 12, bin}]
      {_, _} -> raise ArgumentError, "more spent output ids than non-coinbase inputs"
    end
  end

  defp spend_txs([], _i, rest, _b, acc), do: {acc, rest}

  defp spend_txs([tx | txs], i, spent, b, acc) do
    {acc, i, spent} = spend_inputs(tx.inputs, i, spent, b, acc)
    spend_txs(txs, i, spent, b, acc)
  end

  defp spend_inputs([], i, spent, _b, acc), do: {acc, i, spent}

  defp spend_inputs([_ | ins], i, [out | spent], b, acc),
    do: spend_inputs(ins, i + 1, spent, b, <<acc::binary, out::64, b::32, i::64>>)

  defp spend_inputs([_ | _], _i, [], _b, _acc),
    do: raise(ArgumentError, "fewer spent output ids than non-coinbase inputs")

  # `n_txs`: the new tip block's tx count when connecting it; nil when
  # disconnecting back to `tip`, whose row is already there.
  defp update_chain(a, tip, n_txs \\ nil) do
    # nil if unknown (Core: an unset m_chain_tx_count); never a reason to fail a connect.
    total =
      cond do
        n_txs == nil -> chain_tx_count(a, tip.height)
        tip.height == 0 -> n_txs
        prev = chain_tx_count(a, tip.height - 1) -> prev + n_txs
        true -> nil
      end

    # Remove heights above the new tip (disconnect), then set the tip entry.
    old = a.tip

    if old && old.height >= tip.height do
      for h <- tip.height..old.height//1, id = id_at(a, h), id != nil do
        :ets.delete(a.onchain, id)
        :ets.delete(a.chain, h)
      end
    end

    :ets.insert(a.chain, {tip.height, tip.id, total})
    :ets.insert(a.onchain, {tip.id, tip.height})
    %{a | tip: tip}
  end

  # --- witness pruning ---------------------------------------------------------

  defp prune_witness(%{prune_keep: nil} = a), do: a

  defp prune_witness(a) do
    {current, _} = Segments.position(a.segs.witness)
    limit = a.tip.height - a.prune_keep

    segs =
      Stream.iterate(a.wpruned + 1, &(&1 + 1))
      |> Enum.take_while(fn s ->
        s < current and match?({:ok, h} when h < limit, Map.fetch(a.wseg_max, s))
      end)

    case segs do
      [] ->
        a

      _ ->
        a = %{a | wpruned: List.last(segs), wseg_max: Map.drop(a.wseg_max, segs)}
        write_with_meta(a, [])
        # Readers see the prune before the files go.
        :atomics.put(a.wpruned_live, 1, a.wpruned)
        Enum.each(segs, &Segments.remove(a.segs.witness, &1))
        a
    end
  end

  @doc "Highest pruned witness segment (-1: none), as of now (also for a reader)."
  def witness_pruned(%__MODULE__{wpruned: w, wpruned_live: nil}), do: w
  def witness_pruned(%__MODULE__{wpruned: w, wpruned_live: ref}), do: max(w, :atomics.get(ref, 1))

  @doc """
  Whether block `hash` is archived with what connecting it needs (Core
  BLOCK_HAVE_DATA): on the active chain (already connected), or off it with
  its witness data kept.
  """
  def have_block_data?(%__MODULE__{} = a, hash) do
    case block_id(a, hash) do
      nil -> false
      id -> on_chain?(a, id) or witness_pruned(a) < 0 or not witness_pruned?(a, id)
    end
  end

  @doc "Whether block `id`'s witness data is pruned (now)."
  def witness_pruned?(%__MODULE__{} = a, id), do: rec_pruned?(a, block_record!(a, id))

  # A block record without `:wseg` has no witness segment to lose.
  @doc false
  def rec_pruned?(a, rec) do
    case rec do
      %{wseg: s} -> s <= witness_pruned(a)
      _ -> false
    end
  end

  @doc false
  def sparse, do: @sparse
end
