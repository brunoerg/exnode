defmodule Exnode.Index.Scripthash do
  @moduledoc """
  Scripthash history index (Electrum style). Keyed by `sha256(scriptPubKey)`:

  * funding: `<<sh::32-bytes, height::32, pos::32, 0, vout::32>>` -> `<<txid::32-bytes, value::64>>`
  * spending: `<<sh::32-bytes, height::32, pos::32, 1, vin::32>>` -> `<<txid::32-bytes, prev_txid::32-bytes, prev_vout::32, value::64>>`

  so a scripthash's history is one prefix scan, in chain order. Built from
  the archive (`Archive.read_index_facts/3`, `Archive.undo_outputs/2`), kept on the committed
  active chain by `Exnode.Index.Follower`; a reorg deletes exactly the keys
  of the blocks it disconnects.

  Per-script totals, so an address's stats need no history scan:
  `<<"t", sh::32-bytes, k>>` -> an integer term, for `k` 0..4: funded
  outputs, funded value, spent outputs, spent value, txs (a tx touching the
  script both ways counts once; as in electrs, a txid confirmed twice, the
  BIP30 duplicate coinbases, counts twice). Each block's rows come with
  merges (`{:int_add, n}`, the family's merge operator) that add to them, or
  subtract on disconnect, in the same write. `"totals"` marks them complete:
  an index built before them gets them from one scan of its rows first
  (`backfill_totals/1`); until then `totals/2` returns nil.
  """
  use GenServer
  require Logger

  alias Exnode.Archive
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Index.Follower
  alias Exnode.Store.KV

  @cf :scripthash
  @tick_ms 200

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "`sha256(spk)`, the index key (Electrum displays it byte-reversed)."
  def scripthash(spk), do: :crypto.hash(:sha256, spk)

  @doc """
  Confirmed history of a scripthash, oldest first:
  `[%{kind: :funding | :spending, height, pos, txid, index, value, prevout}]`.
  The scan runs in the caller (KV handles are shared between processes), so
  a long history costs the caller only and never holds the index process.
  """
  def history(server, sh) do
    server
    |> kv()
    |> KV.fold_prefix(@cf, sh, [], &[row(&1) | &2])
    |> Enum.reject(&is_nil/1)
    |> Enum.reverse()
  end

  @doc """
  The confirmed outputs of `sh` not spent in its history, in chain order:
  `{:ok, [%{txid, index, value, height}]}`, or `{:error, :too_many}` as
  soon as more than `limit` are unspent at any point of the scan (electrs'
  `utxo_delta`, `--utxos-limit`). The rows are folded in chain order, a
  spend always after the funding it spends, so only the outputs unspent so
  far are held: memory is bounded by `limit`, not by the history's length.
  In the caller, like `history/2`.
  """
  def utxos(server, sh, limit) do
    unspent =
      fold_history(server, sh, %{}, fn
        %{kind: :funding} = r, acc ->
          acc = Map.put(acc, {r.txid, r.index}, {r.height, r.pos, r.value})
          if map_size(acc) > limit, do: throw({__MODULE__, :too_many}), else: acc

        %{kind: :spending, prevout: op}, acc ->
          Map.delete(acc, op)
      end)

    {:ok,
     unspent
     |> Enum.sort_by(fn {{_txid, vout}, {h, pos, _}} -> {h, pos, vout} end)
     |> Enum.map(fn {{txid, vout}, {h, _pos, value}} ->
       %{txid: txid, index: vout, value: value, height: h}
     end)}
  catch
    {__MODULE__, :too_many} -> {:error, :too_many}
  end

  @doc """
  Folds `fun` over the confirmed history rows of `sh`, oldest first,
  without holding them (in the caller, like `history/2`).
  """
  def fold_history(server, sh, acc, fun) do
    server
    |> kv()
    |> KV.fold_prefix(@cf, sh, acc, fn kv, acc ->
      case row(kv) do
        nil -> acc
        r -> fun.(r, acc)
      end
    end)
  end

  @doc """
  One page of history, newest first: the rows of at most `limit` txs (by
  `{height, pos}`), before the tx at `before` (`{height, pos}`, exclusive;
  nil: from the newest). Reads only those rows (a reverse seek), in the
  caller like `history/2`.
  """
  def history_page(server, sh, before, limit) do
    start = if before, do: (fn {h, pos} -> <<sh::binary, h::32, pos::32>> end).(before)

    server
    |> kv()
    |> KV.fold_prefix_reverse(@cf, sh, start, {[], nil, 0}, fn kv, {rows, last, n} ->
      case row(kv) do
        nil ->
          {:cont, {rows, last, n}}

        %{height: h, pos: p} = r when {h, p} == last ->
          {:cont, {[r | rows], last, n}}

        _ when n == limit ->
          {:halt, {rows, last, n}}

        %{height: h, pos: p} = r ->
          {:cont, {[r | rows], {h, p}, n + 1}}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  @totals [:funded_txo_count, :funded_txo_sum, :spent_txo_count, :spent_txo_sum, :tx_count]

  @doc """
  The confirmed totals of `sh`: `%{funded_txo_count, funded_txo_sum,
  spent_txo_count, spent_txo_sum, tx_count}` (five point reads, in the
  caller), or nil while an older index is still getting its totals.
  """
  def totals(server, sh) do
    kv = kv(server)

    if KV.get(kv, @cf, "totals") == {:ok, <<1>>} do
      kv
      |> KV.multi_get(@cf, for(k <- 0..4, do: total_key(sh, k)))
      |> Enum.map(fn
        {:ok, v} -> :erlang.binary_to_term(v)
        :not_found -> 0
      end)
      |> then(&Map.new(Enum.zip(@totals, &1)))
    end
  end

  defp total_key(sh, k), do: <<"t", sh::binary, k>>

  @doc "The rows of `sh` for the tx at `{height, pos}` (one seek)."
  def rows_at(server, sh, {h, pos}) do
    server
    |> kv()
    |> KV.fold_prefix(@cf, <<sh::binary, h::32, pos::32>>, [], &[row(&1) | &2])
    |> Enum.reject(&is_nil/1)
  end

  # The index's KV handle, published at init (no call into the process).
  defp kv(server) when is_atom(server), do: :persistent_term.get({__MODULE__, server})
  defp kv(server), do: GenServer.call(server, :kv, 5_000)

  defp row(
         {<<_::binary-size(32), h::32, pos::32, 0, vout::32>>,
          <<txid::binary-size(32), value::64>>}
       ),
       do: %{kind: :funding, height: h, pos: pos, txid: txid, index: vout, value: value}

  defp row(
         {<<_::binary-size(32), h::32, pos::32, 1, vin::32>>,
          <<txid::binary-size(32), pt::binary-size(32), pv::32, value::64>>}
       ),
       do: %{
         kind: :spending,
         height: h,
         pos: pos,
         txid: txid,
         index: vin,
         value: value,
         prevout: {pt, pv}
       }

  defp row(_), do: nil

  def tip(server), do: GenServer.call(server, :tip, 5_000)

  @doc """
  The hash of the block the index holds at height `h`, or nil. Read in the
  caller, like `history/2`: a reader compares it with the active chain to
  skip rows of a block a reorg has replaced but the index has not yet
  rewound (≤ 200 ms).
  """
  def hash_at(server, h), do: Follower.hash_at(kv(server), @cf, h)

  @doc """
  Cumulative work counters of the index process since it started: the
  follower's (`Exnode.Index.Follower`), this index's per block
  (`sh_blocks`, `sh_outputs` funding rows, `sh_undo` spent output ids,
  `sh_materialize_us` the block record plus `Archive.read_index_facts/3`
  (it replaced `sh_reconstruct_us`, the full `read_block_txs`
  reconstruction, on 2026-11-10), `sh_spent_us` reading the spent outputs,
  `sh_rows_us` building the rows) and the archive work it did
  (`Exnode.Archive.take_stats/0`: `preads`, `pread_bytes`,
  `output_groups`, `facts_read_us`, `facts_txid_us`, `facts_merkle_us`,
  ...; zero counters omitted). Added up once per tick, never per row.
  """
  def stats(server), do: GenServer.call(server, :stats, 5_000)
  @doc "Waits until block `hash` is on the indexed chain (at or below its tip)."
  def sync_to(server, hash, timeout \\ 30_000),
    do: GenServer.call(server, {:sync_to, hash}, timeout)

  @impl true
  def init(opts) do
    send(self(), :tick)
    kv = Keyword.fetch!(opts, :kv)

    # Readers scan in their own process (`history/2`); a restart with the
    # same handle does not rewrite the term (a rewrite costs a global GC).
    if (name = opts[:name]) && :persistent_term.get({__MODULE__, name}, nil) != kv,
      do: :persistent_term.put({__MODULE__, name}, kv)

    {:ok, %{kv: kv, chain_state: Keyword.fetch!(opts, :chain_state), waiters: [], stats: %{}}}
  end

  @impl true
  def handle_call(:kv, _from, st), do: {:reply, st.kv, st}

  def handle_call(:tip, _from, st), do: {:reply, Follower.tip(st.kv, @cf), st}

  def handle_call(:stats, _from, st) do
    st = take_work(st)
    {:reply, st.stats, st}
  end

  def handle_call({:sync_to, hash}, from, st) do
    if indexed?(st, hash),
      do: {:reply, :ok, st},
      else: {:noreply, %{st | waiters: [{hash, from} | st.waiters]}}
  end

  @impl true
  def handle_info(:tick, st) do
    result =
      try do
        backfill_totals(st.kv)
        Follower.sync(st.kv, @cf, st.chain_state, &connect/3, &disconnect/3)
      catch
        kind, reason ->
          if ChainState.view(st.chain_state) != nil,
            do: Logger.warning("scripthash index: #{inspect(kind)} #{inspect(reason, limit: 5)}")

          :done
      end

    waiters =
      Enum.reject(st.waiters, fn {h, from} ->
        indexed?(st, h) and GenServer.reply(from, :ok) == :ok
      end)

    Process.send_after(self(), :tick, if(result == :more, do: 0, else: @tick_ms))
    {:noreply, take_work(%{st | waiters: waiters})}
  end

  @counters [:sh_blocks, :sh_outputs, :sh_undo, :sh_materialize_us, :sh_spent_us, :sh_rows_us]

  # Adds this process's counters (this index, the follower, the archive's
  # reads) into the cumulative stats.
  defp take_work(st) do
    mine = Map.new(@counters, &{&1, Process.delete({__MODULE__, &1}) || 0})

    work =
      mine
      |> Map.merge(Follower.take_stats())
      |> Map.merge(Archive.take_stats())
      |> Map.reject(fn {_, v} -> v == 0 end)

    %{st | stats: Map.merge(st.stats, work, fn _, a, b -> a + b end)}
  end

  defp bump(k, n), do: Process.put({__MODULE__, k}, (Process.get({__MODULE__, k}) || 0) + n)

  # The indexed chain contains `hash` (at its height), not only as its tip:
  # a caller waiting for a tip the index has already passed used to wait
  # until its timeout.
  defp indexed?(st, hash) do
    case Follower.tip(st.kv, @cf) do
      {_, ^hash} ->
        true

      {tip_h, _} ->
        with view when view != nil <- ChainState.view(st.chain_state),
             reader = ChainState.view_reader(view),
             id when id != nil <- Archive.block_id(reader, hash),
             %{height: h} when h <= tip_h <- Archive.block_record!(reader, id) do
          Follower.hash_at(st.kv, @cf, h) == hash
        else
          _ -> false
        end
    end
  end

  @doc false
  # The KV ops (`:put` or `:delete`) for block `id` at `height`, from a
  # committed reader (tests compare it with a reference generator).
  def block_ops(height, id, reader, op), do: keys_for(height, id, reader, op)

  # The block's rows as `op` ops.
  defp keys_for(height, id, reader, op),
    do: for({k, v} <- rows_for(height, id, reader), do: kv(op, k, v))

  # A block's rows with the merges that add them to the totals.
  defp connect(height, id, reader) do
    rows = rows_for(height, id, reader)
    for({k, v} <- rows, do: kv(:put, k, v)) ++ total_ops(rows, 1)
  end

  # The block's rows deleted, and taken off the totals.
  defp disconnect(height, hash, reader) do
    case Archive.block_id(reader, hash) do
      nil ->
        []

      id ->
        rows = rows_for(height, id, reader)
        for({k, v} <- rows, do: kv(:delete, k, v)) ++ total_ops(rows, -1)
    end
  end

  # `sign` times each script's totals over `rows` (one block), as merges.
  defp total_ops(rows, sign) do
    rows
    |> Enum.reduce(%{}, fn {k, v}, acc ->
      %{kind: kind, value: value, height: h, pos: pos} = row({k, v})
      sh = binary_part(k, 0, 32)
      {fc, fs, sc, ss, txs} = Map.get(acc, sh, {0, 0, 0, 0, MapSet.new()})

      t =
        if kind == :funding,
          do: {fc + 1, fs + value, sc, ss, MapSet.put(txs, {h, pos})},
          else: {fc, fs, sc + 1, ss + value, MapSet.put(txs, {h, pos})}

      Map.put(acc, sh, t)
    end)
    |> Enum.flat_map(fn {sh, {fc, fs, sc, ss, txs}} ->
      for {n, k} <- Enum.with_index([fc, fs, sc, ss, MapSet.size(txs)]),
          n != 0,
          do: {:merge, @cf, total_key(sh, k), :erlang.term_to_binary({:int_add, sign * n})}
    end)
  end

  @doc false
  # Gives an index built before the totals its totals: one scan of the rows
  # (in key order, so one script's rows are together), writing each
  # script's totals, then the "totals" mark. A new index is marked at once.
  # Interrupted, it starts over (plain puts, so a rerun overwrites).
  def backfill_totals(kv) do
    cond do
      KV.get(kv, @cf, "totals") == {:ok, <<1>>} ->
        :ok

      Follower.tip(kv, @cf) == {-1, nil} ->
        :ok = KV.write(kv, [{:put, @cf, "totals", <<1>>}])

      true ->
        Logger.info("scripthash index: computing per-script totals from the history (once)")
        t0 = System.monotonic_time(:millisecond)

        acc =
          KV.fold_prefix(
            kv,
            @cf,
            <<>>,
            %{sh: nil, t: nil, last: nil, ops: [], n: 0, scripts: 0},
            fn {k, _} = kv_pair, acc ->
              case row(kv_pair) do
                nil -> acc
                r -> backfill_row(kv, acc, binary_part(k, 0, 32), r)
              end
            end
          )

        acc = flush_script(acc)
        :ok = KV.write(kv, acc.ops ++ [{:put, @cf, "totals", <<1>>}])

        Logger.info(
          "scripthash index: totals for #{acc.scripts} scripts in #{System.monotonic_time(:millisecond) - t0} ms"
        )
    end
  end

  defp backfill_row(kv, %{sh: sh} = acc, sh, r) do
    {fc, fs, sc, ss, tc} = acc.t
    tc = if {r.height, r.pos} == acc.last, do: tc, else: tc + 1

    t =
      if r.kind == :funding,
        do: {fc + 1, fs + r.value, sc, ss, tc},
        else: {fc, fs, sc + 1, ss + r.value, tc}

    %{acc | t: t, last: {r.height, r.pos}} |> maybe_write(kv)
  end

  defp backfill_row(kv, acc, sh, r) do
    acc = flush_script(acc)
    backfill_row(kv, %{acc | sh: sh, t: {0, 0, 0, 0, 0}, last: nil}, sh, r)
  end

  # The totals of the script just finished, as puts.
  defp flush_script(%{sh: nil} = acc), do: acc

  defp flush_script(%{sh: sh, t: t} = acc) do
    ops =
      for {n, k} <- Enum.with_index(Tuple.to_list(t)),
          do: {:put, @cf, total_key(sh, k), :erlang.term_to_binary(n)}

    %{acc | ops: ops ++ acc.ops, n: acc.n + 5, scripts: acc.scripts + 1, sh: nil}
  end

  defp maybe_write(%{n: n} = acc, kv) when n >= 10_000 do
    :ok = KV.write(kv, acc.ops, sync: false)
    %{acc | ops: [], n: 0}
  end

  defp maybe_write(acc, _kv), do: acc

  # One block's rows, `{key, value}`: a funding row for every output, a
  # spending row for every input. The block record is read once. Txids,
  # prevouts and funding outputs come from Archive.read_index_facts/3 (base
  # records only, txids checked against the header's merkle root; no
  # witnesses, no full-block decode). The spent outputs (value and script
  # together) come from one grouped read of the record's undo ids
  # (Archive.undo_outputs/2), matched to the non-coinbase inputs in order.
  # An archive inconsistency (facts error, count mismatch) raises; rows are
  # never truncated.
  defp rows_for(height, id, reader) do
    t0 = System.monotonic_time(:microsecond)
    rec = Archive.block_record!(reader, id)

    txs =
      case Archive.read_index_facts(reader, id, rec) do
        {:ok, %{txs: txs}} ->
          txs

        {:error, why} ->
          raise ArgumentError, "block #{id} at #{height}: archive index facts: #{inspect(why)}"
      end

    t1 = System.monotonic_time(:microsecond)
    spent = Archive.undo_outputs(reader, rec)
    t2 = System.monotonic_time(:microsecond)

    {ops, rest} =
      txs
      |> Enum.with_index()
      |> Enum.flat_map_reduce(spent, fn {{txid, prevouts, outputs}, pos}, rest ->
        funding =
          for {{value, spk}, vout} <- Enum.with_index(outputs),
              do:
                {<<scripthash(spk)::binary, height::32, pos::32, 0, vout::32>>,
                 <<txid::binary, value::64>>}

        if pos == 0 do
          {funding, rest}
        else
          {spending, rest} = spending_keys(height, pos, txid, prevouts, rest, 0, [])
          {funding ++ spending, rest}
        end
      end)

    if rest != [],
      do:
        raise(
          ArgumentError,
          "block #{id} at #{height}: more spent outputs than non-coinbase inputs"
        )

    bump(:sh_blocks, 1)
    bump(:sh_undo, length(spent))
    bump(:sh_outputs, Enum.reduce(txs, 0, fn {_, _, outs}, n -> n + length(outs) end))
    bump(:sh_materialize_us, t1 - t0)
    bump(:sh_spent_us, t2 - t1)
    bump(:sh_rows_us, System.monotonic_time(:microsecond) - t2)
    ops
  end

  defp spending_keys(_height, _pos, _txid, [], rest, _vin, acc), do: {Enum.reverse(acc), rest}

  defp spending_keys(height, pos, txid, [{ph, pi} | ins], [{value, spk} | rest], vin, acc) do
    k =
      {<<scripthash(spk)::binary, height::32, pos::32, 1, vin::32>>,
       <<txid::binary, ph::binary, pi::32, value::64>>}

    spending_keys(height, pos, txid, ins, rest, vin + 1, [k | acc])
  end

  defp spending_keys(height, pos, _txid, [_ | _], [], _vin, _acc),
    do:
      raise(ArgumentError, "tx #{pos} at #{height}: fewer spent outputs than non-coinbase inputs")

  defp kv(:put, k, v), do: {:put, @cf, k, v}
  defp kv(:delete, k, _v), do: {:delete, @cf, k}
end
