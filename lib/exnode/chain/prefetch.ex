defmodule Exnode.Chain.Prefetch do
  @moduledoc """
  The prefetch stage of block connection. While the chain state connects
  block N, worker processes prepare the next `depth` blocks of the path: each reads the block from
  `pending`, decodes it, and computes `Archive.committed_answers/2` for
  every outpoint `Validation.Connect.connect_block/6` will look up (inputs,
  and BIP30 outputs where Core enforces BIP30). That is the txindex lookup,
  the spend record check and the output reads, the largest part of
  connecting a block, now off the chain-state process and in parallel.

  The chain state uses the answers only when they cannot differ from what
  it would compute itself:
  * the archive's committed state is unchanged (`Archive.epoch/1` equal at
    prefetch and at use: any commit or disconnect in between voids them);
  * the overlay, the batch and the in-flight blocks still answer first, so
    the answers only stand in for the committed lookup;
  * no prefetch on a path that reconnects already-archived blocks: those
    change which archived blocks are on the chain without a commit.
  Anything else (a stale epoch, a failed or crashed worker, a block not in
  `pending`) falls back to the chain state's own path, as before.

  Cache-aware: outpoints the overlay answers when the worker runs (cached
  coins, uncommitted spends; `ctx.hint`, its ETS handles only) are not
  looked up (`Archive.prefetch_block/4`). They are absent from the
  answers, so if the overlay drops them before use, the chain state looks
  them up itself: the hint saves I/O, it never supplies an answer.

  The worker also returns the committed txindex rows of the block's own
  txids (`history`, read in the same `multi_get`; where BIP30 applies the
  BIP30 outpoints need them anyway). The block's append reuses them
  instead of reading them again only under the same epoch rule, checked
  again at append (`Archive.connect/5`'s `:history`); otherwise it reads.

  Each result carries the worker's own counters (`stats`): unique outpoints
  `considered`, `omitted` by the hint and `sent` to committed resolution,
  the archive read counters of `Archive.take_stats/0`, and `worker_us`, the
  worker's own busy time. Workers run concurrently, so their times overlap.

  **Asynchronous.** The owner never waits on a worker: a result arrives as
  `{:prefetch_done, tag, result}` (handled with `reply/3`), a crashed
  worker's `:DOWN` with `down/2`, and `take/3` answers `:wait` until the
  next block's result is in. Workers are linked to the owner (they die with
  it); `stop/1` unlinks and kills those left, so the owner sees no exit.
  Results are tagged with a fresh reference per worker, so a late message
  from a stopped prefetch is recognised as stale (`reply/3` returns
  `:unknown`). Admission is bounded by `depth` and by the owner's byte
  budget (`fill/3`'s `admit?`).
  """

  alias Exnode.Archive
  alias Exnode.Chain.HeaderIndex
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Validation.Connect

  # tasks: FIFO of {hash, tag}; workers: tag => {pid, mref}; results: tag => result.
  defstruct todo: [],
            tasks: :queue.new(),
            workers: %{},
            results: %{},
            retained: 0,
            depth: 0,
            ctx: nil

  @doc """
  Starts prefetching `path` (header entries, in order), keeping up to
  `depth` blocks in progress or ready. `ctx`: `%{kv, params, idx, current, hint}`
  where `current` is a decoded block already in hand (or nil) and `hint`
  is `Archive.overlay_hint/1` of the chain state's archive (or nil).
  `admit?.(pf)` gates each new worker (the owner's byte budget).
  """
  def start(path, depth, reader, ctx, admit? \\ fn _ -> true end)
  def start(_path, depth, _reader, _ctx, _admit?) when depth <= 0, do: %__MODULE__{}

  def start(path, depth, reader, ctx, admit?) do
    fill(%__MODULE__{todo: path, depth: depth, ctx: ctx}, reader, admit?)
  end

  @doc "Appends entries to the path (an extension on the same branch); `ctx.idx` is updated."
  def extend(%__MODULE__{depth: 0} = pf, _entries, _idx, _reader, _admit?), do: pf

  def extend(%__MODULE__{} = pf, entries, idx, reader, admit?),
    do: fill(%{pf | todo: pf.todo ++ entries, ctx: %{pf.ctx | idx: idx}}, reader, admit?)

  @doc "Starts workers while fewer than `depth` are pending or ready and `admit?.(pf)` holds."
  def fill(%__MODULE__{todo: [entry | rest]} = pf, reader, admit?) do
    if :queue.len(pf.tasks) < pf.depth and admit?.(pf) do
      ctx = pf.ctx
      owner = self()
      tag = make_ref()
      pid = spawn_link(fn -> send(owner, {:prefetch_done, tag, prepare(reader, entry, ctx)}) end)
      mref = Process.monitor(pid)

      fill(
        %{
          pf
          | todo: rest,
            tasks: :queue.in({entry.hash, tag}, pf.tasks),
            workers: Map.put(pf.workers, tag, {pid, mref})
        },
        reader,
        admit?
      )
    else
      pf
    end
  end

  def fill(pf, _reader, _admit?), do: pf

  @doc "Records a worker's result. `:unknown` if `tag` is not one of this prefetch's workers."
  def reply(%__MODULE__{} = pf, tag, result) do
    case Map.pop(pf.workers, tag) do
      {nil, _} ->
        :unknown

      {{_pid, mref}, workers} ->
        Process.demonitor(mref, [:flush])

        {:ok,
         %{
           pf
           | workers: workers,
             results: Map.put(pf.results, tag, result),
             retained: pf.retained + result_bytes(result)
         }}
    end
  end

  @doc "A worker's `:DOWN` before its result: the block falls back (`:none`). `:unknown` if not ours."
  def down(%__MODULE__{} = pf, mref) do
    case Enum.find(pf.workers, fn {_tag, {_pid, m}} -> m == mref end) do
      nil ->
        :unknown

      {tag, _} ->
        {:ok,
         %{pf | workers: Map.delete(pf.workers, tag), results: Map.put(pf.results, tag, :none)}}
    end
  end

  @doc """
  The result for `entry` (the next block of the path): `{{:ok, block, epoch,
  answers, history, stats}, pf}` (`history`: `Archive.prefetch_block/4`'s
  committed txindex rows of the block's txids, for its append), `{:none,
  pf}` (no prefetch, a failed worker, or a diverged path, which stops the
  prefetch), or `{:wait, pf}` while its worker runs. Taking a result starts
  the next worker.
  """
  def take(%__MODULE__{depth: 0} = pf, _entry, _reader, _admit?), do: {:none, pf}

  def take(%__MODULE__{} = pf, entry, reader, admit?) do
    case :queue.peek(pf.tasks) do
      {:value, {hash, tag}} when hash == entry.hash ->
        case Map.pop(pf.results, tag) do
          {nil, _} ->
            {:wait, pf}

          {result, results} ->
            pf = %{
              pf
              | tasks: :queue.drop(pf.tasks),
                results: results,
                retained: pf.retained - result_bytes(result)
            }

            result = if match?({:ok, _, _, _, _, _}, result), do: result, else: :none
            {result, fill(pf, reader, admit?)}
        end

      _ ->
        # The path diverged from what was prefetched: stop.
        stop(pf)
        {:none, %__MODULE__{}}
    end
  end

  @doc "Workers started and not yet taken (running or ready)."
  def in_flight(%__MODULE__{tasks: t}), do: :queue.len(t)

  @doc "Kills the workers still running (unlinked first: the owner sees no exit)."
  def stop(%__MODULE__{workers: workers}) do
    for {_tag, {pid, mref}} <- workers do
      Process.unlink(pid)
      Process.exit(pid, :kill)
      Process.demonitor(mref, [:flush])
    end

    :ok
  end

  # Retained bytes of a ready result: the raw block plus its decoded form
  # (about twice the raw size) and the answer map. An approximation.
  defp result_bytes({:ok, %Block{raw: raw}, _epoch, answers, history, _stats})
       when is_binary(raw),
       do: 3 * byte_size(raw) + 160 * map_size(answers) + 64 * map_size(history.rows)

  defp result_bytes(_), do: 0

  # One block: load, decode, committed answers. Any failure gives :none.
  defp prepare(reader, entry, ctx) do
    t0 = System.monotonic_time(:microsecond)

    with %Block{} = b <- load(ctx, entry.hash) do
      prev = HeaderIndex.prev(ctx.idx, entry)
      ops = Connect.lookup_ops(b, entry, prev, ctx.params, ctx.idx)
      # The committed txindex rows of the block's own txids serve its append
      # (where Core enforces BIP30 the BIP30 outpoints read them anyway).
      txids = for tx <- b.txs, do: tx.txid
      {answers, filter, history} = Archive.prefetch_block(reader, ops, Map.get(ctx, :hint), txids)

      stats =
        filter
        |> Map.merge(Archive.take_stats())
        |> Map.put(:worker_us, System.monotonic_time(:microsecond) - t0)

      {:ok, b, Archive.epoch(reader), answers, history, stats}
    else
      _ -> :none
    end
  rescue
    _ -> :none
  catch
    _, _ -> :none
  end

  defp load(%{current: %Block{header: %{hash: h}} = b}, h), do: b

  defp load(ctx, hash) do
    case KV.get(ctx.kv, :pending, hash) do
      {:ok, raw} ->
        case Block.decode_exact(raw) do
          {:ok, b} -> b
          _ -> nil
        end

      :not_found ->
        nil
    end
  end
end
