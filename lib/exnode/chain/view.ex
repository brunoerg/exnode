defmodule Exnode.Chain.View do
  @moduledoc """
  Lock-free `:protected` ETS view (`:chain_view`) of a `Chain.State`'s tip,
  committed height, read-only `Archive.reader/1`, held/quarantined block
  hashes, halt state and latched IBD status.

  Published in `Exnode.Node.Runtime` under `{Exnode.Chain.State, name}` when
  the chain state is registered by name so RPC, REST, index followers and
  peers read it without calling into the chain-state process.

  Because the ETS table is `:protected`, only the owning chain-state process
  mutates it. The IBD latch (`m_cached_finished_ibd`) and the active-chain
  seqlock generation live in a 2-slot `:atomics` ref stored in the view:
  * slot 1 (`@ibd_done_slot`): `0` while still in IBD, `1` once finished
    (latched lock-free by any reader via `:atomics.put/3`);
  * slot 2 (`@active_gen_slot`): monotonic seqlock counter for lock-free
    active-chain coin reads (Plan 02).
  """

  alias Exnode.Archive
  alias Exnode.Archive.Overlay
  alias Exnode.Chain.HeaderIndex
  alias Exnode.Node.Runtime

  @handle_ns Exnode.Chain.State
  @ibd_done_slot 1
  @active_gen_slot 2
  @seqlock_retries 6

  @doc "Creates the `:protected` `:chain_view` ETS table and publishes it if `name` is given."
  def new(kv, name \\ nil) do
    t = :ets.new(:chain_view, [:set, :protected, read_concurrency: true])
    atomics = :atomics.new(2, [])
    :ets.insert(t, [{:kv, kv}, {:halted, false}, {:atomics, atomics}])
    if name, do: Runtime.put_handle({@handle_ns, name}, t)
    t
  end

  @doc """
  The chain view ETS handle for `server` (must be a registered atom name),
  or `nil` if none is published.
  """
  def view(server) when is_atom(server), do: Runtime.get_handle({@handle_ns, server}, nil)
  def view(_server), do: nil

  @doc "The 2-slot `:atomics` ref backing `ibd_done` (slot 1) and `active_gen` (slot 2)."
  def view_atomics(view), do: :ets.lookup_element(view, :atomics, 2)

  @doc "Current `active_gen` seqlock generation (even = quiescent, odd = mutation in progress)."
  def view_active_gen(view), do: :atomics.get(view_atomics(view), @active_gen_slot)

  @doc false
  def bump_active_gen(view), do: :atomics.add_get(view_atomics(view), @active_gen_slot, 1)

  @doc "A read-only archive (committed blocks only) for serving, from the view."
  def view_reader(nil), do: exit({:noproc, {Exnode.Chain.State, :view_reader, [nil]}})

  def view_reader(view) do
    :ets.lookup_element(view, :reader, 2)
  rescue
    ArgumentError -> exit({:noproc, {Exnode.Chain.State, :view_reader, [view]}})
  end

  @doc """
  The read-only archive of `server`'s committed chain, without a call into
  the chain-state process. Its `Archive.tip/1` is the committed tip.
  """
  def reader(server), do: view_reader(view(server))

  @doc "Height of the last committed (durable) tip, from the view."
  def view_committed(view), do: :ets.lookup_element(view, :committed, 2)

  @doc "Halt reason (`false` if none), from the view."
  def view_halted(view), do: :ets.lookup_element(view, :halted, 2)

  @doc "Active tip from the view (no call into the chain-state process)."
  def view_tip(view), do: :ets.lookup_element(view, :tip, 2)

  @doc """
  Lock-free active-chain coin lookup (Plan 02 seqlock): reads the active tip
  and resolves `outpoints` against the published overlay and committed reader
  without calling `Chain.State`.

  Returns `{:ok, {tip, %{outpoint => {:ok, coin} | :missing}}}` on a clean
  seqlock read, or `:retry` if `Chain.State` mutated the active state during
  the read (or the view has no published overlay yet).
  """
  def resolve_active(view, outpoints) do
    do_resolve_active(view, Enum.uniq(outpoints), @seqlock_retries)
  end

  defp do_resolve_active(_view, _ops, 0), do: :retry

  defp do_resolve_active(view, ops, retries) do
    try do
      atomics = view_atomics(view)
      g1 = :atomics.get(atomics, @active_gen_slot)

      if rem(g1, 2) == 1 do
        :erlang.yield()
        do_resolve_active(view, ops, retries - 1)
      else
        case lookup_active_snapshot(view) do
          {:ok, tip, reader, overlay, batch_txids} ->
            resolved = resolve_with_overlay(reader, overlay, batch_txids, ops)
            g2 = :atomics.get(atomics, @active_gen_slot)

            if g1 == g2 do
              {:ok, {tip, resolved}}
            else
              do_resolve_active(view, ops, retries - 1)
            end

          :unavailable ->
            :retry
        end
      end
    rescue
      # View or reader ETS tables (:chain_view / :archive_chain / :archive_onchain)
      # can vanish mid-read if Archive.Writer restarts; fall back cleanly.
      ArgumentError -> :retry
    end
  end

  defp lookup_active_snapshot(view) do
    with [{:tip, tip}] <- :ets.lookup(view, :tip),
         [{:reader, reader}] <- :ets.lookup(view, :reader),
         [{:overlay, overlay}] when overlay != nil <- :ets.lookup(view, :overlay),
         [{:batch_txids, batch_txids}] <- :ets.lookup(view, :batch_txids) do
      {:ok, tip, reader, overlay, batch_txids}
    else
      _ -> :unavailable
    end
  rescue
    ArgumentError -> :unavailable
  end

  defp resolve_with_overlay(_reader, _overlay, _batch_txids, []), do: %{}

  defp resolve_with_overlay(reader, overlay, batch_txids, ops) do
    {known, rest} =
      Enum.reduce(ops, {%{}, []}, fn {txid, _} = op, {known, rest} ->
        case Overlay.lookup(overlay, op) do
          {:ok, coin} -> {Map.put(known, op, {:ok, coin}), rest}
          :spent -> {Map.put(known, op, :missing), rest}
          :unknown when is_map_key(batch_txids, txid) -> {Map.put(known, op, :missing), rest}
          :unknown -> {known, [op | rest]}
        end
      end)

    if rest == [],
      do: known,
      else: Map.merge(known, Archive.committed_answers(reader, rest))
  end

  @doc """
  Core `IsInitialBlockDownload`, the one answer for peers and RPC: the
  tip's work is below the chain's minimum, or the tip is older than 24 h
  at `now` (seconds). Once false it stays false for this chain state's
  life (Core `m_cached_finished_ibd`), latched lock-free in the view's
  `:atomics` slot so the ETS table remains `:protected`.
  """
  def view_ibd?(view, idx, now, params) do
    atomics = view_atomics(view)

    if :atomics.get(atomics, @ibd_done_slot) == 1 do
      false
    else
      ibd =
        case HeaderIndex.lookup(idx, view_tip(view).hash) do
          nil -> true
          e -> e.chain_work < params.minimum_chain_work or e.time < now - 24 * 3600
        end

      if not ibd, do: :atomics.put(atomics, @ibd_done_slot, 1)
      ibd
    end
  end

  @doc """
  Whether `hash`'s block data is held in memory, archived (see
  `Archive.have_block_data?/2`), or quarantined (no call).
  """
  def view_have?(view, hash) do
    :ets.member(view, {:held, hash}) or :ets.member(view, {:quarantined, hash}) or
      Archive.have_block_data?(view_reader(view), hash)
  end

  @doc """
  Subset of `hashes` whose block data is held in memory, archived (see
  `Archive.have_block_data?/2`), or quarantined (no call).
  """
  def view_have_many(view, hashes) do
    reader = view_reader(view)

    MapSet.new(
      Enum.filter(hashes, fn h ->
        :ets.member(view, {:held, h}) or :ets.member(view, {:quarantined, h}) or
          Archive.have_block_data?(reader, h)
      end)
    )
  end

  # --- writer updates (owned by Chain.State) -----------------------------------

  @doc false
  def publish(view, %Archive{} = a) do
    :ets.insert(view, [
      {:tip, Archive.tip(a)},
      {:committed, Archive.committed_tip(a).height},
      {:reader, Archive.reader(a)},
      {:overlay, Overlay.hint(a.overlay)},
      {:batch_txids, a.batch.txindex}
    ])

    :ok
  end

  @doc false
  def put_tip(view, tip, batch_txids \\ nil) do
    if batch_txids == nil do
      :ets.insert(view, {:tip, tip})
    else
      :ets.insert(view, [{:tip, tip}, {:batch_txids, batch_txids}])
    end

    :ok
  end

  @doc false
  def put_committed(view, %Archive{} = a) do
    :ets.insert(view, [
      {:committed, Archive.committed_tip(a).height},
      {:reader, Archive.reader(a)},
      {:overlay, Overlay.hint(a.overlay)},
      {:batch_txids, a.batch.txindex}
    ])

    :ok
  end

  @doc false
  def with_active_mutation(view, fun) do
    bump_active_gen(view)

    try do
      fun.()
    after
      bump_active_gen(view)
    end
  end

  @doc false
  def put_halted(view, halted) do
    :ets.insert(view, {:halted, halted})
    :ok
  end

  @doc false
  def hold(view, hash) do
    :ets.insert(view, {{:held, hash}})
    :ok
  end

  @doc false
  def hold_many(view, hashes) do
    for h <- hashes, do: :ets.insert(view, {{:held, h}})
    :ok
  end

  @doc false
  def unhold(view, hash) do
    :ets.delete(view, {:held, hash})
    :ok
  end

  @doc false
  def unhold_many(view, hashes) do
    for h <- hashes, do: :ets.delete(view, {:held, h})
    :ok
  end

  @doc false
  def quarantine(view, hash) do
    :ets.delete(view, {:held, hash})
    :ets.insert(view, {{:quarantined, hash}})
    :ok
  end

  @doc false
  def quarantine_many(view, hashes) do
    for h <- hashes, do: :ets.insert(view, {{:quarantined, h}})
    :ok
  end

  @doc false
  def unquarantine_many(view, hashes) do
    for h <- hashes, do: :ets.delete(view, {:quarantined, h})
    :ok
  end
end
