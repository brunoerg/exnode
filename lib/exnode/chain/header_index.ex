defmodule Exnode.Chain.HeaderIndex do
  @moduledoc """
  In-memory header tree (Core's `BlockMap` of `CBlockIndex`), backed by ETS.

  Three tables:
  * `entries`: hash → `%Entry{}` for every accepted header, side chains included.
  * `heights`: height → hash along the best-header chain (`m_best_header`).
    This makes ancestor lookups and locators cheap; Core uses its skiplist.
  * `meta`: the best header's entry (`best/1`).

  Writes come only from the owner process (`Exnode.Chain.Headers`). Reads
  work from any process, and the struct itself never changes after `new/0`:
  a handle taken once always reads the current index, including the best
  header, without a call into the owner (which can be blocked, e.g. on a
  KV write queued behind a chain-state commit).

  Coherence of `heights` for other processes: a best-header change rewrites
  the table back to the fork point, one height at a time, so a reader in
  another process could see the new best already "on the best chain" while
  lower heights still name the old branch, and get a wrong ancestor. The
  writer brackets every rewrite with a generation counter (`gen`, odd while
  writing; a seqlock), and `ancestor/3` uses the table only when the
  generation was even and unchanged across its reads; otherwise it retries,
  then walks parent links, which never change. Entries themselves are
  immutable apart from `status`.
  """
  alias Exnode.Codec.Header
  alias Exnode.Consensus.Pow

  defmodule Entry do
    @moduledoc false
    # status: :valid_header | :failed (Core BLOCK_VALID_TREE / BLOCK_FAILED_VALID)
    defstruct [
      :hash,
      :height,
      :prev_hash,
      :chain_work,
      :version,
      :time,
      :bits,
      :raw,
      status: :valid_header
    ]
  end

  defstruct [:entries, :heights, :meta, :gen]

  @type t :: %__MODULE__{}

  def new do
    %__MODULE__{
      entries: :ets.new(:header_entries, [:set, :protected, read_concurrency: true]),
      heights: :ets.new(:header_heights, [:set, :protected, read_concurrency: true]),
      # The best header's entry, under the key :best (absent until genesis is inserted).
      meta: :ets.new(:header_meta, [:set, :protected, read_concurrency: true]),
      # Rewrite generation of `heights` (seqlock: odd while rewriting).
      gen: :atomics.new(1, [])
    }
  end

  @doc "Builds an entry for `header` on top of `prev` (nil for genesis). Core `AddToBlockIndex`."
  def make_entry(%Header{} = h, prev) do
    {height, work0} = if prev, do: {prev.height + 1, prev.chain_work}, else: {0, 0}

    %Entry{
      hash: :binary.copy(h.hash),
      height: height,
      prev_hash: :binary.copy(h.prev_hash),
      chain_work: work0 + Pow.bits_proof(h.bits),
      version: h.version,
      time: h.time,
      bits: h.bits,
      # An 80-byte slice can otherwise pin an entire padded P2P frame.
      raw: :binary.copy(h.raw || Header.encode(h))
    }
  end

  def lookup(%__MODULE__{entries: t}, hash) do
    case :ets.lookup(t, hash) do
      [{_, e}] -> e
      [] -> nil
    end
  end

  @doc """
  The best header (Core `m_best_header`): the most-work entry that is not
  failed, or nil before genesis is inserted. Read from ETS, so it is current
  for every holder of the index.
  """
  def best(%__MODULE__{meta: t}) do
    case :ets.lookup(t, :best) do
      [{_, e}] -> e
      [] -> nil
    end
  end

  def prev(_idx, %Entry{height: 0}), do: nil
  def prev(idx, %Entry{prev_hash: p}), do: lookup(idx, p)

  def size(%__MODULE__{entries: t}), do: :ets.info(t, :size)

  @doc "Hash on the best-header chain at `height`, or nil."
  def hash_at(%__MODULE__{heights: t}, height) do
    case :ets.lookup(t, height) do
      [{_, h}] -> h
      [] -> nil
    end
  end

  def on_best_chain?(idx, %Entry{height: h, hash: hash}), do: hash_at(idx, h) == hash

  @doc """
  Inserts an entry. If it has more work than the current best header, it
  becomes the best header and the height table is rewritten back to the fork
  point. Core `AddToBlockIndex` updates `m_best_header` only when work is
  strictly greater, so on ties the first-seen header wins. A failed entry
  (only when loading) never becomes the best header: Core `LoadBlockIndex`
  considers only `IsValid(BLOCK_VALID_TREE)` entries.
  """
  # Core: AddToBlockIndex; LoadBlockIndex (validation.cpp)
  def insert(%__MODULE__{} = idx, %Entry{} = e) do
    :ets.insert(idx.entries, {e.hash, e})
    best = best(idx)

    if best == nil or (e.status != :failed and e.chain_work > best.chain_work) do
      set_best(idx, e)
    else
      idx
    end
  end

  @doc "Replaces an existing entry (e.g. a status change) without changing best-header selection."
  def update(%__MODULE__{} = idx, %Entry{} = e) do
    :ets.insert(idx.entries, {e.hash, e})
    idx
  end

  defp set_best(idx, e) do
    old = best(idx)
    old_best_height = if old, do: old.height, else: -1
    # Extending the best chain by one entry rewrites only its own height: a
    # reader of a lower height is unaffected, and one of this height reads
    # either nothing (not yet an ancestor of anything it holds) or the entry.
    extending = old != nil and e.prev_hash == old.hash
    unless extending, do: bump_gen(idx)
    rewrite_heights(idx, e)
    for h <- (e.height + 1)..old_best_height//1, do: :ets.delete(idx.heights, h)
    # After the heights rewrite and inside the seqlock bracket: a reader that
    # sees the new best and then the heights either gets them coherent or an
    # odd/changed generation (ancestor/3 retries or walks parent links).
    :ets.insert(idx.meta, {:best, e})
    unless extending, do: bump_gen(idx)
    idx
  end

  defp bump_gen(%{gen: nil}), do: :ok
  defp bump_gen(%{gen: g}), do: :atomics.add(g, 1, 1)

  @doc "The `heights` rewrite generation (even: stable), for readers in other processes."
  def generation(%__MODULE__{gen: nil}), do: 0
  def generation(%__MODULE__{gen: g}), do: :atomics.get(g, 1)

  defp rewrite_heights(idx, e) do
    if hash_at(idx, e.height) != e.hash do
      :ets.insert(idx.heights, {e.height, e.hash})
      if e.height > 0, do: rewrite_heights(idx, lookup(idx, e.prev_hash))
    end
  end

  @doc """
  Marks `hash` and every descendant in the index as failed (Core
  `BLOCK_FAILED_VALID`, `SetBlockFailureFlags`). If the best header descends
  from it, the best header becomes the most-work entry that is not failed,
  at least `fallback`, the active tip (Core `RecalculateBestHeader`).
  Returns `{idx, newly_failed_entries}` (for persisting).
  """
  # Core: InvalidBlockFound -> InvalidChainFound (validation.cpp)
  def invalidate(%__MODULE__{} = idx, hash, %Entry{} = fallback) do
    case lookup(idx, hash) do
      nil ->
        {idx, []}

      e ->
        newly = set_failure_flags(idx, e)

        best = best(idx)

        if best && ancestor_of?(idx, e, best),
          do: {recalculate_best(idx, fallback), newly},
          else: {idx, newly}
    end
  end

  # Core: Chainstate::SetBlockFailureFlags. One pass over the entries above
  # `e`, by height: an entry descends from `e` iff its parent does (or is `e`).
  defp set_failure_flags(idx, e) do
    above =
      :ets.foldl(
        fn {_, x}, acc -> if x.height > e.height, do: [x | acc], else: acc end,
        [],
        idx.entries
      )
      |> Enum.sort_by(& &1.height)

    {_, newly} =
      Enum.reduce(above, {MapSet.new([e.hash]), []}, fn x, {desc, newly} ->
        if MapSet.member?(desc, x.prev_hash),
          do: {MapSet.put(desc, x.hash), if(x.status == :failed, do: newly, else: [x | newly])},
          else: {desc, newly}
      end)

    newly = if e.status == :failed, do: newly, else: [e | newly]
    failed = for x <- newly, do: %{x | status: :failed}
    :ets.insert(idx.entries, for(x <- failed, do: {x.hash, x}))
    failed
  end

  # Core: ChainstateManager::RecalculateBestHeader: the active tip, or an
  # entry with strictly more work that is not failed.
  defp recalculate_best(idx, tip) do
    best =
      :ets.foldl(
        fn {_, x}, best ->
          if x.status != :failed and x.chain_work > best.chain_work, do: x, else: best
        end,
        tip,
        idx.entries
      )

    set_best(idx, best)
  end

  @doc "True if `e` or any ancestor down to height `stop_height` is marked failed."
  def failed_path?(idx, %Entry{} = e, stop_height) do
    cond do
      e.status == :failed -> true
      e.height <= stop_height -> false
      true -> failed_path?(idx, prev(idx, e), stop_height)
    end
  end

  @doc "Core `CBlockIndex::GetAncestor(height)`."
  def ancestor(_idx, %Entry{height: h} = e, height) when height == h, do: e
  def ancestor(_idx, %Entry{height: h}, height) when height > h or height < 0, do: nil

  def ancestor(idx, %Entry{} = e, height), do: ancestor(idx, e, height, 3)

  # The fast path (the heights table) only on a stable, unchanged
  # generation; a rewrite in progress is retried, then walked around.
  defp ancestor(idx, e, height, tries) do
    g0 = generation(idx)

    if rem(g0, 2) == 1 do
      if tries > 0, do: ancestor(idx, e, height, tries - 1), else: walk_to(idx, e, height)
    else
      r =
        if on_best_chain?(idx, e),
          do: {:fast, lookup(idx, hash_at(idx, height))},
          else: :slow

      cond do
        generation(idx) != g0 and tries > 0 -> ancestor(idx, e, height, tries - 1)
        generation(idx) != g0 -> walk_to(idx, e, height)
        r == :slow -> ancestor_slow(idx, lookup(idx, e.prev_hash), height)
        true -> elem(r, 1)
      end
    end
  end

  # One step down, then the normal lookup (which may take the fast path
  # once on the best chain), as before.
  defp ancestor_slow(_idx, nil, _height), do: nil
  defp ancestor_slow(idx, e, height), do: ancestor(idx, e, height)

  # Parent links only: always coherent.
  defp walk_to(_idx, %Entry{height: h} = e, height) when h == height, do: e
  defp walk_to(_idx, nil, _height), do: nil
  defp walk_to(idx, %Entry{} = e, height), do: walk_to(idx, lookup(idx, e.prev_hash), height)

  @doc """
  Core `PeerManagerImpl::GetAntiDoSWorkThreshold`: the larger of the active
  tip's work less 144 of its block proofs (0 if that would go below 0, or
  with no tip) and `minimum_chain_work`. `tip` is the active tip's entry.
  """
  # Core: GetAntiDoSWorkThreshold (net_processing.cpp)
  def anti_dos_work_threshold(tip, p) do
    near_tip =
      case tip do
        %Entry{chain_work: w, bits: b} -> w - min(144 * Pow.bits_proof(b), w)
        _ -> 0
      end

    max(near_tip, p.minimum_chain_work)
  end

  @doc "Core `CBlockIndex::GetMedianTimePast()` (nMedianTimeSpan = 11)."
  def median_time_past(idx, %Entry{} = e) do
    times = collect_times(idx, e, 11, [])
    times |> Enum.sort() |> Enum.at(div(length(times), 2))
  end

  defp collect_times(_idx, nil, _n, acc), do: acc
  defp collect_times(_idx, _e, 0, acc), do: acc
  defp collect_times(idx, e, n, acc), do: collect_times(idx, prev(idx, e), n - 1, [e.time | acc])

  @doc "Core `LocatorEntries(index)`: hashes back from `e`, with exponentially larger steps after 10, plus genesis."
  def locator(idx, %Entry{} = e), do: locator(idx, e, 1, [])

  defp locator(idx, e, step, acc) do
    acc = [e.hash | acc]

    if e.height == 0 do
      Enum.reverse(acc)
    else
      next = ancestor(idx, e, max(e.height - step, 0))
      step = if length(acc) > 10, do: step * 2, else: step
      locator(idx, next, step, acc)
    end
  end

  @doc "Core `LastCommonAncestor(pa, pb)`."
  def last_common_ancestor(idx, a, b) do
    {a, b} =
      cond do
        a.height > b.height -> {ancestor(idx, a, b.height), b}
        b.height > a.height -> {a, ancestor(idx, b, a.height)}
        true -> {a, b}
      end

    walk_together(idx, a, b)
  end

  defp walk_together(_idx, %Entry{hash: h} = a, %Entry{hash: h}), do: a
  defp walk_together(idx, a, b), do: walk_together(idx, prev(idx, a), prev(idx, b))

  @doc "True if `e` is an ancestor of (or equal to) `tip`."
  def ancestor_of?(idx, %Entry{} = e, %Entry{} = tip) do
    case ancestor(idx, tip, e.height) do
      %Entry{hash: h} -> h == e.hash
      nil -> false
    end
  end
end
