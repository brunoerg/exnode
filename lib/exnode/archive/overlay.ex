defmodule Exnode.Archive.Overlay do
  @moduledoc """
  In-memory coin view in front of the archive. Mirrors the role of Core v32.1
  `CCoinsViewCache` (coins.cpp) over `CCoinsViewDB`, adapted to the archive
  (which needs no UTXO database).

  Two kinds of entry:
  * **coins**: `{txid, vout} => {gen, coin}`, outputs created by connected
    blocks and still unspent on the selected chain. `gen` is the archive id of
    the creating block. Entries of uncommitted blocks (gen > `flushed`) are
    the overlay that lets blocks connect ahead of the durable commit.
    Entries of committed blocks stay as a cache until evicted (oldest first)
    while the cache is over its byte budget `max` (see `memory/1`).
  * **spent**: outpoints spent by connected but uncommitted blocks. The
    archive's `spends` records for them are not written yet, so this set masks
    them. It is cleared when the batch commits.

  Invariant: a coin entry is an unspent output on the selected chain, so a hit
  answers `resolve` without the archive. Any disconnect clears everything
  (reorgs are rare; Core's cache is likewise rebuilt from the DB).

  ETS tables owned by the archive's process.
  """

  # `gens`: queue of `{gen, n, packed}`, the outpoints each block created
  # (spent ones included), packed into one off-heap binary (`pack_ops/1`).
  # `queued`: their count; `queued_bytes`: the packed bytes. Charged to the
  # budget too, so a cache larger than the UTXO set does not keep every
  # outpoint ever made.
  defstruct [
    :coins,
    :spent,
    gens: :queue.new(),
    queued: 0,
    queued_bytes: 0,
    flushed: -1,
    max: 0
  ]

  # The budget counts real memory, as Core's -dbcache counts its cache's
  # dynamic usage (CS-9). Measured on OTP 28, 64-bit:
  # * a coin entry in ETS, {{txid, vout}, gen, coin map} with a typical
  #   22-34 byte script: about 301 bytes (rounded up);
  # * the generation queue: each block's outpoints packed in one off-heap
  #   binary (37 bytes per mainnet outpoint, counted exactly), plus about
  #   64 bytes per block for the binary and the queue element. Kept as
  #   tuples on the process heap they cost 88 bytes each, and the heap's
  #   growth margin and garbage-collection copies about doubled that.
  # A script over 64 bytes is an off-heap binary and is not counted (rare).
  @entry_bytes 320
  @gen_bytes 64

  @doc "`max_bytes`: cache budget (Core `-dbcache` role). 0 keeps only uncommitted entries."
  def new(max_bytes) do
    %__MODULE__{
      coins: :ets.new(:overlay_coins, [:set, :protected]),
      spent: :ets.new(:overlay_spent, [:set, :protected]),
      max: max_bytes
    }
  end

  @doc "Memory charged against the budget, in bytes: coin entries plus the generation queue."
  def memory(%__MODULE__{} = ov),
    do: size(ov) * @entry_bytes + ov.queued_bytes + :queue.len(ov.gens) * @gen_bytes

  @doc "`{:ok, coin}`, `:spent` (by an uncommitted block) or `:unknown`."
  def lookup(%__MODULE__{coins: c, spent: s}, op) do
    case :ets.lookup(c, op) do
      [{_, _gen, coin}] -> {:ok, coin}
      [] -> if :ets.member(s, op), do: :spent, else: :unknown
    end
  end

  @doc """
  The overlay's two ETS handles alone (no generation queue), for another
  process to test outpoints with `answerable?/2` (prefetch). The tables stay
  owned and written by the archive's process; other processes only read.
  """
  def hint(%__MODULE__{coins: c, spent: s}), do: %__MODULE__{coins: c, spent: s}

  @doc """
  True if `lookup/2` answers `op` right now (a coin, or a spend by an
  uncommitted block). From another process this is advisory only: the owner
  may evict or clear entries at any moment.
  """
  def answerable?(%__MODULE__{coins: c, spent: s}, op),
    do: :ets.member(c, op) or :ets.member(s, op)

  @doc """
  Applies a connected block: `spent` outpoints are removed and masked, then
  `created` (`%{op => coin}`, unspendable outputs already excluded) is added.
  Cached entries (ETS, and the generation queue's packed outpoints) never
  keep block binaries alive. Since OTP 27 a
  binary of at most 64 bytes is never a sub-binary (matching or
  `binary_part/3` copies it), so a txid or a short script cannot reference
  its block: only larger binaries are copied. The mask and the coins each
  go in with one insert per block.
  """
  def apply_block(%__MODULE__{} = ov, gen, created, spent),
    do: apply_prepared(ov, prepare_block(gen, created, spent))

  @doc """
  The table-independent part of `apply_block/4`: the mask rows, the coin
  rows (owned binaries, see above) and the packed outpoints of generation
  `gen`. Pure, so any process may build it; `apply_prepared/2` applies it.
  """
  def prepare_block(gen, created, spent) do
    mask = for op <- spent, do: {own_op(op)}

    {entries, ops} =
      Enum.reduce(created, {[], []}, fn {op, coin}, {es, os} ->
        op = own_op(op)
        {[{op, gen, own_script(coin)} | es], [op | os]}
      end)

    %{gen: gen, mask: mask, entries: entries, n: length(ops), packed: pack_ops(ops)}
  end

  @doc "Applies a `prepare_block/3` result: the same effect as `apply_block/4`."
  def apply_prepared(%__MODULE__{} = ov, %{
        gen: gen,
        mask: mask,
        entries: entries,
        n: n,
        packed: packed
      }) do
    t0 = System.monotonic_time(:microsecond)
    for {op} <- mask, do: :ets.delete(ov.coins, op)
    :ets.insert(ov.spent, mask)
    t1 = System.monotonic_time(:microsecond)
    for {op, _, _} <- entries, do: :ets.delete(ov.spent, op)
    :ets.insert(ov.coins, entries)
    t2 = System.monotonic_time(:microsecond)
    bump(:ov_spent_us, t1 - t0)
    bump(:ov_created_us, t2 - t1)
    bump(:ov_spent_n, length(mask))
    bump(:ov_created_n, n)

    %{
      ov
      | gens: :queue.in({gen, n, packed}, ov.gens),
        queued: ov.queued + n,
        queued_bytes: ov.queued_bytes + byte_size(packed)
    }
  end

  # <<txid size, txid, vout::32>> per outpoint (a 32-byte txid on mainnet).
  defp pack_ops(ops),
    do: IO.iodata_to_binary(for {txid, vout} <- ops, do: [byte_size(txid), txid, <<vout::32>>])

  # A binary that may be a sub-binary of its block (over 64 bytes) is copied.
  defp own_op({txid, vout}) when byte_size(txid) > 64, do: {:binary.copy(txid), vout}
  defp own_op(op), do: op

  defp own_script(%{script_pubkey: spk} = coin) when byte_size(spk) > 64,
    do: %{coin | script_pubkey: :binary.copy(spk)}

  defp own_script(coin), do: coin

  @doc """
  The batch up to `gen` is committed: spend records are on disk, entries
  become evictable. `gen` never decreases (the archive passes its highest
  block id, `next.block - 1`; reconnected blocks keep lower ids), so a
  queued generation once committed stays committed; eviction without a
  cache budget relies on this.
  """
  def committed(%__MODULE__{} = ov, gen) do
    t0 = System.monotonic_time(:microsecond)
    :ets.delete_all_objects(ov.spent)
    t1 = System.monotonic_time(:microsecond)
    ov = evict(%{ov | flushed: gen})
    bump(:ov_mask_clear_us, t1 - t0)
    bump(:ov_evict_us, System.monotonic_time(:microsecond) - t1)
    ov
  end

  @doc "Drops everything (disconnect)."
  def clear(%__MODULE__{} = ov) do
    :ets.delete_all_objects(ov.coins)
    :ets.delete_all_objects(ov.spent)
    %{ov | gens: :queue.new(), queued: 0, queued_bytes: 0}
  end

  def size(%__MODULE__{coins: c}), do: :ets.info(c, :size)

  # Evicts the oldest committed blocks' entries while over budget. An entry
  # is removed only if it still belongs to that block (it may have been spent,
  # or overwritten by a BIP30 duplicate in a later block).
  #
  # No cache (max 0) and every queued block committed: the loop would evict
  # every block. Each coin entry `{op, gen}` is listed under its own `gen`
  # in the queue (apply_block adds both together; only spending, eviction
  # and clear/1 remove entries), so the table would end empty: one
  # delete_all_objects does the same.
  defp evict(%{max: 0} = ov) do
    if Enum.all?(:queue.to_list(ov.gens), fn {g, _, _} -> g <= ov.flushed end) do
      bump(:ov_evicted, ov.queued)
      bump(:ov_evict_all, 1)
      :ets.delete_all_objects(ov.coins)
      %{ov | gens: :queue.new(), queued: 0, queued_bytes: 0}
    else
      evict_oldest(ov)
    end
  end

  defp evict(ov), do: evict_oldest(ov)

  defp evict_oldest(ov) do
    with true <- memory(ov) > ov.max,
         {{:value, {gen, n, packed}}, rest} when gen <= ov.flushed <- :queue.out(ov.gens) do
      # The owner is the only writer (:protected), so test-then-delete is
      # the select_delete of `{op, gen, _}` without a match specification.
      # The txid is a sub-binary of `packed`, used only as a key here.
      for <<len, txid::binary-size(len), vout::32 <- packed>>,
          op = {txid, vout},
          :ets.lookup_element(ov.coins, op, 2, nil) == gen,
          do: :ets.delete(ov.coins, op)

      bump(:ov_evicted, n)

      evict_oldest(%{
        ov
        | gens: rest,
          queued: ov.queued - n,
          queued_bytes: ov.queued_bytes - byte_size(packed)
      })
    else
      _ -> ov
    end
  end

  def close(%__MODULE__{coins: c, spent: s}) do
    :ets.delete(c)
    :ets.delete(s)
  end

  @doc """
  Takes (and resets) this process's overlay work counters (per block or
  per commit, never per entry): `ov_spent_us`/`ov_spent_n` (spent outpoints
  removed and masked), `ov_created_us`/`ov_created_n` (created coins copied
  and inserted), `ov_mask_clear_us` (commit: spent mask cleared),
  `ov_evict_us`/`ov_evicted` (commit: committed generations evicted;
  `ov_evict_all`: whole-table evictions without a cache budget).
  """
  def take_stats do
    Map.new(
      [
        :ov_spent_us,
        :ov_spent_n,
        :ov_created_us,
        :ov_created_n,
        :ov_mask_clear_us,
        :ov_evict_us,
        :ov_evicted,
        :ov_evict_all
      ],
      &{&1, Process.delete({__MODULE__, &1}) || 0}
    )
  end

  defp bump(k, n), do: Process.put({__MODULE__, k}, (Process.get({__MODULE__, k}) || 0) + n)
end
