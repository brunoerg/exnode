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

  The tables live in native memory (`native/overlay_nif`), not ETS: plain
  allocations in an open-addressing hash table, as Core's `CCoinsMap`, that
  no garbage collector scans and no lookup copies whole. As ETS tables
  (about 320 bytes per coin, copied in and out on each access) they held
  ~100M coins once a 32 GiB cache filled in a mainnet IBD, and the overlay's
  cost per input grew from 1.1 to 2.5 µs between heights 200k and 700k.
  The archive's process is the only writer; other processes (prefetch) may
  test membership with `answerable?/2`. The memory is freed when the last
  reference to the tables goes (or by `close/1`).
  """

  # `tab`: the native tables (both kinds of entry).
  # `gens`: queue of `{gen, n, packed}`, the outpoints each block created
  # (spent ones included), packed into one off-heap binary (`pack_ops/1`).
  # `queued`: their count; `queued_bytes`: the packed bytes. Charged to the
  # budget too, so a cache larger than the UTXO set does not keep every
  # outpoint ever made.
  defstruct [
    :tab,
    gens: :queue.new(),
    queued: 0,
    queued_bytes: 0,
    flushed: -1,
    max: 0
  ]

  # The budget counts real memory, as Core's -dbcache counts its cache's
  # dynamic usage: the native tables report their slots and each entry's
  # aligned allocation footprint, and the generation queue is charged its
  # packed bytes plus about 64 bytes per block for the binary and the
  # queue element.
  @gen_bytes 64

  @on_load :load_nif

  @doc false
  def load_nif do
    path = :filename.join(:code.priv_dir(:exnode), ~c"native/overlay_nif")
    :erlang.load_nif(path, 0)
  end

  @doc "`max_bytes`: cache budget (Core `-dbcache` role). 0 keeps only uncommitted entries."
  def new(max_bytes), do: %__MODULE__{tab: new_nif(), max: max_bytes}

  @doc "Memory charged against the budget, in bytes: the native tables plus the generation queue."
  def memory(%__MODULE__{} = ov),
    do: native_bytes(ov) + ov.queued_bytes + :queue.len(ov.gens) * @gen_bytes

  @doc "Bytes held by the native tables (slots and entries, both kinds)."
  def native_bytes(%__MODULE__{tab: t}), do: elem(info_nif(t), 2)

  @doc "`{:ok, coin}`, `:spent` (by an uncommitted block) or `:unknown`."
  def lookup(%__MODULE__{tab: t}, {txid, vout}), do: lookup_nif(t, txid, vout)

  @doc """
  The overlay's tables alone (no generation queue), for another process to
  test outpoints with `answerable?/2` (prefetch). The tables stay written
  by the archive's process only.
  """
  def hint(%__MODULE__{tab: t}), do: %__MODULE__{tab: t}

  @doc """
  True if `lookup/2` answers `op` right now (a coin, or a spend by an
  uncommitted block). From another process this is advisory only: the owner
  may evict or clear entries at any moment, and while the owner is writing
  the tables this answers false without waiting (the caller then resolves
  `op` itself).
  """
  def answerable?(%__MODULE__{tab: t}, {txid, vout}), do: member_nif(t, txid, vout)

  @doc """
  Applies a connected block: `spent` outpoints are removed and masked, then
  `created` (`%{op => coin}`, unspendable outputs already excluded) is added.
  The tables keep their own copies of keys and scripts, never a reference
  into a block binary.
  """
  def apply_block(%__MODULE__{} = ov, gen, created, spent),
    do: apply_prepared(ov, prepare_block(gen, created, spent))

  @doc """
  The table-independent part of `apply_block/4`: the block's spent
  outpoints and created coins packed into binaries, and its created
  outpoints for the generation queue. Pure, so any process may build it
  (the archive's preparation workers do); `apply_prepared/2` applies it.
  """
  def prepare_block(gen, created, spent) do
    {coins, ops} =
      Enum.reduce(created, {[], []}, fn {op, c}, {cs, os} ->
        spk = c.script_pubkey

        rec = [
          op_rec(op),
          <<c.output_id::64, c.value::64, c.height::32, if(c.coinbase, do: 1, else: 0)::8,
            byte_size(spk)::32>>,
          spk
        ]

        {[rec | cs], [op | os]}
      end)

    %{
      gen: gen,
      mask: pack_ops(spent),
      coins: IO.iodata_to_binary(coins),
      n: length(ops),
      packed: pack_ops(ops)
    }
  end

  @doc "Applies a `prepare_block/3` result: the same effect as `apply_block/4`."
  def apply_prepared(%__MODULE__{tab: t} = ov, %{
        gen: gen,
        mask: mask,
        coins: coins,
        n: n,
        packed: packed
      }) do
    # One call, so a malformed block changes nothing; it times its two
    # phases itself. Out of memory it raises :enomem with the block partly
    # applied: the owner must not go on with these tables (the chain state
    # treats it as fatal and restarts from its last commit).
    {:ok, spent_us, created_us} = apply_nif(t, gen, mask, coins)
    bump(:ov_spent_us, spent_us)
    bump(:ov_created_us, created_us)
    bump(:ov_spent_n, count_ops(mask))
    bump(:ov_created_n, n)

    %{
      ov
      | gens: :queue.in({gen, n, packed}, ov.gens),
        queued: ov.queued + n,
        queued_bytes: ov.queued_bytes + byte_size(packed)
    }
  end

  # <<txid size, txid, vout::32>> per outpoint (a 32-byte txid on mainnet).
  defp pack_ops(ops), do: IO.iodata_to_binary(Enum.map(ops, &op_rec/1))
  defp op_rec({txid, vout}), do: [byte_size(txid), txid, <<vout::32>>]

  defp count_ops(packed), do: count_ops(packed, 0)
  defp count_ops(<<>>, n), do: n

  defp count_ops(<<len, _::binary-size(len), _::32, rest::binary>>, n),
    do: count_ops(rest, n + 1)

  @doc """
  The batch up to `gen` is committed: spend records are on disk, entries
  become evictable. `gen` never decreases (the archive passes its highest
  block id, `next.block - 1`; reconnected blocks keep lower ids), so a
  queued generation once committed stays committed; eviction without a
  cache budget relies on this.
  """
  def committed(%__MODULE__{tab: t} = ov, gen) do
    t0 = System.monotonic_time(:microsecond)
    :ok = clear_nif(t, :spent)
    t1 = System.monotonic_time(:microsecond)
    ov = evict(%{ov | flushed: gen})
    bump(:ov_mask_clear_us, t1 - t0)
    bump(:ov_evict_us, System.monotonic_time(:microsecond) - t1)
    ov
  end

  @doc "Drops everything (disconnect)."
  def clear(%__MODULE__{tab: t} = ov) do
    :ok = clear_nif(t, :all)
    %{ov | gens: :queue.new(), queued: 0, queued_bytes: 0}
  end

  @doc "Coin entries held."
  def size(%__MODULE__{tab: t}), do: elem(info_nif(t), 0)

  @doc "Masked (spent, uncommitted) outpoints held."
  def spent_size(%__MODULE__{tab: t}), do: elem(info_nif(t), 1)

  @doc false
  # The generation a coin entry belongs to, or nil (tests).
  def gen_of(%__MODULE__{tab: t}, {txid, vout}), do: gen_of_nif(t, txid, vout)

  @doc false
  # Drops the coin entries of `ops` as an eviction would, without touching
  # the generation queue (tests: a cache entry gone between preparation
  # and use).
  def drop(%__MODULE__{tab: t}, ops) do
    for op <- ops, gen = gen_of(%__MODULE__{tab: t}, op), gen != nil do
      evict_nif(t, gen, pack_ops([op]))
    end

    :ok
  end

  # Evicts the oldest committed blocks' entries while over budget. An entry
  # is removed only if it still belongs to that block (it may have been spent,
  # or overwritten by a BIP30 duplicate in a later block).
  #
  # No cache (max 0) and every queued block committed: the loop would evict
  # every block. Each coin entry `{op, gen}` is listed under its own `gen`
  # in the queue (apply_block adds both together; only spending, eviction
  # and clear/1 remove entries), so the table would end empty: one clear
  # does the same.
  defp evict(%{max: 0} = ov) do
    if Enum.all?(:queue.to_list(ov.gens), fn {g, _, _} -> g <= ov.flushed end) do
      bump(:ov_evicted, ov.queued)
      bump(:ov_evict_all, 1)
      :ok = clear_nif(ov.tab, :all)
      %{ov | gens: :queue.new(), queued: 0, queued_bytes: 0}
    else
      evict_oldest(ov)
    end
  end

  defp evict(ov), do: evict_oldest(ov)

  defp evict_oldest(ov) do
    with true <- memory(ov) > ov.max,
         {{:value, {gen, n, packed}}, rest} when gen <= ov.flushed <- :queue.out(ov.gens) do
      _removed = evict_nif(ov.tab, gen, packed)
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

  @doc "Frees the tables now (they are freed anyway once unreferenced)."
  def close(%__MODULE__{tab: t}), do: :ok = clear_nif(t, :all)

  defp new_nif, do: :erlang.nif_error(:nif_not_loaded)
  defp apply_nif(_t, _gen, _mask, _coins), do: :erlang.nif_error(:nif_not_loaded)
  defp lookup_nif(_t, _txid, _vout), do: :erlang.nif_error(:nif_not_loaded)
  defp member_nif(_t, _txid, _vout), do: :erlang.nif_error(:nif_not_loaded)
  defp gen_of_nif(_t, _txid, _vout), do: :erlang.nif_error(:nif_not_loaded)
  defp evict_nif(_t, _gen, _ops), do: :erlang.nif_error(:nif_not_loaded)
  defp clear_nif(_t, _which), do: :erlang.nif_error(:nif_not_loaded)
  defp info_nif(_t), do: :erlang.nif_error(:nif_not_loaded)

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
