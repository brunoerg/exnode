defmodule Exnode.Index.Follower do
  @moduledoc """
  Keeps an index in step with the committed active chain (the role of Core's
  `BaseIndex`: catch up from the chain, rewind on reorg). It reads the
  archive through the read-only reader in the chain view, so the chain state
  is never blocked.

  The index keeps, in its KV column family `cf`:
  * `"tip"` -> `<<height::32, hash::binary>>`
  * `<<"h", height::32>>` -> block hash on the indexed chain

  `connect.(height, block_id, reader)` returns the KV ops for one block;
  `disconnect.(height, hash, reader)` the ops that undo it. Both run inside
  the index process.

  Work counters, in the index process (`take_stats/0`): `ix_blocks`
  (blocks connected), `ix_connect_us` (building their ops), `ix_writes`,
  `ix_write_us` (the KV writes, `sync: false`), `ix_ops` and `ix_rewinds`
  (blocks disconnected).
  """
  alias Exnode.Archive
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Store.KV

  @batch 200

  @doc "Indexed tip `{height, hash}`, or `{-1, nil}`."
  def tip(kv, cf) do
    case KV.get(kv, cf, "tip") do
      {:ok, <<h::32, hash::binary>>} -> {h, hash}
      :not_found -> {-1, nil}
    end
  end

  def hash_at(kv, cf, h) do
    case KV.get(kv, cf, <<"h", h::32>>) do
      {:ok, hash} -> hash
      :not_found -> nil
    end
  end

  @doc "Advances (or rewinds) the index; returns `:done` when at the committed tip, else `:more`."
  def sync(kv, cf, chain_state, connect, disconnect) do
    view = ChainState.view(chain_state)
    reader = ChainState.view_reader(view)
    committed = ChainState.view_committed(view)
    {h, hash} = rewind(kv, cf, reader, disconnect)

    if h >= committed do
      :done
    else
      stop = min(committed, h + @batch)

      t0 = System.monotonic_time(:microsecond)

      # The chain table is live: a reorg can replace heights while this batch
      # is built. Each block must link to the one before it (the first to the
      # indexed tip), and the tip is the last linked block itself, so a batch
      # never mixes branches; it stops at the first break and the next sync
      # rewinds whatever the reorg disconnected.
      {ops, {last_h, last_hash}} =
        Enum.reduce_while((h + 1)..stop//1, {[], {h, hash}}, fn height, {acc, {_, prev}} ->
          with id when id != nil <- Archive.id_at(reader, height),
               rec = Archive.block_record!(reader, id),
               true <- linked?(rec, height, prev) do
            ops = connect.(height, id, reader) ++ [{:put, cf, <<"h", height::32>>, rec.hash}]
            {:cont, {[ops | acc], {height, rec.hash}}}
          else
            _ -> {:halt, {acc, {height - 1, prev}}}
          end
        end)

      if last_h == h do
        # The chain changed under the first block: nothing consistent to add
        # yet. Wait a tick (no busy loop); the next sync rewinds if needed.
        :done
      else
        ops = ops |> Enum.reverse() |> Enum.concat()
        t1 = System.monotonic_time(:microsecond)

        :ok =
          KV.write(kv, ops ++ [{:put, cf, "tip", <<last_h::32, last_hash::binary>>}], sync: false)

        bump(:ix_blocks, last_h - h)
        bump(:ix_connect_us, t1 - t0)
        bump(:ix_writes, 1)
        bump(:ix_write_us, System.monotonic_time(:microsecond) - t1)
        bump(:ix_ops, length(ops) + 1)
        if last_h >= committed, do: :done, else: :more
      end
    end
  end

  # Height 0 has no parent; otherwise the header's prev hash must be the
  # hash indexed (or just added) at height - 1.
  defp linked?(_rec, 0, nil), do: true
  defp linked?(%{header: <<_::32, prev::binary-size(32), _::binary>>}, _height, prev), do: true
  defp linked?(_rec, _height, _prev), do: false

  # While the indexed block at the tip is no longer on the active chain, undo it.
  defp rewind(kv, cf, reader, disconnect) do
    case tip(kv, cf) do
      {-1, nil} = t ->
        t

      {h, hash} ->
        active = Archive.id_at(reader, h)
        active_hash = active && Archive.block_record!(reader, active).hash

        if active_hash == hash do
          {h, hash}
        else
          prev = hash_at(kv, cf, h - 1)
          ops = disconnect.(h, hash, reader) ++ [{:delete, cf, <<"h", h::32>>}]

          tip_op =
            if h > 0,
              do: {:put, cf, "tip", <<h - 1::32, prev::binary>>},
              else: {:delete, cf, "tip"}

          :ok = KV.write(kv, ops ++ [tip_op], sync: false)
          bump(:ix_rewinds, 1)
          rewind(kv, cf, reader, disconnect)
        end
    end
  end

  @counters [:ix_blocks, :ix_connect_us, :ix_writes, :ix_write_us, :ix_ops, :ix_rewinds]

  @doc "Takes (and resets) this process's follower counters (see the moduledoc)."
  def take_stats, do: Map.new(@counters, &{&1, Process.delete({__MODULE__, &1}) || 0})

  defp bump(k, n), do: Process.put({__MODULE__, k}, (Process.get({__MODULE__, k}) || 0) + n)
end
