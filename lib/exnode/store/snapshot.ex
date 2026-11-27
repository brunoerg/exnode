defmodule Exnode.Store.Snapshot do
  @moduledoc """
  Quiescent, rotated store snapshots and atomic restore (libbitcoin model).

  Mutable RocksDB state (`index/` for canonical state, `derived/` for optional
  query indexes) is never trusted after an unclean shutdown or storage fault.
  Instead:

  1. At every quiescent commit point (after append-only segments are fsynced and
     the synced canonical KV batch has written `meta["archive"]`), `take_canonical!/3`
     calls `KV.checkpoint/2` (flushing memtables to immutable SSTs, zero WAL,
     hard-linking SSTs, fsyncing MANIFEST/CURRENT) into `snapshots/staging`,
     writes a checksummed `SNAPSHOT_OK` sentinel, and rotates two slots on the
     same filesystem via atomic directory renames + directory fsyncs:
     `rm secondary -> rename(primary, secondary) -> rename(staging, primary)`.
  2. At every instant during rotation, at least one complete snapshot (`primary`
     or `secondary`) exists on disk.
  3. On restore (`restore!/2`), the live crashed `index/` is replaced whole from
     a hard-linked clone of the latest valid snapshot (leaving the snapshot
     itself intact for idempotency), append-only hot/cold segments are truncated
     to the exact `ends` recorded in that snapshot's `meta["archive"]`,
     ephemeral `staging/` is wiped, `derived/` is restored from its snapshot (or
     wiped if dirty with no snapshot), and `flush.lock` is removed.
  """

  require Logger

  alias Exnode.Archive.Segments
  alias Exnode.StorageError
  alias Exnode.Store.{Guard, KV}

  @sentinel "SNAPSHOT_OK"
  @tag "exnode-snapshot-ok"
  @version 1

  @doc "Path of the snapshots directory inside any store directory (`chain_dir` or `derived/<name>`)."
  def snapshots_dir(store_dir), do: Path.join(store_dir, "snapshots")

  @doc "Known per-index derived store directories under `chain_dir` that exist on disk."
  def derived_store_dirs(chain_dir) do
    per_index =
      for name <- ["filters", "scripthash"],
          dir = Path.join([chain_dir, "derived", name]),
          File.dir?(dir),
          do: {name, dir}

    legacy = Path.join(chain_dir, "derived")

    if per_index == [] and Guard.inspect_lock(legacy) != :clean do
      [{"derived", legacy}]
    else
      per_index
    end
  end

  @doc """
  Takes a quiescent canonical snapshot of `kv` and rotates `primary` / `secondary`.

  `meta` must contain `%{tip: %{id, height, hash}, ends: %{outputs, inputs, witness}, wpruned: integer}`.

  Returns `{:ok, safe_wpruned}` where `safe_wpruned` is the minimum `wpruned`
  across all retained complete snapshots (`primary` and `secondary`, if present).
  The caller may safely delete witness segments `<= safe_wpruned` without
  breaking any retained snapshot.
  """
  def take_canonical!(%KV{} = kv, chain_dir, %{tip: _, ends: _, wpruned: _} = meta) do
    snaps = snapshots_dir(chain_dir)

    sentinel_payload = %{
      version: @version,
      kind: :canonical,
      tip: meta.tip,
      ends: meta.ends,
      wpruned: meta.wpruned,
      taken_at: System.os_time(:second)
    }

    rotate_checkpoint!(kv, snaps, sentinel_payload)
    {:ok, safe_wpruned(snaps)}
  end

  @doc """
  Takes a quiescent snapshot of a single-writer derived index DB (`store_dir/index`)
  and rotates `store_dir/snapshots/{primary,secondary}`. Must be called by that
  index's sole writer process between batches or on clean shutdown.
  """
  def take_derived!(%KV{} = kv, store_dir) do
    snaps = snapshots_dir(store_dir)

    sentinel_payload = %{
      version: @version,
      kind: :derived,
      taken_at: System.os_time(:second)
    }

    rotate_checkpoint!(kv, snaps, sentinel_payload)
    :ok
  end

  @doc """
  Minimum `wpruned` across all valid complete snapshots currently retained in
  `snaps_dir`, or `-1` if no complete snapshot exists.
  """
  def safe_wpruned(snaps_dir) do
    vals =
      for slot <- ["primary", "secondary"],
          {:ok, payload} <- [read_sentinel(Path.join(snaps_dir, slot))],
          is_integer(payload[:wpruned]),
          do: payload.wpruned

    case vals do
      [] -> -1
      list -> Enum.min(list)
    end
  end

  @doc """
  Returns the latest valid complete snapshot in `snaps_dir`:
  `{:ok, :primary | :secondary, dir, sentinel_payload}` or `{:error, :no_valid_snapshot}`.
  """
  def latest_valid(snaps_dir) do
    with {:error, _} <- check_slot(snaps_dir, :primary, "primary"),
         {:error, _} <- check_slot(snaps_dir, :secondary, "secondary") do
      {:error, :no_valid_snapshot}
    end
  end

  defp check_slot(snaps_dir, slot_atom, slot_name) do
    dir = Path.join(snaps_dir, slot_name)

    case read_sentinel(dir) do
      {:ok, payload} -> {:ok, slot_atom, dir, payload}
      {:error, _} = err -> err
    end
  end

  @doc """
  Restores the canonical store (and any dirty derived index stores) at
  `chain_dir` from their latest complete snapshots.

  Options:
  * `:hot` — hot archive directory (default `Path.join(chain_dir, "archive")`)
  * `:cold` — cold archive directory (default same as `:hot`)
  * `:force_from_snapshot` — allow restoring even if `flush.lock` records a
    latched storage fault (default `false`)
  * `:force` — restore canonical store even if its `flush.lock` is absent (default `false`)

  Returns:
  * `{:ok, :already_clean}` if canonical and all derived stores closed cleanly
    and `force: false`
  * `{:ok, %{canonical: :already_clean, derived: derived_map}}` if canonical
    closed cleanly (`force: false`) and one or more derived stores were restored
    or wiped
  * `{:ok, %{slot, tip, ends, wpruned, taken_at, derived}}` when the canonical
    store was restored
  """
  def restore!(chain_dir, opts \\ []) do
    hot = Keyword.get(opts, :hot, Path.join(chain_dir, "archive"))
    cold = Keyword.get(opts, :cold) || hot
    force_fault? = Keyword.get(opts, :force_from_snapshot, false)
    force_clean? = Keyword.get(opts, :force, false)

    canonical_state = Guard.inspect_lock(chain_dir)

    derived_states =
      for {name, dir} <- derived_store_dirs(chain_dir) do
        {name, dir, Guard.inspect_lock(dir)}
      end

    if not force_fault? do
      check_not_faulted!(chain_dir, "canonical", canonical_state)

      for {name, dir, state} <- derived_states do
        check_not_faulted!(dir, "derived:#{name}", state)
      end
    end

    dirty_derived? = Enum.any?(derived_states, fn {_, _, state} -> state != :clean end)

    cond do
      canonical_state == :clean and not force_clean? and not dirty_derived? ->
        {:ok, :already_clean}

      canonical_state == :clean and not force_clean? ->
        {:ok, %{canonical: :already_clean, derived: restore_derived!(chain_dir)}}

      true ->
        do_restore!(chain_dir, hot, cold)
    end
  end

  defp check_not_faulted!(dir, label, {:faulted, info}) do
    raise StorageError,
      source: :snapshot,
      reason: {:faulted_store_requires_force, info},
      message:
        "#{label} store at #{dir} halted after a latched storage fault " <>
          "(#{inspect(info[:source])} #{inspect(info[:reason])}: #{info[:message]}). " <>
          "Investigate hardware/software first, then re-run with --force-from-snapshot or resync"
  end

  defp check_not_faulted!(_dir, _label, _state), do: :ok

  @doc """
  Restores a dirty per-index derived store at `store_dir` (`derived/filters` or
  `derived/scripthash`) from `store_dir/snapshots/`, or wipes `store_dir` if no
  valid snapshot exists (so the index rebuilds cleanly from the canonical
  archive). Returns `:clean | {:restored, slot} | :wiped`.
  """
  def restore_derived_store!(store_dir) do
    if not File.dir?(store_dir) do
      :clean
    else
      case Guard.inspect_lock(store_dir) do
        :clean ->
          :clean

        _dirty ->
          snaps = snapshots_dir(store_dir)
          index_dir = Path.join(store_dir, "index")

          case latest_valid(snaps) do
            {:ok, slot, snap_dir, _payload} ->
              replace_db_from_snapshot!(store_dir, index_dir, snap_dir)
              Guard.remove_lock_for_restore!(store_dir)
              clean_staging!(snaps)
              {:restored, slot}

            {:error, :no_valid_snapshot} ->
              File.rm_rf!(store_dir)
              Guard.sync_dir!(Path.dirname(store_dir))
              :wiped
          end
      end
    end
  end

  @doc """
  Restores or wipes all dirty derived index stores under `chain_dir`.
  Returns a map of `%{name => :clean | {:restored, slot} | :wiped}`.
  """
  def restore_derived!(chain_dir) do
    for {name, dir} <- derived_store_dirs(chain_dir), into: %{} do
      {name, restore_derived_store!(dir)}
    end
  end

  # --- internals ---------------------------------------------------------------

  defp rotate_checkpoint!(%KV{guard: guard} = kv, snaps_dir, sentinel_payload) do
    Guard.check!(guard)
    File.mkdir_p!(snaps_dir)

    staging = Path.join(snaps_dir, "staging")
    staging_tmp = Path.join(snaps_dir, "staging.tmp")
    primary = Path.join(snaps_dir, "primary")
    secondary = Path.join(snaps_dir, "secondary")

    clean_path!(staging, guard)
    clean_path!(staging_tmp, guard)
    Guard.sync_dir!(snaps_dir, guard)

    # 1. Create RocksDB checkpoint in staging (flushes memtables, hard-links SSTs,
    #    copies MANIFEST & CURRENT with fsync).
    :ok = KV.checkpoint(kv, staging)

    # 2. Write checksummed SNAPSHOT_OK sentinel and fsync staging + parent.
    sentinel_path = Path.join(staging, @sentinel)

    case Guard.write_atomic_synced(sentinel_path, encode_sentinel(sentinel_payload)) do
      :ok ->
        :ok

      {:error, err} ->
        StorageError.raise_and_latch!(
          guard,
          :snapshot,
          {:write_sentinel, err},
          "failed to write snapshot sentinel #{sentinel_path}: #{inspect(err)}"
        )
    end

    Guard.sync_dir!(staging, guard)
    Guard.sync_dir!(snaps_dir, guard)

    # 3. Rotate primary -> secondary -> staging -> primary (each step + dir fsync).
    if File.exists?(secondary) do
      clean_path!(secondary, guard)
      Guard.sync_dir!(snaps_dir, guard)
    end

    if File.exists?(primary) do
      rename_checked!(primary, secondary, guard)
      Guard.sync_dir!(snaps_dir, guard)
    end

    rename_checked!(staging, primary, guard)
    Guard.sync_dir!(snaps_dir, guard)
    :ok
  end

  defp do_restore!(chain_dir, hot, cold) do
    snaps = snapshots_dir(chain_dir)

    {slot, snap_dir, sentinel} =
      case latest_valid(snaps) do
        {:ok, slot, dir, payload} ->
          {slot, dir, payload}

        {:error, :no_valid_snapshot} ->
          raise StorageError,
            source: :snapshot,
            reason: :no_valid_snapshot,
            message:
              "no valid snapshot found under #{snaps}; cannot restore store — full resync from the network is required"
      end

    # Verify snapshot RocksDB is readable and its meta["archive"] agrees with SNAPSHOT_OK.
    meta = verify_canonical_snapshot!(snap_dir, sentinel)
    ends = meta.ends
    wpruned = Map.get(meta, :wpruned, -1)

    # Verify all hot and cold committed segments exist and are >= committed offsets
    # BEFORE touching the live index or truncating anything.
    Segments.verify_committed_dir!(hot, :outputs, Map.fetch!(ends, :outputs), 0)
    Segments.verify_committed_dir!(cold, :inputs, Map.fetch!(ends, :inputs), 0)
    Segments.verify_committed_dir!(cold, :witness, Map.fetch!(ends, :witness), wpruned + 1)

    # Replace live index/ whole from a hard-linked clone of the snapshot.
    index_dir = Path.join(chain_dir, "index")
    replace_db_from_snapshot!(chain_dir, index_dir, snap_dir)

    # Truncate append-only segments to exact snapshot-recorded offsets.
    Segments.truncate_dir!(hot, :outputs, Map.fetch!(ends, :outputs), 0)
    Segments.truncate_dir!(cold, :inputs, Map.fetch!(ends, :inputs), 0)
    Segments.truncate_dir!(cold, :witness, Map.fetch!(ends, :witness), wpruned + 1)

    # Remove any witness segments already marked pruned in the restored snapshot.
    for seg <- 0..wpruned//1, do: Segments.remove_offline!(cold, :witness, seg)

    # Wipe ephemeral staging/ (pending blocks + ahead-of-tip headers).
    staging_db = Path.join(chain_dir, "staging")

    if File.exists?(staging_db) do
      File.rm_rf!(staging_db)
      Guard.sync_dir!(chain_dir)
    end

    # Handle derived/ if present and dirty.
    derived = restore_derived!(chain_dir)

    # Clean any partial staging checkpoint left behind by a crash during rotation.
    clean_staging!(snaps)

    # Release flush.lock after all files and directories are durable.
    Guard.remove_lock_for_restore!(chain_dir)

    {:ok,
     %{
       slot: slot,
       tip: sentinel.tip,
       ends: ends,
       wpruned: wpruned,
       taken_at: sentinel.taken_at,
       derived: derived
     }}
  end

  defp verify_canonical_snapshot!(snap_dir, sentinel) do
    {:ok, ro} =
      case KV.open_readonly(snap_dir, mode: :canonical) do
        {:ok, ro} ->
          {:ok, ro}

        {:error, reason} ->
          raise StorageError,
            source: :snapshot,
            reason: {:snapshot_open_failed, snap_dir, reason},
            message: "snapshot #{snap_dir} failed read-only verification: #{inspect(reason)}"
      end

    try do
      meta =
        case KV.get(ro, :meta, "archive") do
          {:ok, bin} ->
            try do
              :erlang.binary_to_term(bin)
            rescue
              e in ArgumentError ->
                raise StorageError,
                  source: :snapshot,
                  reason: {:corrupt_snapshot_meta, e},
                  message: "snapshot #{snap_dir} has corrupt archive metadata"
            end

          :not_found ->
            raise StorageError,
              source: :snapshot,
              reason: :missing_snapshot_meta,
              message: "snapshot #{snap_dir} is missing archive metadata"
        end

      if meta.tip != sentinel.tip.id or meta.ends != sentinel.ends or
           Map.get(meta, :wpruned, -1) != sentinel.wpruned do
        raise StorageError,
          source: :snapshot,
          reason: {:snapshot_meta_mismatch, sentinel, meta},
          message: "snapshot #{snap_dir} metadata does not match SNAPSHOT_OK sentinel"
      end

      meta
    after
      KV.close(ro)
    end
  end

  # Replaces `live_dir` atomically with a fresh clone of `snap_dir`, leaving
  # `snap_dir` completely untouched so a crash mid-restore is idempotent.
  defp replace_db_from_snapshot!(parent_dir, live_dir, snap_dir) do
    restore_tmp = live_dir <> ".restore"
    old_dir = live_dir <> ".old"

    if File.exists?(restore_tmp), do: File.rm_rf!(restore_tmp)
    if File.exists?(old_dir), do: File.rm_rf!(old_dir)
    Guard.sync_dir!(parent_dir)

    clone_rocksdb_dir!(snap_dir, restore_tmp)
    Guard.sync_dir!(restore_tmp)
    Guard.sync_dir!(parent_dir)

    if File.exists?(live_dir) do
      rename_checked!(live_dir, old_dir, nil)
      Guard.sync_dir!(parent_dir)
    end

    rename_checked!(restore_tmp, live_dir, nil)
    Guard.sync_dir!(parent_dir)

    if File.exists?(old_dir) do
      File.rm_rf!(old_dir)
      Guard.sync_dir!(parent_dir)
    end

    :ok
  end

  defp clone_rocksdb_dir!(src, dst) do
    File.mkdir_p!(dst)

    for name <- File.ls!(src),
        name != @sentinel and name != "LOCK" and not String.starts_with?(name, "LOG") do
      src_path = Path.join(src, name)
      dst_path = Path.join(dst, name)

      if File.regular?(src_path) do
        if String.ends_with?(name, ".sst") or String.ends_with?(name, ".blob") do
          case :file.make_link(String.to_charlist(src_path), String.to_charlist(dst_path)) do
            :ok -> :ok
            {:error, _} -> copy_file_synced!(src_path, dst_path)
          end
        else
          copy_file_synced!(src_path, dst_path)
        end
      end
    end

    :ok
  end

  defp copy_file_synced!(src, dst) do
    data = File.read!(src)

    with {:ok, fd} <- :file.open(dst, [:write, :raw, :binary]),
         :ok <- :file.write(fd, data),
         :ok <- :file.sync(fd),
         :ok <- :file.close(fd) do
      :ok
    else
      err ->
        raise StorageError,
          source: :snapshot,
          reason: {:copy_failed, src, dst, err},
          message: "failed to copy #{src} to #{dst}: #{inspect(err)}"
    end
  end

  defp clean_staging!(snaps_dir) do
    if File.dir?(snaps_dir) do
      removed? =
        Enum.reduce(["staging", "staging.tmp"], false, fn name, acc ->
          p = Path.join(snaps_dir, name)

          if File.exists?(p) do
            File.rm_rf!(p)
            true
          else
            acc
          end
        end)

      if removed?, do: Guard.sync_dir!(snaps_dir)
    end

    :ok
  end

  defp clean_path!(path, guard) do
    if File.exists?(path) do
      case File.rm_rf(path) do
        {:ok, _} ->
          :ok

        {:error, reason, bad_path} ->
          StorageError.raise_and_latch!(
            guard,
            :snapshot,
            {:rm_rf_failed, bad_path, reason},
            "failed to remove #{bad_path}: #{inspect(reason)}"
          )
      end
    end

    :ok
  end

  defp rename_checked!(from, to, guard) do
    case File.rename(from, to) do
      :ok ->
        :ok

      {:error, reason} ->
        StorageError.raise_and_latch!(
          guard,
          :snapshot,
          {:rename_failed, from, to, reason},
          "failed to rename #{from} -> #{to}: #{inspect(reason)}"
        )
    end
  end

  # --- sentinel encoding / decoding --------------------------------------------

  defp encode_sentinel(map) do
    body = [@tag, <<@version>>, :erlang.term_to_binary(map)]
    IO.iodata_to_binary([body, Exnode.Crypto.Hash.hash256(body)])
  end

  defp read_sentinel(dir) do
    path = Path.join(dir, @sentinel)

    case File.read(path) do
      {:ok, bin} -> decode_sentinel(bin)
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_sentinel(bin) when is_binary(bin) and byte_size(bin) > 32 do
    body = binary_part(bin, 0, byte_size(bin) - 32)
    sum = binary_part(bin, byte_size(bin) - 32, 32)

    if Exnode.Crypto.Hash.hash256(body) != sum do
      {:error, :checksum}
    else
      case body do
        <<@tag, @version, data::binary>> ->
          try do
            {:ok, :erlang.binary_to_term(data)}
          rescue
            _ -> {:error, :undecodable}
          end

        _ ->
          {:error, :unknown_format}
      end
    end
  end

  defp decode_sentinel(_), do: {:error, :truncated}
end
