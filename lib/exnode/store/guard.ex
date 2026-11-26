defmodule Exnode.Store.Guard do
  @moduledoc """
  Fail-stop store integrity guard: clean-close lock (`flush.lock`),
  permanent first-fault latch, and durable POSIX fsync helpers.

  Invariants enforced:
  * **Clean-close gate**: `acquire!/2` refuses to open a store if `flush.lock`
    already exists (unclean shutdown or prior latched storage fault). Before
    any database or segment file is opened for writing, `flush.lock` is
    created, fsynced, and its parent directory is fsynced.
  * **Unambiguous fault latching**: `latch_fault/4` atomically latches the
    first storage or integrity fault (`0 -> 1`, never cleared in-process),
    persists the fault details into `flush.lock`, and invokes `on_fault` once
    so the node stops immediately. Every subsequent `check!/1` raises
    `Exnode.StorageError` (`{:store_faulted, info}`).
  * **Clean release only**: `release_clean!/1` removes `flush.lock` (and
    fsyncs its directory) only when no fault has been latched and the store's
    writers completed a clean close (`chain_closed_clean?/1`). On any fault or
    unclean exit, `flush.lock` remains on disk so the store can only be
    restored from a quiescent snapshot or resynced from the network.
  """

  require Logger

  @lock_filename "flush.lock"
  @tag "exnode-flush-lock"
  @version 1

  # Atomic slots:
  #   1: fault latched (0 = healthy, 1 = faulted; monotonic 0 -> 1)
  #   2: clean close prepared by primary writer (0 = no, 1 = yes)
  @slot_fault 1
  @slot_clean 2

  defstruct [:dir, :lock_path, :state, :info_tab, :on_fault, :name]

  @type t :: %__MODULE__{}

  @doc "Path of the clean-close lock file inside `dir`."
  def lock_path(dir), do: Path.join(dir, @lock_filename)

  @doc """
  Inspects `flush.lock` in `dir` without modifying anything.

  Returns:
  * `:clean` — no `flush.lock` exists
  * `{:dirty, info}` — `flush.lock` exists with an open marker (unclean shutdown)
  * `{:faulted, info}` — `flush.lock` exists with a latched storage fault
  * `{:corrupt_lock, reason}` — `flush.lock` exists but cannot be decoded
  """
  def inspect_lock(dir) do
    path = lock_path(dir)

    case File.read(path) do
      {:error, :enoent} ->
        :clean

      {:error, reason} ->
        {:corrupt_lock, {:read_failed, reason}}

      {:ok, bin} ->
        decode_lock(bin)
    end
  end

  @doc """
  Acquires the clean-close lock for `dir` before opening the store.

  Refuses with `Exnode.StorageError` if `flush.lock` already exists. Creates
  `dir` if missing, atomically writes and fsyncs `flush.lock` (`O_CREAT | O_EXCL`),
  and fsyncs `dir`.

  Options:
  * `:name` — human-readable store label (default `"canonical"`)
  * `:on_fault` — 1-arity callback invoked once on the first latched fault
  * `:require_clean_mark` — if `true` (default), `release_clean!/1` requires
    `mark_clean_close!/1` to have been called first
  """
  def acquire!(dir, opts \\ []) do
    File.mkdir_p!(dir)
    path = lock_path(dir)
    name = Keyword.get(opts, :name, "canonical")

    case inspect_lock(dir) do
      :clean ->
        :ok

      {:dirty, info} ->
        raise Exnode.StorageError,
          source: :store_guard,
          reason: {:dirty_store, name, path, info},
          message:
            "#{name} store at #{dir} did not close cleanly (#{path} present; " <>
              "opened at #{inspect(info[:opened_at])}, os_pid #{inspect(info[:os_pid])}): " <>
              "refusing to open crashed store; run `mix exnode.restore` (or `bin/exnode-restore`) " <>
              "to restore from a snapshot, or resync from the network"

      {:faulted, info} ->
        raise Exnode.StorageError,
          source: :store_guard,
          reason: {:faulted_store, name, path, info},
          message:
            "#{name} store at #{dir} halted after a storage fault (#{path} present: " <>
              "#{inspect(info[:source])} #{inspect(info[:reason])} - #{info[:message]}): " <>
              "investigate hardware/software before running `mix exnode.restore --force-from-snapshot` or resyncing"

      {:corrupt_lock, reason} ->
        raise Exnode.StorageError,
          source: :store_guard,
          reason: {:corrupt_lock, name, path, reason},
          message:
            "#{name} store lock #{path} is unreadable/corrupt (#{inspect(reason)}): " <>
              "refusing to open store; restore from snapshot or resync"
    end

    open_info = %{
      status: :open,
      store: name,
      os_pid: System.pid(),
      opened_at: System.os_time(:second)
    }

    write_exclusive_synced!(path, encode_lock(open_info))
    sync_dir!(dir)

    state = :atomics.new(2, signed: false)
    :atomics.put(state, @slot_fault, 0)

    :atomics.put(
      state,
      @slot_clean,
      if(Keyword.get(opts, :require_clean_mark, true), do: 0, else: 1)
    )

    tab = :ets.new(:store_guard_info, [:set, :public, read_concurrency: true])

    %__MODULE__{
      dir: dir,
      lock_path: path,
      state: state,
      info_tab: tab,
      on_fault: Keyword.get(opts, :on_fault),
      name: name
    }
  end

  @doc "Updates the `on_fault` callback (e.g. once the supervising owner starts)."
  def set_on_fault(%__MODULE__{info_tab: tab} = guard, fun) when is_function(fun, 1) do
    :ets.insert(tab, {:on_fault, fun})
    guard
  end

  @doc "True if a storage fault has been latched on `guard`."
  def faulted?(nil), do: false
  def faulted?(%__MODULE__{state: state}), do: :atomics.get(state, @slot_fault) != 0

  @doc "The first latched fault map, or `nil` if healthy."
  def fault_info(nil), do: nil

  def fault_info(%__MODULE__{info_tab: tab}) do
    case :ets.lookup(tab, :fault) do
      [{:fault, info}] -> info
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  end

  @doc """
  Fast-path pre-operation check. Raises `Exnode.StorageError` if a fault has
  already been latched on `guard`. A `nil` guard is a no-op (standalone tests).
  """
  def check!(nil), do: :ok

  def check!(%__MODULE__{state: state} = guard) do
    if :atomics.get(state, @slot_fault) != 0 do
      info = fault_info(guard)

      raise Exnode.StorageError,
        source: :store_guard,
        reason: {:store_faulted, info},
        latched: true,
        message:
          "#{guard.name} store is halted after latched storage fault: " <>
            if(info,
              do: "#{inspect(info.source)} #{inspect(info.reason)} (#{info.message})",
              else: "unknown"
            )
    end

    :ok
  end

  @doc """
  Latches the first storage or integrity fault permanently (monotonic `0 -> 1`).

  Persists the fault record into `flush.lock` (best-effort atomic overwrite +
  fsync), logs a critical error, and invokes `on_fault` once. Subsequent calls
  are no-ops so the first fault is never masked by cascading errors.
  """
  def latch_fault(nil, _source, _reason, _message), do: :ok

  def latch_fault(%__MODULE__{state: state, info_tab: tab} = guard, source, reason, message) do
    if :atomics.compare_exchange(state, @slot_fault, 0, 1) == :ok do
      # Never allow a clean close after any fault.
      :atomics.put(state, @slot_clean, 0)

      info = %{
        status: :faulted,
        store: guard.name,
        source: source,
        reason: safe_reason(reason),
        message: to_string(message),
        at: System.os_time(:second),
        os_pid: System.pid()
      }

      try do
        :ets.insert(tab, {:fault, info})
      rescue
        ArgumentError -> :ok
      end

      Logger.critical(
        "STORAGE FAULT LATCHED on #{guard.name} store (#{inspect(source)}): " <>
          "#{inspect(reason)} — #{message}. Stopping store and retaining #{guard.lock_path}."
      )

      persist_fault_lock(guard.lock_path, info)

      callback =
        try do
          case :ets.lookup(tab, :on_fault) do
            [{:on_fault, fun}] -> fun
            [] -> guard.on_fault
          end
        rescue
          ArgumentError -> guard.on_fault
        end

      if is_function(callback, 1) do
        try do
          callback.(info)
        catch
          kind, err ->
            Logger.error("store fault callback failed: #{inspect(kind)} #{inspect(err)}")
        end
      end
    end

    :ok
  end

  @doc "Marks that the primary writer flushed, snapshotted, and closed cleanly."
  def mark_clean_close!(nil), do: :ok

  def mark_clean_close!(%__MODULE__{state: state}) do
    if :atomics.get(state, @slot_fault) == 0 do
      :atomics.put(state, @slot_clean, 1)
    end

    :ok
  end

  @doc "True if the primary writer completed a clean close with zero latched faults."
  def clean_close_ready?(nil), do: true

  def clean_close_ready?(%__MODULE__{state: state}) do
    :atomics.get(state, @slot_fault) == 0 and :atomics.get(state, @slot_clean) == 1
  end

  @doc """
  Removes `flush.lock` and fsyncs its parent directory ONLY if no fault was
  latched and `mark_clean_close!/1` was called (when required).

  Returns `:ok` if released cleanly, or `{:kept, reason}` if `flush.lock` was
  intentionally kept on disk.
  """
  def release_clean!(nil), do: :ok

  def release_clean!(%__MODULE__{} = guard) do
    result =
      cond do
        faulted?(guard) ->
          Logger.warning("retaining #{guard.lock_path}: storage fault was latched")
          {:kept, :faulted}

        not clean_close_ready?(guard) ->
          Logger.warning("retaining #{guard.lock_path}: store did not complete clean close")
          {:kept, :unclean}

        true ->
          case File.rm(guard.lock_path) do
            :ok ->
              sync_dir!(guard.dir)
              :ok

            {:error, :enoent} ->
              :ok

            {:error, reason} ->
              Logger.error("failed to remove #{guard.lock_path}: #{inspect(reason)}")
              {:kept, {:rm_failed, reason}}
          end
      end

    cleanup_tab(guard)
    result
  end

  @doc "Frees in-memory guard state while intentionally retaining `flush.lock` on disk."
  def abandon(%__MODULE__{} = guard) do
    cleanup_tab(guard)
    :ok
  end

  @doc "Removes `flush.lock` during explicit restore and fsyncs its directory."
  def remove_lock_for_restore!(dir) do
    path = lock_path(dir)

    case File.rm(path) do
      :ok ->
        :ok

      {:error, :enoent} ->
        :ok

      {:error, reason} ->
        raise Exnode.StorageError,
          source: :store_guard,
          reason: {:rm_lock_failed, path, reason},
          message: "cannot remove #{path} during restore: #{inspect(reason)}"
    end

    sync_dir!(dir)
  end

  # --- durable POSIX filesystem primitives -------------------------------------

  @doc """
  fsyncs directory `dir` (Linux/POSIX read-only directory handle).
  Raises `Exnode.StorageError` on failure (latching `guard` if provided).
  """
  def sync_dir!(dir, guard \\ nil) do
    with {:ok, fd} <- :file.open(String.to_charlist(dir), [:read, :raw, :directory]),
         :ok <- :file.sync(fd),
         :ok <- :file.close(fd) do
      :ok
    else
      err ->
        msg =
          "cannot fsync directory #{dir} (#{inspect(err)}): store durability contract violated"

        latch_fault(guard, :fsync_dir, {:fsync_dir, dir, err}, msg)

        raise Exnode.StorageError,
          source: :store_guard,
          reason: {:fsync_dir, dir, err},
          latched: guard != nil,
          message: msg
    end
  end

  @doc """
  Atomically writes `iodata` to `path`: writes to a sibling temporary file,
  fsyncs the file, closes it, renames over `path`, and fsyncs the parent dir.
  """
  def write_atomic_synced(path, iodata) do
    dir = Path.dirname(path)
    File.mkdir_p!(dir)
    tmp = path <> ".#{:erlang.unique_integer([:positive])}.tmp"

    with {:ok, fd} <- :file.open(tmp, [:write, :raw, :binary]),
         :ok <- :file.write(fd, iodata),
         :ok <- :file.sync(fd),
         :ok <- :file.close(fd),
         :ok <- File.rename(tmp, path) do
      sync_dir!(dir)
      :ok
    else
      err ->
        File.rm(tmp)
        {:error, err}
    end
  end

  # --- lock encoding / decoding ------------------------------------------------

  defp write_exclusive_synced!(path, bin) do
    with {:ok, fd} <- :file.open(path, [:write, :exclusive, :raw, :binary]),
         :ok <- :file.write(fd, bin),
         :ok <- :file.sync(fd),
         :ok <- :file.close(fd) do
      :ok
    else
      {:error, :eexist} ->
        raise Exnode.StorageError,
          source: :store_guard,
          reason: {:lock_exists, path},
          message: "lock #{path} appeared concurrently while opening store"

      err ->
        raise Exnode.StorageError,
          source: :store_guard,
          reason: {:write_lock, path, err},
          message: "cannot create store lock #{path}: #{inspect(err)}"
    end
  end

  defp persist_fault_lock(path, info) do
    case write_atomic_synced(path, encode_lock(info)) do
      :ok ->
        :ok

      {:error, err} ->
        Logger.error("could not update fault marker in #{path}: #{inspect(err)}")
        :ok
    end
  rescue
    e ->
      Logger.error("could not update fault marker in #{path}: #{Exception.message(e)}")
      :ok
  end

  defp encode_lock(map) when is_map(map) do
    body = [@tag, <<@version>>, :erlang.term_to_binary(map)]
    IO.iodata_to_binary([body, Exnode.Crypto.Hash.hash256(body)])
  end

  defp decode_lock(bin) when is_binary(bin) and byte_size(bin) > 32 do
    body = binary_part(bin, 0, byte_size(bin) - 32)
    sum = binary_part(bin, byte_size(bin) - 32, 32)

    if Exnode.Crypto.Hash.hash256(body) != sum do
      {:corrupt_lock, :checksum}
    else
      case body do
        <<@tag, @version, data::binary>> ->
          try do
            case :erlang.binary_to_term(data) do
              %{status: :faulted} = info -> {:faulted, info}
              %{status: :open} = info -> {:dirty, info}
              other -> {:corrupt_lock, {:unexpected_payload, other}}
            end
          rescue
            _ -> {:corrupt_lock, :undecodable}
          end

        _ ->
          {:corrupt_lock, :unknown_format}
      end
    end
  end

  defp decode_lock(_), do: {:corrupt_lock, :truncated}

  # Strip non-serializable or huge terms (like PIDs/refs/stacktraces) when persisting.
  defp safe_reason(reason) when is_atom(reason) or is_binary(reason) or is_number(reason),
    do: reason

  defp safe_reason(reason), do: inspect(reason, limit: 20)

  defp cleanup_tab(%__MODULE__{info_tab: tab}) do
    :ets.delete(tab)
  rescue
    ArgumentError -> :ok
  end
end
