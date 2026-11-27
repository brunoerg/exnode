defmodule Exnode.Node.Runtime do
  @moduledoc """
  Per-node runtime resource owner and lock-free handle registry.

  Sits first under `Exnode.Node` (`:rest_for_one`):
  * opens the node's RocksDB store (`Exnode.Store.KV`) in `init/1` and closes
    it in `terminate/2`, stopping last after every process that uses the store;
  * owns the per-node named ETS handle table (`Handles`, `:protected`,
    `read_concurrency: true`) for lock-free lookups of node-scoped resources
    (`:kv`, etc.).

  Also provides access to the VM-wide `Exnode.Handles` ETS table (owned by
  `Exnode.Node.Handles`, a permanent child under `Exnode.Supervisor`) that maps
  registered component names (`{mod, server}`) to their published lock-free
  handles (`HeaderIndex`, `Chain.View`, `ScriptExec` worker fence pids, index
  `KV` handles) and tracks per-node and application-wide stopping flags.

  Using ETS instead of `:persistent_term` means starting/stopping nodes,
  restarting components, or losing/replacing `ScriptExec` workers never
  triggers a VM-wide global GC.
  """
  use GenServer
  require Logger

  alias Exnode.Store.{Guard, KV, Snapshot}

  @global_table Exnode.Handles
  @derived_snapshot_ms 60_000

  # --- VM-wide handle registry (owned by Exnode.Node.Handles) -----------------

  defp ensure_global_table do
    case :ets.whereis(@global_table) do
      :undefined ->
        try do
          :ets.new(@global_table, [:named_table, :set, :public, read_concurrency: true])
        rescue
          ArgumentError -> @global_table
        end

      _tid ->
        @global_table
    end
  end

  @doc false
  def put_handle(key, value) do
    ensure_global_table()
    :ets.insert(@global_table, {key, value})
    :ok
  end

  @doc false
  def get_handle(key, default \\ nil) do
    case :ets.lookup(@global_table, key) do
      [{^key, val}] -> val
      [] -> default
    end
  rescue
    ArgumentError -> default
  end

  @doc false
  def delete_handle(key) do
    :ets.delete(@global_table, key)
    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc false
  def mark_app_stopping do
    ensure_global_table()
    :ets.insert(@global_table, {:app_stopping, true})
    :ok
  end

  @doc false
  def app_stopping? do
    case :ets.lookup(@global_table, :app_stopping) do
      [{:app_stopping, true}] -> true
      _ -> false
    end
  rescue
    ArgumentError -> false
  end

  # --- Per-node stopping flag -------------------------------------------------

  @doc """
  Marks node `name` (or `:all` nodes) as stopping. Stored as a single ETS entry
  in `Exnode.Handles` so no `:persistent_term` entry is created or mutated.
  """
  def mark_stopping(:all), do: mark_app_stopping()

  def mark_stopping(node_name) when is_atom(node_name) do
    ensure_global_table()
    :ets.insert(@global_table, {{:stopping, node_name}, true})
    :ok
  end

  @doc false
  def clear_stopping(node_name) when is_atom(node_name) do
    delete_handle({:stopping, node_name})
  end

  @doc "Whether node `name` is stopping (`Exnode.Node.stop/2`, or the application is)."
  def stopping?(node_name) do
    app_stopping?() or node_stopping?(node_name)
  end

  defp node_stopping?(node_name) when is_atom(node_name) do
    case :ets.lookup(@global_table, {:stopping, node_name}) do
      [{{:stopping, ^node_name}, true}] -> true
      _ -> false
    end
  rescue
    ArgumentError -> false
  end

  defp node_stopping?(_), do: false

  # --- Per-node Runtime process & Handles ETS table ---------------------------

  @doc "Named `:protected` ETS table owned by `node_name`'s `Runtime` process."
  def handles_table(node_name \\ Exnode.Node), do: Module.concat(node_name, Handles)

  @doc "Returns the open `%KV{}` handle for `node_name`."
  def kv(node_name \\ Exnode.Node) do
    :ets.lookup_element(handles_table(node_name), :kv, 2)
  end

  @doc "Returns the staging `%KV{}` handle for `node_name`, or `nil` if not split."
  def staging_kv(node_name \\ Exnode.Node) do
    store_kv(node_name, :staging_kv, nil)
  end

  @doc "Returns the derived `%KV{}` handle for `node_name`, falling back to canonical `:kv`."
  def derived_kv(node_name \\ Exnode.Node) do
    store_kv(node_name, :derived_kv, nil) || kv(node_name)
  end

  @doc "Returns the store `%KV{}` handle stored under `key` for `node_name`, or `default`."
  def store_kv(node_name, key, default \\ nil) do
    case :ets.lookup(handles_table(node_name), key) do
      [{^key, val}] -> val
      [] -> default
    end
  end

  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :id, __MODULE__),
      start: {__MODULE__, :start_link, [opts]},
      # Stops last, after all KV users; erlang-rocksdb close waits for NIF refs.
      shutdown: 60_000
    }
  end

  @doc """
  Starts a node runtime owner.

  Options:
  * `:name` — registered name for this process (optional)
  * `:node_name` — node prefix used to name the `:protected` `Handles` ETS table
    (when omitted, no per-node named table is created)
  * `:kv` — an already-opened `%KV{}` handle (for lightweight test setups), OR
  * `:kv_path` + `:kv_opts` — opens a single RocksDB store in `init/1`, OR
  * `:stores` — list of `{key, path, kv_opts}` store specs to open in `init/1`
    (used by `Exnode.Node` in split-store mode)
  * `:guards` — list of `Exnode.Store.Guard` locks managed by this runtime
  * `:node_pid` — `Exnode.Node` supervisor pid to halt on latched storage fault
  * `:cleanup_keys` — list of global `Exnode.Handles` keys to erase on terminate
  """
  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    ensure_global_table()

    node_name = Keyword.get(opts, :node_name)
    cleanup_keys = Keyword.get(opts, :cleanup_keys, [])
    guards = opts |> Keyword.get(:guards, []) |> Enum.reject(&is_nil/1)
    owner = self()

    for g <- guards do
      Guard.check!(g)
      Guard.set_on_fault(g, fn info -> send(owner, {:storage_fault, g.name, info}) end)
    end

    store_entries =
      case Keyword.fetch(opts, :stores) do
        {:ok, specs} ->
          for k <- cleanup_keys, do: delete_handle(k)
          open_stores!(specs, guards)

        :error ->
          case Keyword.fetch(opts, :kv) do
            {:ok, %KV{} = kv} ->
              [{:kv, kv}]

            :error ->
              # If a previous Node.Runtime was killed (:kill skips terminate/2),
              # stale global handle entries (BlockFilter, Scripthash, etc.) can
              # still hold references to the old %KV{} and pin the RocksDB LOCK.
              # Clearing them before KV.open/2 lets GC release the old handle.
              for k <- cleanup_keys, do: delete_handle(k)
              path = Keyword.fetch!(opts, :kv_path)
              kv_opts = Keyword.get(opts, :kv_opts, [])
              {:ok, kv} = KV.open(path, kv_opts)
              [{:kv, kv}]
          end
      end

    store_map = Map.new(store_entries)
    kvs = Enum.map(store_entries, &elem(&1, 1))

    table =
      if node_name do
        t =
          :ets.new(handles_table(node_name), [
            :named_table,
            :set,
            :protected,
            read_concurrency: true
          ])

        :ets.insert(t, store_entries)
        t
      end

    derived_kv = Map.get(store_map, :derived_kv)
    derived_guard = Keyword.get(opts, :derived_guard)
    chain_dir = Keyword.get(opts, :chain_dir)

    if derived_kv && chain_dir do
      Process.send_after(self(), :derived_snapshot, @derived_snapshot_ms)
    end

    {:ok,
     %{
       kv: Map.fetch!(store_map, :kv),
       kvs: kvs,
       guards: guards,
       node_name: node_name,
       node_pid: Keyword.get(opts, :node_pid),
       staging_kv: Map.get(store_map, :staging_kv),
       derived_kv: derived_kv,
       derived_guard: derived_guard,
       chain_dir: chain_dir,
       table: table,
       cleanup_keys: cleanup_keys,
       fault_triggered: false
     }}
  end

  @impl true
  def handle_info({:storage_fault, store_name, info}, st) do
    if not st.fault_triggered do
      Logger.critical(
        "stopping node immediately after latched storage fault on #{store_name}: #{inspect(info)}"
      )

      if is_pid(st.node_pid) do
        node_pid = st.node_pid

        spawn(fn ->
          try do
            Supervisor.stop(node_pid, {:shutdown, :storage_fault}, 30_000)
          catch
            :exit, _ -> :ok
          end
        end)
      end
    end

    {:noreply, %{st | fault_triggered: true}}
  end

  def handle_info(:derived_snapshot, %{derived_kv: dkv, derived_guard: dg, chain_dir: dir} = st)
      when dkv != nil and dir != nil do
    if not st.fault_triggered and not Guard.faulted?(dg) do
      try do
        Snapshot.take_derived!(dkv, dir)
      catch
        kind, reason ->
          Logger.error(
            "periodic derived snapshot failed: #{inspect(kind)} #{inspect(reason, limit: 5)}"
          )
      end
    end

    Process.send_after(self(), :derived_snapshot, @derived_snapshot_ms)
    {:noreply, st}
  end

  def handle_info({:EXIT, _, _}, st), do: {:noreply, st}
  def handle_info(_, st), do: {:noreply, st}

  @impl true
  def terminate(reason, st) do
    for k <- st.cleanup_keys, do: delete_handle(k)

    if st.node_name do
      delete_handle({:stopping, st.node_name})
    end

    clean_stop? = reason in [:normal, :shutdown] and not st.fault_triggered

    # Make `staging/` durable (fsync WAL + dir) BEFORE closing and removing
    # `flush.lock`, so a power loss after a clean shutdown never leaves an
    # unsynced staging WAL behind a missing lock.
    staging_synced? =
      if clean_stop? and st.staging_kv != nil do
        try do
          :ok = KV.sync_wal!(st.staging_kv)
          true
        catch
          kind, err ->
            Logger.error(
              "staging clean-close sync failed (retaining flush.lock): #{inspect(kind)} #{inspect(err, limit: 5)}"
            )

            false
        end
      else
        true
      end

    # Final snapshot for derived indexes on clean shutdown (after index processes stopped).
    if clean_stop? and st.derived_kv != nil and st.chain_dir != nil and
         not Guard.faulted?(st.derived_guard) do
      try do
        Snapshot.take_derived!(st.derived_kv, st.chain_dir)
      catch
        kind, err ->
          Logger.error(
            "final derived snapshot failed: #{inspect(kind)} #{inspect(err, limit: 5)}"
          )
      end
    end

    close_ok? =
      Enum.reduce(st.kvs, true, fn kv, ok ->
        ok and KV.close(kv) == :ok
      end)

    for g <- st.guards, g != nil do
      if clean_stop? and staging_synced? and close_ok? do
        _ = Guard.release_clean!(g)
      else
        Guard.abandon(g)
      end
    end

    :ok
  end

  defp open_stores!(specs, guards) do
    specs
    |> Enum.reduce([], fn {key, path, kv_opts}, opened ->
      case KV.open(path, kv_opts) do
        {:ok, kv} ->
          [{key, kv} | opened]

        {:error, reason} ->
          for {_, kv} <- opened, do: KV.close(kv)

          for g <- guards do
            Guard.latch_fault(
              g,
              :kv,
              {:open, path, reason},
              "cannot open store #{path}: #{inspect(reason)}"
            )

            Guard.abandon(g)
          end

          raise Exnode.StorageError,
            source: :kv,
            reason: {:open, path, reason},
            latched: guards != [],
            message: "cannot open store at #{path}: #{inspect(reason)}"
      end
    end)
    |> Enum.reverse()
  end
end
