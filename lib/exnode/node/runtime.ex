defmodule Exnode.Node.Runtime do
  @moduledoc """
  Per-node runtime resource owner and lock-free handle registry.

  Sits first under `Exnode.Node` (`:rest_for_one`):
  * opens the node's RocksDB store (`Exnode.Store.KV`) in `init/1` and closes
    it in `terminate/2`, stopping last after every process that uses the store;
  * owns the per-node named ETS handle table (`Handles`, `:protected`,
    `read_concurrency: true`) for lock-free lookups of node-scoped resources
    (`:kv`, etc.).

  Also maintains the VM-wide `Exnode.Handles` ETS table (owned by the
  application supervisor via `Exnode.Application`) that maps registered
  component names (`{mod, server}`) to their published lock-free handles
  (`HeaderIndex`, `Chain.View`, `ScriptExec` worker fence pids, index `KV`
  handles) and tracks per-node and application-wide stopping flags.

  Using ETS instead of `:persistent_term` means starting/stopping nodes,
  restarting components, or losing/replacing `ScriptExec` workers never
  triggers a VM-wide global GC.
  """
  use GenServer

  alias Exnode.Store.KV

  @global_table Exnode.Handles

  # --- VM-wide handle registry (owned by Exnode.Application) ------------------

  @doc false
  def ensure_global_table do
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
  def init_global_table do
    ensure_global_table()
    :ok
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

  @doc "Reads `key` from `node_name`'s per-node `Handles` ETS table."
  def get(node_name, key, default \\ nil) do
    case :ets.lookup(handles_table(node_name), key) do
      [{^key, val}] -> val
      [] -> default
    end
  rescue
    ArgumentError -> default
  end

  @doc "Returns the open `%KV{}` handle for `node_name`."
  def kv(node_name \\ Exnode.Node) do
    :ets.lookup_element(handles_table(node_name), :kv, 2)
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
  * `:kv_path` + `:kv_opts` — opens RocksDB in `init/1` (used by `Exnode.Node`)
  * `:cleanup_keys` — list of global `Exnode.Handles` keys to erase on terminate
  """
  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    init_global_table()

    node_name = Keyword.get(opts, :node_name)
    cleanup_keys = Keyword.get(opts, :cleanup_keys, [])

    kv =
      case Keyword.fetch(opts, :kv) do
        {:ok, %KV{} = kv} ->
          kv

        :error ->
          # If a previous Node.Runtime was killed (:kill skips terminate/2),
          # stale global handle entries (BlockFilter, Scripthash, etc.) can
          # still hold references to the old %KV{} and pin the RocksDB LOCK.
          # Clearing them before KV.open/2 lets GC release the old handle.
          for k <- cleanup_keys, do: delete_handle(k)
          path = Keyword.fetch!(opts, :kv_path)
          kv_opts = Keyword.get(opts, :kv_opts, [])
          {:ok, kv} = KV.open(path, kv_opts)
          kv
      end

    table =
      if node_name do
        t =
          :ets.new(handles_table(node_name), [
            :named_table,
            :set,
            :protected,
            read_concurrency: true
          ])

        :ets.insert(t, {:kv, kv})
        t
      end

    {:ok, %{kv: kv, node_name: node_name, table: table, cleanup_keys: cleanup_keys}}
  end

  @impl true
  def handle_info({:EXIT, _, _}, st), do: {:noreply, st}

  @impl true
  def terminate(_reason, st) do
    for k <- st.cleanup_keys, do: delete_handle(k)

    if st.node_name do
      delete_handle({:stopping, st.node_name})
    end

    KV.close(st.kv)
  end
end
