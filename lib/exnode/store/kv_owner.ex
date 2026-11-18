defmodule Exnode.Store.KVOwner do
  @moduledoc """
  Closes the node's store when the node shuts down.

  The node opens the store before starting its children and hands the
  handle to them. Without an owner, the database (and its LOCK) would be
  released only once the VM freed the last copy of the handle, some time
  after the node stopped, so a node restarted on the same datadir in the
  same VM could find the store still held. The owner is the node's first
  child, so it stops last, after every process that uses the store.
  """
  use GenServer

  alias Exnode.Store.KV

  def start_link(%KV{} = kv), do: GenServer.start_link(__MODULE__, kv)

  def child_spec(kv),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [kv]}, shutdown: 60_000}

  @impl true
  def init(kv) do
    Process.flag(:trap_exit, true)
    {:ok, kv}
  end

  @impl true
  def handle_info({:EXIT, _, _}, kv), do: {:noreply, kv}

  # On every stop. The owner does no work of its own, so it only stops
  # when the node does: on shutdown, or when the root is killed (the exit
  # reaches this trapping process as `:killed`). It used to close only on
  # shutdown, and after an abnormal stop the handles kept in persistent_term
  # by the indexes pinned the database and its LOCK for the life of the VM:
  # a node restarted on the same datadir could not open it. erlang-rocksdb only flags the close; the database
  # is closed once NIF calls in progress have released their references.
  @impl true
  def terminate(_reason, kv), do: KV.close(kv)
end
