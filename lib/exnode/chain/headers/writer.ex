defmodule Exnode.Chain.Headers.Writer do
  @moduledoc """
  Persists accepted headers to the RocksDB `headers` column family for
  `Exnode.Chain.Headers`, so that process never waits on the KV.

  The KV is shared with the chain state, whose commit is one large synced
  write batch (seconds during IBD). RocksDB queues writers, so a small
  header write issued while a commit is in progress waits for it, even
  with `sync: false`. Done inside `Headers`, that wait stalled every
  peer delivering headers and every caller of the header tree.

  Writes are applied in the order they were sent (one sender, one
  mailbox). `write/2` returns at once; `write_sync/2` and `sync/1` return
  once everything sent before them is written, which keeps a status change
  (a `:failed` mark) from being overtaken by an older queued put.

  Started and linked by `Headers`, and traps exits: when `Headers` exits,
  the writes it queued before exiting are still applied (Erlang delivers a
  sender's messages before its exit signal), then this process stops.
  `Headers.terminate/2` stops it explicitly, so an orderly shutdown has
  written everything before the store closes.

  Durability is unchanged: writes were `sync: false` before and still are.
  A header lost on power failure is downloaded again.
  """
  use GenServer

  alias Exnode.Store.KV

  def start_link(kv), do: GenServer.start_link(__MODULE__, kv)

  @doc "Queues `ops` (KV ops on the `headers` column family). Returns at once."
  def write(w, ops), do: GenServer.cast(w, {:write, ops})

  @doc "Writes `ops` after everything queued before them, and waits."
  def write_sync(w, ops), do: GenServer.call(w, {:write, ops}, :infinity)

  @doc "Waits until everything queued so far is written."
  def sync(w), do: GenServer.call(w, :sync, :infinity)

  @doc """
  Writes everything queued so far, then stops. An ordinary call, not
  `GenServer.stop/3`: a system message can be handled ahead of queued
  writes (e.g. while the process is suspended), a call cannot.
  """
  def stop(w), do: GenServer.call(w, :stop, :infinity)

  @impl true
  def init(kv) do
    Process.flag(:trap_exit, true)
    {:ok, kv}
  end

  @impl true
  def handle_cast({:write, ops}, kv) do
    :ok = KV.write(kv, ops, sync: false)
    {:noreply, kv}
  end

  @impl true
  def handle_call({:write, ops}, _from, kv) do
    :ok = KV.write(kv, ops, sync: false)
    {:reply, :ok, kv}
  end

  def handle_call(:sync, _from, kv), do: {:reply, :ok, kv}
  def handle_call(:stop, _from, kv), do: {:stop, :normal, :ok, kv}
end
