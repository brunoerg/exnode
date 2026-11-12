defmodule Exnode.P2P.SyncState do
  @moduledoc """
  Shared header-sync bookkeeping, Core's `nSyncStarted` (net_processing.cpp
  `SendMessages`):

      if (!state.fSyncStarted && CanServeBlocks(peer) && !fImporting && !fReindex) {
          if ((nSyncStarted == 0 && fFetch) || m_best_header->Time() > now - 24h) { ...start... }

  Peers ask `try_start/4` before sending their first getheaders. A peer that
  exits is monitored and stops counting. Core also stops counting a NoBan
  peer whose headers sync timed out; exnode grants no NoBan permission, so a
  peer stops counting only when it exits.
  """
  use GenServer

  def start_link(opts), do: GenServer.start_link(__MODULE__, :ok, Keyword.take(opts, [:name]))

  @doc """
  Returns true if `peer` may start headers sync (and counts it as started).
  Waits like Core's peer thread on `cs_main` (no timeout); the peer's inactivity timeout bounds it.
  """
  def try_start(server, peer, preferred, best_header_recent),
    do: GenServer.call(server, {:try_start, peer, preferred, best_header_recent}, :infinity)

  @doc "The number of peers that started headers sync (Core `nSyncStarted`). Waits like `try_start/4`."
  def count(server), do: GenServer.call(server, :count, :infinity)

  @impl true
  def init(:ok), do: {:ok, %{started: %{}}}

  @impl true
  def handle_call({:try_start, peer, preferred, recent}, _from, st) do
    if Map.has_key?(st.started, peer) do
      {:reply, false, st}
    else
      if (map_size(st.started) == 0 and preferred) or recent do
        ref = Process.monitor(peer)
        {:reply, true, put_in(st.started[peer], ref)}
      else
        {:reply, false, st}
      end
    end
  end

  def handle_call(:count, _from, st), do: {:reply, map_size(st.started), st}

  @impl true
  def handle_info({:DOWN, _ref, :process, peer, _}, st),
    do: {:noreply, %{st | started: Map.delete(st.started, peer)}}
end
