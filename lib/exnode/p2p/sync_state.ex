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

  It also counts the outbound peers protected from chain-sync eviction
  (`try_protect/2`, Core `m_outbound_peers_with_protect_from_disconnect`).
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

  @doc """
  Returns true if `peer` may be protected from chain-sync eviction (and
  counts it), Core `m_outbound_peers_with_protect_from_disconnect` below
  MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT. A peer that exits stops
  counting. Waits like `try_start/4`.
  """
  def try_protect(server, peer), do: GenServer.call(server, {:try_protect, peer}, :infinity)

  # net_processing.cpp MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT
  @max_protected 4

  @impl true
  def init(:ok), do: {:ok, %{started: %{}, protected: %{}}}

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

  def handle_call({:try_protect, peer}, _from, st) do
    if Map.has_key?(st.protected, peer) or map_size(st.protected) >= @max_protected do
      {:reply, false, st}
    else
      ref = Process.monitor(peer)
      {:reply, true, put_in(st.protected[peer], ref)}
    end
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, peer, _}, st) do
    {:noreply,
     %{st | started: Map.delete(st.started, peer), protected: Map.delete(st.protected, peer)}}
  end
end
