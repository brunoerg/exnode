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
  def init(:ok), do: {:ok, %{started: MapSet.new(), protected: MapSet.new(), monitors: %{}}}

  @impl true
  def handle_call({:try_start, peer, preferred, recent}, _from, st) do
    if MapSet.member?(st.started, peer) do
      {:reply, false, st}
    else
      if (MapSet.size(st.started) == 0 and preferred) or recent do
        st = ensure_monitored(st, peer)
        {:reply, true, %{st | started: MapSet.put(st.started, peer)}}
      else
        {:reply, false, st}
      end
    end
  end

  def handle_call(:count, _from, st), do: {:reply, MapSet.size(st.started), st}

  def handle_call({:try_protect, peer}, _from, st) do
    if MapSet.member?(st.protected, peer) or MapSet.size(st.protected) >= @max_protected do
      {:reply, false, st}
    else
      st = ensure_monitored(st, peer)
      {:reply, true, %{st | protected: MapSet.put(st.protected, peer)}}
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, peer, _}, st) do
    case Map.get(st.monitors, peer) do
      ^ref ->
        {:noreply,
         %{
           st
           | started: MapSet.delete(st.started, peer),
             protected: MapSet.delete(st.protected, peer),
             monitors: Map.delete(st.monitors, peer)
         }}

      _ ->
        {:noreply, st}
    end
  end

  defp ensure_monitored(st, peer) do
    if Map.has_key?(st.monitors, peer) do
      st
    else
      %{st | monitors: Map.put(st.monitors, peer, Process.monitor(peer))}
    end
  end
end
