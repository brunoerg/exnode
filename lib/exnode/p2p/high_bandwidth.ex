defmodule Exnode.P2P.HighBandwidth do
  @moduledoc """
  BIP152 high-bandwidth peer selection. Core v32.1
  `PeerManagerImpl::MaybeSetPeerAsAnnouncingHeaderAndIDs`
  (net_processing.cpp): the last 3 peers (`m_bip152_highbandwidth_to`) that
  delivered a new block are asked to announce new blocks directly as
  `cmpctblock` (`sendcmpct` with announce = 1). Adding a fourth demotes the
  oldest (`sendcmpct` with announce = 0), except that an inbound peer never
  displaces the last outbound one: it is moved to the second slot first, as
  in Core. A select for a peer that is already gone changes nothing; it
  used to demote a live peer and then leave its slot to the dead one until
  the DOWN.
  """
  use GenServer

  @max 3

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "`peer` delivered a new valid block and supports compact blocks v2."
  def select(server, peer, inbound? \\ false),
    do: GenServer.cast(server, {:select, peer, inbound?})

  def peers(server), do: GenServer.call(server, :peers, 5_000)

  # list: [{peer, inbound?}], oldest first.
  # monitors: %{peer => ref}
  @impl true
  def init(_opts), do: {:ok, %{list: [], monitors: %{}}}

  @impl true
  def handle_cast({:select, peer, inbound?}, %{list: list, monitors: monitors} = st) do
    cond do
      List.keymember?(list, peer, 0) ->
        {item, rest} = List.keytake(list, peer, 0)
        {:noreply, %{st | list: rest ++ [item]}}

      not Process.alive?(peer) ->
        {:noreply, st}

      true ->
        {list, monitors} =
          if length(list) >= @max do
            [{oldest, _} | rest] = protect_outbound(list, inbound?)
            send(oldest, {:send, {:sendcmpct, %{announce: false, version: 2}}})

            monitors =
              case Map.pop(monitors, oldest) do
                {nil, m} ->
                  m

                {ref, m} ->
                  Process.demonitor(ref, [:flush])
                  m
              end

            {rest, monitors}
          else
            {list, monitors}
          end

        monitors =
          if Map.has_key?(monitors, peer),
            do: monitors,
            else: Map.put(monitors, peer, Process.monitor(peer))

        send(peer, {:send, {:sendcmpct, %{announce: true, version: 2}}})
        {:noreply, %{st | list: list ++ [{peer, inbound?}], monitors: monitors}}
    end
  end

  # Core: when adding an inbound peer, do not remove the only outbound one:
  # if it is the oldest, swap it into the second slot.
  defp protect_outbound([{_, false} = first, second | rest] = list, true) do
    if Enum.count(list, fn {_, inb} -> not inb end) == 1, do: [second, first | rest], else: list
  end

  defp protect_outbound(list, _inbound?), do: list

  @impl true
  def handle_call(:peers, _from, st), do: {:reply, Enum.map(st.list, &elem(&1, 0)), st}

  @impl true
  def handle_info({:DOWN, ref, :process, peer, _}, st) do
    case Map.get(st.monitors, peer) do
      ^ref ->
        {:noreply,
         %{
           st
           | list: List.keydelete(st.list, peer, 0),
             monitors: Map.delete(st.monitors, peer)
         }}

      _ ->
        {:noreply, st}
    end
  end
end
