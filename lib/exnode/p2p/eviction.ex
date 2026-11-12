defmodule Exnode.P2P.Eviction do
  @moduledoc """
  Inbound peer eviction. Port of Core v32.1 `node/eviction.cpp`
  (`SelectNodeToEvict`, `ProtectEvictionCandidatesByRatio`,
  `EraseLastKElements` and the comparators).

  A candidate is a map with Core's `NodeEvictionCandidate` fields:
  `id`, `connected` (connect time; larger = more recent), `min_ping`
  (`:infinity` until a pong, as Core's `duration::max()`),
  `last_block_time`, `last_tx_time` (0 = never), `relevant_services`,
  `relay_txs`, `bloom_filter`, `keyed_netgroup`, `prefer_evict`, `is_local`,
  `network` (`:ipv4 | :ipv6 | :onion | :i2p | :cjdns | ...`), `noban`,
  `conn_type`.

  Each Core comparator is written as a sort key: candidates sort ascending
  by it (or descending, `{key, :desc}`), first = most likely evicted, and
  the last `k` are protected. Tuples compare element by element and
  `false < true`, so a key such as `{last_block_time, relevant_services,
  -connected}` is Core's three-way comparator. `:infinity` sorts above
  every number, as Core's `duration::max()`.

  Core sorts with `std::sort`, which is not stable, so ties between equal
  candidates are broken arbitrarily there; here sorts are stable (ties keep
  input order). Every rule and count is Core's.
  """

  @doc "Core `SelectNodeToEvict`: the id to evict, or nil."
  def select_node_to_evict(candidates) do
    cs =
      candidates
      # ProtectNoBanConnections, ProtectOutboundConnections
      |> Enum.reject(& &1.noban)
      |> Enum.filter(&(&1.conn_type == :inbound))
      # 4 by keyed netgroup, 8 by lowest ping, 4 by novel txs.
      |> erase_last_k({&netgroup_key/1, :asc}, 4)
      |> erase_last_k({&ping_key/1, :desc}, 8)
      |> erase_last_k({&tx_time_key/1, :asc}, 4)
      # Up to 8 non-tx-relay peers that sent novel blocks, then 4 by novel blocks.
      |> erase_last_k(
        {&block_relay_only_key/1, :asc},
        8,
        &(not &1.relay_txs and &1.relevant_services)
      )
      |> erase_last_k({&block_time_key/1, :asc}, 4)
      |> protect_by_ratio()

    if cs == [] do
      nil
    else
      # If any remaining peers are preferred for eviction, consider only them.
      cs = if Enum.any?(cs, & &1.prefer_evict), do: Enum.filter(cs, & &1.prefer_evict), else: cs
      group = most_connected_group(cs)
      Enum.find(cs, &(&1.keyed_netgroup == group)).id
    end
  end

  # Core: the netgroup with the most connections and the youngest member.
  # `cs` is sorted youngest first, so a group's first member is its youngest.
  # Core compares `size > most or (size == most and time > most_time)` as
  # each candidate is added: the tuple `{size, time}` compared strictly, so
  # on an exact tie the group that reached it first stays.
  defp most_connected_group(cs) do
    {_groups, {_score, group}} =
      Enum.reduce(cs, {%{}, {{0, nil}, nil}}, fn c, {groups, {best_score, _} = best} ->
        {size, time} = Map.get(groups, c.keyed_netgroup, {0, c.connected})
        score = {size + 1, time}
        best = if score > best_score, do: {score, c.keyed_netgroup}, else: best
        {Map.put(groups, c.keyed_netgroup, score), best}
      end)

    group
  end

  @doc """
  Core `ProtectEvictionCandidatesByRatio`: removes (protects) half of the
  candidates, up to a quarter of them from disadvantaged networks (CJDNS,
  I2P, localhost, onion), the rest by longest uptime.
  """
  def protect_by_ratio(cs) do
    initial = length(cs)
    total_protect = div(initial, 2)

    networks =
      [
        %{local: false, id: :cjdns},
        %{local: false, id: :i2p},
        %{local: true, id: nil},
        %{local: false, id: :onion}
      ]
      |> Enum.map(fn n -> Map.put(n, :count, Enum.count(cs, &on_net?(&1, n))) end)
      # Stable: equal counts keep this order.
      |> Enum.sort_by(& &1.count)

    {cs, protected} = protect_networks(cs, networks, div(total_protect, 2), 0)
    erase_last_k(cs, {&connected_key/1, :desc}, total_protect - protected)
  end

  # Core's `while (num_protected < max_protect_by_network)` loop: rounds over
  # the networks, each protecting up to an equal share of what is left,
  # until the limit is reached or a round protects no one.
  defp protect_networks(cs, _networks, max, protected) when protected >= max, do: {cs, protected}

  defp protect_networks(cs, networks, max, protected) do
    case Enum.count(networks, &(&1.count > 0)) do
      0 ->
        {cs, protected}

      num_networks ->
        per_network = max(div(max - protected, num_networks), 1)

        case protect_round(cs, networks, per_network, max, protected, []) do
          {cs, _networks, ^protected} -> {cs, protected}
          {cs, networks, protected} -> protect_networks(cs, networks, max, protected)
        end
    end
  end

  # One pass of Core's inner `for` over the networks. On reaching `max` Core
  # breaks out, and the outer loop ends too, so the networks left are not needed.
  defp protect_round(cs, [], _per, _max, protected, done), do: {cs, Enum.reverse(done), protected}

  defp protect_round(cs, [%{count: 0} = n | rest], per, max, protected, done),
    do: protect_round(cs, rest, per, max, protected, [n | done])

  defp protect_round(cs, [n | rest], per, max, protected, done) do
    left = erase_last_k(cs, {network_time_key(n), :asc}, per, &on_net?(&1, n))
    delta = length(cs) - length(left)

    if protected + delta >= max,
      do: {left, [], protected + delta},
      else:
        protect_round(left, rest, per, max, protected + delta, [
          %{n | count: n.count - delta} | done
        ])
  end

  defp on_net?(c, %{local: true}), do: c.is_local
  defp on_net?(c, %{id: net}), do: c.network == net

  # Core `EraseLastKElements`: sort (stably), then remove, among the last
  # `k`, those matching `pred`.
  defp erase_last_k(cs, {key, order}, k, pred \\ fn _ -> true end) do
    {head, tail} = cs |> Enum.sort_by(key, order) |> Enum.split(max(length(cs) - k, 0))
    head ++ Enum.reject(tail, pred)
  end

  # --- sort keys (Core's comparators) -------------------------------------------

  # CompareNetGroupKeyed
  defp netgroup_key(c), do: c.keyed_netgroup
  # ReverseCompareNodeMinPingTime: highest ping first.
  defp ping_key(c), do: c.min_ping
  # ReverseCompareNodeTimeConnected: most recent first.
  defp connected_key(c), do: c.connected
  # CompareNodeTXTime: oldest tx time, then non-relaying, then bloom filter, then most recent.
  defp tx_time_key(c), do: {c.last_tx_time, c.relay_txs, not c.bloom_filter, -c.connected}
  # CompareNodeBlockTime: oldest block time, then without relevant services, then most recent.
  defp block_time_key(c), do: {c.last_block_time, c.relevant_services, -c.connected}
  # CompareNodeBlockRelayOnlyTime: tx-relaying first, then as CompareNodeBlockTime.
  defp block_relay_only_key(c),
    do: {not c.relay_txs, c.last_block_time, c.relevant_services, -c.connected}

  # CompareNodeNetworkTime(is_local, network): non-local first (if is_local),
  # then not on `network`, then most recent.
  defp network_time_key(%{local: local, id: net}),
    do: fn c -> {local and c.is_local, c.network == net, -c.connected} end
end
