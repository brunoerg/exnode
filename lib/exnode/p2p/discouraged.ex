defmodule Exnode.P2P.Discouraged do
  @moduledoc """
  The discouragement table (Core `BanMan::Discourage` / `IsDiscouraged`).

  Keys are IP addresses without port, `{:ipv4, <<_::32>>}` or
  `{:ipv6, <<_::128>>}` (`key/1`): Core `DiscourageAddress` keys on the
  address alone, so a misbehaving peer that reconnects from a new source
  port is still recognised. IPv4-mapped IPv6 addresses are folded into IPv4
  (as `CNetAddr` does). A DNS name has no key: it can only be a manual
  `-connect` target, which is never discouraged.

  Values are the insertion time (unix seconds). An entry expires after 24 h
  (Core `DEFAULT_MISBEHAVING_BANTIME`); expired entries count as absent and
  are pruned lazily. The table holds at most `cap` entries (default
  100,000); on overflow the oldest are evicted.

  Core persists discouragement in `banlist.json`; here the table is saved
  to `discouraged.dat` with `PeerFile` by its owner (Connman), periodically
  and at shutdown, never on each insert, so mass misbehaviour cannot force
  an fsync per event.
  """

  # banman.h DEFAULT_MISBEHAVING_BANTIME: 60 * 60 * 24
  @ttl_s 24 * 3600
  @default_cap 100_000

  defstruct entries: %{}, cap: @default_cap, dirty: false

  def ttl, do: @ttl_s

  def new(opts \\ []), do: %__MODULE__{cap: Keyword.get(opts, :cap, @default_cap)}

  @doc """
  The discouragement key of a peer address: `{host, port}` (host a string
  or an ip tuple), an AddrMan entry or key (`%{net, addr}` / `{net, addr,
  port}`). `nil` for DNS names and unknown networks (never discouraged).
  """
  def key({host, _port}) when is_binary(host) or is_list(host) do
    case :inet.parse_strict_address(to_charlist(host)) do
      {:ok, ip} -> key({ip, 0})
      _ -> nil
    end
  end

  def key({{a, b, c, d}, _port}), do: {:ipv4, <<a, b, c, d>>}
  def key({{0, 0, 0, 0, 0, 0xFFFF, x, y}, _port}), do: {:ipv4, <<x::16, y::16>>}

  def key({{_, _, _, _, _, _, _, _} = t, _port}),
    do: {:ipv6, for(x <- Tuple.to_list(t), into: <<>>, do: <<x::16>>)}

  def key({:ipv4, <<_::32>> = a, _port}), do: {:ipv4, a}
  def key({:ipv6, <<0::80, 0xFFFF::16, v4::binary-size(4)>>, _port}), do: {:ipv4, v4}
  def key({:ipv6, <<_::128>> = a, _port}), do: {:ipv6, a}
  def key(%{net: net, addr: addr}), do: key({net, addr, 0})
  def key(_), do: nil

  @doc """
  Core `CNetAddr::IsLocal` on a key: IPv4 127.0.0.0/8 or 0.0.0.0/8, or IPv6
  `::1` (IPv4-mapped addresses are already folded into IPv4 by `key/1`).
  Core `MaybeDiscourageAndDisconnect` disconnects such a peer but does not
  discourage it, since that would discourage every peer on the same local
  address.
  """
  def local?({:ipv4, <<a, _::24>>}) when a in [0, 127], do: true
  def local?({:ipv6, <<1::128>>}), do: true
  def local?(_), do: false

  @doc "Core `IsDiscouraged`: present and not expired at `now`."
  def member?(_t, nil, _now), do: false

  def member?(%__MODULE__{entries: e}, key, now) do
    case e do
      %{^key => at} -> now - at < @ttl_s
      _ -> false
    end
  end

  @doc "Core `Discourage`: records `key` at `now` and marks the table dirty."
  def put(t, nil, _now), do: t

  def put(%__MODULE__{} = t, key, now) do
    t = if map_size(t.entries) >= t.cap, do: prune(t, now), else: t
    t = %{t | entries: Map.put(t.entries, key, now), dirty: true}
    if map_size(t.entries) > t.cap, do: evict_oldest(t), else: t
  end

  @doc "Drops the expired entries."
  def prune(%__MODULE__{} = t, now) do
    kept = for {k, at} <- t.entries, now - at < @ttl_s, into: %{}, do: {k, at}
    if map_size(kept) == map_size(t.entries), do: t, else: %{t | entries: kept, dirty: true}
  end

  # Evicts the oldest entries down to 90 % of the cap, so a flood of inserts
  # at the cap pays one sort per cap/10 inserts, not one per insert.
  defp evict_oldest(t) do
    keep = div(t.cap * 9, 10)

    kept =
      t.entries
      |> Enum.sort_by(fn {_k, at} -> -at end)
      |> Enum.take(keep)
      |> Map.new()

    %{t | entries: kept}
  end

  def size(%__MODULE__{entries: e}), do: map_size(e)

  @doc "What is written to `discouraged.dat`: `%{key => inserted_at}`."
  def to_term(%__MODULE__{entries: e}), do: e

  @doc """
  A table from a file's term, without expired or malformed entries (and
  within the cap). Not dirty: it matches the file.
  """
  def from_term(term, now, opts \\ []) do
    t = new(opts)

    entries =
      for {k, at} <- (is_map(term) && term) || %{},
          is_integer(at),
          valid_key?(k),
          now - at < @ttl_s,
          into: %{},
          do: {k, at}

    t = %{t | entries: entries}
    if map_size(entries) > t.cap, do: evict_oldest(t), else: t
  end

  defp valid_key?({:ipv4, <<_::32>>}), do: true
  defp valid_key?({:ipv6, <<_::128>>}), do: true
  defp valid_key?(_), do: false
end
