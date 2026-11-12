defmodule Exnode.ChainParams.SeedParser do
  @moduledoc """
  Parses Core's fixed-seed lists (`vendor/bitcoin/contrib/seeds/nodes_*.txt`,
  format in contrib/seeds/README.md and `generate-seeds.py`): one
  `<host>:<port>` per line, `#` comments, blank lines. Hosts are IPv4,
  `[IPv6]`, `<onion>.onion`, `<i2p>.b32.i2p`, or CJDNS (`fc00::/8`, written
  as IPv6; Core's generator treats that range as CJDNS, not RFC4193).

  Only IPv4 and IPv6 are returned as addresses: they are the networks exnode
  can reach, and Core adds fixed seeds only for reachable networks
  (`ThreadOpenConnections`, `GetReachableEmptyNetworks`).
  """

  @doc """
  One line: `{:ok, %{net, addr, port}}`, `:skip` (blank or comment),
  `{:unsupported, :onion | :i2p | :cjdns}`, or `{:error, reason}` (never raises).
  """
  def parse_line(line) when is_binary(line) do
    case line |> String.split("#", parts: 2) |> hd() |> String.trim() do
      "" -> :skip
      spec -> parse_spec(spec)
    end
  end

  @doc "A whole list: the addresses, in file order (unsupported, comment and bad lines left out)."
  def parse(text) when is_binary(text) do
    for line <- String.split(text, "\n"), {:ok, a} <- [parse_line(line)], do: a
  end

  defp parse_spec(spec) do
    with {:ok, host, port} <- split_host_port(spec) do
      cond do
        String.ends_with?(host, ".onion") -> {:unsupported, :onion}
        String.ends_with?(host, ".b32.i2p") -> {:unsupported, :i2p}
        true -> parse_ip(host, port)
      end
    end
  end

  defp split_host_port("[" <> rest) do
    case String.split(rest, "]:", parts: 2) do
      [host, port] -> with {:ok, p} <- port(port), do: {:ok, host, p}
      _ -> {:error, :bad_ipv6_spec}
    end
  end

  defp split_host_port(spec) do
    case String.split(spec, ":") do
      [host, port] -> with {:ok, p} <- port(port), do: {:ok, host, p}
      _ -> {:error, :bad_spec}
    end
  end

  defp port(s) do
    case Integer.parse(s) do
      {p, ""} when p in 0..65_535 -> {:ok, p}
      _ -> {:error, :bad_port}
    end
  end

  defp parse_ip(host, port) do
    case :inet.parse_strict_address(to_charlist(host)) do
      {:ok, {a, b, c, d}} ->
        {:ok, %{net: :ipv4, addr: <<a, b, c, d>>, port: port}}

      {:ok, {w0, _, _, _, _, _, _, _} = t} ->
        if Bitwise.bsr(w0, 8) == 0xFC,
          do: {:unsupported, :cjdns},
          else:
            {:ok,
             %{
               net: :ipv6,
               addr: for(x <- Tuple.to_list(t), into: <<>>, do: <<x::16>>),
               port: port
             }}

      {:error, _} ->
        {:error, :bad_address}
    end
  end
end
