defmodule Exnode.RPC.Net do
  @moduledoc """
  Core v32.1 `rpc/net.cpp` and `rpc/node.cpp` (`setmocktime`, `uptime`)
  JSON-RPC methods.
  """
  import Bitwise

  alias Exnode.Mempool.Policy
  alias Exnode.RPC.Methods
  import Exnode.RPC.JSON, only: [obj: 1, amount: 1]

  @rpc_misc_error -1
  @rpc_type_error -3
  @rpc_invalid_parameter -8

  @max_mocktime 0xFFFFFFFF

  # Core: setmocktime (rpc/node.cpp). The node's clock (Exnode.Clock) only:
  # timers keep their pace; Exnode.Node.tick/1 runs them now (tests).
  def setmocktime(params, ctx) do
    t = Methods.arg(params, 0)

    cond do
      ctx.params.network != :regtest ->
        {:error, @rpc_misc_error, "setmocktime is for regression testing (-regtest mode) only"}

      not is_integer(t) ->
        {:error, @rpc_type_error,
         "JSON value of type #{Methods.json_type(t)} is not of expected type number"}

      t < 0 or t > @max_mocktime ->
        {:error, @rpc_invalid_parameter,
         "Mocktime must be in the range [0, #{@max_mocktime}], not #{t}."}

      true ->
        Exnode.Clock.set(ctx.clock, t)
        {:ok, nil}
    end
  end

  def uptime(_params, ctx),
    do: {:ok, Methods.now(ctx) - Map.get(ctx, :started_at, Methods.now(ctx))}

  def getconnectioncount(_params, ctx),
    do: {:ok, map_size(Exnode.P2P.Connman.peers(ctx.connman))}

  # Core: getnetworkinfo (field set; values are exnode's)
  def getnetworkinfo(_params, ctx) do
    services = ctx.services
    peers = Exnode.P2P.Connman.peers(ctx.connman)
    inbound = Enum.count(peers, fn {_, p} -> p.type == :inbound end)

    inv =
      if ctx[:tx_relay] do
        try do
          Exnode.P2P.TxRelay.inv_stats(ctx.tx_relay)
        catch
          :exit, _ -> nil
        end
      end

    {:ok,
     obj([
       {"version", 320_100},
       {"subversion", ctx.user_agent},
       {"protocolversion", Exnode.P2P.Message.protocol_version()},
       {"localservices",
        services |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(16, "0")},
       {"localservicesnames", service_names(services)},
       {"localrelay", true},
       {"timeoffset", 0},
       {"tx_send_rate", 14},
       {"inv_buckets",
        obj([
          {"inbound", bucket_json(inv && inv[:inbound])},
          {"outbound", bucket_json(inv && inv[:outbound])}
        ])},
       {"networkactive", true},
       {"connections", map_size(peers)},
       {"connections_in", inbound},
       {"connections_out", map_size(peers) - inbound},
       {"networks",
        for(
          n <- ~w(ipv4 ipv6 onion i2p cjdns),
          do:
            obj([
              {"name", n},
              {"limited", n not in ~w(ipv4 ipv6)},
              {"reachable", n in ~w(ipv4 ipv6)},
              {"proxy", ""},
              {"proxy_randomize_credentials", false}
            ])
        )},
       {"relayfee", amount(Policy.default_min_relay_tx_fee())},
       {"incrementalfee", amount(Policy.default_incremental_relay_fee())},
       {"localaddresses", []},
       {"warnings", []}
     ])}
  end

  defp bucket_json(%{backlog: n, count_tok: c, size_tok: s}),
    do: obj([{"backlog", n}, {"count_tok", c}, {"size_tok", s}])

  defp bucket_json(_),
    do: obj([{"backlog", 0}, {"count_tok", 0}, {"size_tok", 0}])

  defp service_names(s) do
    for {name, bit} <- [
          {"NETWORK", 1},
          {"BLOOM", 4},
          {"WITNESS", 8},
          {"COMPACT_FILTERS", 64},
          {"NETWORK_LIMITED", 1024},
          {"P2P_V2", 2048}
        ],
        (s &&& bit) != 0,
        do: name
  end

  # Core: getpeerinfo (Core's field set; values from exnode's peer state)
  def getpeerinfo(_params, ctx) do
    peers = Exnode.P2P.Connman.peers(ctx.connman)

    list =
      peers
      |> Enum.with_index()
      |> Enum.map(fn {{pid, p}, id} ->
        info =
          try do
            Exnode.P2P.Peer.info(pid)
          catch
            :exit, _ -> %{}
          end

        {host, port} = p.target || {"", 0}
        svc = info[:services] || 0

        ping =
          if(info[:ping_ms], do: [{"pingtime", info.ping_ms / 1000}], else: []) ++
            cond do
              info[:min_ping_us] -> [{"minping", info.min_ping_us / 1_000_000}]
              info[:ping_ms] -> [{"minping", info.ping_ms / 1000}]
              true -> []
            end

        obj(
          [
            {"id", id},
            {"addr", "#{host}:#{port}"},
            {"network", if(String.contains?("#{host}", ":"), do: "ipv6", else: "ipv4")},
            {"services",
             svc |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(16, "0")},
            {"servicesnames", service_names(svc)},
            {"relaytxes", p.type != :block_relay and Map.get(info, :relay, true)},
            {"last_inv_sequence", 0},
            {"inv_to_send", 0},
            {"lastsend", info[:last_send] || 0},
            {"lastrecv", info[:last_recv] || 0},
            {"last_transaction", p[:last_tx] || 0},
            {"last_block", p[:last_block] || 0},
            {"bytessent", info[:bytes_sent] || 0},
            {"bytesrecv", info[:bytes_recv] || 0},
            {"conntime", info[:conntime] || 0},
            {"timeoffset", info[:timeoffset] || 0}
          ] ++
            ping ++
            [
              {"version", info[:version] || 0},
              {"subver", info[:user_agent] || ""},
              {"inbound", p.type == :inbound},
              {"bip152_hb_to", Map.get(info, :hb_to, false)},
              {"bip152_hb_from", Map.get(info, :hb_from, false)},
              {"startingheight", info[:start_height] || -1},
              {"presynced_headers", info[:presynced_headers] || -1},
              {"synced_headers", info[:best_known] || -1},
              {"synced_blocks", info[:synced_blocks] || info[:best_known] || -1},
              {"inflight", []},
              {"addr_relay_enabled", p.type != :block_relay},
              {"addr_processed", 0},
              {"addr_rate_limited", 0},
              {"permissions", []},
              {"minfeefilter", amount(info[:feefilter] || 0)},
              {"bytessent_per_msg", obj([])},
              {"bytesrecv_per_msg", obj([])},
              {"connection_type", conn_type(p.type)},
              {"transport_protocol_type", info[:transport_protocol_type] || "v1"},
              # Core: the hex session id for v2, "" otherwise.
              {"session_id",
               if(info[:session_id], do: Base.encode16(info.session_id, case: :lower), else: "")}
            ]
        )
      end)

    {:ok, list}
  end

  defp conn_type(:inbound), do: "inbound"
  defp conn_type(:block_relay), do: "block-relay-only"
  defp conn_type(:manual), do: "manual"
  defp conn_type(_), do: "outbound-full-relay"
end
