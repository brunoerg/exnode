defmodule Exnode.P2P.Peer do
  @moduledoc """
  One `:gen_statem` process per peer connection. Mirrors the per-peer parts of
  Core v32.1 `net_processing.cpp` (`ProcessMessage`, `SendMessages`): handshake,
  ping/pong, addr relay, headers-first sync with the low-work presync
  (`Exnode.P2P.Peer.HeadersHandler` / `HeadersSync`), block download and
  compact blocks (`Exnode.P2P.Peer.BlockSync`), transaction relay (through
  `TxRelay`), block and header serving (`Exnode.P2P.Peer.Serving`), and BIP157
  filter serving (`Exnode.P2P.FilterServing`).

  Transport framing, BIP324 encryption/v1 fallback, writer flow control, and
  `-maxsendbuffer` accounting live in `Exnode.P2P.Peer.Conn` and
  `Exnode.P2P.Peer.Writer`.

  States:
    * `:connecting` — outbound peer dialling `{host, port}`.
    * `:awaiting_socket` — inbound peer waiting for `{:socket_ready, sock}`.
    * `:awaiting_version` — socket attached; accepts only `:version`.
    * `:awaiting_verack` — `:version` received; accepts `:wtxidrelay`,
      `:sendaddrv2`, `:verack`.
    * `{:ready, :active}` — handshake complete; socket armed with `active: :once`.
    * `{:ready, :draining}` — `getdata_queue` non-empty; drains one pass per
      `:continue_getdata`, socket held unarmed until drained.
    * `{:ready, :paused}` — send buffer over `max_send_buffer` or
      `tx_in_flight >= max_tx_in_flight`; socket held unarmed until resumed.

  Isolation: protocol violations, malformed frames and decode failures end
  only this process. `Misbehaving` in v32.1 means disconnect and discourage
  (there is no score). The peer exits with `{:shutdown, {:misbehaving, why}}`
  and the connection manager discourages the address; a manual peer is
  kept, as Core's `MaybeDiscourageAndDisconnect` does. A message that fails
  to decode is dropped, not punished, as Core drops one that fails to
  deserialize.

  `node` (passed at start) is a map:
    params, headers, addrman, sync, connman (optional), local_nonces
    (optional Registry of outbound handshake nonces), services,
    user_agent, serve_headers (default true),
    clock (optional `Exnode.Clock`, the node's; nil: the system clock),
    tick_ms (optional, default 1 s; nil: no timer, tests tick explicitly)

  The tick (timeouts, pings, sync and block requests) also runs on
  `Exnode.Clock.tick/2`.
  """
  @behaviour :gen_statem

  require Logger
  import Bitwise

  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Clock
  alias Exnode.Codec.{Block, Tx}
  alias Exnode.Consensus

  alias Exnode.P2P.{
    AddrMan,
    AddrRate,
    Connman,
    DecodeBudget,
    FilterServing,
    HeadersSync,
    Message,
    NetAddr,
    TxRelay
  }

  alias Exnode.P2P.Peer.{BlockSync, Conn, Data, HeadersHandler, Serving}
  alias Exnode.P2P.Peer.Data.{Handshake, Proto}
  alias Exnode.Util.RollingBloom

  # net.cpp m_peer_connect_timeout default (DEFAULT_PEER_CONNECT_TIMEOUT)
  @handshake_timeout_s 60
  # Bound inbound :awaiting_socket so an orphaned Peer cannot leak if Listener crashes mid-handoff.
  @socket_handoff_timeout_ms 10_000
  # net_processing.cpp
  @ping_interval_s 120
  @timeout_interval_s 20 * 60
  @tick_ms 1_000

  @sendheaders_version 70012
  @short_ids_blocks_version 70014
  @wtxid_relay_version 70016
  # Core: node::MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER.
  @max_notfound_items 5_000 + 16

  # --- Supervision & API -----------------------------------------------------

  def child_spec(args) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [args]},
      restart: :temporary,
      shutdown: 5_000,
      type: :worker
    }
  end

  @doc """
  Starts a peer.
  * `connect: {host, port}`: outbound; dials the address.
  * inbound: caller hands over socket control with
    `:gen_tcp.controlling_process/2`, then sends `{:socket_ready, socket}`.
  `conn_type`: `:outbound_full_relay | :block_relay | :manual | :inbound | :feeler`.
  `v2: true` uses the BIP324 transport (Core `use_v2transport`): an
  outbound peer initiates v2; an inbound one detects v1 or v2 from the first
  bytes. An outbound v2 attempt that the remote closed before sending
  anything exits with `{:shutdown, {:reconnect_v1, reason}}` (Core
  `ShouldReconnectV1`), and the connection manager retries with v1.
  """
  def start_link(args), do: :gen_statem.start_link(__MODULE__, args, [])

  def info(pid), do: :gen_statem.call(pid, :info, 5_000)

  @doc false
  defdelegate select_txs(raw, ranges, indexes), to: Serving

  # --- :gen_statem callbacks -------------------------------------------------

  @impl :gen_statem
  def callback_mode, do: :handle_event_function

  @impl :gen_statem
  def init(args) do
    node = Map.fetch!(args, :node)
    conn_type = Map.fetch!(args, :conn_type)
    inbound = conn_type == :inbound

    conn_opts =
      [
        magic: node.params.magic,
        inbound: inbound,
        v2: Map.get(args, :v2, false)
      ] ++
        if(Map.has_key?(node, :socket_send), do: [send_fun: node.socket_send], else: []) ++
        if(Map.has_key?(node, :send_timeout_ms),
          do: [send_timeout_ms: node.send_timeout_ms],
          else: []
        ) ++
        if(Map.has_key?(node, :max_send_buffer),
          do: [max_send_buffer: node.max_send_buffer],
          else: []
        )

    data = %Data{
      node: node,
      p: node.params,
      conn_type: conn_type,
      inbound: inbound,
      target: args[:target],
      conn: Conn.new(conn_opts),
      handshake: %Handshake{local_nonce: rand64()},
      proto: nil
    }

    case args[:connect] do
      {host, port} ->
        {:ok, :connecting, %{data | target: {host, port}}, [{:next_event, :internal, :connect}]}

      nil ->
        timeout = Map.get(args, :socket_timeout_ms, @socket_handoff_timeout_ms)
        {:ok, :awaiting_socket, data, [{:state_timeout, timeout, :socket_timeout}]}
    end
  end

  @impl :gen_statem
  def terminate(reason, _state, %Data{conn: conn}) do
    Conn.flush_on_terminate(conn, reason)
  end

  # --- :connecting & :awaiting_socket ----------------------------------------

  @impl :gen_statem
  def handle_event(:internal, :connect, :connecting, %Data{target: target} = data) do
    t = now(data)

    case Conn.connect(data.conn, target, t) do
      {:ok, conn} ->
        data =
          %{data | conn: conn}
          |> Data.update_handshake(&%{&1 | connected_at: t})
          |> send_version()

        {:next_state, :awaiting_version, data, tick_actions(data)}

      {:error, reason} ->
        {:stop, {:shutdown, {:connect_failed, reason}}, data}
    end
  end

  def handle_event(:info, {:socket_ready, sock}, :awaiting_socket, %Data{} = data) do
    t = now(data)
    conn = Conn.attach(data.conn, sock, t)

    data =
      %{data | conn: conn}
      |> Data.update_handshake(&%{&1 | connected_at: t})

    {:next_state, :awaiting_version, data, tick_actions(data)}
  end

  def handle_event(:state_timeout, :socket_timeout, :awaiting_socket, %Data{} = data) do
    {:stop, {:shutdown, :socket_timeout}, data}
  end

  # --- Calls (valid in all states) -------------------------------------------

  def handle_event({:call, from}, :info, state, %Data{} = data) do
    {:keep_state_and_data, [{:reply, from, build_info(state, data)}]}
  end

  # --- Clock & periodic tick (valid in all states) ---------------------------

  def handle_event({:timeout, :tick}, :tick, state, %Data{} = data) do
    case run_tick(state, data) do
      {:ok, next_state, data} ->
        transition(state, next_state, data, tick_actions(data))

      {:stop, reason, data} ->
        {:stop, reason, data}
    end
  end

  def handle_event(:info, {Clock, :tick, from, ref}, state, %Data{} = data) do
    case run_tick(state, data) do
      {:ok, next_state, data} ->
        Clock.ticked({from, ref})
        transition(state, next_state, data, [])

      {:stop, reason, data} ->
        {:stop, reason, data}
    end
  end

  # --- Disconnect & socket errors (valid in all states) ----------------------

  def handle_event(:info, {:disconnect, reason}, _state, %Data{} = data) do
    {:stop, {:shutdown, reason}, data}
  end

  def handle_event(:info, {:send_failed, reason}, _state, %Data{} = data) do
    {:stop, {:shutdown, {:send_failed, reason}}, data}
  end

  def handle_event(:info, {:tcp_closed, _}, _state, %Data{} = data) do
    age = if data.handshake.connected_at, do: now(data) - data.handshake.connected_at, else: nil
    ua = data.handshake.version && data.handshake.version.user_agent
    closing(data, {:closed, %{age_s: age, ua: ua, recent: Enum.reverse(data.trace)}})
  end

  def handle_event(:info, {:tcp_error, _, reason}, _state, %Data{} = data) do
    closing(data, {:tcp_error, reason})
  end

  # --- Writer accounting ({:sent, n}) ----------------------------------------

  def handle_event(:info, {:sent, n}, state, %Data{} = data) do
    {resumed?, conn} = Conn.on_sent(data.conn, n, now(data))
    data = %{data | conn: conn}

    if resumed? do
      send(self(), :continue_getdata)
    end

    transition(state, flow_state(state, data), data, [])
  end

  # --- TCP incoming bytes (connected states) ---------------------------------

  def handle_event(
        :info,
        {:tcp, sock, bytes},
        state,
        %Data{conn: %Conn{socket: sock}} = data
      )
      when state in [:awaiting_version, :awaiting_verack] or elem(state, 0) == :ready do
    case Conn.on_tcp(data.conn, bytes, now(data)) do
      {:v1, conn} ->
        drain(state, %{data | conn: conn}) |> rearm_and_reply(state)

      {:v2, conn, msgs} ->
        dispatch(state, %{data | conn: conn}, msgs) |> rearm_and_reply(state)

      {:error, reason} ->
        {:stop, {:shutdown, reason}, data}
    end
  end

  # --- Getdata & pause resume ------------------------------------------------

  def handle_event(:info, :continue_getdata, {:ready, _} = state, %Data{} = data) do
    case Serving.process_getdata(data) do
      {:ok, data} ->
        if getdata_pending?(data) do
          transition(state, flow_state(state, data), data, [])
        else
          result =
            if Conn.v1?(data.conn) do
              drain(state, data)
            else
              {msgs, conn} = Conn.take_pending(data.conn)
              dispatch(state, %{data | conn: conn}, msgs)
            end

          rearm_and_reply(result, state)
        end

      {:stop, reason, data} ->
        {:stop, reason, data}
    end
  end

  def handle_event(:info, :continue_getdata, state, %Data{} = data)
      when state in [:awaiting_version, :awaiting_verack] do
    # Send buffer resumed during handshake (e.g., after v2/version burst).
    result =
      if Conn.v1?(data.conn) do
        drain(state, data)
      else
        {msgs, conn} = Conn.take_pending(data.conn)
        dispatch(state, %{data | conn: conn}, msgs)
      end

    rearm_and_reply(result, state)
  end

  # --- Ready-only asynchronous events ----------------------------------------

  def handle_event(:info, :request_blocks, {:ready, _} = state, %Data{} = data) do
    data = BlockSync.maybe_request_blocks(data)
    transition(state, flow_state(state, data), data, [])
  end

  def handle_event(:info, :novel_tx, {:ready, _}, %Data{} = data) do
    {:keep_state, report_stats(data, %{last_tx_time: now(data)})}
  end

  def handle_event(
        :info,
        {:block_checked, hash, {:error, {result, reason}}},
        {:ready, _} = state,
        %Data{proto: %Proto{} = proto} = data
      ) do
    via_compact = hash in proto.rebuilt_deferred
    data = %{data | proto: %{proto | rebuilt_deferred: List.delete(proto.rebuilt_deferred, hash)}}

    case BlockSync.maybe_punish_for_block(data, result, "invalid block: #{reason}", via_compact) do
      {:ok, data} -> transition(state, flow_state(state, data), data, [])
      {:stop, reason, data} -> {:stop, reason, data}
    end
  end

  def handle_event(
        :info,
        {:send, {:sendcmpct, %{announce: a}} = msg},
        state,
        %Data{conn: %Conn{socket: s}, proto: nil} = data
      )
      when s != nil do
    # Allow HighBandwidth / callers that race verack to select hb_selected once
    # socket is attached; carry into Proto on verack via pending_hb_selected.
    data =
      data
      |> Data.update_handshake(&%{&1 | pending_hb_selected: a})
      |> push(msg)

    transition(state, flow_state(state, data), data, [])
  end

  def handle_event(
        :info,
        {:send, {:sendcmpct, %{announce: a}} = msg},
        {:ready, _} = state,
        %Data{conn: %Conn{socket: s}} = data
      )
      when s != nil do
    data =
      data
      |> Data.update_proto(&%{&1 | hb_selected: a})
      |> push(msg)

    transition(state, flow_state(state, data), data, [])
  end

  def handle_event(
        :info,
        {:send, msg},
        state,
        %Data{conn: %Conn{socket: s}} = data
      )
      when s != nil do
    data = push(data, msg)
    transition(state, flow_state(state, data), data, [])
  end

  def handle_event(:info, :tx_relay_resync, {:ready, _}, %Data{} = data) do
    tx_relay_connected(data)
    :keep_state_and_data
  end

  # TxRelay notifies Peer when an in-flight tx finishes validation.
  def handle_event(
        :info,
        {:tx_done, _ref},
        {:ready, _} = state,
        %Data{proto: %Proto{} = proto} = data
      ) do
    was_paused = paused?(data)
    data = %{data | proto: %{proto | tx_in_flight: max(proto.tx_in_flight - 1, 0)}}
    next = flow_state(state, data)

    if was_paused and not paused?(data) do
      send(self(), :continue_getdata)
    end

    transition(state, next, data, [])
  end

  def handle_event(:info, _msg, _state, _data) do
    :keep_state_and_data
  end

  # --- Frame & message dispatch ----------------------------------------------

  defp drain(state, data) do
    if blocked?(data) do
      {:ok, flow_state(state, data), data}
    else
      case Conn.next_v1_frame(data.conn) do
        {:more, conn} ->
          data = %{data | conn: conn}
          {:ok, flow_state(state, data), data}

        {:error, reason} ->
          {:stop, {:shutdown, {:bad_frame, reason}}, data}

        {:reject, _cmd, conn} ->
          drain(state, %{data | conn: conn})

        {:ok, cmd, payload, conn} ->
          case process_message(state, %{data | conn: conn}, cmd, payload) do
            {:ok, next_state, data} -> drain(next_state, data)
            {:stop, reason, data} -> {:stop, reason, data}
          end
      end
    end
  end

  defp dispatch(state, data, []), do: {:ok, flow_state(state, data), data}

  defp dispatch(state, data, msgs) do
    if blocked?(data),
      do: {:ok, flow_state(state, data), %{data | conn: Conn.append_pending(data.conn, msgs)}},
      else: dispatch_now(state, data, msgs)
  end

  defp dispatch_now(state, data, []), do: {:ok, flow_state(state, data), data}
  defp dispatch_now(state, data, [:reject | rest]), do: dispatch(state, data, rest)

  defp dispatch_now(state, data, [{:msg, cmd, payload} | rest]) do
    case process_message(state, data, cmd, payload) do
      {:ok, next_state, data} -> dispatch(next_state, data, rest)
      {:stop, reason, data} -> {:stop, reason, data}
    end
  end

  defp rearm_and_reply({:ok, next_state, data}, prev_state) do
    if not blocked?(data), do: Conn.rearm(data.conn)
    transition(prev_state, next_state, data, [])
  end

  defp rearm_and_reply({:stop, reason, data}, _prev_state) do
    {:stop, reason, data}
  end

  defp transition(state, state, data, []), do: {:keep_state, data}
  defp transition(state, state, data, actions), do: {:keep_state, data, actions}
  defp transition(_old, next, data, []), do: {:next_state, next, data}
  defp transition(_old, next, data, actions), do: {:next_state, next, data, actions}

  defp flow_state({:ready, _}, data) do
    cond do
      paused?(data) -> {:ready, :paused}
      getdata_pending?(data) -> {:ready, :draining}
      true -> {:ready, :active}
    end
  end

  defp flow_state(state, _data), do: state

  @doc false
  def getdata_pending?(%Data{proto: nil}), do: false
  def getdata_pending?(%Data{proto: %Proto{getdata_queue: q}}), do: not :queue.is_empty(q)

  @doc false
  def paused?(%Data{conn: conn, proto: nil}), do: Conn.paused?(conn)

  def paused?(%Data{conn: conn, proto: %Proto{tx_in_flight: n, max_tx_in_flight: max}}),
    do: Conn.paused?(conn) or (is_integer(max) and n >= max)

  defp blocked?(data), do: getdata_pending?(data) or paused?(data)

  defp process_message({:ready, _} = state, data, "block", payload) do
    data = Data.trace(data, {:in, "block"})
    wrap_ready(state, BlockSync.received_block_payload(data, payload))
  end

  defp process_message(state, data, cmd, payload) do
    case DecodeBudget.with_budget(data.node[:decode_budget], byte_size(payload), fn ->
           decode_and_handle(state, data, cmd, payload)
         end) do
      :unavailable -> {:stop, {:shutdown, :decode_budget_unavailable}, data}
      result -> result
    end
  end

  defp decode_and_handle(state, data, cmd, payload) do
    data = Data.trace(data, {:in, cmd})

    case Message.decode(cmd, payload) do
      {:ok, msg} ->
        handle_msg(state, msg, data)

      {:unknown, _} ->
        {:ok, state, data}

      {:error, {kind, _}}
      when kind in [:too_many_headers, :inv_too_large, :addr_too_large, :locator_too_large] and
             state in [:awaiting_version, :awaiting_verack] ->
        Logger.debug("peer #{inspect(data.target)}: #{cmd} before the handshake, ignored")
        {:ok, state, data}

      {:error, {:locator_too_large, _n}} ->
        {:stop, {:shutdown, :locator_too_large}, data}

      {:error, {:too_many_headers, n}} ->
        wrap_ready(state, misbehaving(data, "headers message size = #{n}"))

      {:error, {:inv_too_large, n}} ->
        wrap_ready(state, misbehaving(data, "inv message size = #{n}"))

      {:error, {:addr_too_large, n}} ->
        wrap_ready(state, misbehaving(data, "addr message size = #{n}"))

      {:error, reason} ->
        Logger.debug("peer #{inspect(data.target)}: #{cmd} decode error #{inspect(reason)}")
        {:ok, state, data}
    end
  end

  defp wrap_ready(state, {:ok, data}), do: {:ok, flow_state(state, data), data}
  defp wrap_ready(_state, {:stop, reason, data}), do: {:stop, reason, data}

  defp closing(data, reason) do
    if Conn.should_reconnect_v1?(data.conn),
      do: {:stop, {:shutdown, {:reconnect_v1, reason}}, data},
      else: {:stop, {:shutdown, reason}, data}
  end

  # --- Handshake state message handlers --------------------------------------

  # :awaiting_version accepts only :version; all other messages are ignored.
  defp handle_msg(:awaiting_version, {:version, v}, data) do
    desirable = Message.service(:network) ||| Message.service(:witness)
    expects_services = data.conn_type in [:outbound_full_relay, :block_relay]

    cond do
      expects_services and (v.services &&& desirable) != desirable ->
        {:stop, {:shutdown, {:missing_services, v.services}}, data}

      v.version < Message.min_peer_proto_version() ->
        {:stop, {:shutdown, {:obsolete_version, v.version}}, data}

      connected_to_self?(data, v.nonce) ->
        {:stop, {:shutdown, :connected_to_self}, data}

      data.conn_type == :feeler ->
        if data.node[:connman],
          do: send(data.node.connman, {:peer_ready, self(), data.target, :feeler, v.services})

        data = Data.update_handshake(data, &%{&1 | version: v})
        {:stop, {:shutdown, :feeler_done}, data}

      true ->
        data = Data.update_handshake(data, &%{&1 | version: v})
        data = if data.inbound, do: send_version(data), else: data
        common = min(v.version, Message.protocol_version())
        data = if common >= @wtxid_relay_version, do: push(data, :wtxidrelay), else: data
        data = if common >= 70016, do: push(data, :sendaddrv2), else: data

        if (not data.inbound and data.node[:addrman]) && data.target,
          do: AddrMan.set_services(data.node.addrman, AddrMan.key(target_addr(data)), v.services)

        relay = v.relay != false and data.conn_type != :block_relay
        stats = %{relay_txs: relay, relevant_services: desirable_services?(data, v.services)}
        data = report_stats(data, stats)

        if data.inbound and relay and data.node[:connman] != nil and
             Connman.tx_relay_capacity(data.node.connman, stats) == :disconnect do
          {:stop, {:shutdown, :tx_relay_capacity}, data}
        else
          {:ok, :awaiting_verack, push(data, :verack)}
        end
    end
  end

  defp handle_msg(:awaiting_version, _msg, data), do: {:ok, :awaiting_version, data}

  # :awaiting_verack accepts :wtxidrelay, :sendaddrv2, :verack; duplicate :version or others ignored.
  defp handle_msg(:awaiting_verack, :wtxidrelay, data) do
    wtxid = common_version(data) >= @wtxid_relay_version
    {:ok, :awaiting_verack, Data.update_handshake(data, &%{&1 | wtxid_relay: wtxid})}
  end

  defp handle_msg(:awaiting_verack, :sendaddrv2, data) do
    {:ok, :awaiting_verack, Data.update_handshake(data, &%{&1 | addrv2: true})}
  end

  defp handle_msg(:awaiting_verack, :verack, data) do
    common = common_version(data)
    t = now(data)

    if data.node[:local_nonces],
      do: Registry.unregister(data.node.local_nonces, data.handshake.local_nonce)

    view = data.node[:chain_state] && ChainState.view(data.node.chain_state)
    announced = if view, do: ChainState.view_tip(view).hash, else: nil

    proto = %Proto{
      next_ping_at: t,
      addr_rate: AddrRate.new(Clock.mono(data.node[:clock])),
      announced: announced,
      hb_selected: data.handshake.pending_hb_selected,
      max_tx_in_flight: Map.get(data.node, :max_tx_in_flight, :infinity)
    }

    data = %{data | proto: proto}
    data = if common >= @sendheaders_version, do: push(data, :sendheaders), else: data

    data =
      if common >= @short_ids_blocks_version,
        do: push(data, {:sendcmpct, %{announce: false, version: 2}}),
        else: data

    data =
      if data.conn_type in [:outbound_full_relay, :manual] do
        data
        |> push(:getaddr)
        |> Data.update_proto(&%{&1 | addr_rate: AddrRate.getaddr_sent(&1.addr_rate)})
      else
        data
      end

    if data.node[:connman],
      do:
        send(
          data.node.connman,
          {:peer_ready, self(), data.target, data.conn_type, data.handshake.version.services}
        )

    tx_relay_connected(data)
    {:ok, flow_state({:ready, :active}, data), data}
  end

  defp handle_msg(:awaiting_verack, _msg, data), do: {:ok, :awaiting_verack, data}

  # --- Ready state protocol message handlers ---------------------------------

  defp handle_msg({:ready, _}, :wtxidrelay, data),
    do: {:stop, {:shutdown, :wtxidrelay_after_verack}, data}

  defp handle_msg({:ready, _}, :sendaddrv2, data),
    do: {:stop, {:shutdown, :sendaddrv2_after_verack}, data}

  defp handle_msg({:ready, _} = state, {:version, _}, data), do: {:ok, state, data}
  defp handle_msg({:ready, _} = state, :verack, data), do: {:ok, state, data}

  defp handle_msg({:ready, _} = state, :sendheaders, data),
    do: {:ok, state, Data.update_proto(data, &%{&1 | prefers_headers: true})}

  defp handle_msg({:ready, _} = state, {:sendcmpct, %{version: 2, announce: a}}, data),
    do: {:ok, state, Data.update_proto(data, &%{&1 | provides_cmpct: true, hb_requested: a})}

  defp handle_msg({:ready, _} = state, {:sendcmpct, _}, data), do: {:ok, state, data}

  defp handle_msg({:ready, _} = state, {:cmpctblock, payload}, data),
    do: wrap_ready(state, BlockSync.compact_block(data, payload))

  defp handle_msg({:ready, _} = state, {:blocktxn, payload}, data),
    do: wrap_ready(state, BlockSync.block_txn(data, payload))

  defp handle_msg({:ready, _} = state, {:getblocktxn, payload}, data),
    do: wrap_ready(state, Serving.serve_getblocktxn(data, payload))

  defp handle_msg({:ready, _} = state, {:getcfilters, req}, data),
    do: wrap_ready(state, FilterServing.serve_cfilters(data, req))

  defp handle_msg({:ready, _} = state, {:getcfheaders, req}, data),
    do: wrap_ready(state, FilterServing.serve_cfheaders(data, req))

  defp handle_msg({:ready, _} = state, {:getcfcheckpt, req}, data),
    do: wrap_ready(state, FilterServing.serve_cfcheckpt(data, req))

  defp handle_msg({:ready, _} = state, {:feefilter, rate}, %Data{proto: %Proto{} = proto} = data) do
    cond do
      not Consensus.money_range?(rate) or rate == proto.feefilter ->
        {:ok, state, data}

      true ->
        if data.node[:tx_relay], do: TxRelay.feefilter(data.node.tx_relay, self(), rate)
        {:ok, state, %{data | proto: %{proto | feefilter: rate}}}
    end
  end

  defp handle_msg({:ready, _} = state, {:ping, nil}, data), do: {:ok, state, data}

  defp handle_msg({:ready, _} = state, {:ping, nonce}, data) do
    data = push(data, {:pong, nonce})
    {:ok, flow_state(state, data), data}
  end

  defp handle_msg(
         {:ready, _} = state,
         {:pong, nonce},
         %Data{proto: %Proto{ping_nonce: nonce} = proto} = data
       )
       when nonce != nil do
    rtt = :erlang.monotonic_time(:millisecond) - proto.ping_sent_mono
    min_ping = min(proto.min_ping_us || :infinity, rtt * 1000)

    data =
      %{data | proto: %{proto | min_ping_us: min_ping, ping_nonce: nil, last_pong_rtt_ms: rtt}}
      |> report_stats(%{min_ping: min_ping})

    {:ok, state, data}
  end

  defp handle_msg({:ready, _} = state, {:pong, _}, data), do: {:ok, state, data}

  defp handle_msg({:ready, _} = state, {:headers, headers}, data),
    do: wrap_ready(state, HeadersHandler.process_headers_message(data, headers))

  defp handle_msg({:ready, _} = state, {:block, payload}, data) do
    result =
      case Block.decode_exact(payload) do
        {:ok, b} -> BlockSync.received_block(data, b)
        {:error, _} -> {:ok, data}
      end

    wrap_ready(state, result)
  end

  defp handle_msg({:ready, _} = state, {:getheaders, gh}, data) do
    if Map.get(data.node, :serve_headers, true) and not initial_block_download?(data),
      do: wrap_ready(state, Serving.serve_getheaders(data, gh)),
      else: {:ok, state, data}
  end

  defp handle_msg({:ready, _} = state, {:tx, payload}, data) do
    cond do
      data.conn_type == :block_relay ->
        {:stop, {:shutdown, :tx_from_block_relay_peer}, data}

      data.node[:tx_relay] == nil or initial_block_download?(data) ->
        {:ok, state, data}

      true ->
        case Tx.decode_exact(payload) do
          {:ok, tx} -> TxRelay.received_tx(data.node.tx_relay, self(), tx)
          {:error, _} -> :ok
        end

        {:ok, state, data}
    end
  end

  defp handle_msg({:ready, _} = state, {:notfound, items}, data) do
    tx_items =
      if length(items) <= @max_notfound_items,
        do: Enum.filter(items, &(&1.type in [:tx, :wtx])),
        else: []

    if data.node[:tx_relay] && tx_items != [],
      do: TxRelay.notfound(data.node.tx_relay, self(), tx_items)

    {:ok, state, data}
  end

  defp handle_msg({:ready, _} = state, {:getdata, items}, %Data{proto: %Proto{} = proto} = data) do
    q = Enum.reduce(items, proto.getdata_queue, &:queue.in/2)
    wrap_ready(state, Serving.process_getdata(%{data | proto: %{proto | getdata_queue: q}}))
  end

  defp handle_msg({:ready, _} = state, {:inv, items}, %Data{proto: %Proto{} = proto} = data) do
    tx_items = Enum.filter(items, &(&1.type in [:tx, :wtx]))

    data =
      if tx_items != [] and data.node[:tx_relay] != nil and data.conn_type != :block_relay and
           not initial_block_download?(data) do
        known = proto.known_in || TxRelay.new_known_filter()
        kind = if data.handshake.wtxid_relay, do: :wtx, else: :tx
        for %{type: ^kind, hash: h} <- tx_items, do: RollingBloom.insert(known, h)
        TxRelay.inv(data.node.tx_relay, self(), tx_items, known)
        Data.update_proto(data, &%{&1 | known_in: known})
      else
        data
      end

    idx = Headers.index(data.node.headers)

    data =
      Enum.reduce(items, data, fn
        %{type: :block, hash: h}, acc ->
          case HeaderIndex.lookup(idx, h) do
            nil ->
              acc

            e ->
              Data.update_proto(acc, fn p ->
                %{
                  p
                  | best_known: better(p.best_known, e),
                    best_known_block: max(p.best_known_block, e.height)
                }
              end)
          end

        _, acc ->
          acc
      end)

    data =
      if Enum.any?(items, &(&1.type == :block and HeaderIndex.lookup(idx, &1.hash) == nil)),
        do:
          HeadersHandler.maybe_send_getheaders(
            data,
            HeaderIndex.locator(idx, HeaderIndex.best(idx))
          ),
        else: data

    {:ok, flow_state(state, data), data}
  end

  defp handle_msg({:ready, _} = state, {kind, addrs}, %Data{proto: %Proto{} = proto} = data)
       when kind in [:addr, :addrv2] do
    if data.conn_type != :block_relay and data.node[:addrman] do
      {rate, accepted, _limited} =
        AddrRate.received(proto.addr_rate, addrs, Clock.mono(data.node[:clock]))

      accepted = sanitize_addrs(data, accepted)
      src = data.target && AddrMan.key(target_addr(data))
      if accepted != [], do: AddrMan.add(data.node.addrman, accepted, src || :seed, 2 * 3600)
      {:ok, state, %{data | proto: %{proto | addr_rate: rate}}}
    else
      {:ok, state, data}
    end
  end

  defp handle_msg({:ready, _} = state, :getaddr, %Data{proto: %Proto{} = proto} = data) do
    if data.inbound and not proto.getaddr_answered and data.node[:addrman] do
      net = (data.target && elem(AddrMan.key(target_addr(data)), 0)) || :ipv4

      addrs =
        try do
          AddrMan.addr_response(data.node.addrman, net)
        catch
          :exit, _ -> []
        end

      msg =
        if data.handshake.addrv2,
          do: {:addrv2, addrs},
          else: {:addr, Enum.filter(addrs, &(&1.net in [:ipv4, :ipv6]))}

      data =
        data
        |> push(msg)
        |> Data.update_proto(&%{&1 | getaddr_answered: true})

      {:ok, flow_state(state, data), data}
    else
      {:ok, state, data}
    end
  end

  defp handle_msg({:ready, _} = state, _msg, data), do: {:ok, state, data}

  # --- Handshake helpers -----------------------------------------------------

  defp send_version(%Data{} = data) do
    addr_recv =
      case data.target && NetAddr.from_target(data.target) do
        %{net: :ipv4} = a -> Map.put(a, :services, 0)
        _ -> %{services: 0, net: :ipv6, addr: <<0::128>>, port: 0}
      end

    best = Headers.best_header(data.node.headers)

    v = %{
      version: Message.protocol_version(),
      services: data.node.services,
      time: now(data),
      addr_recv: addr_recv,
      nonce: data.handshake.local_nonce,
      user_agent: data.node.user_agent,
      start_height: best.height,
      relay: data.conn_type != :block_relay
    }

    if not data.inbound and data.node[:local_nonces],
      do: Registry.register(data.node.local_nonces, data.handshake.local_nonce, nil)

    data
    |> Data.update_handshake(&%{&1 | sent_version: true})
    |> push({:version, v})
  end

  defp rand64, do: elem(:rand.uniform_s(0xFFFFFFFFFFFFFFFF, :crypto.rand_seed_s()), 0)

  defp connected_to_self?(%Data{} = data, nonce) do
    data.inbound and data.node[:local_nonces] != nil and
      Registry.lookup(data.node.local_nonces, nonce) != []
  end

  defp tx_relay_connected(%Data{proto: %Proto{} = proto} = data) do
    if data.node[:tx_relay] && data.conn_type != :block_relay do
      TxRelay.connected(data.node.tx_relay, self(), %{
        wtxid_relay: data.handshake.wtxid_relay,
        preferred: not data.inbound,
        relay_txs: data.handshake.version.relay,
        inbound: data.inbound
      })

      if (proto.feefilter || 0) > 0,
        do: TxRelay.feefilter(data.node.tx_relay, self(), proto.feefilter)
    end
  end

  # --- Shared helpers (also used by Peer submodules) -------------------------

  defp common_version(%Data{handshake: %Handshake{version: v}}),
    do: min(v.version, Message.protocol_version())

  @doc false
  def handshake_done?(%Data{} = data), do: Data.ready?(data)

  @doc false
  def initial_block_download?(%Data{} = data) do
    view = data.node[:chain_state] && ChainState.view(data.node.chain_state)

    if view,
      do: ChainState.view_ibd?(view, Headers.index(data.node.headers), now(data), data.p),
      else: false
  end

  @doc false
  def better(nil, e), do: e
  def better(a, b), do: if(b.chain_work > a.chain_work, do: b, else: a)

  @doc false
  def now(%Data{} = data), do: Clock.now(data.node[:clock])

  @doc false
  def report_stats(%Data{} = data, stats) do
    if data.node[:connman], do: send(data.node.connman, {:peer_stats, self(), stats})
    data
  end

  @doc false
  def misbehaving(%Data{conn_type: :manual} = data, why) do
    Logger.info("peer #{inspect(data.target)}: misbehaving (#{why}), but manual: kept")
    {:ok, data}
  end

  def misbehaving(%Data{} = data, why), do: {:stop, {:shutdown, {:misbehaving, why}}, data}

  @doc false
  def dropped(%Data{} = data, cmd, why) do
    Logger.debug("peer #{inspect(data.target)}: #{cmd} decode error #{inspect(why)}")
    {:ok, data}
  end

  @doc false
  def push(%Data{} = data, msg) do
    {cmd, payload} = Message.encode(msg)
    conn = Conn.send_msg(data.conn, cmd, payload, now(data))
    Data.trace(%{data | conn: conn}, {:out, cmd})
  end

  # --- Tick & info helpers ---------------------------------------------------

  defp run_tick(state, data) when state in [:connecting, :awaiting_socket] do
    {:ok, state, data}
  end

  defp run_tick(state, %Data{} = data) when state in [:awaiting_version, :awaiting_verack] do
    t = now(data)

    cond do
      t - data.handshake.connected_at > @handshake_timeout_s ->
        closing(data, :handshake_timeout)

      reason = inactivity(data, t) ->
        {:stop, {:shutdown, reason}, data}

      true ->
        {:ok, state, data}
    end
  end

  defp run_tick({:ready, _} = state, %Data{proto: %Proto{} = proto} = data) do
    t = now(data)

    cond do
      proto.ping_nonce && t - proto.ping_sent_at > @timeout_interval_s ->
        {:stop, {:shutdown, :ping_timeout}, data}

      reason = inactivity(data, t) ->
        {:stop, {:shutdown, reason}, data}

      true ->
        result =
          data
          |> BlockSync.expire_partials(t)
          |> maybe_ping(t)
          |> HeadersHandler.maybe_start_sync(t)
          |> BlockSync.maybe_request_blocks()
          |> Serving.maybe_announce_blocks()
          |> HeadersHandler.check_headers_sync_timeout(t)
          |> HeadersHandler.consider_eviction(t)

        case result do
          {:ok, data} -> {:ok, flow_state(state, data), data}
          {:stop, reason, data} -> {:stop, reason, data}
        end
    end
  end

  defp tick_actions(%Data{node: node}) do
    case Map.get(node, :tick_ms, @tick_ms) do
      nil -> []
      ms -> [{{:timeout, :tick}, ms, :tick}]
    end
  end

  defp maybe_ping(%Data{proto: %Proto{ping_nonce: nil, next_ping_at: next} = proto} = data, t)
       when t >= next do
    nonce = rand64()

    %{
      data
      | proto: %{
          proto
          | ping_nonce: nonce,
            ping_sent_at: t,
            ping_sent_mono: :erlang.monotonic_time(:millisecond),
            next_ping_at: t + @ping_interval_s
        }
    }
    |> push({:ping, nonce})
  end

  defp maybe_ping(data, _t), do: data

  defp inactivity(%Data{} = data, t) do
    Conn.inactivity_reason(
      data.conn,
      data.handshake.connected_at,
      t,
      @handshake_timeout_s,
      @timeout_interval_s
    )
  end

  defp build_info(state, %Data{} = data) do
    v = data.handshake.version || %{}
    proto = data.proto || %Proto{}

    presynced_headers =
      if proto.headers_sync && HeadersSync.state(proto.headers_sync) != :final,
        do: HeadersSync.presync_height(proto.headers_sync),
        else: -1

    %{
      conn_type: data.conn_type,
      target: data.target,
      version: v[:version],
      services: v[:services],
      user_agent: v[:user_agent],
      start_height: v[:start_height],
      handshake_done: match?({:ready, _}, state),
      sync_started: proto.sync_started,
      presync: proto.headers_sync && HeadersSync.progress(proto.headers_sync),
      presynced_headers: presynced_headers,
      ping_ms: proto.last_pong_rtt_ms,
      min_ping_us: proto.min_ping_us,
      best_known: proto.best_known && proto.best_known.height,
      synced_blocks: proto.best_known_block,
      bytes_sent: data.conn.bytes_sent,
      bytes_recv: data.conn.bytes_recv,
      last_send: data.conn.last_send || 0,
      last_recv: data.conn.last_recv || 0,
      conntime: data.handshake.connected_at || 0,
      relay: v[:relay] != false,
      hb_to: proto.hb_requested,
      hb_from: proto.hb_selected,
      feefilter: proto.feefilter || 0,
      provides_cmpct: proto.provides_cmpct,
      timeoffset: (v[:time] && now(data) - v[:time]) || 0,
      transport_protocol_type: Conn.transport_type(data.conn),
      session_id: Conn.session_id(data.conn)
    }
  end

  defp target_addr(%Data{target: target}), do: NetAddr.from_target(target)

  defp desirable_services?(%Data{} = data, services) do
    limited = Message.service(:network_limited)

    want =
      if (services &&& limited) != 0 and not initial_block_download?(data),
        do: limited ||| Message.service(:witness),
        else: Message.service(:network) ||| Message.service(:witness)

    (services &&& want) == want
  end

  defp sanitize_addrs(_data, []), do: []

  defp sanitize_addrs(data, addrs) do
    now = now(data)
    full = Message.service(:network) ||| Message.service(:network_limited)
    reachable = Connman.reachable_nets()

    addrs
    |> Enum.filter(&((&1.services &&& full) != 0 and &1.net in reachable))
    |> Enum.map(fn a ->
      if a.time <= 100_000_000 or a.time > now + 600,
        do: %{a | time: now - 5 * 86_400},
        else: a
    end)
    |> reject_discouraged(data.node[:connman])
  end

  defp reject_discouraged([], _connman), do: []
  defp reject_discouraged(addrs, nil), do: addrs

  defp reject_discouraged(addrs, connman) do
    Connman.reject_discouraged(connman, addrs)
  catch
    :exit, _ -> addrs
  end
end
