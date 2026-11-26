defmodule Exnode.P2P.Peer do
  @moduledoc """
  One process per peer connection. Mirrors the per-peer parts of Core v32.1
  `net_processing.cpp` (`ProcessMessage`, `SendMessages`): handshake,
  ping/pong, addr relay, headers-first sync with the low-work presync
  (`Exnode.P2P.Peer.HeadersHandler` / `HeadersSync`), block download and
  compact blocks (`Exnode.P2P.Peer.BlockSync`), transaction relay (through
  `TxRelay`), block and header serving (`Exnode.P2P.Peer.Serving`), and BIP157
  filter serving (`Exnode.P2P.FilterServing`).

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
  use GenServer, restart: :temporary
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

  alias Exnode.P2P.Peer.{BlockSync, Conn, HeadersHandler, Serving}
  alias Exnode.Util.RollingBloom

  # net.cpp m_peer_connect_timeout default (DEFAULT_PEER_CONNECT_TIMEOUT)
  @handshake_timeout_s 60
  # net_processing.cpp
  @ping_interval_s 120
  @timeout_interval_s 20 * 60
  @tick_ms 1_000

  @sendheaders_version 70012
  @short_ids_blocks_version 70014
  @wtxid_relay_version 70016
  # Core: node::MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER.
  @max_notfound_items 5_000 + 16

  # --- API -------------------------------------------------------------------

  @doc """
  Starts a peer.
  * `{:connect, {host, port}}`: outbound; dials the address.
  * `{:socket, socket}`: inbound; the caller must hand over socket control
    with `:gen_tcp.controlling_process/2`, then send `{:socket_ready}`.
  `conn_type`: `:outbound_full_relay | :block_relay | :manual | :inbound`.
  `v2: true` uses the BIP324 transport (Core `use_v2transport`): an
  outbound peer initiates v2; an inbound one detects v1 or v2 from the first
  bytes. An outbound v2 attempt that the remote closed before sending
  anything exits with `{:shutdown, {:reconnect_v1, reason}}` (Core
  `ShouldReconnectV1`), and the connection manager retries with v1.
  """
  def start_link(args), do: GenServer.start_link(__MODULE__, args)

  def info(pid), do: GenServer.call(pid, :info, 5_000)

  @doc false
  defdelegate select_txs(raw, ranges, indexes), to: Serving

  # --- init ------------------------------------------------------------------

  @impl true
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

    st = %{
      node: node,
      p: node.params,
      conn_type: conn_type,
      inbound: inbound,
      target: args[:target],
      conn: Conn.new(conn_opts),
      # Core m_getdata_requests: getdata items not served yet.
      getdata_queue: :queue.new(),
      connected_at: nil,
      # handshake
      version: nil,
      verack_received: false,
      # The peer's last feefilter (sat/kvB), resent to TxRelay after it restarts.
      feefilter: 0,
      sent_version: false,
      # Core nLocalHostNonce: our version nonce, fresh per connection, so
      # connections cannot be linked to each other by it.
      local_nonce: rand64(),
      wtxid_relay: false,
      addrv2: false,
      prefers_headers: false,
      # ping
      ping_nonce: nil,
      ping_sent_at: nil,
      next_ping_at: nil,
      last_pong_rtt_ms: nil,
      min_ping_us: nil,
      # headers & block sync
      sync_started: false,
      headers_sync_timeout: nil,
      headers_sync: nil,
      last_getheaders_at: nil,
      best_known: nil,
      best_known_block: -1,
      # Core ChainSyncTimeoutState (m_timeout, m_work_header,
      # m_sent_getheaders, m_protect); timeout nil is Core's 0s.
      chain_sync: %{timeout: nil, work_header: nil, sent_getheaders: false, protect: false},
      getaddr_answered: false,
      # Core m_addr_token_bucket.
      addr_rate: AddrRate.new(Clock.mono(node[:clock])),
      # BIP152: the peer sent sendcmpct version 2; blocks being rebuilt from cmpctblock.
      provides_cmpct: false,
      partials: %{},
      # Compact blocks this peer already sent us that we tried to rebuild.
      cmpct_seen: [],
      # Core m_tx_inventory_known_filter, the part this peer announced to us:
      # a RollingBloom written here, read by TxRelay.
      known_in: nil,
      # Blocks rebuilt from this peer's compact blocks stored for a deferred verdict.
      rebuilt_deferred: [],
      # BIP152: the peer asked us to announce new blocks as cmpctblock.
      hb_requested: false,
      # BIP152: we asked the peer to announce new blocks to us as cmpctblock.
      hb_selected: false,
      # Last tip announced to this peer (block announcements).
      announced: nil
    }

    case args[:connect] do
      {host, port} -> {:ok, %{st | target: {host, port}}, {:continue, :connect}}
      nil -> {:ok, st}
    end
  end

  @impl true
  def handle_continue(:connect, %{target: target} = st) do
    t = now(st)

    case Conn.connect(st.conn, target, t) do
      {:ok, conn} ->
        schedule_tick(st)
        st = %{st | conn: conn, connected_at: t, next_ping_at: t}
        {:noreply, send_version(st)}

      {:error, reason} ->
        {:stop, {:shutdown, {:connect_failed, reason}}, st}
    end
  end

  # --- socket ----------------------------------------------------------------

  @impl true
  def handle_info({:socket_ready, sock}, st) do
    t = now(st)
    conn = Conn.attach(st.conn, sock, t)
    schedule_tick(st)
    {:noreply, %{st | conn: conn, connected_at: t, next_ping_at: t}}
  end

  def handle_info({:tcp, sock, data}, %{conn: %Conn{socket: sock}} = st) do
    case Conn.on_tcp(st.conn, data, now(st)) do
      {:v1, conn} ->
        drain(%{st | conn: conn}) |> rearm()

      {:v2, conn, msgs} ->
        dispatch(%{st | conn: conn}, msgs) |> rearm()

      {:error, reason} ->
        {:stop, {:shutdown, reason}, st}
    end
  end

  def handle_info({:tcp_closed, _}, st) do
    age = if st.connected_at, do: now(st) - st.connected_at, else: nil
    ua = st.version && st.version.user_agent
    closing(st, {:closed, %{age_s: age, ua: ua, recent: Enum.reverse(Map.get(st, :trace, []))}})
  end

  def handle_info({:tcp_error, _, reason}, st), do: closing(st, {:tcp_error, reason})

  def handle_info(:tick, st) do
    schedule_tick(st)
    tick(st)
  end

  def handle_info({Clock, :tick, from, ref}, st) do
    case if(st.connected_at, do: tick(st), else: {:noreply, st}) do
      {:noreply, _} = r ->
        Clock.ticked({from, ref})
        r

      stop ->
        stop
    end
  end

  def handle_info({:disconnect, reason}, st), do: {:stop, {:shutdown, reason}, st}

  def handle_info(:request_blocks, st), do: {:noreply, BlockSync.maybe_request_blocks(st)}

  def handle_info(:continue_getdata, st) do
    case Serving.process_getdata(st) do
      {:ok, st} ->
        if getdata_pending?(st) do
          {:noreply, st}
        else
          if Conn.v1?(st.conn) do
            drain(st)
          else
            {msgs, conn} = Conn.take_pending(st.conn)
            dispatch(%{st | conn: conn}, msgs)
          end
          |> rearm()
        end

      stop ->
        stop
    end
  end

  def handle_info({:send_failed, reason}, st),
    do: {:stop, {:shutdown, {:send_failed, reason}}, st}

  def handle_info({:sent, n}, st) do
    {resumed?, conn} = Conn.on_sent(st.conn, n, now(st))
    if resumed?, do: send(self(), :continue_getdata)
    {:noreply, %{st | conn: conn}}
  end

  def handle_info(:novel_tx, st), do: {:noreply, report_stats(st, %{last_tx_time: now(st)})}

  def handle_info({:block_checked, hash, {:error, {result, reason}}}, st) do
    via_compact = hash in st.rebuilt_deferred
    st = %{st | rebuilt_deferred: List.delete(st.rebuilt_deferred, hash)}

    case BlockSync.maybe_punish_for_block(st, result, "invalid block: #{reason}", via_compact) do
      {:ok, st} -> {:noreply, st}
      stop -> stop
    end
  end

  def handle_info({:send, {:sendcmpct, %{announce: a}} = msg}, %{conn: %Conn{socket: s}} = st)
      when s != nil,
      do: {:noreply, push(%{st | hb_selected: a}, msg)}

  def handle_info({:send, msg}, %{conn: %Conn{socket: s}} = st) when s != nil,
    do: {:noreply, push(st, msg)}

  def handle_info(:tx_relay_resync, st) do
    if handshake_done?(st), do: tx_relay_connected(st)
    {:noreply, st}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  @impl true
  def terminate(reason, st) do
    Conn.flush_on_terminate(st.conn, reason)
  end

  @impl true
  def handle_call(:info, _from, st) do
    v = st.version || %{}

    presynced_headers =
      if st.headers_sync && HeadersSync.state(st.headers_sync) != :final,
        do: HeadersSync.presync_height(st.headers_sync),
        else: -1

    {:reply,
     %{
       conn_type: st.conn_type,
       target: st.target,
       version: v[:version],
       services: v[:services],
       user_agent: v[:user_agent],
       start_height: v[:start_height],
       handshake_done: handshake_done?(st),
       sync_started: st.sync_started,
       presync: st.headers_sync && HeadersSync.progress(st.headers_sync),
       presynced_headers: presynced_headers,
       ping_ms: st.last_pong_rtt_ms,
       min_ping_us: st.min_ping_us,
       best_known: st.best_known && st.best_known.height,
       synced_blocks: st.best_known_block,
       bytes_sent: st.conn.bytes_sent,
       bytes_recv: st.conn.bytes_recv,
       last_send: st.conn.last_send || 0,
       last_recv: st.conn.last_recv || 0,
       conntime: st.connected_at || 0,
       relay: v[:relay] != false,
       hb_to: st.hb_requested,
       hb_from: st.hb_selected,
       feefilter: st.feefilter || 0,
       provides_cmpct: st.provides_cmpct,
       timeoffset: (v[:time] && now(st) - v[:time]) || 0,
       transport_protocol_type: Conn.transport_type(st.conn),
       session_id: Conn.session_id(st.conn)
     }, st}
  end

  # --- frame & message dispatch ----------------------------------------------

  defp drain(st) do
    if blocked?(st) do
      {:noreply, st}
    else
      case Conn.next_v1_frame(st.conn) do
        {:more, conn} ->
          {:noreply, %{st | conn: conn}}

        {:error, reason} ->
          {:stop, {:shutdown, {:bad_frame, reason}}, st}

        {:reject, _cmd, conn} ->
          drain(%{st | conn: conn})

        {:ok, cmd, payload, conn} ->
          case process_message(%{st | conn: conn}, cmd, payload) do
            {:ok, st} -> drain(st)
            stop -> stop
          end
      end
    end
  end

  @doc false
  def getdata_pending?(st), do: not :queue.is_empty(st.getdata_queue)

  @doc false
  def paused?(st), do: Conn.paused?(st.conn)

  defp blocked?(st), do: getdata_pending?(st) or paused?(st)

  defp rearm({:noreply, st} = r) do
    if not blocked?(st), do: Conn.rearm(st.conn)
    r
  end

  defp rearm(other), do: other

  defp dispatch(st, []), do: {:noreply, st}

  defp dispatch(st, msgs) do
    if blocked?(st),
      do: {:noreply, %{st | conn: Conn.append_pending(st.conn, msgs)}},
      else: dispatch_now(st, msgs)
  end

  defp dispatch_now(st, []), do: {:noreply, st}
  defp dispatch_now(st, [:reject | rest]), do: dispatch(st, rest)

  defp dispatch_now(st, [{:msg, cmd, payload} | rest]) do
    case process_message(st, cmd, payload) do
      {:ok, st} -> dispatch(st, rest)
      stop -> stop
    end
  end

  defp process_message(st, cmd, payload) do
    case DecodeBudget.with_budget(st.node[:decode_budget], byte_size(payload), fn ->
           decode_and_handle(st, cmd, payload)
         end) do
      :unavailable -> {:stop, {:shutdown, :decode_budget_unavailable}, st}
      result -> result
    end
  end

  defp decode_and_handle(st, cmd, payload) do
    st = trace(st, {:in, cmd})

    case Message.decode(cmd, payload) do
      {:ok, msg} ->
        handle_msg(msg, st)

      {:unknown, _} ->
        {:ok, st}

      {:error, {kind, _}}
      when kind in [:too_many_headers, :inv_too_large, :addr_too_large, :locator_too_large] and
             not (st.version != nil and st.verack_received) ->
        Logger.debug("peer #{inspect(st.target)}: #{cmd} before the handshake, ignored")
        {:ok, st}

      {:error, {:locator_too_large, _n}} ->
        {:stop, {:shutdown, :locator_too_large}, st}

      {:error, {:too_many_headers, n}} ->
        misbehaving(st, "headers message size = #{n}")

      {:error, {:inv_too_large, n}} ->
        misbehaving(st, "inv message size = #{n}")

      {:error, {:addr_too_large, n}} ->
        misbehaving(st, "addr message size = #{n}")

      {:error, reason} ->
        Logger.debug("peer #{inspect(st.target)}: #{cmd} decode error #{inspect(reason)}")
        {:ok, st}
    end
  end

  defp closing(st, reason) do
    if Conn.should_reconnect_v1?(st.conn),
      do: {:stop, {:shutdown, {:reconnect_v1, reason}}, st},
      else: {:stop, {:shutdown, reason}, st}
  end

  # --- handshake -------------------------------------------------------------

  defp send_version(st) do
    addr_recv =
      case st.target && NetAddr.from_target(st.target) do
        %{net: :ipv4} = a -> Map.put(a, :services, 0)
        _ -> %{services: 0, net: :ipv6, addr: <<0::128>>, port: 0}
      end

    best = Headers.best_header(st.node.headers)

    v = %{
      version: Message.protocol_version(),
      services: st.node.services,
      time: now(st),
      addr_recv: addr_recv,
      nonce: st.local_nonce,
      user_agent: st.node.user_agent,
      start_height: best.height,
      relay: st.conn_type != :block_relay
    }

    if not st.inbound and st.node[:local_nonces],
      do: Registry.register(st.node.local_nonces, st.local_nonce, nil)

    push(%{st | sent_version: true}, {:version, v})
  end

  defp rand64, do: elem(:rand.uniform_s(0xFFFFFFFFFFFFFFFF, :crypto.rand_seed_s()), 0)

  defp connected_to_self?(st, nonce) do
    st.inbound and st.node[:local_nonces] != nil and
      Registry.lookup(st.node.local_nonces, nonce) != []
  end

  @doc false
  def handshake_done?(st), do: st.version != nil and st.verack_received

  defp tx_relay_connected(st) do
    if st.node[:tx_relay] && st.conn_type != :block_relay do
      TxRelay.connected(st.node.tx_relay, self(), %{
        wtxid_relay: st.wtxid_relay,
        preferred: not st.inbound,
        relay_txs: st.version.relay,
        inbound: st.inbound
      })

      if (st.feefilter || 0) > 0, do: TxRelay.feefilter(st.node.tx_relay, self(), st.feefilter)
    end
  end

  # --- protocol message handlers ---------------------------------------------

  defp handle_msg({:version, _}, %{version: v} = st) when v != nil, do: {:ok, st}

  defp handle_msg({:version, v}, st) do
    desirable = Message.service(:network) ||| Message.service(:witness)
    expects_services = st.conn_type in [:outbound_full_relay, :block_relay]

    cond do
      expects_services and (v.services &&& desirable) != desirable ->
        {:stop, {:shutdown, {:missing_services, v.services}}, st}

      v.version < Message.min_peer_proto_version() ->
        {:stop, {:shutdown, {:obsolete_version, v.version}}, st}

      connected_to_self?(st, v.nonce) ->
        {:stop, {:shutdown, :connected_to_self}, st}

      st.conn_type == :feeler ->
        if st.node[:connman],
          do: send(st.node.connman, {:peer_ready, self(), st.target, :feeler, v.services})

        {:stop, {:shutdown, :feeler_done}, %{st | version: v}}

      true ->
        st = %{st | version: v}
        st = if st.inbound, do: send_version(st), else: st
        common = min(v.version, Message.protocol_version())
        st = if common >= @wtxid_relay_version, do: push(st, :wtxidrelay), else: st
        st = if common >= 70016, do: push(st, :sendaddrv2), else: st

        if (not st.inbound and st.node[:addrman]) && st.target,
          do: AddrMan.set_services(st.node.addrman, AddrMan.key(target_addr(st)), v.services)

        relay = v.relay != false and st.conn_type != :block_relay
        stats = %{relay_txs: relay, relevant_services: desirable_services?(st, v.services)}
        st = report_stats(st, stats)

        if st.inbound and relay and st.node[:connman] != nil and
             Connman.tx_relay_capacity(st.node.connman, stats) == :disconnect do
          {:stop, {:shutdown, :tx_relay_capacity}, st}
        else
          {:ok, push(st, :verack)}
        end
    end
  end

  defp handle_msg(_msg, %{version: nil} = st), do: {:ok, st}

  defp handle_msg(:verack, %{verack_received: true} = st), do: {:ok, st}

  defp handle_msg(:verack, st) do
    common = common_version(st)
    st = %{st | verack_received: true}
    if st.node[:local_nonces], do: Registry.unregister(st.node.local_nonces, st.local_nonce)
    st = if common >= @sendheaders_version, do: push(st, :sendheaders), else: st

    st =
      if common >= @short_ids_blocks_version,
        do: push(st, {:sendcmpct, %{announce: false, version: 2}}),
        else: st

    st =
      if st.conn_type in [:outbound_full_relay, :manual],
        do: %{push(st, :getaddr) | addr_rate: AddrRate.getaddr_sent(st.addr_rate)},
        else: st

    if st.node[:connman],
      do:
        send(st.node.connman, {:peer_ready, self(), st.target, st.conn_type, st.version.services})

    view = st.node[:chain_state] && ChainState.view(st.node.chain_state)
    st = if view, do: %{st | announced: ChainState.view_tip(view).hash}, else: st

    tx_relay_connected(st)
    {:ok, st}
  end

  defp handle_msg(:wtxidrelay, st) do
    if st.verack_received,
      do: {:stop, {:shutdown, :wtxidrelay_after_verack}, st},
      else: {:ok, %{st | wtxid_relay: common_version(st) >= @wtxid_relay_version}}
  end

  defp handle_msg(:sendaddrv2, st) do
    if st.verack_received,
      do: {:stop, {:shutdown, :sendaddrv2_after_verack}, st},
      else: {:ok, %{st | addrv2: true}}
  end

  # Remaining messages need a completed handshake (Core: fSuccessfullyConnected).
  defp handle_msg(_msg, %{verack_received: false} = st), do: {:ok, st}

  defp handle_msg(:sendheaders, st), do: {:ok, %{st | prefers_headers: true}}

  defp handle_msg({:sendcmpct, %{version: 2, announce: a}}, st),
    do: {:ok, %{st | provides_cmpct: true, hb_requested: a}}

  defp handle_msg({:sendcmpct, _}, st), do: {:ok, st}

  defp handle_msg({:cmpctblock, payload}, st), do: BlockSync.compact_block(st, payload)
  defp handle_msg({:blocktxn, payload}, st), do: BlockSync.block_txn(st, payload)
  defp handle_msg({:getblocktxn, payload}, st), do: Serving.serve_getblocktxn(st, payload)
  defp handle_msg({:getcfilters, req}, st), do: FilterServing.serve_cfilters(st, req)
  defp handle_msg({:getcfheaders, req}, st), do: FilterServing.serve_cfheaders(st, req)
  defp handle_msg({:getcfcheckpt, req}, st), do: FilterServing.serve_cfcheckpt(st, req)

  defp handle_msg({:feefilter, rate}, st) do
    cond do
      not Consensus.money_range?(rate) or rate == st.feefilter ->
        {:ok, st}

      true ->
        if st.node[:tx_relay], do: TxRelay.feefilter(st.node.tx_relay, self(), rate)
        {:ok, %{st | feefilter: rate}}
    end
  end

  defp handle_msg({:ping, nil}, st), do: {:ok, st}
  defp handle_msg({:ping, nonce}, st), do: {:ok, push(st, {:pong, nonce})}

  defp handle_msg({:pong, nonce}, %{ping_nonce: nonce} = st) when nonce != nil do
    rtt = :erlang.monotonic_time(:millisecond) - st.ping_sent_mono
    min_ping = min(st.min_ping_us || :infinity, rtt * 1000)
    st = %{st | min_ping_us: min_ping, ping_nonce: nil, last_pong_rtt_ms: rtt}
    {:ok, report_stats(st, %{min_ping: min_ping})}
  end

  defp handle_msg({:pong, _}, st), do: {:ok, st}

  defp handle_msg({:headers, headers}, st),
    do: HeadersHandler.process_headers_message(st, headers)

  defp handle_msg({:block, payload}, st) do
    case Block.decode_exact(payload) do
      {:ok, b} -> BlockSync.received_block(st, b)
      {:error, _} -> {:ok, st}
    end
  end

  defp handle_msg({:getheaders, gh}, st) do
    if Map.get(st.node, :serve_headers, true) and not initial_block_download?(st),
      do: Serving.serve_getheaders(st, gh),
      else: {:ok, st}
  end

  defp handle_msg({:tx, payload}, st) do
    cond do
      st.conn_type == :block_relay ->
        {:stop, {:shutdown, :tx_from_block_relay_peer}, st}

      st.node[:tx_relay] == nil or initial_block_download?(st) ->
        {:ok, st}

      true ->
        case Tx.decode_exact(payload) do
          {:ok, tx} -> TxRelay.received_tx(st.node.tx_relay, self(), tx)
          {:error, _} -> :ok
        end

        {:ok, st}
    end
  end

  defp handle_msg({:notfound, items}, st) do
    tx_items =
      if length(items) <= @max_notfound_items,
        do: Enum.filter(items, &(&1.type in [:tx, :wtx])),
        else: []

    if st.node[:tx_relay] && tx_items != [],
      do: TxRelay.notfound(st.node.tx_relay, self(), tx_items)

    {:ok, st}
  end

  defp handle_msg({:getdata, items}, st) do
    Serving.process_getdata(%{
      st
      | getdata_queue: Enum.reduce(items, st.getdata_queue, &:queue.in/2)
    })
  end

  defp handle_msg({:inv, items}, st) do
    tx_items = Enum.filter(items, &(&1.type in [:tx, :wtx]))

    st =
      if tx_items != [] and st.node[:tx_relay] != nil and st.conn_type != :block_relay and
           not initial_block_download?(st) do
        known = st.known_in || TxRelay.new_known_filter()
        kind = if st.wtxid_relay, do: :wtx, else: :tx
        for %{type: ^kind, hash: h} <- tx_items, do: RollingBloom.insert(known, h)
        TxRelay.inv(st.node.tx_relay, self(), tx_items, known)
        %{st | known_in: known}
      else
        st
      end

    idx = Headers.index(st.node.headers)

    st =
      Enum.reduce(items, st, fn
        %{type: :block, hash: h}, acc ->
          case HeaderIndex.lookup(idx, h) do
            nil ->
              acc

            e ->
              %{
                acc
                | best_known: better(acc.best_known, e),
                  best_known_block: max(acc.best_known_block, e.height)
              }
          end

        _, acc ->
          acc
      end)

    if Enum.any?(items, &(&1.type == :block and HeaderIndex.lookup(idx, &1.hash) == nil)),
      do:
        {:ok,
         HeadersHandler.maybe_send_getheaders(st, HeaderIndex.locator(idx, HeaderIndex.best(idx)))},
      else: {:ok, st}
  end

  defp handle_msg({kind, addrs}, st) when kind in [:addr, :addrv2] do
    if st.conn_type != :block_relay and st.node[:addrman] do
      {rate, accepted, _limited} =
        AddrRate.received(st.addr_rate, addrs, Clock.mono(st.node[:clock]))

      accepted = sanitize_addrs(st, accepted)
      src = st.target && AddrMan.key(target_addr(st))
      if accepted != [], do: AddrMan.add(st.node.addrman, accepted, src || :seed, 2 * 3600)
      {:ok, %{st | addr_rate: rate}}
    else
      {:ok, st}
    end
  end

  defp handle_msg(:getaddr, st) do
    if st.inbound and not st.getaddr_answered and st.node[:addrman] do
      net = (st.target && elem(AddrMan.key(target_addr(st)), 0)) || :ipv4

      addrs =
        try do
          AddrMan.addr_response(st.node.addrman, net)
        catch
          :exit, _ -> []
        end

      msg =
        if st.addrv2,
          do: {:addrv2, addrs},
          else: {:addr, Enum.filter(addrs, &(&1.net in [:ipv4, :ipv6]))}

      {:ok, %{push(st, msg) | getaddr_answered: true}}
    else
      {:ok, st}
    end
  end

  defp handle_msg(_msg, st), do: {:ok, st}

  # --- shared helpers (also used by Peer submodules) -------------------------

  defp common_version(st), do: min(st.version.version, Message.protocol_version())

  @doc false
  def initial_block_download?(st) do
    view = st.node[:chain_state] && ChainState.view(st.node.chain_state)

    if view,
      do: ChainState.view_ibd?(view, Headers.index(st.node.headers), now(st), st.p),
      else: false
  end

  @doc false
  def better(nil, e), do: e
  def better(a, b), do: if(b.chain_work > a.chain_work, do: b, else: a)

  @doc false
  def now(st), do: Clock.now(st.node[:clock])

  @doc false
  def report_stats(st, stats) do
    if st.node[:connman], do: send(st.node.connman, {:peer_stats, self(), stats})
    st
  end

  @doc false
  def misbehaving(%{conn_type: :manual} = st, why) do
    Logger.info("peer #{inspect(st.target)}: misbehaving (#{why}), but manual: kept")
    {:ok, st}
  end

  def misbehaving(st, why), do: {:stop, {:shutdown, {:misbehaving, why}}, st}

  @doc false
  def dropped(st, cmd, why) do
    Logger.debug("peer #{inspect(st.target)}: #{cmd} decode error #{inspect(why)}")
    {:ok, st}
  end

  @doc false
  def push(st, msg) do
    {cmd, payload} = Message.encode(msg)
    conn = Conn.send_msg(st.conn, cmd, payload, now(st))
    trace(%{st | conn: conn}, {:out, cmd})
  end

  # --- internal helpers ------------------------------------------------------

  defp target_addr(%{target: target}), do: NetAddr.from_target(target)

  defp maybe_ping(st, t) do
    if handshake_done?(st) and st.ping_nonce == nil and t >= st.next_ping_at do
      nonce = rand64()

      push(
        %{st | ping_nonce: nonce, ping_sent_at: t, next_ping_at: t + @ping_interval_s},
        {:ping, nonce}
      )
      |> Map.put(:ping_sent_mono, :erlang.monotonic_time(:millisecond))
    else
      st
    end
  end

  defp inactivity(st, now) do
    Conn.inactivity_reason(
      st.conn,
      st.connected_at,
      now,
      @handshake_timeout_s,
      @timeout_interval_s
    )
  end

  defp desirable_services?(st, services) do
    limited = Message.service(:network_limited)

    want =
      if (services &&& limited) != 0 and not initial_block_download?(st),
        do: limited ||| Message.service(:witness),
        else: Message.service(:network) ||| Message.service(:witness)

    (services &&& want) == want
  end

  defp trace(st, ev), do: Map.put(st, :trace, Enum.take([ev | Map.get(st, :trace, [])], 12))

  defp tick(st) do
    t = now(st)

    cond do
      not handshake_done?(st) and t - st.connected_at > @handshake_timeout_s ->
        closing(st, :handshake_timeout)

      st.ping_nonce && t - st.ping_sent_at > @timeout_interval_s ->
        {:stop, {:shutdown, :ping_timeout}, st}

      reason = inactivity(st, t) ->
        {:stop, {:shutdown, reason}, st}

      true ->
        st
        |> BlockSync.expire_partials(t)
        |> maybe_ping(t)
        |> HeadersHandler.maybe_start_sync(t)
        |> BlockSync.maybe_request_blocks()
        |> Serving.maybe_announce_blocks()
        |> HeadersHandler.check_headers_sync_timeout(t)
        |> HeadersHandler.consider_eviction(t)
    end
  end

  defp schedule_tick(st) do
    case Map.get(st.node, :tick_ms, @tick_ms) do
      nil -> :ok
      ms -> Process.send_after(self(), :tick, ms)
    end
  end

  defp sanitize_addrs(_st, []), do: []

  defp sanitize_addrs(st, addrs) do
    now = now(st)
    full = Message.service(:network) ||| Message.service(:network_limited)
    reachable = Connman.reachable_nets()

    addrs
    |> Enum.filter(&((&1.services &&& full) != 0 and &1.net in reachable))
    |> Enum.map(fn a ->
      if a.time <= 100_000_000 or a.time > now + 600,
        do: %{a | time: now - 5 * 86_400},
        else: a
    end)
    |> reject_discouraged(st.node[:connman])
  end

  defp reject_discouraged([], _connman), do: []
  defp reject_discouraged(addrs, nil), do: addrs

  defp reject_discouraged(addrs, connman) do
    Connman.reject_discouraged(connman, addrs)
  catch
    :exit, _ -> addrs
  end
end
