defmodule Exnode.P2P.Peer do
  @moduledoc """
  One process per peer connection. Mirrors the per-peer parts of Core v32.1
  `net_processing.cpp` (`ProcessMessage`, `SendMessages`): handshake,
  ping/pong, addr relay, headers-first sync with the low-work presync
  (`HeadersSync`), block download, compact blocks, transaction relay
  (through `TxRelay`), and block, header and filter serving.

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
    user_agent, serve_headers (default false), active_tip_fn (optional),
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
  alias Exnode.Codec.Block
  alias Exnode.Consensus.Pow
  alias Exnode.P2P.{AddrMan, BlockDownload, Frame, FrameBuffer, HeadersSync, Message, SyncState}
  alias Exnode.P2P.DecodeBudget
  alias Exnode.Util.RollingBloom
  alias Exnode.P2P.V2.Transport

  # net.cpp m_peer_connect_timeout default (DEFAULT_PEER_CONNECT_TIMEOUT)
  @handshake_timeout_s 60
  # net_processing.cpp
  @ping_interval_s 120
  @timeout_interval_s 20 * 60
  @headers_response_time_s 120
  @headers_download_timeout_base_s 15 * 60
  @headers_download_timeout_per_header_ms 1
  @chain_sync_timeout_s 20 * 60
  @tick_ms 1_000
  # A send blocked this long (peer not reading) fails and closes the socket,
  # so the writer cannot hang; Core's send-side TIMEOUT_INTERVAL.
  # (node.send_timeout_ms overrides it in tests.)
  @send_timeout_ms 20 * 60 * 1000
  # net.h DEFAULT_MAXSENDBUFFER (1000) * 1000 bytes, Core -maxsendbuffer
  # (node.max_send_buffer overrides it in tests).
  @max_send_buffer 1_000 * 1_000
  # Bytes the writer coalesces into one socket send.
  @writer_batch 256 * 1024

  @sendheaders_version 70012
  @short_ids_blocks_version 70014
  @wtxid_relay_version 70016
  # Core bounds partial reconstructions by MAX_BLOCKS_IN_TRANSIT_PER_PEER.
  @max_partials 16
  @max_cmpct_seen 16
  # Core: node::MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER.
  @max_notfound_items 5_000 + 16
  @partial_timeout_s 60

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

  # --- init ------------------------------------------------------------------

  @impl true
  def init(args) do
    node = Map.fetch!(args, :node)
    conn_type = Map.fetch!(args, :conn_type)

    st = %{
      node: node,
      p: node.params,
      conn_type: conn_type,
      inbound: conn_type == :inbound,
      target: args[:target],
      socket: nil,
      # v1 receive buffer (FrameBuffer: linear in bytes received).
      buf: Exnode.P2P.FrameBuffer.new(),
      # Core m_getdata_requests: getdata items not served yet.
      getdata_queue: :queue.new(),
      # v2 messages decoded but not processed while the getdata queue drains.
      pending_msgs: [],
      # Send buffer (Core vSendMsg / m_send_memusage / fPauseSend):
      # bytes go to a linked writer process, which owns the blocking socket
      # send; `send_queued` counts the bytes it has not written yet. Over
      # the limit, `paused_since` is set: no more messages from the peer are
      # processed and no more getdata is served until it drains.
      writer: nil,
      send_queued: 0,
      paused_since: nil,
      # :v1, or a V2.Transport (BIP324) once the session starts.
      transport: :v1,
      v2: Map.get(args, :v2, false),
      connected_at: nil,
      # handshake
      version: nil,
      verack_received: false,
      # The peer's last feefilter, resent to TxRelay after it restarts.
      feefilter: nil,
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
      # headers sync
      sync_started: false,
      headers_sync_timeout: nil,
      headers_sync: nil,
      last_getheaders_at: nil,
      best_known: nil,
      # Core ChainSyncTimeoutState (m_timeout, m_work_header,
      # m_sent_getheaders, m_protect); timeout nil is Core's 0s.
      chain_sync: %{timeout: nil, work_header: nil, sent_getheaders: false, protect: false},
      getaddr_answered: false,
      # Core m_addr_token_bucket.
      addr_rate: Exnode.P2P.AddrRate.new(Exnode.Clock.mono(node[:clock])),
      # BIP152: the peer sent sendcmpct version 2; blocks being rebuilt from cmpctblock.
      provides_cmpct: false,
      partials: %{},
      # Compact blocks this peer already sent us that we tried to rebuild
      # (newest first, at most @max_cmpct_seen): Core marks such a block in
      # flight from the peer, so a resend is "already syncing" and ignored.
      cmpct_seen: [],
      # Core m_tx_inventory_known_filter, the part this peer announced to us:
      # a RollingBloom written here, read by TxRelay.
      known_in: nil,
      # Blocks rebuilt from this peer's compact blocks that the chain state
      # stored for a deferred verdict (newest first, at most @max_partials):
      # their {:block_checked, ...} is via_compact_block (Core mapBlockSource
      # with fMayBan = false).
      rebuilt_deferred: [],
      # BIP152: the peer asked us to announce new blocks as cmpctblock.
      hb_requested: false,
      # BIP152: we asked the peer to announce new blocks to us as cmpctblock
      # (Core m_bip152_highbandwidth_to; set by HighBandwidth's sendcmpct).
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
  def handle_continue(:connect, %{target: {host, port}} = st) do
    # IP literals are parsed to tuples. IPv6 needs the :inet6 option, otherwise
    # gen_tcp treats the literal as a hostname (nxdomain).
    {host, family} =
      case :inet.parse_address(to_charlist(host)) do
        {:ok, ip} when tuple_size(ip) == 8 -> {ip, [:inet6]}
        {:ok, ip} -> {ip, []}
        {:error, _} -> {to_charlist(host), []}
      end

    case connect(
           host,
           port,
           family ++ [:binary, active: :once, packet: :raw, nodelay: true] ++ send_opts(st)
         ) do
      {:ok, sock} ->
        st = start_session(%{st | socket: sock})
        {:noreply, send_version(st)}

      {:error, reason} ->
        {:stop, {:shutdown, {:connect_failed, reason}}, st}
    end
  end

  # `:gen_tcp.connect/4` turns the socket's EINVAL into `exit(badarg)`
  # instead of returning it, e.g. for a link-local IPv6 outside fe80::/64
  # (Core IsRFC4862 covers only that /64, so such an address is routable
  # and stored, as in Core): fe80:2::/64 gossiped by a peer crashed the peer
  # process. Core's connect just fails; so does this one.
  defp connect(host, port, opts) do
    :gen_tcp.connect(host, port, opts, 5_000)
  catch
    :exit, :badarg -> {:error, :einval}
  end

  defp start_session(st) do
    schedule_tick(st)
    st = %{start_writer(st) | connected_at: now(st), next_ping_at: now(st)}

    if st.v2 do
      # Core MakeTransport: V2Transport(initiating = outbound). The initiator
      # sends its key and garbage at once.
      {t, out} = Transport.new(not st.inbound, st.p.magic)
      send_bytes(%{st | transport: t}, out)
    else
      st
    end
  end

  # --- socket ----------------------------------------------------------------

  @impl true
  def handle_info({:socket_ready, sock}, st) do
    :ok = :inet.setopts(sock, [active: :once] ++ send_opts(st))
    {:noreply, start_session(%{st | socket: sock})}
  end

  def handle_info({:tcp, sock, data}, %{socket: sock} = st) do
    st =
      st
      |> Map.update(:bytes_recv, byte_size(data), &(&1 + byte_size(data)))
      |> Map.put(:last_recv, now(st))

    case st.transport do
      :v1 ->
        drain(%{st | buf: FrameBuffer.append(st.buf, data)}) |> rearm()

      %Transport{} = t ->
        case Transport.received(t, data) do
          {:ok, t, out, msgs} ->
            st |> Map.put(:transport, t) |> send_bytes(out) |> dispatch(msgs) |> rearm()

          {:v1, bytes} ->
            # Core: an inbound v1 peer (version header seen); continue as v1,
            # with anything queued for the v2 handshake re-sent as v1 frames.
            st = %{st | transport: :v1, buf: FrameBuffer.from_binary(bytes)}

            st =
              Enum.reduce(Transport.queued(t), st, fn {cmd, p}, st ->
                send_bytes(st, Frame.encode(st.p.magic, cmd, p))
              end)

            drain(st) |> rearm()

          {:error, reason} ->
            {:stop, {:shutdown, {:v2_error, reason}}, st}
        end
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

  # Exnode.Clock.tick/2: the same pass, now (none before the session starts,
  # as the timer); no reply when it ends the peer (the caller sees it exit).
  def handle_info({Exnode.Clock, :tick, from, ref}, st) do
    case if(st.connected_at, do: tick(st), else: {:noreply, st}) do
      {:noreply, _} = r ->
        Exnode.Clock.ticked({from, ref})
        r

      stop ->
        stop
    end
  end

  def handle_info({:disconnect, reason}, st), do: {:stop, {:shutdown, reason}, st}

  # BlockDownload: blocks may be available now (tip advanced, reservations
  # or bytes released) after this peer last found nothing to request.
  def handle_info(:request_blocks, st), do: {:noreply, maybe_request_blocks(st)}

  # Core: ProcessGetData again on the next pass (SendMessages / ProcessMessages
  # loop). When the queue is empty, buffered input is processed and reading resumes.
  def handle_info(:continue_getdata, st) do
    case process_getdata(st) do
      {:ok, st} ->
        if getdata_pending?(st) do
          {:noreply, st}
        else
          case st.transport do
            :v1 ->
              drain(st)

            _ ->
              msgs = st.pending_msgs
              dispatch(%{st | pending_msgs: []}, msgs)
          end
          |> rearm()
        end

      stop ->
        stop
    end
  end

  def handle_info({:send_failed, reason}, st),
    do: {:stop, {:shutdown, {:send_failed, reason}}, st}

  # The writer wrote `n` bytes (Core SocketSendData: nLastSend, nSendBytes,
  # and fPauseSend recomputed). Once under the limit again, the next pass
  # serves the remaining getdata and then the buffered input.
  def handle_info({:sent, n}, st) do
    st =
      st
      |> Map.update(:bytes_sent, n, &(&1 + n))
      |> Map.put(:last_send, now(st))
      |> Map.put(:send_queued, st.send_queued - n)

    if st.paused_since != nil and st.send_queued <= max_send_buffer(st) do
      send(self(), :continue_getdata)
      {:noreply, %{st | paused_since: nil}}
    else
      {:noreply, st}
    end
  end

  # TxRelay accepted a tx this peer sent (Core m_last_tx_time).
  def handle_info(:novel_tx, st), do: {:noreply, report_stats(st, %{last_tx_time: now(st)})}

  # Core BlockChecked -> MaybePunishNodeForBlock, for a block this peer sent
  # that failed when the chain state connected it (deferred submission).
  def handle_info({:block_checked, hash, {:error, {result, reason}}}, st) do
    via_compact = hash in st.rebuilt_deferred
    st = %{st | rebuilt_deferred: List.delete(st.rebuilt_deferred, hash)}

    case maybe_punish_for_block(st, result, "invalid block: #{reason}", via_compact) do
      {:ok, st} -> {:noreply, st}
      stop -> stop
    end
  end

  # Messages queued for this peer by other components (tx relay).
  # Our sendcmpct from HighBandwidth: announce = true selects the peer as a
  # high-bandwidth compact block source, false demotes it.
  def handle_info({:send, {:sendcmpct, %{announce: a}} = msg}, %{socket: s} = st) when s != nil,
    do: {:noreply, push(%{st | hb_selected: a}, msg)}

  def handle_info({:send, msg}, %{socket: s} = st) when s != nil, do: {:noreply, push(st, msg)}

  # TxRelay restarted: it lost its per-peer state, so register
  # again, as after the handshake. Before the handshake there is nothing to
  # resend; the handshake registers the peer itself.
  def handle_info(:tx_relay_resync, st) do
    if handshake_done?(st), do: tx_relay_connected(st)
    {:noreply, st}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  # Messages pushed just before a stop are still written (as with the
  # earlier blocking send), waiting at most 1 s for the writer.
  @impl true
  def terminate(_reason, st) do
    if st.writer && st.send_queued > 0 do
      send(st.writer, {:flush, self()})

      receive do
        :flushed -> :ok
      after
        1_000 -> :ok
      end
    end

    :ok
  end

  @impl true
  def handle_call(:info, _from, st) do
    v = st.version || %{}

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
       ping_ms: st.last_pong_rtt_ms,
       best_known: st.best_known && st.best_known.height,
       bytes_sent: Map.get(st, :bytes_sent, 0),
       bytes_recv: Map.get(st, :bytes_recv, 0),
       last_send: Map.get(st, :last_send, 0),
       last_recv: Map.get(st, :last_recv, 0),
       conntime: st.connected_at || 0,
       relay: v[:relay] != false,
       hb_to: st.hb_requested,
       provides_cmpct: st.provides_cmpct,
       timeoffset: (v[:time] && now(st) - v[:time]) || 0,
       transport_protocol_type: transport_type(st.transport),
       session_id:
         (match?(%Transport{}, st.transport) && Transport.session_id(st.transport)) || nil
     }, st}
  end

  # Core TransportProtocolType: "v2" only once the version packet is in.
  defp transport_type(:v1), do: "v1"

  defp transport_type(%Transport{} = t),
    do: if(Transport.established?(t), do: "v2", else: "detecting")

  # Core ProcessMessages: while getdata requests are queued, no further
  # message from this peer is processed ("this maintains the order of
  # responses and prevents m_getdata_requests to grow unbounded"); they stay
  # in the buffer, and the socket is re-armed once the queue drains.
  defp drain(st) do
    if blocked?(st) do
      {:noreply, st}
    else
      case FrameBuffer.next(st.buf, st.p.magic) do
        {:more, buf} ->
          {:noreply, %{st | buf: buf}}

        {:error, reason} ->
          {:stop, {:shutdown, {:bad_frame, reason}}, st}

        {:reject, _cmd, buf} ->
          drain(%{st | buf: buf})

        {:ok, cmd, payload, buf} ->
          case process_message(%{st | buf: buf}, cmd, payload) do
            {:ok, st} -> drain(st)
            stop -> stop
          end
      end
    end
  end

  defp getdata_pending?(st), do: not :queue.is_empty(st.getdata_queue)

  # Core ProcessMessages: nothing more from this peer is processed while its
  # getdata queue is not empty or its send buffer is full (fPauseSend).
  defp blocked?(st), do: getdata_pending?(st) or paused?(st)
  defp paused?(st), do: st.paused_since != nil

  # Reads the next segment only when no getdata is being served and the send
  # buffer is not full (TCP backpressure on a peer that keeps asking, or that
  # asks without reading the answers).
  defp rearm({:noreply, st} = r) do
    if not blocked?(st) and st.socket != nil, do: :inet.setopts(st.socket, active: :once)
    r
  end

  defp rearm(other), do: other

  # Messages decoded by the v2 transport, in order. `:reject` (undecodable
  # message type) is dropped, as Core does with `reject_message`.
  defp dispatch(st, []), do: {:noreply, st}

  # Same rule as drain/1: later messages wait while getdata is being served.
  defp dispatch(st, msgs) do
    if blocked?(st),
      do: {:noreply, %{st | pending_msgs: st.pending_msgs ++ msgs}},
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

  # A large message is decoded and handled holding its size from the
  # node-wide DecodeBudget: decoded terms are several times their
  # wire size, and Core decodes one message at a time on one thread.
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

      # Core checks the handshake before these size limits: a message other
      # than version/verack (and the pre-verack feature messages) is ignored
      # until the handshake completes, never punished.
      {:error, {kind, _}}
      when kind in [:too_many_headers, :inv_too_large, :addr_too_large] and
             not (st.version != nil and st.verack_received) ->
        Logger.debug("peer #{inspect(st.target)}: #{cmd} before the handshake, ignored")
        {:ok, st}

      {:error, {:too_many_headers, n}} ->
        misbehaving(st, "headers message size = #{n}")

      {:error, {:inv_too_large, n}} ->
        misbehaving(st, "inv message size = #{n}")

      {:error, {:addr_too_large, n}} ->
        misbehaving(st, "addr message size = #{n}")

      {:error, reason} ->
        # Core: a deserialization exception is logged and the message
        # dropped; the peer is not disconnected.
        Logger.debug("peer #{inspect(st.target)}: #{cmd} decode error #{inspect(reason)}")
        {:ok, st}
    end
  end

  # Core: at disconnection, an outbound v2 attempt that got nothing back is
  # retried with v1 (CConnman::DisconnectNodes, ShouldReconnectV1).
  defp closing(st, reason) do
    case st.transport do
      %Transport{} = t ->
        if Transport.should_reconnect_v1?(t),
          do: {:stop, {:shutdown, {:reconnect_v1, reason}}, st},
          else: {:stop, {:shutdown, reason}, st}

      _ ->
        {:stop, {:shutdown, reason}, st}
    end
  end

  # --- handshake -------------------------------------------------------------

  defp send_version(st) do
    {host, port} = st.target || {nil, 0}

    addr_recv =
      case host && :inet.parse_address(to_charlist(host)) do
        {:ok, {a, b, c, d}} -> %{services: 0, net: :ipv4, addr: <<a, b, c, d>>, port: port}
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
      # Block-relay-only connections announce fRelay = false.
      relay: st.conn_type != :block_relay
    }

    # Core CheckIncomingNonce: only outbound connections not yet fully
    # connected count; the entry goes at verack or when this process exits.
    if not st.inbound and st.node[:local_nonces],
      do: Registry.register(st.node.local_nonces, st.local_nonce, nil)

    push(%{st | sent_version: true}, {:version, v})
  end

  # Core FastRandomContext: unpredictable to peers, never 0.
  defp rand64, do: elem(:rand.uniform_s(0xFFFFFFFFFFFFFFFF, :crypto.rand_seed_s()), 0)

  defp connected_to_self?(st, nonce) do
    st.inbound and st.node[:local_nonces] != nil and
      Registry.lookup(st.node.local_nonces, nonce) != []
  end

  defp handshake_done?(st), do: st.version != nil and st.verack_received

  # Core: VERACK -> TxDownloadManager::ConnectedPeer for every peer that is not
  # block-relay-only. A peer that sent version fRelay = false still has its txs
  # and tx invs processed (only RejectIncomingTxs drops them), so TxRelay must
  # know it too: its DOWN monitor is what erases the orphans it announced
  # (Core DisconnectedPeer -> EraseForPeer). `relay_txs` keeps
  # us from announcing txs to it.
  defp tx_relay_connected(st) do
    if st.node[:tx_relay] && st.conn_type != :block_relay do
      Exnode.P2P.TxRelay.connected(st.node.tx_relay, self(), %{
        wtxid_relay: st.wtxid_relay,
        preferred: not st.inbound,
        relay_txs: st.version.relay,
        inbound: st.inbound
      })

      if st.feefilter, do: Exnode.P2P.TxRelay.feefilter(st.node.tx_relay, self(), st.feefilter)
    end
  end

  # Core: ProcessMessage VERSION
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

      # Core: a feeler only checks that the address is online; AddrMan::Good
      # is applied at VERSION ("feeler connection completed"), then it ends.
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

        # Core: the services an outbound peer reports update addrman, so a
        # NODE_P2P_V2 peer is reached over v2 next time (AddrMan::SetServices).
        if (not st.inbound and st.node[:addrman]) && st.target,
          do: AddrMan.set_services(st.node.addrman, AddrMan.key(target_addr(st)), v.services)

        # Core: m_relays_txs (fRelay on a non-block-relay connection) and
        # m_has_all_wanted_services (HasAllDesirableServiceFlags), for eviction.
        relay = v.relay != false and st.conn_type != :block_relay
        stats = %{relay_txs: relay, relevant_services: desirable_services?(st, v.services)}
        st = report_stats(st, stats)

        # Core MaybeDisconnectForTxRelayCapacity, before VERACK.
        if st.inbound and relay and st.node[:connman] != nil and
             Exnode.P2P.Connman.tx_relay_capacity(st.node.connman, stats) == :disconnect do
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
    # Core fSuccessfullyConnected: no longer a self-connection candidate.
    if st.node[:local_nonces], do: Registry.unregister(st.node.local_nonces, st.local_nonce)
    st = if common >= @sendheaders_version, do: push(st, :sendheaders), else: st

    st =
      if common >= @short_ids_blocks_version,
        do: push(st, {:sendcmpct, %{announce: false, version: 2}}),
        else: st

    # Ask outbound full-relay peers for addresses (Core: getaddr once, outbound only).
    st =
      if st.conn_type in [:outbound_full_relay, :manual],
        do: %{push(st, :getaddr) | addr_rate: Exnode.P2P.AddrRate.getaddr_sent(st.addr_rate)},
        else: st

    if st.node[:connman],
      do:
        send(st.node.connman, {:peer_ready, self(), st.target, st.conn_type, st.version.services})

    # Block announcements start from the tip at handshake time.
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
  # Core: SENDCMPCT. Only version 2 (wtxid short ids) is supported.
  defp handle_msg({:sendcmpct, %{version: 2, announce: a}}, st),
    do: {:ok, %{st | provides_cmpct: true, hb_requested: a}}

  defp handle_msg({:sendcmpct, _}, st), do: {:ok, st}

  defp handle_msg({:cmpctblock, payload}, st), do: compact_block(st, payload)
  defp handle_msg({:blocktxn, payload}, st), do: block_txn(st, payload)
  defp handle_msg({:getblocktxn, payload}, st), do: serve_getblocktxn(st, payload)
  defp handle_msg({:getcfilters, req}, st), do: serve_cfilters(st, req)
  defp handle_msg({:getcfheaders, req}, st), do: serve_cfheaders(st, req)
  defp handle_msg({:getcfcheckpt, req}, st), do: serve_cfcheckpt(st, req)

  # Core ProcessMessage FEEFILTER: kept only if MoneyRange. TxRelay is told
  # only of a change, and waits the peer like any other TxRelay call, so a
  # feefilter flood cannot queue work there.
  defp handle_msg({:feefilter, rate}, st) do
    cond do
      not Exnode.Consensus.money_range?(rate) or rate == st.feefilter ->
        {:ok, st}

      true ->
        if st.node[:tx_relay], do: Exnode.P2P.TxRelay.feefilter(st.node.tx_relay, self(), rate)
        {:ok, %{st | feefilter: rate}}
    end
  end

  defp handle_msg({:ping, nil}, st), do: {:ok, st}
  defp handle_msg({:ping, nonce}, st), do: {:ok, push(st, {:pong, nonce})}

  defp handle_msg({:pong, nonce}, %{ping_nonce: nonce} = st) when nonce != nil do
    rtt = :erlang.monotonic_time(:millisecond) - st.ping_sent_mono
    # Core m_min_ping_time (eviction protects the 8 lowest).
    min_ping = min(Map.get(st, :min_ping_us, :infinity), rtt * 1000)
    st = st |> Map.put(:min_ping_us, min_ping) |> report_stats(%{min_ping: min_ping})
    {:ok, %{st | ping_nonce: nil, last_pong_rtt_ms: rtt}}
  end

  defp handle_msg({:pong, _}, st), do: {:ok, st}

  defp handle_msg({:headers, headers}, st), do: process_headers_message(st, headers)

  defp handle_msg({:block, payload}, st) do
    result =
      case Block.decode_exact(payload) do
        {:ok, b} -> received_block(st, b)
        # Core: a deserialization failure is logged and the message dropped.
        {:error, _} -> {:ok, st}
      end

    # Blocks are large refcounted binaries; a mostly idle peer process would
    # otherwise keep them alive until its next (rare) garbage collection.
    :erlang.garbage_collect()
    result
  end

  # Core ignores getheaders while in IBD (unless the peer has download
  # permission). node.serve_headers (default true) turns serving off
  # altogether (tests).
  defp handle_msg({:getheaders, gh}, st) do
    # Core ignores getheaders while in IBD.
    if Map.get(st.node, :serve_headers, true) and not initial_block_download?(st),
      do: serve_getheaders(st, gh),
      else: {:ok, st}
  end

  # Core ProcessMessage TX. A block-relay-only peer must not send txs.
  defp handle_msg({:tx, payload}, st) do
    cond do
      st.conn_type == :block_relay ->
        {:stop, {:shutdown, :tx_from_block_relay_peer}, st}

      st.node[:tx_relay] == nil or initial_block_download?(st) ->
        {:ok, st}

      true ->
        case Exnode.Codec.Tx.decode_exact(payload) do
          {:ok, tx} -> Exnode.P2P.TxRelay.received_tx(st.node.tx_relay, self(), tx)
          {:error, _} -> :ok
        end

        {:ok, st}
    end
  end

  # Core ProcessMessage NOTFOUND: tx items count only when the message has at
  # most MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER entries.
  # TxRelay.notfound is a call, so the peer waits for it to be handled
  # instead of queueing unbounded work in TxRelay.
  defp handle_msg({:notfound, items}, st) do
    tx_items =
      if length(items) <= @max_notfound_items,
        do: Enum.filter(items, &(&1.type in [:tx, :wtx])),
        else: []

    if st.node[:tx_relay] && tx_items != [],
      do: Exnode.P2P.TxRelay.notfound(st.node.tx_relay, self(), tx_items)

    {:ok, st}
  end

  # Core: GETDATA appends to m_getdata_requests, then ProcessGetData.
  defp handle_msg({:getdata, items}, st) do
    process_getdata(%{st | getdata_queue: Enum.reduce(items, st.getdata_queue, &:queue.in/2)})
  end

  # Unknown block announced: ask for headers (Core: getheaders on block inv).
  defp handle_msg({:inv, items}, st) do
    tx_items = Enum.filter(items, &(&1.type in [:tx, :wtx]))

    # Core: tx announcements are ignored during IBD and from block-relay peers.
    st =
      if tx_items != [] and st.node[:tx_relay] != nil and st.conn_type != :block_relay and
           not initial_block_download?(st) do
        # Core AddKnownTx, here rather than in the shared TxRelay: MSG_WTX
        # from a wtxid-relay peer, MSG_TX from the others.
        known = st.known_in || Exnode.P2P.TxRelay.new_known_filter()
        kind = if st.wtxid_relay, do: :wtx, else: :tx
        for %{type: ^kind, hash: h} <- tx_items, do: RollingBloom.insert(known, h)
        Exnode.P2P.TxRelay.inv(st.node.tx_relay, self(), tx_items, known)
        %{st | known_in: known}
      else
        st
      end

    idx = Headers.index(st.node.headers)

    # Core: UpdateBlockAvailability for announced blocks whose header we know.
    st =
      Enum.reduce(items, st, fn
        %{type: :block, hash: h}, st ->
          case HeaderIndex.lookup(idx, h) do
            nil -> st
            e -> %{st | best_known: better(st.best_known, e)}
          end

        _, st ->
          st
      end)

    if Enum.any?(items, &(&1.type == :block and HeaderIndex.lookup(idx, &1.hash) == nil)),
      do: {:ok, maybe_send_getheaders(st, HeaderIndex.locator(idx, HeaderIndex.best(idx)))},
      else: {:ok, st}
  end

  defp handle_msg({kind, addrs}, st) when kind in [:addr, :addrv2] do
    if st.conn_type != :block_relay and st.node[:addrman] do
      # Core ProcessAddrs: the token bucket decides how many are processed.
      {rate, accepted, _limited} =
        Exnode.P2P.AddrRate.received(st.addr_rate, addrs, Exnode.Clock.mono(st.node[:clock]))

      accepted = sanitize_addrs(st, accepted)
      src = st.target && AddrMan.key(target_addr(st))
      # Core: gossiped addresses get a 2 h time penalty (none for self-announcements).
      if accepted != [], do: AddrMan.add(st.node.addrman, accepted, src || :seed, 2 * 3600)
      {:ok, %{st | addr_rate: rate}}
    else
      {:ok, st}
    end
  end

  defp handle_msg(:getaddr, st) do
    # Core answers only inbound peers, once per connection.
    if st.inbound and not st.getaddr_answered and st.node[:addrman] do
      # Core GetAddresses: the cached answer for the requester's network.
      net = (st.target && elem(AddrMan.key(target_addr(st)), 0)) || :ipv4
      # AddrMan may be restarting on its own: answer with nothing.
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

  defp common_version(st), do: min(st.version.version, Message.protocol_version())

  # Core IsInitialBlockDownload (simplified): the active tip is more than 24 h
  # old (DEFAULT_MAX_TIP_AGE) or behind the minimum chain work.
  defp initial_block_download?(st) do
    view = st.node[:chain_state] && ChainState.view(st.node.chain_state)

    if view,
      do: ChainState.view_ibd?(view, Headers.index(st.node.headers), now(st), st.p),
      else: false
  end

  defp target_addr(%{target: {host, port}}) do
    case :inet.parse_address(to_charlist(host)) do
      {:ok, {a, b, c, d}} ->
        %{net: :ipv4, addr: <<a, b, c, d>>, port: port}

      {:ok, t} ->
        %{net: :ipv6, addr: for(x <- Tuple.to_list(t), into: <<>>, do: <<x::16>>), port: port}

      _ ->
        %{net: :dns, addr: to_string(host), port: port}
    end
  end

  # --- ping ------------------------------------------------------------------

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

  # --- headers sync (Core SendMessages / ProcessHeadersMessage) --------------

  defp maybe_start_sync(%{sync_started: true} = st, _t), do: st

  defp maybe_start_sync(st, t) do
    can_serve = st.version && (st.version.services &&& Message.service(:network)) != 0

    if handshake_done?(st) and can_serve do
      idx = Headers.index(st.node.headers)
      best = HeaderIndex.best(idx)
      preferred = not st.inbound
      recent = best.time > t - 24 * 3600

      if SyncState.try_start(st.node.sync, self(), preferred, recent) do
        # Core: m_headers_sync_timeout = now + BASE + PER_HEADER * (now - best.time) / spacing
        expected_headers = div(max(t - best.time, 0), st.p.pow_target_spacing)

        timeout =
          t + @headers_download_timeout_base_s +
            div(expected_headers * @headers_download_timeout_per_header_ms, 1000)

        # Core starts from pindexBestHeader->pprev, so the peer replies with at least one header.
        start = HeaderIndex.prev(idx, best) || best
        st = %{st | sync_started: true, headers_sync_timeout: timeout}
        maybe_send_getheaders(st, HeaderIndex.locator(idx, start))
      else
        st
      end
    else
      st
    end
  end

  # Core SendMessages "Timeout downloading headers": past the deadline with
  # our best header still older than 24h, the peer is disconnected if it is
  # the only one syncing and another preferred (outbound) peer could take
  # over, inbound or not. Otherwise it stays and is checked again on the next
  # pass ("if all our peers are inbound ... we have bigger problems"). Core
  # instead stops counting a NoBan peer; exnode has no NoBan peers. A best
  # header within 24h ends the deadline.
  defp check_headers_sync_timeout(%{sync_started: true, headers_sync_timeout: dl} = st, t)
       when is_integer(dl) and t > dl do
    best = Headers.best_header(st.node.headers)

    cond do
      best.time > t - 24 * 3600 ->
        {:noreply, %{st | headers_sync_timeout: nil}}

      SyncState.count(st.node.sync) == 1 and other_preferred_peer?(st) ->
        {:stop, {:shutdown, :headers_sync_timeout}, st}

      true ->
        {:noreply, st}
    end
  end

  defp check_headers_sync_timeout(st, _t), do: {:noreply, st}

  defp other_preferred_peer?(%{node: %{block_download: bd}}) when bd != nil,
    do: BlockDownload.other_preferred?(bd, self())

  defp other_preferred_peer?(_st), do: false

  # Core: MaybeSendGetHeaders (HEADERS_RESPONSE_TIME throttle)
  defp maybe_send_getheaders(st, locator, force \\ false) do
    t = now(st)

    if force or st.last_getheaders_at == nil or
         t - st.last_getheaders_at > @headers_response_time_s do
      push(
        %{st | last_getheaders_at: t},
        {:getheaders, %{locator: locator, hash_stop: <<0::256>>}}
      )
    else
      st
    end
  end

  # Core: PeerManagerImpl::ProcessHeadersMessage
  defp process_headers_message(st, []) do
    {:ok, %{st | headers_sync: nil, last_getheaders_at: nil}}
  end

  defp process_headers_message(st, headers) do
    count = length(headers)
    full = count == Message.max_headers_results()

    # Core: CheckHeadersPoW (HasValidProofOfWork + CheckHeadersAreContinuous)
    cond do
      not Enum.all?(headers, &Pow.check_proof_of_work(&1.hash, &1.bits, st.p.pow_limit)) ->
        misbehaving(st, "header with invalid proof of work")

      not continuous?(headers) ->
        misbehaving(st, "non-continuous headers sequence")

      true ->
        {already_validated, headers, st} = continuation_of_low_work_sync(st, headers, full)
        have_headers_sync = st.headers_sync != nil

        if headers == [],
          do: {:ok, st},
          else:
            process_connected_headers(st, headers, count, already_validated, have_headers_sync)
    end
  end

  defp process_connected_headers(st, headers, count, already_validated, have_headers_sync) do
    idx = Headers.index(st.node.headers)

    case HeaderIndex.lookup(idx, hd(headers).prev_hash) do
      nil ->
        # Core: HandleUnconnectingHeaders
        {:ok, maybe_send_getheaders(st, HeaderIndex.locator(idx, HeaderIndex.best(idx)))}

      chain_start ->
        st = %{st | last_getheaders_at: nil}
        last_received = HeaderIndex.lookup(idx, List.last(headers).hash)

        already_validated =
          already_validated or
            (last_received != nil and
               HeaderIndex.ancestor_of?(idx, last_received, HeaderIndex.best(idx)))

        case not already_validated &&
               try_low_work_headers_sync(st, idx, chain_start, headers, count) do
          {:handled, st} -> {:ok, st}
          _ -> accept_headers(st, headers, count, have_headers_sync)
        end
    end
  end

  defp accept_headers(st, headers, count, have_headers_sync) do
    case Headers.process_headers(st.node.headers, headers, min_pow_checked: true, now: now(st)) do
      {:ok, last} ->
        st = maybe_protect(%{st | best_known: better(st.best_known, last)})

        st =
          if count == Message.max_headers_results() and not have_headers_sync,
            do:
              maybe_send_getheaders(st, HeaderIndex.locator(Headers.index(st.node.headers), last)),
            else: st

        {:ok, st}

      {:error, {result, reason}, _last} ->
        maybe_punish_for_block(st, result, "invalid header received: #{reason}")
    end
  end

  defp better(nil, e), do: e
  defp better(a, b), do: if(b.chain_work > a.chain_work, do: b, else: a)

  # Core: IsContinuationOfLowWorkHeadersSync
  defp continuation_of_low_work_sync(%{headers_sync: nil} = st, headers, _full),
    do: {false, headers, st}

  defp continuation_of_low_work_sync(st, headers, full) do
    {res, hs} = HeadersSync.process_next_headers(st.headers_sync, headers, full)
    st = if res.success, do: %{st | last_getheaders_at: nil}, else: st

    st =
      if res.request_more,
        do: maybe_send_getheaders(st, HeadersSync.next_headers_request_locator(hs), true),
        else: st

    st = %{st | headers_sync: if(HeadersSync.state(hs) == :final, do: nil, else: hs)}

    if res.success, do: {true, res.pow_validated_headers, st}, else: {false, headers, st}
  end

  # Core: TryLowWorkHeadersSync
  defp try_low_work_headers_sync(st, idx, chain_start, headers, count) do
    claimed = Enum.reduce(headers, 0, &(&2 + Pow.bits_proof(&1.bits)))
    threshold = anti_dos_work_threshold(st)

    if chain_start.chain_work + claimed < threshold do
      if count == Message.max_headers_results() do
        hs =
          HeadersSync.new(
            st.p,
            chain_start,
            HeaderIndex.median_time_past(idx, chain_start),
            HeaderIndex.locator(idx, chain_start),
            threshold,
            now(st)
          )

        {_validated, _headers, st} =
          continuation_of_low_work_sync(%{st | headers_sync: hs}, headers, true)

        {:handled, st}
      else
        # "Ignoring low-work chain"
        {:handled, st}
      end
    else
      :not_low_work
    end
  end

  # Core: GetAntiDoSWorkThreshold, on the active tip (genesis until blocks connect).
  defp anti_dos_work_threshold(st),
    do: HeaderIndex.anti_dos_work_threshold(active_tip_header(st), st.p)

  # The active tip's header entry; nil without a chain state.
  defp active_tip_header(st) do
    if cs = st.node[:chain_state] do
      t =
        if v = is_atom(cs) && ChainState.view(cs),
          do: ChainState.view_tip(v),
          else: ChainState.tip(cs)

      HeaderIndex.lookup(Headers.index(st.node.headers), t.hash)
    end
  end

  # The active tip, genesis without a chain state.
  defp chain_sync_tip(st, idx),
    do: active_tip_header(st) || HeaderIndex.ancestor(idx, HeaderIndex.best(idx), 0)

  # Core: UpdatePeerStateForReceivedHeaders. Up to
  # MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT (4) outbound full-relay
  # peers with a chain at least as good as our tip are exempt from
  # ConsiderEviction; block-relay peers never are.
  defp maybe_protect(
         %{conn_type: :outbound_full_relay, chain_sync: %{protect: false}, best_known: b} = st
       )
       when b != nil do
    tip = chain_sync_tip(st, Headers.index(st.node.headers))

    if b.chain_work >= tip.chain_work and SyncState.try_protect(st.node.sync, self()),
      do: put_in(st.chain_sync.protect, true),
      else: st
  end

  defp maybe_protect(st), do: st

  # Core: ConsiderEviction (CHAIN_SYNC_TIMEOUT, HEADERS_RESPONSE_TIME). An
  # unprotected outbound full-relay or block-relay peer that started sync
  # and whose best known block has less work than our tip has 20 min to
  # reach the work of the tip at the time; then it gets one getheaders and
  # 2 min to answer, else it is disconnected. Without this, a peer that only
  # answers pings holds an outbound slot forever.
  defp consider_eviction(
         {:noreply, %{chain_sync: %{protect: false}, sync_started: true, conn_type: ct} = st},
         t
       )
       when ct in [:outbound_full_relay, :block_relay] do
    idx = Headers.index(st.node.headers)
    tip = chain_sync_tip(st, idx)
    cs = st.chain_sync
    best = st.best_known

    cond do
      best != nil and best.chain_work >= tip.chain_work ->
        {:noreply,
         %{st | chain_sync: %{cs | timeout: nil, work_header: nil, sent_getheaders: false}}}

      cs.timeout == nil or
          (cs.work_header != nil and best != nil and
             best.chain_work >= cs.work_header.chain_work) ->
        cs = %{cs | timeout: t + @chain_sync_timeout_s, work_header: tip, sent_getheaders: false}
        {:noreply, %{st | chain_sync: cs}}

      t > cs.timeout and cs.sent_getheaders ->
        Logger.info(
          "outbound peer has old chain, best known block = " <>
            if(best, do: Base.encode16(best.hash, case: :lower), else: "<none>")
        )

        {:stop, {:shutdown, :chain_sync_timeout}, st}

      t > cs.timeout ->
        # Core: GetLocator(m_work_header->pprev), through the getheaders throttle.
        start = HeaderIndex.prev(idx, cs.work_header) || cs.work_header
        st = maybe_send_getheaders(st, HeaderIndex.locator(idx, start))
        cs = %{cs | sent_getheaders: true, timeout: t + @headers_response_time_s}
        {:noreply, %{st | chain_sync: cs}}

      true ->
        {:noreply, st}
    end
  end

  defp consider_eviction(result, _t), do: result

  defp continuous?([_]), do: true
  defp continuous?([a, b | rest]), do: b.prev_hash == a.hash and continuous?([b | rest])

  # Core: MaybePunishNodeForBlock. `via_compact`: the header came in a
  # cmpctblock, or the block was rebuilt from one. BIP152 lets a
  # high-bandwidth peer relay a block after checking only its header (Core
  # announces from NewPoWValidBlock, before ConnectBlock), so an invalid
  # block or a header we hold as invalid is not that peer's fault; a peer
  # that builds on an invalid chain is still caught by its headers.
  defp maybe_punish_for_block(st, result, msg, via_compact \\ false) do
    case result do
      # Our own validation crash (quarantine), or a block refused because it
      # is quarantined: never the peer's fault.
      r when r in [:crash, :quarantined] ->
        {:ok, st}

      r when r in [:consensus, :mutated] ->
        if via_compact, do: {:ok, st}, else: misbehaving(st, msg)

      r when r in [:invalid_header, :invalid_prev, :missing_prev] ->
        misbehaving(st, msg)

      # Outbound (not inbound) peers on an invalid chain; not via compact.
      :cached_invalid ->
        if st.inbound or via_compact, do: {:ok, st}, else: misbehaving(st, msg)

      _ ->
        {:ok, st}
    end
  end

  # --- blocks ----------------------------------------------------------------

  # Core SendMessages block download. `preferred` is Core fPreferredDownload
  # (outbound); in IBD a non-preferred (inbound) peer is used only when no
  # preferred peer is connected or nothing is in flight.
  # The call is made without a best known header too, so BlockDownload
  # counts preferred peers from the handshake on.
  defp maybe_request_blocks(%{node: %{block_download: bd}} = st) when bd != nil do
    serves = st.version && (st.version.services &&& Message.service(:network)) != 0

    if handshake_done?(st) and serves do
      best = st.best_known && st.best_known.hash
      # (IBD matters only for a non-preferred peer; skip the lookup otherwise.)
      opts = [preferred: not st.inbound, ibd: st.inbound and initial_block_download?(st)]

      case BlockDownload.request(bd, self(), best, opts) do
        [] ->
          st

        hashes ->
          push(st, {:getdata, Enum.map(hashes, &%{type: :block, witness: true, hash: &1})})
      end
    else
      st
    end
  end

  defp maybe_request_blocks(st), do: st

  # Core ProcessMessage BLOCK: a block that connects to a known header is
  # checked for mutation (IsBlockMutated) before anything else, so a garbage
  # body under a real header is punished before it can touch download state
  # or the storage gates.
  defp received_block(st, b) do
    idx = Headers.index(st.node.headers)

    case HeaderIndex.lookup(idx, b.header.prev_hash) do
      nil ->
        process_block(st, b)

      prev ->
        # DeploymentActiveAfter(prev_block, SEGWIT)
        if Exnode.P2P.CompactBlock.mutated?(b, prev.height + 1 >= st.p.segwit_height),
          do: misbehaving(st, "mutated block"),
          else: process_block(st, b)
    end
  end

  # Core: ProcessMessage BLOCK -> ProcessBlock, then MaybePunishNodeForBlock.
  # `rebuilt`: a block rebuilt from a compact block, which Core processes with
  # force_processing = true (ProcessCompactBlockTxns, net_processing.cpp).
  defp process_block(st, %Block{} = b, rebuilt \\ false) do
    st = %{st | partials: Map.delete(st.partials, b.header.hash)}
    # Core: forceProcessing = IsBlockRequested(hash); RemoveBlockRequest(hash).
    # The request becomes a checking reservation (BlockDownload) until the
    # outcome below: nobody re-requests the block while it is checked here.
    # A rebuilt block takes over whoever's request it had.
    in_flight =
      st.node[:block_download] != nil and
        if(rebuilt,
          do:
            BlockDownload.rebuilt(
              st.node.block_download,
              self(),
              b.header.hash,
              byte_size(b.raw || <<>>)
            ),
          else:
            BlockDownload.received(
              st.node.block_download,
              self(),
              b.header.hash,
              byte_size(b.raw || <<>>)
            )
        )

    requested = rebuilt or in_flight

    # The cheap storage/header gates run first. CheckBlock then runs here,
    # in parallel with other peers, ahead of the single-writer chain state.
    # In IBD the chain state only stores the block and replies; it connects
    # blocks afterwards, in steps, so this peer goes on downloading. A block
    # found invalid then comes back as {:block_checked, ...} (Core BlockChecked).
    ibd = initial_block_download?(st)

    submit = fn cs ->
      case ChainState.precheck_block(cs, b.header, requested) do
        :check ->
          ChainState.submit_block(cs, b,
            checked: ChainState.check_block(b, st.node.params),
            defer: ibd,
            requested: requested,
            source: self()
          )

        reply ->
          reply
      end
    end

    outcome = st.node[:chain_state] && submit.(st.node.chain_state)

    # Releases this peer's checking reservation (a no-op if it held none):
    # held now, or selectable again from anyone.
    if st.node[:block_download] != nil,
      do:
        BlockDownload.checked(
          st.node.block_download,
          self(),
          b.header.hash,
          outcome in [nil, {:ok, :connected}, {:ok, :stored}, {:ok, :duplicate}]
        )

    # A rebuilt block stored for a deferred verdict: that verdict is via
    # compact block too.
    st =
      if rebuilt and outcome == {:ok, :stored},
        do: %{
          st
          | rebuilt_deferred: Enum.take([b.header.hash | st.rebuilt_deferred], @max_partials)
        },
        else: st

    case outcome do
      {:error, {result, reason}} ->
        maybe_punish_for_block(st, result, "invalid block: #{reason}", rebuilt)

      reply ->
        # Core ProcessBlock: m_last_block_time when the block was new (eviction);
        # a duplicate or a skipped unrequested block (`{:ok, :skipped}`) is not.
        st =
          if reply in [{:ok, :connected}, {:ok, :stored}],
            do: report_stats(st, %{last_block_time: now(st)}),
            else: st

        idx = Headers.index(st.node.headers)
        e = HeaderIndex.lookup(idx, b.header.hash)
        st = if e, do: %{st | best_known: better(st.best_known, e)}, else: st

        # BIP152: a peer that delivers a new block becomes high-bandwidth.
        if reply == {:ok, :connected} and st.provides_cmpct and st.node[:high_bandwidth] != nil and
             not initial_block_download?(st),
           do: Exnode.P2P.HighBandwidth.select(st.node.high_bandwidth, self(), st.inbound)

        {:ok, maybe_request_blocks(st)}
    end
  end

  # --- compact blocks (BIP152) -------------------------------------------------

  alias Exnode.P2P.CompactBlock

  # Core ProcessMessage CMPCTBLOCK (receive side).
  defp compact_block(%{provides_cmpct: false} = st, _payload), do: {:ok, st}

  defp compact_block(st, payload) do
    case CompactBlock.decode(payload) do
      # Core: a deserialization failure drops the message; an
      # invalid but well-formed one is misbehaving (CompactBlock.init/2).
      {:error, why} -> dropped(st, "cmpctblock", why)
      {:ok, c} -> compact_block_decoded(st, c)
    end
  end

  defp compact_block_decoded(st, c) do
    idx = Headers.index(st.node.headers)
    prev = HeaderIndex.lookup(idx, c.header.prev_hash)

    cond do
      prev == nil ->
        # Unknown parent: sync headers instead.
        {:ok,
         if(initial_block_download?(st),
           do: st,
           else: maybe_send_getheaders(st, HeaderIndex.locator(idx, HeaderIndex.best(idx)))
         )}

      # Core: "Ignoring low-work compact block" (net_processing.cpp), before
      # ProcessNewBlockHeaders, so a cheap low-work header is never stored
      # (the headers path does this in TryLowWorkHeadersSync).
      prev.chain_work + Pow.bits_proof(c.header.bits) < anti_dos_work_threshold(st) ->
        {:ok, st}

      true ->
        # Core: ProcessNewBlockHeaders with min_pow_checked = true.
        case Headers.process_headers(st.node.headers, [c.header],
               min_pow_checked: true,
               now: now(st)
             ) do
          {:error, {result, reason}, _} ->
            maybe_punish_for_block(st, result, "invalid header via cmpctblock: #{reason}", true)

          {:error, {result, reason}} ->
            maybe_punish_for_block(st, result, "invalid header via cmpctblock: #{reason}", true)

          {:ok, _} ->
            compact_block_header_ok(st, c)
        end
    end
  end

  # Core ProcessMessage CMPCTBLOCK after ProcessNewBlockHeaders. Reconstruction
  # costs a pass over the whole mempool, so, as in Core, only a block we
  # requested from this peer or one announced by a peer we selected as
  # high-bandwidth gets one; anything else is ignored.
  defp compact_block_header_ok(st, c) do
    hash = c.header.hash
    idx = Headers.index(st.node.headers)
    e = HeaderIndex.lookup(idx, hash)
    view = ChainState.view(st.node.chain_state)
    tip = ChainState.view_tip(view)
    tip_e = HeaderIndex.lookup(idx, tip.hash)
    st = %{st | best_known: better(st.best_known, e)}

    cond do
      # BLOCK_HAVE_DATA: nothing to do.
      MapSet.member?(ChainState.view_have_many(view, [hash]), hash) ->
        {:ok, st}

      # "Peer sent us compact block we were already syncing": a reconstruction
      # in progress, or one already tried (the full block was then requested).
      Map.has_key?(st.partials, hash) or hash in st.cmpct_seen ->
        {:ok, st}

      true ->
        {owner, already_in_flight, checking} = block_in_flight(st, hash)
        from_this_peer = owner == self()

        cond do
          # Received and being processed by a peer: Core has its data
          # already (BLOCK_HAVE_DATA), so no mempool pass or getblocktxn.
          checking ->
            {:ok, st}

          # "not marked as high-bandwidth, sent us an unsolicited compact block"
          not from_this_peer and not st.hb_selected ->
            {:ok, st}

          # We know something better: a block we asked this peer for is fetched whole.
          e.chain_work <= tip_e.chain_work ->
            {:ok, if(from_this_peer, do: request_full_block(st, hash), else: st)}

          # Not close to the tip yet: parallel block download handles it.
          not already_in_flight and not can_direct_fetch?(st, tip_e) ->
            {:ok, st}

          # Too far ahead to rebuild from the mempool: normal block download handles it.
          e.height > tip.height + 2 ->
            {:ok, maybe_request_blocks(st)}

          # Full block, but only while this peer can take it in flight.
          map_size(st.partials) >= @max_partials ->
            {:ok, request_full_block(st, hash)}

          true ->
            rebuild(%{st | cmpct_seen: Enum.take([hash | st.cmpct_seen], @max_cmpct_seen)}, c)
        end
    end
  end

  # `{peer holding the request or nil, whether any peer holds it, whether
  # it is received and being checked}` (Core mapBlocksInFlight), from the
  # shared block download state.
  defp block_in_flight(%{node: %{block_download: bd}}, hash) when bd != nil do
    case BlockDownload.in_flight_state(bd, hash) do
      nil -> {nil, false, false}
      {:requested, peer} -> {peer, true, false}
      {:checking, peer} -> {peer, true, true}
    end
  end

  defp block_in_flight(_st, _hash), do: {nil, false, false}

  # Core CanDirectFetch: the tip is less than 20 block intervals old.
  defp can_direct_fetch?(st, tip_e), do: tip_e.time > now(st) - st.p.pow_target_spacing * 20

  defp rebuild(st, c) do
    mp = st.node[:mempool]

    match = fn keys, ids ->
      if mp, do: Exnode.Mempool.match_short_ids(mp, keys, ids), else: %{}
    end

    case CompactBlock.init(c, match) do
      :invalid ->
        misbehaving(st, "invalid compact block")

      :failed ->
        {:ok, request_full_block(st, c.header.hash)}

      {:ok, partial} ->
        case CompactBlock.missing(partial) do
          [] ->
            finish_rebuild(st, c.header.hash, partial, [])

          gaps ->
            mark_in_flight(st, c.header.hash)

            {:ok,
             %{
               push(st, {:getblocktxn, CompactBlock.encode_getblocktxn(c.header.hash, gaps)})
               | partials:
                   Map.put(st.partials, c.header.hash, %{partial: partial, started: now(st)})
             }}
        end
    end
  end

  # Core ProcessMessage BLOCKTXN -> ProcessCompactBlockTxns.
  defp block_txn(st, payload) do
    case CompactBlock.decode_blocktxn(payload) do
      {:error, why} ->
        dropped(st, "blocktxn", why)

      {:ok, hash, txs} ->
        case Map.pop(st.partials, hash) do
          {nil, _} ->
            {:ok, st}

          {%{partial: partial}, rest} ->
            finish_rebuild(%{st | partials: rest}, hash, partial, txs)
        end
    end
  end

  defp expire_partials(%{partials: ps} = st, _t) when map_size(ps) == 0, do: st

  defp expire_partials(st, t) do
    have = ChainState.view_have_many(ChainState.view(st.node.chain_state), Map.keys(st.partials))

    Enum.reduce(st.partials, st, fn {hash, p}, st ->
      cond do
        MapSet.member?(have, hash) ->
          if bd = st.node[:block_download], do: BlockDownload.cancel(bd, self(), hash)
          %{st | partials: Map.delete(st.partials, hash)}

        t - p.started >= @partial_timeout_s ->
          request_full_block(%{st | partials: Map.delete(st.partials, hash)}, hash)

        true ->
          st
      end
    end)
  end

  defp finish_rebuild(st, hash, partial, txs) do
    case CompactBlock.fill(partial, txs) do
      {:ok, b} ->
        Logger.info(
          "compact block #{Exnode.Crypto.Hash.to_hex(hash)} rebuilt: #{length(b.txs)} txs, #{length(txs)} requested"
        )

        process_block(st, b, true)

      :invalid ->
        misbehaving(st, "invalid compact block txns")

      # Mutated (a short-id collision picked a wrong tx): get the full block.
      :failed ->
        {:ok, request_full_block(st, hash)}
    end
  end

  # Core falls back to getdata only when this peer is first in flight for
  # the block; otherwise it gives up on this peer and waits for the others.
  # A getdata without the request would be untracked here, beyond the
  # peer's MAX_BLOCKS_IN_TRANSIT_PER_PEER and the byte budget.
  defp request_full_block(st, hash) do
    if mark_in_flight(st, hash),
      do: push(st, {:getdata, [%{type: :block, witness: true, hash: hash}]}),
      else: st
  end

  # Core BlockRequested for a compact block's reconstruction or its full
  # fallback: in flight from this peer, so parallel download does not fetch
  # it too. False if another peer holds it or this peer has
  # MAX_BLOCKS_IN_TRANSIT_PER_PEER in flight; true without block download.
  defp mark_in_flight(st, hash) do
    if bd = st.node[:block_download], do: BlockDownload.mark(bd, self(), hash), else: true
  end

  # --- getheaders serving ----------------------------------------------------

  # Core: ProcessMessage GETHEADERS. Find the fork point via the locator,
  # then return up to 2000 headers after it along the best-header chain.
  defp serve_getheaders(st, %{locator: loc, hash_stop: stop}) do
    if length(loc) > Message.max_locator_sz() do
      {:stop, {:shutdown, :locator_too_large}, st}
    else
      idx = Headers.index(st.node.headers)
      tip = active_tip_entry(st, idx)

      on_active = fn e ->
        e.height <= tip.height and HeaderIndex.ancestor(idx, tip, e.height).hash == e.hash
      end

      # Core: FindForkInGlobalIndex: the first locator hash on the *active*
      # chain (else genesis); headers follow the active chain (ActiveChain().Next).
      fork =
        Enum.find_value(loc, fn h ->
          e = HeaderIndex.lookup(idx, h)
          e && on_active.(e) && e
        end) || HeaderIndex.ancestor(idx, tip, 0)

      last = min(tip.height, fork.height + Message.max_headers_results())

      headers =
        if last <= fork.height do
          []
        else
          (fork.height + 1)..last
          |> Enum.map(&HeaderIndex.ancestor(idx, tip, &1))
          |> Enum.reduce_while([], fn e, acc ->
            acc = [decode_header(e.raw) | acc]
            if e.hash == stop, do: {:halt, acc}, else: {:cont, acc}
          end)
          |> Enum.reverse()
        end

      {:ok, push(st, {:headers, headers})}
    end
  end

  # --- block serving -------------------------------------------------------

  alias Exnode.Archive

  @max_cmpctblock_depth 5
  @max_blocktxn_depth 10
  @max_blocks_to_announce 8
  @node_network_limited_min_blocks 288

  defp active_tip_entry(st, idx) do
    tip = ChainState.view_tip(ChainState.view(st.node.chain_state))
    HeaderIndex.lookup(idx, tip.hash)
  end

  # Re-check membership and pruning even for a cached response. The usual
  # unpruned path needs only the block-hash index and small header entry.
  defp active_block_ref(st, hash) do
    reader = ChainState.view_reader(ChainState.view(st.node.chain_state))

    with id when id != nil <- Archive.block_id(reader, hash),
         true <- Archive.on_chain?(reader, id),
         true <- Archive.witness_pruned(reader) < 0 or not Archive.witness_pruned?(reader, id) do
      e = HeaderIndex.lookup(Headers.index(st.node.headers), hash)
      {:ok, reader, id, e.height}
    else
      _ -> :notfound
    end
  end

  # Committed block `hash` on the active chain: `{:ok, height, raw}` or :notfound.
  defp active_block(st, hash) do
    with {:ok, reader, id, height} <- active_block_ref(st, hash),
         {:ok, {:block, raw}} <-
           cached_block(st, reader, id, hash, :witness, near_tip?(st, height)) do
      {:ok, height, raw}
    else
      _ -> :notfound
    end
  end

  # `priority`: a near-tip block, built ahead of queued historical requests
  # (BlockServing).
  defp cached_block(st, reader, id, hash, format, priority) do
    Exnode.P2P.BlockServing.get(
      st.node[:block_serving],
      reader,
      id,
      hash,
      format,
      Map.get(st.node, :decode_block, &Block.decode_exact/1),
      priority
    )
  end

  # Within getblocktxn's serving depth of the active tip (Core MAX_BLOCKTXN_DEPTH).
  defp near_tip?(st, height),
    do:
      ChainState.view_tip(ChainState.view(st.node.chain_state)).height - height <
        @max_blocktxn_depth

  # Core ProcessGetBlockData: MSG_WITNESS_BLOCK -> block with witness; MSG_BLOCK
  # -> without; MSG_CMPCT_BLOCK -> cmpctblock if within 5 of the tip. Blocks
  # off the active chain get notfound. A NODE_NETWORK_LIMITED node disconnects
  # peers asking below its 288-block window (+2 margin).
  # Core ProcessGetData: per pass, the leading tx items (here at most
  # @getdata_tx_per_pass, one batched lookup), then at most ONE block item
  # ("Only process one BLOCK item per call, since they're uncommon and can be
  # expensive to process"); an item of another type is dropped. If items
  # remain, the next pass runs on :continue_getdata, after the mailbox (the
  # peer's own timers) and TCP backpressure from the blocking send.
  @getdata_tx_per_pass 1_000

  defp process_getdata(st) do
    {tx_items, q} = take_tx_items(st.getdata_queue, [], 0)
    st = serve_txs(%{st | getdata_queue: q}, tx_items)

    result =
      case :queue.out(st.getdata_queue) do
        # Core: a block item only while !fPauseSend.
        _ when st.paused_since != nil ->
          {:ok, st}

        {{:value, %{type: t} = item}, q} when t in [:block, :cmpct_block] ->
          serve_block(%{st | getdata_queue: q}, item)

        {{:value, %{type: t}}, q} when t not in [:tx, :wtx, :block, :cmpct_block] ->
          {:ok, %{st | getdata_queue: q}}

        _ ->
          {:ok, st}
      end

    case result do
      {:ok, st} ->
        # While paused the next pass is started by the writer draining
        # (handle_info {:sent, _}), not here.
        if getdata_pending?(st) and not paused?(st), do: send(self(), :continue_getdata)
        {:ok, st}

      stop ->
        stop
    end
  end

  defp take_tx_items(q, acc, n) when n >= @getdata_tx_per_pass, do: {Enum.reverse(acc), q}

  defp take_tx_items(q, acc, n) do
    case :queue.peek(q) do
      {:value, %{type: t} = item} when t in [:tx, :wtx] ->
        take_tx_items(:queue.drop(q), [item | acc], n + 1)

      _ ->
        {Enum.reverse(acc), q}
    end
  end

  # Core: FindTxForGetData for each, notfound for the missing ones. As in
  # Core's loop, no item is served once the send buffer is full
  # (`if (pfrom.fPauseSend) break;`): the rest go back to the front of the
  # queue, and notfound covers only the items processed.
  defp serve_txs(st, []), do: st

  # Core ProcessGetData: no TxRelay for a block-relay-only peer or one that
  # sent fRelay = false (we offer no NODE_BLOOM): its tx items are skipped,
  # with no notfound.
  defp serve_txs(st, tx_items) do
    if st.node[:tx_relay] != nil and st.conn_type != :block_relay and st.version.relay do
      # Found txs come back in request order (Mempool.get_txs).
      {txs, missing} = Exnode.P2P.TxRelay.lookup(st.node.tx_relay, tx_items)
      {st, rest, notfound} = push_txs(st, tx_items, txs, MapSet.new(missing), [])
      st = if notfound != [], do: push(st, {:notfound, notfound}), else: st
      %{st | getdata_queue: :queue.join(:queue.from_list(rest), st.getdata_queue)}
    else
      st
    end
  end

  defp push_txs(st, [], _txs, _missing, nf), do: {st, [], Enum.reverse(nf)}

  defp push_txs(st, items, _txs, _missing, nf) when st.paused_since != nil,
    do: {st, items, Enum.reverse(nf)}

  defp push_txs(st, [i | rest], txs, missing, nf) do
    if MapSet.member?(missing, i) do
      push_txs(st, rest, txs, missing, [i | nf])
    else
      [tx | txs] = txs
      push_txs(push(st, {:tx, tx_bytes(tx, i)}), rest, txs, missing, nf)
    end
  end

  # Core: MSG_TX gets TX_NO_WITNESS; MSG_WITNESS_TX and MSG_WTX the full tx.
  defp tx_bytes(tx, %{type: :tx, witness: false}),
    do: IO.iodata_to_binary(Exnode.Codec.Tx.encode(tx, witness: false))

  defp tx_bytes(tx, _item), do: tx.raw

  # Core ProcessGetBlockData for one item. The block is decoded only when it
  # must be re-encoded (cmpctblock, or without witness); a witness or
  # deep-cmpct request forwards the stored bytes as they are.
  defp serve_block(st, item) do
    tip_h = ChainState.view_tip(ChainState.view(st.node.chain_state)).height
    limited = Bitwise.band(st.node.services, Message.service(:network)) == 0

    case active_block_ref(st, item.hash) do
      :notfound ->
        {:ok, push(st, {:notfound, [item]})}

      {:ok, _, _, h} when limited and tip_h - h > @node_network_limited_min_blocks + 2 ->
        {:stop, {:shutdown, :request_below_network_limited_threshold}, st}

      {:ok, reader, id, h} ->
        format =
          cond do
            item.type == :cmpct_block and tip_h - h < @max_cmpctblock_depth -> :compact
            item.type == :cmpct_block or item.witness -> :witness
            true -> :stripped
          end

        case cached_block(st, reader, id, item.hash, format, tip_h - h < @max_blocktxn_depth) do
          {:ok, msg} -> {:ok, push(st, msg)}
          :notfound -> {:ok, push(st, {:notfound, [item]})}
        end
    end
  end

  # Core ProcessGetBlockTxn (via ProcessMessage GETBLOCKTXN): recent blocks
  # answer with the requested txs; older ones with the full block.
  defp serve_getblocktxn(st, payload) do
    case CompactBlock.decode_getblocktxn(payload) do
      {:error, why} ->
        dropped(st, "getblocktxn", why)

      # Core: "getblocktxn received with no transaction indexes": disconnect.
      {:ok, _hash, []} ->
        {:stop, {:shutdown, :empty_getblocktxn}, st}

      {:ok, hash, indexes} ->
        tip_h = ChainState.view_tip(ChainState.view(st.node.chain_state)).height

        case active_block(st, hash) do
          :notfound ->
            {:ok, st}

          {:ok, h, raw} when tip_h - h >= @max_blocktxn_depth ->
            {:ok, push(st, {:block, raw})}

          # Only the txs' extents are needed, not the decoded block: a 34-byte
          # request is below the DecodeBudget, and every peer decoding a
          # recent 4 MB block at once (tens of MB of heap each) is an OOM.
          {:ok, _h, raw} ->
            {:ok, ranges} = Block.tx_ranges(raw)

            # Indexes strictly increase (decode_getblocktxn): the last is the largest.
            if List.last(indexes) >= tuple_size(ranges) do
              misbehaving(st, "getblocktxn with out-of-bounds tx indices")
            else
              txs = select_txs(raw, ranges, indexes)
              {:ok, push(st, {:blocktxn, CompactBlock.encode_blocktxn_raw(hash, txs)})}
            end
        end
    end
  end

  @doc false
  # The serialized txs at `indexes` (all in range), sliced from the block:
  # O(1) per index, no copy.
  def select_txs(raw, ranges, indexes) do
    Enum.map(indexes, fn i ->
      {offset, len} = elem(ranges, i)
      binary_part(raw, offset, len)
    end)
  end

  # Core SendMessages block announcements: cmpctblock to peers that asked for
  # high-bandwidth (one new block), headers to sendheaders peers (up to 8
  # blocks connecting to what they know), otherwise an inv of the tip. Not
  # during our IBD (UpdatedBlockTip returns early).
  defp maybe_announce_blocks(st) do
    view = st.node[:chain_state] && ChainState.view(st.node.chain_state)
    tip = view && ChainState.view_tip(view)

    cond do
      not st.verack_received or tip == nil or tip.hash == st.announced ->
        st

      st.announced == nil ->
        # Nothing announced yet: start from the current tip.
        %{st | announced: tip.hash}

      initial_block_download?(st) ->
        %{st | announced: tip.hash}

      true ->
        announce_new_blocks(st, tip)
    end
  end

  defp announce_new_blocks(st, tip) do
    idx = Headers.index(st.node.headers)
    tip_e = HeaderIndex.lookup(idx, tip.hash)
    prev = HeaderIndex.lookup(idx, st.announced)
    # The peer knows `best_known` or what we announced last, whichever is on our chain.
    known =
      [st.best_known, prev]
      |> Enum.filter(
        &(&1 != nil and &1.height <= tip_e.height and
            HeaderIndex.ancestor(idx, tip_e, &1.height).hash == &1.hash)
      )
      |> Enum.max_by(& &1.height, fn -> nil end)

    new =
      case known do
        nil -> nil
        k when k.height >= tip_e.height -> []
        k -> for h <- (k.height + 1)..tip_e.height, do: HeaderIndex.ancestor(idx, tip_e, h)
      end

    st = %{st | announced: tip.hash}

    cond do
      new == [] ->
        st

      st.hb_requested and new != nil and length(new) == 1 ->
        with {:ok, reader, id, _} <- active_block_ref(st, tip.hash),
             {:ok, msg} <- cached_block(st, reader, id, tip.hash, :compact, true) do
          push(st, msg)
        else
          _ -> push(st, {:inv, [%{type: :block, hash: tip.hash}]})
        end

      st.prefers_headers and new != nil and length(new) <= @max_blocks_to_announce ->
        push(st, {:headers, Enum.map(new, &decode_header(&1.raw))})

      true ->
        push(st, {:inv, [%{type: :block, hash: tip.hash}]})
    end
  end

  # --- BIP157 (compact filter serving) -------------------------------------

  @max_getcfilters 1000
  @max_getcfheaders 2000
  @cfcheckpt_interval 1000

  # Core PrepareBlockFilterRequest: basic filters only, and only with
  # NODE_COMPACT_FILTERS; a known stop block; a valid, bounded range.
  # Violations disconnect the peer.
  defp filter_request(st, type, start, stop_hash, max_diff) do
    idx = Headers.index(st.node.headers)
    stop = HeaderIndex.lookup(idx, stop_hash)

    cond do
      type != 0 or Bitwise.band(st.node.services, Message.service(:compact_filters)) == 0 or
          st.node[:filter_index] == nil ->
        {:stop, {:shutdown, :unsupported_filter_type}, st}

      stop == nil ->
        {:stop, {:shutdown, :invalid_filter_stop_hash}, st}

      start > stop.height ->
        {:stop, {:shutdown, :invalid_filter_range}, st}

      stop.height - start >= max_diff ->
        {:stop, {:shutdown, :too_many_filters_requested}, st}

      true ->
        {:ok, idx, stop}
    end
  end

  defp filters_for(st, idx, stop, start) do
    blocks = for h <- start..stop.height//1, do: HeaderIndex.ancestor(idx, stop, h)
    results = Exnode.Index.BlockFilter.get_many(st.node.filter_index, Enum.map(blocks, & &1.hash))
    if Enum.any?(results, &(&1 == :not_found)), do: :not_indexed, else: Enum.zip(blocks, results)
  end

  defp serve_cfilters(st, %{filter_type: t, start_height: start, stop_hash: stop_hash}) do
    with {:ok, idx, stop} <- filter_request(st, t, start, stop_hash, @max_getcfilters) do
      case filters_for(st, idx, stop, start) do
        :not_indexed ->
          {:ok, st}

        pairs ->
          {:ok,
           Enum.reduce(pairs, st, fn {e, {:ok, f, _}}, st ->
             push(st, {:cfilter, %{filter_type: 0, block_hash: e.hash, filter: f}})
           end)}
      end
    end
  end

  defp serve_cfheaders(st, %{filter_type: t, start_height: start, stop_hash: stop_hash}) do
    with {:ok, idx, stop} <- filter_request(st, t, start, stop_hash, @max_getcfheaders) do
      # Filter hashes and headers only (never the filters),
      # the previous header in the same RocksDB multi_get.
      blocks = for h <- max(start - 1, 0)..stop.height//1, do: HeaderIndex.ancestor(idx, stop, h)

      results =
        Exnode.Index.BlockFilter.get_headers(st.node.filter_index, Enum.map(blocks, & &1.hash))

      case if(:not_found in results, do: :not_indexed, else: results) do
        pairs when is_list(pairs) ->
          {prev_header, pairs} =
            if start == 0,
              do: {<<0::256>>, pairs},
              else: (fn [{:ok, _, h} | rest] -> {h, rest} end).(pairs)

          hashes = for {:ok, fh, _} <- pairs, do: fh

          {:ok,
           push(
             st,
             {:cfheaders,
              %{
                filter_type: 0,
                stop_hash: stop.hash,
                prev_header: prev_header,
                filter_hashes: hashes
              }}
           )}

        _ ->
          {:ok, st}
      end
    end
  end

  defp serve_cfcheckpt(st, %{filter_type: t, stop_hash: stop_hash}) do
    with {:ok, idx, stop} <- filter_request(st, t, 0, stop_hash, 0x1_0000_0000) do
      n = div(stop.height, @cfcheckpt_interval)

      hashes = for i <- 1..n//1, do: HeaderIndex.ancestor(idx, stop, i * @cfcheckpt_interval).hash

      headers =
        Exnode.Index.BlockFilter.get_headers(st.node.filter_index, hashes)
        |> Enum.map(fn
          {:ok, _, h} -> h
          :not_found -> nil
        end)

      if Enum.any?(headers, &is_nil/1),
        do: {:ok, st},
        else:
          {:ok, push(st, {:cfcheckpt, %{filter_type: 0, stop_hash: stop.hash, headers: headers}})}
    end
  end

  defp decode_header(raw) do
    {h, ""} = Exnode.Codec.Header.decode(raw)
    h
  end

  # --- helpers ---------------------------------------------------------------

  defp send_opts(st),
    do: [
      send_timeout: Map.get(st.node, :send_timeout_ms, @send_timeout_ms),
      send_timeout_close: true
    ]

  # Core CConnman::InactivityCheck, once connected for longer than the
  # connect timeout (ShouldRunInactivityChecks): nothing ever sent or
  # received, or nothing sent / received for TIMEOUT_INTERVAL (20 min).
  defp inactivity(st, now) do
    last_send = Map.get(st, :last_send)
    last_recv = Map.get(st, :last_recv)

    cond do
      st.connected_at == nil or now - st.connected_at <= @handshake_timeout_s -> nil
      last_send == nil or last_recv == nil -> :no_message_in_connect_timeout
      now > last_send + @timeout_interval_s -> :send_timeout
      now > last_recv + @timeout_interval_s -> :receive_timeout
      # Core: "send buffer full for %is" (fPauseSend for TIMEOUT_INTERVAL).
      st.paused_since != nil and now > st.paused_since + @timeout_interval_s -> :send_buffer_full
      true -> nil
    end
  end

  # Eviction fields, pushed to the connection manager as they change.
  defp report_stats(st, stats) do
    if st.node[:connman], do: send(st.node.connman, {:peer_stats, self(), stats})
    st
  end

  # Core HasAllDesirableServiceFlags: NODE_NETWORK | NODE_WITNESS, or
  # NODE_NETWORK_LIMITED | NODE_WITNESS for a limited peer once near the tip
  # (Core: best block depth < 144; here: out of IBD).
  defp desirable_services?(st, services) do
    limited = Message.service(:network_limited)

    want =
      if (services &&& limited) != 0 and not initial_block_download?(st),
        do: limited ||| Message.service(:witness),
        else: Message.service(:network) ||| Message.service(:witness)

    (services &&& want) == want
  end

  # Core Misbehaving + MaybeDiscourageAndDisconnect: disconnect (Connman
  # discourages), except a manual peer, which Core never disconnects or
  # discourages.
  defp misbehaving(%{conn_type: :manual} = st, why) do
    Logger.info("peer #{inspect(st.target)}: misbehaving (#{why}), but manual: kept")
    {:ok, st}
  end

  defp misbehaving(st, why), do: {:stop, {:shutdown, {:misbehaving, why}}, st}

  # Core: a message that fails to deserialize is logged and dropped.
  defp dropped(st, cmd, why) do
    Logger.debug("peer #{inspect(st.target)}: #{cmd} decode error #{inspect(why)}")
    {:ok, st}
  end

  defp push(st, msg) do
    {cmd, payload} = Message.encode(msg)

    st =
      case st.transport do
        %Transport{} = t ->
          {t, out} = Transport.send_message(t, cmd, payload)
          send_bytes(%{st | transport: t}, out)

        :v1 ->
          send_bytes(st, Frame.encode(st.p.magic, cmd, payload))
      end

    trace(st, {:out, cmd})
  end

  # Core PushMessage: the bytes join the send queue (here the writer's
  # mailbox) and never block this process; over the limit, fPauseSend.
  defp send_bytes(st, bytes) do
    case IO.iodata_length(bytes) do
      0 ->
        st

      n ->
        send(st.writer, {:write, bytes})
        queued = st.send_queued + n

        if queued > max_send_buffer(st) and st.paused_since == nil,
          do: %{st | send_queued: queued, paused_since: now(st)},
          else: %{st | send_queued: queued}
    end
  end

  defp max_send_buffer(st), do: Map.get(st.node, :max_send_buffer, @max_send_buffer)

  # The writer: owns the blocking socket send, so a peer that does
  # not read stalls only this process, and the peer process keeps answering
  # calls and timers. It reports every write ({:sent, n}) and the first
  # failure ({:send_failed, reason}, then it exits). Linked to the peer, and
  # monitoring it, so it never outlives it.
  defp start_writer(st) do
    peer = self()
    sock = st.socket
    send_fun = Map.get(st.node, :socket_send, &:gen_tcp.send/2)

    pid =
      spawn_link(fn ->
        ref = Process.monitor(peer)
        writer_loop(sock, send_fun, peer, ref)
      end)

    %{st | writer: pid}
  end

  defp writer_loop(sock, send_fun, peer, ref) do
    receive do
      {:write, data} ->
        {data, n} = writer_collect([data], IO.iodata_length(data))

        case send_fun.(sock, data) do
          :ok ->
            send(peer, {:sent, n})
            writer_loop(sock, send_fun, peer, ref)

          # Timed out (socket closed by send_timeout_close) or already closed.
          {:error, reason} ->
            send(peer, {:send_failed, reason})
        end

      {:flush, from} ->
        send(from, :flushed)
        writer_loop(sock, send_fun, peer, ref)

      {:DOWN, ^ref, :process, _, _} ->
        :ok
    end
  end

  # Coalesces queued writes, in order, into one send of at most @writer_batch.
  defp writer_collect(acc, n) when n >= @writer_batch, do: {Enum.reverse(acc), n}

  defp writer_collect(acc, n) do
    receive do
      {:write, data} -> writer_collect([data | acc], n + IO.iodata_length(data))
    after
      0 -> {Enum.reverse(acc), n}
    end
  end

  # Last 8 messages each way, for diagnosing remote disconnects.
  defp trace(st, ev), do: Map.put(st, :trace, Enum.take([ev | Map.get(st, :trace, [])], 12))

  # The periodic pass (Core SendMessages and InactivityCheck): handshake,
  # ping and inactivity timeouts, then pings, sync, block requests and
  # announcements.
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
        |> expire_partials(t)
        |> maybe_ping(t)
        |> maybe_start_sync(t)
        |> maybe_request_blocks()
        |> maybe_announce_blocks()
        |> check_headers_sync_timeout(t)
        |> consider_eviction(t)
    end
  end

  defp schedule_tick(st) do
    case Map.get(st.node, :tick_ms, @tick_ms) do
      nil -> :ok
      ms -> Process.send_after(self(), :tick, ms)
    end
  end

  # Core ProcessAddrs, for each address the token bucket let through:
  # only full nodes (NODE_NETWORK or NODE_NETWORK_LIMITED); a
  # time before 1973 or more than 10 minutes ahead becomes 5 days ago (a
  # future time would make the entry, even a tried one, terrible and
  # evictable); not discouraged; only reachable networks are stored.
  defp sanitize_addrs(_st, []), do: []

  defp sanitize_addrs(st, addrs) do
    now = now(st)
    full = Message.service(:network) ||| Message.service(:network_limited)
    reachable = Exnode.P2P.Connman.reachable_nets()

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

  # Connman restarting: the addresses still go in (they are only candidates).
  defp reject_discouraged(addrs, connman) do
    Exnode.P2P.Connman.reject_discouraged(connman, addrs)
  catch
    :exit, _ -> addrs
  end

  defp now(st), do: Exnode.Clock.now(st.node[:clock])
end
