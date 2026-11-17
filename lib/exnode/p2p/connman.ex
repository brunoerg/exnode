defmodule Exnode.P2P.Connman do
  @moduledoc """
  Connection manager, in the spirit of Core v32.1 `CConnman` (net.cpp):

  * Outbound slots: MAX_OUTBOUND_FULL_RELAY_CONNECTIONS (8) full-relay plus
    MAX_BLOCK_RELAY_ONLY_CONNECTIONS (2) block-relay-only. At most one
    outbound connection per network group.
  * `connect: [{host, port}]` behaves like `-connect`: only these manual
    peers, no automatic outbound, no DNS seeding.
  * Inbound: the limit is `max_connections - outbound slots - 1 feeler`
    (Core nMaxInbound). The listener asks `accept_inbound?/2`. When inbound
    slots are full, an existing inbound peer is evicted
    (`P2P.Eviction`, Core `AttemptToEvictConnection`); if none can be, the
    new connection is dropped (Core `CreateNodeFromAcceptedSocket`).
  * At most half the inbound slots relay transactions (Core
    `-inboundrelaypercent` 50, `EvictTxPeerIfFull`): a new tx-relaying
    inbound peer evicts another tx-relaying one or is itself dropped
    (`tx_relay_capacity/2`, Core `MaybeDisconnectForTxRelayCapacity`).
  * A peer that exits with `{:misbehaving, _}` is discouraged: no new
    outbound connections to it, and inbound accepted only if slots are not
    (almost) full; a discouraged inbound peer is preferred for eviction
    (Core `DiscourageAddress`, `prefer_evict`). Discouragement is by IP
    (any port), lasts 24 h, does not apply to manual peers, and is saved to
    `discouraged.dat` (`Exnode.P2P.Discouraged`).
  * Outbound targets come from the address book as in Core's
    `ThreadOpenConnections`: anchors first (the block-relay peers of the
    last run, `anchors.dat`), then full-relay slots, then block-relay ones;
    once full, a **feeler** every ~2 minutes (exponential) to a new-table
    address or to a tried entry a pending move would displace
    (test-before-evict). Each pick is retried up to 100 times, skipping a
    network group already used, an address tried in the last 10 minutes
    (until 30 picks), missing services, bad ports (until 50 picks),
    discouraged and already-connected addresses. Failures count against an
    address only while at least 2 outbound groups are connected (Core
    fCountFailure), so going offline does not wear down the book.
  * Peers report their eviction fields (`{:peer_stats, pid, map}`: min
    ping, last novel block and tx, relay and services flags) as they change,
    so eviction never waits on a busy peer process.

  Each peer is a temporary child of a DynamicSupervisor, so a crashing peer
  never affects the others or this process.

  Time comes from `:clock` (an `Exnode.Clock`, default the node map's
  `clock`, nil: the system clock); the 1 s tick also runs on
  `Exnode.Clock.tick/2`.
  """
  use GenServer
  import Bitwise
  require Logger

  alias Exnode.Clock
  alias Exnode.P2P.{AddrMan, Discouraged, NetAddr, Peer, PeerFile}

  @max_full_relay 8
  @max_block_relay 2
  @default_max_connections 200

  @doc "Peer connection limit when none is given (`:max_connections`)."
  def default_max_connections, do: @default_max_connections
  # net.h DEFAULT_FULL_RELAY_INBOUND_PCT
  @full_relay_inbound_pct 50
  @tick_ms 1_000
  # An evicted peer handles {:disconnect, :evicted} in its own process, which
  # may be blocked (e.g. waiting on a busy TxRelay). Core closes the socket
  # on the socket thread whatever the message thread does (DisconnectNodes),
  # so a peer still alive after this grace is killed, which closes its
  # socket.
  @evict_grace_ms 2_000
  # While this many evicted peers have not exited yet, a full inbound side
  # refuses new connections instead of evicting more: connections cannot
  # outgrow max_inbound by more than this during a stall.
  @max_pending_evictions 8
  # File descriptors kept for everything but peers (RocksDB, RPC, REST,
  # listeners, logs). Core init clamps -maxconnections to the available fds
  # the same way (MIN_CORE_FDS + MAX_ADDNODE_CONNECTIONS + binds).
  @reserved_fds 500
  # Bootstrap (Core ThreadOpenConnections / ThreadDNSAddressSeed): fixed seeds
  # 60 s after start for reachable networks with no addresses; DNS seeding
  # retried while the book is empty (Core queries once; the retry is ours).
  @fixed_seed_delay_s 60
  @dns_retry_s 30
  @reachable_nets [:ipv4, :ipv6]
  # net.h FEELER_INTERVAL; net.cpp MAX_BLOCK_RELAY_ONLY_ANCHORS.
  @feeler_interval_s 120
  @max_anchors 2

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  def peers(server), do: GenServer.call(server, :peers, 5_000)
  @doc "We signal NODE_P2P_V2 (BIP324 enabled)."
  def local_v2?(node), do: (node.services &&& Exnode.P2P.Message.service(:p2p_v2)) != 0

  @doc """
  May an inbound connection from `target` be accepted? May evict an inbound peer to make room.
  Waits with no timeout, as Core's accept thread does on its locks (a busy
  Connman must not kill the accept loop).
  """
  def accept_inbound?(server, target \\ nil),
    do: GenServer.call(server, {:accept_inbound?, target}, :infinity)

  @doc """
  Tracks the inbound peer `pid`: `:ok`. A call, so the Listener knows the
  peer is tracked before it hands it the socket. As a cast it was dropped
  when Connman was restarting (its name unregistered while PeerSup was
  already back), and the peer ran untracked: outside the inbound limit and
  eviction (P2P-4 in STATE_MACHINES.md). Exits like any call if Connman is
  not running; waits like `accept_inbound?/2`.
  """
  def register_inbound(server, pid, target),
    do: GenServer.call(server, {:register_inbound, pid, target}, :infinity)

  @doc """
  Core `MaybeDisconnectForTxRelayCapacity` for an inbound peer that relays
  txs (`stats` from its version): `:ok`, or `:disconnect` when the
  tx-relaying inbound peers are over the limit and none can be evicted.
  Waits like Core's peer thread on `cs_main` (no timeout); the peer's inactivity timeout bounds it.
  """
  def tx_relay_capacity(server, stats),
    do: GenServer.call(server, {:tx_relay_capacity, self(), stats}, :infinity)

  @doc "Whether a peer address (any form `Discouraged.key/1` takes) is discouraged now."
  def discouraged?(server, addr), do: GenServer.call(server, {:discouraged?, addr}, 5_000)

  @doc "The addresses of `addrs` that are not discouraged now, in one call."
  def reject_discouraged(server, addrs),
    do: GenServer.call(server, {:reject_discouraged, addrs}, 5_000)

  @doc "Networks we can connect to (Core g_reachable_nets: no proxy, so IPv4 and IPv6)."
  def reachable_nets, do: @reachable_nets

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    anchors_path = Keyword.get(opts, :anchors_path)
    node_name = Keyword.get(opts, :node_name)
    magic = Keyword.get(opts, :magic, <<0, 0, 0, 0>>)
    node = Keyword.fetch!(opts, :node)
    clock = Keyword.get(opts, :clock, node[:clock])
    disc_path = Keyword.get(opts, :discouraged_path)

    st = %{
      anchors_path: anchors_path,
      node_name: node_name,
      magic: magic,
      anchors: read_anchors(anchors_path, magic),
      next_feeler: Clock.mono(clock, :second) + exp_delay(@feeler_interval_s),
      node: node,
      sup: Keyword.fetch!(opts, :peer_sup),
      manual: Keyword.get(opts, :connect),
      max_full: Keyword.get(opts, :max_outbound_full_relay, @max_full_relay),
      max_block: Keyword.get(opts, :max_block_relay, @max_block_relay),
      max_conn:
        fit_fds(
          Keyword.get(opts, :max_connections, @default_max_connections),
          Keyword.get(opts, :max_fds, max_fds())
        ),
      evict_grace_ms: Keyword.get(opts, :evict_grace_ms, @evict_grace_ms),
      peers: %{},
      # Discouraged IPs (no port) with their insertion times, 24 h TTL, saved
      # to discouraged.dat, by unix time.
      discouraged:
        read_discouraged(
          disc_path,
          magic,
          Clock.now(clock),
          Keyword.take(opts, [:discouraged_cap])
        ),
      disc_path: disc_path,
      disc_flushed_at: nil,
      clock: clock,
      # Bootstrap state (non-manual mode): times in monotonic seconds,
      # DNS seeding :idle | {:running, monitor ref} and when it last started,
      # and Core's add_fixed_seeds flag (fixed seeds are added once per run).
      started_at: nil,
      dns: :idle,
      dns_last: nil,
      add_fixed_seeds: true,
      seed_fun: Keyword.get(opts, :seed_fun, &AddrMan.seed_from_dns/3),
      # Core nKeyedNetGroup: netgroups hashed with a secret, so which groups
      # eviction protects cannot be predicted.
      netgroup_key: :crypto.strong_rand_bytes(32)
    }

    send(self(), :tick)
    now = mono_s(st)
    {:ok, %{st | started_at: now, disc_flushed_at: now}}
  end

  @impl true
  def handle_call({:register_inbound, pid, target}, _from, st) do
    st = track(st, pid, :inbound, target)
    # Core prefer_evict: the address was discouraged when it connected.
    prefer = target != nil and disc?(st, Discouraged.key(target))
    {:reply, :ok, update_in(st.peers[pid], &%{&1 | prefer_evict: prefer})}
  end

  def handle_call(:peers, _from, st), do: {:reply, st.peers, st}

  # Core CreateNodeFromAcceptedSocket.
  def handle_call({:accept_inbound?, target}, _from, st) do
    inbound = Enum.count(st.peers, fn {_, p} -> p.type == :inbound end)
    max_inbound = max_inbound(st)
    discouraged = target != nil and disc?(st, Discouraged.key(target))

    cond do
      discouraged and inbound + 1 >= max_inbound ->
        {:reply, false, st}

      # Core counts only connections not being disconnected; ours linger up
      # to @evict_grace_ms, so their number is capped.
      inbound >= max_inbound and
          Enum.count(st.peers, fn {_, p} -> p.type == :inbound and p.evicting end) >=
            @max_pending_evictions ->
        {:reply, false, st}

      inbound >= max_inbound ->
        case evict(st, fn _ -> true end) do
          {:ok, st} -> {:reply, true, st}
          :none -> {:reply, false, st}
        end

      true ->
        {:reply, true, st}
    end
  end

  # Core EvictTxPeerIfFull(protect_peer = the new peer).
  def handle_call({:tx_relay_capacity, pid, stats}, _from, st) do
    st = update_stats(st, pid, stats)
    max_relay = max(0, trunc(@full_relay_inbound_pct / 100 * max_inbound(st)))

    relaying =
      Enum.count(st.peers, fn {_, p} ->
        p.type == :inbound and not p.evicting and p.stats.relay_txs
      end)

    if relaying > max_relay do
      case evict(st, fn {q, p} -> q != pid and p.stats.relay_txs end) do
        {:ok, st} -> {:reply, :ok, st}
        :none -> {:reply, :disconnect, st}
      end
    else
      {:reply, :ok, st}
    end
  end

  def handle_call({:discouraged?, addr}, _from, st),
    do: {:reply, disc?(st, Discouraged.key(addr)), st}

  def handle_call({:reject_discouraged, addrs}, _from, st),
    do: {:reply, Enum.reject(addrs, &disc?(st, Discouraged.key(&1))), st}

  @impl true
  def handle_info(:tick, st) do
    Process.send_after(self(), :tick, @tick_ms)
    {:noreply, tick(st)}
  end

  def handle_info({Clock, :tick, from, ref}, st) do
    st = tick(st)
    Clock.ticked({from, ref})
    {:noreply, st}
  end

  def handle_info({:peer_stats, pid, stats}, st), do: {:noreply, update_stats(st, pid, stats)}

  # Still tracked (no DOWN yet): the peer did not act on its eviction.
  def handle_info({:evict_deadline, pid}, st) do
    case st.peers do
      %{^pid => %{evicting: true} = p} ->
        Logger.info("evicted peer #{inspect(p.target)} did not exit: killing it")
        Process.exit(pid, :kill)

      _ ->
        :ok
    end

    {:noreply, st}
  end

  # Core: VERSION from an outbound peer -> AddrMan::Good (moves it to tried,
  # or records a collision). Feelers report the same, then disconnect.
  def handle_info({:peer_ready, pid, target, type}, st),
    do: handle_info({:peer_ready, pid, target, type, nil}, st)

  def handle_info({:peer_ready, pid, target, type, services}, st) do
    if type != :inbound && st.node[:addrman] && target,
      do: AddrMan.good(st.node.addrman, addr_key(target))

    case st.peers do
      %{^pid => peer} ->
        {:noreply, put_in(st.peers[pid], %{peer | ready: true, services: services})}

      _ ->
        {:noreply, st}
    end
  end

  # The DNS seeding task ended (results, if any, are already in AddrMan).
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{dns: {:running, ref}} = st),
    do: {:noreply, %{st | dns: :idle}}

  def handle_info({:DOWN, _ref, :process, pid, reason}, st) do
    {peer, peers} = Map.pop(st.peers, pid)

    if peer do
      level = if match?({:shutdown, {:connect_failed, _}}, reason), do: :debug, else: :info

      Logger.log(
        level,
        "peer #{inspect(peer.target)} (#{peer.type}, ready=#{peer.ready}) exited: #{inspect(reason, limit: 60)}"
      )
    end

    st = %{st | peers: peers}

    # Core FinalizeNode: AddrMan::Connected for full outbound peers that
    # completed the handshake (not block-relay, inbound or feeler).
    if peer && peer.ready && peer.type in [:outbound_full_relay, :manual] && peer.target &&
         st.node[:addrman],
       do: AddrMan.connected(st.node.addrman, addr_key(peer.target))

    st =
      case {peer, reason} do
        # Core MaybeDiscourageAndDisconnect: a manual peer is not punished.
        {%{target: t, type: :manual}, {:shutdown, {:misbehaving, why}}} when t != nil ->
          Logger.info("not discouraging manual peer #{inspect(t)}: #{why}")
          st

        {%{target: t}, {:shutdown, {:misbehaving, why}}} when t != nil ->
          case Discouraged.key(t) do
            k when k != nil ->
              if Discouraged.local?(k) do
                # Core: "disconnecting but not discouraging local peer".
                Logger.info("disconnecting but not discouraging local peer #{inspect(t)}: #{why}")
                st
              else
                Logger.info("discouraging #{inspect(t)}: #{why}")
                %{st | discouraged: Discouraged.put(st.discouraged, k, Clock.now(st.clock))}
              end

            # A DNS name has no key (Discouraged.key/1): nothing to record.
            nil ->
              st
          end

        # Core DisconnectNodes: ShouldReconnectV1, so retry this peer with v1.
        {%{target: t, type: type, v2: true}, {:shutdown, {:reconnect_v1, _}}} when t != nil ->
          Logger.debug("retrying #{inspect(t)} with v1 transport")
          start_outbound(st, t, type, false)

        _ ->
          st
      end

    {:noreply, st}
  end

  # The periodic pass: discouragement flush, seeding, outbound slots.
  defp tick(st), do: st |> maybe_flush_discouraged() |> maybe_seed() |> fill_slots()

  defp mono_s(st), do: Clock.mono(st.clock, :second)

  # -connect (manual mode): no seeding of any kind.
  defp maybe_seed(%{manual: m} = st) when is_list(m), do: st
  defp maybe_seed(st), do: st |> maybe_dns_seed() |> maybe_fixed_seeds()

  # Core ThreadDNSAddressSeed: query the DNS seeds when the address book is
  # empty. Core queries once; here a failed or empty round is retried every
  # @dns_retry_s while the book stays empty, so a node whose resolver was
  # down at start still bootstraps from DNS. Never while a round runs.
  defp maybe_dns_seed(st) do
    p = st.node.params
    now = mono_s(st)

    cond do
      p.dns_seeds == [] ->
        st

      st.dns != :idle ->
        st

      st.dns_last != nil and now - st.dns_last < @dns_retry_s ->
        st

      # Not seeding while the book is unknown (AddrMan restarting) or non-empty.
      (n = book_size(st)) == nil or n > 0 ->
        st

      true ->
        {addrman, fun} = {st.node.addrman, st.seed_fun}
        {_pid, ref} = spawn_monitor(fn -> fun.(addrman, p.dns_seeds, p.default_port) end)
        if st.dns_last, do: Logger.info("address book still empty; querying DNS seeds again")
        %{st | dns: {:running, ref}, dns_last: now}
    end
  end

  # Core ThreadOpenConnections: once per run, when some reachable network has
  # no addresses (GetReachableEmptyNetworks) and either 60 s have passed since
  # start or there is no DNS seeding (Core: -dnsseed=0 and no -seednode /
  # -addnode), add the fixed seeds of those networks, all with the source
  # SetInternal("fixedseeds") and SeedsAssumedServiceFlags(), each with a
  # random last-seen time one to two weeks ago (ConvertSeeds), no penalty.
  defp maybe_fixed_seeds(%{add_fixed_seeds: false} = st), do: st

  defp maybe_fixed_seeds(st) do
    p = st.node.params
    empty = for net <- @reachable_nets, book_size(st, net) == 0, do: net

    cond do
      empty == [] ->
        st

      mono_s(st) - st.started_at > @fixed_seed_delay_s or p.dns_seeds == [] ->
        now = Clock.now(st.clock)
        week = 7 * 86_400

        seeds =
          for s <- p.fixed_seeds, s.net in empty do
            Map.merge(s, %{
              services: AddrMan.seeds_assumed_services(),
              time: now - week - :rand.uniform(week)
            })
          end

        if p.fixed_seeds != [],
          do:
            Logger.info(
              "adding #{length(seeds)} fixed seeds: 60 s passed and no addresses for #{inspect(empty)}"
            )

        AddrMan.add(st.node.addrman, seeds, {:internal, "fixedseeds"}, 0)
        %{st | add_fixed_seeds: false}

      true ->
        st
    end
  end

  defp fill_slots(%{manual: manual} = st) when is_list(manual) do
    connected = st.peers |> Map.values() |> MapSet.new(& &1.target)

    Enum.reduce(manual, st, fn target, st ->
      # Core ThreadOpenConnections (-connect): v2 whenever we support it.
      if MapSet.member?(connected, target),
        do: st,
        else: start_outbound(st, target, :manual, local_v2?(st.node))
    end)
  end

  # Core ThreadOpenConnections: which connection to open next.
  defp fill_slots(st) do
    count = fn type -> Enum.count(st.peers, fn {_, p} -> p.type == type end) end
    full = count.(:outbound_full_relay)
    block = count.(:block_relay)
    now = mono_s(st)

    cond do
      st.anchors != [] and block < st.max_block ->
        connect_anchor(st)

      full < st.max_full ->
        try_outbound(st, :outbound_full_relay)

      block < st.max_block ->
        try_outbound(st, :block_relay)

      now >= st.next_feeler and count.(:feeler) == 0 ->
        try_outbound(%{st | next_feeler: now + exp_delay(@feeler_interval_s)}, :feeler)

      true ->
        st
    end
  end

  defp exp_delay(mean_s), do: round(-mean_s * :math.log(1.0 - :rand.uniform()))

  defp outbound_groups(st) do
    st.peers
    |> Map.values()
    |> Enum.filter(
      &(&1.type in [:outbound_full_relay, :block_relay, :manual] and &1.group != nil)
    )
    |> MapSet.new(& &1.group)
  end

  # Core AlreadyConnectedToAddress: the address (IP and port) or its IP
  # alone. Inbound peers carry an ephemeral port, so (IP, port) alone let us
  # open an outbound connection to a node already connected to us
  # (P2P-2 in STATE_MACHINES.md).
  defp connected_targets(st) do
    for %{target: t} <- Map.values(st.peers), t != nil, k = addr_key(t), reduce: MapSet.new() do
      acc -> acc |> MapSet.put(k) |> MapSet.put(ip_only(k))
    end
  end

  defp already_connected?(connected, key),
    do: MapSet.member?(connected, key) or MapSet.member?(connected, ip_only(key))

  defp ip_only({net, a, _port}) when net in [:ipv4, :ipv6], do: {:ip, net, a}
  defp ip_only(key), do: key

  # An anchor (a block-relay peer of the last run) is reconnected as block-relay.
  defp connect_anchor(%{anchors: [a | rest]} = st) do
    st = %{st | anchors: rest}
    k = AddrMan.key(a)

    if NetAddr.valid?(a) and not NetAddr.local?(a) and a.net in [:ipv4, :ipv6] and
         desirable?(a.services) and not already_connected?(connected_targets(st), k) and
         AddrMan.group(a) not in outbound_groups(st) do
      Logger.info("reconnecting anchor #{inspect(ip_string(a))}:#{a.port}")
      AddrMan.attempt(st.node.addrman, k, count_failures?(st))

      start_outbound(
        st,
        {ip_string(a), a.port},
        :block_relay,
        local_v2?(st.node) and v2_bit?(a.services)
      )
    else
      st
    end
  end

  defp try_outbound(st, type) do
    AddrMan.resolve_collisions(st.node.addrman)
    feeler = type == :feeler
    groups = outbound_groups(st)
    connected = connected_targets(st)
    now = Clock.now(st.clock)

    pick =
      Enum.reduce_while(1..100, nil, fn tries, _ ->
        info =
          if feeler, do: feeler_candidate(st, connected), else: book_select(st)

        cond do
          info == nil -> {:halt, nil}
          # Outbound IPv4/IPv6 connections (not feelers) to distinct groups.
          not feeler and AddrMan.group(info) in groups -> {:cont, nil}
          not NetAddr.valid?(info) or NetAddr.local?(info) -> {:halt, nil}
          # Only very recently tried addresses after 30 picks.
          now - info.last_try < 600 and tries < 30 -> {:cont, nil}
          not feeler and not desirable?(info.services) -> {:cont, nil}
          feeler and not useful_addr_db?(info.services) -> {:cont, nil}
          tries < 50 and NetAddr.bad_port?(info.port) -> {:cont, nil}
          disc?(st, Discouraged.key(info)) -> {:cont, nil}
          already_connected?(connected, info.key) -> {:cont, nil}
          true -> {:halt, info}
        end
      end)

    case pick do
      nil ->
        st

      info ->
        AddrMan.attempt(st.node.addrman, info.key, count_failures?(st))
        # Core: v2 when both we and the address advertise NODE_P2P_V2.
        v2 = local_v2?(st.node) and v2_bit?(info.services)
        start_outbound(st, {ip_string(info), info.port}, type, v2)
    end
  end

  # Core: a tried-table collision to test first; else a new-table address.
  # A collision with a peer we are already connected to counts as good.
  defp feeler_candidate(st, connected) do
    case book(fn -> AddrMan.select_tried_collision(st.node.addrman) end, nil) do
      nil ->
        book_select(st, new_only: true)

      old ->
        if already_connected?(connected, old.key) do
          AddrMan.good(st.node.addrman, old.key)
          book_select(st, new_only: true)
        else
          old
        end
    end
  end

  # AddrMan restarts alone, under its own supervisor, so it can be
  # absent (or still loading peers.dat) for a moment. Its casts are dropped
  # then (GenServer.cast to an unregistered name is a no-op); its calls go
  # through `book/2`, which turns an exit (noproc, or a timeout on a busy
  # book) into `default`: no address to dial this tick, size unknown, so no
  # seeding. A reply after a timeout is never delivered (calls use a process
  # alias, deactivated on timeout), so it needs no handling.
  defp book(fun, default) do
    fun.()
  catch
    :exit, _ -> default
  end

  defp book_size(st), do: book(fn -> AddrMan.size(st.node.addrman) end, nil)
  defp book_size(st, net), do: book(fn -> AddrMan.size(st.node.addrman, net) end, nil)
  defp book_select(st, opts \\ []), do: book(fn -> AddrMan.select(st.node.addrman, opts) end, nil)

  # Core fCountFailure: only while at least 2 outbound groups are connected.
  defp count_failures?(st), do: MapSet.size(outbound_groups(st)) >= min(st.max_conn - 1, 2)

  defp v2_bit?(services), do: ((services || 0) &&& Exnode.P2P.Message.service(:p2p_v2)) != 0

  # Core HasAllDesirableServiceFlags (as during IBD): NODE_NETWORK | NODE_WITNESS.
  defp desirable?(services) do
    want = Exnode.P2P.Message.service(:network) ||| Exnode.P2P.Message.service(:witness)
    ((services || 0) &&& want) == want
  end

  # Core MayHaveUsefulAddressDB.
  defp useful_addr_db?(services),
    do:
      ((services || 0) &&&
         (Exnode.P2P.Message.service(:network) ||| Exnode.P2P.Message.service(:network_limited))) !=
        0

  # --- anchors.dat (Core DumpAnchors / ReadAnchors) ------------------------------

  # Read once at start, then deleted, so a crash loop does not keep
  # reconnecting to the same peers (Core deletes it after reading too).
  defp read_anchors(nil, _magic), do: []

  defp read_anchors(path, magic) do
    case PeerFile.read(path, magic) do
      {:ok, list} when is_list(list) ->
        File.rm(path)
        Logger.info("#{length(list)} anchor peers to reconnect")
        Enum.take(list, @max_anchors)

      :missing ->
        []

      other ->
        Logger.warning("#{path}: #{inspect(other)}")
        File.rm(path)
        []
    end
  end

  # --- discouraged.dat ------------------------------------------------------------

  defp disc?(st, key), do: Discouraged.member?(st.discouraged, key, Clock.now(st.clock))

  # Missing or corrupt: an empty table (as peers.dat); expired entries are dropped.
  defp read_discouraged(nil, _magic, _now, opts), do: Discouraged.new(cap_opt(opts))

  defp read_discouraged(path, magic, now, opts) do
    case PeerFile.read(path, magic) do
      {:ok, term} ->
        t = Discouraged.from_term(term, now, cap_opt(opts))

        if Discouraged.size(t) > 0,
          do: Logger.info("#{Discouraged.size(t)} discouraged addresses loaded")

        t

      :missing ->
        Discouraged.new(cap_opt(opts))

      other ->
        Logger.warning("#{path}: #{inspect(other)}; starting with no discouraged addresses")
        Discouraged.new(cap_opt(opts))
    end
  end

  defp cap_opt(opts), do: if(c = opts[:discouraged_cap], do: [cap: c], else: [])

  # From the tick: prune, and write when changed, at most once per
  # @disc_flush_s (never per insert: no fsync per misbehaving peer).
  @disc_flush_s 60

  defp maybe_flush_discouraged(st) do
    if mono_s(st) - st.disc_flushed_at >= @disc_flush_s do
      d = Discouraged.prune(st.discouraged, Clock.now(st.clock))
      write_discouraged(%{st | discouraged: d, disc_flushed_at: mono_s(st)})
    else
      st
    end
  end

  defp write_discouraged(%{disc_path: path, discouraged: %{dirty: true} = d} = st)
       when is_binary(path) do
    case PeerFile.write(path, st.magic, Discouraged.to_term(d)) do
      :ok ->
        %{st | discouraged: %{d | dirty: false}}

      err ->
        Logger.warning("could not write #{path}: #{inspect(err)}")
        st
    end
  end

  defp write_discouraged(st), do: st

  @impl true
  def terminate(reason, st) do
    write_discouraged(st)
    write_anchors(reason, st)
  end

  # Only when the node stops (Core DumpAnchors runs in StopNodes): after a
  # crash the restart would redial the same peers, every time, in a crash
  # loop. A restart cascade (a ChainState, Headers or P2P sibling crash)
  # stops Connman with `:shutdown` too, so the reason alone cannot tell; the
  # node's stopping mark does (P2P-3b in STATE_MACHINES.md). `:normal` is a
  # direct stop of Connman itself.
  defp write_anchors(reason, %{anchors_path: path} = st)
       when is_binary(path) and (reason == :normal or st.node_name != nil) do
    if reason == :normal or Exnode.Node.stopping?(st.node_name),
      do: dump_anchors(path, st),
      else: :ok
  end

  defp write_anchors(_reason, _st), do: :ok

  defp dump_anchors(path, st) do
    anchors =
      for {_, %{type: :block_relay, ready: true, target: t} = p} <- st.peers, t != nil do
        {net, a, port} = addr_key(t)

        %{
          net: net,
          addr: a,
          port: port,
          services: p[:services] || 0,
          time: Clock.now(st.clock)
        }
      end
      |> Enum.take(@max_anchors)

    if anchors != [], do: PeerFile.write(path, st.magic, anchors)
    :ok
  end

  defp start_outbound(st, target, type, v2) do
    spec =
      {Peer,
       %{node: Map.put(st.node, :connman, self()), conn_type: type, connect: target, v2: v2}}

    case DynamicSupervisor.start_child(st.sup, spec) do
      {:ok, pid} -> track(st, pid, type, target, v2)
      _ -> st
    end
  end

  defp track(st, pid, type, target, v2 \\ false) do
    Process.monitor(pid)
    group = if target, do: AddrMan.group(addr_key(target)), else: nil

    put_in(st.peers[pid], %{
      type: type,
      target: target,
      group: group,
      ready: false,
      v2: v2,
      evicting: false,
      prefer_evict: false,
      stats: default_stats(st),
      services: nil
    })
  end

  defp max_inbound(st), do: st.max_conn - (st.max_full + st.max_block + 1)

  # The VM's fd limit (RLIMIT_NOFILE when it started), from its poll set.
  defp max_fds do
    :erlang.system_info(:check_io)
    |> List.wrap()
    |> List.flatten()
    |> Enum.find_value(fn
      {:max_fds, n} when is_integer(n) -> n
      _ -> nil
    end)
  end

  # Core init: trim the requested connections to the fds left after the reserve.
  @doc false
  def fit_fds(requested, nil), do: requested

  def fit_fds(requested, max_fds) do
    n = max(0, min(requested, max_fds - @reserved_fds))

    if n < requested,
      do:
        Logger.warning(
          "reducing max connections from #{requested} to #{n} because of the file descriptor limit (#{max_fds})"
        )

    n
  end

  # Eviction fields a peer has not reported yet (Core's initial CNode values).
  defp default_stats(st) do
    %{
      connected: Clock.mono(st.clock, :microsecond),
      min_ping: :infinity,
      last_block_time: 0,
      last_tx_time: 0,
      relevant_services: false,
      relay_txs: false
    }
  end

  defp update_stats(st, pid, stats) do
    case st.peers do
      %{^pid => p} -> put_in(st.peers[pid], %{p | stats: Map.merge(p.stats, stats)})
      _ -> st
    end
  end

  # Core AttemptToEvictConnection: candidates are the peers not already
  # being disconnected that pass `filter`; the selected one is told to go.
  defp evict(st, filter) do
    candidates =
      for {pid, p} = e <- st.peers, not p.evicting, filter.(e) do
        key = p.target && addr_key(p.target)

        Map.merge(p.stats, %{
          id: pid,
          bloom_filter: false,
          noban: false,
          prefer_evict: p.prefer_evict,
          conn_type: p.type,
          keyed_netgroup: keyed_netgroup(st, p.group),
          is_local: local?(key),
          network: network(key)
        })
      end

    case Exnode.P2P.Eviction.select_node_to_evict(candidates) do
      nil ->
        :none

      pid ->
        Logger.info("evicting inbound peer #{inspect(st.peers[pid].target)}")
        send(pid, {:disconnect, :evicted})
        Process.send_after(self(), {:evict_deadline, pid}, st.evict_grace_ms)
        {:ok, put_in(st.peers[pid].evicting, true)}
    end
  end

  defp keyed_netgroup(st, group) do
    <<k::64, _::binary>> = :crypto.hash(:sha256, st.netgroup_key <> :erlang.term_to_binary(group))
    k
  end

  # Core CNetAddr::IsLocal: 127.0.0.0/8 and ::1 (and 0.0.0.0/8).
  defp local?({:ipv4, <<127, _, _, _>>, _}), do: true
  defp local?({:ipv4, <<0, _, _, _>>, _}), do: true
  defp local?({:ipv6, <<1::128>>, _}), do: true
  defp local?(_), do: false

  defp network({:ipv4, _, _}), do: :ipv4
  defp network({:ipv6, _, _}), do: :ipv6
  defp network(_), do: :unroutable

  defp ip_string(%{net: :ipv4, addr: <<a, b, c, d>>}), do: "#{a}.#{b}.#{c}.#{d}"

  defp ip_string(%{net: :ipv6, addr: bin}),
    do: for(<<x::16 <- bin>>, do: x) |> List.to_tuple() |> :inet.ntoa() |> to_string()

  # AddrMan-facing key, (IP, port) as AddrMan entries are. Discouragement
  # uses Discouraged.key/1 (IP only).
  def addr_key({host, port}) do
    case :inet.parse_address(to_charlist(host)) do
      {:ok, {a, b, c, d}} -> {:ipv4, <<a, b, c, d>>, port}
      {:ok, t} -> {:ipv6, for(x <- Tuple.to_list(t), into: <<>>, do: <<x::16>>), port}
      _ -> {:dns, to_string(host), port}
    end
  end
end
