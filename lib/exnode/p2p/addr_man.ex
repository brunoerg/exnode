defmodule Exnode.P2P.AddrMan do
  @moduledoc """
  The address book: one process holding an `AddrMan.Table` (Core v32.1
  `AddrMan`: new and tried tables, keyed buckets, test-before-evict), saved
  to `peers.dat` (`PeerFile`) at start-up load, every 15 minutes (Core
  `DUMP_PEERS_INTERVAL`) and on shutdown.

  Why a file and not the RocksDB index: the book is a cache the node can
  rebuild from DNS seeds, it is rewritten as a whole (a few MB at most),
  and keeping it out of the chain database means deleting it never touches
  consensus data. Core and rbitcoin keep it in a file for the same reasons.

  `getaddr` answers come from `addr_response/2`, cached per requesting
  network for 21–27 hours (Core `CConnman::GetAddresses`), so repeated
  requests cannot map the book or its timestamps.

  Keys are `{net, addr_bytes, port}`; an address is
  `%{net, addr, port}` with optional `services` and `time`.
  """
  use GenServer
  require Logger

  alias Exnode.P2P.AddrMan.Table
  alias Exnode.P2P.{NetAddr, PeerFile}

  @dump_interval_ms 15 * 60 * 1000
  # net_processing.cpp MAX_ADDR_TO_SEND, MAX_PCT_ADDR_TO_SEND
  @max_addr_to_send 1000
  @max_pct_addr_to_send 23
  # net.cpp: the getaddr cache lives 21 h plus up to 6 h of jitter.
  @addr_cache_s 21 * 3600
  @addr_cache_jitter_s 6 * 3600

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  Adds addresses learned from `source`: an address (`%{net, addr}` or a
  key), `{:internal, name}` (a DNS seed), or `:seed`. `penalty` seconds
  (Core: 2 h for gossip) are taken off their times.
  """
  def add(server, addrs, source, penalty \\ 0),
    do: GenServer.cast(server, {:add, addrs, source, penalty})

  @doc "Core `Good`: an outbound connection to `key` completed its handshake."
  def good(server, key), do: GenServer.cast(server, {:good, key})

  @doc "Core `Attempt`: we are dialling `key`; `count_failure` when the node is online (Core fCountFailure)."
  def attempt(server, key, count_failure \\ true),
    do: GenServer.cast(server, {:attempt, key, count_failure})

  @doc "Core `Connected`: a full outbound peer disconnected after a good session."
  def connected(server, key), do: GenServer.cast(server, {:connected, key})

  @doc "Core `SetServices`: the services an outbound peer reported in its version."
  def set_services(server, key, services),
    do: GenServer.cast(server, {:set_services, key, services})

  @doc """
  Core `Select`: an entry to try, or nil. Options: `new_only: true`
  (feelers), `networks: [...]` (default IPv4 and IPv6, the networks exnode
  can reach).
  """
  def select(server, opts \\ []), do: GenServer.call(server, {:select, opts}, 5_000)

  @doc "Core `SelectTriedCollision`: the tried entry a pending move would displace, or nil."
  def select_tried_collision(server), do: GenServer.call(server, :select_tried_collision, 5_000)

  @doc "Core `ResolveCollisions`."
  def resolve_collisions(server), do: GenServer.cast(server, :resolve_collisions)

  @doc "The cached `getaddr` answer for a requester on `network` (Core `GetAddresses`)."
  def addr_response(server, network), do: GenServer.call(server, {:addr_response, network}, 5_000)

  def size(server), do: GenServer.call(server, :size, 5_000)

  @doc "Entries (new and tried) on one network, e.g. `:ipv4` (Core `AddrMan::Size(net)`)."
  def size(server, net), do: GenServer.call(server, {:size, net}, 5_000)
  def find_entry(server, key), do: GenServer.call(server, {:find_entry, key}, 5_000)

  @doc "Writes peers.dat now."
  def dump(server), do: GenServer.call(server, :dump, 5_000)

  @doc "Resolves DNS seeds (A and AAAA) and adds the results, with each seed's name as their source (Core ThreadDNSAddressSeed)."
  def seed_from_dns(server, seeds, port) do
    total =
      for seed <- seeds, reduce: 0 do
        n ->
          host = String.trim_trailing(seed, ".")

          addrs =
            for type <- [:a, :aaaa],
                ip <- :inet_res.lookup(String.to_charlist(host), :in, type, timeout: 5000),
                do: dns_seed_addr(ip, port, System.os_time(:second))

          add(server, addrs, {:internal, host})
          n + length(addrs)
      end

    total
  end

  # protocol.h SeedsAssumedServiceFlags(): NODE_NETWORK | NODE_WITNESS |
  # NODE_P2P_V2 (2057); Connman uses it for the fixed seeds too.
  @seeds_assumed_services 0x0809

  @doc "The services assumed for DNS and fixed seeds (Core `SeedsAssumedServiceFlags()`, 2057)."
  def seeds_assumed_services, do: @seeds_assumed_services

  @doc """
  The address book entry for one DNS seed result (Core ThreadDNSAddressSeed):
  the default port, `SeedsAssumedServiceFlags()`, and a random time 3 to 7
  days before `now`.
  """
  def dns_seed_addr(ip, port, now) do
    ip
    |> NetAddr.from_ip()
    |> Map.merge(%{
      port: port,
      services: @seeds_assumed_services,
      time: now - 3 * 86_400 - :rand.uniform(4 * 86_400)
    })
  end

  def key(%{net: n, addr: a, port: p}), do: {n, a, p}

  @doc "Core `GetGroup` of a key or address (bytes)."
  def group({net, a, _port}), do: NetAddr.group(%{net: net, addr: a})
  def group(%{net: _, addr: _} = x), do: NetAddr.group(x)

  def routable?({net, a, _}), do: NetAddr.routable?(%{net: net, addr: a})

  # --- server ------------------------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    path = opts[:path]
    magic = Keyword.get(opts, :magic, <<0, 0, 0, 0>>)

    table =
      case path && PeerFile.read(path, magic) do
        {:ok, term} ->
          t = Table.from_term(term)

          Logger.info(
            "loaded #{Table.size(t)} addresses from #{path} (#{t.n_tried} tried, #{t.n_new} new)"
          )

          t

        {:error, reason} ->
          Logger.warning("#{path}: #{inspect(reason)}; starting with an empty address book")
          new_table(opts)

        _ ->
          new_table(opts)
      end

    if path, do: Process.send_after(self(), :dump, @dump_interval_ms)

    {:ok,
     %{
       t: table,
       path: path,
       magic: magic,
       clock: Keyword.get(opts, :clock, fn -> System.os_time(:second) end),
       cache: %{}
     }}
  end

  @impl true
  def handle_cast({:add, addrs, source, penalty}, st) do
    {t, _} = Table.add(st.t, addrs, source_addr(source), penalty, st.clock.())
    {:noreply, %{st | t: t}}
  end

  def handle_cast({:good, key}, st),
    do: {:noreply, %{st | t: elem(Table.good(st.t, key, true, st.clock.()), 0)}}

  def handle_cast({:attempt, key, cf}, st),
    do: {:noreply, %{st | t: Table.attempt(st.t, key, cf, st.clock.())}}

  def handle_cast({:connected, key}, st),
    do: {:noreply, %{st | t: Table.connected(st.t, key, st.clock.())}}

  def handle_cast({:set_services, key, s}, st),
    do: {:noreply, %{st | t: Table.set_services(st.t, key, s)}}

  def handle_cast(:resolve_collisions, st),
    do: {:noreply, %{st | t: Table.resolve_collisions(st.t, st.clock.())}}

  @impl true
  def handle_call({:select, opts}, _from, st) do
    info =
      Table.select(
        st.t,
        Keyword.get(opts, :new_only, false),
        Keyword.get(opts, :networks, [:ipv4, :ipv6]),
        st.clock.()
      )

    {:reply, info && export(info), st}
  end

  def handle_call(:select_tried_collision, _from, st) do
    {t, info} = Table.select_tried_collision(st.t)
    {:reply, info && export(info), %{st | t: t}}
  end

  def handle_call({:addr_response, network}, _from, st) do
    now = st.clock.()

    case st.cache[network] do
      {expires, addrs} when expires > now ->
        {:reply, addrs, st}

      _ ->
        addrs =
          st.t
          |> Table.get_addr(@max_addr_to_send, @max_pct_addr_to_send, now)
          |> Enum.map(&export/1)

        expires = now + @addr_cache_s + :rand.uniform(@addr_cache_jitter_s)
        {:reply, addrs, put_in(st.cache[network], {expires, addrs})}
    end
  end

  def handle_call(:size, _from, st), do: {:reply, Table.size(st.t), st}

  def handle_call({:size, net}, _from, st) do
    {n, t} = Map.get(st.t.net_counts, net, {0, 0})
    {:reply, n + t, st}
  end

  def handle_call({:find_entry, key}, _from, st), do: {:reply, Table.find_entry(st.t, key), st}
  def handle_call(:dump, _from, st), do: {:reply, do_dump(st), st}

  @impl true
  def handle_info(:dump, st) do
    do_dump(st)
    Process.send_after(self(), :dump, @dump_interval_ms)
    {:noreply, st}
  end

  def handle_info(_, st), do: {:noreply, st}

  @impl true
  def terminate(_reason, st), do: do_dump(st)

  defp do_dump(%{path: nil}), do: :ok

  defp do_dump(st) do
    case PeerFile.write(st.path, st.magic, Table.to_term(st.t)) do
      :ok -> :ok
      err -> Logger.warning("could not write #{st.path}: #{inspect(err)}") && err
    end
  end

  # Test only: `key:` fixes the bucket secret, for deterministic placement.
  defp new_table(opts), do: if(k = opts[:key], do: Table.new(k), else: Table.new())

  defp source_addr(:seed), do: NetAddr.internal("dnsseed")
  defp source_addr({:internal, name}), do: NetAddr.internal(name)
  defp source_addr({net, a, _port}), do: %{net: net, addr: a}
  defp source_addr(%{net: _, addr: _} = a), do: Map.take(a, [:net, :addr])

  # The shape callers use: address fields plus the key and history.
  defp export(i) do
    Map.merge(i.addr, %{
      key: key(i.addr),
      services: i.services,
      time: i.time,
      last_try: i.last_try,
      last_success: i.last_success,
      attempts: i.attempts,
      in_tried: i.in_tried
    })
  end
end
