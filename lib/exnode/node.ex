defmodule Exnode.Node do
  @moduledoc """
  Top-level node supervisor. The tree keeps a failure inside the
  part of the node it belongs to:

      Node (rest_for_one)
      ├─ Shadow.Monitor (optional)
      ├─ Headers
      ├─ ScriptExec (the shared native script executor)
      ├─ ChainState
      ├─ Relay (rest_for_one): MempoolVerify (Task.Supervisor), Mempool, TxRelay
      ├─ P2P (rest_for_one): Book (AddrMan), SyncState, BlockDownload,
       │    HighBandwidth, BlockServing, DecodeBudget, Conns (one_for_all): PeerSup, Connman; Listener (optional)
      └─ Services (one_for_one): BlockFilter, Scripthash, RPC, REST (optional)

  * The chain core (Headers, ChainState) is upstream of everything: if it
    restarts, so does every subtree after it, since they hold views of it.
  * A Mempool or TxRelay crash restarts only the Relay subtree. Peers stay
    connected; the new TxRelay asks them to register again
    (`:tx_relay_resync`). Before, it restarted every peer, Connman, the
    listener, the indexes and RPC.
  * A crash in the P2P subtree restarts the P2P processes after it, never
    the mempool, the indexes or RPC. Connman and the peers are restarted
    together, so Connman's peer table always matches the running peers.
    AddrMan restarts alone (its Book subtree): while it is down, Connman
    dials nothing and does not seed, and a peer's getaddr gets no addresses.
  * Indexes, RPC and REST are leaves: each restarts alone.
  * Every subtree has its own restart intensity (10 in 60 s). A subtree that
    exceeds it counts as one failure of the root, which restarts the subtrees
    after it. If the root exceeds its own intensity the node supervisor
    stops (`restart: :temporary` under the application), and `mix
    exnode.node` exits with status 1 rather than run without a node.

  Components find each other by registered name (`names/1`), never by pid,
  and a message sent to a name that is restarting is dropped rather than
  raising (`Mempool` and `ChainState` listeners).

  Options:
    * `:chain`: `:mainnet | :testnet | :testnet4 | :signet | :regtest`
    * `:datadir`: data directory (RocksDB under `<datadir>/<chain>/index`, segments under `<chain>/archive`)
    * `:datadir_cold`: optional second directory for inputs and witness segments
    * `:connect`: list of `{host, port}`; only these peers (like `-connect`)
    * `:listen`: port to accept inbound peers on (default: none); `0` binds
      a free port, reported by `listen_port/1`
    * `:max_outbound_full_relay`, `:max_block_relay`, `:max_connections`
    * `:decode_budget_bytes`: payload bytes of large peer messages decoded and
      handled at once, node-wide (default `Exnode.P2P.DecodeBudget.default_bytes/0`)
    * `:assume_valid`: block hash (display hex), `"0"` to verify every script, default: the chain's
    * `:shadow`: run the shadow validator (Core's engine) and compare every verdict (default false)
    * `:halt_on_divergence`: halt block connection on a shadow divergence (default true)
    * `:prune_witness`: keep witness data only for the last 288 blocks (default false)
    * `:block_filter_index`: build the BIP158 basic filter index (Core `-blockfilterindex`)
    * `:peer_block_filters`: serve BIP157 filters to peers, NODE_COMPACT_FILTERS (Core `-peerblockfilters`)
    * `:index_scripthash`: build the scripthash history index (Electrum style)
    * `:rest_port`: serve the Esplora REST API on this port (needs `:index_scripthash` for addresses)
    * `:cache_bytes`: coin cache budget (default 450 MiB, Core `DEFAULT_KERNEL_CACHE`)
    * `:kv_cache_bytes`: RocksDB shared block cache budget (default 256 MiB)
    * `:chain_state_min_heap`: the chain state's minimum heap in words
      (default `Exnode.Chain.State.default_min_heap_size/0`, 384 MiB)
    * `:chain_state_min_bin_vheap`: the chain state's minimum binary virtual
      heap in words (default `Exnode.Chain.State.default_min_bin_vheap_size/0`;
      `nil`: the VM default)
    * `:script_workers`: native script jobs run at once by the node's executor,
      blocks and mempool together (default `ScriptExec.default_workers/0`)
    * `:rpc_port`: serve JSON-RPC on this port (default: off); cookie auth via
      `<datadir>/<chain>/.cookie`, plus `:rpc_user` / `:rpc_password` if given
    * `:name`: registered name prefix (default `Exnode.Node`)
    * `:clock`: the node's `Exnode.Clock` (default a new one, on the system
      time); every time-dependent component reads it, `setmocktime` sets
      it, and `tick/1` runs the periodic work against it
  """
  use Supervisor
  import Bitwise

  require Logger

  alias Exnode.ChainParams
  alias Exnode.Chain.Headers
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Node.Runtime
  alias Exnode.P2P.BlockDownload
  alias Exnode.P2P.{AddrMan, Connman, Listener, SyncState}
  alias Exnode.Store.Guard

  def start_link(opts),
    do: Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @doc """
  Stops the node `name` (Core StopNodes): marks it as stopping, so the
  components that save state for the next run (Connman's anchors.dat) can
  tell a node stop from a subtree restart, which stops them with the same
  `:shutdown` reason; then stops the supervisor. The mix task's SIGTERM path
  (application stop) marks every node through `mark_stopping(:all)`.
  """
  def stop(name \\ __MODULE__, timeout \\ :infinity) do
    mark_stopping(name)
    Supervisor.stop(name, :normal, timeout)
  end

  @doc "Marks node `name` (or `:all` nodes) as stopping; see `stop/2`."
  def mark_stopping(name), do: Runtime.mark_stopping(name)

  @doc "Whether node `name` is stopping (`stop/2`, or the application is)."
  def stopping?(name), do: Runtime.stopping?(name)

  @doc "Registered names of the node's components."
  def names(prefix \\ __MODULE__) do
    %{
      runtime: Module.concat(prefix, Runtime),
      handles: Runtime.handles_table(prefix),
      headers: Module.concat(prefix, Headers),
      addrman: Module.concat(prefix, AddrMan),
      sync: Module.concat(prefix, SyncState),
      peer_sup: Module.concat(prefix, PeerSup),
      local_nonces: Module.concat(prefix, LocalNonces),
      chain_state: Module.concat(prefix, ChainState),
      script_exec: Module.concat(prefix, ScriptExec),
      block_download: Module.concat(prefix, BlockDownload),
      block_serving: Module.concat(prefix, BlockServing),
      shadow_monitor: Module.concat(prefix, ShadowMonitor),
      mempool: Module.concat(prefix, Mempool),
      mempool_verify: Module.concat(prefix, MempoolVerify),
      tx_relay: Module.concat(prefix, TxRelay),
      high_bandwidth: Module.concat(prefix, HighBandwidth),
      rpc: Module.concat(prefix, RPC),
      filter_index: Module.concat(prefix, FilterIndex),
      scripthash_index: Module.concat(prefix, ScripthashIndex),
      connman: Module.concat(prefix, Connman),
      decode_budget: Module.concat(prefix, DecodeBudget),
      listener: Module.concat(prefix, Listener),
      relay_sup: Module.concat(prefix, RelaySup),
      p2p_sup: Module.concat(prefix, P2PSup),
      book_sup: Module.concat(prefix, BookSup),
      conns_sup: Module.concat(prefix, ConnsSup),
      services_sup: Module.concat(prefix, ServicesSup)
    }
  end

  @doc """
  Runs the node's periodic work now, against its clock, and returns once it
  has run (Core `mockscheduler` plus a `SendMessages` pass): BlockDownload's
  (stall and download timeouts), every peer's (timeouts, pings, sync,
  requests), then TxRelay's (request expiry, trickle) and Connman's
  (seeding, discouragement flush, outbound slots).
  Tests move the clock (`Exnode.Clock.advance/2`) and then call this,
  instead of sleeping for the timers.
  """
  def tick(prefix \\ __MODULE__) do
    n = names(prefix)

    peers =
      case GenServer.whereis(n.peer_sup) do
        nil -> []
        sup -> for {_, pid, _, _} <- DynamicSupervisor.which_children(sup), is_pid(pid), do: pid
      end

    Exnode.Clock.tick([n.block_download | peers] ++ [n.tx_relay, n.connman])
  end

  @doc "The P2P port the node's listener bound (`listen: 0` picks a free one); nil if not listening."
  def listen_port(prefix \\ __MODULE__) do
    case GenServer.whereis(names(prefix).listener) do
      nil -> nil
      pid -> Listener.port(pid)
    end
  end

  @doc """
  Child spec for the node under the application supervisor. Temporary: if
  the node's own restart intensity is exceeded it is not restarted in a
  loop (its RocksDB handle is opened in `init/1`); the caller decides
  (`mix exnode.node` exits).
  """
  def child_spec(opts),
    do: %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :supervisor,
      restart: :temporary
    }

  @group_restarts [max_restarts: 10, max_seconds: 60]

  # A subtree of the node.
  defp group(name, strategy, children),
    do: %{
      id: name,
      type: :supervisor,
      start:
        {Supervisor, :start_link, [children, [strategy: strategy, name: name] ++ @group_restarts]}
    }

  # JSON-RPC server.
  defp rpc_children(opts, n, node, params, datadir, chain) do
    case Keyword.get(opts, :rpc_port) do
      nil ->
        []

      port ->
        cookie = Exnode.RPC.Server.write_cookie(Path.join(datadir, Atom.to_string(chain)))

        userpass =
          if opts[:rpc_user], do: [{opts[:rpc_user], opts[:rpc_password] || ""}], else: []

        ctx = %{
          chain_state: n.chain_state,
          headers: n.headers,
          mempool: n.mempool,
          tx_relay: n.tx_relay,
          connman: n.connman,
          params: params,
          services: node.services,
          user_agent: node.user_agent,
          prune_witness: Keyword.get(opts, :prune_witness, false),
          clock: node.clock,
          started_at: Exnode.Clock.now(node.clock),
          # nil when disabled (the methods test for nil, not false).
          filter_index: if(Keyword.get(opts, :block_filter_index, false), do: n.filter_index)
        }

        [{Exnode.RPC.Server, port: port, ctx: ctx, auth: [cookie | userpass], id: n.rpc}]
    end
  end

  # Esplora REST API.
  defp rest_children(opts, n, params) do
    case Keyword.get(opts, :rest_port) do
      nil ->
        []

      port ->
        budget = Module.concat(n.rpc, RESTBlockBudget)

        ctx = %{
          chain_state: n.chain_state,
          headers: n.headers,
          mempool: n.mempool,
          params: params,
          # nil when disabled (the routes test for nil, not false).
          scripthash_index:
            if(Keyword.get(opts, :index_scripthash, false), do: n.scripthash_index),
          block_budget: budget
        }

        [
          Supervisor.child_spec(
            {Exnode.P2P.DecodeBudget,
             name: budget, bytes: Exnode.REST.Esplora.block_budget_bytes()},
            id: budget
          ),
          {Exnode.REST.Esplora, port: port, ctx: ctx, id: Module.concat(n.rpc, REST)}
        ]
    end
  end

  @impl true
  def init(opts) do
    chain = Keyword.fetch!(opts, :chain)
    params = ChainParams.get(chain)
    name = Keyword.get(opts, :name, __MODULE__)
    n = names(name)
    # A node started again under this name is running, not stopping.
    Runtime.clear_stopping(name)
    datadir = Keyword.fetch!(opts, :datadir)
    budget = fd_budget!(opts)
    chain_dir = Path.join(datadir, Atom.to_string(chain))
    File.mkdir_p!(chain_dir)

    want_filters? = Keyword.get(opts, :block_filter_index, false)
    want_scripthash? = Keyword.get(opts, :index_scripthash, false)
    derived_count = if(want_filters?, do: 1, else: 0) + if want_scripthash?, do: 1, else: 0

    # Acquire clean-close lock BEFORE opening RocksDB or any segment file.
    # A dirty or faulted store is refused here and must be restored via
    # `mix exnode.restore` (or resynced).
    canonical_guard = Guard.acquire!(chain_dir, name: "canonical", require_clean_mark: true)

    {canonical_fds, staging_fds, derived_fds} =
      split_table_files(budget.table_files, derived_count)

    kv_cache = Keyword.get(opts, :kv_cache_bytes, 256 * 1024 * 1024)

    derived_cache = min(32 * 1024 * 1024, max(8 * 1024 * 1024, div(kv_cache, 8)))

    {filters_store, filters_guard} =
      if want_filters? do
        dir = Path.join([chain_dir, "derived", "filters"])
        {dir, acquire_derived_guard!(dir, :filters, [canonical_guard])}
      else
        {nil, nil}
      end

    {scripthash_store, scripthash_guard} =
      if want_scripthash? do
        dir = Path.join([chain_dir, "derived", "scripthash"])

        {dir,
         acquire_derived_guard!(
           dir,
           :scripthash,
           Enum.reject([canonical_guard, filters_guard], &is_nil/1)
         )}
      else
        {nil, nil}
      end

    stores =
      [
        {:kv, Path.join(chain_dir, "index"),
         [
           mode: :canonical,
           guard: canonical_guard,
           max_open_files: canonical_fds,
           block_cache_bytes: kv_cache
         ]},
        {:staging_kv, Path.join(chain_dir, "staging"),
         [
           mode: :staging,
           guard: canonical_guard,
           max_open_files: staging_fds,
           block_cache_bytes: min(16 * 1024 * 1024, max(4 * 1024 * 1024, div(kv_cache, 16)))
         ]}
      ] ++
        if(want_filters?,
          do: [
            {:filters_kv, Path.join(filters_store, "index"),
             [
               mode: :derived,
               column_families: [:filters],
               guard: filters_guard,
               max_open_files: derived_fds,
               block_cache_bytes: derived_cache
             ]}
          ],
          else: []
        ) ++
        if(want_scripthash?,
          do: [
            {:scripthash_kv, Path.join(scripthash_store, "index"),
             [
               mode: :derived,
               column_families: [:scripthash],
               guard: scripthash_guard,
               max_open_files: derived_fds,
               block_cache_bytes: derived_cache
             ]}
          ],
          else: []
        )

    # Track whether Chain.State is opening the archive for the first time on
    # this node boot (strict_clean: true) vs an in-process non-storage restart.
    boot_open = :atomics.new(1, signed: false)
    :atomics.put(boot_open, 1, 0)

    clock = Keyword.get_lazy(opts, :clock, &Exnode.Clock.new/0)

    node = %{
      params: params,
      clock: clock,
      headers: n.headers,
      addrman: n.addrman,
      sync: n.sync,
      chain_state: n.chain_state,
      block_download: n.block_download,
      block_serving: n.block_serving,
      tx_relay: n.tx_relay,
      mempool: n.mempool,
      high_bandwidth: n.high_bandwidth,
      decode_budget: n.decode_budget,
      # Each peer sends its own version nonce; outbound ones still in the
      # handshake are registered here for the inbound self-connection check.
      local_nonces: n.local_nonces,
      # NODE_WITNESS, plus NODE_NETWORK (all blocks served), or
      # NODE_NETWORK_LIMITED with witness pruning.
      # BIP324 (Core -v2transport, default on): NODE_P2P_V2.
      services:
        Exnode.P2P.Message.service(:witness) |||
          if(Keyword.get(opts, :prune_witness, false),
            do: Exnode.P2P.Message.service(:network_limited),
            else: Exnode.P2P.Message.service(:network)
          ) |||
          if(Keyword.get(opts, :peer_block_filters, false),
            do: Exnode.P2P.Message.service(:compact_filters),
            else: 0
          ) |||
          if(Keyword.get(opts, :v2_transport, true),
            do: Exnode.P2P.Message.service(:p2p_v2),
            else: 0
          ),
      filter_index: if(Keyword.get(opts, :block_filter_index, false), do: n.filter_index),
      user_agent: "/exnode:0.1.0/",
      serve_headers: Keyword.get(opts, :serve_headers, true)
    }

    connman_opts =
      [
        name: n.connman,
        node: node,
        node_name: name,
        peer_sup: n.peer_sup,
        magic: params.magic,
        anchors_path: Path.join([datadir, Atom.to_string(chain), "anchors.dat"]),
        discouraged_path: Path.join([datadir, Atom.to_string(chain), "discouraged.dat"])
      ] ++
        Keyword.take(opts, [
          :connect,
          :max_outbound_full_relay,
          :max_block_relay,
          :max_connections
        ])

    shadow =
      if Keyword.get(opts, :shadow, false) do
        # Long shutdown: the shadow flushes Core's caches on exit.
        [
          Supervisor.child_spec(
            {Exnode.Shadow.Monitor,
             name: n.shadow_monitor,
             chain: chain,
             chain_state: n.chain_state,
             headers: n.headers,
             dir: Path.join([datadir, Atom.to_string(chain)]),
             halt: Keyword.get(opts, :halt_on_divergence, true)},
            shutdown: 130_000
          )
        ]
      else
        []
      end

    indexes =
      if(want_filters?,
        do: [
          {Exnode.Index.BlockFilter,
           name: n.filter_index,
           node_name: name,
           store_dir: filters_store,
           chain_state: n.chain_state}
        ],
        else: []
      ) ++
        if(want_scripthash?,
          do: [
            {Exnode.Index.Scripthash,
             name: n.scripthash_index,
             node_name: name,
             store_dir: scripthash_store,
             chain_state: n.chain_state}
          ],
          else: []
        )

    listener =
      case Keyword.get(opts, :listen) do
        nil ->
          []

        port ->
          [
            {Listener,
             name: n.listener, port: port, node: node, connman: n.connman, peer_sup: n.peer_sup}
          ]
      end

    services =
      indexes ++
        rpc_children(opts, n, node, params, datadir, chain) ++ rest_children(opts, n, params)

    # First, so it stops last: opens RocksDB in init/1, publishes it in the
    # per-node Handles ETS table, and on terminate erases published handles
    # and closes the store after all its users.
    # ScriptExec's worker fence key is intentionally omitted: it holds only
    # PIDs (no %KV{} ref) and must survive a Node.Runtime crash/restart so the
    # restarted ScriptExec still awaits any lingering dirty-NIF workers.
    cleanup_keys = [
      {Exnode.Chain.Headers, n.headers},
      {Exnode.Chain.State, n.chain_state},
      {Exnode.Index.BlockFilter, n.filter_index},
      {Exnode.Index.Scripthash, n.scripthash_index}
    ]

    runtime_spec =
      {Runtime,
       name: n.runtime,
       node_name: name,
       node_pid: self(),
       stores: stores,
       guards: Enum.reject([canonical_guard, filters_guard, scripthash_guard], &is_nil/1),
       cleanup_keys: cleanup_keys}

    children =
      [runtime_spec | shadow] ++
        [
          {Headers,
           name: n.headers,
           params: params,
           node_name: name,
           now: fn -> Exnode.Clock.now(clock) end},
          # Before the chain state (rest_for_one): an executor restart
          # restarts it, and the executor waits for its old workers' native
          # calls before taking new work (ScriptExec moduledoc).
          {Exnode.Validation.ScriptExec,
           name: n.script_exec, workers: Keyword.get(opts, :script_workers)},
          {
            ChainState,
            # BlockDownload wakes waiting peers when the tip advances.
            script_exec: n.script_exec,
            min_heap_size:
              Keyword.get(opts, :chain_state_min_heap, ChainState.default_min_heap_size()),
            min_bin_vheap_size:
              Keyword.get(
                opts,
                :chain_state_min_bin_vheap,
                ChainState.default_min_bin_vheap_size()
              ),
            listeners: [n.block_download],
            gc_probe: Keyword.get(opts, :gc_probe, true),
            name: n.chain_state,
            node_name: name,
            params: params,
            headers: n.headers,
            guard: canonical_guard,
            chain_dir: chain_dir,
            boot_open: boot_open,
            assume_valid: Keyword.get(opts, :assume_valid),
            prune_witness: Keyword.get(opts, :prune_witness, false),
            commit_at_tip: Keyword.get(opts, :commit_at_tip, true),
            batch_blocks:
              Keyword.get(opts, :batch_blocks, elem(ChainState.default_batch_limits(), 0)),
            batch_bytes:
              Keyword.get(opts, :batch_bytes, elem(ChainState.default_batch_limits(), 1)),
            snapshot_every_commits: Keyword.get(opts, :snapshot_every_commits, 1),
            prefetch_depth:
              Keyword.get(opts, :prefetch_depth, Exnode.Chain.State.default_prefetch_depth()),
            mempool: n.mempool,
            cache_bytes: Keyword.get(opts, :cache_bytes, 450 * 1024 * 1024),
            shadow_monitor: if(Keyword.get(opts, :shadow, false), do: n.shadow_monitor),
            hot: Path.join([datadir, Atom.to_string(chain), "archive"]),
            crash_dir: Path.join([datadir, Atom.to_string(chain), "crashes"]),
            cold:
              Keyword.get(opts, :datadir_cold) &&
                Path.join([opts[:datadir_cold], Atom.to_string(chain), "archive"])
          },
          group(n.relay_sup, :rest_for_one, [
            # The mempool's script checks (Core: the -par script-check threads).
            {Task.Supervisor, name: n.mempool_verify},
            # Script checks share the node's executor (and its cap) with blocks.
            {
              Exnode.Mempool,
              # The Esplora address endpoints' mempool side (needs the
              # scripthash index anyway).
              name: n.mempool,
              verify_sup: n.mempool_verify,
              verify: &Exnode.Validation.ScriptExec.verify(n.script_exec, &1, &2, &3),
              chain_state: n.chain_state,
              headers: n.headers,
              params: params,
              clock: fn -> Exnode.Clock.now(clock) end,
              index_scripts: Keyword.get(opts, :index_scripthash, false),
              listeners: [n.tx_relay]
            },
            # Core times tx requests, the trickle and the inv buckets on
            # NodeClock, which setmocktime moves: the node clock, not mono.
            {Exnode.P2P.TxRelay,
             name: n.tx_relay,
             mempool: n.mempool,
             peer_sup: n.peer_sup,
             clock: fn -> Exnode.Clock.now_ms(clock) end}
          ]),
          group(
            n.p2p_sup,
            :rest_for_one,
            [
              # Its own one-child subtree: an AddrMan crash restarts only
              # AddrMan; Connman and the peers tolerate its absence meanwhile.
              group(n.book_sup, :one_for_one, [
                {AddrMan,
                 name: n.addrman,
                 path: Path.join([datadir, Atom.to_string(chain), "peers.dat"]),
                 magic: params.magic,
                 clock: fn -> Exnode.Clock.now(clock) end}
              ]),
              {SyncState, name: n.sync},
              {BlockDownload,
               name: n.block_download,
               headers: n.headers,
               chain: n.chain_state,
               params: params,
               clock: clock},
              {Exnode.P2P.HighBandwidth, name: n.high_bandwidth},
              {Exnode.P2P.BlockServing, name: n.block_serving},
              {Exnode.P2P.DecodeBudget,
               name: n.decode_budget,
               bytes:
                 Keyword.get(opts, :decode_budget_bytes, Exnode.P2P.DecodeBudget.default_bytes())},
              group(n.conns_sup, :one_for_all, [
                {Registry, keys: :unique, name: n.local_nonces},
                {DynamicSupervisor, name: n.peer_sup, strategy: :one_for_one},
                {Connman, connman_opts}
              ])
            ] ++ listener
          ),
          group(n.services_sup, :one_for_one, services)
        ]

    # Restart intensity above the default (3 in 5 s), so a few transient
    # failures do not take the whole node down. The real defense against a
    # block that crashes validation is the chain state's quarantine (a crash
    # is contained to the block, and a restart cannot replay it). Most
    # failures are absorbed by a subtree and never reach this level.
    Supervisor.init(children, strategy: :rest_for_one, max_restarts: 10, max_seconds: 60)
  end

  @doc """
  The descriptor budget for these node options (`Exnode.FdBudget`); raises
  with the reason when the process's soft limit is too low.
  `:kv_max_open_files` overrides the RocksDB part.
  """
  def fd_budget!(opts) do
    max_conn = Keyword.get(opts, :max_connections, Exnode.P2P.Connman.default_max_connections())

    case Exnode.FdBudget.plan(Exnode.FdBudget.soft_limit(), max_conn) do
      {:ok, b} ->
        b = %{b | table_files: Keyword.get(opts, :kv_max_open_files, b.table_files)}
        rec = Exnode.FdBudget.recommended(max_conn)

        if is_integer(b.limit) and b.limit < rec,
          do:
            Logger.warning(
              "file descriptor limit #{b.limit}: the index store keeps at most #{b.table_files} table files open; `ulimit -n #{rec}` lets it keep its full budget"
            )

        b

      {:error, msg} ->
        raise ArgumentError, msg
    end
  end

  defp split_table_files(total, 0) do
    staging = min(64, max(16, div(total, 8)))
    {max(32, total - staging), staging, 0}
  end

  defp split_table_files(total, n_derived) when n_derived > 0 do
    staging = min(64, max(16, div(total, 8)))
    derived_total = min(128, max(32 * n_derived, div(total, 4)))
    per_derived = max(16, div(derived_total, n_derived))
    {max(32, total - staging - per_derived * n_derived), staging, per_derived}
  end

  # Acquires the clean-close lock for a dedicated single-writer derived index
  # store under `store_dir` (`store_dir/flush.lock`, `store_dir/index/`,
  # `store_dir/snapshots/`). If acquiring the derived lock fails (dirty/faulted
  # derived store), cleanly releases any already-acquired locks so clean stores
  # stay clean.
  defp acquire_derived_guard!(store_dir, cf, prior_guards) do
    File.mkdir_p!(store_dir)
    name = "derived:#{cf}"

    try do
      Guard.acquire!(store_dir, name: name, require_clean_mark: true)
    rescue
      e ->
        for g <- prior_guards do
          Guard.mark_clean_close!(g)
          Guard.release_clean!(g)
        end

        reraise e, __STACKTRACE__
    end
  end
end
