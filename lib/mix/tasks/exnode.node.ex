defmodule Mix.Tasks.Exnode.Node do
  @shortdoc "Runs an exnode node"
  @moduledoc """
  Runs a node until interrupted, printing a status line every 10 seconds.

      mix exnode.node --chain mainnet --datadir ~/.exnode [--connect host:port]... [--listen 8333]
                      [--status-file path]

  Validation options: `--assumevalid <hash>|0`, `--shadow` (cross-check every
  verdict with Core's engine), `--no-halt-on-divergence`.

  Service options: `--rpcport <port>` (default: Core's port for the chain),
  `--rpcuser` / `--rpcpassword` (besides the `.cookie` file), `--norpc`,
  `--blockfilterindex`, `--peerblockfilters` (BIP157/158), `--indexscripthash`,
  `--restport <port>` (Esplora REST API).

  P2P options: `--no-v2transport` (BIP324 off; on by default, as Core's
  `-v2transport=1`).

  Storage options: `--datadir-cold <dir>` (inputs and witness segments, which
  are rarely read), `--prune-witness` (keep witness data for the last 288
  blocks only), `--dbcache <MiB>` (coin cache budget, default 450 as Core's
  `DEFAULT_KERNEL_CACHE`), `--batch-blocks <n>` / `--batch-mib <MiB>` (commit
  batch limits, default 128 blocks / 64 MiB; larger values cut sync overhead
  during IBD at the cost of memory and crash replay), `--chain-state-heap-mib
  <MiB>` (the chain state's minimum heap, default 16; during IBD its live
  data is hundreds of MiB, and a larger floor means fewer collections).

  `--status-file` also writes the latest status as JSON (best header height
  and hash, peer count), for scripts that compare against bitcoind.
  """
  use Mix.Task

  alias Exnode.Chain.Headers
  alias Exnode.Crypto.Hash
  alias Exnode.P2P.{Connman, Peer}

  @switches [
    chain: :string,
    datadir: :string,
    connect: :keep,
    listen: :integer,
    status_file: :string,
    serve_headers: :boolean,
    status_interval: :integer,
    assumevalid: :string,
    shadow: :boolean,
    halt_on_divergence: :boolean,
    datadir_cold: :string,
    prune_witness: :boolean,
    dbcache: :integer,
    commit_at_tip: :boolean,
    prefetch: :integer,
    batch_blocks: :integer,
    batch_mib: :integer,
    chain_state_heap_mib: :integer,
    rpcport: :integer,
    rpcuser: :string,
    rpcpassword: :string,
    norpc: :boolean,
    blockfilterindex: :boolean,
    peerblockfilters: :boolean,
    indexscripthash: :boolean,
    restport: :integer,
    v2transport: :boolean
  ]

  @impl true
  def run(argv) do
    {opts, _} = OptionParser.parse!(argv, strict: @switches)
    Mix.Task.run("app.start")

    name = Keyword.get(opts, :chain, "mainnet")

    chain =
      Enum.find(Exnode.ChainParams.networks(), &(Atom.to_string(&1) == name)) ||
        Mix.raise(
          "unknown chain #{name}; expected one of #{inspect(Exnode.ChainParams.networks())}"
        )

    datadir = opts |> Keyword.get(:datadir, Path.expand("~/.exnode")) |> Path.expand()

    connect =
      for c <- Keyword.get_values(opts, :connect) do
        [host, port] = String.split(c, ":")
        {host, String.to_integer(port)}
      end

    node_opts =
      [
        chain: chain,
        datadir: datadir,
        serve_headers: Keyword.get(opts, :serve_headers, true),
        assume_valid: opts[:assumevalid],
        shadow: Keyword.get(opts, :shadow, false),
        halt_on_divergence: Keyword.get(opts, :halt_on_divergence, true),
        datadir_cold: opts[:datadir_cold] && Path.expand(opts[:datadir_cold]),
        prune_witness: Keyword.get(opts, :prune_witness, false),
        cache_bytes: Keyword.get(opts, :dbcache, 450) * 1024 * 1024,
        # Test only: --no-commit-at-tip keeps blocks batched at the tip (crash tests).
        commit_at_tip: Keyword.get(opts, :commit_at_tip, true),
        # Commit batch limits: a batch is committed (segment sync + one synced
        # KV write) once it reaches either. Larger batches amortize the syncs
        # during IBD at the cost of memory and more blocks to replay after a crash.
        batch_blocks:
          Keyword.get(opts, :batch_blocks, elem(Exnode.Chain.State.default_batch_limits(), 0)),
        batch_bytes:
          if(opts[:batch_mib],
            do: opts[:batch_mib] * 1024 * 1024,
            else: elem(Exnode.Chain.State.default_batch_limits(), 1)
          ),
        # The chain state's minimum heap, in words.
        chain_state_min_heap:
          if(opts[:chain_state_heap_mib],
            do: div(opts[:chain_state_heap_mib] * 1024 * 1024, :erlang.system_info(:wordsize)),
            else: Exnode.Chain.State.default_min_heap_size()
          ),
        # Blocks the prefetch stage prepares ahead (--prefetch 0 turns it off).
        prefetch_depth: Keyword.get(opts, :prefetch, Exnode.Chain.State.default_prefetch_depth()),
        rpc_port:
          if(opts[:norpc], do: nil, else: Keyword.get(opts, :rpcport, default_rpc_port(chain))),
        rpc_user: opts[:rpcuser],
        rpc_password: opts[:rpcpassword],
        block_filter_index:
          Keyword.get(opts, :blockfilterindex, false) or
            Keyword.get(opts, :peerblockfilters, false),
        peer_block_filters: Keyword.get(opts, :peerblockfilters, false),
        index_scripthash: Keyword.get(opts, :indexscripthash, false),
        rest_port: opts[:restport],
        v2_transport: Keyword.get(opts, :v2transport, true)
      ] ++
        if(connect == [], do: [], else: [connect: connect]) ++
        if(opts[:listen], do: [listen: opts[:listen]], else: [])

    # Under the application supervisor, so SIGTERM (init:stop) shuts the node
    # down in order and terminate callbacks run: Connman writes anchors.dat,
    # AddrMan peers.dat, the chain state commits.
    # The descriptor budget first (Exnode.FdBudget): a clear refusal now
    # instead of `emfile` deep into IBD.
    max_conn =
      Keyword.get(node_opts, :max_connections, Exnode.P2P.Connman.default_max_connections())

    with {:error, msg} <- Exnode.FdBudget.plan(Exnode.FdBudget.soft_limit(), max_conn) do
      IO.puts(:stderr, "exnode: " <> msg)
      System.halt(1)
    end

    pid =
      case Supervisor.start_child(Exnode.Supervisor, {Exnode.Node, node_opts}) do
        {:ok, pid} ->
          pid

        {:error, reason} ->
          IO.puts(:stderr, "exnode: the node did not start: #{inspect(reason, limit: 10)}")
          System.halt(1)
      end

    n = Exnode.Node.names()
    Process.put(:node_ref, Process.monitor(pid))

    loop(
      n,
      opts[:status_file],
      System.monotonic_time(:second),
      Keyword.get(opts, :status_interval, 10_000)
    )
  end

  # The node supervisor is temporary: if it gave up, exit with
  # status 1 instead of running on without a node. A shutdown in progress
  # (SIGTERM, init:stop) also stops it; then let the shutdown finish.
  defp node_down(reason) do
    case :init.get_status() do
      {:stopping, _} ->
        Process.sleep(:infinity)

      _ ->
        IO.puts(:stderr, "node supervisor stopped: #{inspect(reason, limit: 10)}; exiting")
        System.halt(1)
    end
  end

  # chainparamsbase.cpp default RPC ports.
  defp default_rpc_port(:mainnet), do: 8332
  defp default_rpc_port(:testnet), do: 18332
  defp default_rpc_port(:testnet4), do: 48332
  defp default_rpc_port(:signet), do: 38332
  defp default_rpc_port(:regtest), do: 18443

  defp loop(n, status_file, t0, interval) do
    ref = Process.get(:node_ref)

    receive do
      {:DOWN, ^ref, :process, _, reason} -> node_down(reason)
    after
      interval -> :ok
    end

    try do
      status(n, status_file, t0)
    catch
      kind, reason -> IO.puts("status unavailable: #{inspect(kind)} #{inspect(reason, limit: 5)}")
    end

    loop(n, status_file, t0, interval)
  end

  # Reads the chain view (ETS) rather than calling the chain-state process,
  # which can be busy for seconds on a large block.
  defp status(n, status_file, t0) do
    best = Headers.best_header(n.headers)
    view = Exnode.Chain.State.view(n.chain_state)
    tip = Exnode.Chain.State.view_tip(view)
    committed = Exnode.Chain.State.view_committed(view)
    peers = Connman.peers(n.connman)
    ready = Enum.count(peers, fn {_, p} -> p.ready end)

    presync =
      peers
      |> Map.keys()
      |> Enum.flat_map(fn pid ->
        try do
          case Peer.info(pid) do
            %{presync: s} when s != nil -> ["#{s}"]
            _ -> []
          end
        catch
          :exit, _ -> []
        end
      end)

    sstats =
      if Process.whereis(n.shadow_monitor), do: Exnode.Shadow.Monitor.stats(n.shadow_monitor)

    shadow = if sstats, do: " shadow=#{sstats.blocks}blk/#{sstats.divergences}div", else: ""
    halted_r = Exnode.Chain.State.view_halted(view)
    halted = if halted_r, do: " HALTED=#{inspect(halted_r)}", else: ""

    line =
      "[#{System.monotonic_time(:second) - t0}s] tip=#{tip.height} committed=#{committed} best_header=#{best.height} #{Hash.to_hex(best.hash)} " <>
        "peers=#{ready}/#{map_size(peers)} presync=#{inspect(presync)}" <> shadow <> halted

    IO.puts(line)

    if status_file do
      File.write!(
        status_file,
        Jason.encode!(%{
          height: best.height,
          hash: Hash.to_hex(best.hash),
          peers: ready,
          tip_height: tip.height,
          tip_hash: Hash.to_hex(tip.hash),
          committed_height: committed,
          shadow: sstats,
          halted: halted_r && inspect(halted_r),
          presync: presync,
          time: System.os_time(:second)
        })
      )
    end
  end
end
