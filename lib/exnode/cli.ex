defmodule Exnode.CLI do
  @moduledoc """
  The node's command-line entry points, without Mix: `mix exnode.node` and
  `mix exnode.reconsider` call them, and so do the release's `bin/exnoded`
  and `bin/exnode-reconsider` (see `rel/overlays/bin`). Options are
  documented in those Mix tasks.
  """

  alias Exnode.Chain.Headers
  alias Exnode.Crypto.Hash
  alias Exnode.P2P.{Connman, Peer}
  alias Exnode.Store.KV

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
    decode_budget_mib: :integer,
    max_connections: :integer,
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

  @doc "`mix exnode.node` and `bin/exnoded`: runs a node until it stops."
  def node(argv) do
    {opts, _} = OptionParser.parse!(argv, strict: @switches)
    {:ok, _} = Application.ensure_all_started(:exnode)

    name = Keyword.get(opts, :chain, "mainnet")

    chain =
      Enum.find(Exnode.ChainParams.networks(), &(Atom.to_string(&1) == name)) ||
        fail("unknown chain #{name}; expected one of #{inspect(Exnode.ChainParams.networks())}")

    params = Exnode.ChainParams.get(chain)
    datadir = opts |> Keyword.get(:datadir, Path.expand("~/.exnode")) |> Path.expand()

    connect =
      for c <- Keyword.get_values(opts, :connect) do
        case parse_connect(c, params.default_port) do
          {:ok, target} ->
            target

          :error ->
            fail("invalid --connect address #{inspect(c)}; expected host[:port] or [ipv6]:port")
        end
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
        decode_budget_bytes:
          if(opts[:decode_budget_mib],
            do: opts[:decode_budget_mib] * 1024 * 1024,
            else: Exnode.P2P.DecodeBudget.default_bytes()
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
        if(opts[:listen], do: [listen: opts[:listen]], else: []) ++
        if(opts[:max_connections], do: [max_connections: opts[:max_connections]], else: [])

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
      tmp = status_file <> ".tmp"

      File.write!(
        tmp,
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

      File.rename!(tmp, status_file)
    end
  end

  defp parse_connect("[" <> rest, default_port) do
    case String.split(rest, "]", parts: 2) do
      [host, ""] when host != "" -> {:ok, {host, default_port}}
      [host, ":" <> p] when host != "" -> parse_port(host, p)
      _ -> :error
    end
  end

  defp parse_connect(s, default_port) do
    case String.split(s, ":") do
      [host] when host != "" -> {:ok, {host, default_port}}
      [host, p] when host != "" -> parse_port(host, p)
      _ -> :error
    end
  end

  defp parse_port(host, p) do
    case Integer.parse(p) do
      {port, ""} when port in 1..65_535 -> {:ok, {host, port}}
      _ -> :error
    end
  end

  defp fail(msg) do
    IO.puts(:stderr, "exnode: " <> msg)
    System.halt(1)
  end

  @doc "`mix exnode.reconsider` and `bin/exnode-reconsider`."
  def reconsider(argv) do
    {opts, args} =
      OptionParser.parse!(argv,
        strict: [chain: :string, datadir: :string, all: :boolean, clear_halt: :boolean]
      )

    name = Keyword.get(opts, :chain, "mainnet")

    _chain =
      Enum.find(Exnode.ChainParams.networks(), &(Atom.to_string(&1) == name)) ||
        fail("unknown chain #{name}; expected one of #{inspect(Exnode.ChainParams.networks())}")

    datadir = opts |> Keyword.get(:datadir, "~/.exnode") |> Path.expand()
    path = Path.join([datadir, name, "index"])

    kv =
      case KV.open(path, create_if_missing: false) do
        {:ok, kv} -> kv
        {:error, reason} -> fail("cannot open store at #{path}: #{inspect(reason)}")
      end

    try do
      clear_halt? = Keyword.get(opts, :clear_halt, false)

      case Exnode.Chain.State.halt_mark(kv) do
        nil ->
          IO.puts("block connection not halted")

        m when clear_halt? ->
          :ok = KV.write(kv, [{:delete, :meta, "halt"}], sync: true)
          IO.puts("cleared halt: #{inspect(m.reason)} (height #{m.height})")

        m ->
          IO.puts(
            "HALTED since #{m.time} at height #{m.height} (#{Hash.to_hex(m.hash)}): #{inspect(m.reason)} " <>
              "(clear with --clear-halt)"
          )
      end

      marks =
        KV.fold_prefix(kv, :poisoned, <<>>, [], fn {k, v}, acc ->
          [{k, :erlang.binary_to_term(v)} | acc]
        end)

      targets =
        cond do
          opts[:all] -> Enum.map(marks, &elem(&1, 0))
          args != [] -> Enum.map(args, &parse_hash_arg!/1)
          true -> []
        end

      if targets == [] do
        if marks == [] and not clear_halt?, do: IO.puts("no quarantined blocks")

        for {h, m} <- marks,
            do: IO.puts("#{Hash.to_hex(h)} height #{m.height} at #{m.time}: #{m.error}")
      else
        :ok = KV.write(kv, for(h <- targets, do: {:delete, :poisoned, h}), sync: true)
        for h <- targets, do: IO.puts("cleared #{Hash.to_hex(h)}")
      end
    after
      KV.close(kv)
    end
  end

  defp parse_hash_arg!(hex) do
    if is_binary(hex) and byte_size(hex) == 64 do
      case Base.decode16(hex, case: :mixed) do
        {:ok, _} -> Hash.from_hex(hex)
        :error -> fail("invalid block hash #{inspect(hex)}")
      end
    else
      fail("invalid block hash #{inspect(hex)}")
    end
  end
end
