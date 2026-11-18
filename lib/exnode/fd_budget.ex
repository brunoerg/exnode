defmodule Exnode.FdBudget do
  @moduledoc """
  The node's file-descriptor budget, checked at startup (Core:
  `RaiseFileDescriptorLimit` and the `MIN_CORE_FILEDESCRIPTORS` check in
  init.cpp). Exnode cannot raise its own limit, so it fits RocksDB's open
  table files to the soft limit it was started with, and refuses to start
  when even the minimum does not fit, instead of failing mid-IBD with
  `emfile`.

  The descriptors, by user:

  * a fixed reserve (`@reserve`, Core's `MIN_CORE_FILEDESCRIPTORS` = 150):
    the VM (code loading, standard streams), RocksDB's WAL, manifest and log,
    the segment writers, peers.dat/anchors/status files;
  * peers: one socket per allowed connection, plus the listener;
  * archive segment reads: at most `Exnode.Archive.Segments.read_handles/0`
    per reading process, for `@readers` long-lived readers (chain state,
    prefetch workers, block serving, indexes);
  * the RPC and REST servers: at most `api_connections/0` connections each
    (one socket and `api_read_handles/0` segment handles per connection
    process). Uncapped, every keep-alive connection was a reader of 16
    handles that the budget did not count: enough of them exhausted the
    limit, and the chain state failed its next segment open;
  * RocksDB table files: the rest, at most `@max_table_files`, at least
    `@min_table_files`.
  """

  alias Exnode.Archive.Segments

  @reserve 150
  @readers 16
  @api_servers 2
  @api_connections 16
  @api_read_handles 2
  @min_table_files 64
  @max_table_files 4096

  @doc """
  The soft `RLIMIT_NOFILE` of this OS process (`/proc/self/limits`), or
  `:unknown` where that file does not exist.
  """
  def soft_limit do
    with {:ok, text} <- File.read("/proc/self/limits"),
         [_, soft] <- Regex.run(~r/^Max open files\s+(\d+|unlimited)/m, text) do
      if soft == "unlimited", do: :infinity, else: String.to_integer(soft)
    else
      _ -> :unknown
    end
  end

  @doc """
  The budget for `limit` descriptors and `max_connections` peers:
  `{:ok, %{limit, table_files, reserve, peers, segment_reads}}` with
  `table_files` the RocksDB `max_open_files` to use, or `{:error, message}`
  when fewer than `@min_table_files` would remain. An unknown limit gets
  `KV.default_max_open_files/0`.
  """
  def plan(limit, max_connections) do
    peers = max_connections + 1
    reads = @readers * Segments.read_handles()
    fixed = @reserve + peers + reads + api()

    case limit do
      :unknown ->
        {:ok,
         %{
           limit: :unknown,
           table_files: Exnode.Store.KV.default_max_open_files(),
           reserve: @reserve,
           peers: peers,
           segment_reads: reads,
           api: api()
         }}

      :infinity ->
        {:ok,
         %{
           limit: :infinity,
           table_files: @max_table_files,
           reserve: @reserve,
           peers: peers,
           segment_reads: reads,
           api: api()
         }}

      n when n - fixed >= @min_table_files ->
        {:ok,
         %{
           limit: n,
           table_files: min(n - fixed, @max_table_files),
           reserve: @reserve,
           peers: peers,
           segment_reads: reads,
           api: api()
         }}

      n ->
        {:error,
         "not enough file descriptors: the soft limit is #{n}, the node needs at least #{fixed + @min_table_files} " <>
           "(#{@reserve} reserved, #{peers} for peers, #{reads} for archive reads, #{api()} for RPC/REST, " <>
           "#{@min_table_files} for the index store). " <>
           "Raise it before starting, e.g. `ulimit -n 8192`, or lower max_connections."}
    end
  end

  @doc "Descriptors for which RocksDB gets its full `@max_table_files`."
  def recommended(max_connections),
    do:
      @reserve + max_connections + 1 + @readers * Segments.read_handles() + api() +
        @max_table_files

  @doc "Concurrent connections each API server (RPC, REST) accepts; more wait, then are closed."
  def api_connections, do: @api_connections

  @doc "Segment read handles each API connection process keeps (`Segments.limit_read_handles/1`)."
  def api_read_handles, do: @api_read_handles

  @doc "Descriptors of the API servers at their connection caps."
  def api, do: @api_servers * @api_connections * (1 + @api_read_handles)

  @doc "Bandit's `thousand_island_options` enforcing `api_connections/0` (one acceptor, so the cap is total)."
  def api_server_options, do: [num_acceptors: 1, num_connections: @api_connections]
end
