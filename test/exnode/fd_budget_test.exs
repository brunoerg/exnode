defmodule Exnode.FdBudgetTest do
  @moduledoc """
  The node's descriptor budget (`Exnode.FdBudget`): RocksDB gets what the
  reserve, peers and archive reads leave, bounded both ways; a limit too low
  for the minimum is refused with the numbers; the soft limit is read from
  the OS. The mainnet failure it addresses: a 1,024 soft limit, 920 index
  SST files all open plus unbounded segment read handles, `emfile` at
  height 593,719.
  """
  use ExUnit.Case, async: true

  alias Exnode.Archive.Segments
  alias Exnode.FdBudget
  alias Exnode.Store.KV

  @reads 16 * 16
  # RPC and REST: 16 connections each, one socket and 2 segment handles per connection.
  @api 2 * 16 * 3

  test "a 1,024 soft limit with the default 200 peers fits, with a bounded index store" do
    assert Segments.read_handles() == 16
    assert {:ok, b} = FdBudget.plan(1024, 200)
    assert b.peers == 201
    assert b.segment_reads == @reads
    assert b.api == @api
    assert b.table_files == 1024 - 150 - 201 - @reads - @api
    assert b.reserve + b.peers + b.segment_reads + b.api + b.table_files == 1024
  end

  test "RocksDB's share is capped above and refused below its minimum" do
    assert {:ok, %{table_files: 4096}} = FdBudget.plan(1_048_576, 200)
    assert {:ok, %{table_files: 4096}} = FdBudget.plan(:infinity, 200)
    assert {:ok, %{table_files: n}} = FdBudget.plan(:unknown, 200)
    assert n == KV.default_max_open_files()

    # The smallest limit that still leaves 64 table files.
    min = 150 + 201 + @reads + @api + 64
    assert {:ok, %{table_files: 64}} = FdBudget.plan(min, 200)
    assert {:error, msg} = FdBudget.plan(min - 1, 200)
    assert msg =~ "soft limit is #{min - 1}"
    assert msg =~ "at least #{min}"
    assert msg =~ "ulimit -n"

    # Fewer peers leave more for the store.
    assert {:ok, %{table_files: t}} = FdBudget.plan(1024, 10)
    assert t == 1024 - 150 - 11 - @reads - @api
  end

  test "recommended/1 is the limit at which the store gets its whole share" do
    rec = FdBudget.recommended(200)
    assert {:ok, %{table_files: 4096}} = FdBudget.plan(rec, 200)
    assert {:ok, %{table_files: 4095}} = FdBudget.plan(rec - 1, 200)
  end

  @tag :tmp_dir
  test "the soft limit comes from the OS, and KV.open takes the bound", %{tmp_dir: dir} do
    case FdBudget.soft_limit() do
      :unknown -> :ok
      :infinity -> :ok
      n -> assert is_integer(n) and n > 0
    end

    {:ok, kv} = KV.open(dir, max_open_files: 64)
    :ok = KV.write(kv, [{:put, :spends, "k", "v"}])
    assert KV.get(kv, :spends, "k") == {:ok, "v"}
    KV.close(kv)
  end

  # IDX-2 (STATE_MACHINES.md): every RPC/REST keep-alive connection is an
  # archive reader with up to 16 segment handles, and nothing bounded the
  # connections, so clients could exhaust the descriptors the budget gives
  # RocksDB and the chain state. Both servers are capped, and each
  # connection process keeps fewer handles; the budget counts both.
  test "the API servers are capped at the connections the budget counts" do
    opts = FdBudget.api_server_options()
    assert opts[:num_acceptors] * opts[:num_connections] == FdBudget.api_connections()

    for spec <- [
          Exnode.RPC.Server.child_spec(port: 0, ctx: %{}, auth: {"u", "p"}),
          Exnode.REST.Esplora.child_spec(port: 0, ctx: %{})
        ] do
      {Bandit, :start_link, [args]} = spec.start
      assert args[:thousand_island_options] == opts
    end
  end
end
