defmodule Exnode.Store.FaultPropagationTest do
  @moduledoc """
  End-to-end verification of the five store integrity invariants on a live
  `Exnode.Node`:

  1. Clean shutdown removes `flush.lock`, rotates snapshots, and reopens cleanly.
  2. Unclean kill leaves `flush.lock` on disk; reopening `Exnode.Node` refuses
     the dirty store until `Snapshot.restore!/2` restores an exact prior state.
  3. Any storage or integrity fault in `BlockServing`, `Scripthash`, `RPC`, or
     `Chain.State` latches `Store.Guard` immediately, halts the entire
     `Exnode.Node` supervisor without restarting `Chain.State`, skips
     uncommitted batch commit in `terminate/2`, retains `flush.lock` with the
     fault record, and refuses restore without `force_from_snapshot: true`.
  4. Canonical scan count cross-checks (`:blockhash`, `:headers`, `:poisoned`)
     catch silently truncated scans loudly.
  """
  use Exnode.NodeCase
  import ExUnit.CaptureLog

  alias Exnode.Archive
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Crypto.Hash
  alias Exnode.Index.Scripthash
  alias Exnode.P2P.BlockServing
  alias Exnode.Store.{Guard, KV, Snapshot}
  alias Exnode.Test.BlockBuilder, as: BB

  @p Exnode.ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp blocks(n) do
    @chain
    |> BB.read_chain()
    |> Enum.take(n)
    |> Enum.map(&elem(Block.decode_exact(&1), 1))
  end

  defp start_unlinked_node(dir, opts \\ []) do
    name = TestNode.unique_name()

    node_opts =
      Keyword.merge(
        [
          chain: :regtest,
          datadir: dir,
          name: name,
          connect: [{"127.0.0.1", 1}],
          chain_state_min_heap: 2_000_000,
          gc_probe: false
        ],
        opts
      )

    {:ok, pid} = Exnode.Node.start_link(node_opts)
    Process.unlink(pid)
    {pid, name, Exnode.Node.names(name)}
  end

  defp corrupt_last_byte!(path) do
    bin = File.read!(path)
    flipped = Bitwise.bxor(:binary.last(bin), 0xFF)
    File.write!(path, binary_part(bin, 0, byte_size(bin) - 1) <> <<flipped>>)
  end

  test "clean shutdown removes flush.lock and reopens cleanly; kill leaves flush.lock and refuses open until restored",
       %{tmp_dir: dir} do
    chain_dir = Path.join(dir, "regtest")
    [b1, b2, b3, b4] = blocks(4)

    # 1. Start, connect 2 blocks, stop cleanly -> flush.lock removed, reopen succeeds.
    %{name: name1, n: n1} = TestNode.start(dir)
    assert {:dirty, %{status: :open}} = Guard.inspect_lock(chain_dir)
    for b <- [b1, b2], do: assert({:ok, :connected} = State.submit_block(n1.chain_state, b))
    :ok = stop_supervised(name1)
    assert Guard.inspect_lock(chain_dir) == :clean

    assert {:ok, :primary, _, %{tip: %{height: 2}}} =
             Snapshot.latest_valid(Snapshot.snapshots_dir(chain_dir))

    # 2. Reopen cleanly, connect b3 & b4 WITHOUT committing, then kill node root.
    {root, _name2, n2} = start_unlinked_node(dir, batch_blocks: 100, commit_at_tip: false)
    assert State.tip(n2.chain_state).height == 2
    for b <- [b3, b4], do: assert({:ok, :connected} = State.submit_block(n2.chain_state, b))
    assert State.tip(n2.chain_state).height == 4

    ref = Process.monitor(root)
    Process.exit(root, :kill)
    assert_receive {:DOWN, ^ref, :process, ^root, :killed}, 5_000

    # flush.lock MUST remain on disk!
    assert {:dirty, %{status: :open}} = Guard.inspect_lock(chain_dir)

    # Starting Exnode.Node on the dirty store MUST fail before opening RocksDB!
    capture_log(fn ->
      parent = self()

      spawn(fn ->
        Process.flag(:trap_exit, true)

        res =
          Exnode.Node.start_link(
            chain: :regtest,
            datadir: dir,
            name: TestNode.unique_name(),
            connect: [{"127.0.0.1", 1}],
            chain_state_min_heap: 2_000_000,
            gc_probe: false
          )

        send(parent, {:start_res, res})
      end)

      assert_receive {:start_res,
                      {:error,
                       {%Exnode.StorageError{reason: {:dirty_store, "canonical", _, _}}, _}}},
                     5_000
    end)

    # Restore brings back exact prior committed state (height 2) and clears flush.lock.
    {:ok, restored} = Snapshot.restore!(chain_dir)
    assert restored.tip.height == 2
    assert Guard.inspect_lock(chain_dir) == :clean

    # Reopen succeeds with strict_clean: true at exact height 2.
    %{name: name3, n: n3} = TestNode.start(dir)
    assert State.tip(n3.chain_state).height == 2

    State.with_archive(n3.chain_state, fn a ->
      assert Archive.read_block(a, Archive.id_at(a, 1)) == b1.raw
      assert Archive.read_block(a, Archive.id_at(a, 2)) == b2.raw
    end)

    :ok = stop_supervised(name3)
  end

  test "corrupt segment read in BlockServing latches fault and immediately halts Exnode.Node", %{
    tmp_dir: dir
  } do
    chain_dir = Path.join(dir, "regtest")
    [b1, b2] = blocks(2)

    {root, _name, n} = start_unlinked_node(dir, batch_blocks: 100, commit_at_tip: false)
    ref = Process.monitor(root)
    assert {:ok, :connected} = State.submit_block(n.chain_state, b1)
    :ok = State.commit_now(n.chain_state)
    seg0 = Path.join([chain_dir, "archive", "outputs", "00000.seg"])
    b1_end = File.stat!(seg0).size
    # Leave b2 uncommitted in memory: fault-triggered shutdown MUST NOT commit it!
    assert {:ok, :connected} = State.submit_block(n.chain_state, b2)
    assert State.tip(n.chain_state).height == 2

    # Corrupt b1's output bytes (at b1_end - 1, before b2's uncommitted tail).
    bin = File.read!(seg0)
    idx = b1_end - 1
    flipped = Bitwise.bxor(:binary.at(bin, idx), 0xFF)

    File.write!(
      seg0,
      binary_part(bin, 0, idx) <>
        <<flipped>> <> binary_part(bin, idx + 1, byte_size(bin) - idx - 1)
    )

    # Requesting b1 via BlockServing triggers Archive.read_block -> merkle failure ->
    # latches Store.Guard -> Node.Runtime stops the entire Node immediately!
    reader = State.reader(n.chain_state)
    b1_id = Archive.id_at(reader, 1)

    log =
      capture_log(fn ->
        spawn(fn ->
          try do
            BlockServing.get(n.block_serving, reader, b1_id, b1.header.hash, :witness)
          catch
            _, _ -> :ok
          end
        end)

        assert_receive {:DOWN, ^ref, :process, ^root, {:shutdown, :storage_fault}}, 5_000
      end)

    assert log =~ "STORAGE FAULT LATCHED"
    assert {:faulted, %{source: :archive}} = Guard.inspect_lock(chain_dir)

    # Reopening refuses without restore, and restore refuses without --force-from-snapshot.
    assert_raise Exnode.StorageError, ~r/--force-from-snapshot/, fn ->
      Snapshot.restore!(chain_dir)
    end

    # Even with --force-from-snapshot, the snapshot tip is height 1 (b2 was NOT committed
    # during fault-triggered terminate/2).
    {:ok, restored} = Snapshot.restore!(chain_dir, force_from_snapshot: true)
    assert restored.tip.height == 1
  end

  test "corrupt archive data detected by Scripthash index latches canonical fault and halts Exnode.Node",
       %{tmp_dir: dir} do
    chain_dir = Path.join(dir, "regtest")
    [b1, b2] = blocks(2)

    {root, _name, n} = start_unlinked_node(dir, index_scripthash: true)
    ref = Process.monitor(root)
    assert {:ok, :connected} = State.submit_block(n.chain_state, b1)
    :ok = Scripthash.sync_to(n.scripthash_index, b1.header.hash)

    # Corrupt outputs right after committing b2 so Scripthash.rows_for -> read_index_facts fails!
    # Suspend scripthash momentarily so b2 commits before corruption is injected.
    sh_pid = GenServer.whereis(n.scripthash_index)
    :sys.suspend(sh_pid)
    assert {:ok, :connected} = State.submit_block(n.chain_state, b2)
    corrupt_last_byte!(Path.join([chain_dir, "archive", "outputs", "00000.seg"]))

    log =
      capture_log(fn ->
        :sys.resume(sh_pid)
        assert_receive {:DOWN, ^ref, :process, ^root, {:shutdown, :storage_fault}}, 5_000
      end)

    assert log =~ "STORAGE FAULT LATCHED"
    assert {:faulted, %{source: :archive}} = Guard.inspect_lock(chain_dir)
  end

  test "corrupt segment read via RPC latches fault and immediately halts Exnode.Node", %{
    tmp_dir: dir
  } do
    chain_dir = Path.join(dir, "regtest")
    [b1] = blocks(1)

    {root, _name, n} = start_unlinked_node(dir)
    ref = Process.monitor(root)
    assert {:ok, :connected} = State.submit_block(n.chain_state, b1)

    corrupt_last_byte!(Path.join([chain_dir, "archive", "outputs", "00000.seg"]))

    ctx = %{
      chain_state: n.chain_state,
      headers: n.headers,
      mempool: n.mempool,
      tx_relay: n.tx_relay,
      connman: n.connman,
      params: @p,
      services: 0,
      user_agent: "/test/",
      prune_witness: false,
      clock: Exnode.Clock.new(),
      started_at: 0,
      filter_index: nil
    }

    log =
      capture_log(fn ->
        res = Exnode.RPC.Methods.call("getblock", [Hash.to_hex(b1.header.hash), 0], ctx)
        assert {:error, -32603, msg} = res
        assert msg =~ "fatal storage fault"
        assert_receive {:DOWN, ^ref, :process, ^root, {:shutdown, :storage_fault}}, 5_000
      end)

    assert log =~ "STORAGE FAULT LATCHED"
    assert {:faulted, %{source: :archive}} = Guard.inspect_lock(chain_dir)
  end

  test "canonical blockhash scan count mismatch raises StorageError and latches guard", %{
    tmp_dir: dir
  } do
    chain_dir = Path.join(dir, "regtest")
    [b1, b2] = blocks(2)

    %{name: name, n: n} = TestNode.start(dir)
    for b <- [b1, b2], do: assert({:ok, :connected} = State.submit_block(n.chain_state, b))
    :ok = stop_supervised(name)

    # Delete b2's :blockhash key directly to simulate a silently truncated scan.
    {:ok, kv} = KV.open(Path.join(chain_dir, "index"), mode: :canonical)
    :ok = KV.write(kv, [{:delete, :blockhash, b2.header.hash}], sync: true)
    KV.close(kv)

    g = Guard.acquire!(chain_dir, name: "canonical", require_clean_mark: false)
    {:ok, kv2} = KV.open(Path.join(chain_dir, "index"), mode: :canonical, guard: g)
    {:ok, stg} = KV.open(Path.join(chain_dir, "staging"), mode: :staging)
    {:ok, hs} = Headers.start_link(params: @p, kv: kv2, staging_kv: stg)

    capture_log(fn ->
      assert {:error, {%Exnode.StorageError{reason: {:blockhash_count_mismatch, 2, 3}}, _}} =
               GenServer.start(State,
                 params: @p,
                 headers: hs,
                 kv: kv2,
                 staging_kv: stg,
                 guard: g,
                 hot: Path.join(chain_dir, "archive")
               )
    end)

    assert Guard.faulted?(g)
    GenServer.stop(hs)
    KV.close(stg)
    KV.close(kv2)
    Guard.abandon(g)
  end

  test "corrupt key/hash mismatch in staging headers_cache raises StorageError and latches guard",
       %{
         tmp_dir: dir
       } do
    chain_dir = Path.join(dir, "regtest")
    [b1] = blocks(1)

    %{name: name, n: n} = TestNode.start(dir)
    # Persist b1's header only (not connected -> lives in staging/:headers_cache).
    assert {:ok, _} = Headers.process_headers(n.headers, [b1.header])
    :ok = stop_supervised(name)
    assert Guard.inspect_lock(chain_dir) == :clean

    # Tamper with staging/:headers_cache so the key does not match the 80-byte raw header hash.
    {:ok, stg} = KV.open(Path.join(chain_dir, "staging"), mode: :staging)
    wrong_key = <<0xAA::256>>
    raw = Exnode.Codec.Header.encode(b1.header)

    :ok =
      KV.write(stg, [{:put, :headers_cache, wrong_key, <<1::32, 0, raw::binary>>}], sync: true)

    :ok = KV.sync_wal!(stg)
    KV.close(stg)

    g = Guard.acquire!(chain_dir, name: "canonical", require_clean_mark: false)
    {:ok, kv2} = KV.open(Path.join(chain_dir, "index"), mode: :canonical, guard: g)
    {:ok, stg2} = KV.open(Path.join(chain_dir, "staging"), mode: :staging, guard: g)

    capture_log(fn ->
      assert {:error, {%Exnode.StorageError{reason: {:corrupt_staging_header_hash, _, _}}, _}} =
               GenServer.start(Headers, params: @p, kv: kv2, staging_kv: stg2)
    end)

    assert Guard.faulted?(g)
    KV.close(stg2)
    KV.close(kv2)
    Guard.abandon(g)
  end

  test "clean canonical store with dirty derived store refuses open, keeps canonical clean, and recovers via restore!",
       %{tmp_dir: dir} do
    chain_dir = Path.join(dir, "regtest")
    filters_dir = Path.join([chain_dir, "derived", "filters"])
    [b1, b2] = blocks(2)

    # 1. Start node with block_filter_index, sync 2 blocks, stop cleanly.
    %{name: name1, n: n1} = TestNode.start(dir, block_filter_index: true)
    for b <- [b1, b2], do: assert({:ok, :connected} = State.submit_block(n1.chain_state, b))
    :ok = Exnode.Index.BlockFilter.sync_to(n1.filter_index, b2.header.hash)
    :ok = stop_supervised(name1)

    assert Guard.inspect_lock(chain_dir) == :clean
    assert Guard.inspect_lock(filters_dir) == :clean

    assert {:ok, :primary, _, %{kind: :derived}} =
             Snapshot.latest_valid(Snapshot.snapshots_dir(filters_dir))

    # 2. Simulate crash between canonical unlock and derived unlock (derived dirty, canonical clean).
    gd = Guard.acquire!(filters_dir, name: "derived:filters", require_clean_mark: false)
    Guard.abandon(gd)
    assert {:dirty, _} = Guard.inspect_lock(filters_dir)

    # 3. Node refuses to open AND cleanly releases canonical lock (no collateral dirtying).
    capture_log(fn ->
      parent = self()

      spawn(fn ->
        Process.flag(:trap_exit, true)

        res =
          Exnode.Node.start_link(
            chain: :regtest,
            datadir: dir,
            name: TestNode.unique_name(),
            block_filter_index: true,
            connect: [{"127.0.0.1", 1}],
            chain_state_min_heap: 2_000_000,
            gc_probe: false
          )

        send(parent, {:start_res, res})
      end)

      assert_receive {:start_res,
                      {:error,
                       {%Exnode.StorageError{reason: {:dirty_store, "derived:filters", _, _}}, _}}},
                     5_000
    end)

    assert Guard.inspect_lock(chain_dir) == :clean

    # 4. Snapshot.restore! handles the dirty derived store (not :already_clean!).
    assert {:ok, %{canonical: :already_clean, derived: %{"filters" => {:restored, :primary}}}} =
             Snapshot.restore!(chain_dir)

    assert Guard.inspect_lock(filters_dir) == :clean

    # 5. Node reopens cleanly and filter index serves b2.
    %{name: name2, n: n2} = TestNode.start(dir, block_filter_index: true)
    :ok = Exnode.Index.BlockFilter.sync_to(n2.filter_index, b2.header.hash)
    :ok = stop_supervised(name2)
  end
end
