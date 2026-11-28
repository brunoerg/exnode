defmodule Exnode.NodeSupervisionTest do
  @moduledoc """
  The node's supervision tree keeps a failure inside its subtree.
  A regtest node runs with the block filter index and one real peer (a
  manual connection to a socket the test drives, handshaked with fRelay so
  it registers with TxRelay). Each test kills one component and checks
  which processes were restarted (a new pid) and which were not.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Codec.Block
  alias Exnode.P2P.{AddrMan, Connman}
  alias Exnode.Test.BlockBuilder, as: BB

  @p Exnode.ChainParams.get(:regtest)
  @chain Path.expand("../fixtures/regtest/chain150.bin", __DIR__)

  setup %{tmp_dir: dir} do
    %{n: n, name: name} = TestNode.start(dir, block_filter_index: true)
    %{n: n, name: name}
  end

  # A manual peer to a listening socket we own; returns {peer pid, socket}
  # after the handshake (the peer has received our verack).
  defp connect(n) do
    {pid, sock} =
      FakePeer.connect_from(n,
        node: %{tx_relay: n.tx_relay, mempool: n.mempool},
        version: %{relay: true},
        after_handshake: [{:feefilter, 4321}]
      )

    wait_until(fn -> relay_knows?(n, pid) end)
    {pid, sock}
  end

  defp relay_peer(n, pid) do
    case GenServer.whereis(n.tx_relay) do
      nil -> nil
      r -> :sys.get_state(r).peers[pid]
    end
  catch
    :exit, _ -> nil
  end

  defp relay_knows?(n, pid), do: relay_peer(n, pid) != nil

  # The pids of every component that matters here.
  defp pids(n) do
    for k <- [
          :headers,
          :chain_state,
          :relay_sup,
          :mempool,
          :tx_relay,
          :p2p_sup,
          :book_sup,
          :addrman,
          :sync,
          :block_download,
          :high_bandwidth,
          :conns_sup,
          :peer_sup,
          :connman,
          :services_sup,
          :filter_index
        ],
        into: %{},
        do: {k, GenServer.whereis(Map.fetch!(n, k))}
  end

  defp kill(n, k) do
    pid = GenServer.whereis(Map.fetch!(n, k))
    ref = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^ref, _, _, _}
    wait_until(fn -> (p = GenServer.whereis(Map.fetch!(n, k))) && p != pid end)
  end

  # Which components have a new pid.
  defp restarted(before, n) do
    settle(n)
    now = pids(n)
    for {k, p} <- before, now[k] != p, into: MapSet.new(), do: k
  end

  # A supervisor restarts children inside the handler of the exit that
  # caused it, so a call it answers comes after that restart. Top down: the
  # node's supervisor (found as the Relay group's parent), then each group.
  defp settle(n) do
    root =
      case GenServer.whereis(n.relay_sup) do
        nil -> nil
        pid -> pid |> Process.info(:dictionary) |> elem(1) |> Keyword.get(:"$ancestors") |> hd()
      end

    for s <- [root, n.relay_sup, n.p2p_sup, n.book_sup, n.conns_sup, n.services_sup],
        pid = s && GenServer.whereis(s) do
      try do
        Supervisor.count_children(pid)
      catch
        :exit, _ -> :ok
      end
    end
  end

  test "the tree: chain core, then the Relay, P2P and Services subtrees", %{n: n, name: name} do
    # which_children lists the newest child first.
    ids = for {id, _, _, _} <- Supervisor.which_children(name), do: id

    assert Enum.reverse(ids) == [
             # Stops last: owns Handles ETS and closes the store after everything using it.
             Exnode.Node.Runtime,
             Exnode.Chain.Headers,
             # The shared script executor, upstream of the chain state.
             Exnode.Validation.ScriptExec,
             Exnode.Chain.State,
             n.relay_sup,
             n.p2p_sup,
             n.services_sup
           ]

    p2p = for {id, _, _, _} <- Supervisor.which_children(n.p2p_sup), do: id
    assert List.last(p2p) == n.book_sup
    assert n.conns_sup in p2p

    assert {:ok, %{restart: :temporary}} =
             {:ok, Exnode.Node.child_spec(name: name, chain: :regtest)}
  end

  test "a Mempool crash restarts only Mempool and TxRelay; the peer stays and registers again",
       %{n: n} do
    {peer, _sock} = connect(n)
    # The feefilter follows the handshake: registered first, then applied.
    wait_until(fn -> relay_peer(n, peer).feefilter == 4321 end)
    before = pids(n)

    kill(n, :mempool)
    wait_until(fn -> relay_knows?(n, peer) end)

    assert restarted(before, n) == MapSet.new([:mempool, :tx_relay])
    assert Process.alive?(peer)
    # The resent registration carries the peer's feefilter too.
    assert relay_peer(n, peer).feefilter == 4321
  end

  test "a stopped node has closed its store: it reopens at once", %{tmp_dir: dir, name: name} do
    :ok = stop_supervised(name)
    assert Exnode.Store.Guard.inspect_lock(Path.join(dir, "regtest")) == :clean

    {:ok, kv} =
      Exnode.Store.KV.open(Path.join([dir, "regtest", "index"]),
        mode: :canonical,
        lock_wait_ms: 0
      )

    Exnode.Store.KV.close(kv)
  end

  # Regression: the owner closed the store only on shutdown;
  # after the root was killed, the index handles kept in persistent_term
  # held the database and its LOCK, and a new node on the datadir failed.
  test "a killed node has closed its store too: it reopens at once (and leaves flush.lock dirty)",
       %{
         tmp_dir: dir,
         name: name
       } do
    root = GenServer.whereis(name)
    ref = Process.monitor(root)
    Process.exit(root, :kill)
    assert_receive {:DOWN, ^ref, :process, _, :killed}
    wait_until(fn -> match?({:ok, _}, try_open(dir)) end, 2_000)
    assert {:dirty, _} = Exnode.Store.Guard.inspect_lock(Path.join(dir, "regtest"))
  end

  defp try_open(dir) do
    case Exnode.Store.KV.open(Path.join([dir, "regtest", "index"]),
           mode: :canonical,
           lock_wait_ms: 0
         ) do
      {:ok, kv} -> Exnode.Store.KV.close(kv) && {:ok, kv}
      other -> other
    end
  end

  test "a TxRelay crash restarts only TxRelay; the peer registers again", %{n: n} do
    {peer, _sock} = connect(n)
    before = pids(n)

    kill(n, :tx_relay)
    wait_until(fn -> relay_knows?(n, peer) end)

    assert restarted(before, n) == MapSet.new([:tx_relay])
    assert Process.alive?(peer)
  end

  test "Connman and the peers restart together; nothing outside P2P restarts", %{n: n} do
    {peer, _sock} = connect(n)
    ref = Process.monitor(peer)
    before = pids(n)

    kill(n, :connman)
    assert_receive {:DOWN, ^ref, _, _, _}, 5000

    assert restarted(before, n) == MapSet.new([:connman, :peer_sup])
  end

  # Connman may be mid-call into the killed supervisor: its crash is logged.
  @tag :capture_log
  test "a peer supervisor crash restarts Connman too", %{n: n} do
    before = pids(n)
    kill(n, :peer_sup)
    assert restarted(before, n) == MapSet.new([:connman, :peer_sup])
  end

  test "an AddrMan crash restarts only AddrMan; Connman and the peer stay", %{n: n, name: name} do
    {peer, _sock} = connect(n)
    before = pids(n)
    # Held in the restart window (its supervisor suspended): Connman and the
    # peers run a pass without it, and tolerate the absence.
    book_sup = GenServer.whereis(n.book_sup)
    :sys.suspend(book_sup)
    am = GenServer.whereis(n.addrman)
    ref = Process.monitor(am)
    Process.exit(am, :kill)
    assert_receive {:DOWN, ^ref, _, _, _}
    :ok = Exnode.Node.tick(name)
    :sys.resume(book_sup)
    wait_until(fn -> (p = GenServer.whereis(n.addrman)) && p != am end)
    assert restarted(before, n) == MapSet.new([:addrman])
    assert Process.alive?(peer)
  end

  test "an AddrMan subtree past its intensity restarts the P2P subtree, not Relay or the chain",
       %{n: n} do
    before = pids(n)
    for _ <- 1..11, do: kill(n, :addrman)

    assert restarted(before, n) ==
             MapSet.new([
               :book_sup,
               :addrman,
               :sync,
               :block_download,
               :high_bandwidth,
               :conns_sup,
               :peer_sup,
               :connman
             ])
  end

  test "an index crash restarts only the index", %{n: n} do
    {peer, _sock} = connect(n)
    before = pids(n)
    kill(n, :filter_index)
    assert restarted(before, n) == MapSet.new([:filter_index])
    assert Process.alive?(peer)
  end

  test "a ChainState crash restarts everything after it, not Headers", %{n: n} do
    before = pids(n)
    kill(n, :chain_state)
    got = restarted(before, n)
    refute :headers in got

    for k <- [:relay_sup, :mempool, :tx_relay, :p2p_sup, :connman, :services_sup, :filter_index],
        do: assert(k in got, "#{k} not restarted")
  end

  test "a subtree past its restart intensity is restarted once by the root; the chain is untouched",
       %{n: n} do
    before = pids(n)
    # 11 index crashes in well under 60 s: the Services subtree gives up.
    for _ <- 1..11, do: kill(n, :filter_index)
    got = restarted(before, n)
    assert :services_sup in got
    refute :chain_state in got
    refute :mempool in got
    refute :connman in got
  end

  test "Mempool notifications to a listener that is not running are dropped, not a crash",
       %{n: n} do
    mp = GenServer.whereis(n.mempool)

    :sys.replace_state(mp, fn st -> %{st | listeners: [Module.concat(__MODULE__, NotRunning)]} end)

    for raw <- Enum.take(BB.read_chain(@chain), 3) do
      {:ok, b} = Block.decode_exact(raw)
      {:ok, :connected} = State.submit_block(n.chain_state, b)
    end

    # The block events reach the mempool, which notifies its listeners.
    wait_until(fn -> State.view_tip(State.view(n.chain_state)).height == 3 end)
    _ = Exnode.Mempool.size(n.mempool)
    assert GenServer.whereis(n.mempool) == mp
  end

  describe "Connman without a running AddrMan" do
    # Connman alone, its address book a name nothing is registered under
    # (as while AddrMan restarts), DNS seeding observable through seed_fun.
    defp lone_connman(book, opts) do
      test = self()
      {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)

      node = %{
        params: %{@p | dns_seeds: ["seed.example."], fixed_seeds: []},
        addrman: book,
        services: 9,
        nonce: 1,
        user_agent: "/t/",
        headers: nil,
        sync: nil
      }

      {:ok, cm} =
        Connman.start_link(
          [
            node: node,
            peer_sup: sup,
            seed_fun: fn _am, _seeds, _port -> send(test, :dns_seeding) end
          ] ++ opts
        )

      cm
    end

    defp tick(cm) do
      send(cm, :tick)
      _ = Connman.peers(cm)
    end

    test "absent: no crash, no dial, no seeding; seeding starts once an empty book is back" do
      book = Module.concat(__MODULE__, "Book#{System.unique_integer([:positive])}")
      cm = lone_connman(book, max_outbound_full_relay: 2, max_block_relay: 0)
      ref = Process.monitor(cm)

      for _ <- 1..5, do: tick(cm)
      refute_received :dns_seeding
      refute_received {:DOWN, ^ref, _, _, _}
      assert Connman.peers(cm) == %{}

      {:ok, _} = AddrMan.start_link(name: book)
      tick(cm)
      assert_receive :dns_seeding, 2_000
      GenServer.stop(cm)
    end

    @tag timeout: 30_000
    test "busy (a call times out): no crash, Connman carries on" do
      book = Module.concat(__MODULE__, "Busy#{System.unique_integer([:positive])}")
      {:ok, am} = AddrMan.start_link(name: book)
      # A non-empty book: Connman then asks its size on every tick.
      AddrMan.add(
        am,
        [
          %{
            net: :ipv4,
            addr: <<8, 8, 8, 8>>,
            port: 18_444,
            services: 9,
            time: System.os_time(:second)
          }
        ],
        :seed
      )

      assert AddrMan.size(am) == 1
      cm = lone_connman(book, max_outbound_full_relay: 0, max_block_relay: 0)
      _ = Connman.peers(cm)
      refute_received :dns_seeding
      :sys.suspend(am)
      ref = Process.monitor(cm)

      # This tick's size call times out after 5 s; no seeding meanwhile.
      send(cm, :tick)
      Process.sleep(5_500)
      :sys.resume(am)
      # Any late reply is discarded (call aliases); Connman still serves calls.
      _ = Connman.peers(cm)
      refute_received {:DOWN, ^ref, _, _, _}
      assert Process.alive?(cm)
      GenServer.stop(cm)
    end
  end
end
