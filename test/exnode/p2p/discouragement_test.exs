defmodule Exnode.P2P.DiscouragementTest do
  @moduledoc """
  Discouragement keyed by IP only (Core `DiscourageAddress`),
  expiring after 24 h (Core `DEFAULT_MISBEHAVING_BANTIME`), bounded, and kept
  across restarts in `discouraged.dat`, written from the tick at most once a
  minute and at shutdown.

  Connman runs in manual mode with no targets (it dials nothing). Peers are
  stand-in processes registered as inbound, then exited with
  `{:shutdown, {:misbehaving, _}}`, as a real `Peer` does. Connman runs on
  a mock `Exnode.Clock` (its monotonic side times the flush interval, its
  unix time the TTL); `Exnode.Clock.tick/2` runs its periodic pass.
  """
  use ExUnit.Case, async: false
  import Exnode.Test.Wait

  alias Exnode.Clock
  alias Exnode.P2P.{Connman, Discouraged, PeerFile}

  @moduletag :tmp_dir
  @p Exnode.ChainParams.get(:regtest)
  @day 24 * 3600

  defp clocks do
    c = Clock.new()
    Clock.set(c, 1_800_000_000)
    c
  end

  defp advance(c, s), do: Clock.advance(c, s)

  defp node_map(addrman \\ nil),
    do: %{
      params: @p,
      addrman: addrman,
      services: 9,
      nonce: 1,
      user_agent: "/t/",
      headers: nil,
      sync: nil
    }

  # max_connections 12 leaves one inbound slot (11 are outbound).
  defp start_cm(dir, c, opts \\ []) do
    {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)

    {:ok, cm} =
      Connman.start_link(
        [
          node: Keyword.get(opts, :node, node_map()),
          peer_sup: sup,
          connect: Keyword.get(opts, :connect, []),
          magic: @p.magic,
          max_connections: 12,
          discouraged_path: Path.join(dir, "discouraged.dat"),
          clock: c
        ] ++ Keyword.drop(opts, [:node, :connect])
      )

    cm
  end

  # An inbound peer from `target` that misbehaves and exits.
  defp misbehave(cm, target) do
    pid = spawn(fn -> receive do: (:go -> exit({:shutdown, {:misbehaving, "test"}})) end)
    Connman.register_inbound(cm, pid, target)
    _ = Connman.peers(cm)
    ref = Process.monitor(pid)
    send(pid, :go)
    assert_receive {:DOWN, ^ref, _, _, _}
    # The :DOWN reaches Connman too; a call after it is processed in order.
    _ = Connman.peers(cm)
  end

  defp idle_inbound(cm, target) do
    pid = spawn(fn -> Process.sleep(:infinity) end)
    Connman.register_inbound(cm, pid, target)
    {pid, Connman.peers(cm)[pid]}
  end

  defp file_term(dir) do
    case PeerFile.read(Path.join(dir, "discouraged.dat"), @p.magic) do
      {:ok, t} -> t
      other -> other
    end
  end

  test "port rotation: the same IP from a new source port is still discouraged", %{tmp_dir: dir} do
    c = clocks()
    cm = start_cm(dir, c)
    misbehave(cm, {"1.2.3.4", 50_000})

    # Refused when it would take the last inbound slot; another IP is accepted.
    refute Connman.accept_inbound?(cm, {"1.2.3.4", 50_001})
    assert Connman.accept_inbound?(cm, {"5.6.7.8", 50_001})
    # The IPv4-mapped IPv6 form of the same address is the same key.
    refute Connman.accept_inbound?(cm, {"::ffff:1.2.3.4", 50_002})
    assert Connman.discouraged?(cm, {"1.2.3.4", 1})

    # Accepted while slots are free (max_connections raised), marked prefer_evict.
    {_, peer} = idle_inbound(cm, {"1.2.3.4", 50_003})
    assert peer.prefer_evict
    {_, other} = idle_inbound(cm, {"5.6.7.8", 50_004})
    refute other.prefer_evict
  end

  test "a manual peer that misbehaves is not discouraged (Core: manual peers are not punished)",
       %{tmp_dir: dir} do
    cm = start_cm(dir, clocks())
    pid = spawn(fn -> receive do: (:go -> exit({:shutdown, {:misbehaving, "test"}})) end)

    # The function runs inside Connman, so the monitor is Connman's own.
    :sys.replace_state(cm, fn st ->
      Process.monitor(pid)

      put_in(st.peers[pid], %{
        type: :manual,
        target: {"9.9.9.9", 8333},
        group: nil,
        ready: false,
        v2: false,
        evicting: false,
        prefer_evict: false,
        stats: %{},
        services: nil
      })
    end)

    send(pid, :go)
    # Connman has handled the exit once the peer is gone from its table.
    wait_until(fn -> not Map.has_key?(Connman.peers(cm), pid) end)
    refute Connman.discouraged?(cm, {"9.9.9.9", 1})
    misbehave(cm, {"9.9.9.10", 1})
    assert Connman.discouraged?(cm, {"9.9.9.10", 1})
  end

  test "a local peer that misbehaves is disconnected but not discouraged (Core IsLocal)",
       %{tmp_dir: dir} do
    cm = start_cm(dir, clocks())

    for t <- [
          {"127.0.0.1", 50_000},
          {"127.8.9.10", 1},
          {"0.0.0.1", 1},
          {"::1", 1},
          {"::ffff:127.0.0.1", 1}
        ] do
      misbehave(cm, t)
      refute Connman.discouraged?(cm, t)
      assert Connman.accept_inbound?(cm, t)
    end

    # A non-local address next to loopback is still discouraged.
    misbehave(cm, {"128.0.0.1", 1})
    assert Connman.discouraged?(cm, {"128.0.0.1", 1})
    GenServer.stop(cm)
    assert file_term(dir) |> Map.keys() == [{:ipv4, <<128, 0, 0, 1>>}]
  end

  test "expiry: absent after 24 h, and pruned from the table and the file", %{tmp_dir: dir} do
    c = clocks()
    cm = start_cm(dir, c)
    misbehave(cm, {"1.2.3.4", 50_000})
    advance(c, @day - 1)
    assert Connman.discouraged?(cm, {"1.2.3.4", 2})
    advance(c, 1)
    refute Connman.discouraged?(cm, {"1.2.3.4", 2})
    assert Connman.accept_inbound?(cm, {"1.2.3.4", 50_001})

    # The tick (past the flush interval) prunes it.
    :ok = Clock.tick(cm)
    assert Discouraged.size(:sys.get_state(cm).discouraged) == 0
  end

  test "persistence: kept across a restart with its remaining TTL; written only at flush points",
       %{tmp_dir: dir} do
    c = clocks()
    cm = start_cm(dir, c)
    misbehave(cm, {"1.2.3.4", 50_000})

    # Not written on the insert, nor by a tick before 60 s.
    advance(c, 30)
    :ok = Clock.tick(cm)
    assert file_term(dir) == :missing
    advance(c, 30)
    :ok = Clock.tick(cm)
    assert %{{:ipv4, <<1, 2, 3, 4>>} => _} = file_term(dir)

    # A later insert waits for the next flush point...
    misbehave(cm, {"5.6.7.8", 1})
    advance(c, 30)
    :ok = Clock.tick(cm)
    refute Map.has_key?(file_term(dir), {:ipv4, <<5, 6, 7, 8>>})
    # ...or for shutdown.
    GenServer.stop(cm)
    assert map_size(file_term(dir)) == 2

    # A fresh Connman loads both; they expire 24 h after their insertion.
    cm = start_cm(dir, c)
    assert Connman.discouraged?(cm, {"1.2.3.4", 9})
    refute Connman.accept_inbound?(cm, {"1.2.3.4", 9})
    advance(c, @day - 90)
    refute Connman.discouraged?(cm, {"1.2.3.4", 9})
    assert Connman.discouraged?(cm, {"5.6.7.8", 9})
    GenServer.stop(cm)

    # Expired entries are dropped on load.
    advance(c, @day)
    cm = start_cm(dir, c)
    assert Discouraged.size(:sys.get_state(cm).discouraged) == 0
    GenServer.stop(cm)
  end

  test "a corrupt discouraged.dat gives an empty table, no crash", %{tmp_dir: dir} do
    File.write!(
      Path.join(dir, "discouraged.dat"),
      "exnode-peers garbage that is long enough to have a checksum"
    )

    cm = start_cm(dir, clocks())
    assert Discouraged.size(:sys.get_state(cm).discouraged) == 0
    refute Connman.discouraged?(cm, {"1.2.3.4", 1})
  end

  # A stand-in address book serving a fixed list (as in outbound_selection_test).
  defmodule FakeBook do
    use GenServer
    def init({cands, test}), do: {:ok, %{cands: cands, test: test}}
    def handle_call(:size, _f, st), do: {:reply, 1, st}
    def handle_call({:size, _net}, _f, st), do: {:reply, 1, st}
    def handle_call(:select_tried_collision, _f, st), do: {:reply, nil, st}

    def handle_call({:select, _}, _f, %{cands: [c | rest]} = st),
      do: {:reply, c, %{st | cands: rest}}

    def handle_call({:select, _}, _f, st), do: {:reply, nil, st}

    def handle_cast({:attempt, key, _cf}, st) do
      send(st.test, {:attempt, key})
      {:noreply, st}
    end

    def handle_cast(_, st), do: {:noreply, st}
  end

  defp cand(a, port) do
    %{
      net: :ipv4,
      addr: a,
      port: port,
      key: {:ipv4, a, port},
      services: 9,
      last_try: 0,
      attempts: 0,
      in_tried: false
    }
  end

  test "outbound: an address book entry whose IP is discouraged is never dialled, on any port",
       %{tmp_dir: dir} do
    c = clocks()
    now = Clock.now(c)
    bad = <<250, 0, 7, 1>>
    :ok = PeerFile.write(Path.join(dir, "discouraged.dat"), @p.magic, %{{:ipv4, bad} => now})
    good = <<250, 0, 8, 1>>

    {:ok, book} =
      GenServer.start_link(
        FakeBook,
        {[cand(bad, 18_444), cand(bad, 18_445), cand(good, 18_444)], self()}
      )

    cm =
      start_cm(dir, c,
        node: node_map(book),
        connect: nil,
        max_outbound_full_relay: 1,
        max_block_relay: 0
      )

    assert_receive {:attempt, {:ipv4, ^good, 18_444}}, 3_000
    refute_received {:attempt, {:ipv4, ^bad, _}}
    GenServer.stop(cm)
  end

  describe "Discouraged table" do
    test "key/1: IP only, mapped IPv4 folded, DNS names exempt" do
      assert Discouraged.key({"1.2.3.4", 1}) == Discouraged.key({"1.2.3.4", 2})
      assert Discouraged.key({"1.2.3.4", 1}) == {:ipv4, <<1, 2, 3, 4>>}
      assert Discouraged.key({"::ffff:1.2.3.4", 1}) == {:ipv4, <<1, 2, 3, 4>>}
      assert Discouraged.key({:ipv4, <<1, 2, 3, 4>>, 8333}) == {:ipv4, <<1, 2, 3, 4>>}

      assert Discouraged.key(%{net: :ipv6, addr: <<0x2001::16, 0::112>>}) ==
               {:ipv6, <<0x2001::16, 0::112>>}

      assert Discouraged.key({"seed.example.org", 8333}) == nil
      refute Discouraged.member?(Discouraged.put(Discouraged.new(), nil, 0), nil, 0)
    end

    test "local?/1: 127/8, 0/8 and ::1 only" do
      for h <- ["127.0.0.1", "127.255.255.255", "0.0.0.0", "0.1.2.3", "::1", "::ffff:127.0.0.1"],
          do: assert(Discouraged.local?(Discouraged.key({h, 1})), h)

      for h <- [
            "126.255.255.255",
            "128.0.0.0",
            "1.0.0.0",
            "10.0.0.1",
            "192.168.1.1",
            "::",
            "::2",
            "fe80::1"
          ],
          do: refute(Discouraged.local?(Discouraged.key({h, 1})), h)

      refute Discouraged.local?(nil)
    end

    test "cap: inserting past it evicts the oldest" do
      t =
        Enum.reduce(1..11, Discouraged.new(cap: 10), fn i, t ->
          Discouraged.put(t, {:ipv4, <<10, 0, 0, i>>}, 1000 + i)
        end)

      assert Discouraged.size(t) <= 10
      refute Discouraged.member?(t, {:ipv4, <<10, 0, 0, 1>>}, 1012)
      assert Discouraged.member?(t, {:ipv4, <<10, 0, 0, 11>>}, 1012)
      assert Discouraged.member?(t, {:ipv4, <<10, 0, 0, 10>>}, 1012)
    end

    test "at the cap, expired entries are pruned before anything live is evicted" do
      t =
        Enum.reduce(1..10, Discouraged.new(cap: 10), fn i, t ->
          Discouraged.put(t, {:ipv4, <<10, 0, 0, i>>}, i)
        end)

      # Entry 1 is the only one expired at this time.
      now = 1 + Discouraged.ttl()
      t = Discouraged.put(t, {:ipv4, <<10, 0, 1, 0>>}, now)
      assert Discouraged.size(t) == 10
      for i <- 2..10, do: assert(Discouraged.member?(t, {:ipv4, <<10, 0, 0, i>>}, now))
    end

    test "from_term drops malformed and expired entries" do
      term = %{
        {:ipv4, <<1, 2, 3, 4>>} => 100,
        {:ipv4, <<1, 2, 3>>} => 100,
        {:dns, "x"} => 100,
        {:ipv6, <<0::128>>} => :x,
        {:ipv4, <<5, 6, 7, 8>>} => 100 - Discouraged.ttl()
      }

      t = Discouraged.from_term(term, 100)
      assert Discouraged.to_term(t) == %{{:ipv4, <<1, 2, 3, 4>>} => 100}
      assert Discouraged.size(Discouraged.from_term(:not_a_map, 100)) == 0
    end
  end
end
