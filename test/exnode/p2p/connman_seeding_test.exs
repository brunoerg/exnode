defmodule Exnode.P2P.ConnmanSeedingTest do
  @moduledoc """
  Bootstrap (Core `ThreadDNSAddressSeed` / `ThreadOpenConnections`):
  DNS seeding is retried while the address book is empty, and 60 s after
  start the fixed seeds of every reachable network without addresses are
  added once, with the shared source `SetInternal("fixedseeds")` and
  `SeedsAssumedServiceFlags()`. Manual (`-connect`) mode seeds nothing.
  Plus the fixed-seed list parser.
  """
  use ExUnit.Case, async: true
  import Bitwise

  import Exnode.Test.Wait

  alias Exnode.ChainParams.SeedParser
  alias Exnode.Clock
  alias Exnode.P2P.{AddrMan, Connman, NetAddr}

  @v4 for i <- 1..5, do: %{net: :ipv4, addr: <<250, i * 7, 1, 1>>, port: 18_444}
  @v6 for i <- 1..3, do: %{net: :ipv6, addr: <<0x2A01::16, 0::96, i::16>>, port: 18_444}

  defp start(opts) do
    clock = Clock.new()
    # A fixed bucket key: seeds share one source group, so placement (and any
    # slot collision) must be deterministic for exact counts.
    {:ok, am} = AddrMan.start_link(key: :crypto.hash(:sha256, "seeding-test"))
    {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)

    params = %{
      Exnode.ChainParams.get(:regtest)
      | dns_seeds: Keyword.get(opts, :dns_seeds, ["seed.example."]),
        fixed_seeds: @v4 ++ @v6
    }

    node = %{
      params: params,
      addrman: am,
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
          clock: clock,
          seed_fun: Keyword.fetch!(opts, :seed_fun),
          max_outbound_full_relay: 0,
          max_block_relay: 0
        ] ++
          Keyword.take(opts, [:connect])
      )

    %{cm: cm, am: am, clock: clock}
  end

  # Runs one Connman cycle now and waits for it.
  defp tick(cm), do: Clock.tick(cm)

  defp advance(%{clock: c}, s), do: Clock.advance(c, s)

  # A DNS stub: answers the i-th round with `rounds[i]` (addresses to add, or :fail).
  defp dns(test, rounds) do
    agent = start_supervised!({Agent, fn -> rounds end}, id: make_ref())

    fn am, _seeds, _port ->
      round =
        Agent.get_and_update(agent, fn
          [r | rest] -> {r, rest}
          [] -> {:fail, []}
        end)

      send(test, {:dns_round, round})

      case round do
        :fail ->
          0

        addrs ->
          AddrMan.add(am, addrs, {:internal, "seed.example."})
          _ = AddrMan.size(am)
          length(addrs)
      end
    end
  end

  defp has?(am, a), do: AddrMan.find_entry(am, AddrMan.key(a)) != nil

  # The DNS round's process has exited and Connman has handled it.
  defp wait_dns_idle(cm), do: wait_until(fn -> :sys.get_state(cm).dns == :idle end)

  test "DNS down: retried, then after 60 s the fixed seeds are added with Core's source and services" do
    n = start(seed_fun: dns(self(), []))
    assert_receive {:dns_round, :fail}, 2_000
    wait_dns_idle(n.cm)
    # No retry before the backoff.
    last = :sys.get_state(n.cm).dns_last
    advance(n, 10)
    tick(n.cm)
    # That pass started no round (one would be running or have a newer start).
    assert %{dns: :idle, dns_last: ^last} = :sys.get_state(n.cm)
    refute_received {:dns_round, _}
    advance(n, 25)
    tick(n.cm)
    assert_receive {:dns_round, :fail}, 2_000
    wait_dns_idle(n.cm)
    assert AddrMan.size(n.am) == 0

    # 61 s after start: fixed seeds for both empty networks.
    advance(n, 30)
    tick(n.cm)
    assert AddrMan.size(n.am) == length(@v4) + length(@v6)

    # Core ConvertSeeds / SeedsAssumedServiceFlags, one shared internal source.
    t = :sys.get_state(n.am).t
    now = Clock.now(n.clock)

    for a <- @v4 ++ @v6 do
      e = Exnode.P2P.AddrMan.Table.get(t, AddrMan.key(a))
      assert e.source == NetAddr.internal("fixedseeds")
      assert e.services == (1 ||| 8 ||| 2048)
      assert e.time in (now - 14 * 86_400 - 5)..(now - 7 * 86_400)
    end

    # Once per run: emptying a network again later does not re-add them.
    assert :sys.get_state(n.cm).add_fixed_seeds == false
  end

  test "DNS fails, then succeeds on retry: no fixed seeds needed" do
    n = start(seed_fun: dns(self(), [:fail, dns_addrs()]))
    assert_receive {:dns_round, :fail}, 2_000
    wait_dns_idle(n.cm)
    advance(n, 31)
    tick(n.cm)
    assert_receive {:dns_round, [_ | _]}, 2_000
    wait_dns_idle(n.cm)
    assert AddrMan.size(n.am) == length(dns_addrs())

    advance(n, 60)
    tick(n.cm)
    tick(n.cm)
    refute Enum.any?(@v4 ++ @v6, &has?(n.am, &1))
    # The book is no longer empty: no further DNS rounds either.
    last = :sys.get_state(n.cm).dns_last
    advance(n, 60)
    tick(n.cm)
    # That pass started no round (one would be running or have a newer start).
    assert %{dns: :idle, dns_last: ^last} = :sys.get_state(n.cm)
    refute_received {:dns_round, _}
  end

  test "per reachable network (Core GetReachableEmptyNetworks): DNS gave only IPv4, so only IPv6 fixed seeds" do
    only_v4 = for a <- dns_addrs(), a.net == :ipv4, do: a
    n = start(seed_fun: dns(self(), [only_v4]))
    assert_receive {:dns_round, _}, 2_000
    wait_dns_idle(n.cm)
    advance(n, 61)
    tick(n.cm)
    assert Enum.all?(@v6, &has?(n.am, &1))
    refute Enum.any?(@v4, &has?(n.am, &1))
  end

  test "no DNS seeds configured: fixed seeds at once (Core: -dnsseed=0, no -seednode / -addnode)" do
    n = start(seed_fun: dns(self(), []), dns_seeds: [])
    tick(n.cm)
    assert AddrMan.size(n.am) == length(@v4) + length(@v6)
    refute_received {:dns_round, _}
  end

  test "manual (-connect) mode: no DNS and no fixed seeds, ever" do
    n = start(seed_fun: dns(self(), []), connect: [{"127.0.0.1", 1}])

    for _ <- 1..3,
        do:
          (
            advance(n, 100)
            tick(n.cm)
          )

    refute_received {:dns_round, _}
    assert AddrMan.size(n.am) == 0
  end

  defp dns_addrs do
    for(
      i <- 1..4,
      do: %{
        net: :ipv4,
        addr: <<251, i, 1, 1>>,
        port: 18_444,
        services: 1033,
        time: System.os_time(:second)
      }
    ) ++
      [
        %{
          net: :ipv6,
          addr: <<0x2A02::16, 0::96, 9::16>>,
          port: 18_444,
          services: 1033,
          time: System.os_time(:second)
        }
      ]
  end

  describe "SeedParser (contrib/seeds format)" do
    test "IPv4, [IPv6], comments and blank lines" do
      assert {:ok, %{net: :ipv4, addr: <<3, 11, 75, 34>>, port: 8333}} =
               SeedParser.parse_line("3.11.75.34:8333 # AS16509")

      assert {:ok, %{net: :ipv6, addr: <<1::128>>, port: 8333}} =
               SeedParser.parse_line("[::1]:8333")

      assert {:ok, %{net: :ipv6, port: 18_333}} =
               SeedParser.parse_line("  [2001:470:1f05:1a::2]:18333  ")

      assert :skip = SeedParser.parse_line("")
      assert :skip = SeedParser.parse_line("   # only a comment")
    end

    test "Tor, I2P and CJDNS are recognised and left out" do
      assert {:unsupported, :onion} =
               SeedParser.parse_line(
                 "2bqghnldu6mcug4pikzprwhtjjnsyederctvci6klcwzepnjd46ikjyd.onion:8333"
               )

      assert {:unsupported, :i2p} =
               SeedParser.parse_line(
                 "255fhcp6ajvftnyo7bwz3an3t4a4brhopm3bamyh2iu5r3gnr2rq.b32.i2p:0"
               )

      assert {:unsupported, :cjdns} =
               SeedParser.parse_line("[fc10:efa7:ca6:1548:f8c:6bb9:1cc4:63ae]:8333")
    end

    test "garbage lines are errors, not exceptions" do
      for bad <- [
            "not an address",
            "1.2.3.4",
            "1.2.3.4:99999",
            "1.2.3.4:x",
            "[::1:8333",
            "999.1.1.1:8333",
            "[::1]:",
            ":8333"
          ] do
        assert {:error, _} = SeedParser.parse_line(bad), bad
      end

      assert SeedParser.parse("1.2.3.4:8333\ngarbage\n# c\n\n[::2]:8333\n") |> length() == 2
    end

    test "the vendored mainnet list parses to Core's 512 IPv4 + 512 IPv6 seeds, as checked in" do
      path = Path.expand("../../../vendor/bitcoin/contrib/seeds/nodes_main.txt", __DIR__)
      parsed = path |> File.read!() |> SeedParser.parse()

      assert Enum.count(parsed, &(&1.net == :ipv4)) == 512 and
               Enum.count(parsed, &(&1.net == :ipv6)) == 512

      assert parsed == Exnode.ChainParams.FixedSeeds.get(:mainnet)
    end
  end
end
