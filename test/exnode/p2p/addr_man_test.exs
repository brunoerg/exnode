defmodule Exnode.P2P.AddrManTest do
  @moduledoc """
  The address book process: services from `version`, persistence in
  peers.dat across restarts (with corrupt and foreign files refused), the
  cached `getaddr` answer, unroutable addresses.
  """
  use ExUnit.Case, async: true

  alias Exnode.P2P.{AddrMan, PeerFile}

  @moduletag :tmp_dir
  @magic <<0xFA, 0xBF, 0xB5, 0xDA>>

  defp addr(a, b, c \\ 1),
    do: %{
      net: :ipv4,
      addr: <<a, b, c, 1>>,
      port: 8333,
      services: 1033,
      time: System.os_time(:second)
    }

  test "SetServices: a version's services replace the gossiped ones (so NODE_P2P_V2 is seen)" do
    {:ok, am} = AddrMan.start_link([])
    AddrMan.add(am, [addr(8, 8)], :seed)
    %{key: k, services: 1033} = AddrMan.select(am)
    AddrMan.set_services(am, k, 1033 + 2048)
    assert %{services: 3081} = AddrMan.select(am)
  end

  test "DNS seed results: SeedsAssumedServiceFlags (2057), default port, 3 to 7 days old" do
    now = 1_800_000_000
    import Bitwise

    for ip <- [{1, 2, 3, 4}, {0x2A02, 0, 0, 0, 0, 0, 0, 9}], _ <- 1..50 do
      a = AddrMan.dns_seed_addr(ip, 48_333, now)
      # NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2, as Core and the fixed seeds.
      assert a.services == 2057
      assert a.services == (1 ||| 8 ||| 2048)
      assert a.services == AddrMan.seeds_assumed_services()
      assert a.port == 48_333
      assert a.time >= now - 7 * 86_400 and a.time < now - 3 * 86_400
    end

    assert %{net: :ipv4, addr: <<1, 2, 3, 4>>} = AddrMan.dns_seed_addr({1, 2, 3, 4}, 1, now)

    assert %{net: :ipv6, addr: <<0x2A02::16, 0::96, 9::16>>} =
             AddrMan.dns_seed_addr({0x2A02, 0, 0, 0, 0, 0, 0, 9}, 1, now)
  end

  test "non-routable addresses are ignored" do
    {:ok, am} = AddrMan.start_link([])

    AddrMan.add(
      am,
      [
        %{net: :ipv4, addr: <<192, 168, 0, 1>>, port: 8333},
        %{net: :ipv4, addr: <<10, 0, 0, 1>>, port: 8333}
      ],
      :seed
    )

    assert AddrMan.size(am) == 0
  end

  test "peers.dat survives a restart with tried and new entries in place", %{tmp_dir: dir} do
    path = Path.join(dir, "peers.dat")
    {:ok, am} = AddrMan.start_link(path: path, magic: @magic)
    src = {:ipv4, <<9, 9, 9, 9>>, 8333}
    addrs = for a <- 1..40, b <- [1, 2], do: addr(a, b)
    AddrMan.add(am, addrs, src, 2 * 3600)
    for a <- Enum.take(addrs, 10), do: AddrMan.good(am, AddrMan.key(a))
    n = AddrMan.size(am)
    assert n > 50

    before =
      for a <- addrs, into: %{}, do: {AddrMan.key(a), AddrMan.find_entry(am, AddrMan.key(a))}

    GenServer.stop(am)
    assert File.exists?(path)

    {:ok, am2} = AddrMan.start_link(path: path, magic: @magic)
    assert AddrMan.size(am2) == n
    for {k, e} <- before, do: assert(AddrMan.find_entry(am2, k) == e)
    assert Enum.count(before, fn {_, e} -> e && e.tried end) == 10
  end

  test "a corrupt or foreign peers.dat gives an empty book, not a crash", %{tmp_dir: dir} do
    path = Path.join(dir, "peers.dat")
    :ok = PeerFile.write(path, @magic, %{key: :crypto.strong_rand_bytes(32), entries: []})
    {:ok, bin} = File.read(path)
    <<head::binary-size(20), b, rest::binary>> = bin
    File.write!(path, head <> <<Bitwise.bxor(b, 1)>> <> rest)
    assert PeerFile.read(path, @magic) == {:error, :checksum}
    {:ok, am} = AddrMan.start_link(path: path, magic: @magic)
    assert AddrMan.size(am) == 0
    GenServer.stop(am)

    :ok = PeerFile.write(path, <<1, 2, 3, 4>>, %{key: :crypto.strong_rand_bytes(32), entries: []})
    assert PeerFile.read(path, @magic) == {:error, :wrong_network}
  end

  test "getaddr: at most 23% of the book, and the same answer until the cache expires" do
    clock = :atomics.new(1, [])
    :atomics.put(clock, 1, 1_800_000_000)
    {:ok, am} = AddrMan.start_link(clock: fn -> :atomics.get(clock, 1) end)
    addrs = for a <- 1..200, b <- [1, 2, 3], do: %{addr(a, b) | time: 1_800_000_000}
    AddrMan.add(am, addrs, {:ipv4, <<9, 9, 9, 9>>, 8333})
    n = AddrMan.size(am)
    first = AddrMan.addr_response(am, :ipv4)
    assert length(first) == div(23 * n, 100)
    assert AddrMan.addr_response(am, :ipv4) == first
    # Another network gets its own draw.
    assert AddrMan.addr_response(am, :ipv6) != first
    # 27 hours later (past 21 h + up to 6 h), a fresh answer.
    :atomics.add(clock, 1, 27 * 3600 + 1)
    assert AddrMan.addr_response(am, :ipv4) != first
  end

  # Regression: decoding is `:safe`, and in a fresh VM (node start-up) the
  # entry field atoms did not exist yet, so a restart discarded peers.dat.
  test "peers.dat decodes in a fresh VM", %{tmp_dir: dir} do
    path = Path.join(dir, "peers.dat")
    {:ok, am} = AddrMan.start_link(path: path, magic: @magic)
    AddrMan.add(am, for(a <- 1..20, do: addr(a, 7)), {:ipv4, <<9, 9, 9, 9>>, 8333})
    # (Fewer than 20 if two land on one new-table slot with this random key.)
    n = AddrMan.size(am)
    assert n > 0
    GenServer.stop(am)

    code =
      ~s|{:ok, t} = Exnode.P2P.PeerFile.read("#{path}", #{inspect(@magic)}); IO.puts("ENTRIES=" <> to_string(length(t.entries)))|

    {out, 0} =
      System.cmd("mix", ["run", "--no-start", "--no-compile", "-e", code],
        env: [{"MIX_ENV", "test"}],
        stderr_to_stdout: true
      )

    assert out =~ "ENTRIES=#{n}"
  end
end
