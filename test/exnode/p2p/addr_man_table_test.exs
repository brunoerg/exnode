defmodule Exnode.P2P.AddrMan.TableTest do
  @moduledoc """
  `AddrMan.Table` against Core v32.1 `src/test/addrman_tests.cpp`. The
  deterministic cases (bucket numbers, which address collides with which)
  depend only on the bucket hashes and the key, so they are ported with
  Core's exact expectations. Core's deterministic AddrMan uses the key
  `uint256{1}`; the bucket tests use `nKey1 = SHA256d(int32 1)`.
  """
  use ExUnit.Case, async: true

  alias Exnode.P2P.AddrMan.Table
  alias Exnode.P2P.NetAddr

  @det_key <<1, 0::248>>
  @now 1_800_000_000

  defp ip(s) do
    {:ok, t} = :inet.parse_address(to_charlist(s))

    case t do
      {a, b, c, d} -> %{net: :ipv4, addr: <<a, b, c, d>>}
      t -> %{net: :ipv6, addr: for(x <- Tuple.to_list(t), into: <<>>, do: <<x::16>>)}
    end
  end

  defp svc(s, port \\ 0), do: Map.put(ip(s), :port, port)

  # CAddress(addr, NODE_NONE): time TIME_INIT unless given.
  defp caddr(s, port \\ 0, time \\ nil),
    do: svc(s, port) |> Map.put(:time, time || Table.time_init()) |> Map.put(:services, 0)

  defp add(t, a, src, now \\ @now), do: Table.add(t, [a], src, 0, now)
  defp good(t, a, now \\ @now), do: Table.good(t, Table.key(a), true, now)

  defp hostport(nil), do: "[::]:0"

  defp hostport(%{addr: %{net: :ipv4, addr: <<a, b, c, d>>, port: p}}),
    do: "#{a}.#{b}.#{c}.#{d}:#{p}"

  describe "bucket placement (caddrinfo_get_*_bucket_legacy)" do
    setup do
      %{
        k1: Exnode.Crypto.Hash.hash256(<<1::little-32>>),
        k2: Exnode.Crypto.Hash.hash256(<<2::little-32>>)
      }
    end

    test "tried bucket", %{k1: k1, k2: k2} do
      a1 = svc("250.1.1.1", 8333)
      assert Table.tried_bucket(k1, a1) == 40
      assert Table.tried_bucket(k1, a1) != Table.tried_bucket(k2, a1)
      assert Table.tried_bucket(k1, a1) != Table.tried_bucket(k1, svc("250.1.1.1", 9999))
      assert MapSet.size(MapSet.new(0..254, &Table.tried_bucket(k1, svc("250.1.1.#{&1}")))) == 8
      assert MapSet.size(MapSet.new(0..254, &Table.tried_bucket(k1, svc("250.#{&1}.1.1")))) == 160
    end

    test "new bucket", %{k1: k1, k2: k2} do
      a1 = svc("250.1.2.1", 8333)
      src = ip("250.1.2.1")
      assert Table.new_bucket(k1, a1, src) == 786
      assert Table.new_bucket(k1, a1, src) != Table.new_bucket(k2, a1, src)
      assert Table.new_bucket(k1, a1, src) == Table.new_bucket(k1, svc("250.1.2.1", 9999), src)
      # Same group as the source: one bucket.
      assert MapSet.size(
               MapSet.new(
                 0..254,
                 &Table.new_bucket(k1, svc("250.1.1.#{&1}"), ip("250.1.1.#{&1}"))
               )
             ) == 1

      # Same source group: at most 64 buckets.
      same_src =
        for j <- 0..(4 * 255 - 1),
            do:
              Table.new_bucket(
                k1,
                svc("#{250 + div(j, 255)}.#{rem(j, 256)}.1.1"),
                ip("251.4.1.1")
              )

      assert MapSet.size(MapSet.new(same_src)) <= 64
      # Different source groups: more than 64.
      assert MapSet.size(
               MapSet.new(0..254, &Table.new_bucket(k1, svc("250.1.1.1"), ip("250.#{&1}.1.1")))
             ) > 64
    end
  end

  test "addrman_new_collisions: 250.1.1.1-22 fit, 23 replaces a terrible entry" do
    src = ip("252.2.2.2")

    t =
      Enum.reduce(1..22, Table.new(@det_key), fn i, t ->
        {t, 1} = add(t, caddr("250.1.1.#{i}"), src)
        assert Table.size(t) == i
        t
      end)

    {t, 1} = add(t, caddr("250.1.1.23"), src)
    assert Table.size(t) == 22
    {t, 1} = add(t, caddr("250.1.1.24"), src)
    assert Table.size(t) == 23
  end

  test "addrman_tried_collisions: 1-35 move to tried, 36 collides, 37 does not" do
    src = ip("252.2.2.2")

    t =
      Enum.reduce(1..35, Table.new(@det_key), fn i, t ->
        {t, 1} = add(t, caddr("250.1.1.#{i}"), src)
        {t, true} = good(t, caddr("250.1.1.#{i}"))
        t
      end)

    {t, 1} = add(t, caddr("250.1.1.36"), src)
    {t, false} = good(t, caddr("250.1.1.36"))
    {t, 1} = add(t, caddr("250.1.1.37"), src)
    {_t, true} = good(t, caddr("250.1.1.37"))
  end

  test "addrman_selecttriedcollision: duplicates are not collisions" do
    src = ip("252.2.2.2")
    assert {_, nil} = Table.select_tried_collision(Table.new(@det_key))

    t =
      Enum.reduce(1..22, Table.new(@det_key), fn i, t ->
        {t, 1} = add(t, caddr("250.1.1.#{i}"), src)
        {t, true} = good(t, caddr("250.1.1.#{i}"))
        assert {_, nil} = Table.select_tried_collision(t)
        t
      end)

    for i <- 1..22 do
      {t2, false} = good(t, caddr("250.1.1.#{i}"))
      assert {_, nil} = Table.select_tried_collision(t2)
    end
  end

  test "addrman_noevict: the old tried entry stays when it is reachable" do
    src = ip("252.2.2.2")

    fill = fn t, range ->
      Enum.reduce(range, t, fn i, t ->
        {t, 1} = add(t, caddr("250.1.1.#{i}"), src)
        {t, true} = good(t, caddr("250.1.1.#{i}"))
        t
      end)
    end

    t = fill.(Table.new(@det_key), 1..35)

    {t, 1} = add(t, caddr("250.1.1.36"), src)
    {t, false} = good(t, caddr("250.1.1.36"))
    {t, old} = Table.select_tried_collision(t)
    assert hostport(old) == "250.1.1.19:0"
    # 19 connected just now: 36 is discarded, 19 stays.
    t = Table.resolve_collisions(t, @now)
    assert {_, nil} = Table.select_tried_collision(t)

    t = fill.(t, 37..58)
    {t, 1} = add(t, caddr("250.1.1.59"), src)
    {t, false} = good(t, caddr("250.1.1.59"))
    {t, old} = Table.select_tried_collision(t)
    assert hostport(old) == "250.1.1.10:0"
    # Re-adding 36 does not create a second new entry...
    {t, 0} = add(t, caddr("250.1.1.36"), src)
    # ...and 36 still collides with 19.
    {t, false} = good(t, caddr("250.1.1.36"))
    assert {_, %{}} = Table.select_tried_collision(t)
    t = Table.resolve_collisions(t, @now)
    assert {_, nil} = Table.select_tried_collision(t)
  end

  test "addrman_evictionworks: an unreachable tried entry is replaced; after 4 h anyway" do
    src = ip("252.2.2.2")

    t =
      Enum.reduce(1..35, Table.new(@det_key), fn i, t ->
        {t, 1} = add(t, caddr("250.1.1.#{i}"), src)
        {t, true} = good(t, caddr("250.1.1.#{i}"))
        t
      end)

    a36 = caddr("250.1.1.36")
    {t, 1} = add(t, a36, src)
    {t, false} = good(t, a36)
    {t, old} = Table.select_tried_collision(t)
    assert hostport(old) == "250.1.1.19:0"

    # 19's last success far in the past, and a failed try 61 s ago.
    {t, false} = Table.good(t, Table.key(old.addr), true, 1)
    t = Table.attempt(t, Table.key(old.addr), false, @now - 61)
    t = Table.resolve_collisions(t, @now)
    assert {_, nil} = Table.select_tried_collision(t)
    assert Table.find_entry(t, Table.key(a36)).tried

    # 36 is in tried now: Good is a duplicate, no collision.
    {t, false} = good(t, a36)
    assert {_, nil} = Table.select_tried_collision(t)
    # 19 back from new collides with 36.
    {t, false} = good(t, caddr("250.1.1.19"))
    {t, old} = Table.select_tried_collision(t)
    assert hostport(old) == "250.1.1.36:0"
    # 4 hours later the collision resolves by eviction anyway.
    t = Table.resolve_collisions(t, @now + 4 * 3600)
    assert {_, nil} = Table.select_tried_collision(t)
    assert Table.find_entry(t, Table.key(caddr("250.1.1.19"))).tried
    refute Table.find_entry(t, Table.key(a36)).tried
  end

  test "addrman_new_multiplicity: same time keeps 1 reference; newer times reach at most 8" do
    a = caddr("253.3.3.3", 8333, @now)

    t =
      Enum.reduce(1..19, Table.new(@det_key), fn i, t ->
        {t, _} = Table.add(t, [a], ip("#{rem(i, 256)}.#{div(i, 256)}.1.1"), 0, @now)
        t
      end)

    assert Table.find_entry(t, Table.key(a)).multiplicity == 1
    assert Table.size(t) == 1

    # Core's deterministic RNG reaches 8 within 400 tries; with a real RNG, allow more.
    t =
      Enum.reduce(1..3000, t, fn i, t ->
        {t, _} =
          Table.add(
            t,
            [%{a | time: @now + i}],
            ip("#{rem(i, 256)}.#{div(i, 256)}.1.1"),
            0,
            @now + 3000
          )

        t
      end)

    assert Table.find_entry(t, Table.key(a)).multiplicity == 8
    assert Table.size(t) == 1
  end

  test "addrman_terrible_many_failures: 10 failures in a week filter an entry out of getaddr" do
    src = ip("250.1.2.1")
    a = caddr("250.250.2.1", 8333, @now)
    {t, 1} = add(t0 = Table.new(@det_key), a, src)
    _ = t0
    {t, true} = good(t, a)
    later = @now + 7 * 86_400 + 86_400
    helper = caddr("251.252.2.3", 8333, later)
    {t, 1} = add(t, helper, src, later)
    {t, true} = good(t, helper, later)
    t = Enum.reduce(1..10, t, fn _, t -> Table.attempt(t, Table.key(a), true, later - 61) end)
    filtered = Table.get_addr(t, 0, 0, later)
    assert [%{addr: %{addr: <<251, 252, 2, 3>>}}] = filtered
    assert length(Table.get_addr(t, 0, 0, later, false)) == 2
  end

  test "addrman_penalty_self_announcement: no time penalty when a source announces itself" do
    base = @now - 10_000
    a1 = caddr("250.1.1.1", 8333, base)
    {t, 1} = Table.add(Table.new(@det_key), [a1], ip("250.1.1.1"), 3600, @now)
    assert Table.get(t, Table.key(a1)).time == base
    a2 = caddr("250.1.1.2", 8333, base)
    {t, 1} = Table.add(t, [a2], ip("250.1.1.1"), 3600, @now)
    assert Table.get(t, Table.key(a2)).time == base - 3600
  end

  test "addrman_ports: the same IP with another port is a separate entry" do
    src = ip("252.5.1.1")
    {t, 1} = add(Table.new(@det_key), caddr("250.1.1.1", 8333), src)
    {t, 1} = add(t, caddr("250.1.1.1", 8334), src)
    assert Table.size(t) == 2
  end

  test "select: tried or new, never a missing network, and new_only" do
    src = ip("252.2.2.2")
    assert Table.select(Table.new(@det_key), false, nil, @now) == nil
    {t, 1} = add(Table.new(@det_key), caddr("250.1.1.1", 8333, @now), src)
    assert %{addr: %{addr: <<250, 1, 1, 1>>}} = Table.select(t, false, nil, @now)
    assert %{} = Table.select(t, true, nil, @now)
    assert Table.select(t, false, [:ipv6], @now) == nil
    {t, true} = good(t, caddr("250.1.1.1", 8333))
    assert Table.select(t, true, nil, @now) == nil
    assert %{} = Table.select(t, false, [:ipv4], @now)
  end

  test "unroutable addresses are refused; 240/4 and port 0 are allowed as in Core" do
    t = Table.new(@det_key)
    src = ip("8.8.8.8")

    for bad <- [
          "10.0.0.1",
          "192.168.1.1",
          "127.0.0.1",
          "169.254.1.1",
          "100.64.1.1",
          "0.0.0.0",
          "198.18.0.1",
          "203.0.113.5"
        ] do
      assert {_, 0} = add(t, caddr(bad, 8333), src)
    end

    assert {_, 1} = add(t, caddr("250.1.1.1"), src)
    assert {_, 0} = Table.add(t, [Map.merge(svc("fe80::1", 8333), %{time: @now})], src, 0, @now)

    assert {_, 0} =
             Table.add(t, [Map.merge(svc("2001:db8::1", 8333), %{time: @now})], src, 0, @now)

    assert {_, 1} = Table.add(t, [Map.merge(svc("2a01::1", 8333), %{time: @now})], src, 0, @now)
  end

  test "persistence term round trip keeps buckets and tried state" do
    src = ip("252.2.2.2")

    t =
      Enum.reduce(1..40, Table.new(@det_key), fn i, t ->
        {t, _} = add(t, caddr("250.1.#{rem(i, 3)}.#{i}", 8333, @now), src)
        t
      end)

    t =
      Enum.reduce(1..10, t, fn i, t ->
        {t, _} = good(t, caddr("250.1.#{rem(i, 3)}.#{i}", 8333))
        t
      end)

    t2 = Table.from_term(Table.to_term(t))
    assert Table.size(t2) == Table.size(t)
    assert {t2.n_new, t2.n_tried} == {t.n_new, t.n_tried}

    for {_, i} <- t.info do
      assert Table.find_entry(t2, Table.key(i.addr)) == Table.find_entry(t, Table.key(i.addr))
    end
  end

  test "netbase_getgroup: Core's group vectors" do
    for unroutable <- ["127.0.0.1", "10.0.0.1", "169.254.1.1"],
        do: assert(NetAddr.group(ip(unroutable)) == <<0>>)

    for linked <- [
          "1.2.3.4",
          "::FFFF:0:102:304",
          "64:FF9B::102:304",
          "2002:102:304:9999:9999:9999:9999:9999",
          "2001:0:9999:9999:9999:9999:FEFD:FCFB"
        ],
        do: assert(NetAddr.group(ip(linked)) == <<1, 1, 2>>, linked)

    assert NetAddr.group(ip("2001:470:abcd:9999:9999:9999:9999:9999")) ==
             <<2, 32, 1, 4, 112, 175>>

    assert NetAddr.group(ip("2001:2001:9999:9999:9999:9999:9999:9999")) == <<2, 32, 1, 32, 1>>
    # Internal: NET_INTERNAL followed by the 10 name-hash bytes.
    assert NetAddr.group(NetAddr.internal("baz.net")) ==
             <<6>> <> binary_part(:crypto.hash(:sha256, "baz.net"), 0, 10)
  end
end
