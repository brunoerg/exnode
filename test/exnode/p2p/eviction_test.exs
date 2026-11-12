defmodule Exnode.P2P.EvictionTest do
  @moduledoc """
  Core v32.1 `src/test/net_peer_eviction_tests.cpp`, ported:
  * `peer_protection_test`: all 32 `IsProtected` cases (generated from the
    vendored source by a converter and reviewed), each run 20 times with
    random other fields and shuffled input. As in Core: exactly
    `size - size/2` candidates remain, the listed peers are protected and
    the listed others are not.
  * `peer_eviction_test`: the same loop over 0..199 candidates.
  """
  use ExUnit.Case, async: true

  alias Exnode.P2P.Eviction

  @networks [:unroutable, :ipv4, :ipv6, :onion, :i2p, :cjdns, :internal]

  # Core test/util/net.cpp GetRandomNodeEvictionCandidates.
  defp random_candidates(n) do
    for id <- 0..(n - 1)//1 do
      %{
        id: id,
        connected: :rand.uniform(100) - 1,
        min_ping: :rand.uniform(100) - 1,
        last_block_time: :rand.uniform(100) - 1,
        last_tx_time: :rand.uniform(100) - 1,
        relevant_services: :rand.uniform(2) == 1,
        relay_txs: :rand.uniform(2) == 1,
        bloom_filter: :rand.uniform(2) == 1,
        keyed_netgroup: :rand.uniform(100) - 1,
        prefer_evict: :rand.uniform(2) == 1,
        is_local: :rand.uniform(2) == 1,
        network: Enum.random(@networks),
        noban: false,
        conn_type: :inbound
      }
    end
  end

  defp protected?(n, setup, prot, unprot) do
    cs = n |> random_candidates() |> Enum.map(&setup.(&1, n)) |> Enum.shuffle()
    left = Eviction.protect_by_ratio(cs)
    assert length(left) == n - div(n, 2)
    ids = MapSet.new(left, & &1.id)

    Enum.all?(prot, &(not MapSet.member?(ids, &1))) and
      Enum.all?(unprot, &MapSet.member?(ids, &1))
  end

  test "peer_protection_test: Core's 32 cases" do
    :rand.seed(:exsss, {1, 2, 3})
    assert length(protection_cases()) == 32

    for {{n, setup, prot, unprot}, i} <- Enum.with_index(protection_cases()), _ <- 1..20 do
      assert protected?(n, setup, prot, unprot), "case #{i}"
    end
  end

  defp evicted?(n, setup, ids) do
    cs = n |> random_candidates() |> Enum.map(&setup.(&1, n)) |> Enum.shuffle()
    Eviction.select_node_to_evict(cs) in ids
  end

  test "peer_eviction_test: Core's loop over 0..199 candidates" do
    :rand.seed(:exsss, {4, 5, 6})

    for n <- 0..199 do
      refute evicted?(n, fn c, n -> %{c | keyed_netgroup: n - c.id} end, [0, 1, 2, 3])
      refute evicted?(n, fn c, _ -> %{c | min_ping: c.id} end, Enum.to_list(0..7))
      refute evicted?(n, fn c, n -> %{c | last_tx_time: n - c.id} end, [0, 1, 2, 3])

      relay_only = fn c, n ->
        c = %{c | last_block_time: n - c.id}
        if c.id <= 7, do: %{c | relay_txs: false, relevant_services: true}, else: c
      end

      refute evicted?(n, relay_only, Enum.to_list(0..7))
      refute evicted?(n, fn c, n -> %{c | last_block_time: n - c.id} end, [0, 1, 2, 3])
      refute evicted?(n, relay_only, Enum.to_list(0..11))

      all = fn c, n ->
        %{
          c
          | keyed_netgroup: n - c.id,
            min_ping: c.id,
            last_tx_time: n - c.id,
            last_block_time: n - c.id
        }
      end

      refute evicted?(n, all, Enum.to_list(0..19))

      if n >= 29, do: assert(Eviction.select_node_to_evict(random_candidates(n)) != nil)
      if n <= 20, do: assert(Eviction.select_node_to_evict(random_candidates(n)) == nil)
    end
  end

  test "Core's untested cases: prefer_evict first; the largest netgroup's youngest member" do
    base = fn id, group, connected ->
      %{
        id: id,
        connected: connected,
        min_ping: 50,
        last_block_time: 0,
        last_tx_time: 0,
        relevant_services: false,
        relay_txs: true,
        bloom_filter: false,
        keyed_netgroup: group,
        prefer_evict: false,
        is_local: false,
        network: :ipv4,
        noban: false,
        conn_type: :inbound
      }
    end

    # 40 candidates. Ids 0..19 win the fixed protections (netgroup, ping,
    # tx, block); of 20..39 the ratio step protects the 10 longest-connected
    # (20..29). Left: 30..39, where 34..39 share netgroup 7 (the largest).
    cs = for id <- 0..39, do: base.(id, if(id >= 34, do: 7, else: 100 + id), id)

    protect = fn c ->
      if c.id < 20,
        do: %{
          c
          | keyed_netgroup: 1000 + c.id,
            min_ping: c.id,
            last_tx_time: 100 - c.id,
            last_block_time: 100 - c.id
        },
        else: c
    end

    cs = Enum.map(cs, protect)
    # The largest group's youngest member (largest connect time).
    assert Eviction.select_node_to_evict(Enum.shuffle(cs)) == 39

    # A prefer_evict candidate among those left is taken instead.
    cs2 = Enum.map(cs, fn c -> if c.id == 31, do: %{c | prefer_evict: true}, else: c end)
    assert Eviction.select_node_to_evict(Enum.shuffle(cs2)) == 31
    # But prefer_evict does not undo a protection.
    cs3 = Enum.map(cs, fn c -> if c.id == 21, do: %{c | prefer_evict: true}, else: c end)
    assert Eviction.select_node_to_evict(Enum.shuffle(cs3)) == 39

    # Outbound and noban candidates are never evicted.
    only = for c <- cs, do: %{c | conn_type: :outbound_full_relay}
    assert Eviction.select_node_to_evict(only) == nil
    assert Eviction.select_node_to_evict(for c <- cs, do: %{c | noban: true}) == nil
  end

  defp protection_cases do
    [
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: false}
         c = %{c | network: :ipv4}
         c
       end, [0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11]},
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: n - c.id}
         c = %{c | is_local: false}
         c = %{c | network: :ipv6}
         c
       end, [6, 7, 8, 9, 10, 11], [0, 1, 2, 3, 4, 5]},
      {12,
       fn c, n ->
         _ = n
         c = %{c | is_local: false}
         c = %{c | network: if(c.id == 3 or c.id == 8 or c.id == 9, do: :onion, else: :ipv4)}
         c
       end, [3, 8, 9], []},
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: false}
         c = %{c | network: if(c.id == 3 or c.id > 7, do: :onion, else: :ipv6)}
         c
       end, [0, 1, 2, 3, 8, 9], [4, 5, 6, 7, 10, 11]},
      {12,
       fn c, n ->
         _ = n
         c = %{c | is_local: c.id == 1 or c.id == 9 or c.id == 11}
         c = %{c | network: :ipv4}
         c
       end, [1, 9, 11], []},
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id > 6}
         c = %{c | network: :ipv6}
         c
       end, [0, 1, 2, 7, 8, 9], [3, 4, 5, 6, 10, 11]},
      {12,
       fn c, n ->
         _ = n
         c = %{c | is_local: false}
         c = %{c | network: if(c.id == 2 or c.id == 7 or c.id == 10, do: :i2p, else: :ipv4)}
         c
       end, [2, 7, 10], []},
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: false}
         c = %{c | network: if(c.id == 4 or c.id > 8, do: :i2p, else: :ipv6)}
         c
       end, [0, 1, 2, 4, 9, 10], [3, 5, 6, 7, 8, 11]},
      {12,
       fn c, n ->
         _ = n
         c = %{c | is_local: false}
         c = %{c | network: if(c.id == 2 or c.id == 7 or c.id == 10, do: :cjdns, else: :ipv4)}
         c
       end, [2, 7, 10], []},
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: false}
         c = %{c | network: if(c.id == 4 or c.id > 8, do: :cjdns, else: :ipv6)}
         c
       end, [0, 1, 2, 4, 9, 10], [3, 5, 6, 7, 8, 11]},
      {4,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 4}
         c = %{c | network: if(c.id == 3, do: :onion, else: :ipv4)}
         c
       end, [0, 4], [1, 2]},
      {7,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 6}
         c = %{c | network: if(c.id == 5, do: :onion, else: :ipv4)}
         c
       end, [0, 1, 6], [2, 3, 4, 5]},
      {8,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 6}
         c = %{c | network: if(c.id == 5, do: :onion, else: :ipv4)}
         c
       end, [0, 1, 5, 6], [2, 3, 4, 7]},
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 6 or c.id == 9 or c.id == 11}
         c = %{c | network: if(c.id == 7 or c.id == 8 or c.id == 10, do: :onion, else: :ipv6)}
         c
       end, [0, 1, 2, 6, 7, 9], [3, 4, 5, 8, 10, 11]},
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id > 4 and c.id < 9}
         c = %{c | network: if(c.id == 10, do: :onion, else: :ipv4)}
         c
       end, [0, 1, 2, 5, 6, 10], [3, 4, 7, 8, 9, 11]},
      {16,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 6 or c.id == 9 or c.id == 11 or c.id == 12}
         c = %{c | network: if(c.id == 8 or c.id == 10, do: :onion, else: :ipv6)}
         c
       end, [0, 1, 2, 3, 6, 8, 9, 10], [4, 5, 7, 11, 12, 13, 14, 15]},
      {16,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id > 10}
         c = %{c | network: if(c.id == 10, do: :onion, else: :ipv4)}
         c
       end, [0, 1, 2, 3, 10, 11, 12, 13], [4, 5, 6, 7, 8, 9, 14, 15]},
      {16,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 15}
         c = %{c | network: if(c.id > 6 and c.id < 11, do: :onion, else: :ipv6)}
         c
       end, [0, 1, 2, 3, 7, 8, 9, 15], [5, 6, 10, 11, 12, 13, 14]},
      {12,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: false}

         c = %{
           c
           | network:
               cond do
                 c.id == 8 or c.id == 10 -> :onion
                 c.id == 6 or c.id == 9 or c.id == 11 or c.id == 12 -> :i2p
                 true -> :ipv4
               end
         }

         c
       end, [0, 1, 2, 6, 8, 10], [3, 4, 5, 7, 9, 11]},
      {4,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 2}

         c = %{
           c
           | network:
               cond do
                 c.id == 3 -> :i2p
                 c.id == 1 -> :onion
                 true -> :ipv6
               end
         }

         c
       end, [0, 3], [1, 2]},
      {7,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 4}

         c = %{
           c
           | network:
               cond do
                 c.id == 6 -> :i2p
                 c.id == 5 -> :onion
                 true -> :ipv6
               end
         }

         c
       end, [0, 1, 6], [2, 3, 4, 5]},
      {8,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 6}

         c = %{
           c
           | network:
               cond do
                 c.id == 5 -> :i2p
                 c.id == 4 -> :onion
                 true -> :ipv6
               end
         }

         c
       end, [0, 1, 5, 6], [2, 3, 4, 7]},
      {16,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 6 or c.id > 11}

         c = %{
           c
           | network:
               cond do
                 c.id == 7 or c.id == 11 -> :i2p
                 c.id == 9 or c.id == 10 -> :onion
                 true -> :ipv4
               end
         }

         c
       end, [0, 1, 2, 3, 6, 7, 9, 11], [4, 5, 8, 10, 12, 13, 14, 15]},
      {24,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 12}

         c = %{
           c
           | network:
               cond do
                 c.id > 14 and c.id < 23 -> :i2p
                 c.id == 23 -> :onion
                 true -> :ipv6
               end
         }

         c
       end, [0, 1, 2, 3, 4, 5, 12, 15, 16, 17, 18, 23],
       [6, 7, 8, 9, 10, 11, 13, 14, 19, 20, 21, 22]},
      {24,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 15}

         c = %{
           c
           | network:
               cond do
                 c.id == 12 or c.id == 14 or c.id == 17 -> :i2p
                 c.id > 17 -> :onion
                 true -> :ipv4
               end
         }

         c
       end, [0, 1, 2, 3, 4, 5, 12, 14, 15, 17, 18, 19],
       [6, 7, 8, 9, 10, 11, 13, 16, 20, 21, 22, 23]},
      {24,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 13}

         c = %{
           c
           | network:
               cond do
                 c.id > 16 -> :i2p
                 c.id == 12 or c.id == 14 or c.id == 15 or c.id == 16 -> :onion
                 true -> :ipv6
               end
         }

         c
       end, [0, 1, 2, 3, 4, 5, 12, 13, 14, 15, 17, 18],
       [6, 7, 8, 9, 10, 11, 16, 19, 20, 21, 22, 23]},
      {24,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id > 15}

         c = %{
           c
           | network:
               cond do
                 c.id > 10 and c.id < 15 -> :cjdns
                 c.id > 6 and c.id < 10 -> :onion
                 true -> :ipv4
               end
         }

         c
       end, [0, 1, 2, 3, 4, 5, 7, 8, 11, 12, 16, 17],
       [6, 9, 10, 13, 14, 15, 18, 19, 20, 21, 22, 23]},
      {5,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 3}

         c = %{
           c
           | network:
               cond do
                 c.id == 4 -> :cjdns
                 c.id == 1 -> :i2p
                 c.id == 2 -> :onion
                 true -> :ipv6
               end
         }

         c
       end, [0, 4], [1, 2, 3]},
      {7,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 4}

         c = %{
           c
           | network:
               cond do
                 c.id == 6 -> :cjdns
                 c.id == 5 -> :i2p
                 c.id == 3 -> :onion
                 true -> :ipv4
               end
         }

         c
       end, [0, 1, 6], [2, 3, 4, 5]},
      {8,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 3}

         c = %{
           c
           | network:
               cond do
                 c.id == 5 -> :cjdns
                 c.id == 6 -> :i2p
                 c.id == 3 -> :onion
                 true -> :ipv6
               end
         }

         c
       end, [0, 1, 5, 6], [2, 3, 4, 7]},
      {16,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id > 5}

         c = %{
           c
           | network:
               cond do
                 c.id == 11 or c.id == 15 -> :cjdns
                 c.id == 10 or c.id == 14 -> :i2p
                 c.id == 8 or c.id == 9 -> :onion
                 true -> :ipv4
               end
         }

         c
       end, [0, 1, 2, 3, 6, 8, 10, 11], [4, 5, 7, 9, 12, 13, 14, 15]},
      {24,
       fn c, n ->
         _ = n
         c = %{c | connected: c.id}
         c = %{c | is_local: c.id == 13}

         c = %{
           c
           | network:
               cond do
                 c.id > 17 -> :cjdns
                 c.id == 17 -> :i2p
                 c.id == 12 or c.id == 14 or c.id == 15 or c.id == 16 -> :onion
                 true -> :ipv6
               end
         }

         c
       end, [0, 1, 2, 3, 4, 5, 12, 13, 14, 17, 18, 19],
       [6, 7, 8, 9, 10, 11, 15, 16, 20, 21, 22, 23]}
    ]
  end
end
