defmodule Exnode.Properties.StructuresPropertyTest do
  @moduledoc """
  Properties of exnode's data structures: addresses, BIP158 filters,
  compact-block reconstruction, the header tree, and the mempool graph.
  Each is checked against a naive reference or an invariant.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.{Address, BlockFilter}
  alias Exnode.Chain.HeaderIndex
  alias Exnode.Codec.{Header, Tx}
  alias Exnode.Mempool.{Linearize, Pool}
  alias Exnode.P2P.CompactBlock
  alias Exnode.Test.Generators, as: G

  # --- addresses ----------------------------------------------------------------------

  defp destination do
    one_of([
      map(binary(length: 20), &(<<0x76, 0xA9, 20>> <> &1 <> <<0x88, 0xAC>>)),
      map(binary(length: 20), &(<<0xA9, 20>> <> &1 <> <<0x87>>)),
      map(binary(length: 20), &(<<0, 20>> <> &1)),
      map(binary(length: 32), &(<<0, 32>> <> &1)),
      map(binary(length: 32), &(<<0x51, 32>> <> &1)),
      # Future witness versions 1..16 with any program of 2..40 bytes.
      gen(
        all(
          v <- integer(1..16),
          p <- binary(min_length: 2, max_length: 40),
          do: <<0x50 + v, byte_size(p)>> <> p
        )
      )
    ])
  end

  @bech32 ~c"qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  @base58 ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  property "addresses: script -> address -> script round-trips; any one-character change is rejected" do
    check all(
            spk <- destination(),
            net <- member_of([:mainnet, :testnet4, :regtest]),
            pos <- integer(0..200),
            pick <- integer(0..57),
            max_runs: 1000
          ) do
      addr = Address.from_script(spk, net)
      assert is_binary(addr)
      assert Address.to_script(addr, net) == {:ok, spk}
      # Mixed case is invalid for bech32; upper case is valid (BIP173).
      if String.contains?(addr, "1") and not String.starts_with?(addr, ["1", "3", "m", "n", "2"]),
        do: assert(Address.to_script(String.upcase(addr), net) == {:ok, spk})

      {alphabet, start} =
        case String.split(addr, "1", parts: 2) do
          [hrp, _] when hrp in ["bc", "tb", "bcrt"] -> {@bech32, byte_size(hrp) + 1}
          _ -> {@base58, 0}
        end

      i = start + rem(pos, byte_size(addr) - start)
      old = :binary.at(addr, i)
      new = Enum.at(alphabet -- [old], rem(pick, length(alphabet) - 1))

      mutated =
        binary_part(addr, 0, i) <> <<new>> <> binary_part(addr, i + 1, byte_size(addr) - i - 1)

      # bech32/bech32m detect every single substitution; base58check misses one in 2^32.
      assert match?({:error, _}, Address.to_script(mutated, net)), "#{addr} -> #{mutated}"
    end
  end

  # Reference bech32 encoder (BIP173 / BIP350 Python reference), with the checksum constant as a parameter.
  defp ref_polymod(values) do
    import Bitwise
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

    Enum.reduce(values, 1, fn v, chk ->
      top = chk >>> 25
      chk = bxor((chk &&& 0x1FFFFFF) <<< 5, v)

      Enum.reduce(0..4, chk, fn i, c ->
        if (top >>> i &&& 1) == 1, do: bxor(c, Enum.at(gen, i)), else: c
      end)
    end)
  end

  defp ref_encode(hrp, version, program, const) do
    import Bitwise

    hrp_exp =
      for(c <- String.to_charlist(hrp), do: c >>> 5) ++
        [0] ++ for(c <- String.to_charlist(hrp), do: c &&& 31)

    pad = rem(5 - rem(bit_size(program), 5), 5)
    bits = for <<(b::5 <- <<program::binary, 0::size(pad)>>)>>, do: b
    data = [version | bits]
    pm = bxor(ref_polymod(hrp_exp ++ data ++ [0, 0, 0, 0, 0, 0]), const)
    checksum = for i <- 0..5, do: pm >>> (5 * (5 - i)) &&& 31
    hrp <> "1" <> List.to_string(for d <- data ++ checksum, do: Enum.at(@bech32, d))
  end

  property "segwit addresses equal the BIP173/BIP350 reference; the wrong checksum type for the version is rejected" do
    check all(
            spk <- destination(),
            net <- member_of([:mainnet, :testnet4, :regtest]),
            max_runs: 500
          ) do
      case spk do
        <<v, n, prog::binary>> when (v == 0 or v in 0x51..0x60) and n == byte_size(prog) ->
          version = if v == 0, do: 0, else: v - 0x50
          hrp = Address.prefixes(net).hrp
          {right, wrong} = if version == 0, do: {1, 0x2BC830A3}, else: {0x2BC830A3, 1}
          assert Address.from_script(spk, net) == ref_encode(hrp, version, prog, right)

          assert Address.to_script(ref_encode(hrp, version, prog, wrong), net) ==
                   {:error, :invalid}

        _ ->
          :base58
      end
    end
  end

  # --- BIP158 -------------------------------------------------------------------------

  property "filters: every element matches (no false negatives); order and duplicates don't matter" do
    check all(
            hash <- G.hash(),
            outs <- list_of(G.script(), max_length: 30),
            spent <- list_of(G.script(), max_length: 30),
            max_runs: 300
          ) do
      f = BlockFilter.build(hash, outs, spent)

      elements =
        MapSet.new(
          Enum.reject(outs, &(&1 == <<>> or :binary.first(&1) == 0x6A)) ++
            Enum.reject(spent, &(&1 == <<>>))
        )

      assert BlockFilter.n(f) == MapSet.size(elements)
      for e <- elements, do: assert(BlockFilter.match_any?(f, hash, [e]))
      assert BlockFilter.build(hash, Enum.reverse(outs) ++ outs, Enum.shuffle(spent)) == f
      refute BlockFilter.match_any?(f, hash, [])
    end
  end

  property "filters: elements outside the set rarely match (rate 1/784931)" do
    check all(
            hash <- G.hash(),
            outs <- list_of(binary(min_length: 1, max_length: 30), min_length: 1, max_length: 50),
            max_runs: 100
          ) do
      outs = Enum.map(outs, &(<<0x51>> <> &1))
      f = BlockFilter.build(hash, outs, [])
      # Non-members (prefix 0x52); 200 queries * 50 elements / M gives ~1% chance of one hit.
      others = for i <- 1..200, do: <<0x52, i::32>>
      hits = Enum.count(others, &BlockFilter.match_any?(f, hash, [&1]))
      assert hits <= 2
    end
  end

  # --- compact blocks -------------------------------------------------------------------

  property "compact blocks: any mempool subset and prefilled set reconstructs the exact block" do
    check all(
            b <- G.block(max_txs: 15),
            nonce <- integer(0..0xFFFFFFFFFFFFFFFF),
            in_pool <- list_of(boolean(), length: length(b.txs)),
            prefill <- list_of(boolean(), length: length(b.txs)),
            extra <- list_of(G.tx(witness: false), max_length: 5),
            max_runs: 200
          ) do
      indexed = Enum.with_index(b.txs)
      prefilled = for {{tx, i}, p} <- Enum.zip(indexed, prefill), i == 0 or p, do: {i, tx}
      pre_idx = MapSet.new(prefilled, &elem(&1, 0))
      {k0, k1} = CompactBlock.keys(b.header, nonce)

      short_ids =
        for {tx, i} <- indexed,
            not MapSet.member?(pre_idx, i),
            do: CompactBlock.short_id(k0, k1, tx.wtxid)

      c = %CompactBlock{
        header: b.header,
        nonce: nonce,
        short_ids: short_ids,
        prefilled: prefilled
      }

      # The wire form round-trips.
      {:ok, c2} = c |> CompactBlock.encode() |> IO.iodata_to_binary() |> CompactBlock.decode()

      assert IO.iodata_to_binary(CompactBlock.encode(c2)) ==
               IO.iodata_to_binary(CompactBlock.encode(c))

      pool = for({{tx, _}, true} <- Enum.zip(indexed, in_pool), do: tx) ++ extra

      match = fn {a, z}, wanted ->
        wanted = MapSet.new(wanted)

        for tx <- pool,
            id = CompactBlock.short_id(a, z, tx.wtxid),
            MapSet.member?(wanted, id),
            into: %{},
            do: {id, tx}
      end

      {:ok, partial} = CompactBlock.init(c2, match)
      missing = CompactBlock.missing(partial)

      expected_missing =
        for {{_, i}, false} <- Enum.zip(indexed, in_pool), not MapSet.member?(pre_idx, i), do: i

      assert missing == expected_missing

      assert {:ok, rebuilt} =
               CompactBlock.fill(partial, Enum.map(missing, &Enum.at(b.txs, &1)), false)

      assert rebuilt.raw == b.raw

      # The wrong number of missing txs is the peer's fault; a wrong tx is a failed reconstruction.
      if missing != [] do
        assert CompactBlock.fill(partial, [], false) == :invalid

        assert CompactBlock.fill(
                 partial,
                 Enum.map(missing, fn _ -> hd(extra ++ [G.coinbase(1)]) end),
                 false
               ) == :failed
      end
    end
  end

  # --- the header tree ----------------------------------------------------------------

  # A random tree: header i builds on one of the 4 latest entries (deep
  # chains with short forks), with one of a few work levels.
  defp tree do
    gen all(
          n <- integer(1..120),
          parents <- list_of(integer(0..1_000_000), length: n),
          bits <- list_of(member_of([0x207FFFFF, 0x2000FFFF, 0x1F00FFFF]), length: n + 1)
        ) do
      {parents, bits}
    end
  end

  defp build_tree({parents, bits}) do
    idx = HeaderIndex.new()

    genesis =
      HeaderIndex.make_entry(
        %Header{
          version: 1,
          prev_hash: <<0::256>>,
          merkle_root: <<0::256>>,
          time: 0,
          bits: hd(bits),
          nonce: 0,
          hash: <<0::248, 1>>
        },
        nil
      )

    idx = HeaderIndex.insert(idx, genesis)

    {idx, entries} =
      parents
      |> Enum.zip(tl(bits))
      |> Enum.with_index(1)
      |> Enum.reduce({idx, [genesis]}, fn {{p, b}, i}, {idx, acc} ->
        prev = Enum.at(acc, length(acc) - 1 - rem(p, min(length(acc), 4)))

        h = %Header{
          version: 1,
          prev_hash: prev.hash,
          merkle_root: <<0::256>>,
          time: prev.time + 600,
          bits: b,
          nonce: i,
          hash: <<i::256>> |> then(&:crypto.hash(:sha256, &1))
        }

        e = HeaderIndex.make_entry(h, prev)
        {HeaderIndex.insert(idx, e), acc ++ [e]}
      end)

    {idx, entries}
  end

  defp core_locator_heights(0, _step, acc), do: Enum.reverse([0 | acc])

  defp core_locator_heights(h, step, acc) do
    acc = [h | acc]
    core_locator_heights(max(h - step, 0), if(length(acc) > 10, do: step * 2, else: step), acc)
  end

  defp naive_ancestor(by_hash, e, h),
    do: if(e.height == h, do: e, else: naive_ancestor(by_hash, by_hash[e.prev_hash], h))

  property "header tree: best header, height table, ancestors, fork points and locators match a naive walk" do
    check all(
            t <- tree(),
            picks <-
              list_of(tuple({integer(0..1000), integer(0..1000), integer(0..1000)}), length: 10),
            max_runs: 150
          ) do
      {idx, entries} = build_tree(t)
      by_hash = Map.new(entries, &{&1.hash, &1})

      # Best: most work; on a tie the first inserted (Core: strictly greater work).
      max_work = entries |> Enum.map(& &1.chain_work) |> Enum.max()
      assert idx.best.hash == Enum.find(entries, &(&1.chain_work == max_work)).hash

      for h <- 0..idx.best.height,
          do: assert(HeaderIndex.hash_at(idx, h) == naive_ancestor(by_hash, idx.best, h).hash)

      assert HeaderIndex.hash_at(idx, idx.best.height + 1) == nil

      for {a, b, h} <- picks do
        ea = Enum.at(entries, rem(a, length(entries)))
        eb = Enum.at(entries, rem(b, length(entries)))
        height = rem(h, ea.height + 1)

        assert HeaderIndex.ancestor(idx, ea, height).hash ==
                 naive_ancestor(by_hash, ea, height).hash

        assert HeaderIndex.ancestor(idx, ea, ea.height + 1) == nil

        # Fork point: the highest common ancestor.
        common =
          Enum.find(ea.height..0//-1, fn x ->
            x <= eb.height and
              naive_ancestor(by_hash, ea, x).hash == naive_ancestor(by_hash, eb, x).hash
          end)

        assert HeaderIndex.last_common_ancestor(idx, ea, eb).height == common
        assert HeaderIndex.ancestor_of?(idx, ea, eb) == (common == ea.height)

        # Locator (Core LocatorEntries): heights step back by 1 for the first
        # 10 entries, then by doubling steps, clamped at genesis; all on the entry's chain.
        loc = HeaderIndex.locator(idx, ea)
        assert Enum.map(loc, &by_hash[&1].height) == core_locator_heights(ea.height, 1, [])
        for x <- loc, do: assert(naive_ancestor(by_hash, ea, by_hash[x].height).hash == x)
      end
    end
  end

  # --- the mempool graph --------------------------------------------------------------

  # Random tx DAG in topological order: each tx spends 1-3 coins, either
  # outside the pool or unspent outputs of earlier txs.
  defp dag do
    gen all(
          n <- integer(1..40),
          picks <- list_of(list_of(integer(0..10_000), min_length: 1, max_length: 3), length: n),
          nouts <- list_of(integer(1..3), length: n),
          fees <- list_of(integer(0..100_000), length: n),
          removes <- list_of(integer(0..10_000), max_length: 6)
        ) do
      {picks, nouts, fees, removes}
    end
  end

  defp build_pool({picks, nouts, fees, _}) do
    {pool, _coins, _} =
      Enum.zip([picks, nouts, fees])
      |> Enum.reduce({Pool.new(index_scripts: true), [], 0}, fn {ps, no, fee}, {pool, coins, i} ->
        # Pick distinct unspent mempool coins, or an outside coin.
        {ins, coins} =
          Enum.reduce(ps, {[], coins}, fn p, {ins, coins} ->
            if coins != [] and rem(p, 3) != 0 do
              c = Enum.at(coins, rem(p, length(coins)))
              {[c | ins], List.delete(coins, c)}
            else
              {[{:crypto.hash(:sha256, <<i::32, p::32, length(ins)::8>>), 0, <<0x54>>} | ins],
               coins}
            end
          end)

        tx =
          G.finish(%Tx{
            version: 2,
            locktime: 0,
            inputs:
              for(
                {h, v, _} <- ins,
                do: %Tx.In{prev_hash: h, prev_index: v, script_sig: <<>>, sequence: 0}
              ),
            outputs:
              for(v <- 1..no, do: %Tx.Out{value: 1000, script_pubkey: <<0x51 + rem(i + v, 3)>>})
          })

        w = Tx.weight(tx)

        e = %Pool.Entry{
          tx: tx,
          txid: tx.txid,
          wtxid: tx.wtxid,
          fee: fee,
          weight: w,
          vsize: div(w + 3, 4),
          sigops: 0,
          time: 0,
          height: 1,
          spends_coinbase: false,
          spent: for({_, _, spk} <- ins, do: {1000, :crypto.hash(:sha256, spk)})
        }

        outs = for {o, v} <- Enum.with_index(tx.outputs), do: {tx.txid, v, o.script_pubkey}
        {Pool.add(pool, e), coins ++ outs, i + 1}
      end)

    pool
  end

  defp check_invariants(pool) do
    entries = pool.entries

    for {txid, e} <- entries do
      parents =
        for i <- e.tx.inputs,
            Map.has_key?(entries, i.prev_hash),
            into: MapSet.new(),
            do: i.prev_hash

      assert e.parents == parents, "parents derive from inputs"

      for c <- e.children,
          do: assert(MapSet.member?(entries[c].parents, txid), "children mirror parents")

      for i <- e.tx.inputs, do: assert(Pool.spender(pool, {i.prev_hash, i.prev_index}) == txid)
      assert Pool.by_wtxid(pool, e.wtxid).txid == txid
    end

    assert map_size(pool.spenders) == Enum.sum(for {_, e} <- entries, do: length(e.tx.inputs))

    # The script index: each script's txs are those paying to it or spending
    # an output of it, and no script is left with no tx.
    by_script =
      Enum.reduce(entries, %{}, fn {txid, e}, acc ->
        shs =
          for(o <- e.tx.outputs, do: :crypto.hash(:sha256, o.script_pubkey)) ++
            for({_, sh} <- e.spent, do: sh)

        Enum.reduce(
          shs,
          acc,
          &Map.update(&2, &1, MapSet.new([txid]), fn s -> MapSet.put(s, txid) end)
        )
      end)

    assert pool.by_script == by_script
    assert pool.total_vsize == Enum.sum(for {_, e} <- entries, do: e.vsize)

    # Clusters partition the pool; chunks cover each cluster in a topological order with non-increasing feerates.
    clusters = entries |> Map.keys() |> Enum.map(&Pool.cluster(pool, &1)) |> Enum.uniq()
    assert Enum.sum(Enum.map(clusters, &MapSet.size/1)) == map_size(entries)

    for cl <- clusters do
      chunks = Pool.chunks(pool, Enum.at(MapSet.to_list(cl), 0))
      order = Enum.flat_map(chunks, &elem(&1, 2))
      assert MapSet.new(order) == cl and length(order) == MapSet.size(cl)
      pos = order |> Enum.with_index() |> Map.new()
      for t <- order, p <- entries[t].parents, do: assert(pos[p] < pos[t], "topological")

      for {{f, s, ids}, {f2, s2, _}} <- Enum.zip(chunks, tl(chunks) ++ [{0, 1, []}]), ids != [] do
        assert f == Enum.sum(for(t <- ids, do: entries[t].fee)) and
                 s == Enum.sum(for(t <- ids, do: entries[t].weight))

        if f2 > 0 or s2 > 1,
          do:
            assert(Linearize.ratio_cmp({f, s}, {f2, s2}) != :lt, "chunk feerates non-increasing")
      end
    end
  end

  property "mempool graph: links, spenders, totals, clusters and chunks stay consistent through adds and removals" do
    check all(d <- dag(), max_runs: 200) do
      pool = build_pool(d)
      check_invariants(pool)
      {_, _, _, removes} = d
      txids = Map.keys(pool.entries)

      pool =
        Enum.reduce(removes, pool, fn r, pool ->
          live = Enum.filter(txids, &Pool.exists?(pool, &1))

          if live == [] do
            pool
          else
            pick = Enum.at(live, rem(r, length(live)))

            # Even: evict with descendants (replacement, expiry, trim). Odd:
            # confirm an ancestor-closed set as a block would; its children stay.
            gone =
              if rem(r, 2) == 0,
                do: Pool.with_descendants(pool, [pick]),
                else: MapSet.put(Pool.ancestors(pool, pick), pick)

            pool = Pool.remove(pool, gone)
            for t <- gone, do: refute(Pool.exists?(pool, t))
            check_invariants(pool)
            pool
          end
        end)

      # Removing everything leaves an empty pool.
      empty = Pool.remove(pool, Pool.with_descendants(pool, Map.keys(pool.entries)))

      assert empty.entries == %{} and empty.spenders == %{} and empty.by_wtxid == %{} and
               empty.total_vsize == 0
    end
  end
end
