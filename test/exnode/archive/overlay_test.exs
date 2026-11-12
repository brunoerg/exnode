defmodule Exnode.Archive.OverlayTest do
  use ExUnit.Case, async: true

  alias Exnode.Archive.Overlay

  defp coin(id),
    do: %{output_id: id, value: id, script_pubkey: <<0x51>>, height: id, coinbase: false}

  test "spent masks the archive until committed; created is answered" do
    ov = Overlay.new(1_000_000)
    ov = Overlay.apply_block(ov, 1, %{{"a", 0} => coin(1)}, [{"old", 3}])
    assert Overlay.lookup(ov, {"a", 0}) == {:ok, coin(1)}
    assert Overlay.lookup(ov, {"old", 3}) == :spent
    assert Overlay.lookup(ov, {"x", 0}) == :unknown

    ov = Overlay.committed(ov, 1)
    # The spend record is now on disk: the archive answers.
    assert Overlay.lookup(ov, {"old", 3}) == :unknown
    assert Overlay.lookup(ov, {"a", 0}) == {:ok, coin(1)}
  end

  test "spend then re-create (a BIP30-allowed duplicate) and create then spend" do
    ov = Overlay.new(1_000_000)
    ov = Overlay.apply_block(ov, 1, %{}, [{"d", 0}])
    ov = Overlay.apply_block(ov, 2, %{{"d", 0} => coin(2)}, [])
    assert Overlay.lookup(ov, {"d", 0}) == {:ok, coin(2)}
    ov = Overlay.apply_block(ov, 3, %{}, [{"d", 0}])
    assert Overlay.lookup(ov, {"d", 0}) == :spent
  end

  test "eviction drops only committed entries, oldest first, and never a newer overwrite" do
    # Budget of 2 entries, each with its queued outpoint (6 packed bytes for
    # a 1-byte txid) and its block's queue element: 2 * (320 + 6 + 64).
    ov = Overlay.new(780)
    ov = Overlay.apply_block(ov, 1, %{{"a", 0} => coin(1), {"b", 0} => coin(1)}, [])
    ov = Overlay.apply_block(ov, 2, %{{"c", 0} => coin(2)}, [])
    # Block 3 overwrites a (BIP30 exception): the entry now belongs to block 3.
    ov = Overlay.apply_block(ov, 3, %{{"a", 0} => coin(3)}, [])
    # Nothing is committed yet: no eviction even though over budget.
    assert Overlay.size(ov) == 3
    ov = Overlay.committed(ov, 2)
    # Block 1 evicted: b goes; a stays (it is block 3's now). Block 2's c is
    # next, but the size is back within budget.
    assert Overlay.lookup(ov, {"b", 0}) == :unknown
    assert Overlay.lookup(ov, {"a", 0}) == {:ok, coin(3)}
    assert Overlay.lookup(ov, {"c", 0}) == {:ok, coin(2)}
  end

  test "cached script binaries are copies, not references into the block" do
    big = :crypto.strong_rand_bytes(1_000_000)
    spk = binary_part(big, 10, 25)
    ov = Overlay.new(1_000_000)
    ov = Overlay.apply_block(ov, 1, %{{"a", 0} => %{coin(1) | script_pubkey: spk}}, [])
    {:ok, %{script_pubkey: cached}} = Overlay.lookup(ov, {"a", 0})
    assert cached == spk
    assert :binary.referenced_byte_size(cached) == 25
  end

  test "no entry, mask, key or queued outpoint references the block binary" do
    big = :crypto.strong_rand_bytes(1_000_000)
    # Matched out of the block, as the decoder does. At most 64 bytes is
    # never a sub-binary (OTP 27+); anything larger references `big`.
    <<_::binary-size(7), t32::binary-size(32), s25::binary-size(25), s64::binary-size(64),
      s65::binary-size(65), s3k::binary-size(3000), t100::binary-size(100),
      spent::binary-size(32), spent100::binary-size(100), _::binary>> = big

    assert :binary.referenced_byte_size(t32) == 32
    assert :binary.referenced_byte_size(s65) == 1_000_000

    created = %{
      {t32, 0} => %{coin(1) | script_pubkey: s25},
      {t32, 1} => %{coin(1) | script_pubkey: s64},
      {t32, 2} => %{coin(1) | script_pubkey: s65},
      {t32, 3} => %{coin(1) | script_pubkey: s3k},
      {t100, 0} => %{coin(1) | script_pubkey: s3k}
    }

    ov = Overlay.new(1_000_000)
    ov = Overlay.apply_block(ov, 1, created, [{spent, 7}, {spent100, 8}])
    own? = fn bin -> :binary.referenced_byte_size(bin) == byte_size(bin) end

    for {{txid, _}, 1, %{script_pubkey: spk}} <- :ets.tab2list(ov.coins) do
      assert own?.(txid) and own?.(spk)
    end

    assert length(:ets.tab2list(ov.spent)) == 2
    for {{txid, _}} <- :ets.tab2list(ov.spent), do: assert(own?.(txid))
    assert {:value, {1, 5, packed}} = :queue.peek(ov.gens)
    assert own?.(packed)
    assert byte_size(packed) == 4 * (5 + 32) + (5 + 100)
    assert Overlay.memory(ov) == 5 * 320 + byte_size(packed) + 64

    for {op, c} <- created do
      assert Overlay.lookup(ov, op) == {:ok, c}
    end
  end

  test "CS-9: the budget bounds real memory: ETS entries plus the packed queue" do
    budget = 8 * 1024 * 1024
    w = :erlang.system_info(:wordsize)

    ov =
      Enum.reduce(1..60, Overlay.new(budget), fn gen, ov ->
        created =
          Map.new(1..2_000, fn i ->
            spk = :crypto.strong_rand_bytes(if rem(i, 3) == 0, do: 34, else: 22)
            {{:crypto.strong_rand_bytes(32), rem(i, 4)}, %{coin(gen) | script_pubkey: spk}}
          end)

        ov
        |> Overlay.apply_block(gen, created, [])
        |> Overlay.committed(gen)
      end)

    # The old charge (200 bytes per entry) let the table alone reach ~1.5x.
    assert :ets.info(ov.coins, :memory) * w <= budget

    real =
      :ets.info(ov.coins, :memory) * w +
        Enum.sum(for {_, _, packed} <- :queue.to_list(ov.gens), do: byte_size(packed))

    # Evicting kept it under budget, and the charge is close to the real use.
    assert Overlay.memory(ov) <= budget
    assert real <= budget
    assert real >= 0.8 * Overlay.memory(ov)
  end

  test "clear drops everything" do
    ov = Overlay.new(1_000_000)
    ov = Overlay.apply_block(ov, 1, %{{"a", 0} => coin(1)}, [{"z", 1}])
    ov = Overlay.clear(ov)
    assert Overlay.lookup(ov, {"a", 0}) == :unknown
    assert Overlay.lookup(ov, {"z", 1}) == :unknown
  end
end

defmodule Exnode.Archive.TxindexCodecTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Archive

  property "txindex entries round-trip; legacy term values still decode" do
    entry =
      tuple(
        {integer(0..0x7FFFFFFF), integer(0..0xFFFFFF), integer(0..0xFFFFFFFFFFFF),
         integer(0..0xFFFFFF), integer(0..0xFFFFFFFFFFFF)}
      )

    check all(list <- list_of(entry, min_length: 1, max_length: 4)) do
      assert Archive.decode_txindex(Archive.encode_txindex(list)) == list
      assert Archive.decode_txindex(:erlang.term_to_binary(list)) == list
      assert byte_size(Archive.encode_txindex(list)) == 22 * length(list)
    end
  end
end

defmodule Exnode.Archive.OverlayModelTest do
  @moduledoc """
  The overlay against a pure model of its original semantics (per-entry
  generation-matched eviction, oldest committed block first, while over
  budget), over random block sequences with BIP30-style re-creations,
  same-block spend-and-create, out-of-order (reconnected) generations,
  partial commits and clears, with no cache budget and with small ones.
  Committed generations never decrease, as in the archive.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Archive.Overlay

  @ops for t <- ["a", "b", "c", "d", "e"], v <- 0..2, do: {t, v}

  defp coin(gen, op),
    do: %{
      output_id: :erlang.phash2({gen, op}),
      value: gen,
      script_pubkey: <<gen>>,
      height: gen,
      coinbase: false
    }

  # The model: coins op => {gen, coin}; spent mask; queue of {gen, ops};
  # `max` in bytes, charged as Overlay.memory/1 documents.
  defp m_new(max),
    do: %{coins: %{}, spent: MapSet.new(), gens: [], queued: 0, flushed: -1, max: max}

  # 320 bytes per coin entry, the packed outpoints (<<size, txid, vout::32>>)
  # and 64 bytes per queued block.
  defp m_memory(m) do
    packed =
      for {_, ops} <- m.gens, {txid, _} <- ops, reduce: 0, do: (b -> b + 5 + byte_size(txid))

    map_size(m.coins) * 320 + packed + length(m.gens) * 64
  end

  defp m_apply(m, gen, created, spent) do
    m =
      Enum.reduce(spent, m, fn op, m ->
        %{m | coins: Map.delete(m.coins, op), spent: MapSet.put(m.spent, op)}
      end)

    m =
      Enum.reduce(created, m, fn {op, c}, m ->
        %{m | spent: MapSet.delete(m.spent, op), coins: Map.put(m.coins, op, {gen, c})}
      end)

    ops = Map.keys(created)
    %{m | gens: m.gens ++ [{gen, ops}], queued: m.queued + length(ops)}
  end

  defp m_committed(m, gen), do: m_evict(%{m | spent: MapSet.new(), flushed: gen})

  defp m_evict(m) do
    case m.gens do
      [{g, ops} | rest]
      when g <= m.flushed ->
        if m_memory(m) > m.max, do: m_evict_first(m, g, ops, rest), else: m

      _ ->
        m
    end
  end

  defp m_evict_first(m, g, ops, rest) do
    coins =
      Enum.reduce(ops, m.coins, fn op, cs ->
        if match?(%{^op => {^g, _}}, cs), do: Map.delete(cs, op), else: cs
      end)

    m_evict(%{m | coins: coins, gens: rest, queued: m.queued - length(ops)})
  end

  defp m_lookup(m, op) do
    case m.coins do
      %{^op => {_, c}} -> {:ok, c}
      _ -> if MapSet.member?(m.spent, op), do: :spent, else: :unknown
    end
  end

  defp step_gen do
    one_of([
      tuple(
        {constant(:block), integer(0..12), list_of(member_of(@ops), max_length: 6),
         list_of(member_of(@ops), max_length: 4)}
      ),
      tuple({constant(:commit), integer(-1..12)}),
      tuple({constant(:commit_all)}),
      constant({:clear})
    ])
  end

  property "lookups and size match the model after every step" do
    check all(
            max <- member_of([0, 390, 780, 1950]),
            steps <- list_of(step_gen(), max_length: 40)
          ) do
      ov = Overlay.new(max)

      {ov, _m, _top} =
        Enum.reduce(steps, {ov, m_new(max), -1}, fn step, {ov, m, top} ->
          {ov, m, top} =
            case step do
              {:block, gen, created, spent} ->
                created = Map.new(created, &{&1, coin(gen, &1)})

                {Overlay.apply_block(ov, gen, created, spent), m_apply(m, gen, created, spent),
                 max(top, gen)}

              # Committed generations never decrease (Overlay.committed/2).
              {:commit, gen} ->
                gen = max(gen, m.flushed)
                {Overlay.committed(ov, gen), m_committed(m, gen), top}

              {:commit_all} ->
                gen = max(top, m.flushed)
                {Overlay.committed(ov, gen), m_committed(m, gen), top}

              {:clear} ->
                {Overlay.clear(ov), %{m | coins: %{}, spent: MapSet.new(), gens: [], queued: 0},
                 top}
            end

          for op <- @ops,
              do:
                assert(
                  Overlay.lookup(ov, op) == m_lookup(m, op),
                  "#{inspect(op)} after #{inspect(step)}"
                )

          assert Overlay.size(ov) == map_size(m.coins)
          {ov, m, top}
        end)

      Overlay.close(ov)
    end
  end
end
