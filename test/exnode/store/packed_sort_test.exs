defmodule Exnode.Store.PackedSortTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Store.{KV, PackedSort}

  # Reference: split the records, stable sort by key, join.
  defp records(bin, ks, :var),
    do:
      for(<<k::binary-size(ks), len::32, v::binary-size(len) <- bin>>,
        do: {k, <<len::32, v::binary>>}
      )

  defp records(bin, ks, vs),
    do: for(<<k::binary-size(ks), v::binary-size(vs) <- bin>>, do: {k, v})

  defp reference(bin, ks, vs),
    do:
      records(bin, ks, vs)
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {k, v} -> k <> v end)
      |> IO.iodata_to_binary()

  # Keys from a small alphabet, so equal keys (and their order) are common.
  defp key(ks), do: StreamData.binary(length: ks)

  defp small_key(ks),
    do:
      StreamData.list_of(StreamData.integer(0..2), length: ks)
      |> StreamData.map(&:erlang.list_to_binary/1)

  property "fixed-size records: the stable key order" do
    check all(
            ks <- StreamData.integer(1..12),
            vs <- StreamData.integer(1..9),
            recs <-
              StreamData.list_of(
                StreamData.tuple(
                  {StreamData.one_of([key(ks), small_key(ks)]), StreamData.binary(length: vs)}
                )
              )
          ) do
      bin = IO.iodata_to_binary(for {k, v} <- recs, do: [k, v])
      assert PackedSort.sort(bin, ks, vs) == reference(bin, ks, vs)
    end
  end

  property "length-prefixed values: the stable key order" do
    check all(
            ks <- StreamData.integer(1..8),
            recs <-
              StreamData.list_of(
                StreamData.tuple({small_key(ks), StreamData.binary(max_length: 20)})
              )
          ) do
      bin = IO.iodata_to_binary(for {k, v} <- recs, do: [k, <<byte_size(v)::32>>, v])
      assert PackedSort.sort(bin, ks, :var) == reference(bin, ks, :var)
    end
  end

  test "a cut-short record is badarg" do
    assert_raise ArgumentError, fn -> PackedSort.sort(<<1, 2, 3>>, 2, 2) end
    assert_raise ArgumentError, fn -> PackedSort.sort(<<1, 2, 0, 0, 0, 5, "abc">>, 2, :var) end
    assert PackedSort.sort(<<>>, 4, :var) == <<>>
  end

  test "edge cases: empty, one record, empty values, bad lengths" do
    assert PackedSort.sort(<<>>, 2, 3) == <<>>
    assert PackedSort.sort(<<9, 9, "abc">>, 2, 3) == <<9, 9, "abc">>
    assert PackedSort.sort(<<9, 9, 0::32>>, 2, :var) == <<9, 9, 0::32>>
    assert PackedSort.sort(<<>>, 2, 0) == <<>>
    assert PackedSort.sort(<<3, 3, 1, 1, 2, 2>>, 2, 0) == <<1, 1, 2, 2, 3, 3>>
    assert_raise ArgumentError, fn -> PackedSort.sort(<<1, 2, 3>>, 2, 0) end

    # Empty values between non-empty ones: every record keeps its whole length.
    bin = <<3, 0::32, 1, 2::32, "xy", 2, 0::32, 1, 0::32>>
    assert PackedSort.sort(bin, 1, :var) == <<1, 2::32, "xy", 1, 0::32, 2, 0::32, 3, 0::32>>

    # A length prefix past the end of the binary, up to the 32-bit maximum.
    for len <- [3, 0xFFFF_FFFF] do
      assert_raise ArgumentError, fn ->
        PackedSort.sort(<<1, 0::32, 2, len::32, "ab">>, 1, :var)
      end
    end

    # A record size past the binary (the value size near the 32-bit maximum).
    assert_raise ArgumentError, fn -> PackedSort.sort(<<1, 2, 3, 4>>, 1, 0xFFFF_FFFF) end
    assert_raise ArgumentError, fn -> PackedSort.sort(<<1, 2, 3, 4>>, 1025, 1) end
  end

  @tag :tmp_dir
  test "KV.write with sort_packed: the same store as without", %{tmp_dir: dir} do
    spends = fn seed ->
      :rand.seed(:exsss, {seed, 2, 3})
      for _ <- 1..500, into: <<>>, do: <<:rand.uniform(64)::64, :rand.uniform(4)::32, seed::64>>
    end

    tx = fn seed ->
      for i <- 1..200, into: <<>>, do: <<rem(i * 7, 50)::256, 3::32, seed, i::16>>
    end

    ops = [
      {:put_packed, :spends, 12, 8, spends.(1)},
      {:put_packed, :txindex, 32, :var, tx.(1)},
      {:put, :blocks, <<1::32>>, "b1"},
      {:put_packed, :spends, 12, 8, spends.(2)},
      {:put_packed, :txindex, 32, :var, tx.(2)},
      # A family with another op is written as given.
      {:put_packed, :locs, 4, 2, <<1::32, "aa", 1::32, "bb">>},
      {:put, :locs, <<1::32>>, "cc"},
      {:put, :meta, "archive", "m"}
    ]

    dump = fn kv ->
      for cf <- [:spends, :txindex, :blocks, :locs, :meta],
          do: {cf, KV.fold_prefix(kv, cf, <<>>, [], &[&1 | &2])}
    end

    {:ok, a} = KV.open(Path.join(dir, "a"))
    {:ok, b} = KV.open(Path.join(dir, "b"))
    :ok = KV.write(a, ops)
    :ok = KV.write(b, ops, sort_packed: true)
    assert dump.(a) == dump.(b)
    assert {:ok, "cc"} = KV.get(b, :locs, <<1::32>>)
    KV.close(a)
    KV.close(b)
  end
end
