defmodule Exnode.Store.KVTest do
  use ExUnit.Case, async: true
  alias Exnode.Store.KV

  @moduletag :tmp_dir

  test "batched writes across column families, multi_get order, reopen", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(dir)

    :ok =
      KV.write(kv, [
        {:put, :spends, <<1::64>>, "a"},
        {:put, :spends, <<2::64>>, "b"},
        {:put, :txindex, <<1::64>>, "tx"},
        {:delete, :spends, <<2::64>>}
      ])

    assert KV.multi_get(kv, :spends, [<<2::64>>, <<1::64>>, <<3::64>>]) == [
             :not_found,
             {:ok, "a"},
             :not_found
           ]

    # Column families are separate keyspaces.
    assert KV.get(kv, :txindex, <<1::64>>) == {:ok, "tx"}
    assert KV.get(kv, :blocks, <<1::64>>) == :not_found

    KV.close(kv)
    {:ok, kv} = KV.open(dir)
    assert KV.get(kv, :spends, <<1::64>>) == {:ok, "a"}
    KV.close(kv)
  end

  test "open waits for a handle in this VM to release the store; a held one still fails",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(dir)
    assert {:error, {:db_open, msg}} = KV.open(dir, lock_wait_ms: 50)
    assert to_string(msg) =~ "lock hold by current process"

    # Released while the second open waits.
    Task.start(fn ->
      Process.sleep(100)
      KV.close(kv)
    end)

    assert {:ok, kv2} = KV.open(dir)
    KV.close(kv2)
    # Closing again is harmless.
    assert KV.close(kv) == :ok
  end

  test "fold_prefix stays inside the prefix", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(dir)
    :ok = KV.write(kv, for(p <- [1, 2, 3], i <- 1..3, do: {:put, :spends, <<p, i>>, <<i>>}))

    assert KV.fold_prefix(kv, :spends, <<2>>, [], fn {k, _}, acc -> [k | acc] end) == [
             <<2, 3>>,
             <<2, 2>>,
             <<2, 1>>
           ]

    assert KV.fold_prefix(kv, :spends, <<9>>, [], fn kv, acc -> [kv | acc] end) == []
    KV.close(kv)
  end

  # Regression: a read error came back as {:error, _}, which callers
  # matching {:ok, _} | :not_found crashed on outside the storage layer (so
  # the chain state took it for a bug in the block, not a disk fault).
  test "a read error raises KV.Error from get and multi_get", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(dir)
    :ok = KV.write(kv, [{:put, :pending, "k", :crypto.strong_rand_bytes(100_000)}])
    :ok = KV.write(kv, [{:put, :pending, "inline", "v"}])
    :ok = KV.flush(kv, :pending)
    # The value's blob file is gone: reading it fails inside RocksDB.
    Enum.each(Path.wildcard(Path.join(dir, "*.blob")), &File.rm!/1)

    assert %KV.Error{op: :get, cf: :pending} = catch_error(KV.get(kv, :pending, "k"))

    assert %KV.Error{op: :multi_get} =
             catch_error(KV.multi_get(kv, :pending, ["inline", "k"]))

    assert KV.multi_get(kv, :pending, ["inline", "none"]) == [{:ok, "v"}, :not_found]
    KV.close(kv)
  end
end

defmodule Exnode.Store.KVPackedTest do
  @moduledoc """
  `{:put_packed, ...}` writes exactly what the same puts written one by one
  do, in order (a later put or delete of the same key wins either way), and
  counts the same ops and bytes.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties
  alias Exnode.Store.KV

  @moduletag :tmp_dir

  # Small key space so packed puts overwrite and are overwritten/deleted.
  defp key(ks), do: map(integer(0..7), &<<&1::size(ks * 8)>>)

  defp op_gen do
    one_of([
      tuple({constant(:put), key(2), binary(max_length: 70)}),
      tuple({constant(:delete), key(2)}),
      tuple(
        {constant(:fixed),
         list_of(tuple({key(2), binary(length: 3)}), min_length: 1, max_length: 5)}
      ),
      tuple(
        {constant(:var),
         list_of(tuple({key(2), binary(max_length: 90)}), min_length: 1, max_length: 5)}
      )
    ])
  end

  defp expand({:put, k, v}), do: [{:put, :spends, k, v}]
  defp expand({:delete, k}), do: [{:delete, :spends, k}]
  defp expand({_, kvs}), do: for({k, v} <- kvs, do: {:put, :spends, k, v})

  defp packed({:fixed, kvs}),
    do: {:put_packed, :spends, 2, 3, for({k, v} <- kvs, into: <<>>, do: k <> v)}

  defp packed({:var, kvs}),
    do:
      {:put_packed, :spends, 2, :var,
       for({k, v} <- kvs, into: <<>>, do: <<k::binary, byte_size(v)::32, v::binary>>)}

  defp packed(op), do: hd(expand(op))

  defp contents(kv), do: KV.fold_prefix(kv, :spends, "", [], &[&1 | &2])

  property "packed puts are the same writes", %{tmp_dir: dir} do
    check all(ops <- list_of(op_gen(), max_length: 12), max_runs: 50) do
      # Fresh directories per run, not removed after it: KV.close only asks
      # RocksDB to close, and the DB is torn down (still writing files) when
      # its last reference goes, so removing the directory right after the
      # close can fail with it not empty. The tmp_dir goes with the next run.
      run = System.unique_integer([:positive])
      {:ok, a} = KV.open(Path.join(dir, "a#{run}"))
      {:ok, b} = KV.open(Path.join(dir, "b#{run}"))

      # Closed even when an assertion fails, so shrinking reruns do not pile
      # up open stores.
      try do
        KV.take_stats()
        :ok = KV.write(a, Enum.flat_map(ops, &expand/1), stats: true)
        sa = Map.take(KV.take_stats(), [:kv_ops, :kv_bytes])
        :ok = KV.write(b, Enum.map(ops, &packed/1), stats: true)
        sb = Map.take(KV.take_stats(), [:kv_ops, :kv_bytes])
        assert contents(a) == contents(b)
        assert sa == sb
      after
        KV.close(a)
        KV.close(b)
      end
    end
  end

  test "a truncated packed record fails the whole write", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(dir)

    assert_raise MatchError, fn ->
      KV.write(kv, [{:put, :spends, "x", "1"}, {:put_packed, :spends, 2, 3, <<0, 1, 2, 3>>}])
    end

    assert KV.get(kv, :spends, "x") == :not_found
    KV.close(kv)
  end
end
