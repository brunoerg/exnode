defmodule Exnode.Store.PendingBlobTest do
  @moduledoc """
  `pending` stores raw blocks in blob files, so compactions move keys and
  blob references, not blocks; `fold_keys/5` (the startup scan of held
  blocks) reads no blob.
  """
  use ExUnit.Case, async: true
  alias Exnode.Store.KV

  @moduletag :tmp_dir

  defp blob_files(dir), do: Path.wildcard(Path.join(dir, "*.blob"))

  test "block-sized pending values go to blob files and read back", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(dir)
    blocks = for i <- 1..5, into: %{}, do: {<<i::256>>, :crypto.strong_rand_bytes(200_000)}
    tiny = {<<99::256>>, "small"}

    :ok =
      KV.write(kv, for({h, raw} <- [tiny | Map.to_list(blocks)], do: {:put, :pending, h, raw}))

    # A block-sized value elsewhere stays inline (no blob files for other families).
    :ok = KV.write(kv, [{:put, :txindex, <<1::64>>, :binary.copy("x", 200_000)}])
    :ok = KV.flush(kv, :txindex)
    assert blob_files(dir) == []

    :ok = KV.flush(kv, :pending)
    assert [_ | _] = blob_files(dir)

    for {h, raw} <- blocks, do: assert(KV.get(kv, :pending, h) == {:ok, raw})
    assert KV.get(kv, :pending, elem(tiny, 0)) == {:ok, "small"}

    KV.close(kv)
    {:ok, kv} = KV.open(dir)
    for {h, raw} <- blocks, do: assert(KV.get(kv, :pending, h) == {:ok, raw})
    KV.close(kv)
  end

  test "fold_keys lists held blocks without reading their blob files", %{tmp_dir: dir} do
    {:ok, kv} = KV.open(dir)
    [first | _] = keys = for i <- 1..4, do: <<i::256>>

    :ok =
      KV.write(kv, for(h <- keys, do: {:put, :pending, h, :crypto.strong_rand_bytes(100_000)}))

    :ok = KV.write(kv, [{:put, :pending, <<9::256>>, "inline"}])
    :ok = KV.flush(kv, :pending)

    # Remove the blob files under the open store: any read of a block now
    # fails, so a fold that succeeds read none of them.
    files = blob_files(dir)
    assert files != []
    Enum.each(files, &File.rm!/1)
    assert_raise KV.Error, fn -> KV.get(kv, :pending, first) end

    assert KV.fold_keys(kv, :pending, <<>>, [], &[&1 | &2]) |> Enum.reverse() ==
             keys ++ [<<9::256>>]

    assert KV.get(kv, :pending, <<9::256>>) == {:ok, "inline"}
    KV.close(kv)
  end
end
