defmodule Exnode.Replay.SeedTest do
  @moduledoc """
  Seeded ranges (`Exnode.Replay.Seed`) on the 150-block regtest fixture: a
  seed at 100 built by ordinary processing is cloned (never written), each
  preparation mode connects 101..150 on its own clone, and the range's
  effects digest equals a fresh 1..150 run's; the tip and digest survive a
  restart. Destinations overlapping a seed or export are refused.
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Crypto.Hash
  alias Exnode.Replay.{Dataset, Seed}
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp blocks, do: for(raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1))

  defp open(dir, opts \\ []) do
    {:ok, kv} = KV.open(Path.join(dir, "index"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link([params: @p, headers: hs, kv: kv, hot: Path.join(dir, "archive")] ++ opts)

    %{kv: kv, hs: hs, cs: cs}
  end

  defp close(n) do
    for pid <- [n.cs, n.hs] do
      Process.unlink(pid)
      :ok = GenServer.stop(pid, :normal, :infinity)
    end

    KV.close(n.kv)
  end

  defp connect(n, bs), do: for(b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b))
  defp digest(n, from, to), do: State.peek_archive(n.cs, &Seed.effects_digest(&1, from, to))

  defp range_manifest(dir, from) do
    raws = BB.read_chain(@chain)
    File.mkdir_p!(dir)
    rec = fn bin -> <<byte_size(bin)::32, bin::binary>> end
    File.write!(Path.join(dir, "headers.bin"), Enum.map(raws, &rec.(binary_part(&1, 0, 80))))
    File.write!(Path.join(dir, "blocks.bin"), raws |> Enum.drop(from - 1) |> Enum.map(rec))
    Dataset.build(dir, "regtest", 1, from)
  end

  test "seeded ranges equal the fresh run in every mode, and survive a restart", %{tmp_dir: dir} do
    bs = blocks()

    # Fresh reference run 1..150.
    fresh = open(Path.join(dir, "fresh"))
    connect(fresh, bs)
    fresh_digest = digest(fresh, 101, 150)
    close(fresh)

    # The seed: blocks 1..100 by ordinary processing.
    seed_dir = Path.join(dir, "seed")
    s = open(seed_dir)
    connect(s, Enum.take(bs, 100))
    d = State.peek_archive(s.cs, &Seed.describe/1)
    close(s)

    Seed.write(
      seed_dir,
      Map.merge(d, %{"chain" => "regtest", "genesis" => Hash.to_hex(@p.genesis.header.hash)})
    )

    {:ok, seed} = Seed.read(seed_dir)
    assert seed["height"] == 100
    seed_files = File.ls!(Path.join(seed_dir, "index")) |> Enum.sort()

    m = range_manifest(Path.join(dir, "export"), 101)
    assert :ok = Seed.compatible(seed, m)

    assert {:error, {:seed_height, 100, 101}} =
             Seed.compatible(seed, range_manifest(Path.join(dir, "export2"), 102))

    assert {:error, {:seed_hash, _, _}} =
             Seed.compatible(seed, put_in(m, ["blocks", "parent"], String.duplicate("0", 64)))

    assert {:error, {:chain, _, _}} = Seed.compatible(seed, Map.put(m, "chain", "testnet4"))

    for mode <- [:reference, :engine, :worker] do
      dest = Path.join(dir, "run-#{mode}")
      assert :ok = Seed.check_destination(dest, [seed_dir, Path.join(dir, "export")])
      assert Seed.clone(seed_dir, dest) >= 0
      refute File.exists?(Seed.path(dest))

      n = open(dest, prep_mode: mode)
      assert State.tip(n.cs).height == 100
      assert State.peek_archive(n.cs, &Seed.describe/1) == d
      connect(n, Enum.drop(bs, 100))
      State.commit_now(n.cs)
      assert digest(n, 101, 150) == fresh_digest, "#{mode}"
      tip = State.tip(n.cs)
      close(n)

      # Restart on the same store.
      n = open(dest, prep_mode: mode)
      assert State.tip(n.cs) == tip
      assert tip.height == 150
      assert digest(n, 101, 150) == fresh_digest
      close(n)
    end

    # The seed itself was never opened for writing by the runs.
    assert File.ls!(Path.join(seed_dir, "index")) |> Enum.sort() == seed_files
    assert {:ok, ^seed} = Seed.read(seed_dir)
  end

  test "destinations overlapping a seed or an export, or holding a seed, are refused", %{
    tmp_dir: dir
  } do
    seed = Path.join(dir, "seed")
    export = Path.join(dir, "export")
    File.mkdir_p!(seed)
    Seed.write(seed, %{"height" => 0})

    assert {:error, {:destination_overlaps, _, _}} = Seed.check_destination(seed, [seed, export])

    assert {:error, {:destination_overlaps, _, _}} =
             Seed.check_destination(Path.join(seed, "x"), [seed])

    assert {:error, {:destination_overlaps, _, _}} = Seed.check_destination(dir, [seed])

    assert {:error, {:destination_overlaps, _, _}} =
             Seed.check_destination(export <> "/", [export])

    assert {:error, {:refused_destination, _}} = Seed.check_destination("/", [])

    other = Path.join(dir, "other-seed")
    File.mkdir_p!(other)
    Seed.write(other, %{"height" => 0})
    assert {:error, {:destination_is_a_seed, _}} = Seed.check_destination(other, [seed])
    assert :ok = Seed.check_destination(Path.join(dir, "seedling"), [seed, export])
    assert_raise ArgumentError, fn -> Seed.clone(seed, other) end
  end
end
