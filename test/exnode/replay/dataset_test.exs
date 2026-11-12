defmodule Exnode.Replay.DatasetTest do
  @moduledoc """
  Replay dataset manifests (`Exnode.Replay.Dataset`) on exports generated
  from the 150-block regtest fixture: a valid export and range export
  validate; truncated, inconsistent, reordered, mislabelled or unknown
  inputs are rejected with a reason, never read as something else.
  """
  use ExUnit.Case, async: true

  alias Exnode.Crypto.Hash
  alias Exnode.Replay.Dataset
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp rec(bin), do: <<byte_size(bin)::32, bin::binary>>

  # Headers 1..150 and blocks from..150 of the fixture in `dir`.
  defp export(dir, from \\ 1, raws \\ nil) do
    raws = raws || BB.read_chain(@chain)
    File.mkdir_p!(dir)
    File.write!(Path.join(dir, "headers.bin"), Enum.map(raws, &rec(binary_part(&1, 0, 80))))
    File.write!(Path.join(dir, "blocks.bin"), raws |> Enum.drop(from - 1) |> Enum.map(&rec/1))
    m = Dataset.build(dir, "regtest", 1, from)
    Dataset.write_manifest(dir, m)
    {m, raws}
  end

  defp edit_manifest(dir, f) do
    {:ok, m} = Dataset.read_manifest(dir)
    Dataset.write_manifest(dir, f.(m))
  end

  test "a full export and a range export validate; a range requires its seed", %{tmp_dir: dir} do
    {m, raws} = export(Path.join(dir, "full"))
    assert {:ok, ^m} = Dataset.validate(Path.join(dir, "full"))
    assert m["seed"] == nil
    assert m["blocks"]["count"] == 150
    assert m["blocks"]["last_hash"] == Hash.to_hex(Dataset.ids(List.last(raws)) |> elem(0))
    assert m["headers"]["work_hex"] != nil

    {r, _} = export(Path.join(dir, "range"), 101)
    assert {:ok, _} = Dataset.validate(Path.join(dir, "range"))
    parent = Hash.to_hex(elem(Dataset.ids(Enum.at(raws, 99)), 0))
    assert r["seed"] == %{"height" => 100, "hash" => parent}
    assert r["blocks"]["parent"] == parent
    assert r["blocks"]["first_height"] == 101 and r["blocks"]["count"] == 50

    # A manifest that drops the seed requirement is inconsistent.
    edit_manifest(Path.join(dir, "range"), &Map.put(&1, "seed", nil))
    assert {:error, {:seed_requirement, nil}} = Dataset.validate(Path.join(dir, "range"))
  end

  test "legacy exports are described explicitly and validated", %{tmp_dir: dir} do
    export(dir)
    File.rm!(Dataset.manifest_path(dir))
    assert Dataset.read_manifest(dir) == :none
    assert {:error, :no_manifest} = Dataset.validate(dir)
    assert {:ok, m} = Dataset.legacy(dir, "regtest")
    assert m["source"]["legacy"] == true
    # The wrong chain: its genesis is not the first block's parent.
    assert {:error, {:invalid_export, msg}} = Dataset.legacy(dir, "testnet4")
    assert msg =~ "does not link"
    assert {:error, {:unsupported_chain, "fakenet"}} = Dataset.legacy(dir, "fakenet")
  end

  test "truncated files are rejected", %{tmp_dir: dir} do
    export(dir)
    path = Path.join(dir, "blocks.bin")
    bin = File.read!(path)

    File.write!(path, binary_part(bin, 0, byte_size(bin) - 7))
    assert {:error, {:invalid_export, msg}} = Dataset.validate(dir)
    assert msg =~ "truncated record"

    # Cut inside the last length prefix.
    last = BB.read_chain(@chain) |> List.last() |> byte_size()
    File.write!(path, binary_part(bin, 0, byte_size(bin) - last - 2))
    assert {:error, {:invalid_export, msg}} = Dataset.validate(dir)
    assert msg =~ "truncated length prefix"

    # Whole records missing: the counts and terminal no longer match.
    File.write!(path, binary_part(bin, 0, byte_size(bin) - last - 4))
    assert {:error, {:block_count, 149, 150}} = Dataset.validate(dir)
  end

  test "inconsistent contents are rejected", %{tmp_dir: dir} do
    {_, raws} = export(dir)
    path = Path.join(dir, "blocks.bin")
    good = File.read!(path)

    # One byte of a tx changed (same length, still linked): only the checksum sees it.
    pos = byte_size(good) - 10
    <<a::binary-size(pos), b, c::binary>> = good
    File.write!(path, <<a::binary, Bitwise.bxor(b, 1), c::binary>>)
    assert {:error, {:block_checksum, _}} = Dataset.validate(dir)
    assert {:ok, _} = Dataset.validate(dir, checksums: false)

    # Two blocks swapped: not linked.
    swapped =
      raws |> List.replace_at(9, Enum.at(raws, 10)) |> List.replace_at(10, Enum.at(raws, 9))

    File.write!(path, Enum.map(swapped, &rec/1))
    assert {:error, {:invalid_export, msg}} = Dataset.validate(dir)
    assert msg =~ "does not link"

    # A block that is not the header file's block at its height.
    File.write!(path, good)
    {:ok, b1} = Exnode.Codec.Block.decode_exact(hd(raws))
    other = BB.build(b1.header, [BB.coinbase(2, 1)])
    File.write!(path, [rec(hd(raws)), rec(other.raw) | Enum.map(Enum.drop(raws, 2), &rec/1)])
    assert {:error, {:invalid_export, msg}} = Dataset.validate(dir)
    assert msg =~ "not the header file's block"

    File.write!(path, good)
    assert {:ok, _} = Dataset.validate(dir)

    # Manifest claims that do not match the files.
    edit_manifest(dir, &put_in(&1, ["blocks", "last_hash"], String.duplicate("0", 64)))
    assert {:error, {:block_terminal, _}} = Dataset.validate(dir)

    edit_manifest(
      dir,
      &put_in(&1, ["blocks", "last_hash"], Hash.to_hex(elem(Dataset.ids(List.last(raws)), 0)))
    )

    edit_manifest(dir, &Map.put(&1, "genesis", String.duplicate("1", 64)))
    assert {:error, {:genesis_mismatch, _}} = Dataset.validate(dir)
    edit_manifest(dir, &Map.merge(&1, %{"chain" => "Mainnet ", "genesis" => "x"}))
    assert {:error, {:unsupported_chain, "Mainnet "}} = Dataset.validate(dir)
    edit_manifest(dir, &Map.put(&1, "format", 2))
    assert {:error, {:unsupported_format, 2}} = Dataset.validate(dir)
    File.write!(Dataset.manifest_path(dir), "{not json")
    assert {:error, {:bad_json, _}} = Dataset.validate(dir)
  end

  test "headers: wrong record length and a broken link are rejected", %{tmp_dir: dir} do
    {_, raws} = export(dir)
    hpath = Path.join(dir, "headers.bin")

    File.write!(hpath, [
      rec(binary_part(hd(raws), 0, 79)) | Enum.map(tl(raws), &rec(binary_part(&1, 0, 80)))
    ])

    assert {:error, {:invalid_export, msg}} = Dataset.validate(dir)
    assert msg =~ "header record of 79 bytes"

    File.write!(hpath, raws |> Enum.drop(1) |> Enum.map(&rec(binary_part(&1, 0, 80))))
    assert {:error, {:invalid_export, msg}} = Dataset.validate(dir)
    assert msg =~ "does not link"
  end
end
