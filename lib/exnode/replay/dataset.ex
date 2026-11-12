defmodule Exnode.Replay.Dataset do
  @moduledoc """
  Replay datasets (benchmark tooling, `scripts/replay*.exs`): an export
  directory with `headers.bin` and `blocks.bin` (`<<len::32, bytes>>`
  records) and a versioned `manifest.json` describing them.

  A manifest (format #{1}) records the chain and its genesis, the header
  file (count, checksum, first/last height and hash, the work it adds), the
  block file (count, checksum, first/last height and hash, the expected
  parent of the first block, tx/input/output/byte totals), the seed a
  range starting above height 1 requires (height and hash of that parent),
  the full-witness/pruning constraint and the source it was exported from.

  `validate/2` trusts none of it: it re-reads both files, rejects a
  truncated record, a count, size or checksum mismatch, a header not
  linked to its predecessor (or the first one not to the expected parent
  or genesis), a block not at its manifest height, out of order, or not
  the header file's block at that height, and a wrong terminal hash.

  Exports written before manifests (`replay_export.exs` up to 2026-11-09:
  testnet4 only, headers and blocks from height 1) have no manifest.
  `legacy/2` describes one explicitly as a given chain from height 1 and
  validates it the same way; nothing is assumed silently.

  Chain names are whitelisted (`chain/1`); no atom is created from input.
  """
  alias Exnode.ChainParams
  alias Exnode.Consensus.Pow
  alias Exnode.Crypto.Hash

  @format 1
  @chains %{
    "mainnet" => :mainnet,
    "testnet" => :testnet,
    "testnet4" => :testnet4,
    "signet" => :signet,
    "regtest" => :regtest
  }

  def format, do: @format

  @doc "The chain params atom for a whitelisted chain name: `{:ok, atom}` or `{:error, _}`."
  def chain(name) when is_binary(name) do
    case Map.fetch(@chains, name) do
      {:ok, c} -> {:ok, c}
      :error -> {:error, {:unsupported_chain, name}}
    end
  end

  def chain(name), do: {:error, {:unsupported_chain, name}}

  @doc "The whitelisted name of a chain params atom."
  def chain_name(atom), do: Enum.find_value(@chains, fn {n, a} -> if a == atom, do: n end)

  # --- record files --------------------------------------------------------------

  @doc """
  Streams the records of `path` (each `{offset, bytes}`). A record whose
  length prefix or payload is cut short raises `ArgumentError` with the
  offset: a truncated export is rejected, never read as shorter.
  """
  def records(path) do
    Stream.resource(
      fn ->
        {:ok, f} = File.open(path, [:read, :binary, :raw, :read_ahead])
        {f, 0}
      end,
      fn {f, off} ->
        case :file.read(f, 4) do
          {:ok, <<n::32>>} ->
            case :file.read(f, n) do
              {:ok, bin} when byte_size(bin) == n -> {[{off, bin}], {f, off + 4 + n}}
              _ -> raise ArgumentError, "#{path}: truncated record at offset #{off} (length #{n})"
            end

          {:ok, short} ->
            raise ArgumentError,
                  "#{path}: truncated length prefix at offset #{off} (#{byte_size(short)} bytes)"

          :eof ->
            {:halt, {f, off}}
        end
      end,
      fn {f, _} -> File.close(f) end
    )
  end

  @doc "Block hash and parent hash of a serialized header or block."
  def ids(<<header::binary-size(80), _::binary>>) do
    <<_v::32, prev::binary-size(32), _::binary>> = header
    {Hash.hash256(header), prev}
  end

  def ids(_), do: raise(ArgumentError, "record shorter than a header")

  # --- manifest ------------------------------------------------------------------

  def manifest_path(dir), do: Path.join(dir, "manifest.json")

  @doc "Reads `manifest.json`: `{:ok, map}`, `:none` or `{:error, _}`."
  def read_manifest(dir) do
    case File.read(manifest_path(dir)) do
      {:ok, bin} ->
        case Jason.decode(bin) do
          {:ok, %{"format" => @format} = m} -> {:ok, m}
          {:ok, %{"format" => f}} -> {:error, {:unsupported_format, f}}
          {:ok, _} -> {:error, :not_a_manifest}
          {:error, e} -> {:error, {:bad_json, Exception.message(e)}}
        end

      {:error, :enoent} ->
        :none

      {:error, r} ->
        {:error, r}
    end
  end

  def write_manifest(dir, m),
    do: File.write!(manifest_path(dir), Jason.encode_to_iodata!(m, pretty: true))

  @doc """
  Builds the manifest for the files in `dir` by reading them: `chain` (a
  whitelisted name), `headers_from` (the first header's height),
  `blocks_from` (the first block's height), plus `extra` merged in
  (`source`, `constraints`, `benchmark`). Raises if the files are not
  consistent with these heights (the same checks as `validate/2`).
  """
  def build(dir, chain_name, headers_from, blocks_from, extra \\ %{}) do
    {:ok, c} = chain(chain_name)
    p = ChainParams.get(c)
    hs = scan_headers(Path.join(dir, "headers.bin"), headers_from, nil, p)
    bs = scan_blocks(Path.join(dir, "blocks.bin"), blocks_from, hs.hashes)

    m = %{
      "format" => @format,
      "chain" => chain_name,
      "genesis" => Hash.to_hex(p.genesis.header.hash),
      "headers" => %{
        "file" => "headers.bin",
        "count" => hs.count,
        "bytes" => hs.bytes,
        "sha256" => hs.sha256,
        "first_height" => headers_from,
        "parent" => Hash.to_hex(hs.parent),
        "last_height" => headers_from + hs.count - 1,
        "last_hash" => Hash.to_hex(hs.last),
        "work_hex" => Integer.to_string(hs.work, 16)
      },
      "blocks" => %{
        "file" => "blocks.bin",
        "count" => bs.count,
        "bytes" => bs.bytes,
        "sha256" => bs.sha256,
        "first_height" => blocks_from,
        "first_hash" => Hash.to_hex(bs.first),
        "parent" => Hash.to_hex(bs.parent),
        "last_height" => blocks_from + bs.count - 1,
        "last_hash" => Hash.to_hex(bs.last)
      },
      "seed" =>
        if(blocks_from > 1,
          do: %{"height" => blocks_from - 1, "hash" => Hash.to_hex(bs.parent)},
          else: nil
        )
    }

    deep_merge(m, extra)
  end

  @doc """
  Validates the export in `dir` against its manifest (or `manifest` when
  given, e.g. from `legacy/2`). `{:ok, manifest}` or `{:error, reason}`.
  Options: `checksums: false` skips the SHA-256 comparison (the structure
  is still checked).
  """
  def validate(dir, opts \\ []) do
    with {:ok, m} <- Keyword.get_lazy(opts, :manifest, fn -> require_manifest(dir) end) |> wrap(),
         {:ok, c} <- chain(m["chain"]),
         p = ChainParams.get(c),
         :ok <-
           expect(
             m["genesis"] == Hash.to_hex(p.genesis.header.hash),
             {:genesis_mismatch, m["genesis"]}
           ) do
      try do
        h = m["headers"]
        b = m["blocks"]
        parent = if h["first_height"] == 1, do: nil, else: Hash.from_hex(h["parent"])
        hs = scan_headers(Path.join(dir, h["file"]), h["first_height"], parent, p)
        bs = scan_blocks(Path.join(dir, b["file"]), b["first_height"], hs.hashes)
        check = Keyword.get(opts, :checksums, true)

        checks = [
          {hs.count == h["count"], {:header_count, hs.count, h["count"]}},
          {hs.bytes == h["bytes"], {:header_bytes, hs.bytes, h["bytes"]}},
          {not check or hs.sha256 == h["sha256"], {:header_checksum, hs.sha256}},
          {Hash.to_hex(hs.last) == h["last_hash"], {:header_terminal, Hash.to_hex(hs.last)}},
          {h["first_height"] + hs.count - 1 == h["last_height"],
           {:header_last_height, h["last_height"]}},
          {bs.count == b["count"], {:block_count, bs.count, b["count"]}},
          {bs.bytes == b["bytes"], {:block_bytes, bs.bytes, b["bytes"]}},
          {not check or bs.sha256 == b["sha256"], {:block_checksum, bs.sha256}},
          {Hash.to_hex(bs.first) == b["first_hash"], {:block_first, Hash.to_hex(bs.first)}},
          {Hash.to_hex(bs.parent) == b["parent"], {:block_parent, Hash.to_hex(bs.parent)}},
          {Hash.to_hex(bs.last) == b["last_hash"], {:block_terminal, Hash.to_hex(bs.last)}},
          {b["first_height"] + bs.count - 1 == b["last_height"],
           {:block_last_height, b["last_height"]}},
          {seed_ok?(m["seed"], b), {:seed_requirement, m["seed"]}}
        ]

        case Enum.find(checks, fn {ok, _} -> not ok end) do
          nil -> {:ok, m}
          {_, why} -> {:error, why}
        end
      rescue
        e in ArgumentError -> {:error, {:invalid_export, Exception.message(e)}}
      end
    end
  end

  @doc """
  The manifest of a pre-manifest export (headers and blocks from height 1)
  of `chain_name`, built by reading the files: an explicit migration
  (write it with `write_manifest/2`), validated like any other.
  """
  def legacy(dir, chain_name) do
    with {:ok, _} <- chain(chain_name), do: do_legacy(dir, chain_name)
  end

  defp do_legacy(dir, chain_name) do
    try do
      m = build(dir, chain_name, 1, 1, %{"source" => %{"legacy" => true}})
      validate(dir, manifest: m, checksums: false)
    rescue
      e in [ArgumentError, MatchError] -> {:error, {:invalid_export, Exception.message(e)}}
    end
  end

  defp require_manifest(dir) do
    case read_manifest(dir) do
      :none -> {:error, :no_manifest}
      other -> other
    end
  end

  defp wrap({:ok, _} = ok), do: ok
  defp wrap({:error, _} = e), do: e
  defp wrap(%{} = m), do: {:ok, m}

  defp expect(true, _), do: :ok
  defp expect(false, why), do: {:error, why}

  defp seed_ok?(nil, b), do: b["first_height"] == 1

  defp seed_ok?(%{"height" => h, "hash" => hash}, b),
    do: h == b["first_height"] - 1 and hash == b["parent"]

  # Headers from height `from`: each linked to the previous; the first to
  # `parent` (nil: genesis when from == 1). Returns counts, checksum, the
  # work added, and height => hash.
  defp scan_headers(path, from, parent, p) do
    expected0 =
      cond do
        parent -> parent
        from == 1 -> p.genesis.header.hash
        true -> nil
      end

    init = %{
      count: 0,
      bytes: 0,
      sha: :crypto.hash_init(:sha256),
      prev: expected0,
      parent: nil,
      last: nil,
      work: 0,
      hashes: %{}
    }

    r =
      Enum.reduce(records(path), init, fn {off, raw}, acc ->
        if byte_size(raw) != 80,
          do: raise(ArgumentError, "#{path}: header record of #{byte_size(raw)} bytes at #{off}")

        {hash, prev} = ids(raw)

        if acc.prev != nil and prev != acc.prev,
          do: raise(ArgumentError, "#{path}: header at #{off} does not link to its predecessor")

        <<_::binary-size(72), bits::little-32, _::binary>> = raw
        h = from + acc.count

        %{
          acc
          | count: acc.count + 1,
            bytes: acc.bytes + 4 + 80,
            sha: :crypto.hash_update(acc.sha, [<<80::32>>, raw]),
            prev: hash,
            parent: acc.parent || prev,
            last: hash,
            work: acc.work + Pow.bits_proof(bits),
            hashes: Map.put(acc.hashes, h, hash)
        }
      end)

    if r.count == 0, do: raise(ArgumentError, "#{path}: no headers")
    Map.put(r, :sha256, Base.encode16(:crypto.hash_final(r.sha), case: :lower))
  end

  # Blocks from height `from`, consecutive, each the header file's block at
  # its height (so linked); the first one's parent is recorded.
  defp scan_blocks(path, from, header_hashes) do
    init = %{
      count: 0,
      bytes: 0,
      sha: :crypto.hash_init(:sha256),
      prev: nil,
      parent: nil,
      first: nil,
      last: nil
    }

    r =
      Enum.reduce(records(path), init, fn {off, raw}, acc ->
        {hash, prev} = ids(raw)
        h = from + acc.count

        if acc.prev != nil and prev != acc.prev,
          do:
            raise(
              ArgumentError,
              "#{path}: block at #{off} (height #{h}) does not link to its predecessor"
            )

        if Map.get(header_hashes, h) != hash,
          do:
            raise(
              ArgumentError,
              "#{path}: block at #{off} is not the header file's block at height #{h}"
            )

        %{
          acc
          | count: acc.count + 1,
            bytes: acc.bytes + 4 + byte_size(raw),
            sha: :crypto.hash_update(acc.sha, [<<byte_size(raw)::32>>, raw]),
            prev: hash,
            parent: acc.parent || prev,
            first: acc.first || hash,
            last: hash
        }
      end)

    if r.count == 0, do: raise(ArgumentError, "#{path}: no blocks")
    Map.put(r, :sha256, Base.encode16(:crypto.hash_final(r.sha), case: :lower))
  end

  defp deep_merge(a, b) when is_map(a) and is_map(b),
    do:
      Map.merge(a, b, fn _k, x, y -> if is_map(x) and is_map(y), do: deep_merge(x, y), else: y end)
end
