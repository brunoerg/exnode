defmodule Exnode.Replay.Seed do
  @moduledoc """
  Replay seeds (benchmark tooling): a stopped exnode store (`index/` KV
  and `archive/` segments) at height H, produced by ordinary validated
  processing (`scripts/replay.exs ... REPLAY_WRITE_SEED=1` over an export
  of blocks 1..H), with a `seed.json` recording what it is:

  * chain and genesis, tip height and hash, the archive's next ids;
  * `digest`: `effects_digest/3` over heights 0..H, the archived blocks'
    canonical effects (hash, height, first output and input ids, tx count,
    the spent output ids in input order, the coins it overwrote). Two
    stores built from the same blocks agree on it; a different or
    tampered history does not. It checks a clone, it does not prove
    history: `provenance` says how the seed was built (export manifest
    checksum, range, validation mode, exnode revision).

  A seeded run never writes to the seed: `clone/2` copies it into a fresh
  disposable destination first (`cp -a --reflink=auto`), and
  `check_destination/2` refuses a destination that is, contains or lies
  inside the seed or export, or is itself a seed.
  """
  alias Exnode.Archive
  alias Exnode.Crypto.Hash

  @file_name "seed.json"
  @format 1

  def path(dir), do: Path.join(dir, @file_name)

  @doc "Reads `seed.json`: `{:ok, map}` or `{:error, _}`."
  def read(dir) do
    with {:ok, bin} <- File.read(path(dir)),
         {:ok, %{"format" => @format} = m} <- Jason.decode(bin) do
      {:ok, m}
    else
      {:ok, other} -> {:error, {:not_a_seed, other}}
      {:error, :enoent} -> {:error, {:no_seed_json, dir}}
      {:error, e} -> {:error, e}
    end
  end

  def write(dir, m),
    do:
      File.write!(path(dir), Jason.encode_to_iodata!(Map.put(m, "format", @format), pretty: true))

  @doc """
  The canonical effects of the selected chain's blocks at heights
  `from..to` (SHA-256, hex): per block its hash, height, base output and
  input ids, tx count, spent output ids (input order) and overwritten coins.
  """
  def effects_digest(%Archive{} = a, from, to) do
    from..to//1
    |> Enum.reduce(:crypto.hash_init(:sha256), fn h, acc ->
      rec = Archive.block_record!(a, Archive.id_at(a, h))
      undo = rec.undo
      ow = rec |> Map.get(:overwritten, []) |> Enum.sort()

      :crypto.hash_update(acc, [
        rec.hash,
        <<rec.height::32, rec.base_out::64, rec.base_in::64, rec.n_tx::32, length(undo)::32>>,
        for(id <- undo, do: <<id::64>>),
        <<length(ow)::32>>,
        for(id <- ow, do: <<id::64>>)
      ])
    end)
    |> :crypto.hash_final()
    |> Base.encode16(case: :lower)
  end

  @doc """
  Identity of the scripthash index in `kv` (independent of the archive's
  `effects_digest/3`): its tip `height`/`hash` and, with `rows: true`, the
  row count and a SHA-256 over every row of its column family in key
  order (funding, spending, height rows and the tip). The row scan reads
  the whole column family: diagnostic and equivalence runs only.
  """
  def index_identity(kv, opts \\ []) do
    {h, hash} = Exnode.Index.Follower.tip(kv, :scripthash)
    base = %{"height" => h, "hash" => hash && Hash.to_hex(hash)}

    if Keyword.get(opts, :rows, false) do
      add = fn {k, v}, {n, d} ->
        {n + 1, :crypto.hash_update(d, [<<byte_size(k)::32>>, k, <<byte_size(v)::32>>, v])}
      end

      {n, d} =
        Exnode.Store.KV.fold_prefix(kv, :scripthash, "", {0, :crypto.hash_init(:sha256)}, add)

      digest = d |> :crypto.hash_final() |> Base.encode16(case: :lower)
      Map.merge(base, %{"rows" => n, "digest" => digest})
    else
      base
    end
  end

  @doc "What a store's archive says about itself (for `seed.json` and checks)."
  def describe(%Archive{} = a) do
    tip = Archive.tip(a)
    next = Archive.next_ids(a)

    %{
      "height" => tip.height,
      "hash" => Hash.to_hex(tip.hash),
      "next" => %{"block" => next.block, "out" => next.out, "inp" => next.inp},
      "digest" => effects_digest(a, 0, tip.height)
    }
  end

  @doc """
  Checks a seed's `seed.json` against an export manifest it is to be used
  with: same chain and genesis; the seed's tip is the first block's parent.
  """
  def compatible(seed, manifest) do
    b = manifest["blocks"]

    cond do
      seed["chain"] != manifest["chain"] ->
        {:error, {:chain, seed["chain"], manifest["chain"]}}

      seed["genesis"] != manifest["genesis"] ->
        {:error, {:genesis, seed["genesis"]}}

      seed["height"] != b["first_height"] - 1 ->
        {:error, {:seed_height, seed["height"], b["first_height"] - 1}}

      seed["hash"] != b["parent"] ->
        {:error, {:seed_hash, seed["hash"], b["parent"]}}

      true ->
        :ok
    end
  end

  @doc """
  `:ok` if `dest` may be deleted and replaced by a replay: it is not (and
  does not contain, and is not inside) any of `protected` (seed, export,
  source), and is not itself a seed. Else `{:error, reason}`.
  """
  def check_destination(dest, protected) do
    d = Path.expand(dest)

    clash =
      Enum.find(protected, fn p ->
        p = Path.expand(p)
        d == p or String.starts_with?(d, p <> "/") or String.starts_with?(p, d <> "/")
      end)

    cond do
      d in ["/", Path.expand("~")] -> {:error, {:refused_destination, d}}
      clash -> {:error, {:destination_overlaps, d, clash}}
      File.exists?(path(d)) -> {:error, {:destination_is_a_seed, d}}
      true -> :ok
    end
  end

  @doc """
  Copies the seed store `seed` to `dest` (which must not exist), without
  its `seed.json` (the clone is a working store, not a seed). Returns the
  elapsed milliseconds.
  """
  def clone(seed, dest) do
    if File.exists?(dest), do: raise(ArgumentError, "clone destination #{dest} exists")
    t0 = System.monotonic_time(:millisecond)
    File.mkdir_p!(dest)

    for sub <- ["index", "archive"] do
      {_, 0} =
        System.cmd("cp", ["-a", "--reflink=auto", Path.join(seed, sub), Path.join(dest, sub)])
    end

    System.monotonic_time(:millisecond) - t0
  end
end
