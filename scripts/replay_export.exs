# Exports headers (all, to the copy's best header) and raw blocks from a
# COPY of an exnode datadir (never a live node's: RocksDB refuses a store
# another process has open, and the copy's KV is opened read-write).
# Usage:
#   mix run scripts/replay_export.exs <copy_dir> <out_dir> <max_height> [stats_only]
#   mix run scripts/replay_export.exs <copy_dir> <out_dir> <max_height> --from <h> [--chain <name>]
# Blocks <from>..<max_height> (default from 1); chain default testnet4
# (whitelisted names: Exnode.Replay.Dataset.chain/1). Files:
# <<len::32, bytes>> records, plus manifest.json (Exnode.Replay.Dataset),
# validated after writing. An export with --from > 1 needs a seed store at
# <from> - 1 to be replayed (scripts/replay.exs, REPLAY_SEED).
alias Exnode.{Archive, ChainParams}
alias Exnode.Chain.{HeaderIndex, Headers}
alias Exnode.Crypto.Hash
alias Exnode.Replay.Dataset
alias Exnode.Store.KV

{opts, args, []} = OptionParser.parse(System.argv(), strict: [from: :integer, chain: :string])
[copy, out, max | rest] = args
max = String.to_integer(max)
from = Keyword.get(opts, :from, 1)
stats_only = rest == ["stats_only"]
chain_name = Keyword.get(opts, :chain, "testnet4")
{:ok, chain} = Dataset.chain(chain_name)
p = ChainParams.get(chain)

if from < 1 or from > max, do: raise("bad range #{from}..#{max}")
out_x = Path.expand(out)
copy_x = Path.expand(copy)
if out_x == copy_x or String.starts_with?(out_x, copy_x <> "/"), do: raise("out_dir is inside the source copy")
if File.exists?(Path.join(out, "manifest.json")), do: raise("#{out} already holds an export (manifest.json)")

{:ok, kv} = KV.open(Path.join(copy, "index"))
{:ok, hs} = Headers.start_link(params: p, kv: kv)
idx = Headers.index(hs)
best = idx.best
IO.puts("best header #{best.height}")
a = Archive.open(kv, Path.join(copy, "archive"), nil, p.genesis, cache_bytes: 0)
tip = Archive.tip(a).height
IO.puts("archive tip #{tip}")
if max > tip, do: raise("archive tip #{tip} is below #{max}")

# Tx counts per 5k heights (from the in-memory running totals).
for h0 <- 0..min(tip, 160_000)//5_000, h0 + 5_000 <= tip do
  n = Archive.chain_tx_count(a, h0 + 5_000) - Archive.chain_tx_count(a, h0)
  IO.puts("heights #{h0}..#{h0 + 5_000}: #{n} txs")
end

unless stats_only do
  File.mkdir_p!(out)
  {:ok, hf} = File.open(Path.join(out, "headers.bin"), [:write, :binary, :raw])

  for h <- 1..best.height do
    e = HeaderIndex.lookup(idx, HeaderIndex.hash_at(idx, h))
    :ok = :file.write(hf, <<byte_size(e.raw)::32, e.raw::binary>>)
  end

  :file.close(hf)
  {:ok, bf} = File.open(Path.join(out, "blocks.bin"), [:write, :binary, :raw, {:delayed_write, 8 * 1024 * 1024, 2000}])

  totals =
    Enum.reduce(from..max, %{txs: 0, inputs: 0, outputs: 0, witness_txs: 0, raw_bytes: 0}, fn h, t ->
      raw = Archive.read_block(a, Archive.id_at(a, h))
      # A pruned witness would make the export useless for validation.
      true = is_binary(raw)
      {:ok, b} = Exnode.Codec.Block.decode_exact(raw)
      ^h = HeaderIndex.lookup(idx, b.header.hash).height
      :ok = :file.write(bf, <<byte_size(raw)::32, raw::binary>>)

      %{
        t
        | txs: t.txs + length(b.txs),
          inputs: t.inputs + Enum.sum(for tx <- b.txs, do: length(tx.inputs)),
          outputs: t.outputs + Enum.sum(for tx <- b.txs, do: length(tx.outputs)),
          witness_txs: t.witness_txs + Enum.count(b.txs, & &1.has_witness),
          raw_bytes: t.raw_bytes + byte_size(raw)
      }
    end)

  :file.close(bf)

  m =
    Dataset.build(out, chain_name, 1, from, %{
      "blocks" => Map.new(totals, fn {k, v} -> {Atom.to_string(k), v} end),
      "constraints" => %{
        "full_witness" => true,
        "source_witness_pruned_segments" => Archive.witness_pruned(a) + 1,
        "pruned_blocks" => false
      },
      "benchmark" => %{
        "validation" => "set by the replay (REPLAY_ASSUMEVALID; default: the chain's assumevalid)",
        "indexes" => "none beyond the archive's own (txindex occurrences, spends): no scripthash/filter index"
      },
      "source" => %{
        "datadir" => copy_x,
        "archive_tip_height" => tip,
        "archive_tip_hash" => Hash.to_hex(Archive.tip(a).hash),
        "best_header_height" => best.height,
        "best_header_work_hex" => Integer.to_string(best.chain_work, 16),
        "exported_at" => DateTime.utc_now() |> DateTime.to_iso8601()
      }
    })

  Dataset.write_manifest(out, m)
  {:ok, _} = Dataset.validate(out)
  IO.puts("exported #{best.height} headers, blocks #{from}..#{max}: #{inspect(totals)}; manifest validated")
end
