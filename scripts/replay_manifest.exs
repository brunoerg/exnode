# Explicit migration of a pre-manifest export (scripts/replay_export.exs
# before 2026-11-09: headers and blocks from height 1, no manifest.json).
# Usage: mix run scripts/replay_manifest.exs <export_dir> <chain>
# Reads and checks both files (Exnode.Replay.Dataset.legacy/2: record
# lengths, continuity from the chain's genesis, block heights against the
# header file), then writes manifest.json with checksums. Refuses to
# overwrite an existing manifest.
alias Exnode.Replay.Dataset

[dir, chain] = System.argv()

case Dataset.read_manifest(dir) do
  :none -> :ok
  _ -> raise "#{dir} already has a manifest.json"
end

case Dataset.legacy(dir, chain) do
  {:ok, m} ->
    m = put_in(m, ["source", "migrated_at"], DateTime.utc_now() |> DateTime.to_iso8601())
    Dataset.write_manifest(dir, m)
    {:ok, _} = Dataset.validate(dir)
    IO.puts("manifest written: #{m["blocks"]["count"]} blocks #{m["blocks"]["first_height"]}..#{m["blocks"]["last_height"]}, terminal #{m["blocks"]["last_hash"]}")

  {:error, r} ->
    IO.puts(:stderr, "not a valid #{chain} export: #{inspect(r)}")
    System.halt(1)
end
