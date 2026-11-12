# Index backfill benchmark: builds the scripthash index of an already
# committed archive, on a disposable clone of a replay seed (the seed is
# never opened). Usage (from the exnode tree to measure):
#   mix run scripts/index_backfill.exs <seed_dir> <fresh_datadir> <label>
#
# Setup, reported apart from the measured interval (setup_ms): the clone,
# the clone's archive identity against seed.json (tip, next ids, effects
# digest), headers and chain-state startup. The clone's index must be empty:
# this measures a clean rebuild from the archive, not a resumed one.
#
# Measured interval (index_ready_ms): from starting the ordinary scripthash
# index process (Exnode.Index.Scripthash, under a registered chain-state
# name, reading through the committed reader) until its tip is the
# archive's tip. The follower writes rows and tip with sync: false, so this
# is index-ready, not a crash-durability point. Fails (exit 1, report on
# stderr) if the index process dies, its tip makes no progress for
# INDEX_STALL_S (default 600) or INDEX_DEADLINE_S (default 3600) passes.
#
# After it: query checks (every output of the tip block's first and last
# txs, and of a middle block's, is in its scripthash's history with the
# exact value), the index's own counters (Scripthash.stats/1), a clean stop
# (index first, then the chain state), and a reopen whose index tip must be
# unchanged. INDEX_DIGEST=1 adds the row count and SHA-256 of the whole
# index column family (Seed.index_identity/2), before the stop and after the
# reopen (they must match). INDEX_WRITE_SEED=1 then makes <fresh_datadir> an
# indexed seed: the source seed.json plus "index" (identity with rows) and
# its provenance.
alias Exnode.{Archive, ChainParams}
alias Exnode.Chain.{Headers, State}
alias Exnode.Index.Scripthash
alias Exnode.Replay.{Dataset, Seed}
alias Exnode.Store.KV

require Logger
Logger.configure(level: :warning)

[seed_dir, datadir, label] = System.argv()

abort = fn why ->
  IO.puts(:stderr, "INDEX BACKFILL FAILED: " <> inspect(%{label: label, reason: why}, limit: :infinity))
  System.halt(1)
end

mono = fn -> System.monotonic_time(:millisecond) end
env_int = fn k, d -> String.to_integer(System.get_env(k, Integer.to_string(d))) end
digest? = System.get_env("INDEX_DIGEST") == "1"

seed =
  case Seed.read(seed_dir) do
    {:ok, s} -> s
    {:error, r} -> abort.({:bad_seed, r})
  end

with {:error, r} <- Seed.check_destination(datadir, [seed_dir]), do: abort.(r)
File.rm_rf!(datadir)
setup = %{seed_clone_ms: Seed.clone(seed_dir, datadir)}

{:ok, chain} = Dataset.chain(seed["chain"])
p = ChainParams.get(chain)
t_o = mono.()
{:ok, kv} = KV.open(Path.join(datadir, "index"))

case Seed.index_identity(kv) do
  %{"height" => -1} -> :ok
  other -> abort.({:index_not_empty, other})
end

{:ok, hs} = Headers.start_link(params: p, kv: kv)
cs_name = :index_backfill_chain_state
idx_name = :index_backfill_scripthash
cs_opts = [name: cs_name, params: p, headers: hs, kv: kv, hot: Path.join(datadir, "archive"), cache_bytes: 0]
{:ok, cs} = State.start_link(cs_opts)
setup = Map.put(setup, :open_ms, mono.() - t_o)

t_s = mono.()
d = State.peek_archive(cs, &Seed.describe/1)

if d["digest"] != seed["digest"] or d["next"] != seed["next"] or d["hash"] != seed["hash"],
  do: abort.({:seed_clone_mismatch, Map.take(d, ["height", "hash"]), Map.take(seed, ["height", "hash"])})

setup = Map.put(setup, :seed_verify_ms, mono.() - t_s)
tip = State.tip(cs)

rss_kib = fn key ->
  case File.read("/proc/self/status") do
    {:ok, t} -> case Regex.run(~r/#{key}:\s+(\d+) kB/, t) do [_, v] -> String.to_integer(v); _ -> 0 end
    _ -> 0
  end
end

cpu = fn ->
  stat = File.read!("/proc/self/stat") |> String.split(") ") |> List.last() |> String.split(" ")
  (String.to_integer(Enum.at(stat, 11)) + String.to_integer(Enum.at(stat, 12))) * 10
end

start_index = fn ->
  {:ok, pid} = GenServer.start(Scripthash, [kv: kv, chain_state: cs_name, name: idx_name], name: idx_name)
  {pid, Process.monitor(pid)}
end

# Waits until the index tip is `hash` (at `height`); fails on a dead index,
# no progress for the stall limit, or the deadline.
wait_index = fn {pid, mref}, height, hash, t_start ->
  stall = env_int.("INDEX_STALL_S", 600) * 1000
  deadline = t_start + env_int.("INDEX_DEADLINE_S", 3600) * 1000

  loop = fn loop, last_h, last_t ->
    receive do
      {:DOWN, ^mref, _, _, reason} -> abort.({:index_died, reason, Seed.index_identity(kv)})
    after
      50 ->
        {h, ih} = Exnode.Index.Follower.tip(kv, :scripthash)
        now = mono.()

        cond do
          h == height and ih == hash -> :ok
          now > deadline -> abort.({:index_deadline, %{index_height: h, target: height}})
          h > last_h -> loop.(loop, h, now)
          now - last_t > stall -> abort.({:index_stalled, %{index_height: h, target: height, alive: Process.alive?(pid)}})
          true -> loop.(loop, last_h, last_t)
        end
    end
  end

  loop.(loop, -2, mono.())
end

parent = self()

sampler =
  spawn_link(fn ->
    loop = fn loop, peak, peak_ix ->
      receive do
        :stop -> send(parent, {:peak, peak, peak_ix})
      after
        200 ->
          m = case Process.whereis(idx_name) do nil -> 0; pid -> elem(Process.info(pid, :memory) || {:memory, 0}, 1) end
          loop.(loop, max(peak, :erlang.memory(:total)), max(peak_ix, m))
      end
    end

    loop.(loop, 0, 0)
  end)

cpu0 = cpu.()
t0 = mono.()
ix = start_index.()
wait_index.(ix, tip.height, tip.hash, t0)
elapsed = mono.() - t0
cpu_ms = cpu.() - cpu0
send(sampler, :stop)
{peak_total, peak_ix} = receive do: ({:peak, a, b} -> {a, b})
stats = Scripthash.stats(idx_name)

# --- after the measured interval ---------------------------------------------
# Query checks: outputs of a few txs, from the archive, against history/2.
query_check = fn ->
  State.peek_archive(cs, fn a ->
    for h <- Enum.uniq([tip.height, div(tip.height, 2)]),
        id = Archive.id_at(a, h),
        {:ok, b} = Archive.read_block_txs(a, id),
        {tx, pos} <- Enum.uniq([{hd(b.txs), 0}, {List.last(b.txs), length(b.txs) - 1}]),
        {o, vout} <- Enum.with_index(tx.outputs),
        reduce: 0 do
      n ->
        rows = Scripthash.history(idx_name, Scripthash.scripthash(o.script_pubkey))
        want = %{kind: :funding, height: h, pos: pos, txid: tx.txid, index: vout, value: o.value}
        unless want in rows, do: abort.({:query_check, h, pos, vout})
        n + 1
    end
  end)
end

checked = query_check.()
identity = Seed.index_identity(kv, rows: digest?)
t_stop = mono.()
:ok = GenServer.stop(idx_name, :normal, :infinity)
Process.unlink(cs)
:ok = GenServer.stop(cs, :normal, :infinity)
stop_ms = mono.() - t_stop

# Reopen: the same index tip (and rows) must be there.
# restart_ms: reopen plus the identity check (with INDEX_DIGEST=1 that is a
# full-CF digest); reopen_ms excludes the check (reopen_check_ms).
t_r = mono.()
{:ok, cs} = State.start_link(cs_opts)
{rpid, rref} = start_index.()
t_c = mono.()
reopened = Seed.index_identity(kv, rows: digest?)
if reopened != identity, do: abort.({:reopen_mismatch, identity, reopened})
reopen_check_ms = mono.() - t_c
:ok = Scripthash.sync_to(idx_name, tip.hash, 60_000)
restart_ms = mono.() - t_r
reopen_ms = restart_ms - reopen_check_ms
Process.demonitor(rref, [:flush])
:ok = GenServer.stop(rpid, :normal, :infinity)
Process.unlink(cs)
:ok = GenServer.stop(cs, :normal, :infinity)
Process.unlink(hs)
:ok = GenServer.stop(hs, :normal, :infinity)
KV.close(kv)

if System.get_env("INDEX_WRITE_SEED") == "1" do
  rev = fn args -> case System.cmd("git", args, stderr_to_stdout: true) do {o, 0} -> String.trim(o); _ -> nil end end
  ident = if digest?, do: identity, else: abort.(:index_write_seed_needs_INDEX_DIGEST)

  Seed.write(datadir, Map.merge(Map.delete(seed, "format"), %{
    "index" => %{"scripthash" => ident,
                 "provenance" => %{"built_by" => "scripts/index_backfill.exs (Exnode.Index.Scripthash follower over the committed archive)",
                                   "from_seed" => Path.basename(seed_dir), "label" => label,
                                   "revision" => %{"head" => rev.(["rev-parse", "--short", "HEAD"])}}}
  }))
end

IO.puts(
  inspect(
    %{
      label: label,
      kind: :index_backfill,
      seed: %{height: seed["height"], digest: binary_part(seed["digest"], 0, 16)},
      setup_ms: setup,
      index_ready_ms: elapsed,
      blocks_per_s: Float.round((tip.height + 1) * 1000 / max(elapsed, 1), 1),
      cpu_ms: cpu_ms,
      peak_total_mib: div(peak_total, 1_048_576),
      peak_index_mib: div(peak_ix, 1_048_576),
      peak_rss_mib: div(rss_kib.("VmHWM"), 1024),
      index: identity,
      query_checks: checked,
      stop_ms: stop_ms,
      restart_ms: restart_ms,
      reopen_ms: reopen_ms,
      reopen_check_ms: reopen_check_ms,
      stats: stats
    },
    limit: :infinity,
    printable_limit: :infinity
  )
)
