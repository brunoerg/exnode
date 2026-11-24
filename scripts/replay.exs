# Replays exported testnet4 blocks into a fresh chain state, as IBD does
# (headers first; blocks deferred and requested, CheckBlock in parallel
# feeders, at most `window` blocks ahead of the tip), then commits.
# Fails (exit 1, with a report on stderr) instead of hanging: a block found
# invalid after a deferred submission ({:block_checked, ...}), a quarantined
# block, a halted chain state, a rejected submission, no tip progress for
# REPLAY_STALL_S seconds (default 300; also the limit for one submission),
# or REPLAY_DEADLINE_S (default 7200) exceeded while waiting for the tip.
# Usage (from the exnode tree to measure):
#   mix run scripts/replay.exs <export_dir> <fresh_datadir> <prefetch> <cache_mib> <label>
# Optional: REPLAY_ASSUMEVALID=0 verifies every script (default: the chain's
# assumevalid, so testnet4's first 40k blocks skip scripts); REPLAY_PIPELINE_DEPTH
# sets the activation plan's block count (exploratory); REPLAY_MAX_BLOCKS
# replays only the first N blocks; REPLAY_PROFILE=1 runs :eprof on the chain
# state (slow: for proportions, not timings) and prints its top functions.
# REPLAY_MIN_HEAP sets the chain state's min heap (words; "0" = none; default:
# the node's default when the tree has one). REPLAY_GC_TRACE=1 sums the chain
# state's GC pauses; REPLAY_LIVE_SAMPLE=<ms> samples its live data by part
# (both diagnostic only). Always reported, after the measured interval: the
# chain state's heap and the node's memory just after the final commit and
# after 2 s idle, the stop time, and the OS peak RSS. The run fails
# unless the final tip hash is the last exported block's.
# (from the exnode tree being measured). <fresh_datadir> is deleted first.
#
# Datasets (2026-11-09): <export_dir> is validated before anything runs
# (Exnode.Replay.Dataset): with a manifest.json, its chain/genesis, record
# lengths, counts, SHA-256 checksums (REPLAY_CHECKSUMS=0 skips only the
# hashing), continuity, expected parent and terminal hashes; without one, it
# is a legacy export, checked as testnet4 headers and blocks from height 1
# (Dataset.legacy/2). An export starting
# above height 1 needs REPLAY_SEED=<seed store at the parent> (a store with
# seed.json, made by REPLAY_WRITE_SEED=1): it is cloned into <fresh_datadir>
# (never written itself) and its tip and effects digest are checked against
# seed.json. The measured interval is the block feed through the final
# durable commit; dataset validation, seed clone/verification, header setup
# and store open are reported separately (setup_ms). After it the chain
# state is stopped and restarted on the same store (the tip must survive),
# and the range's effects digest is printed (equal across modes for the same
# export and seed). REPLAY_WRITE_SEED=1 then makes <fresh_datadir> a seed
# (seed.json with its provenance). REPLAY_MSACC=1 adds microstate
# accounting (diagnostic runs only). OS counters (process CPU and I/O,
# device stats of the datadir's disk) cover the measured interval.
alias Exnode.ChainParams
alias Exnode.Chain.{Headers, State}
alias Exnode.Codec.{Block, Header}
alias Exnode.Replay.{Dataset, Seed}
alias Exnode.Store.KV

require Logger
Logger.configure(level: :warning)

[export, datadir, pf, cache_mib, label] = System.argv()
pf = String.to_integer(pf)
cache = String.to_integer(cache_mib) * 1024 * 1024
window = 1024

abort = fn why ->
  IO.puts(:stderr, "REPLAY FAILED: " <> inspect(%{label: label, reason: why}, limit: :infinity))
  System.halt(2)
end

mono = fn -> System.monotonic_time(:millisecond) end
setup = %{}

# --- dataset -----------------------------------------------------------------
t_v = mono.()
checksums = System.get_env("REPLAY_CHECKSUMS", "1") == "1"

{manifest, dataset_kind} =
  case Dataset.read_manifest(export) do
    {:ok, _} ->
      case Dataset.validate(export, checksums: checksums) do
        {:ok, m} -> {m, :manifest}
        {:error, r} -> abort.({:invalid_export, r})
      end

    :none ->
      IO.puts(:stderr, "legacy export (no manifest.json): checked as testnet4 headers and blocks from height 1")

      case Dataset.legacy(export, "testnet4") do
        {:ok, m} -> {m, :legacy}
        {:error, r} -> abort.({:invalid_export, r})
      end

    {:error, r} ->
      abort.({:bad_manifest, r})
  end

{:ok, chain} = Dataset.chain(manifest["chain"])
p = ChainParams.get(chain)
first_height = manifest["blocks"]["first_height"]
setup = Map.put(setup, :dataset_validate_ms, mono.() - t_v)

# --- destination and seed ----------------------------------------------------
seed_dir = System.get_env("REPLAY_SEED")

case Seed.check_destination(datadir, [export | List.wrap(seed_dir)]) do
  :ok -> :ok
  {:error, r} -> abort.(r)
end

File.rm_rf!(datadir)

{seed, setup} =
  cond do
    manifest["seed"] != nil and seed_dir == nil ->
      abort.({:seed_required, manifest["seed"]})

    manifest["seed"] == nil and seed_dir != nil ->
      abort.({:seed_given_for_an_export_from_genesis, seed_dir})

    seed_dir != nil ->
      s =
        case Seed.read(seed_dir) do
          {:ok, s} -> s
          {:error, r} -> abort.({:bad_seed, r})
        end

      with {:error, r} <- Seed.compatible(s, manifest), do: abort.({:incompatible_seed, r})
      {s, Map.put(setup, :seed_clone_ms, Seed.clone(seed_dir, datadir))}

    true ->
      {nil, setup}
  end

t_h = mono.()

read_records = fn path ->
  Stream.resource(
    fn -> {:ok, f} = File.open(path, [:read, :binary, :raw, :read_ahead]); f end,
    fn f ->
      case :file.read(f, 4) do
        {:ok, <<n::32>>} ->
          {:ok, bin} = :file.read(f, n)
          {[bin], f}

        :eof ->
          {:halt, f}
      end
    end,
    &File.close/1
  )
end

{:ok, kv} = KV.open(Path.join(datadir, "index"))
{:ok, hs} = Headers.start_link(params: p, kv: kv)

read_records.(Path.join(export, "headers.bin"))
|> Stream.map(fn raw -> {h, <<>>} = Header.decode(raw); h end)
|> Stream.chunk_every(2000)
|> Enum.each(fn chunk -> {:ok, _} = Headers.process_headers(hs, chunk) end)

setup = Map.put(setup, :header_setup_ms, mono.() - t_h)

env_int = fn k -> (v = System.get_env(k)) && String.to_integer(v) end

min_heap =
  case System.get_env("REPLAY_MIN_HEAP") do
    # The node's default, when the tree has one (as Exnode.Node applies it).
    nil ->
      if Code.ensure_loaded?(State) and function_exported?(State, :default_min_heap_size, 0),
        do: State.default_min_heap_size()

    "0" ->
      nil

    m ->
      String.to_integer(m)
  end

# REPLAY_MIN_BIN_VHEAP: the chain state's minimum binary virtual heap (words;
# "0" = the VM default; default: the node's default when the tree has one).
min_bin_vheap =
  case System.get_env("REPLAY_MIN_BIN_VHEAP") do
    nil ->
      if Code.ensure_loaded?(State) and function_exported?(State, :default_min_bin_vheap_size, 0),
        do: State.default_min_bin_vheap_size()

    "0" ->
      nil

    m ->
      String.to_integer(m)
  end

av_opt =
  [
    assume_valid: System.get_env("REPLAY_ASSUMEVALID"),
    # Exploratory tuning knobs (absent: the tree's defaults).
    pipeline_depth: env_int.("REPLAY_PIPELINE_DEPTH"),
    script_workers: env_int.("REPLAY_SCRIPT_WORKERS"),
    min_heap_size: min_heap,
    min_bin_vheap_size: min_bin_vheap
  ]
  |> Enum.reject(&is_nil(elem(&1, 1)))

cs_opts = [params: p, headers: hs, kv: kv, hot: Path.join(datadir, "archive"), prefetch_depth: pf, cache_bytes: cache] ++ av_opt

# REPLAY_INDEX=scripthash: the ordinary scripthash index runs during the
# replay (Exnode.Index.Scripthash, following the committed chain through the
# registered chain state's view), and the run also waits until it is ready.
idx? =
  case System.get_env("REPLAY_INDEX") do
    nil -> false
    "scripthash" -> true
    other -> abort.({:unknown_index, other})
  end

idx_digest? = System.get_env("REPLAY_INDEX_DIGEST") == "1"
cs_name = :replay_chain_state
idx_name = :replay_scripthash
cs_opts = if idx?, do: [{:name, cs_name} | cs_opts], else: cs_opts
t_o = mono.()
{:ok, cs} = State.start_link(cs_opts)
setup = Map.put(setup, :open_ms, mono.() - t_o)

# The store's tip must be the export's expected parent (genesis, or the seed).
start_tip = State.tip(cs)

if Exnode.Crypto.Hash.to_hex(start_tip.hash) != manifest["blocks"]["parent"] or start_tip.height != first_height - 1,
  do: abort.({:start_tip, start_tip.height, Exnode.Crypto.Hash.to_hex(start_tip.hash), manifest["blocks"]["parent"]})

setup =
  if seed do
    t_s = mono.()
    d = State.peek_archive(cs, &Seed.describe/1)

    if d["digest"] != seed["digest"] or d["next"] != seed["next"] or d["hash"] != seed["hash"],
      do: abort.({:seed_clone_mismatch, d, Map.take(seed, ["digest", "next", "hash"])})

    Map.put(setup, :seed_verify_ms, mono.() - t_s)
  else
    setup
  end

# The index must start where the archive does: complete at the seed's tip
# (an indexed seed, from an indexed replay with REPLAY_WRITE_SEED=1), or empty
# from genesis. Checked against the seed's recorded index identity (tip; with
# REPLAY_INDEX_DIGEST=1 also every row), outside the measured interval.
setup =
  if idx? do
    t_i = mono.()
    want = seed && get_in(seed, ["index", "scripthash"])
    have = Seed.index_identity(kv, rows: idx_digest? and want != nil)

    cond do
      seed && want == nil -> abort.({:index_seed_required, seed_dir})
      seed && want["height"] != seed["height"] -> abort.({:index_seed_incomplete, want["height"], seed["height"]})
      seed && Map.take(have, Map.keys(have)) != Map.take(want, Map.keys(have)) -> abort.({:index_clone_mismatch, have, want})
      seed == nil and have["height"] != -1 -> abort.({:index_not_empty, have})
      true -> Map.put(setup, :index_verify_ms, mono.() - t_i)
    end
  else
    setup
  end

start_index = fn ->
  {:ok, pid} = GenServer.start(Exnode.Index.Scripthash, [kv: kv, chain_state: cs_name, name: idx_name], name: idx_name)
  {pid, Process.monitor(pid)}
end

ix = if idx?, do: start_index.()

# OS counters: this process (CPU ticks, I/O) and the datadir's disk.
os = fn ->
  stat = File.read!("/proc/self/stat") |> String.split(") ") |> List.last() |> String.split(" ")
  # Fields after "(comm) ": state is index 0, utime 11, stime 12 (clock ticks).
  io =
    case File.read("/proc/self/io") do
      {:ok, t} -> for l <- String.split(t, "\n", trim: true), [k, v] = String.split(l, ": "), into: %{}, do: {k, String.to_integer(v)}
      _ -> %{}
    end

  disk =
    with {src, 0} <- System.cmd("findmnt", ["-no", "SOURCE", "-T", datadir]),
         dev = src |> String.trim() |> Path.basename(),
         base = Regex.replace(~r/^(nvme\d+n\d+)p\d+$|^([a-z]+)\d+$/, dev, "\\1\\2"),
         line when line != nil <-
           File.read!("/proc/diskstats") |> String.split("\n") |> Enum.find(&match?([_, _, ^base | _], String.split(&1))) do
      f = line |> String.split() |> Enum.drop(3) |> Enum.map(&String.to_integer/1)
      at = fn i -> Enum.at(f, i, 0) end
      %{dev: base, writes: at.(4), sectors_written: at.(6), write_ms: at.(7), io_ticks_ms: at.(9),
        reads: at.(0), sectors_read: at.(2), flushes: at.(15), flush_ms: at.(16)}
    else
      _ -> nil
    end

  %{utime: String.to_integer(Enum.at(stat, 11)), stime: String.to_integer(Enum.at(stat, 12)), io: io, disk: disk,
    load: File.read!("/proc/loadavg") |> String.split() |> hd()}
end

os_delta = fn a, b ->
  d = fn x, y -> Map.new(y, fn {k, v} -> {k, if(is_integer(v), do: v - Map.get(x, k, 0), else: v)} end) end

  %{cpu_user_ms: (b.utime - a.utime) * 10, cpu_sys_ms: (b.stime - a.stime) * 10,
    proc_read_bytes: Map.get(b.io, "read_bytes", 0) - Map.get(a.io, "read_bytes", 0),
    proc_write_bytes: Map.get(b.io, "write_bytes", 0) - Map.get(a.io, "write_bytes", 0),
    proc_syscw: Map.get(b.io, "syscw", 0) - Map.get(a.io, "syscw", 0),
    disk: if(a.disk && b.disk, do: d.(a.disk, b.disk)),
    load_start: a.load, load_end: b.load}
end

msacc? = System.get_env("REPLAY_MSACC") == "1"

if msacc? do
  [rt | _] = Path.wildcard(Path.join(to_string(:code.root_dir()), "lib/runtime_tools-*/ebin"))
  Code.append_path(rt)
end

# Peak memory sampler.
parent = self()

# REPLAY_MEM_SERIES=1 also keeps, per 5 s window, the maxima of the chain
# state's memory, the node's binary memory and its total (bytes): to check
# that memory stabilizes over a long range.
series? = System.get_env("REPLAY_MEM_SERIES") == "1"

ix_sampler =
  if idx? do
    view = State.view(cs_name)

    spawn_link(fn ->
      loop = fn loop, lag, mem ->
        receive do
          {:stop, to} -> send(to, {:ix_peak, lag, mem})
        after
          200 ->
            {ih, _} = Exnode.Index.Follower.tip(kv, :scripthash)
            m = case Process.whereis(idx_name) do nil -> 0; pid -> elem(Process.info(pid, :memory) || {:memory, 0}, 1) end
            loop.(loop, max(lag, State.view_committed(view) - ih), max(mem, m))
        end
      end

      loop.(loop, 0, 0)
    end)
  end

sampler =
  spawn_link(fn ->
    t_start = System.monotonic_time(:millisecond)

    loop = fn loop, peak, peak_cs, series ->
      receive do
        :stop -> send(parent, {:peak, peak, peak_cs, Enum.reverse(series)})
      after
        200 ->
          {:memory, m} = Process.info(cs, :memory) || {:memory, 0}
          total = :erlang.memory(:total)

          series =
            if series? do
              w = div(System.monotonic_time(:millisecond) - t_start, 5_000) * 5
              b = :erlang.memory(:binary)

              case series do
                [{^w, a, x, y} | rest] -> [{w, max(a, m), max(x, b), max(y, total)} | rest]
                _ -> [{w, m, b, total} | series]
              end
            else
              series
            end

          loop.(loop, max(peak, total), max(peak_cs, m), series)
      end
    end

    loop.(loop, 0, 0, [])
  end)

profile? = System.get_env("REPLAY_PROFILE") == "1"
max_blocks = String.to_integer(System.get_env("REPLAY_MAX_BLOCKS", "1000000000"))

if profile? do
  # `tools` (eprof) is installed but not on mix's code path.
  [tools | _] = Path.wildcard(Path.join(to_string(:code.lib_dir()), "tools-*/ebin"))
  Code.append_path(tools)
  :eprof.start()
  :eprof.start_profiling([cs], {:_, :_, :_}, set_on_spawn: false)
end

# REPLAY_GC_TRACE=1: the chain state's own GC pauses (minor, major): count,
# total, max, a latency histogram, and for majors the heap figures at start
# (words): young + old heap before and after (reclaimed), and which limit
# was reached (old heap block full, or the old binary vheap over its limit).
gc_tracer =
  if System.get_env("REPLAY_GC_TRACE") == "1" do
    t =
      spawn(fn ->
        bucket = fn us -> cond do us <= 1_000 -> :le_1ms; us <= 10_000 -> :le_10ms; us <= 100_000 -> :le_100ms; true -> :gt_100ms end end
        words = fn info -> Keyword.get(info, :heap_size, 0) + Keyword.get(info, :old_heap_size, 0) end

        loop = fn loop, acc, start ->
          receive do
            {:trace_ts, _, kind, info, ts} when kind in [:gc_minor_start, :gc_major_start] ->
              loop.(loop, acc, {kind, ts, info})

            {:trace_ts, _, kind, info, ts} when kind in [:gc_minor_end, :gc_major_end] ->
              case start do
                {_, t0, i0} ->
                  us = :timer.now_diff(ts, t0)
                  k = if kind == :gc_major_end, do: :major, else: :minor
                  e = Map.get(acc, k, %{n: 0, us: 0, max_us: 0, le_1ms: 0, le_10ms: 0, le_100ms: 0, gt_100ms: 0,
                                       words_before: 0, words_after: 0, vheap_trigger: 0, old_trigger: 0,
                                       max_words_before: 0, bin_vheap_before: 0, young_vheap_full: 0,
                                       bin_vheap_block: 0, bin_old_vheap: 0, bin_old_vheap_block: 0})
                  kv = fn key -> Keyword.get(i0, key, 0) end
                  e = %{e | young_vheap_full: e.young_vheap_full + if(kv.(:bin_vheap_size) >= kv.(:bin_vheap_block_size), do: 1, else: 0),
                            bin_vheap_block: e.bin_vheap_block + kv.(:bin_vheap_block_size),
                            bin_old_vheap: e.bin_old_vheap + kv.(:bin_old_vheap_size),
                            bin_old_vheap_block: e.bin_old_vheap_block + kv.(:bin_old_vheap_block_size)}
                  b = bucket.(us)
                  e = %{e | n: e.n + 1, us: e.us + us, max_us: max(e.max_us, us)} |> Map.update!(b, &(&1 + 1))

                  e =
                    if k == :major do
                      vh = Keyword.get(i0, :bin_old_vheap_size, 0) >= Keyword.get(i0, :bin_old_vheap_block_size, 1)
                      %{e | words_before: e.words_before + words.(i0), words_after: e.words_after + words.(info),
                            max_words_before: max(e.max_words_before, words.(i0)),
                            bin_vheap_before: e.bin_vheap_before + Keyword.get(i0, :bin_vheap_size, 0) + Keyword.get(i0, :bin_old_vheap_size, 0),
                            vheap_trigger: e.vheap_trigger + if(vh, do: 1, else: 0),
                            old_trigger: e.old_trigger + if(vh, do: 0, else: 1)}
                    else
                      %{e | words_before: e.words_before + Keyword.get(i0, :heap_size, 0),
                            words_after: e.words_after + Keyword.get(info, :heap_size, 0),
                            bin_vheap_before: e.bin_vheap_before + Keyword.get(i0, :bin_vheap_size, 0)}
                    end

                  loop.(loop, Map.put(acc, k, e), nil)

                nil ->
                  loop.(loop, acc, nil)
              end

            {:report, to} ->
              send(to, {:gc_report, acc})
          end
        end

        loop.(loop, %{}, nil)
      end)

    :erlang.trace(cs, true, [:garbage_collection, :timestamp, {:tracer, t}])
    t
  end

# REPLAY_LIVE_SAMPLE=<ms>: every <ms>, the chain state's live data by part
# (State :debug_live, a call: it waits for the current turn) and the node's
# memory. Diagnostic only: the call walks the whole state.
rss_kib = fn key ->
  case File.read("/proc/self/status") do
    {:ok, t} -> case Regex.run(~r/#{key}:\s+(\d+) kB/, t) do [_, v] -> String.to_integer(v); _ -> 0 end
    _ -> 0
  end
end

mem_now = fn ->
  m = :erlang.memory()
  %{total: m[:total], processes: m[:processes], binary: m[:binary], ets: m[:ets], rss: rss_kib.("VmRSS") * 1024}
end

live_ms = (v = System.get_env("REPLAY_LIVE_SAMPLE")) && String.to_integer(v)

live_sample = fn ->
  try do
    l = GenServer.call(cs, :debug_live, 30_000)
    bins = case Process.info(cs, :binary) do {:binary, bs} -> bs |> Enum.uniq_by(&elem(&1, 0)); _ -> [] end
    Map.merge(l, %{refc_bins: length(bins), refc_bin_bytes: Enum.sum(for {_, sz, _} <- bins, do: sz)})
    |> Map.merge(Map.new(mem_now.(), fn {k, v} -> {:"mem_#{k}", v} end))
  catch
    :exit, _ -> nil
  end
end

live_sampler =
  if live_ms do
    spawn_link(fn ->
      loop = fn loop, acc ->
        receive do
          {:stop, to} -> send(to, {:live, Enum.reverse(acc)})
        after
          live_ms -> loop.(loop, (s = live_sample.()) && [s | acc] || acc)
        end
      end

      loop.(loop, [])
    end)
  end

{gc0, words0, _} = :erlang.statistics(:garbage_collection)
os0 = os.()
if msacc?, do: :msacc.start()
t0 = System.monotonic_time(:millisecond)
stall_ms = String.to_integer(System.get_env("REPLAY_STALL_S", "300")) * 1000
deadline = t0 + String.to_integer(System.get_env("REPLAY_DEADLINE_S", "7200")) * 1000

# A call that cannot hang the script: {:ok, reply} or :unresponsive.
call = fn msg ->
  try do
    {:ok, GenServer.call(cs, msg, 5_000)}
  catch
    :exit, {:timeout, _} -> :unresponsive
  end
end

height_of = fn hash ->
  case Exnode.Chain.HeaderIndex.lookup(Headers.index(hs), hash) do
    %{height: h} -> h
    nil -> nil
  end
end

# Prints what is known and exits non-zero.
fail = fn why, ctx ->
  failures = Map.get(ctx, :failures, [])
  info = fn msg -> case call.(msg) do {:ok, r} -> r; :unresponsive -> :unresponsive end end

  report = %{
    label: label,
    reason: why,
    phase: Map.get(ctx, :phase),
    submitted: Map.get(ctx, :submitted),
    target_height: Map.get(ctx, :target),
    elapsed_s: div(System.monotonic_time(:millisecond) - t0, 1000),
    tip: info.(:tip) |> then(&if(is_map(&1), do: %{height: &1.height, hash: Exnode.Crypto.Hash.to_hex(&1.hash)}, else: &1)),
    halted: info.(:halted),
    poisoned: info.(:poisoned) |> then(&if(is_list(&1), do: Enum.map(&1, fn h -> {height_of.(h), Exnode.Crypto.Hash.to_hex(h)} end), else: &1)),
    invalid_blocks: for({h, r} <- failures, do: %{height: height_of.(h), hash: Exnode.Crypto.Hash.to_hex(h), result: r}),
    prefetch_stats: info.(:prefetch_stats)
  }

  IO.puts(:stderr, "REPLAY FAILED: " <> inspect(report, limit: :infinity, printable_limit: :infinity))
  System.halt(1)
end

# Every {:block_checked, hash, {:error, _}} delivered so far (Core BlockChecked).
take_failures = fn take_failures, acc ->
  receive do
    {:block_checked, h, {:error, r}} -> take_failures.(take_failures, [{h, r} | acc])
  after
    0 -> Enum.reverse(acc)
  end
end

# Waits until `done?.(tip_height)`, failing on any of the conditions above.
wait_for = fn phase, submitted, target, done? ->
  loop = fn loop, last_h, last_t ->
    now = System.monotonic_time(:millisecond)
    ctx = %{phase: phase, submitted: submitted, target: target}

    case take_failures.(take_failures, []) do
      [] -> :ok
      fs -> fail.("block invalid after deferred submission", Map.put(ctx, :failures, fs))
    end

    case call.(:halted) do
      {:ok, h} when h != false -> fail.("chain state halted: #{inspect(h)}", ctx)
      _ -> :ok
    end

    case call.(:poisoned) do
      {:ok, [_ | _]} -> fail.("block quarantined after a validation crash", ctx)
      _ -> :ok
    end

    {h, last_h, last_t} =
      case call.(:tip) do
        {:ok, %{height: h}} when h > last_h -> {h, h, now}
        {:ok, %{height: h}} -> {h, last_h, last_t}
        :unresponsive -> {last_h, last_h, last_t}
      end

    cond do
      done?.(h) -> :ok
      now > deadline -> fail.("deadline exceeded (REPLAY_DEADLINE_S)", ctx)
      now - last_t > stall_ms -> fail.("no tip progress for #{div(stall_ms, 1000)} s (REPLAY_STALL_S)", ctx)
      true -> (Process.sleep(50); loop.(loop, last_h, last_t))
    end
  end

  loop.(loop, -1, System.monotonic_time(:millisecond))
end

Process.put(:last_hash, nil)

{n, txs, ins} =
  read_records.(Path.join(export, "blocks.bin"))
  |> Stream.take(max_blocks)
  |> Task.async_stream(fn raw ->
       {:ok, b} = Block.decode_exact(raw)
       {b, State.check_block(b, p)}
     end, ordered: true, max_concurrency: 8, timeout: :infinity)
  |> Enum.reduce({0, 0, 0}, fn {:ok, {b, checked}}, {n, t, i} ->
    # A deferred submission only stores the block; a reply slower than the
    # stall limit means the chain state is stuck.
    reply =
      try do
        State.submit_block(cs, b, checked: checked, defer: true, requested: true, source: self(), timeout: stall_ms)
      catch
        :exit, {:timeout, _} -> :timeout
      end

    case reply do
      {:ok, r} when r in [:stored, :connected] ->
        :ok

      other ->
        # Often the consequence of an earlier deferred failure: report those too.
        fail.("submission of block at #{height_of.(b.header.hash)} returned #{inspect(other)}",
              %{phase: :feed, submitted: n, failures: take_failures.(take_failures, [])})
    end

    n = n + 1
    Process.put(:last_hash, b.header.hash)

    # Keep at most `window` blocks ahead of the tip, as BlockDownload does.
    # Heights, not counts: a seeded range starts above height 1.
    top = first_height - 1 + n
    if rem(n, 64) == 0, do: wait_for.(:window, n, top - window, &(top - &1 <= window))

    {n, t + length(b.txs), i + Enum.sum(for tx <- b.txs, do: length(tx.inputs))}
  end)

wait_for.(:final, n, first_height - 1 + n, &(&1 >= first_height - 1 + n))
active_ms = System.monotonic_time(:millisecond) - t0
# Include the final flush.
State.commit_now(cs)
elapsed = System.monotonic_time(:millisecond) - t0
os_m = os_delta.(os0, os.())

# Index-ready: the index tip is the last exported block. Fails (exit 1) on a
# dead index, no index progress for REPLAY_INDEX_STALL_S (default 600) or
# REPLAY_DEADLINE_S passed: an index failure, not a block's invalidity.
{index_ready_ms, os_ix} =
  if idx? do
    {pid, mref} = ix
    target = first_height - 1 + n
    target_hash = Process.get(:last_hash)
    stall = String.to_integer(System.get_env("REPLAY_INDEX_STALL_S", "600")) * 1000

    ix_fail = fn why ->
      IO.puts(:stderr, "REPLAY FAILED: " <> inspect(%{label: label, reason: why, phase: :index,
        index: Seed.index_identity(kv), target_height: target}, limit: :infinity))
      System.halt(1)
    end

    loop = fn loop, last_h, last_t ->
      receive do
        {:DOWN, ^mref, _, _, reason} -> ix_fail.({:index_died, reason})
      after
        20 ->
          {h, ih} = Exnode.Index.Follower.tip(kv, :scripthash)
          now = System.monotonic_time(:millisecond)

          cond do
            h == target and ih == target_hash -> :ok
            now > deadline -> ix_fail.(:deadline_exceeded)
            h > last_h -> loop.(loop, h, now)
            now - last_t > stall -> ix_fail.({:index_stalled, Process.alive?(pid)})
            true -> loop.(loop, last_h, last_t)
          end
      end
    end

    loop.(loop, -2, System.monotonic_time(:millisecond))
    {System.monotonic_time(:millisecond) - t0, os_delta.(os0, os.())}
  else
    {nil, nil}
  end

msacc =
  if msacc? do
    stats = :msacc.stats()
    :msacc.stop()

    # Summed per thread type: ms in each state.
    stats
    |> Enum.group_by(& &1.type)
    |> Map.new(fn {type, ts} ->
      {type, ts |> Enum.map(& &1.counters) |> Enum.reduce(&Map.merge(&1, &2, fn _, x, y -> x + y end))
             |> Map.new(fn {k, v} -> {k, div(v, 1000)} end) |> Map.reject(fn {_, v} -> v == 0 end)}
    end)
  end

terminal = State.tip(cs).hash

gc_report =
  if gc_tracer do
    :erlang.trace(cs, false, [:garbage_collection])
    send(gc_tracer, {:report, self()})
    receive do: ({:gc_report, r} -> r)
  end

if profile? do
  :eprof.stop_profiling()
  :eprof.analyze(:total, sort: :time, filter: [time: 20_000.0])
end

if terminal != Process.get(:last_hash),
  do: fail.("terminal hash #{Exnode.Crypto.Hash.to_hex(terminal)} is not the last exported block", %{phase: :done, submitted: n, target: n})
{gc1, words1, _} = :erlang.statistics(:garbage_collection)
send(sampler, :stop)
{ix_lag_max, peak_ix} = if ix_sampler, do: (send(ix_sampler, {:stop, self()}); receive do: ({:ix_peak, l, m} -> {l, m})), else: {nil, 0}

# The index's own work counters, query checks against the archive (every
# output of the last block's first and last txs and of a middle block's is
# in its scripthash's history with its exact value) and its identity.
{index_stats, index_checks, index_identity} =
  if idx? do
    st = Exnode.Index.Scripthash.stats(idx_name)
    top = first_height - 1 + n

    checks =
      State.peek_archive(cs, fn a ->
        for h <- Enum.uniq([top, div(first_height + top, 2)]),
            id = Exnode.Archive.id_at(a, h),
            {:ok, b} = Exnode.Archive.read_block_txs(a, id),
            {tx, pos} <- Enum.uniq([{hd(b.txs), 0}, {List.last(b.txs), length(b.txs) - 1}]),
            {o, vout} <- Enum.with_index(tx.outputs),
            reduce: 0 do
          k ->
            rows = Exnode.Index.Scripthash.history(idx_name, Exnode.Index.Scripthash.scripthash(o.script_pubkey))
            want = %{kind: :funding, height: h, pos: pos, txid: tx.txid, index: vout, value: o.value}
            unless want in rows, do: fail.("index query check at #{h}/#{pos}/#{vout}", %{phase: :index_check, submitted: n, target: n})
            k + 1
        end
      end)

    {st, checks, Seed.index_identity(kv, rows: idx_digest?)}
  else
    {nil, nil, nil}
  end

# After the final durable commit (outside the measured interval): the chain
# state's heap now, then after 2 s idle (no forced collection), and memory.
heap_info = fn -> Map.new(Process.info(cs, [:heap_size, :total_heap_size, :memory, :garbage_collection])) end
post_flush = Map.merge(heap_info.(), %{mem: mem_now.()})
live_series = if live_sampler, do: (send(live_sampler, {:stop, self()}); receive do: ({:live, l} -> l))
Process.sleep(2_000)
quiescent = Map.merge(heap_info.(), %{mem: mem_now.(), live: if(live_ms, do: live_sample.())})

live_summary =
  if live_series && live_series != [] do
    keys = live_series |> hd() |> Map.keys()
    Map.new(keys, fn k ->
      xs = Enum.sort(for s <- live_series, do: Map.get(s, k, 0))
      {k, %{max: List.last(xs), med: Enum.at(xs, div(length(xs), 2))}}
    end)
    |> Map.put(:samples, length(live_series))
  end
{peak, mem_series} = receive do: ({:peak, a, b, ser} -> {{a, b}, ser})
w = State.work_stats(cs)
# A failure reported after the tip reached n (it cannot be one of these
# blocks, but nothing may go unnoticed).
case take_failures.(take_failures, []) do
  [] -> :ok
  fs -> fail.("block invalid after deferred submission", %{phase: :done, submitted: n, target: n, failures: fs})
end
{_, scripts_stats} = {:ok, GenServer.call(cs, :script_stats)}

# --- after the measured interval: range digest, restart, seed ----------------
last_height = first_height + n - 1
range_digest = State.peek_archive(cs, &Seed.effects_digest(&1, first_height, last_height))
t_r = mono.()
# Observers first: the index reads the chain state's view and the shared KV.
if idx?, do: (Process.demonitor(elem(ix, 1), [:flush]); :ok = GenServer.stop(idx_name, :normal, :infinity))
Process.unlink(cs)
:ok = GenServer.stop(cs, :normal, :infinity)
stop_ms = mono.() - t_r
# reopen_ms: the reopen alone (chain state, index start, index at the
# terminal); reopen_check_ms: the identity/digest checks after it. Both are
# inside restart_ms (stop + reopen + checks, its historical meaning).
t_open = mono.()
check_ms = 0
{:ok, cs} = State.start_link(cs_opts)
restarted = State.tip(cs)

# The reopened index: the same identity, already at the terminal.
ix =
  if idx? do
    ix = start_index.()
    t_c = mono.()
    again = Seed.index_identity(kv, rows: idx_digest?)
    if again != index_identity, do: fail.("restart: index identity changed", %{phase: :restart, submitted: n, target: n})
    Process.put(:reopen_check_ms, mono.() - t_c)
    :ok = Exnode.Index.Scripthash.sync_to(idx_name, restarted.hash, 60_000)
    ix
  end

check_ms = check_ms + (Process.delete(:reopen_check_ms) || 0)

if restarted.hash != terminal or restarted.height != last_height,
  do: fail.("restart: tip #{restarted.height} is not the replayed terminal", %{phase: :restart, submitted: n, target: n})

t_c = mono.()
after_restart = State.peek_archive(cs, &Seed.effects_digest(&1, first_height, last_height))
if after_restart != range_digest, do: fail.("restart: range digest changed", %{phase: :restart, submitted: n, target: n})
check_ms = check_ms + (mono.() - t_c)
restart_ms = mono.() - t_r
reopen_ms = mono.() - t_open - check_ms

rev = fn args -> case System.cmd("git", args, stderr_to_stdout: true) do {o, 0} -> String.trim(o); _ -> nil end end

revision = %{
  head: rev.(["rev-parse", "--short", "HEAD"]),
  tracked_diff_sha: (d = rev.(["diff", "HEAD"])) && Base.encode16(:crypto.hash(:sha256, d), case: :lower) |> binary_part(0, 12),
  untracked_lib_files: (u = rev.(["ls-files", "--others", "--exclude-standard", "lib"])) && length(String.split(u, "\n", trim: true))
}

if System.get_env("REPLAY_WRITE_SEED") == "1" do
  d = State.peek_archive(cs, &Seed.describe/1)

  Seed.write(datadir, Map.merge(d, %{
    "chain" => manifest["chain"],
    "genesis" => manifest["genesis"],
    "provenance" => %{
      "built_by" => "scripts/replay.exs (ordinary validated processing: CheckBlock, ConnectBlock, archive commits)",
      "export_blocks_sha256" => manifest["blocks"]["sha256"],
      "export_kind" => Atom.to_string(dataset_kind),
      "blocks" => [first_height, last_height],
      "from_seed" => seed && seed["provenance"],
      "assume_valid" => System.get_env("REPLAY_ASSUMEVALID", "chain default"),
      "revision" => Map.new(revision, fn {k, v} -> {Atom.to_string(k), v} end),
      "label" => label
    }
  }))
end

if idx?, do: (Process.demonitor(elem(ix, 1), [:flush]); :ok = GenServer.stop(idx_name, :normal, :infinity))
Process.unlink(cs)
:ok = GenServer.stop(cs, :normal, :infinity)
Process.unlink(hs)
:ok = GenServer.stop(hs, :normal, :infinity)
KV.close(kv)

IO.puts(
  inspect(
    %{
      label: label,
      assume_valid: System.get_env("REPLAY_ASSUMEVALID", "default"),
      dataset: %{chain: manifest["chain"], kind: dataset_kind, first_height: first_height, last_height: last_height,
                 seed: seed && %{height: seed["height"], digest: binary_part(seed["digest"], 0, 16)}},
      setup_ms: setup,
      restart_ms: restart_ms,
      reopen_ms: reopen_ms,
      reopen_check_ms: check_ms,
      stop_ms: stop_ms,
      index: if(idx?, do: %{active_ms: active_ms, durable_ms: elapsed, ready_ms: index_ready_ms, lag_max_blocks: ix_lag_max,
                            peak_index_mib: div(peak_ix, 1_048_576), os_to_ready: os_ix, stats: index_stats,
                            query_checks: index_checks, identity: index_identity}),
      min_heap: min_heap,
      min_bin_vheap: min_bin_vheap,
      word_size: :erlang.system_info(:wordsize),
      peak_rss_mib: div(rss_kib.("VmHWM"), 1024),
      post_flush: post_flush,
      quiescent: quiescent,
      live: live_summary,
      mem_series: if(series?, do: for({w, a, x, y} <- mem_series, do: [w, div(a, 1_048_576), div(x, 1_048_576), div(y, 1_048_576)])),
      range_digest: range_digest,
      revision: revision,
      runtime: %{otp: System.otp_release(), elixir: System.version(), schedulers: System.schedulers_online(),
                 dirty_cpu: :erlang.system_info(:dirty_cpu_schedulers_online), dirty_io: :erlang.system_info(:dirty_io_schedulers)},
      os: os_m,
      msacc: msacc,
      terminal: Exnode.Crypto.Hash.to_hex(terminal),
      blocks: n,
      txs: txs,
      inputs: ins,
      elapsed_ms: elapsed,
      inputs_per_s: round(ins * 1000 / elapsed),
      blocks_per_s: Float.round(n * 1000 / elapsed, 1),
      peak_total_mib: div(elem(peak, 0), 1024 * 1024),
      peak_chain_state_mib: div(elem(peak, 1), 1024 * 1024),
      gc_count: gc1 - gc0,
      gc_words_reclaimed_m: div(words1 - words0, 1_000_000),
      scripts: scripts_stats,
      prefetch: Map.reject(w.prefetch, fn {_, v} -> v == 0 end),
      chain_state: Map.reject(w.chain_state, fn {_, v} -> v == 0 end),
      pipeline: Map.get(w, :pipeline),
      exec: Map.get(w, :exec),
      chain_state_gc: gc_report
    },
    limit: :infinity,
    printable_limit: :infinity
  )
)
