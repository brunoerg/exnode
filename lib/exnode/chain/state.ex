defmodule Exnode.Chain.State do
  @moduledoc """
  Chain state: owns the archive and decides which blocks count. Mirrors
  Core v32.1 `Chainstate::ActivateBestChain`, `ConnectTip`, `DisconnectTip`
  and `InvalidBlockFound`.

  * Received blocks are kept in memory until connected (`submit_block/3`).
  * After each submission, the chain moves to the most-work candidate whose
    blocks are all available and not failed, preferring the earliest
    activatable body at equal work (Core nSequenceId). Candidates include
    pending blocks and archived-but-disconnected blocks, rebuilt at startup.
  * A block failing validation is marked failed in the header tree, unless
    the failure is MUTATED (Core does not mark those), and activation is
    retried so the node can fall back to another branch.

  Validation per block: `CheckBlock` + `ContextualCheckBlockHeader` (already
  done at header acceptance) + `ContextualCheckBlock` + `ConnectBlock`.

  Batching (Core `FlushStateToDisk` role): connected blocks stay in the
  archive's in-memory batch and are committed together (`commit/1`) when the
  batch reaches `@batch_blocks` blocks or `@batch_bytes` (options
  `:batch_blocks` / `:batch_bytes`), when the oldest is
  `@batch_ms` old (`@batch_ms_behind` while the tip is at least
  `@near_tip_blocks` behind the best header, option `:near_tip_blocks`),
  when the tip reaches the best
  header, before any
  disconnect or rejection, and on shutdown. A block's `pending` copy is
  deleted in the same KV batch that commits it, so a crash loses nothing
  that cannot be reconnected from `pending`. The shadow monitor gets blocks
  only once they are committed.

  Quarantine: an exception (not a consensus `{:error, _}`) while connecting
  a block is contained to that block. It is our bug or corrupt data, not
  proof the block is invalid, so its header is NOT marked failed (as with
  MUTATED). Instead the block is quarantined: a durable mark in the
  `poisoned` column family (fsynced), a `:critical` log, and a crash report
  in `<chain dir>/crashes/<hash>.log` with the block's hex. A quarantined
  block is never an activation candidate, is skipped by `load_pending` at
  start-up (so a restart cannot replay the crash), and is refused at once if
  received again, without being decoded or validated. The node stays up and
  stops below that block until an operator clears the mark
  (`reconsider_poisoned/2`, or `mix exnode.reconsider` while stopped); its
  `pending` copy is kept so it can then be retried without a download.
  """
  use GenServer
  require Logger

  alias Exnode.Archive
  alias Exnode.Chain.{HeaderIndex, Headers, Prefetch}
  alias Exnode.Codec.Block
  alias Exnode.Consensus.Pow
  alias Exnode.Validation.Block, as: BlockRules
  alias Exnode.Validation.Connect
  alias Exnode.Validation.Prepare
  alias Exnode.Validation.ScriptExec

  @batch_blocks 128
  # KV `meta` key of the durable halt mark.
  @halt_key "halt"
  @batch_bytes 64 * 1024 * 1024
  @batch_ms 5_000
  # Far behind the best header (IBD), the age rule waits this long instead:
  # the block and byte limits set the commit cadence, as Core flushes by
  # cache size during IBD, not on a short timer. Every commit voids the
  # prefetched answers still in flight (Chain.Prefetch), so a 5 s cadence
  # on slow blocks left prefetch nothing it could use. This only bounds how
  # long a stalled download leaves blocks uncommitted.
  @batch_ms_behind 300_000
  # How far behind the best header the tip must be for `@batch_ms_behind`.
  # Its own setting, not `batch_blocks`: a larger batch (--batch-blocks 2048)
  # made the 5 s age rule start 2048 blocks out, and on that last stretch
  # each commit voided prefetch's answers (mainnet: 3.3 -> 1.1 blk/s).
  @near_tip_blocks 128
  @gc_bytes 256 * 1024 * 1024
  # Blocks the prefetch stage prepares ahead of the one being connected
  # (0 disables it). On by default: on a mainnet sync bound by input
  # lookups (USB SSD, below assumevalid), depth 8 raised inputs connected
  # per second by about 28%. Core's counterpart,
  # -prevoutfetchthreads, is also on by default (8 threads).
  @prefetch_depth 8
  # Core ActivateBestChainStep: at most 32 blocks are connected before
  # cs_main is released (validation.cpp, `nHeight + 32`). Here: blocks per
  # deferred activation step before the chain state serves its mailbox.
  @activation_step 32
  # Activation plan bounds: prepared, unretired blocks (scripts of up to this
  # many in flight, as the old pipeline); their estimated retained bytes plus
  # ready prefetch results; and the time budget of one activation turn.
  @pipeline_depth 8
  @pipeline_bytes 256 * 1024 * 1024
  @turn_ms 50
  # Core MIN_BLOCKS_TO_KEEP (validation.h): an unrequested block further above
  # the tip than this is not stored (AcceptBlock fTooFarAhead).
  @min_blocks_to_keep 288

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  Submits a block (decoded `%Block{}`). Returns
  `{:ok, :connected | :stored | :duplicate | :skipped}` or `{:error, {result, reason}}`.
  `:stored` means valid so far but not (yet) on the best chain. `:skipped`
  means an unrequested block was not stored (Core `AcceptBlock` returns true
  without writing it): its chain has less work than the active tip, it is
  more than 288 blocks (`MIN_BLOCKS_TO_KEEP`) above the tip, or its work is
  below `minimum_chain_work`. Not a failure: the block is not checked or
  marked, and the peer is not punished.

  The header is accepted with Core's BLOCK-message `min_pow_checked`: the
  parent's work plus the block's proof must reach the anti-DoS threshold
  (`HeaderIndex.anti_dos_work_threshold/2` on the active tip), else
  `{:error, {:header_low_work, "too-little-chainwork"}}`, requested or not.

  Options:
  * `checked:` the result of `check_block/2`, run by the caller.
  * `requested:` (default false) the block was asked for (Core `fRequested`
    / `force_processing`: in flight in `BlockDownload`, or rebuilt from a
    compact block). A requested block skips the three storage gates above.
  * `defer: true` (block download in IBD): the block is checked and stored
    (Core `AcceptBlock`) and the reply is sent at once, `{:ok, :stored}`;
    connection runs afterwards in steps of `@activation_step` blocks (Core
    `ActivateBestChainStep`), with submissions served between steps, so
    peers keep downloading while blocks connect. A block that then fails
    validation is reported to `source:` (a pid) as
    `{:block_checked, hash, {:error, {result, reason}}}`, as Core's
    `BlockChecked` punishes the peer recorded in `mapBlockSource`.
  """
  def submit_block(server, %Block{} = b, opts \\ []) do
    o = %{
      checked: Keyword.get(opts, :checked),
      defer: Keyword.get(opts, :defer, false),
      requested: Keyword.get(opts, :requested, false),
      source: Keyword.get(opts, :source)
    }

    GenServer.call(server, {:submit, b, o}, Keyword.get(opts, :timeout, :infinity))
  end

  @doc """
  Cheap P2P preflight before parallel CheckBlock: `:check`, or the duplicate,
  quarantine, header-error or storage-gate reply submission would return.
  Submission repeats these checks, since the tip can change in between.
  """
  def precheck_block(server, header, requested),
    do: GenServer.call(server, {:precheck_block, header, requested}, :infinity)

  @doc """
  Core `CheckBlock` for `b`, run by the caller (a peer process, in parallel
  with other peers) instead of the chain state. Pass the result to
  `submit_block/3` as `checked:`; the chain state uses it at the point where
  it would call `CheckBlock`, so the rule order is unchanged.
  """
  def check_block(%Block{} = b, p),
    do: BlockRules.check_block(b, p, signet_check: &Exnode.Validation.Signet.check(&1, p))

  @doc """
  Prefetch counters since start (tests, diagnostics): blocks whose answers
  were `used` (same epoch), `revalidated` over one commit (`reval_dropped`
  answers dropped), `stale`, or `none` (no prefetch for the block).
  """
  def prefetch_stats(server), do: GenServer.call(server, :prefetch_stats, 5_000)

  @doc """
  Work counters since start (tests, diagnostics): `%{prefetch: w,
  chain_state: c}`. `w` adds up the prefetch workers' results (taken, stale
  or not): `considered`, `omitted` (answered by the overlay hint, not looked
  up), `sent`, their archive read counters and `worker_us` (busy time of
  concurrent tasks: overlapping, not elapsed time). `c` is the chain-state
  process's own `Exnode.Archive.take_stats/0` counters (its committed
  lookups and reads, and commit timing), plus its per-block totals:
  `blocks`, `block_bytes`, `inputs`, `validate_us` (preparation: checks and
  the non-script ConnectBlock), `resolve_us`, `scripts_wait_us` (script
  latency per block, prepared to scripts done: overlapping, not elapsed
  time), `append_us` (`Archive.connect`) and `pfwait_us`.

  `pipeline` is the activation plan's: `turns`, `turn_us`, `turn_max_us`
  (callback service time of activation turns), `submits`, `submit_us`,
  `submit_max_us`, `items_hwm`, `bytes_hwm` (estimated retained bytes,
  items plus ready prefetch results), `prefetch_hwm`, `turn_retired_max`,
  `head_wait_us` (the oldest unretired block waiting for its own scripts),
  `retire_wait_us` (done to retired: out-of-order completions waiting for
  the head), `scripts_latency_us`, `waits_head_scripts` / `waits_other`
  (turns that ended waiting), `extensions`, `stale_results` and the workers'
  own `script_jobs`, `script_txs`, `script_native_us` (exported with each
  result). `exec` is `ScriptExec.stats/1`: workers, running and queued now,
  high-water marks, done, native time, cancellations, lost workers.

  Preparation (in `pipeline`): `prep_rules_us` (CheckBlock and
  contextual checks), `prep_connect_us` (the non-script ConnectBlock of the
  mode: `connect_block`, or population and inline checks, or population
  only), `prep_populate_us`, `prep_context_us` (MTP capture),
  `prep_check_us` (inline pure checks); with the worker `prep_jobs`,
  `prep_handoff_bytes`, `prep_worker_us`, `prep_roundtrip_us`, `prep_stale`
  (the outstanding job's result for an item no longer preparing) and
  `prep_unknown` (results that were not the outstanding job's: ignored).
  `chain_state` also has `Exnode.Validation.Connect.take_stats/0`
  (`perf_bip30_us`, BIP30 and prevout-age counts) and the archive's append,
  commit and resolution attribution (`Exnode.Archive.take_stats/0`).
  """
  def work_stats(server), do: GenServer.call(server, :work_stats, 5_000)

  @doc "Blocks prefetched ahead when the caller does not set `prefetch_depth`."
  def default_prefetch_depth, do: @prefetch_depth

  @doc "Default commit batch limits: `{blocks, bytes}`."
  def default_batch_limits, do: {@batch_blocks, @batch_bytes}

  @doc """
  The node's chain-state minimum heap (words, 384 MiB). The activation plan
  retains several decoded blocks, prefetch results and deltas; with the
  default heap the chain state spent 6.9 s of a 41 s full-script replay in
  GC, 2.2 s with 16 MiB. During mainnet IBD (around height 900k) its live
  data is 200-700 MiB: with a 16 MiB floor it collected 72 minor and 22
  major times per 30 s, 11.2 s in all; with 384 MiB, 30 and 4.5 times,
  5.1 s (1 GiB did no better). Not applied to chain states started without
  `min_heap_size` (tests), so many can run at once.
  """
  def default_min_heap_size, do: div(384 * 1024 * 1024, :erlang.system_info(:wordsize))

  @doc """
  The node's chain-state minimum binary virtual heap (words). The chain
  state receives decoded blocks (submissions, prefetch results): a message
  copy gives every sub-binary over 64 bytes (each `tx.raw`, long witness
  items and scripts) its own reference to the block, and each reference
  charges the whole block to the process's binary virtual heap, so the
  charge is about one block per such field. With the VM default this
  overcount triggered most collections (in one measured window, 285 of 318
  major and about half of the minor ones). This floor is far above any
  overcount, so binaries are released by the heap-driven collections and
  the explicit collection after every 256 MiB of submitted blocks. Not
  applied to chain states started without `min_bin_vheap_size` (tests).
  """
  def default_min_bin_vheap_size, do: 10_000_000_000

  def tip(server), do: GenServer.call(server, :tip, :infinity)
  def have_block?(server, hash), do: GenServer.call(server, {:have?, hash}, 5_000)

  @doc "The subset of `hashes` whose block data we have (in memory or archived)."
  def have_many(server, hashes), do: GenServer.call(server, {:have_many, hashes}, :infinity)

  @doc """
  The chain view: a public ETS table with the tip and the set of blocks held
  in memory, plus the KV handle. Other processes read it without calling the
  (often busy) chain-state process. `server` must be a registered name.
  """
  def view(server) when is_atom(server), do: :persistent_term.get({__MODULE__, server}, nil)

  @doc "A read-only archive (committed blocks only) for serving, from the view."
  def view_reader(view), do: :ets.lookup_element(view, :reader, 2)

  @doc """
  The read-only archive of `server`'s committed chain, without a call into
  the chain-state process (RPC, REST and peers read through it, in
  parallel with block processing; Core takes `cs_main` instead). Its
  `Archive.tip/1` is the committed tip: everything up to it is readable.
  """
  def reader(server), do: view_reader(view(server))

  @doc "Height of the last committed (durable) tip, and halt reason (false if none), from the view."
  def view_committed(view), do: :ets.lookup_element(view, :committed, 2)
  def view_halted(view), do: :ets.lookup_element(view, :halted, 2)

  @doc "Tip from the view (no call into the chain-state process)."
  def view_tip(view), do: :ets.lookup_element(view, :tip, 2)

  @doc """
  Core `IsInitialBlockDownload`, the one answer for peers and RPC: the
  tip's work is below the chain's minimum, or the tip is older than 24 h
  at `now` (seconds). Once false it stays false for this chain state's
  life (Core `m_cached_finished_ibd`), latched in the view. Peers and RPC
  used to compute it apart (RPC without the work check, on the committed
  tip), unlatched: an old tip flipped them back into IBD. `idx` is the header index.
  """
  def view_ibd?(view, idx, now, params) do
    if :ets.member(view, :ibd_done) do
      false
    else
      ibd =
        case HeaderIndex.lookup(idx, view_tip(view).hash) do
          nil -> true
          e -> e.chain_work < params.minimum_chain_work or e.time < now - 24 * 3600
        end

      if not ibd, do: :ets.insert(view, {:ibd_done, true})
      ibd
    end
  end

  @doc """
  Subset of `hashes` whose block data is held in memory, archived (see
  `Archive.have_block_data?/2`), or quarantined (its body stays in
  `pending`; fetching it again cannot help until the quarantine is cleared)
  (no call).
  """
  def view_have_many(view, hashes) do
    reader = view_reader(view)

    MapSet.new(
      Enum.filter(hashes, fn h ->
        :ets.member(view, {:held, h}) or :ets.member(view, {:quarantined, h}) or
          Archive.have_block_data?(reader, h)
      end)
    )
  end

  @doc "Runs `fun.(archive)` inside the chain-state process (the archive's file handles belong to it)."
  def with_archive(server, fun), do: GenServer.call(server, {:with_archive, fun}, :infinity)

  @doc false
  # Test only: runs `fun.(archive)` without committing the batch first.
  def peek_archive(server, fun), do: GenServer.call(server, {:peek_archive, fun}, :infinity)

  @doc """
  The mempool's view of the chain (Core `CCoinsViewCache` at the tip):
  `{tip, %{outpoint => {:ok, coin} | :missing}}`. Reads through the batch and
  overlay, without committing. Waits with no timeout, as Core's mempool
  holds `cs_main` (the mempool must not restart because a block is slow).
  """
  def mempool_view(server, outpoints) do
    # An outpoint no transaction can have (vout not a uint32) is missing,
    # never sent: the overlay NIF raises on it, inside this server.
    {ok, bad} = Enum.split_with(outpoints, fn {_, v} -> is_integer(v) and v in 0..0xFFFFFFFF end)
    {tip, found} = GenServer.call(server, {:mempool_view, ok}, :infinity)
    {tip, Enum.reduce(bad, found, &Map.put(&2, &1, :missing))}
  end

  @doc """
  Clears quarantine marks (`:all` or one block hash) once the cause is
  fixed. A cleared block still in `pending` is held again and activation
  retried; otherwise it is downloaded again like any missing block. Returns
  the hashes cleared.
  """
  def reconsider_poisoned(server, which \\ :all),
    do: GenServer.call(server, {:reconsider_poisoned, which}, :infinity)

  @doc "The quarantined block hashes."
  def poisoned(server), do: GenServer.call(server, :poisoned, 5_000)

  @doc """
  Clears a durable halt (shadow divergence):
  deletes the mark and resumes block connection, held blocks included.
  Returns the halt reason cleared, or `:not_halted`. Only an operator should
  call it, after deciding which engine was wrong (see the divergence
  records); `mix exnode.reconsider --clear-halt` does the same offline.
  """
  def clear_halt(server), do: GenServer.call(server, :clear_halt, :infinity)

  @doc "The durable halt mark in `kv`: `%{reason, time, height, hash}` or nil."
  def halt_mark(kv) do
    case Exnode.Store.KV.get(kv, :meta, @halt_key) do
      {:ok, bin} -> :erlang.binary_to_term(bin)
      :not_found -> nil
    end
  end

  @doc "Commits the archive batch now."
  def commit_now(server), do: GenServer.call(server, :commit, :infinity)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    # Optional GC tuning (words), e.g. for a plan that retains several decoded
    # blocks (default_min_heap_size/0, default_min_bin_vheap_size/0).
    if n = opts[:min_heap_size], do: Process.flag(:min_heap_size, n)
    if n = opts[:min_bin_vheap_size], do: Process.flag(:min_bin_vheap_size, n)
    # The perf line's garbage collection figures (node only: GcProbe).
    if opts[:gc_probe], do: Process.put(:gc_probe, Exnode.Chain.GcProbe.start())
    p = Keyword.fetch!(opts, :params)
    headers = Keyword.fetch!(opts, :headers)
    kv = Keyword.fetch!(opts, :kv)

    a =
      Archive.open(
        kv,
        Keyword.fetch!(opts, :hot),
        Keyword.get(opts, :cold),
        p.genesis,
        [
          max: opts[:segment_max],
          cache_bytes: opts[:cache_bytes],
          prune_keep: if(opts[:prune_witness], do: Keyword.get(opts, :prune_keep, 288)),
          segwit_height: p.segwit_height
        ]
        |> Enum.reject(&is_nil(elem(&1, 1)))
      )
      |> note_durable()

    st = %{
      p: p,
      headers: headers,
      a: a,
      kv: kv,
      # Hashes of blocks received but not yet connected. The block data
      # lives on disk in the `pending` column family (as Core's AcceptBlock
      # writes received blocks to blk*.dat), not in memory.
      blocks: MapSet.new(),
      assume_valid: Exnode.Validation.AssumeValid.resolve(Keyword.get(opts, :assume_valid), p),
      script_stats: %{checked: 0, skipped: 0},
      rule_override: Keyword.get(opts, :rule_override),
      # Test only: never verify scripts (to inject a divergence).
      test_skip_scripts: Keyword.get(opts, :test_skip_scripts, false),
      # Test only: called inside each block's script task (to inject a task crash).
      test_script_hook: Keyword.get(opts, :test_script_hook),
      # Test only: called after Archive.connect (to inject an archive crash
      # once its side effects have happened).
      test_archive_hook: Keyword.get(opts, :test_archive_hook),
      # Quarantined block hashes (the durable `poisoned` marks), and where
      # crash reports go.
      poisoned: MapSet.new(),
      crash_dir:
        Keyword.get_lazy(opts, :crash_dir, fn ->
          Path.join(Path.dirname(Keyword.fetch!(opts, :hot)), "crashes")
        end),
      monitor: Keyword.get(opts, :shadow_monitor),
      halted: false,
      round_connected: [],
      round_rejected: [],
      # Connected, not yet committed: [{hash, raw}], newest first.
      uncommitted: [],
      batch_blocks: Keyword.get(opts, :batch_blocks, @batch_blocks),
      batch_bytes: Keyword.get(opts, :batch_bytes, @batch_bytes),
      batch_ms: Keyword.get(opts, :batch_ms, @batch_ms),
      batch_ms_behind: Keyword.get(opts, :batch_ms_behind, @batch_ms_behind),
      near_tip_blocks: Keyword.get(opts, :near_tip_blocks, @near_tip_blocks),
      # Blocks prepared ahead by Chain.Prefetch (0 disables it).
      prefetch_depth: Keyword.get(opts, :prefetch_depth, @prefetch_depth),
      pf: nil,
      # Cumulative; the perf line shows each window's (pf_logged: at the last line).
      pf_stats: %{used: 0, revalidated: 0, reval_dropped: 0, stale: 0, none: 0},
      pf_logged: %{used: 0, revalidated: 0, reval_dropped: 0, stale: 0, none: 0},
      # Cumulative work counters (work_stats/1); the perf line shows each window's.
      pf_work: %{},
      cs_work: %{},
      pf_window: %{},
      catch_up_chunk: Keyword.get(opts, :catch_up_chunk, 128),
      # Test only (crash tests): do not commit just because the tip reached the best header.
      commit_at_tip: Keyword.get(opts, :commit_at_tip, true),
      # Core CBlock::fChecked: CheckBlock passed at submission.
      checked: MapSet.new(),
      # Activation runs as a persistent plan driven by `:drive` turns (see
      # "activation" below): at most `activation_step` retirements or
      # preparations, or `turn_ms`, per turn; block hash => source pid (Core
      # mapBlockSource).
      activation_step: Keyword.get(opts, :activation_step, @activation_step),
      turn_ms: Keyword.get(opts, :turn_ms, @turn_ms),
      pipeline_depth: Keyword.get(opts, :pipeline_depth, @pipeline_depth),
      pipeline_bytes: Keyword.get(opts, :pipeline_bytes, @pipeline_bytes),
      # Build each new block's archive records in a short-lived process
      # (Archive.prepare_append) while later blocks are validated; see
      # "archive preparation" below.
      archive_prep: Keyword.get(opts, :archive_prep, true),
      # Test only: called with the block in each archive preparation process.
      test_archive_prep_hook: Keyword.get(opts, :test_archive_prep_hook),
      plan: nil,
      plan_seq: 0,
      drive_queued: false,
      # Something changed that may give a new target (a block held, a
      # failure, a reconsider): find_target runs only then.
      retarget: true,
      # Synchronous submissions and reconsider calls answered when
      # activation is idle (newest first), and their blocks kept at hand.
      waiters: [],
      current_blocks: %{},
      # Blocks fail_block reported to the shadow while waiters were pending:
      # hash => that block's own failure.
      rejected_seen: %{},
      pstats: %{},
      # Non-script ConnectBlock: :reference (Connect.connect_block
      # inline), :engine (Prepare.populate + check inline) or :worker (the
      # owner populates, one preparation worker checks).
      prep_mode:
        Keyword.get_lazy(opts, :prep_mode, fn ->
          Application.get_env(:exnode, :default_prep_mode, :reference)
        end),
      prep_worker: nil,
      # The one preparation job sent and not yet answered (obsolete or not):
      # nil or %{tag, sent_at, worker}. Only its own completion (or its
      # worker's death) releases it.
      prep_job: nil,
      sources: %{},
      listeners: Keyword.get(opts, :listeners, []),
      disconnected: MapSet.new(),
      # Core nSequenceId: assigned when the block AND its ancestors have
      # data, not when the header (or an unlinked body) was received.
      availability: :ets.new(:block_availability, [:set, :private]),
      next_sequence: 2,
      unlinked: %{},
      last_failure: nil,
      # The mempool process (name or pid) and the block events for it, newest first.
      mempool: Keyword.get(opts, :mempool),
      mempool_events: [],
      # The old tip's chain work while a reorg's events are held back from
      # the mempool, else nil.
      reorg_work: nil
    }

    # The shared script executor (the node's, by name), or a private one.
    {exec, private} =
      case Keyword.get(opts, :script_exec) do
        nil ->
          {:ok, pid} =
            ScriptExec.start_private(
              self(),
              Keyword.take(opts, [:script_workers, :script_run])
              |> Enum.map(fn
                {:script_workers, n} -> {:workers, n}
                {:script_run, f} -> {:run, f}
              end)
            )

          {pid, Process.monitor(pid)}

        exec ->
          {exec, nil}
      end

    st = Map.merge(st, %{exec: exec, exec_private: private && {exec, private}})
    st = Map.put(st, :test_prep_hook, Keyword.get(opts, :test_prep_hook))
    st = if st.prep_mode == :worker, do: %{st | prep_worker: start_prep_worker(st)}, else: st

    view = :ets.new(:chain_view, [:set, :public, read_concurrency: true])

    :ets.insert(view, [
      {:kv, kv},
      {:halted, false},
      {:pipeline, %{items: 0, bytes: 0, prefetch: 0}}
    ])

    if name = opts[:name], do: :persistent_term.put({__MODULE__, name}, view)
    # The halt is loaded first: a halted node replays nothing at start-up
    # (pending blocks are held, not connected) until an operator clears it.
    st =
      st
      |> Map.put(:view, view)
      |> load_halt()
      |> load_poisoned()
      |> load_candidates()
      |> load_pending()

    # Startup replay: activation to the end before serving any call (the
    # wait consumes only this process's own executor and prefetch results).
    st = st |> drive_until_idle() |> maybe_commit() |> publish()
    Process.send_after(self(), :commit_tick, @batch_ms)
    {:ok, st, {:continue, :shadow_catch_up}}
  end

  # At startup the shadow may be behind exnode (e.g. its data was lost) or
  # ahead (it processed blocks exnode had not committed). Behind: feed it the
  # missing archived blocks, @catch_up_chunk at a time, as ordinary rounds.
  @impl true
  def handle_continue(:shadow_catch_up, %{monitor: nil} = st), do: {:noreply, st}

  def handle_continue(:shadow_catch_up, st) do
    {:ok, {sh, shash}} = Exnode.Shadow.Monitor.shadow_tip(st.monitor)
    # Blocks reconnected from `pending` during init are committed but not yet
    # sent. They are at or below the tip, so the catch-up below covers them;
    # sending them first would hand the shadow blocks without their parents.
    st = commit(st)
    tip = Archive.tip(st.a)

    if sh > tip.height do
      Exnode.Shadow.Monitor.set_ahead(st.monitor, {sh, shash})
    else
      a = st.a

      start =
        if Archive.id_at(a, sh) && Archive.block_record!(a, Archive.id_at(a, sh)).hash == shash,
          do: sh + 1,
          else: 1

      catch_up(st, start, tip.height)
    end

    {:noreply, flush_round(%{st | round_connected: []})}
  end

  defp catch_up(_st, from, to) when from > to, do: :ok

  defp catch_up(st, from, to) do
    stop = min(to, from + st.catch_up_chunk - 1)

    blocks =
      for h <- from..stop//1,
          id = Archive.id_at(st.a, h),
          do: {Archive.block_record!(st.a, id).hash, Archive.read_block(st.a, id)}

    if Enum.any?(blocks, &match?({_, {:error, _}}, &1)) do
      # Witness pruning removed data the shadow still needs.
      Logger.error("shadow catch-up impossible from height #{from}: witness data pruned; halting")
      GenServer.cast(self(), {:halt, :shadow_behind_pruned})
    else
      Logger.info("shadow catch-up: feeding archived blocks #{from}..#{stop}")
      # The round's expected tip is the last block fed.
      Exnode.Shadow.Monitor.round(st.monitor, blocks, [], elem(List.last(blocks), 0))
      catch_up(st, stop + 1, to)
    end
  end

  # Publishes the tip and held blocks to the view.
  defp publish(st) do
    :ets.insert(st.view, {:tip, Archive.tip(st.a)})

    :ets.insert(st.view, [
      {:committed, Archive.committed_tip(st.a).height},
      {:reader, Archive.reader(st.a)}
    ])

    st
  end

  # Stores a received block on disk (pending) and keeps only its hash in memory.
  # The write is not fsynced: a pending block lost in a crash is downloaded again.
  defp hold(st, hash, %Block{raw: raw}) do
    :ok = Exnode.Store.KV.write(st.kv, [{:put, :pending, hash, raw}], sync: false)
    :ets.insert(st.view, {{:held, hash}})
    %{st | blocks: MapSet.put(st.blocks, hash), retarget: true} |> received_block(hash)
  end

  # --- batching ------------------------------------------------------------

  # Core FlushStateToDisk: commits the batch and the deletion of the blocks'
  # pending copies in one KV batch; the blocks then go to the shadow round.
  defp commit(%{uncommitted: []} = st), do: st

  defp commit(st) do
    hashes = Enum.map(st.uncommitted, &elem(&1, 0))
    # Core writes the block index before the chainstate: the headers'
    # queued (unsynced) writes reach the same KV first, so the synced batch
    # below makes them durable too and a committed block never lacks its
    # header at restart.
    :ok = Headers.flush(st.headers)
    a = Archive.flush(st.a, for(h <- hashes, do: {:delete, :pending, h})) |> note_durable()
    for h <- hashes, do: :ets.delete(st.view, {:held, h})

    :ets.insert(st.view, [
      {:committed, Archive.committed_tip(a).height},
      {:reader, Archive.reader(a)}
    ])

    %{st | a: a, round_connected: st.uncommitted ++ st.round_connected, uncommitted: []}
  end

  # The epoch of the last durable archive write (open, commit, disconnect)
  # made by this process. terminate/2 compares the struct it gets with it.
  defp note_durable(a) do
    Process.put({__MODULE__, :durable_epoch}, Archive.epoch(a))
    a
  end

  defp durable_current?(a), do: Archive.epoch(a) == Process.get({__MODULE__, :durable_epoch})

  defp maybe_commit(%{uncommitted: []} = st), do: st

  defp maybe_commit(st) do
    {n, bytes} = Archive.batch_size(st.a)
    age = System.monotonic_time(:millisecond) - (Archive.batch_since(st.a) || 0)
    best = HeaderIndex.best(Headers.index(st.headers))
    tip = Archive.tip(st.a)
    caught_up = st.commit_at_tip and best.hash == tip.hash

    max_age =
      if best.height - tip.height >= st.near_tip_blocks,
        do: st.batch_ms_behind,
        else: st.batch_ms

    if n >= st.batch_blocks or bytes >= st.batch_bytes or age >= max_age or caught_up or
         st.halted != false,
       do: commit(st),
       else: st
  end

  defp unhold(st, hash) do
    :ok = Exnode.Store.KV.write(st.kv, [{:delete, :pending, hash}], sync: false)
    :ets.delete(st.view, {:held, hash})
    :ets.delete(st.availability, hash)
    %{st | blocks: MapSet.delete(st.blocks, hash), sources: Map.delete(st.sources, hash)}
  end

  # Core InvalidChainFound marks every descendant BLOCK_FAILED_CHILD, which
  # keeps it out of setBlockIndexCandidates for good: a held body under a
  # failed header can never connect, so it is dropped with the failed block.
  defp unhold_failed(st) do
    idx = Headers.index(st.headers)

    Enum.reduce(st.blocks, st, fn h, st ->
      case HeaderIndex.lookup(idx, h) do
        %{status: :failed} -> %{unhold(st, h) | checked: MapSet.delete(st.checked, h)}
        _ -> st
      end
    end)
  end

  # Startup: pending blocks from the previous run are held again (no
  # re-download). Entries already archived are dropped. Keys only: the
  # blocks live in blob files and are not read here.
  defp load_pending(st) do
    hashes = Exnode.Store.KV.fold_keys(st.kv, :pending, <<>>, [], &[&1 | &2])

    # Quarantined blocks stay in `pending` (for reconsider_poisoned) but are not held.
    hashes = Enum.reject(hashes, &MapSet.member?(st.poisoned, &1))
    idx = Headers.index(st.headers)

    # Under a failed header (Core: not a candidate) a body can never connect.
    # Without a header (its unsynced write lost in a crash) it could not
    # link either, and holding it would stop it being downloaded again.
    {dropped, held} =
      Enum.split_with(
        hashes,
        &(Archive.block_id(st.a, &1) != nil or
            match?(e when e == nil or e.status == :failed, HeaderIndex.lookup(idx, &1)))
      )

    if dropped != [],
      do:
        :ok =
          Exnode.Store.KV.write(st.kv, for(h <- dropped, do: {:delete, :pending, h}), sync: false)

    for h <- held, do: :ets.insert(st.view, {{:held, h}})
    st = %{st | blocks: MapSet.new(held)}
    # Like Core LoadBlockIndex: availability ties across restarts are not
    # arrival-ordered (active blocks get 0, other loaded blocks get 1).
    held
    |> Enum.sort_by(fn h ->
      case HeaderIndex.lookup(idx, h) do
        nil -> {0, h}
        e -> {e.height, h}
      end
    end)
    |> Enum.reduce(st, &link_block(&2, idx, &1, 1))
  end

  # Core: PopulateBlockIndexCandidates (validation.cpp). Disconnects are
  # durable individually, so a restart must rediscover ALL archived side
  # branches, even when no pending data remains for the attempted reorg.
  defp load_candidates(st) do
    disconnected =
      Exnode.Store.KV.fold_prefix(st.kv, :blockhash, <<>>, MapSet.new(), fn {hash, <<id::32>>},
                                                                            acc ->
        active = Archive.on_chain?(st.a, id)
        :ets.insert(st.availability, {hash, if(active, do: 0, else: 1)})
        if active, do: acc, else: MapSet.put(acc, hash)
      end)

    %{st | disconnected: disconnected}
  end

  # Core: ReceivedBlockTransactions. Children waiting for a parent receive
  # sequence IDs in body-arrival order when their full ancestry is available.
  defp received_block(st, hash), do: link_block(st, Headers.index(st.headers), hash, nil)

  defp link_block(st, idx, hash, loaded_sequence) do
    entry = HeaderIndex.lookup(idx, hash)

    cond do
      :ets.member(st.availability, hash) ->
        st

      entry == nil ->
        st

      :ets.member(st.availability, entry.prev_hash) ->
        seq = loaded_sequence || st.next_sequence
        :ets.insert(st.availability, {hash, seq})
        {children, unlinked} = Map.pop(st.unlinked, hash, [])

        st = %{
          st
          | unlinked: unlinked,
            next_sequence: if(loaded_sequence, do: st.next_sequence, else: seq + 1)
        }

        Enum.reduce(Enum.reverse(children), st, &link_block(&2, idx, &1, loaded_sequence))

      true ->
        %{st | unlinked: Map.update(st.unlinked, entry.prev_hash, [hash], &[hash | &1])}
    end
  end

  # Start-up: the quarantine marks of earlier runs.
  defp load_halt(st) do
    case halt_mark(st.kv) do
      nil ->
        st

      m ->
        Logger.error(
          "block connection HALTED since #{m.time} at height #{m.height} " <>
            "(#{Exnode.Crypto.Hash.to_hex(m.hash)}): #{inspect(m.reason)}; not connecting blocks. " <>
            "See the shadow's divergences/ records; clear with ChainState.clear_halt/1 or " <>
            "mix exnode.reconsider --clear-halt once resolved"
        )

        :ets.insert(st.view, {:halted, m.reason})
        %{st | halted: m.reason}
    end
  end

  defp load_poisoned(st) do
    hashes =
      Exnode.Store.KV.fold_prefix(st.kv, :poisoned, <<>>, [], fn {k, _v}, acc -> [k | acc] end)

    if hashes != [] do
      Logger.warning(
        "#{length(hashes)} block(s) quarantined after a validation crash; not connecting them: " <>
          Enum.map_join(hashes, ", ", &Exnode.Crypto.Hash.to_hex/1) <>
          " (clear with ChainState.reconsider_poisoned/2 or mix exnode.reconsider once fixed)"
      )
    end

    for h <- hashes, do: :ets.insert(st.view, {{:quarantined, h}})
    %{st | poisoned: MapSet.new(hashes)}
  end

  defp pending_block(st, hash) do
    case Exnode.Store.KV.get(st.kv, :pending, hash) do
      {:ok, raw} ->
        {:ok, b} = Block.decode_exact(raw)
        b

      :not_found ->
        nil
    end
  end

  @impl true
  def handle_call(msg, from, st), do: timed_cb(msg, fn -> do_handle_call(msg, from, st) end)

  defp do_handle_call(:tip, _from, st), do: {:reply, Archive.tip(st.a), st}
  defp do_handle_call({:set_monitor, m}, _from, st), do: {:reply, :ok, %{st | monitor: m}}

  defp do_handle_call(:script_stats, _from, st), do: {:reply, st.script_stats, st}
  defp do_handle_call(:prefetch_stats, _from, st), do: {:reply, st.pf_stats, st}

  defp do_handle_call(:work_stats, _from, st) do
    st = take_cs_work(st)

    {:reply,
     %{
       prefetch: st.pf_work,
       chain_state: st.cs_work,
       pipeline: st.pstats,
       exec: ScriptExec.stats(st.exec)
     }, st}
  end

  defp do_handle_call(:debug, _from, st) do
    idx = Headers.index(st.headers)
    held = for h <- st.blocks, e = HeaderIndex.lookup(idx, h), do: {e.height, e.status}

    {:reply,
     %{
       held: Enum.sort(held),
       disconnected: MapSet.size(st.disconnected),
       last_failure: st.last_failure
     }, st}
  end

  # Diagnostic only (replay REPLAY_LIVE_SAMPLE): heap words reachable from
  # each part of the state (`:erts_debug.size/1`, sharing within a part
  # counted once; parts may share), with the process's own heap figures.
  # Walks the whole state: never on a production path.
  defp do_handle_call(:debug_live, _from, st) do
    w = &:erts_debug.size/1
    a = st.a
    items = if st.plan, do: :queue.to_list(st.plan.items), else: []
    item_part = fn k -> w.(Enum.map(items, &Map.get(&1, k))) end

    parts = %{
      batch_ops: w.(a.batch.ops),
      batch_blocks: w.(a.batch.blocks),
      batch_txindex: w.(a.batch.txindex),
      batch_blockhash: w.(a.batch.blockhash),
      archive_other: w.(%{a | batch: nil}),
      # ETS (not process heap), words.
      ets_chain: :ets.info(a.chain, :memory) + :ets.info(a.onchain, :memory),
      # Native tables (not process heap), words.
      overlay_native: div(Exnode.Archive.Overlay.native_bytes(a.overlay), 8),
      plan_items: length(items),
      item_block: item_part.(:block),
      item_res: item_part.(:res),
      item_history: item_part.(:history),
      item_other: w.(Enum.map(items, &Map.drop(&1, [:block, :res, :history]))),
      plan_todo: if(st.plan, do: w.(st.plan.todo), else: 0),
      uncommitted: w.(st.uncommitted),
      round_connected: w.(st.round_connected),
      mempool_events: w.(st.mempool_events),
      waiters: w.({st.waiters, st.current_blocks}),
      sets: w.({st.blocks, st.checked, st.disconnected, st.sources, st.unlinked, st.poisoned}),
      stats: w.({st.pstats, st.cs_work, st.pf_work, st.pf_window}),
      dict: w.(Process.get())
    }

    info = Process.info(self(), [:heap_size, :total_heap_size, :stack_size, :message_queue_len])
    {:reply, Map.merge(parts, Map.new(info)), st}
  end

  defp do_handle_call({:have?, hash}, _from, st), do: {:reply, have?(st, hash), st}

  defp do_handle_call({:have_many, hashes}, _from, st),
    do:
      {:reply,
       MapSet.new(Enum.filter(hashes, &(have?(st, &1) or MapSet.member?(st.poisoned, &1)))), st}

  defp do_handle_call({:with_archive, fun}, _from, st) do
    st = commit(st)
    {:reply, fun.(st.a), st}
  end

  defp do_handle_call({:peek_archive, fun}, _from, st), do: {:reply, fun.(st.a), st}

  defp do_handle_call({:mempool_view, ops}, _from, st),
    do: {:reply, {Archive.tip(st.a), Archive.resolve_many(st.a, ops)}, st}

  defp do_handle_call({:precheck_block, header, requested}, _from, st) do
    reply =
      case submission_entry(st, header, requested) do
        {:ok, _, _} -> :check
        other -> other
      end

    {:reply, reply, st}
  end

  defp do_handle_call(:commit, _from, st), do: {:reply, :ok, st |> commit() |> flush_round()}

  defp do_handle_call({:submit, %Block{} = b, opts}, from, st) do
    t0 = System.monotonic_time(:microsecond)
    {reply, st} = do_submit(st, b, opts)

    st =
      case reply do
        {:error, r} ->
          if Enum.any?(st.round_rejected, &(elem(&1, 0) == b.header.hash)),
            do: st,
            else: %{st | round_rejected: [{b.header.hash, b.raw, r} | st.round_rejected]}

        :connect ->
          # Synchronous submission: answered (GenServer.reply) once the
          # activation it starts is idle, as ActivateBestChain returned.
          %{
            st
            | waiters: [{:submit, from, b.header.hash, b.raw} | st.waiters],
              current_blocks: Map.put(st.current_blocks, b.header.hash, b)
          }
          |> queue_drive()

        _ ->
          st
      end

    st = st |> flush_round() |> flush_mempool()
    us = System.monotonic_time(:microsecond) - t0
    st = st |> update_pstats(%{submits: 1, submit_us: us}) |> hwm(:submit_max_us, us)
    # Release references to large block binaries (see Peer). A full sweep
    # costs O(heap), and the heap holds the batch, so sweep once per
    # @gc_bytes of submitted blocks rather than per block.
    gc = Map.get(st, :gc_bytes, 0) + byte_size(b.raw || <<>>)

    {st, gc} =
      if gc >= @gc_bytes do
        tg = System.monotonic_time(:microsecond)
        :erlang.garbage_collect()
        gc_us = System.monotonic_time(:microsecond) - tg

        {st
         |> update_pstats(%{explicit_gcs: 1, explicit_gc_us: gc_us})
         |> hwm(:explicit_gc_max_us, gc_us), 0}
      else
        {st, gc}
      end

    st = Map.put(st, :gc_bytes, gc)
    if reply == :connect, do: {:noreply, st}, else: {:reply, reply, st}
  end

  defp do_handle_call(:halted, _from, st), do: {:reply, st.halted, st}

  defp do_handle_call(:clear_halt, _from, %{halted: false} = st), do: {:reply, :not_halted, st}

  defp do_handle_call(:clear_halt, _from, st) do
    :ok = Exnode.Store.KV.write(st.kv, [{:delete, :meta, @halt_key}], sync: true)
    :ets.insert(st.view, {:halted, false})
    Logger.warning("block connection halt cleared (was #{inspect(st.halted)})")
    {:reply, st.halted, queue_drive(%{st | halted: false, retarget: true})}
  end

  defp do_handle_call(:poisoned, _from, st), do: {:reply, MapSet.to_list(st.poisoned), st}

  defp do_handle_call({:reconsider_poisoned, which}, from, st) do
    hashes =
      if which == :all,
        do: MapSet.to_list(st.poisoned),
        else: Enum.filter([which], &MapSet.member?(st.poisoned, &1))

    :ok = Exnode.Store.KV.write(st.kv, for(h <- hashes, do: {:delete, :poisoned, h}), sync: true)
    st = %{st | poisoned: MapSet.difference(st.poisoned, MapSet.new(hashes))}
    for h <- hashes, do: :ets.delete(st.view, {:quarantined, h})

    # Still in pending: held again, so activation can retry it. Archived
    # but off the active chain (quarantined while being reconnected after
    # a reorg): a candidate again, as load_candidates/1 makes it at start
    # (it used to wait for a restart).
    st =
      Enum.reduce(hashes, st, fn h, st ->
        id = Archive.block_id(st.a, h)

        cond do
          Exnode.Store.KV.get(st.kv, :pending, h) != :not_found ->
            :ets.insert(st.view, {{:held, h}})
            %{st | blocks: MapSet.put(st.blocks, h)} |> received_block(h)

          id != nil and not Archive.on_chain?(st.a, id) ->
            %{st | disconnected: MapSet.put(st.disconnected, h)}

          true ->
            st
        end
      end)

    for h <- hashes,
        do: Logger.warning("quarantine cleared for block #{Exnode.Crypto.Hash.to_hex(h)}")

    st = %{st | retarget: true, waiters: [{:reply, from, hashes} | st.waiters]} |> queue_drive()
    {:noreply, st}
  end

  @impl true
  # One activation turn (coalesced); it queues the next only if it stopped
  # on a budget, never to wait for a completion.
  def handle_info(msg, st), do: timed_cb(msg, fn -> do_handle_info(msg, st) end)

  defp do_handle_info(:drive, st), do: {:noreply, drive(%{st | drive_queued: false})}

  defp do_handle_info({:script_exec, tag, outcome, wstats}, st),
    do: {:noreply, script_result(st, tag, outcome, wstats)}

  defp do_handle_info({:prefetch_done, tag, result}, st),
    do: {:noreply, prefetch_result(st, tag, result)}

  defp do_handle_info({:prep_done, tag, result, wstats}, st),
    do: {:noreply, prep_result(st, tag, result, wstats)}

  defp do_handle_info({:archive_prep_done, tag, result}, st),
    do: {:noreply, archive_prep_result(st, tag, result)}

  defp do_handle_info({:DOWN, mref, :process, _, reason}, %{prep_worker: {_, mref}} = st),
    do: {:noreply, prep_worker_down(st, reason)}

  # The private executor went: outstanding script work is lost.
  defp do_handle_info({:DOWN, mref, :process, _, reason}, %{exec_private: {_, mref}} = st),
    do: {:stop, {:script_exec_down, reason}, st}

  defp do_handle_info({:DOWN, mref, :process, _, _} = down, st),
    do: {:noreply, elem(handle_down(st, mref, down), 1)}

  defp do_handle_info(:commit_tick, st) do
    Process.send_after(self(), :commit_tick, @batch_ms)
    {:noreply, st |> maybe_commit() |> flush_round()}
  end

  defp do_handle_info({:EXIT, _pid, reason}, st) do
    cond do
      reason in [:normal, :shutdown] -> {:noreply, st}
      match?({:shutdown, _}, reason) -> {:noreply, st}
      true -> {:stop, reason, st}
    end
  end

  defp do_handle_info(_msg, st), do: {:noreply, st}

  # Commit what is connected (Core flushes on shutdown). Provisional items
  # are dropped (their pending copies remain for the next start); a private
  # executor stops after its running native calls return.
  @impl true
  def terminate(_reason, st) do
    st = cancel_plan(st)

    case st.prep_worker do
      {pid, mref} ->
        Process.demonitor(mref, [:flush])
        Process.exit(pid, :kill)

      nil ->
        :ok
    end

    # Commit only an archive struct that matches the disk. A callback that
    # crashed after its own durable write (a mid-turn batch commit, a reorg's
    # disconnects, a fail/quarantine commit) leaves `st` older than the disk:
    # flushing it would write old meta (tip, segment ends) over the newer
    # commit, orphaning committed rows whose pending copies are gone, or
    # restoring a disconnected block's rows without its spends. The restart
    # recovers from the disk and `pending` instead.
    if durable_current?(st.a) do
      try do
        commit(st)
      catch
        # Headers is gone (a rest_for_one restart), so its writes cannot be
        # flushed first; the restart reconnects the batch from `pending`.
        :exit, _ ->
          Logger.warning("chain state stopped without the header tree; not committing")
      end
    else
      Logger.warning(
        "chain state stopped with an archive state older than its last commit; " <>
          "not committing it (the restart resumes from the disk)"
      )
    end

    case st.exec_private do
      {pid, mref} ->
        Process.demonitor(mref, [:flush])
        # Waits for its running native calls to return.
        if Process.alive?(pid),
          do: catch_exit(fn -> GenServer.stop(pid, :shutdown, :infinity) end)

      nil ->
        :ok
    end

    :ok
  end

  @impl true
  def handle_cast(msg, st), do: timed_cb(msg, fn -> do_handle_cast(msg, st) end)

  defp do_handle_cast({:halt, reason}, %{halted: false} = st) do
    Logger.error("block connection halted: #{inspect(reason)}")
    # Durable first: a restart, with or without the shadow, must not
    # replay `pending` past the divergence. Cleared only by clear_halt/1 or
    # `mix exnode.reconsider --clear-halt`.
    tip = Archive.tip(st.a)
    mark = %{reason: reason, time: System.os_time(:second), height: tip.height, hash: tip.hash}

    :ok =
      Exnode.Store.KV.write(st.kv, [{:put, :meta, @halt_key, :erlang.term_to_binary(mark)}],
        sync: true
      )

    :ets.insert(st.view, {:halted, reason})
    ack_halt(st)
    # The next turn drops the plan (no provisional item is published).
    {:noreply, queue_drive(%{st | halted: reason})}
  end

  # Already halted: the first reason (and its mark) stands.
  defp do_handle_cast({:halt, _reason}, st),
    do:
      (
        ack_halt(st)
        {:noreply, st}
      )

  # The halt is durable: the monitor stops re-sending its pending one.
  defp ack_halt(%{monitor: nil}), do: :ok
  defp ack_halt(st), do: Exnode.Shadow.Monitor.halt_ack(st.monitor)

  # Sends the block events of this activation to the mempool (Core: ConnectTip
  # calls removeForBlock; ActivateBestChainStep calls MaybeUpdateMempoolForReorg).
  #
  # A reorg's events are held until the new chain has more work than the old
  # tip, or its plan ends: Core keeps the disconnectpool across those
  # ConnectTip calls, so txs the new blocks confirm again are never re-added
  # (and never trimmed against).
  defp flush_mempool(%{mempool_events: []} = st), do: st

  defp flush_mempool(%{reorg_work: w, plan: plan} = st) when w != nil and plan != nil do
    tip = HeaderIndex.lookup(Headers.index(st.headers), Archive.tip(st.a).hash)
    if tip.chain_work > w, do: flush_mempool(%{st | reorg_work: nil}), else: st
  end

  defp flush_mempool(st) do
    case st.mempool && GenServer.whereis(st.mempool) do
      pid when is_pid(pid) ->
        send(pid, {:mempool_update, Archive.tip(st.a).hash, Enum.reverse(st.mempool_events)})

      _ ->
        :ok
    end

    %{st | mempool_events: [], reorg_work: nil}
  end

  defp mempool_event(%{mempool: nil} = st, _ev), do: st
  defp mempool_event(st, ev), do: %{st | mempool_events: [ev | st.mempool_events]}

  # Sends this round's connected and rejected blocks to the shadow monitor.
  defp flush_round(%{round_connected: [], round_rejected: []} = st), do: st
  defp flush_round(%{monitor: nil} = st), do: %{st | round_connected: [], round_rejected: []}

  defp flush_round(st) do
    Exnode.Shadow.Monitor.round(
      st.monitor,
      Enum.reverse(st.round_connected),
      Enum.reverse(st.round_rejected),
      # Only committed blocks are in the round: compare the shadow with the committed tip.
      Archive.committed_tip(st.a).hash
    )

    %{st | round_connected: [], round_rejected: []}
  end

  defp do_submit(st, %Block{} = b, %{checked: checked} = opts) do
    hash = b.header.hash

    case submission_entry(st, b.header, opts.requested) do
      {:ok, entry, idx} ->
        with :ok <- check_block_result(checked || check_block(b, st.p)),
             :ok <- BlockRules.contextual_check_block(b, HeaderIndex.prev(idx, entry), st.p, idx) do
          st = st |> hold(hash, b) |> Map.update!(:checked, &MapSet.put(&1, hash))

          if opts.defer do
            st = if is_pid(opts.source), do: put_in(st.sources[hash], opts.source), else: st
            {{:ok, :stored}, queue_drive(st)}
          else
            {:connect, st}
          end
        else
          # Core ProcessNewBlock: a CheckBlock failure is returned (and
          # punished) but the block is never marked invalid, "protective
          # against consensus failure if there are any unknown forms of block
          # malleability" (validation.cpp); the same body under the same
          # header may be valid. Mutated blocks are among these.
          {:check_block, reason} ->
            {{:error, reason}, st}

          {:error, {:mutated, _} = reason} ->
            {{:error, reason}, st}

          {:error, {_result, _r} = reason} ->
            # ContextualCheckBlock failure: Core marks the block failed
            # (AcceptBlock -> InvalidBlockFound).
            fail_submitted(st, hash, reason)
        end

      # Core ProcessNewBlock runs CheckBlock before AcceptBlock's
      # already-have check: a mutated body under a known hash is rejected as
      # mutated, not ignored as a duplicate.
      {:ok, :duplicate} = reply ->
        case checked || check_block(b, st.p) do
          :ok -> {reply, st}
          {:error, reason} -> {{:error, reason}, st}
        end

      reply ->
        {reply, st}
    end
  end

  # Core: AcceptBlockHeader and AcceptBlock's unrequested-block gates.
  # Shared by the advisory preflight and the authoritative submission path.
  defp submission_entry(st, header, requested) do
    hash = header.hash

    cond do
      MapSet.member?(st.poisoned, hash) ->
        {:error, {:quarantined, "block is quarantined after a local validation crash"}}

      have?(st, hash) ->
        {:ok, :duplicate}

      true ->
        idx = Headers.index(st.headers)
        tip = HeaderIndex.lookup(idx, Archive.tip(st.a).hash)

        with {:ok, _} <-
               Headers.process_headers(st.headers, [header],
                 min_pow_checked: min_pow_checked?(idx, header, tip, st.p)
               ),
             idx = Headers.index(st.headers),
             entry = HeaderIndex.lookup(idx, hash),
             :store <- accept_unrequested(entry, tip, requested, st.p) do
          {:ok, entry, idx}
        else
          :skip -> {:ok, :skipped}
          {:error, reason, _last} -> {:error, reason}
        end
    end
  end

  defp check_block_result(:ok), do: :ok
  defp check_block_result({:error, reason}), do: {:check_block, reason}

  # Core: ProcessMessage BLOCK (net_processing.cpp): min_pow_checked is true
  # when the parent's work plus the block's claimed proof reaches
  # GetAntiDoSWorkThreshold. An unknown parent gives false; the header then
  # fails as prev-blk-not-found first.
  defp min_pow_checked?(idx, header, tip_entry, p) do
    case HeaderIndex.lookup(idx, header.prev_hash) do
      nil ->
        false

      prev ->
        prev.chain_work + Pow.bits_proof(header.bits) >=
          HeaderIndex.anti_dos_work_threshold(tip_entry, p)
    end
  end

  # Core: AcceptBlock (validation.cpp), the gates for blocks we did not
  # request, applied before CheckBlock: such a block is not stored (`:skip`)
  # unless it has at least the active tip's work, is at most
  # MIN_BLOCKS_TO_KEEP above it, and has minimum_chain_work. Core's other
  # gate, a pruned previously processed block (nTx != 0), is have?/2 here:
  # an archived block is a duplicate before this point.
  defp accept_unrequested(_entry, _tip_entry, true, _p), do: :store

  defp accept_unrequested(entry, tip_entry, false, p) do
    has_more_or_same_work = tip_entry == nil or entry.chain_work >= tip_entry.chain_work
    active_height = if tip_entry, do: tip_entry.height, else: -1
    too_far_ahead = entry.height > active_height + @min_blocks_to_keep

    cond do
      not has_more_or_same_work -> :skip
      too_far_ahead -> :skip
      entry.chain_work < p.minimum_chain_work -> :skip
      true -> :store
    end
  end

  defp fail_submitted(st, hash, reason) do
    Headers.invalidate(st.headers, hash, Archive.tip(st.a).hash)
    {{:error, reason}, unhold_failed(st)}
  end

  # An archived block off the active chain whose witness data is pruned is
  # not had: reconnecting it needs the full block again (Core clears
  # BLOCK_HAVE_DATA when pruning). Counting it had let a failed deep reorg
  # pick the old branch, crash reading it and quarantine an honest block.
  defp have?(st, hash),
    do: MapSet.member?(st.blocks, hash) or Archive.have_block_data?(st.a, hash)

  # --- activation --------------------------------------------------------------
  #
  # Core ActivateBestChain / ConnectTip as a persistent, asynchronous plan.
  # The plan is state of this
  # process, not of a callback: a `:drive` turn (coalesced: at most one is
  # queued) does a bounded amount of work and returns to the mailbox; script
  # results (`{:script_exec, ...}` from the shared executor) and prefetch
  # results arrive as messages and queue the next turn. No callback waits
  # for a worker.
  #
  # Per turn, in order:
  # 1. no plan: find the best target (only when something changed,
  #    `retarget`), disconnect to the fork (Core DisconnectTip, synchronous
  #    as before), and start a plan for the path;
  # 2. retire: while the oldest item (the FIFO head) is complete, publish it
  #    (Archive.connect, tip, events) or, if it failed, fail/quarantine it and
  #    drop the plan. Only the head is ever retired, so results are as if
  #    blocks connected one at a time: a later block's failure cannot
  #    outrank an earlier block's, and nothing after a failed block is
  #    published (provisional items have no side effects);
  # 3. prepare: the next block of the path gets its checks and the
  #    non-script ConnectBlock against the archive plus the deltas of the
  #    unretired items (newest first), then its script chunks go to the
  #    executor. Bounded by `pipeline_depth` items and `pipeline_bytes`
  #    retained (one item is always admitted: progress for the oldest);
  # 4. when the path is used up, a new target that extends it on the same
  #    branch is appended (prepared items are kept); any other target waits
  #    until the plan drains, then step 1 runs again.
  # A turn stops after `activation_step` retirements or preparations (Core
  # ActivateBestChainStep's 32) or `turn_ms`, and requeues itself only if it
  # stopped on a budget; waiting for a completion queues nothing.
  #
  # Branch generation vs. lookup epoch: each plan has a fresh `gen`; every
  # script job is tagged `{:blk, gen, item_ref, chunk}` with a fresh
  # `item_ref` per prepared body, so a completion for a dropped plan, or for
  # an earlier body of the same header (a mutated-block retry), is ignored.
  # The archive epoch only gates prefetched committed answers (Prefetch);
  # a commit does not void prepared items, whose results do not depend on
  # what is durable, only on the archive's logical contents.

  defp queue_drive(%{drive_queued: true} = st), do: st

  defp queue_drive(st) do
    send(self(), :drive)
    %{st | drive_queued: true}
  end

  # One turn plus the step epilogue of the old ActivateBestChainStep:
  # batch commit, view, shadow round, mempool events, then waiters.
  defp drive(st) do
    t0 = System.monotonic_time(:microsecond)
    {st, state} = turn(Map.put(st, :turn_retired, 0))
    st = hwm(st, :turn_retired_max, st.turn_retired)
    t1 = System.monotonic_time(:microsecond)
    cs_time(:turn, t1 - t0)

    st =
      st |> maybe_commit() |> publish() |> publish_pipeline() |> flush_round() |> flush_mempool()

    cs_time(:epilogue, System.monotonic_time(:microsecond) - t1)

    # Why the turn stopped to wait: the time until the next callback is
    # charged to it (timed_cb/2).
    case state do
      :waiting -> Process.put(:perf_wait, {wait_reason(st), System.monotonic_time(:microsecond)})
      # Nothing left to connect: waiting for blocks to arrive.
      :idle -> Process.put(:perf_wait, {:no_work, System.monotonic_time(:microsecond)})
      :more -> :ok
    end

    st = note_turn(st, System.monotonic_time(:microsecond) - t0)

    case state do
      :more -> queue_drive(st)
      :idle -> answer_waiters(st)
      :waiting -> st
    end
  end

  # Startup (and init-time activation): drive until idle, consuming only
  # this process's own completion messages (executor, prefetch). Nothing it
  # waits for needs this process to serve a call.
  defp drive_until_idle(st) do
    {st, state} = turn(st)
    st = maybe_commit(st)

    case state do
      :idle ->
        st

      :more ->
        drive_until_idle(st)

      :waiting ->
        st =
          receive do
            {:script_exec, tag, outcome, wstats} -> script_result(st, tag, outcome, wstats)
            {:prefetch_done, tag, result} -> prefetch_result(st, tag, result)
            {:prep_done, tag, result, wstats} -> prep_result(st, tag, result, wstats)
            {:archive_prep_done, tag, result} -> archive_prep_result(st, tag, result)
            {:DOWN, mref, :process, _, reason} = down -> any_down(st, mref, reason, down)
          end

        drive_until_idle(st)
    end
  end

  defp turn(st) do
    budget = %{
      retire: st.activation_step,
      # Preparation runs ahead of retirement by up to pipeline_depth.
      prepare: st.activation_step + st.pipeline_depth,
      deadline: System.monotonic_time(:millisecond) + st.turn_ms
    }

    turn(st, budget)
  end

  defp turn(%{halted: h} = st, _budget) when h != false, do: {cancel_plan(st), :idle}

  defp turn(st, budget) do
    cond do
      budget.retire <= 0 or budget.prepare <= 0 or
          System.monotonic_time(:millisecond) >= budget.deadline ->
        {st, :more}

      st.plan == nil ->
        if st.retarget do
          case new_plan(%{st | retarget: false}) do
            {:ok, st} -> turn(st, budget)
            :none -> {%{st | retarget: false}, :idle}
          end
        else
          {st, :idle}
        end

      true ->
        case step(st) do
          {:retired, st} -> turn(retired(st), %{budget | retire: budget.retire - 1})
          {:failed, st} -> turn(retired(st), %{budget | retire: budget.retire - 1})
          {:prepared, st} -> turn(st, %{budget | prepare: budget.prepare - 1})
          {:done, st} -> turn(%{st | plan: nil, retarget: true}, budget)
          {:extended, st} -> turn(st, budget)
          {:waiting, st} -> {note_wait(st), :waiting}
        end
    end
  end

  defp retired(st), do: Map.update(st, :turn_retired, 1, &(&1 + 1))

  # Core: ActivateBestChain's choice of target, then DisconnectTip to the fork.
  defp new_plan(st) do
    idx = Headers.index(st.headers)
    tip_entry = HeaderIndex.lookup(idx, Archive.tip(st.a).hash)

    case timed_find_target(st, idx, tip_entry) do
      {nil, _st} ->
        :none

      {target, st} ->
        fork = HeaderIndex.last_common_ancestor(idx, tip_entry, target)

        st =
          if fork.height < tip_entry.height and st.mempool,
            do: %{st | reorg_work: max(st.reorg_work || 0, tip_entry.chain_work)},
            else: st

        st = disconnect_to(st, fork)
        path = path(idx, fork, target)
        # The prefetch stage runs only on paths of new blocks (see Chain.Prefetch).
        archived = Enum.any?(path, &(Archive.block_id(st.a, &1.hash) != nil))
        depth = if archived, do: 0, else: st.prefetch_depth

        ctx = %{
          kv: st.kv,
          params: st.p,
          idx: idx,
          current: current_block(st),
          hint: Archive.overlay_hint(st.a)
        }

        plan = %{
          gen: make_ref(),
          todo: path,
          last: List.last(path),
          items: :queue.new(),
          n: 0,
          bytes: 0,
          archived: archived,
          # A non-extending target appeared, or an item failed preparation:
          # no more blocks join this plan.
          final: false,
          pf: nil
        }

        st = %{st | plan: plan}
        pf = Prefetch.start(path, depth, Archive.reader(st.a), ctx, admit_fun(st))
        {:ok, put_in(st.plan.pf, pf)}
    end
  end

  # The next action on the plan: retire the head if complete, else prepare
  # the next block if admitted and its data is in, else extend, else wait.
  defp step(st) do
    t0 = System.monotonic_time(:microsecond)
    st = dispatch_archive_preps(st)
    cs_time(:dispatch, System.monotonic_time(:microsecond) - t0)

    case :queue.peek(st.plan.items) do
      {:value, %{state: s} = head} when s in [:ready, :failed] ->
        case await_archive_prep(st, head) do
          {:ok, st, head} -> cs_timed(:retire, fn -> retire(st, head) end)
          :pending -> advance(st)
        end

      _ ->
        advance(st)
    end
  end

  defp advance(st) do
    plan = st.plan

    cond do
      plan.todo != [] and not plan.final and admitted?(st) and prep_free?(st) ->
        case cs_timed(:prepare, fn -> prepare_next(st) end) do
          {:wait, st} -> {:waiting, st}
          {:ok, st} -> {:prepared, st}
        end

      :queue.is_empty(plan.items) and (plan.todo == [] or plan.final) ->
        {:done, cancel_plan(st)}

      plan.todo == [] and not plan.final and st.retarget ->
        extend_plan(%{st | retarget: false})

      true ->
        {:waiting, st}
    end
  end

  # --- archive preparation -------------------------------------------------
  #
  # Archiving a new block (Archive.connect at retirement) runs in this
  # process, after the block's checks and before the next block's.
  # Everything in it that depends only on the block, its `spent` ids, its
  # delta and its archive ids (record encoding and layout, tx metadata, the
  # block's own txindex occurrences, spend records, overlay rows, and its
  # committed txindex rows when the prefetched ones are stale) is built
  # instead by a short-lived process (Archive.prepare_append) as soon as the
  # item has its result, while this process prepares later blocks. A ready
  # head waits for it before retiring (it stays in the view meanwhile, like
  # a head waiting for its scripts).
  #
  # Ids: the archive's next ids, advanced over the unretired items in
  # order (a reconnected block takes none). Archive.connect checks them
  # again and encodes the block in place if they no longer match, so a
  # wrong guess costs time, never correctness. A preparation that fails or
  # whose process dies (:none) is also just done in place. Results are
  # tagged with the plan generation: those of a dropped plan are ignored.

  # Starts preparations for the items that have their result, oldest
  # first, stopping at the first one without (its outputs, and so the
  # later ids, are not known yet).
  defp dispatch_archive_preps(%{archive_prep: false} = st), do: st

  defp dispatch_archive_preps(st) do
    {items, _, launched} =
      Enum.reduce(:queue.to_list(st.plan.items), {[], Archive.next_ids(st.a), false}, fn
        item, {acc, nil, l} ->
          {[item | acc], nil, l}

        %{apre_next: next} = item, {acc, _ids, l} when next != nil ->
          {[item | acc], next, l}

        %{res: nil} = item, {acc, _ids, l} ->
          {[item | acc], nil, l}

        %{state: :failed} = item, {acc, _ids, l} ->
          {[item | acc], nil, l}

        item, {acc, ids, l} ->
          if Map.get(item, :archived, false) do
            {[item | acc], ids, l}
          else
            item = launch_archive_prep(st, item, ids)
            {[item | acc], item.apre_next, true}
          end
      end)

    if launched, do: put_in(st.plan.items, :queue.from_list(Enum.reverse(items))), else: st
  end

  defp launch_archive_prep(st, %{block: block, res: res, entry: entry} = item, ids) do
    {nouts, nins} =
      Enum.reduce(block.txs, {0, 0}, fn tx, {o, i} ->
        {o + length(tx.outputs), i + length(tx.inputs)}
      end)

    next = %{block: ids.block + 1, out: ids.out + nouts, inp: ids.inp + nins}
    owner = self()
    tag = {:apre, st.plan.gen, make_ref()}
    # Only what the preparation reads crosses to its process, since spawning
    # copies it here: the raw block (an off-heap binary, shared, not copied;
    # decoded there), the spent ids, the delta's created and spent coins,
    # and the prefetched txindex rows (re-reading them there instead costs
    # the store a block's worth of lookups again). Rows of another epoch
    # are read there, at this epoch (`kv_reader/1`).
    reader = Archive.kv_reader(st.a)
    history = Map.get(item, :history)
    body = if is_binary(block.raw), do: {:raw, block.raw}, else: {:decoded, block}
    %{spent: spent, delta: %{created: created, spent: sp}} = res
    delta = %{created: created, spent: sp}
    height = entry.height
    hook = st.test_archive_prep_hook
    launched = System.monotonic_time(:microsecond)

    {_pid, mref} =
      spawn_monitor(fn ->
        result =
          try do
            block =
              case body do
                {:raw, raw} -> elem(Block.decode_exact(raw), 1)
                {:decoded, b} -> b
              end

            if hook, do: hook.(block)
            p = Archive.prepare_append(block, height, spent, ids, delta, reader, history)

            {:ok,
             Map.merge(p, %{
               launched_at: launched,
               worker_us: System.monotonic_time(:microsecond) - launched
             })}
          catch
            kind, reason -> {:error, {kind, reason}}
          end

        send(owner, {:archive_prep_done, tag, result})
      end)

    %{item | apre: {:pending, tag, mref}, apre_next: next}
  end

  # The head is ready (or failed): it retires now unless its preparation
  # is still running. A result already in the mailbox is taken at once.
  defp await_archive_prep(st, %{state: :ready, apre: {:pending, tag, _}}) do
    receive do
      {:archive_prep_done, ^tag, result} ->
        st = archive_prep_result(st, tag, result)
        {:value, head} = :queue.peek(st.plan.items)
        {:ok, st, head}
    after
      0 -> :pending
    end
  end

  defp await_archive_prep(st, head), do: {:ok, st, head}

  # A preparation's result: settles the item still pending under `tag` in
  # the current plan; anything else is stale.
  defp archive_prep_result(st, {:apre, gen, _} = tag, result) do
    case st.plan do
      %{gen: ^gen} = plan ->
        {items, found} =
          Enum.map_reduce(:queue.to_list(plan.items), nil, fn
            %{apre: {:pending, ^tag, mref}} = i, nil ->
              Process.demonitor(mref, [:flush])

              case result do
                {:ok, p} ->
                  cs_time(:apre_latency, System.monotonic_time(:microsecond) - p.launched_at)
                  cs_time(:apre_worker, p.worker_us)
                  {%{i | apre: {:done, p}}, p.prepare_us}

                {:error, _} ->
                  {%{i | apre: :none}, 0}
              end

            i, acc ->
              {i, acc}
          end)

        case found do
          nil ->
            update_pstat(st, :archive_prep_stale, 1)

          us ->
            st = put_in(st.plan.items, :queue.from_list(items))

            st
            |> update_pstats(%{archive_prep_us: us, archive_prep_jobs: 1})
            |> queue_drive()
        end

      _ ->
        update_pstat(st, :archive_prep_stale, 1)
    end
  end

  # A preparation process died without answering: its item is archived in place.
  defp archive_prep_down(%{plan: %{items: items}} = st, mref, reason) when reason != :normal do
    list = :queue.to_list(items)

    if Enum.any?(list, &match?(%{apre: {:pending, _, ^mref}}, &1)) do
      list =
        Enum.map(list, fn
          %{apre: {:pending, _, ^mref}} = i -> %{i | apre: :none}
          i -> i
        end)

      st = put_in(st.plan.items, :queue.from_list(list))
      {:ok, queue_drive(update_pstat(st, :archive_prep_down, 1))}
    else
      :unknown
    end
  end

  defp archive_prep_down(_st, _mref, _reason), do: :unknown

  # Items in the plan (prepared, unretired) stay below `pipeline_depth`, and
  # their retained bytes plus ready prefetch results below `pipeline_bytes`;
  # an empty plan always admits one (the oldest block must progress, however
  # large). The byte figure is an estimate (see item_bytes/2) and known only
  # once a block is loaded, so a plan can overshoot by one block.
  defp admitted?(st) do
    plan = st.plan

    plan.n == 0 or
      (plan.n < st.pipeline_depth and plan.bytes + pf_retained(plan) < st.pipeline_bytes)
  end

  defp pf_retained(%{pf: %Prefetch{retained: r}}), do: r
  defp pf_retained(_), do: 0

  defp admit_fun(st) do
    max = st.pipeline_bytes
    fn pf -> pf.retained + plan_bytes(st) < max end
  end

  defp plan_bytes(%{plan: %{bytes: b}}), do: b
  defp plan_bytes(_), do: 0

  # The path is used up: a target on the same branch beyond the plan's last
  # block is appended (prepared items stay valid). Another target, or one
  # needing archived blocks, ends the plan's growth: it drains, then a new
  # plan starts from the right fork.
  defp extend_plan(st) do
    plan = st.plan
    idx = Headers.index(st.headers)
    tip_entry = HeaderIndex.lookup(idx, Archive.tip(st.a).hash)

    case timed_find_target(st, idx, tip_entry) do
      {nil, st} ->
        {:waiting, st}

      {target, st} ->
        last = plan.last
        anc = HeaderIndex.ancestor(idx, target, last.height)

        cond do
          target.hash == last.hash ->
            {:waiting, st}

          anc != nil and anc.hash == last.hash and target.height > last.height ->
            ext = path(idx, last, target)

            if plan.archived or Enum.any?(ext, &(Archive.block_id(st.a, &1.hash) != nil)) do
              {:waiting, put_in(st.plan.final, true)}
            else
              pf = Prefetch.extend(plan.pf, ext, idx, Archive.reader(st.a), admit_fun(st))
              st = update_pstat(st, :extensions, 1)
              {:extended, %{st | plan: %{plan | todo: ext, last: List.last(ext), pf: pf}}}
            end

          true ->
            # Another branch: finish what is prepared, then re-target.
            {:waiting, %{st | plan: %{plan | final: true}, retarget: true}}
        end
    end
  end

  # Drops the plan: queued script jobs are cancelled (running ones finish on
  # their workers, results ignored by generation), prefetch workers killed,
  # retained bytes released with the items. Idempotent.
  defp cancel_plan(%{plan: nil} = st), do: st

  defp cancel_plan(st) do
    plan = st.plan
    refs = for i <- :queue.to_list(plan.items), do: i.ref
    if refs != [], do: ScriptExec.cancel(st.exec, refs)
    if plan.pf, do: Prefetch.stop(plan.pf)
    %{st | plan: nil}
  end

  # The block and its prefetched committed answers (when still valid), or
  # :wait while its prefetch worker runs.
  defp take_prefetched(st, entry) do
    {result, pf} = Prefetch.take(st.plan.pf, entry, Archive.reader(st.a), admit_fun(st))
    st = put_in(st.plan.pf, pf)

    case result do
      :wait ->
        {:wait, st}

      {:ok, block, epoch, answers, history, stats} ->
        # The work was done whether or not the answers are still valid.
        st = %{
          st
          | pf_work: add_counts(st.pf_work, stats),
            pf_window: add_counts(st.pf_window, stats)
        }

        # The txindex rows go with the item to its append, which checks
        # their epoch again (a commit may come before it). Answers of the
        # epoch just before the last commit are carried over it, minus
        # those it may have changed (Archive.revalidate/4); older ones are
        # stale.
        if epoch == Archive.epoch(st.a) do
          {block, answers, history, update_in(st.pf_stats.used, &(&1 + 1))}
        else
          case Archive.revalidate(st.a, epoch, answers, history) do
            {:ok, answers, history, dropped} ->
              st =
                st
                |> update_in([:pf_stats, :revalidated], &(&1 + 1))
                |> update_in([:pf_stats, :reval_dropped], &(&1 + dropped))

              {block, answers, history, st}

            :stale ->
              {block, nil, nil, update_in(st.pf_stats.stale, &(&1 + 1))}
          end
        end

      :none ->
        {load_block(st, entry), nil, nil,
         if(pf.depth > 0, do: update_in(st.pf_stats.none, &(&1 + 1)), else: st)}
    end
  end

  # Core: ConnectTip's checks for the next block of the path: CheckBlock (if
  # not fChecked), ContextualCheckBlock and the non-script ConnectBlock,
  # against the archive plus the unretired items' deltas. Its scripts go to
  # the executor; the item joins the retirement FIFO.
  defp prepare_next(st) do
    [entry | rest] = st.plan.todo
    idx = Headers.index(st.headers)

    # An exception while loading the block is contained like one in validation.
    loaded =
      try do
        take_prefetched(st, entry)
      rescue
        e -> {:crash, {:crash, e, __STACKTRACE__}, st}
      catch
        kind, reason -> {:crash, {:crash, {kind, reason}, __STACKTRACE__}, st}
      end

    # Prefetch wait: from the first turn that found the next block's
    # prefetch result missing to the turn that took it.
    now = System.monotonic_time(:microsecond)

    case loaded do
      {:wait, st} ->
        {:wait, Map.put_new(st, :pf_wait_since, now)}

      {:crash, crash, st} ->
        {:ok, add_item(st, entry, rest, nil, crash, 0)}

      {block, answers, history, st} ->
        {since, st} = Map.pop(st, :pf_wait_since)

        if since,
          do: Process.put(:perf_pfwait_us, (Process.get(:perf_pfwait_us) || 0) + now - since)

        t0 = System.monotonic_time(:microsecond)
        items = :queue.to_list(st.plan.items)

        view = items |> Enum.reverse() |> Enum.flat_map(&if(&1.res, do: [&1.res.delta], else: []))
        spec_out = Archive.next_ids(st.a).out + Enum.reduce(items, 0, &(&2 + &1.new_outputs))
        archived = Archive.block_id(st.a, entry.hash) != nil

        # Exceptions in this block's checks become {:crash, ...}, kept apart
        # from consensus {:error, _} results (which keep their fail_block path).
        result =
          try do
            tc = System.monotonic_time(:microsecond)

            with :ok <- unchecked_check_block(st, entry, block),
                 _ <- add_us(:perf_checkblock_us, tc),
                 :ok <-
                   BlockRules.contextual_check_block(
                     block,
                     HeaderIndex.prev(idx, entry),
                     st.p,
                     idx
                   ),
                 :ok <- override(st, block, entry),
                 _ <-
                   Process.put(
                     :perf_rules_us,
                     (Process.get(:perf_rules_us) || 0) + System.monotonic_time(:microsecond) - tc
                   ) do
              scripts =
                not st.test_skip_scripts and
                  Exnode.Validation.AssumeValid.decide(st.assume_valid, idx, entry, st.p) != :skip

              opts =
                [scripts: if(scripts, do: :defer, else: false), view: view, committed: answers] ++
                  if(archived, do: [], else: [base_out: spec_out])

              tconn = System.monotonic_time(:microsecond)

              r =
                case st.prep_mode do
                  :reference ->
                    Connect.connect_block(st.a, block, entry, st.p, idx, opts)

                  :engine ->
                    facts = timed_populate(st, block, entry, idx, opts)
                    tchk = System.monotonic_time(:microsecond)
                    r = Prepare.check(block, facts)

                    Process.put(
                      :perf_check_us,
                      (Process.get(:perf_check_us) || 0) + System.monotonic_time(:microsecond) -
                        tchk
                    )

                    r

                  :worker ->
                    {:populated, timed_populate(st, block, entry, idx, opts)}
                end

              Process.put(
                :perf_connect_us,
                (Process.get(:perf_connect_us) || 0) + System.monotonic_time(:microsecond) - tconn
              )

              r
            end
          rescue
            e -> {:crash, e, __STACKTRACE__}
          catch
            kind, reason -> {:crash, {kind, reason}, __STACKTRACE__}
          end

        validate_us = System.monotonic_time(:microsecond) - t0

        split = %{
          prep_rules_us: Process.delete(:perf_rules_us) || 0,
          prep_connect_us: Process.delete(:perf_connect_us) || 0,
          prep_populate_us: Process.delete(:perf_populate_us) || 0,
          prep_context_us: Process.delete(:perf_context_us) || 0,
          prep_check_us: Process.delete(:perf_check_us) || 0
        }

        # The perf line's validation split, per window (see perf/4).
        checkblock = Process.delete(:perf_checkblock_us) || 0

        Process.put(
          :perf_vwin,
          add_counts(Process.get(:perf_vwin) || %{}, %{
            checkblock: checkblock,
            contextual: max(split.prep_rules_us - checkblock, 0),
            connect: split.prep_connect_us
          })
        )

        st = update_pstats(st, split)

        case result do
          {:ok, res} ->
            st = add_item(st, entry, rest, block, {:ok, res}, validate_us)
            st = mark_archived(st, archived)
            {:ok, if(archived, do: zero_new_outputs(st), else: attach_history(st, history))}

          {:populated, facts} ->
            st = dispatch_prep(st, entry, rest, block, facts, archived, validate_us)
            {:ok, if(archived, do: st, else: attach_history(st, history))}

          other ->
            {:ok, add_item(st, entry, rest, block, other, validate_us)}
        end
    end
  end

  # --- chain-state time accounting (the perf line's `chain-state:` part) ---
  #
  # Per window: the time in each callback, by message (a call by its
  # request, an info by its message), and within `:drive` the turn's parts.
  # What no callback took is idle. Each gap between two callbacks is split
  # by the mailbox when the first one ended: empty, the process waited for
  # the message that ends the gap (`{:gap_for, key}`); not empty, it had
  # work but did not run (`{:gap, :queued}`: descheduled, collecting
  # garbage, or the gen_server's own receive).

  defp timed_cb(msg, fun) do
    t0 = System.monotonic_time(:microsecond)
    key = if is_tuple(msg) and tuple_size(msg) > 0, do: elem(msg, 0), else: msg
    key = if is_atom(key), do: key, else: :other

    case Process.delete(:perf_wait) do
      {reason, since} -> cs_time({:wait, reason}, t0 - since)
      nil -> :ok
    end

    case Process.delete(:perf_cb_end) do
      {te, true} -> cs_time({:gap, :queued}, t0 - te)
      {te, false} -> cs_time({:gap_for, key}, t0 - te)
      nil -> :ok
    end

    r = fun.()
    t1 = System.monotonic_time(:microsecond)
    cs_time({:cb, key}, t1 - t0)
    {:message_queue_len, q} = Process.info(self(), :message_queue_len)
    Process.put(:perf_cb_end, {t1, q > 0})
    r
  end

  defp cs_timed(key, fun) do
    t0 = System.monotonic_time(:microsecond)
    r = fun.()
    cs_time(key, System.monotonic_time(:microsecond) - t0)
    r
  end

  defp cs_time(key, us) do
    m = Process.get(:perf_cs) || %{}
    {n, t} = Map.get(m, key, {0, 0})
    Process.put(:perf_cs, Map.put(m, key, {n + 1, t + us}))
  end

  # "<head>/<why>": the plan's head (`apre`: ready, its archive preparation
  # running; else its state, or `empty`) and why nothing more was prepared
  # (`prefetch`: the next block's prefetch result; `no_blocks`: none left
  # to prepare; `full`: pipeline_depth or pipeline_bytes; `prep_busy`: the
  # preparation worker).
  defp wait_reason(%{plan: %{} = plan} = st) do
    head =
      case :queue.peek(plan.items) do
        {:value, %{state: :ready, apre: {:pending, _, _}}} -> "apre"
        {:value, %{state: s}} -> Atom.to_string(s)
        :empty -> "empty"
      end

    why =
      cond do
        Map.has_key?(st, :pf_wait_since) -> "prefetch"
        plan.todo == [] or plan.final -> "no_blocks"
        not admitted?(st) -> "full"
        not prep_free?(st) -> "prep_busy"
        true -> "other"
      end

    String.to_atom(head <> "/" <> why)
  end

  defp wait_reason(_st), do: :no_plan

  # Busy and idle time, the turn's parts, and each message's time/count,
  # largest first.
  defp cs_line(m, window_us) do
    cbs = for {{:cb, k}, {n, us}} <- m, do: {k, n, us}
    busy = Enum.reduce(cbs, 0, fn {_, _, us}, acc -> acc + us end)
    g = fn k -> m |> Map.get(k, {0, 0}) |> elem(1) |> div(1000) end

    calls =
      cbs
      |> Enum.sort_by(&(-elem(&1, 2)))
      |> Enum.map_join(" ", fn {k, n, us} -> "#{k} #{div(us, 1000)}ms/#{n}" end)

    waits =
      for({{:wait, k}, {n, us}} <- m, do: {k, n, us})
      |> Enum.sort_by(&(-elem(&1, 2)))
      |> Enum.map_join(" ", fn {k, n, us} -> "#{k} #{div(us, 1000)}ms/#{n}" end)

    gaps_for =
      for({{:gap_for, k}, {n, us}} <- m, do: {k, n, us})
      |> Enum.sort_by(&(-elem(&1, 2)))
      |> Enum.map_join(" ", fn {k, n, us} -> "#{k} #{div(us, 1000)}ms/#{n}" end)

    {queued_n, queued_us} = Map.get(m, {:gap, :queued}, {0, 0})
    {apre_n, apre_lat} = Map.get(m, :apre_latency, {0, 0})
    {_, apre_work} = Map.get(m, :apre_worker, {0, 0})

    "chain-state: busy #{div(busy, 1000)}ms idle #{div(max(window_us - busy, 0), 1000)}ms " <>
      "(turn #{g.(:turn)}ms: prepare #{g.(:prepare)}ms retire #{g.(:retire)}ms " <>
      "dispatch #{g.(:dispatch)}ms; epilogue #{g.(:epilogue)}ms; by message: #{calls}; " <>
      "waiting for: #{waits}; archive preparations #{apre_n}: " <>
      "avg latency #{div(apre_lat, max(apre_n, 1) * 1000)}ms, avg work #{div(apre_work, max(apre_n, 1) * 1000)}ms; " <>
      "gaps: with messages queued #{div(queued_us, 1000)}ms/#{queued_n}, mailbox empty, until: #{gaps_for})" <>
      gc_line()
  end

  defp gc_line do
    case Process.get(:gc_probe) do
      nil ->
        ""

      probe ->
        g = Exnode.Chain.GcProbe.take(probe)

        "; gc: minor #{g.minor_n}x #{div(g.minor_us, 1000)}ms major #{g.major_n}x " <>
          "#{div(g.major_us, 1000)}ms heap max #{div(g.heap_max_words * 8, 1024 * 1024)}MiB; " <>
          "long schedules: chain-state #{g.own_sched_n}x #{g.own_sched_ms}ms " <>
          "others #{g.sched_n}x #{g.sched_ms}ms; " <>
          "run queue now #{:erlang.statistics(:total_run_queue_lengths_all)}"
    end
  end

  defp add_us(key, t0),
    do: Process.put(key, (Process.get(key) || 0) + System.monotonic_time(:microsecond) - t0)

  # CheckBlock unless done at submission (fChecked). A local error there (a
  # kernel API failure on signet's challenge) is a crash, not a verdict.
  defp unchecked_check_block(st, entry, block) do
    if MapSet.member?(st.checked, entry.hash) do
      :ok
    else
      case BlockRules.check_block(block, st.p,
             signet_check: &Exnode.Validation.Signet.check(&1, st.p)
           ) do
        {:error, {:crash, r}} -> raise Exnode.Validation.Scripts.LocalError, reason: r
        other -> other
      end
    end
  end

  # The prefetched txindex rows (Archive.connect's :history) of the item just
  # added, for its append.
  defp attach_history(st, nil), do: st

  defp attach_history(st, history) do
    {{:value, last}, q} = :queue.out_r(st.plan.items)
    put_in(st.plan.items, :queue.in(Map.put(last, :history, history), q))
  end

  defp mark_archived(st, archived) do
    {{:value, last}, q} = :queue.out_r(st.plan.items)
    put_in(st.plan.items, :queue.in(Map.put(last, :archived, archived), q))
  end

  # An archived block (a reconnect) has its output ids already: it reserves none.
  defp zero_new_outputs(st) do
    {{:value, last}, q} = :queue.out_r(st.plan.items)
    put_in(st.plan.items, :queue.in(%{last | new_outputs: 0}, q))
  end

  # Appends an item for `entry` to the FIFO. `result` is {:ok, res} (scripts
  # go to the executor; none: complete at once) or a failure, which ends
  # the plan's growth: blocks after a failed one are not prepared.
  defp add_item(st, entry, rest, block, result, validate_us) do
    plan = st.plan
    ref = make_ref()
    order = st.plan_seq
    now = System.monotonic_time(:microsecond)

    item = %{
      ref: ref,
      order: order,
      entry: entry,
      block: block,
      res: nil,
      state: :failed,
      failure: nil,
      pending: 0,
      outcomes: [],
      new_outputs: 0,
      bytes: 0,
      validate_us: validate_us,
      # Archive preparation: nil (not started), {:pending, tag, mref},
      # {:done, prepared} or :none (failed: archived in place); apre_next:
      # the archive ids after this block.
      apre: nil,
      apre_next: nil,
      prepared_at: now,
      done_at: now,
      # When it became the FIFO head (the oldest unretired block).
      head_at: if(:queue.is_empty(plan.items), do: now)
    }

    {item, final} =
      case result do
        {:preparing, tag, bytes, archived} ->
          {%{item | state: :preparing, bytes: bytes}
           |> Map.merge(%{prep_tag: tag, archived: archived}), false}

        other ->
          settle(st, plan.gen, item, block, other)
      end

    plan = %{
      plan
      | todo: rest,
        items: :queue.in(item, plan.items),
        n: plan.n + 1,
        bytes: plan.bytes + item.bytes,
        final: plan.final or final
    }

    st = %{st | plan: plan, plan_seq: order + 1}
    st = %{st | current_blocks: Map.delete(st.current_blocks, entry.hash)}
    note_occupancy(st)
  end

  # A preparation result for `item`: {:ok, res} (scripts go to the executor;
  # none: complete at once) or a failure, which ends the plan's growth.
  defp settle(st, gen, item, block, result) do
    ref = item.ref
    order = item.order

    case result do
      {:ok, res} ->
        checks = res.checks || []
        chunks = Enum.chunk_every(checks, Exnode.Validation.Scripts.chunk_size())
        item = %{item | res: res, new_outputs: res.n_outputs, bytes: item_bytes(block, res)}

        if chunks == [] do
          {%{item | state: :ready, res: %{res | checks: nil}}, false}
        else
          hook = st.test_script_hook

          jobs =
            chunks
            |> Enum.with_index()
            |> Enum.map(fn {c, i} ->
              %{
                tag: {:blk, gen, ref, i},
                group: ref,
                prio: {order, i},
                checks: c,
                flags: res.flags,
                pre: if(hook && i == 0, do: fn -> hook.(block) end)
              }
            end)

          ScriptExec.submit(st.exec, jobs)
          # The checks now live in the executor's jobs: not retained here.
          {%{item | state: :scripts, pending: length(chunks), res: %{res | checks: nil}}, false}
        end

      {:error, _} = err ->
        {%{item | state: :failed, failure: err}, true}

      {:crash, _, _} = crash ->
        {%{item | state: :failed, failure: crash}, true}
    end
  end

  # --- preparation worker --------------------------------------------------
  #
  # One worker per chain state runs Prepare.check/2 over the facts the owner
  # populated. At most one job is outstanding, obsolete jobs included
  # (prep_job): the next block cannot be populated before this one's
  # delta is known anyway, and a job for a dropped plan still occupies the
  # worker until its result (ignored) comes back. The worker is pure BEAM
  # code (no native call), so killing it is safe. Results are tagged
  # {:prep, plan generation, ref}. Only the outstanding job's own tag
  # releases it (once; its latency is charged to it); its result settles
  # an item only if that item is still preparing under the same tag in
  # the current plan, else it is stale. Any other tag (a duplicate after
  # acceptance, an unknown one) changes nothing but `prep_unknown`. A
  # worker crash or death is a local failure: the block is quarantined,
  # never marked invalid.

  defp start_prep_worker(st) do
    owner = self()
    # Test only: called in the worker with the block before each check.
    hook = st.test_prep_hook

    pid =
      spawn(fn ->
        ref = Process.monitor(owner)
        prep_loop(owner, ref, hook)
      end)

    {pid, Process.monitor(pid)}
  end

  defp prep_loop(owner, oref, hook) do
    receive do
      {:prep, tag, block, facts} ->
        t0 = System.monotonic_time(:microsecond)

        result =
          try do
            cond do
              is_function(hook, 2) -> hook.(tag, block)
              is_function(hook, 1) -> hook.(block)
              true -> :ok
            end

            Prepare.check(block, facts)
          rescue
            e -> {:crash, e, __STACKTRACE__}
          catch
            kind, reason -> {:crash, {kind, reason}, __STACKTRACE__}
          end

        send(
          owner,
          {:prep_done, tag, result, %{worker_us: System.monotonic_time(:microsecond) - t0}}
        )

        prep_loop(owner, oref, hook)

      {:DOWN, ^oref, _, _, _} ->
        :ok
    end
  end

  defp prep_free?(%{prep_mode: :worker} = st) do
    st.prep_job == nil and
      case :queue.peek_r(st.plan.items) do
        {:value, %{state: :preparing}} -> false
        _ -> true
      end
  end

  defp prep_free?(_st), do: true

  defp timed_populate(st, block, entry, idx, opts) do
    t0 = System.monotonic_time(:microsecond)
    facts = Prepare.populate(st.a, block, entry, st.p, idx, opts)

    Process.put(
      :perf_populate_us,
      (Process.get(:perf_populate_us) || 0) + System.monotonic_time(:microsecond) - t0
    )

    facts
  end

  defp dispatch_prep(st, entry, rest, block, facts, archived, validate_us) do
    tag = {:prep, st.plan.gen, make_ref()}
    {pid, _} = st.prep_worker
    nil = st.prep_job
    send(pid, {:prep, tag, block, facts})
    raw = if is_binary(block.raw), do: byte_size(block.raw), else: 0
    # Retained while preparing: the block (raw and decoded, also copied to
    # the worker) and the facts (copied to the worker).
    bytes = 5 * raw + 2 * Prepare.facts_bytes(facts)

    st =
      st
      |> update_pstats(%{prep_jobs: 1, prep_handoff_bytes: 3 * raw + Prepare.facts_bytes(facts)})
      |> Map.put(:prep_job, %{tag: tag, sent_at: System.monotonic_time(:microsecond), worker: pid})

    add_item(st, entry, rest, block, {:preparing, tag, bytes, archived}, validate_us)
  end

  # A preparation result. Not the outstanding job's tag (a duplicate after
  # acceptance, a tag never sent): ignored, nothing released or charged.
  # The outstanding job's: releases it once, then settles the matching
  # :preparing item of the current plan (generation and tag), else stale.
  defp prep_result(%{prep_job: %{tag: tag} = job} = st, tag, result, wstats) do
    now = System.monotonic_time(:microsecond)

    st =
      %{st | prep_job: nil}
      |> update_pstats(%{prep_worker_us: wstats.worker_us, prep_roundtrip_us: now - job.sent_at})

    {:prep, gen, _} = tag

    case st.plan do
      %{gen: ^gen} = plan ->
        case Enum.find(
               :queue.to_list(plan.items),
               &(Map.get(&1, :prep_tag) == tag and &1.state == :preparing)
             ) do
          nil ->
            queue_drive(update_pstat(st, :prep_stale, 1))

          item ->
            {settled, final} = settle(st, gen, item, item.block, result)

            settled =
              if settled.res != nil and Map.get(item, :archived),
                do: %{settled | new_outputs: 0},
                else: settled

            settled = %{
              settled
              | prepared_at: now,
                done_at: if(settled.state == :scripts, do: settled.done_at, else: now)
            }

            items =
              :queue.from_list(
                Enum.map(
                  :queue.to_list(plan.items),
                  &if(&1.ref == item.ref, do: settled, else: &1)
                )
              )

            plan = %{
              plan
              | items: items,
                bytes: plan.bytes - item.bytes + settled.bytes,
                final: plan.final or final
            }

            queue_drive(note_occupancy(%{st | plan: plan}))
        end

      _ ->
        queue_drive(update_pstat(st, :prep_stale, 1))
    end
  end

  defp prep_result(st, _tag, _result, _wstats), do: update_pstat(st, :prep_unknown, 1)

  # The (current) worker died: its outstanding job, if any, is released;
  # the item preparing under that job's tag is a local failure
  # (quarantine). A new worker takes its place (pure BEAM code: nothing
  # outlives it). Results it sent before dying arrived before this DOWN.
  defp prep_worker_down(st, reason) do
    job = st.prep_job
    st = %{st | prep_worker: start_prep_worker(st), prep_job: nil}

    with %{tag: tag} <- job,
         %{} = plan <- st.plan,
         true <-
           Enum.any?(:queue.to_list(plan.items), &(&1.state == :preparing and &1.prep_tag == tag)) do
      crash = {:crash, {:exit, {:prep_worker_down, reason}}, []}

      items =
        Enum.map(:queue.to_list(plan.items), fn
          %{state: :preparing, prep_tag: ^tag} = i -> %{i | state: :failed, failure: crash}
          i -> i
        end)

      queue_drive(%{st | plan: %{plan | items: :queue.from_list(items), final: true}})
    else
      # No job, or an obsolete one: nothing of the current plan was lost.
      _ -> queue_drive(st)
    end
  end

  # Retained bytes of a prepared item: raw block and its decoded form (about
  # twice the raw size), the script jobs (tx bytes are sub-binaries of the
  # raw block; the spent scripts are counted), and the coin-view delta.
  defp item_bytes(%Block{raw: raw}, res) do
    raw_b = if is_binary(raw), do: byte_size(raw), else: 0

    checks_b =
      Enum.reduce(res.checks || [], 0, fn {_tx, spent}, acc ->
        acc + Enum.reduce(spent, 0, fn {spk, _}, a -> a + byte_size(spk) + 16 end)
      end)

    3 * raw_b + checks_b + 160 * map_size(res.delta.created) + 48 * MapSet.size(res.delta.spent)
  end

  # A script job's outcome. Ignored unless it belongs to the current plan
  # and a live item (generation and item reference): stale completions from
  # a dropped plan or an earlier body change nothing.
  defp script_result(st, {:blk, gen, ref, _i}, outcome, wstats) do
    st =
      update_pstats(st, %{
        script_jobs: 1,
        script_native_us: wstats.native_us,
        script_txs: wstats.txs
      })

    case st.plan do
      %{gen: ^gen} = plan ->
        items =
          :queue.to_list(plan.items)
          |> Enum.map(fn
            %{ref: ^ref, state: :scripts} = i -> record_outcome(i, outcome)
            i -> i
          end)

        # A proven failure decides the block: the rest of its chunks are moot.
        case Enum.find(items, &(&1.ref == ref)) do
          %{state: :ready, failure: {:invalid, _}} -> ScriptExec.cancel(st.exec, [ref])
          _ -> :ok
        end

        queue_drive(put_in(st.plan.items, :queue.from_list(items)))

      _ ->
        update_pstat(st, :stale_results, 1)
    end
  end

  defp script_result(st, _tag, _outcome, _wstats), do: update_pstat(st, :stale_results, 1)

  defp record_outcome(item, outcome) do
    item = %{item | pending: item.pending - 1, outcomes: [outcome | item.outcomes]}

    cond do
      match?({:invalid, _}, outcome) ->
        %{item | state: :ready, failure: outcome, done_at: System.monotonic_time(:microsecond)}

      item.pending == 0 ->
        failure =
          case Exnode.Validation.Scripts.combine(item.outcomes) do
            :ok -> nil
            f -> f
          end

        %{item | state: :ready, failure: failure, done_at: System.monotonic_time(:microsecond)}

      true ->
        item
    end
  end

  defp prefetch_result(%{plan: %{pf: %Prefetch{} = pf}} = st, tag, result) do
    case Prefetch.reply(pf, tag, result) do
      {:ok, pf} -> queue_drive(put_in(st.plan.pf, pf))
      :unknown -> st
    end
  end

  defp prefetch_result(st, _tag, _result), do: st

  defp handle_down(%{plan: %{pf: %Prefetch{} = pf}} = st, mref, down) do
    case Prefetch.down(pf, mref) do
      {:ok, pf} -> {:ok, queue_drive(put_in(st.plan.pf, pf))}
      :unknown -> down_other(st, mref, down)
    end
  end

  defp handle_down(st, mref, down), do: down_other(st, mref, down)

  defp down_other(st, mref, {:DOWN, _, :process, _, reason}) do
    case archive_prep_down(st, mref, reason) do
      {:ok, st} -> {:ok, st}
      :unknown -> {:unknown, st}
    end
  end

  # Startup's selective receive: the preparation worker or a prefetch
  # worker; the private executor's death is fatal, as after init (its
  # outstanding jobs never answer: init used to wait for them forever).
  defp any_down(%{exec_private: {_, mref}}, mref, reason, _down),
    do: exit({:script_exec_down, reason})

  defp any_down(%{prep_worker: {_, mref}} = st, mref, reason, _down),
    do: prep_worker_down(st, reason)

  defp any_down(st, mref, _reason, down), do: elem(handle_down(st, mref, down), 1)

  # Retires the FIFO head (complete). Valid: archive it. Otherwise fail or
  # quarantine it and drop the plan (nothing after it has side effects).
  defp retire(st, item) do
    {_, items} = :queue.out(st.plan.items)
    now0 = System.monotonic_time(:microsecond)

    # The next item becomes the head now.
    items =
      case :queue.out(items) do
        {{:value, next}, rest} -> :queue.in_r(%{next | head_at: next.head_at || now0}, rest)
        {:empty, _} -> items
      end

    # Head-of-line wait: how long the oldest unretired block waited for its
    # own scripts after reaching the head (0 if they were done first).
    st = update_pstat(st, :head_wait_us, max(0, item.done_at - (item.head_at || item.done_at)))

    plan = %{st.plan | items: items, n: st.plan.n - 1, bytes: st.plan.bytes - item.bytes}
    st = %{st | plan: plan}
    now = System.monotonic_time(:microsecond)

    st =
      update_pstats(st, %{
        retire_wait_us: now - item.done_at,
        scripts_latency_us: item.done_at - item.prepared_at
      })

    case item.failure do
      nil ->
        case archive_connect(st, item) do
          {:ok, a, archive_us} ->
            {:retired, archive_block(st, item, a, archive_us, item.done_at - item.prepared_at)}

          {:crash, _, _} = crash ->
            st = cancel_plan(st)
            archive_crashed(st, item, crash)
        end

      {:error, _} = err ->
        st = cancel_plan(st)
        {:failed, %{fail_block(st, item.entry, item.block, err) | retarget: true}}

      {:invalid, reason} ->
        st = cancel_plan(st)

        {:failed,
         %{
           fail_block(st, item.entry, item.block, {:error, {:consensus, reason}})
           | retarget: true
         }}

      {:local, reason} ->
        st = cancel_plan(st)
        crash = {:crash, {:error, %Exnode.Validation.Scripts.LocalError{reason: reason}}, []}
        {:failed, %{quarantine_block(st, item.entry, item.block, crash) | retarget: true}}

      {:crash, _, _} = crash ->
        st = cancel_plan(st)
        {:failed, %{quarantine_block(st, item.entry, item.block, crash) | retarget: true}}
    end
  end

  # --- pipeline diagnostics ----------------------------------------------------

  defp update_pstat(st, k, n), do: %{st | pstats: Map.update(st.pstats, k, n, &(&1 + n))}
  defp update_pstats(st, m), do: %{st | pstats: add_counts(st.pstats, m)}

  defp hwm(st, k, v), do: %{st | pstats: Map.update(st.pstats, k, v, &max(&1, v))}

  defp note_occupancy(%{plan: plan} = st) do
    st
    |> hwm(:items_hwm, plan.n)
    |> hwm(:bytes_hwm, plan.bytes + pf_retained(plan))
    |> hwm(:prefetch_hwm, if(plan.pf, do: Prefetch.in_flight(plan.pf), else: 0))
  end

  defp note_turn(st, us) do
    st
    |> update_pstats(%{turns: 1, turn_us: us})
    |> hwm(:turn_max_us, us)
  end

  # Waiting: what blocks progress (the head's scripts, or the next block's
  # prefetch), counted per turn that ended waiting.
  defp note_wait(%{plan: plan} = st) do
    case plan && :queue.peek(plan.items) do
      {:value, %{state: :scripts}} -> update_pstat(st, :waits_head_scripts, 1)
      _ -> update_pstat(st, :waits_other, 1)
    end
  end

  # Occupancy for other components (a credit hook for block download: the
  # view's `:pipeline` entry; nothing reads it yet).
  defp publish_pipeline(st) do
    occ =
      case st.plan do
        nil ->
          %{items: 0, bytes: 0, prefetch: 0}

        p ->
          %{
            items: p.n,
            bytes: p.bytes + pf_retained(p),
            prefetch: if(p.pf, do: Prefetch.in_flight(p.pf), else: 0)
          }
      end

    :ets.insert(st.view, {:pipeline, occ})
    st
  end

  # --- waiters (synchronous submission, reconsider) ------------------------

  # Answered when activation is idle (no plan, no better target), as the
  # synchronous ActivateBestChain returned: the reply and the tip a caller
  # sees afterwards are those of a finished activation.
  defp answer_waiters(%{waiters: []} = st), do: st

  defp answer_waiters(st) do
    {waiters, st} = {Enum.reverse(st.waiters), %{st | waiters: []}}

    st =
      Enum.reduce(waiters, st, fn
        {:submit, from, hash, raw}, st ->
          reply = submit_outcome(st, hash)

          # A rejection fail_block already put in a shadow round (possibly
          # flushed by an earlier turn) is not added again; a quarantine is,
          # as the synchronous path did.
          st =
            case reply do
              {:error, r} ->
                if Map.has_key?(st.rejected_seen, hash),
                  do: st,
                  else: %{st | round_rejected: [{hash, raw, r} | st.round_rejected]}

              _ ->
                st
            end

          GenServer.reply(from, reply)
          st

        {:reply, from, value}, st ->
          GenServer.reply(from, value)
          st
      end)

    %{st | current_blocks: %{}, rejected_seen: %{}} |> flush_round()
  end

  # Only a block that itself failed ConnectBlock gets an error, its own (Core
  # BlockChecked for that block). One failed only through an ancestor was
  # accepted (Core ProcessNewBlock returns true, nobody is punished for it).
  defp submit_outcome(st, hash) do
    cond do
      MapSet.member?(st.poisoned, hash) ->
        {:error, {:crash, "validation crashed; block quarantined"}}

      Map.has_key?(st.rejected_seen, hash) ->
        {:error, Map.fetch!(st.rejected_seen, hash)}

      Archive.on_chain?(st.a, Archive.block_id(st.a, hash) || -1) ->
        {:ok, :connected}

      true ->
        {:ok, :stored}
    end
  end

  defp current_block(st) do
    case Map.values(st.current_blocks) do
      [b | _] -> b
      [] -> nil
    end
  end

  # Selection cost in the chain state (pipeline stats: retargets, retarget_us).
  # Core: CBlockIndexWorkComparator (node/blockstorage.cpp), smallest first:
  # more work, then the earliest activatable body (nSequenceId), regardless of
  # which branch's headers arrived first; the hash only breaks loaded-ID ties.
  # A candidate with the tip's work but an earlier body also ranks above the
  # tip (Core keeps it in setBlockIndexCandidates): after a reorg to a branch
  # whose next block then fails, the node returns to the first-seen
  # equal-work branch.
  defp work_key(st, e) do
    seq =
      case :ets.lookup(st.availability, e.hash) do
        [{_, s}] -> s
        [] -> 0
      end

    {-e.chain_work, seq, e.hash}
  end

  defp timed_find_target(st, idx, tip_entry) do
    t0 = System.monotonic_time(:microsecond)
    target = find_target(st, idx, tip_entry)

    {target,
     update_pstats(st, %{retargets: 1, retarget_us: System.monotonic_time(:microsecond) - t0})}
  end

  # The best candidate, by Core's comparator, that ranks above the tip and
  # whose path from the fork is fully available and not failed.
  defp find_target(st, idx, tip_entry) do
    tip_key = work_key(st, tip_entry)

    # Candidates: blocks held in memory, and archived blocks a reorg disconnected.
    candidates =
      st.blocks
      |> MapSet.to_list()
      |> Enum.concat(MapSet.to_list(st.disconnected))
      |> Enum.uniq()
      |> Enum.map(&HeaderIndex.lookup(idx, &1))
      |> Enum.reject(
        &(&1 == nil or not :ets.member(st.availability, &1.hash) or
            work_key(st, &1) >= tip_key or
            MapSet.member?(st.poisoned, &1.hash))
      )
      |> Enum.sort_by(&work_key(st, &1))

    # A candidate qualifies if every block from the fork up to it is
    # available and not failed (Core keeps only such blocks in
    # setBlockIndexCandidates). Every block above a missing or failed one
    # is remembered as unusable, so one pass is linear in the number of
    # held blocks (during IBD they all wait on the same missing block).
    candidates
    |> Enum.reduce_while(MapSet.new(), fn c, bad ->
      if MapSet.member?(bad, c.hash) do
        {:cont, bad}
      else
        fork = HeaderIndex.last_common_ancestor(idx, tip_entry, c)
        path = path(idx, fork, c)

        case Enum.split_while(
               path,
               &(&1.status != :failed and have?(st, &1.hash) and
                   not MapSet.member?(st.poisoned, &1.hash))
             ) do
          {_, []} -> {:halt, {:found, c}}
          {_, unusable} -> {:cont, Enum.reduce(unusable, bad, &MapSet.put(&2, &1.hash))}
        end
      end
    end)
    |> case do
      {:found, c} -> c
      _ -> nil
    end
  end

  defp path(idx, fork, target) do
    Stream.unfold(target, fn
      e when e.height <= fork.height -> nil
      e -> {e, HeaderIndex.prev(idx, e)}
    end)
    |> Enum.reverse()
  end

  # Core: DisconnectTip (repeated)
  defp disconnect_to(st, fork) do
    if Archive.tip(st.a).height > fork.height do
      st = commit(st)

      # The mempool re-adds a disconnected block's txs. A block below the
      # witness-pruning horizon comes back without witnesses: its segwit
      # spends then fail the re-add and leave the mempool with their
      # descendants. Reading the raw block crashed the disconnect, and the
      # restart replayed the same reorg.
      st =
        if st.mempool do
          {:ok, b} = Archive.read_block_txs(st.a, Archive.tip(st.a).id)
          mempool_event(st, {:disconnected, b.txs})
        else
          st
        end

      old = Archive.tip(st.a).hash
      {a, _id} = Archive.disconnect_tip(st.a)
      note_durable(a)
      # The disconnect lowered the committed tip: readers must not keep the
      # old height while the new branch is connected above it.
      :ets.insert(st.view, [
        {:tip, Archive.tip(a)},
        {:committed, Archive.committed_tip(a).height},
        {:reader, Archive.reader(a)}
      ])

      notify(st, {:block_disconnected, old})
      disconnect_to(%{st | a: a, disconnected: MapSet.put(st.disconnected, old)}, fork)
    else
      st
    end
  end

  # Archive.connect is contained too. An exception or exit
  # becomes {:crash, error, stacktrace}, unless it comes from the storage layer
  # itself (segment files, KV): a disk error is not the block's fault, so it
  # stays fatal and is not quarantined (as Core AbortNode on a write failure).
  defp archive_connect(st, %{entry: entry, block: block, res: res} = item) do
    t1 = System.monotonic_time(:microsecond)

    prepared =
      case item do
        %{apre: {:done, p}} -> p
        _ -> nil
      end

    a =
      Archive.connect(st.a, block, entry.height, res.spent,
        delta: res.delta,
        commit: false,
        history: Map.get(item, :history),
        prepared: prepared
      )

    if hook = st.test_archive_hook, do: hook.(block)
    {:ok, a, System.monotonic_time(:microsecond) - t1}
  catch
    kind, reason ->
      if storage_failure?(__STACKTRACE__) or out_of_memory?(kind, reason),
        do: :erlang.raise(kind, reason, __STACKTRACE__)

      {:crash, {kind, reason}, __STACKTRACE__}
  end

  # Native memory exhausted (the overlay's tables, Archive.Overlay): a fault
  # of this host, not of the block, so fatal like a storage failure, never a
  # quarantine. The restart discards the half-applied tables.
  defp out_of_memory?(:error, :enomem), do: true
  defp out_of_memory?(_kind, _reason), do: false

  # The innermost exnode frame is the storage layer.
  defp storage_failure?(stack) do
    case Enum.find(stack, fn {m, _, _, _} ->
           String.starts_with?(Atom.to_string(m), "Elixir.Exnode.")
         end) do
      {m, _, _, _} -> m in [Exnode.Archive.Segments, Exnode.Store.KV]
      nil -> false
    end
  end

  # A crash inside Archive.connect cannot be contained in place like a
  # validation crash: it may have appended to the segment files (the file
  # position moved) and updated the chain ETS tables and the overlay's
  # native tables, none of which the old archive struct reflects (the
  # overlay's are freed once no process holds a reference to them). So the block is quarantined (the
  # same durable mark, crash report and :crash to its source) and the chain
  # state exits: its restart reopens the archive at the last commit
  # (segments truncated to the committed ends), replays the uncommitted
  # blocks from `pending`, and skips the quarantined one, so there is no
  # crash loop. terminate/2 commits only the state from before this
  # callback, and only when no durable write happened during this callback
  # (see durable_current?/1), so it is consistent with the disk.
  defp archive_crashed(st, %{entry: entry, block: block}, {:crash, error, stack}) do
    hex = Exnode.Crypto.Hash.to_hex(entry.hash)
    msg = crash_message(error, stack)

    Logger.critical(
      "block #{hex} at #{entry.height}: archiving crashed, block quarantined (please report); " <>
        "restarting the chain state from its last commit:\n#{msg}"
    )

    poison(st, entry, block, error, msg)
    exit({:shutdown, {:archive_crashed, hex}})
  end

  defp archive_block(
         st,
         %{entry: entry, block: block, res: res} = item,
         a,
         archive_us,
         scripts_us
       ) do
    Process.put(:perf_scripts_us, (Process.get(:perf_scripts_us) || 0) + scripts_us)
    st = perf(st, block, item.validate_us, archive_us)
    key = if res.scripts_checked, do: :checked, else: :skipped
    st = update_in(st.script_stats[key], &(&1 + 1))
    notify(st, {:block_connected, entry.hash, entry.height})

    st =
      mempool_event(
        st,
        {:connected,
         for(
           tx <- block.txs,
           do: %{
             txid: tx.txid,
             wtxid: tx.wtxid,
             prevouts: for(i <- tx.inputs, do: {i.prev_hash, i.prev_index})
           }
         )}
      )

    :ets.insert(st.view, {:tip, Archive.tip(a)})
    # The pending copy and the view's held entry go when the batch commits.
    st = %{
      st
      | a: a,
        blocks: MapSet.delete(st.blocks, entry.hash),
        sources: Map.delete(st.sources, entry.hash),
        disconnected: MapSet.delete(st.disconnected, entry.hash),
        checked: MapSet.delete(st.checked, entry.hash),
        uncommitted: [{entry.hash, block.raw} | st.uncommitted]
    }

    {n, bytes} = Archive.batch_size(a)
    if n >= st.batch_blocks or bytes >= st.batch_bytes, do: commit(st), else: st
  end

  defp fail_block(st, entry, block, {:error, {result_kind, reason} = r}) do
    Logger.warning(
      "block #{Exnode.Crypto.Hash.to_hex(entry.hash)} at #{entry.height} invalid: #{reason}"
    )

    # Commit the valid blocks before it, so the shadow sees them first.
    st = commit(st)

    # Core: InvalidBlockFound, but never for MUTATED (the data may be wrong, not the block).
    if result_kind != :mutated,
      do: Headers.invalidate(st.headers, entry.hash, Archive.tip(st.a).hash)

    notify(st, {:block_invalid, entry.hash, r})
    # Core BlockChecked: the peer that sent a block found invalid on connect
    # may be punished (MaybePunishNodeForBlock).
    {source, sources} = Map.pop(st.sources, entry.hash)
    if is_pid(source), do: send(source, {:block_checked, entry.hash, {:error, r}})
    st = unhold(%{st | sources: sources}, entry.hash) |> unhold_failed()

    %{
      st
      | disconnected: MapSet.delete(st.disconnected, entry.hash),
        checked: MapSet.delete(st.checked, entry.hash),
        last_failure: r,
        round_rejected: [{entry.hash, block.raw, r} | st.round_rejected],
        rejected_seen:
          if(st.waiters == [],
            do: st.rejected_seen,
            else: Map.put(st.rejected_seen, entry.hash, r)
          )
    }
  end

  # A block whose processing raised: quarantined, not failed. Like
  # fail_block/4, except that the header is NOT invalidated (our bug or bad
  # data, not proof of invalidity), the mark is durable and written first,
  # the pending copy is kept (for reconsider_poisoned/2), and a crash report
  # is written. The source peer is told, as a :crash, which peers never
  # punish.
  defp quarantine_block(st, entry, block, {:crash, error, stack}) do
    hash = entry.hash
    hex = Exnode.Crypto.Hash.to_hex(hash)
    msg = crash_message(error, stack)

    Logger.critical(
      "block #{hex} at #{entry.height}: validation crashed, block quarantined (please report):\n#{msg}"
    )

    st = commit(st)
    sources = poison(st, entry, block, error, msg)

    %{
      st
      | poisoned: MapSet.put(st.poisoned, hash),
        blocks: MapSet.delete(st.blocks, hash),
        sources: sources,
        disconnected: MapSet.delete(st.disconnected, hash),
        checked: MapSet.delete(st.checked, hash),
        last_failure: {:crash, "validation crashed"}
    }
  end

  defp crash_message({kind, reason}, stack) when kind in [:exit, :throw, :error],
    do: Exception.format(kind, reason, stack)

  defp crash_message(e, stack), do: Exception.format(:error, e, stack)

  # The quarantine itself: the durable mark (written first, fsynced), the
  # crash report, the event, and :crash to the source peer. Returns the
  # sources without this block's.
  defp poison(st, entry, block, error, msg) do
    hash = entry.hash

    mark =
      :erlang.term_to_binary(%{
        height: entry.height,
        time: System.os_time(:second),
        error: inspect(error, limit: 50)
      })

    :ok = Exnode.Store.KV.write(st.kv, [{:put, :poisoned, hash, mark}], sync: true)
    write_crash_report(st, entry, block, msg)

    notify(st, {:block_quarantined, hash, error})
    {source, sources} = Map.pop(st.sources, hash)

    if is_pid(source),
      do: send(source, {:block_checked, hash, {:error, {:crash, "validation crashed locally"}}})

    :ets.delete(st.view, {:held, hash})
    :ets.insert(st.view, {{:quarantined, hash}})
    sources
  end

  defp write_crash_report(st, entry, block, msg) do
    raw =
      case block do
        %Block{raw: raw} when is_binary(raw) ->
          raw

        _ ->
          case Exnode.Store.KV.get(st.kv, :pending, entry.hash),
            do: (
              {:ok, raw} -> raw
              _ -> <<>>
            )
      end

    File.mkdir_p!(st.crash_dir)
    hex = Exnode.Crypto.Hash.to_hex(entry.hash)

    File.write!(Path.join(st.crash_dir, hex <> ".log"), """
    block: #{hex}
    height: #{entry.height}
    time: #{DateTime.utc_now() |> DateTime.to_iso8601()}

    #{msg}

    block hex:
    #{Base.encode16(raw, case: :lower)}
    """)
  rescue
    e -> Logger.error("could not write crash report: #{Exception.message(e)}")
  end

  defp load_block(st, entry) do
    case Map.get(st.current_blocks, entry.hash) do
      %Block{} = b ->
        b

      nil ->
        if MapSet.member?(st.blocks, entry.hash),
          do: pending_block(st, entry.hash) || read_archived(st, entry.hash),
          else: read_archived(st, entry.hash)
    end
  end

  # Per-stage timing, logged every 30 s: validation (checks + ConnectBlock incl.
  # scripts, with scripts and input resolution also broken out) and archive write.
  defp perf(st, block, validate_us, archive_us) do
    p =
      Map.get(st, :perf) ||
        %{
          blocks: 0,
          txs: 0,
          inputs: 0,
          validate: 0,
          archive: 0,
          since: System.monotonic_time(:millisecond)
        }

    inputs = Enum.reduce(block.txs, 0, &(&2 + length(&1.inputs)))
    scripts = Process.delete(:perf_scripts_us) || 0
    resolve = Process.delete(:perf_resolve_us) || 0
    pfwait = Process.delete(:perf_pfwait_us) || 0

    p = %{
      p
      | blocks: p.blocks + 1,
        txs: p.txs + length(block.txs),
        inputs: p.inputs + inputs,
        validate: p.validate + validate_us,
        archive: p.archive + archive_us
    }

    p =
      Map.update(p, :scripts, scripts, &(&1 + scripts))
      |> Map.update(:resolve, resolve, &(&1 + resolve))
      |> Map.update(:pfwait, pfwait, &(&1 + pfwait))

    # Cumulative chain-state times for work_stats/1 (the perf line shows windows).
    st = %{
      st
      | cs_work:
          add_counts(st.cs_work, %{
            blocks: 1,
            block_bytes: byte_size(block.raw || <<>>),
            inputs: inputs,
            validate_us: validate_us,
            resolve_us: resolve,
            scripts_wait_us: scripts,
            append_us: archive_us,
            pfwait_us: pfwait
          })
    }

    now = System.monotonic_time(:millisecond)

    if now - p.since >= 30_000 do
      secs = (now - p.since) / 1000
      st = take_cs_work(st)
      c = Map.get(st, :cs_window, %{})
      w = st.pf_window
      g = fn m, k -> Map.get(m, k, 0) end
      pf = fn k -> st.pf_stats[k] - st.pf_logged[k] end
      v = Map.merge(Process.delete(:perf_vwin) || %{}, Exnode.Validation.Connect.take_split())

      # `archive append` is Archive.connect only; commits (segment fsync, KV
      # batch) are timed separately. Worker busy time is summed over
      # concurrent tasks: it overlaps and is not elapsed time.
      Logger.info(
        "perf: #{p.blocks} blk (#{Float.round(p.blocks / secs, 1)}/s) #{p.txs} tx #{p.inputs} in; " <>
          "validate #{ms(p.validate)}ms (resolve #{ms(p.resolve)}ms), script latency #{ms(p.scripts)}ms (overlapping) " <>
          "archive append #{ms(p.archive)}ms; commit #{g.(c, :commits)}x #{ms(g.(c, :commit_us))}ms " <>
          "(sync #{ms(g.(c, :commit_sync_us))}ms, kv #{ms(g.(c, :commit_kv_us))}ms) over #{Float.round(secs, 1)}s; " <>
          "prefetch used #{pf.(:used)} revalidated #{pf.(:revalidated)} (dropped #{pf.(:reval_dropped)} answers) stale #{pf.(:stale)} none #{pf.(:none)} wait #{ms(p.pfwait)}ms; " <>
          "prefetch ops #{g.(w, :considered)} omitted #{g.(w, :omitted)} sent #{g.(w, :sent)}, " <>
          "worker busy #{ms(g.(w, :worker_us))}ms (overlapping), worker reads #{g.(w, :output_groups)} groups " <>
          "#{g.(w, :preads)} preads #{div(g.(w, :pread_bytes), 1024)}KiB; chain-state committed ops #{g.(c, :committed_ops)}, " <>
          "reads #{g.(c, :output_groups)} groups #{g.(c, :preads)} preads #{div(g.(c, :pread_bytes), 1024)}KiB; " <>
          "archive: prepared #{g.(c, :append_prepared)} mismatched #{g.(c, :append_prepared_mismatch)}, " <>
          "encode #{ms(g.(c, :append_encode_us))}ms segments #{ms(g.(c, :append_segments_us))}ms " <>
          "txindex #{ms(g.(c, :append_txindex_us))}ms (reads #{g.(c, :txindex_reads)}, read #{ms(g.(c, :txindex_read_us))}ms, " <>
          "hint stale #{g.(c, :txindex_hint_stale)}) overwritten #{ms(g.(c, :append_overwritten_us))}ms " <>
          "record #{ms(g.(c, :append_record_us))}ms overlay #{ms(g.(c, :connect_overlay_us))}ms " <>
          "(spent #{ms(g.(c, :ov_spent_us))}ms created #{ms(g.(c, :ov_created_us))}ms) chain #{ms(g.(c, :connect_chain_us))}ms; " <>
          "validation: check_block #{ms(g.(v, :checkblock))}ms contextual #{ms(g.(v, :contextual))}ms " <>
          "connect #{ms(g.(v, :connect))}ms (resolve #{ms(p.resolve)}ms, loop #{ms(g.(v, :txloop))}ms ages #{ms(g.(v, :ages))}ms " <>
          "finish #{ms(g.(v, :finish))}ms); " <>
          cs_line(Process.delete(:perf_cs) || %{}, round(secs * 1_000_000))
      )

      %{
        st
        | pf_logged: st.pf_stats,
          pf_window: %{}
      }
      |> Map.put(:cs_window, %{})
      |> Map.put(:perf, nil)
    else
      Map.put(st, :perf, p)
    end
  end

  defp add_counts(a, b), do: Map.merge(a, b, fn _k, x, y -> x + y end)

  # The chain state's own archive counters (lookups, reads, commits), taken
  # from its process dictionary into the cumulative and window totals.
  defp take_cs_work(st) do
    io = Map.merge(Archive.take_stats(), Exnode.Validation.Connect.take_stats())
    st = %{st | cs_work: add_work(st.cs_work, io)}
    Map.update(st, :cs_window, io, &add_work(&1, io))
  end

  # Sums, except maxima (`*_max_us`).
  defp add_work(a, b),
    do:
      Map.merge(a, b, fn k, x, y ->
        if String.ends_with?(Atom.to_string(k), "_max_us"), do: max(x, y), else: x + y
      end)

  defp ms(us), do: div(us, 1000)

  # Test-only hook to inject a deliberate consensus divergence (shadow tests).
  defp override(%{rule_override: f}, block, entry) when is_function(f, 2), do: f.(block, entry)
  defp override(_st, _block, _entry), do: :ok

  defp read_archived(st, hash) do
    raw =
      case Archive.read_block(st.a, Archive.block_id(st.a, hash)) do
        raw when is_binary(raw) ->
          raw

        # As in Core with pruning: a reorg deeper than the kept blocks cannot
        # reconnect from local data.
        {:error, :witness_pruned} ->
          raise "reorg needs block #{Exnode.Crypto.Hash.to_hex(hash)}, whose witness data is pruned"
      end

    {:ok, b} = Block.decode_exact(raw)
    b
  end

  defp catch_exit(f) do
    f.()
  catch
    :exit, _ -> :ok
  end

  # A listener may be a registered name that is restarting in another
  # subtree; `send/2` to an unregistered name would raise here.
  defp notify(st, msg) do
    Enum.each(st.listeners, fn l -> if pid = GenServer.whereis(l), do: send(pid, msg) end)
  end
end
