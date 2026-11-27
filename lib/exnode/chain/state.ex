defmodule Exnode.Chain.State do
  @moduledoc """
  Chain state: owns the archive and decides which blocks count. Mirrors
  Core v32.1 `Chainstate::ActivateBestChain`, `ConnectTip`, `DisconnectTip`
  and `InvalidBlockFound`.

  * Received blocks are kept on disk (`pending`) until connected (`submit_block/3`).
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
  `:batch_blocks` / `:batch_bytes`), when the oldest is `@batch_ms` old
  (`@batch_ms_behind` while the tip is at least `@near_tip_blocks` behind
  the best header, option `:near_tip_blocks`), when the tip reaches the best
  header, before any disconnect or rejection, and on shutdown. A block's
  `pending` copy is deleted in the same KV batch that commits it, so a crash
  loses nothing that cannot be reconnected from `pending`.

  Public ETS view (`Exnode.Chain.View`), quarantine & halt persistence
  (`Exnode.Chain.Quarantine`), and callback / periodic perf telemetry
  (`Exnode.Chain.Telemetry`) live in dedicated submodules.
  """
  use GenServer
  require Logger

  alias Exnode.Archive
  alias Exnode.Archive.Segments
  alias Exnode.Archive.Writer, as: ArchiveWriter
  alias Exnode.Chain.{GcProbe, HeaderIndex, Headers, Prefetch, Quarantine, Telemetry, View}
  alias Exnode.Codec.Block
  alias Exnode.Consensus.Pow
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Validation.AssumeValid
  alias Exnode.Validation.Block, as: BlockRules
  alias Exnode.Validation.{Connect, ScriptExec, Scripts}

  @batch_blocks 128
  @batch_bytes 64 * 1024 * 1024
  @batch_ms 5_000
  @batch_ms_behind 300_000
  @near_tip_blocks 128
  @prefetch_depth 8
  @activation_step 32
  @pipeline_depth 8
  @pipeline_bytes 256 * 1024 * 1024
  @turn_ms 50
  @min_blocks_to_keep 288

  defstruct [
    :p,
    :headers,
    :writer,
    :writer_private,
    :archive_handles,
    :writer_meta,
    :kv,
    :view,
    :exec,
    :exec_private,
    :worker_sup,
    :worker_sup_private,
    :assume_valid,
    :rule_override,
    :test_script_hook,
    :test_archive_hook,
    :test_archive_prep_hook,
    :crash_dir,
    :monitor,
    :availability,
    :last_failure,
    :mempool,
    :reorg_work,
    :plan,
    :pf_wait_since,
    :perf,
    :gc_probe,
    telemetry: %Telemetry{},
    blocks: MapSet.new(),
    script_stats: %{checked: 0, skipped: 0},
    test_skip_scripts: false,
    poisoned: MapSet.new(),
    halted: false,
    round_connected: [],
    round_rejected: [],
    uncommitted: [],
    batch_blocks: @batch_blocks,
    batch_bytes: @batch_bytes,
    batch_ms: @batch_ms,
    batch_ms_behind: @batch_ms_behind,
    near_tip_blocks: @near_tip_blocks,
    prefetch_depth: @prefetch_depth,
    pf_stats: %{used: 0, revalidated: 0, reval_dropped: 0, stale: 0, none: 0},
    pf_logged: %{used: 0, revalidated: 0, reval_dropped: 0, stale: 0, none: 0},
    pf_work: %{},
    cs_work: %{},
    pf_window: %{},
    cs_window: %{},
    catch_up_chunk: 128,
    commit_at_tip: true,
    checked: MapSet.new(),
    activation_step: @activation_step,
    turn_ms: @turn_ms,
    pipeline_depth: @pipeline_depth,
    pipeline_bytes: @pipeline_bytes,
    archive_prep: true,
    plan_seq: 0,
    drive_queued: false,
    retarget: true,
    waiters: [],
    current_blocks: %{},
    rejected_seen: %{},
    pstats: %{},
    sources: %{},
    listeners: [],
    disconnected: MapSet.new(),
    next_sequence: 2,
    unlinked: %{},
    mempool_events: [],
    turn_retired: 0
  ]

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  Submits a block (decoded `%Block{}`). Returns
  `{:ok, :connected | :stored | :duplicate | :skipped}` or `{:error, {result, reason}}`.
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
  """
  def precheck_block(server, header, requested),
    do: GenServer.call(server, {:precheck_block, header, requested}, :infinity)

  @doc """
  Core `CheckBlock` for `b`, run by the caller (a peer process, in parallel
  with other peers) instead of the chain state.
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
  Work counters since start (tests, diagnostics): `%{prefetch, chain_state,
  pipeline, exec}`.
  """
  def work_stats(server), do: GenServer.call(server, :work_stats, 5_000)

  @doc "Blocks prefetched ahead when the caller does not set `prefetch_depth`."
  def default_prefetch_depth, do: @prefetch_depth

  @doc "Default commit batch limits: `{blocks, bytes}`."
  def default_batch_limits, do: {@batch_blocks, @batch_bytes}

  @doc "Default minimum heap floor for the chain state (nil: use the BEAM VM default)."
  def default_min_heap_size, do: nil

  @doc "Default minimum binary virtual heap floor for the chain state (nil: use the BEAM VM default)."
  def default_min_bin_vheap_size, do: nil

  @doc "Subscribes `pid` to archive commit/disconnect events (`{:archive_committed, tip}` / `{:archive_disconnected, tip}`)."
  def subscribe_commits(server, pid \\ self()),
    do: GenServer.call(server, {:subscribe_commits, pid}, 5_000)

  @doc "Unsubscribes `pid` from archive commit/disconnect events."
  def unsubscribe_commits(server, pid \\ self()),
    do: GenServer.cast(server, {:unsubscribe_commits, pid})

  def tip(server), do: GenServer.call(server, :tip, :infinity)
  def have_block?(server, hash), do: GenServer.call(server, {:have?, hash}, 5_000)

  @doc "The subset of `hashes` whose block data we have (in memory or archived)."
  def have_many(server, hashes), do: GenServer.call(server, {:have_many, hashes}, :infinity)

  # --- view & quarantine delegations -------------------------------------------

  defdelegate view(server), to: View
  defdelegate view_reader(view), to: View
  defdelegate reader(server), to: View
  defdelegate view_committed(view), to: View
  defdelegate view_halted(view), to: View
  defdelegate view_tip(view), to: View
  defdelegate view_ibd?(view, idx, now, params), to: View
  defdelegate view_have?(view, hash), to: View
  defdelegate view_have_many(view, hashes), to: View
  defdelegate halt_mark(kv), to: Quarantine

  @doc "Runs `fun.(archive)` inside the chain-state process (the archive's file handles belong to it)."
  def with_archive(server, fun), do: GenServer.call(server, {:with_archive, fun}, :infinity)

  @doc false
  # Test only: runs `fun.(archive)` without committing the batch first.
  def peek_archive(server, fun), do: GenServer.call(server, {:peek_archive, fun}, :infinity)

  @doc """
  The mempool's view of the chain (Core `CCoinsViewCache` at the tip):
  `{tip, %{outpoint => {:ok, coin} | :missing}}`. Reads lock-free through the
  published `Chain.View` seqlock (overlay + committed reader) when `server` is
  a registered name, falling back to a `GenServer.call` on contention or for
  unnamed test PIDs.
  """
  def mempool_view(server, outpoints) do
    {ok, bad} = Enum.split_with(outpoints, fn {_, v} -> is_integer(v) and v in 0..0xFFFFFFFF end)

    {tip, found} =
      case View.view(server) do
        nil ->
          GenServer.call(server, {:mempool_view, ok}, :infinity)

        view ->
          case View.resolve_active(view, ok) do
            {:ok, res} -> res
            :retry -> GenServer.call(server, {:mempool_view, ok}, :infinity)
          end
      end

    {tip, Enum.reduce(bad, found, &Map.put(&2, &1, :missing))}
  end

  @doc """
  Clears quarantine marks (`:all` or one block hash) once the cause is
  fixed. Returns the hashes cleared.
  """
  def reconsider_poisoned(server, which \\ :all),
    do: GenServer.call(server, {:reconsider_poisoned, which}, :infinity)

  @doc "The quarantined block hashes."
  def poisoned(server), do: GenServer.call(server, :poisoned, 5_000)

  @doc """
  Clears a durable halt (shadow divergence): deletes the mark and resumes
  block connection, held blocks included. Returns the halt reason cleared,
  or `:not_halted`.
  """
  def clear_halt(server), do: GenServer.call(server, :clear_halt, :infinity)

  @doc "Commits the archive batch now."
  def commit_now(server), do: GenServer.call(server, :commit, :infinity)

  @doc "Waits until any queued activation / startup replay has settled."
  def await_idle(server, timeout \\ :infinity), do: GenServer.call(server, :await_idle, timeout)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    if n = opts[:min_heap_size], do: Process.flag(:min_heap_size, n)
    if n = opts[:min_bin_vheap_size], do: Process.flag(:min_bin_vheap_size, n)
    gc_probe = if opts[:gc_probe], do: GcProbe.start()
    p = Keyword.fetch!(opts, :params)
    headers = Keyword.fetch!(opts, :headers)

    kv =
      case Keyword.fetch(opts, :kv) do
        {:ok, kv} -> kv
        :error -> Exnode.Node.Runtime.kv(Keyword.fetch!(opts, :node_name))
      end

    {writer, writer_private} =
      case Keyword.get(opts, :archive_writer) do
        nil ->
          writer_opts =
            [
              params: p,
              headers: headers,
              kv: kv,
              view_name: opts[:name]
            ] ++
              Keyword.take(opts, [
                :hot,
                :cold,
                :segment_max,
                :cache_bytes,
                :prune_witness,
                :prune_keep
              ])

          {:ok, pid} = ArchiveWriter.start_link(writer_opts)
          {pid, {pid, Process.monitor(pid)}}

        w ->
          {w, nil}
      end

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

    {worker_sup, worker_sup_private} =
      case Keyword.get(opts, :worker_sup) do
        nil ->
          {:ok, sup} = Task.Supervisor.start_link()
          {sup, sup}

        sup ->
          {sup, nil}
      end

    {view, {halted, poisoned}, archive_handles, writer_meta} = ArchiveWriter.handles(writer)

    st = %__MODULE__{
      p: p,
      headers: headers,
      writer: writer,
      writer_private: writer_private,
      archive_handles: archive_handles,
      writer_meta: writer_meta,
      kv: kv,
      view: view,
      exec: exec,
      exec_private: private && {exec, private},
      worker_sup: worker_sup,
      worker_sup_private: worker_sup_private,
      assume_valid: AssumeValid.resolve(Keyword.get(opts, :assume_valid), p),
      rule_override: Keyword.get(opts, :rule_override),
      test_skip_scripts: Keyword.get(opts, :test_skip_scripts, false),
      test_script_hook: Keyword.get(opts, :test_script_hook),
      test_archive_hook: Keyword.get(opts, :test_archive_hook),
      test_archive_prep_hook: Keyword.get(opts, :test_archive_prep_hook),
      crash_dir:
        Keyword.get_lazy(opts, :crash_dir, fn ->
          Path.join(Path.dirname(Keyword.fetch!(opts, :hot)), "crashes")
        end),
      monitor: Keyword.get(opts, :shadow_monitor),
      batch_blocks: Keyword.get(opts, :batch_blocks, @batch_blocks),
      batch_bytes: Keyword.get(opts, :batch_bytes, @batch_bytes),
      batch_ms: Keyword.get(opts, :batch_ms, @batch_ms),
      batch_ms_behind: Keyword.get(opts, :batch_ms_behind, @batch_ms_behind),
      near_tip_blocks: Keyword.get(opts, :near_tip_blocks, @near_tip_blocks),
      prefetch_depth: Keyword.get(opts, :prefetch_depth, @prefetch_depth),
      catch_up_chunk: Keyword.get(opts, :catch_up_chunk, 128),
      commit_at_tip: Keyword.get(opts, :commit_at_tip, true),
      activation_step: Keyword.get(opts, :activation_step, @activation_step),
      turn_ms: Keyword.get(opts, :turn_ms, @turn_ms),
      pipeline_depth: Keyword.get(opts, :pipeline_depth, @pipeline_depth),
      pipeline_bytes: Keyword.get(opts, :pipeline_bytes, @pipeline_bytes),
      archive_prep: Keyword.get(opts, :archive_prep, true),
      listeners: Keyword.get(opts, :listeners, []),
      availability: :ets.new(:block_availability, [:set, :private]),
      mempool: Keyword.get(opts, :mempool),
      gc_probe: gc_probe,
      halted: halted,
      poisoned: poisoned
    }

    st =
      st
      |> load_candidates()
      |> load_pending()
      |> publish()

    Process.send_after(self(), :commit_tick, @batch_ms)
    {:ok, st, {:continue, :startup}}
  end

  @impl true
  def handle_continue(:startup, st) do
    # Catch the shadow validator up to the already-committed tip BEFORE replaying
    # any uncommitted pending blocks, so rounds produced during replay never reach
    # a behind shadow (or if shadow is ahead, set_ahead is registered first).
    st = run_shadow_catch_up(st)
    st = if st.retarget, do: drive(st), else: st
    {:noreply, st}
  end

  defp run_shadow_catch_up(%__MODULE__{monitor: nil} = st), do: st

  defp run_shadow_catch_up(st) do
    {:ok, {sh, shash}} = Exnode.Shadow.Monitor.shadow_tip(st.monitor)
    st = commit(st)
    a = active_archive(st)
    tip = st.writer_meta.tip

    if sh > tip.height do
      Exnode.Shadow.Monitor.set_ahead(st.monitor, {sh, shash})
    else
      start =
        if (id = Archive.id_at(a, sh)) && Archive.block_record!(a, id).hash == shash,
          do: sh + 1,
          else: 1

      catch_up(st, start, tip.height)
    end

    flush_round(%{st | round_connected: []})
  end

  defp catch_up(_st, from, to) when from > to, do: :ok

  defp catch_up(st, from, to) do
    stop = min(to, from + st.catch_up_chunk - 1)
    a = active_archive(st)

    blocks =
      for h <- from..stop//1,
          id = Archive.id_at(a, h),
          do: {Archive.block_record!(a, id).hash, Archive.read_block(a, id)}

    if Enum.any?(blocks, &match?({_, {:error, _}}, &1)) do
      Logger.error("shadow catch-up impossible from height #{from}: witness data pruned; halting")
      GenServer.cast(self(), {:halt, :shadow_behind_pruned})
    else
      Logger.info("shadow catch-up: feeding archived blocks #{from}..#{stop}")
      Exnode.Shadow.Monitor.round(st.monitor, blocks, [], elem(List.last(blocks), 0))
      catch_up(st, stop + 1, to)
    end
  end

  defp publish(st) do
    ArchiveWriter.view_op(st.writer, :publish)
    st
  end

  defp hold(st, hash, %Block{raw: raw}) do
    :ok = KV.write(st.kv, [{:put, :pending, hash, raw}], sync: false)
    ArchiveWriter.view_op(st.writer, {:hold, hash})
    %{st | blocks: MapSet.put(st.blocks, hash), retarget: true} |> received_block(hash)
  end

  # --- batching ------------------------------------------------------------

  defp commit(%__MODULE__{uncommitted: []} = st), do: st

  defp commit(st) do
    hashes = Enum.map(st.uncommitted, &elem(&1, 0))
    {:ok, meta} = ArchiveWriter.flush(st.writer, hashes)

    %{
      st
      | writer_meta: meta,
        round_connected: st.uncommitted ++ st.round_connected,
        uncommitted: []
    }
  end

  defp maybe_commit(%__MODULE__{uncommitted: []} = st), do: st

  defp maybe_commit(st) do
    %{batch_n: n, batch_bytes: bytes, batch_since: since, tip: tip} = st.writer_meta
    age = System.monotonic_time(:millisecond) - (since || 0)
    best = HeaderIndex.best(Headers.index(st.headers))
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
    :ok = KV.write(st.kv, [{:delete, :pending, hash}], sync: false)
    ArchiveWriter.view_op(st.writer, {:unhold, hash})
    :ets.delete(st.availability, hash)
    %{st | blocks: MapSet.delete(st.blocks, hash), sources: Map.delete(st.sources, hash)}
  end

  defp unhold_failed(st) do
    idx = Headers.index(st.headers)

    {st, dropped} =
      Enum.reduce(st.blocks, {st, MapSet.new()}, fn h, {st, acc} ->
        case HeaderIndex.lookup(idx, h) do
          %{status: :failed} ->
            {%{unhold(st, h) | checked: MapSet.delete(st.checked, h)}, MapSet.put(acc, h)}

          _ ->
            {st, acc}
        end
      end)

    unlinked =
      if MapSet.size(dropped) == 0 do
        st.unlinked
      else
        for {p, cs} <- st.unlinked,
            kept = Enum.reject(cs, &MapSet.member?(dropped, &1)),
            kept != [],
            into: %{},
            do: {p, kept}
      end

    disconnected =
      Enum.reject(st.disconnected, fn h ->
        match?(%{status: :failed}, HeaderIndex.lookup(idx, h))
      end)
      |> MapSet.new()

    %{st | unlinked: unlinked, disconnected: disconnected}
  end

  defp load_pending(st) do
    hashes = KV.fold_keys(st.kv, :pending, <<>>, [], &[&1 | &2])
    hashes = Enum.reject(hashes, &MapSet.member?(st.poisoned, &1))
    idx = Headers.index(st.headers)

    a = active_archive(st)

    {dropped, held} =
      Enum.split_with(
        hashes,
        &(Archive.block_id(a, &1) != nil or
            match?(e when e == nil or e.status == :failed, HeaderIndex.lookup(idx, &1)))
      )

    if dropped != [],
      do: :ok = KV.write(st.kv, for(h <- dropped, do: {:delete, :pending, h}), sync: false)

    ArchiveWriter.view_op(st.writer, {:hold_many, held})
    st = %{st | blocks: MapSet.new(held)}

    held
    |> Enum.sort_by(fn h ->
      case HeaderIndex.lookup(idx, h) do
        nil -> {0, h}
        e -> {e.height, h}
      end
    end)
    |> Enum.reduce(st, &link_block(&2, idx, &1, 1))
  end

  defp load_candidates(st) do
    a = active_archive(st)

    disconnected =
      KV.fold_prefix(st.kv, :blockhash, <<>>, MapSet.new(), fn {hash, <<id::32>>}, acc ->
        active = Archive.on_chain?(a, id)
        :ets.insert(st.availability, {hash, if(active, do: 0, else: 1)})
        if active, do: acc, else: MapSet.put(acc, hash)
      end)

    %{st | disconnected: disconnected}
  end

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

  defp pending_block(st, hash) do
    case KV.get(st.kv, :pending, hash) do
      {:ok, raw} ->
        {:ok, b} = Block.decode_exact(raw)
        b

      :not_found ->
        nil
    end
  end

  @impl true
  def handle_call(msg, from, st),
    do: Telemetry.timed_cb(msg, st, st.gc_probe != nil, &do_handle_call(msg, from, &1))

  defp do_handle_call(:await_idle, from, st) do
    if st.plan == nil and not st.drive_queued and not st.retarget do
      {:reply, :ok, st}
    else
      {:noreply, %{st | waiters: [{:reply, from, :ok} | st.waiters]} |> queue_drive()}
    end
  end

  defp do_handle_call({:subscribe_commits, pid}, _from, st) do
    {:reply, ArchiveWriter.subscribe(st.writer, pid), st}
  end

  defp do_handle_call(:tip, _from, st), do: {:reply, st.writer_meta.tip, st}
  defp do_handle_call({:set_monitor, m}, _from, st), do: {:reply, :ok, %{st | monitor: m}}

  defp do_handle_call(:script_stats, _from, st), do: {:reply, st.script_stats, st}
  defp do_handle_call(:prefetch_stats, _from, st), do: {:reply, st.pf_stats, st}

  defp do_handle_call(:work_stats, _from, st) do
    st = Telemetry.take_cs_work(st)

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

  defp do_handle_call(:debug_live, _from, st), do: {:reply, Telemetry.debug_live(st), st}

  defp do_handle_call({:have?, hash}, _from, st), do: {:reply, have?(st, hash), st}

  defp do_handle_call({:have_many, hashes}, _from, st),
    do:
      {:reply,
       MapSet.new(Enum.filter(hashes, &(have?(st, &1) or MapSet.member?(st.poisoned, &1)))), st}

  defp do_handle_call({:with_archive, fun}, _from, st) do
    st = commit(st)
    {:reply, ArchiveWriter.with_archive(st.writer, [], fun), st}
  end

  defp do_handle_call({:peek_archive, fun}, _from, st),
    do: {:reply, ArchiveWriter.peek_archive(st.writer, fun), st}

  defp do_handle_call({:mempool_view, ops}, _from, st),
    do: {:reply, ArchiveWriter.mempool_view(st.writer, ops), st}

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
    if reply == :connect, do: {:noreply, st}, else: {:reply, reply, st}
  end

  defp do_handle_call(:halted, _from, st), do: {:reply, st.halted, st}

  defp do_handle_call(:clear_halt, _from, %__MODULE__{halted: false} = st),
    do: {:reply, :not_halted, st}

  defp do_handle_call(:clear_halt, _from, st) do
    ArchiveWriter.clear_halt_mark(st.writer)
    Logger.warning("block connection halt cleared (was #{inspect(st.halted)})")
    {:reply, st.halted, queue_drive(%{st | halted: false, retarget: true})}
  end

  defp do_handle_call(:poisoned, _from, st), do: {:reply, MapSet.to_list(st.poisoned), st}

  defp do_handle_call({:reconsider_poisoned, which}, from, st) do
    {hashes, poisoned} = ArchiveWriter.clear_poisoned(st.writer, st.poisoned, which)
    st = %{st | poisoned: poisoned}

    a = active_archive(st)

    st =
      Enum.reduce(hashes, st, fn h, st ->
        id = Archive.block_id(a, h)

        cond do
          KV.get(st.kv, :pending, h) != :not_found ->
            ArchiveWriter.view_op(st.writer, {:hold, h})
            %{st | blocks: MapSet.put(st.blocks, h)} |> received_block(h)

          id != nil and not Archive.on_chain?(a, id) ->
            %{st | disconnected: MapSet.put(st.disconnected, h)}

          true ->
            st
        end
      end)

    st = %{st | retarget: true, waiters: [{:reply, from, hashes} | st.waiters]} |> queue_drive()
    {:noreply, st}
  end

  @impl true
  def handle_info(msg, st),
    do: Telemetry.timed_cb(msg, st, st.gc_probe != nil, &do_handle_info(msg, &1))

  defp do_handle_info(:drive, st), do: {:noreply, drive(%{st | drive_queued: false})}

  defp do_handle_info({:script_exec, tag, outcome, wstats}, st),
    do: {:noreply, script_result(st, tag, outcome, wstats)}

  defp do_handle_info({:prefetch_done, tag, result}, st),
    do: {:noreply, prefetch_result(st, tag, result)}

  defp do_handle_info({:archive_prep_done, tag, result}, st),
    do: {:noreply, archive_prep_result(st, tag, result)}

  defp do_handle_info(
         {:DOWN, mref, :process, _, reason},
         %__MODULE__{exec_private: {_, mref}} = st
       ),
       do: {:stop, {:script_exec_down, reason}, st}

  defp do_handle_info(
         {:DOWN, mref, :process, _, reason},
         %__MODULE__{writer_private: {_, mref}} = st
       ),
       do: {:stop, {:archive_writer_down, reason}, st}

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

  @impl true
  def terminate(reason, st) do
    st = cancel_plan(st)

    # Commit uncommitted blocks only on clean shutdown. On abnormal crashes or
    # archive-crash exits, leave the last durable commit intact so restart
    # replays from :pending.
    clean_stop? =
      reason in [:normal, :shutdown] or
        (match?({:shutdown, _}, reason) and not match?({:shutdown, {:archive_crashed, _}}, reason))

    if clean_stop? do
      try do
        commit(st)
      catch
        kind, err ->
          Logger.warning(
            "chain state stopped without committing (the restart resumes from the disk): " <>
              Exception.format_banner(kind, err, __STACKTRACE__)
          )
      end
    end

    case st.writer_private do
      {pid, mref} ->
        Process.demonitor(mref, [:flush])

        if Process.alive?(pid) do
          stop_reason = if clean_stop?, do: :shutdown, else: reason
          catch_exit(fn -> GenServer.stop(pid, stop_reason, :infinity) end)
        end

      nil ->
        :ok
    end

    case st.exec_private do
      {pid, mref} ->
        Process.demonitor(mref, [:flush])

        if Process.alive?(pid),
          do: catch_exit(fn -> GenServer.stop(pid, :shutdown, :infinity) end)

      nil ->
        :ok
    end

    if is_pid(st.worker_sup_private) and Process.alive?(st.worker_sup_private) do
      catch_exit(fn -> Supervisor.stop(st.worker_sup_private, :shutdown, 5_000) end)
    end

    Segments.close_all_readers()
    :ok
  end

  @impl true
  def handle_cast(msg, st),
    do: Telemetry.timed_cb(msg, st, st.gc_probe != nil, &do_handle_cast(msg, &1))

  defp do_handle_cast({:unsubscribe_commits, pid}, st) do
    ArchiveWriter.unsubscribe(st.writer, pid)
    {:noreply, st}
  end

  defp do_handle_cast({:halt, reason}, %__MODULE__{halted: false} = st) do
    Logger.error("block connection halted: #{inspect(reason)}")
    ArchiveWriter.put_halt_mark(st.writer, reason)
    ack_halt(st)
    {:noreply, queue_drive(%{st | halted: reason})}
  end

  defp do_handle_cast({:halt, _reason}, st) do
    ack_halt(st)
    {:noreply, st}
  end

  defp ack_halt(%__MODULE__{monitor: nil}), do: :ok
  defp ack_halt(st), do: Exnode.Shadow.Monitor.halt_ack(st.monitor)

  defp flush_mempool(%__MODULE__{mempool_events: []} = st), do: st

  defp flush_mempool(%__MODULE__{reorg_work: w, plan: plan} = st) when w != nil and plan != nil do
    tip = HeaderIndex.lookup(Headers.index(st.headers), st.writer_meta.tip.hash)
    if tip.chain_work > w, do: flush_mempool(%{st | reorg_work: nil}), else: st
  end

  defp flush_mempool(st) do
    case st.mempool && GenServer.whereis(st.mempool) do
      pid when is_pid(pid) ->
        send(
          pid,
          {:mempool_update, st.writer_meta.tip.hash, Enum.reverse(st.mempool_events)}
        )

      _ ->
        :ok
    end

    %{st | mempool_events: [], reorg_work: nil}
  end

  defp mempool_event(%__MODULE__{mempool: nil} = st, _ev), do: st
  defp mempool_event(st, ev), do: %{st | mempool_events: [ev | st.mempool_events]}

  defp flush_round(%__MODULE__{round_connected: [], round_rejected: []} = st), do: st

  defp flush_round(%__MODULE__{monitor: nil} = st),
    do: %{st | round_connected: [], round_rejected: []}

  defp flush_round(st) do
    Exnode.Shadow.Monitor.round(
      st.monitor,
      Enum.reverse(st.round_connected),
      Enum.reverse(st.round_rejected),
      st.writer_meta.committed_tip.hash
    )

    %{st | round_connected: [], round_rejected: []}
  end

  defp do_submit(st, %Block{} = b, %{checked: checked} = opts) do
    hash = b.header.hash

    case submission_entry(st, b.header, opts.requested) do
      {:ok, entry, idx} ->
        with :ok <- check_block_result(checked || check_block(b, st.p)),
             :ok <- BlockRules.contextual_check_block(b, HeaderIndex.prev(idx, entry), st.p, idx) do
          st = hold(st, hash, b)
          st = %{st | checked: MapSet.put(st.checked, hash)}

          if opts.defer do
            st =
              if is_pid(opts.source),
                do: %{st | sources: Map.put(st.sources, hash, opts.source)},
                else: st

            {{:ok, :stored}, queue_drive(st)}
          else
            {:connect, st}
          end
        else
          {:check_block, reason} ->
            {{:error, reason}, st}

          {:error, {:mutated, _} = reason} ->
            {{:error, reason}, st}

          {:error, {_result, _r} = reason} ->
            fail_submitted(st, hash, reason)
        end

      {:ok, :duplicate} = reply ->
        case checked || check_block(b, st.p) do
          :ok -> {reply, st}
          {:error, reason} -> {{:error, reason}, st}
        end

      reply ->
        {reply, st}
    end
  end

  defp submission_entry(st, header, requested) do
    hash = header.hash

    cond do
      MapSet.member?(st.poisoned, hash) ->
        {:error, {:quarantined, "block is quarantined after a local validation crash"}}

      have?(st, hash) ->
        {:ok, :duplicate}

      true ->
        idx = Headers.index(st.headers)
        tip = HeaderIndex.lookup(idx, st.writer_meta.tip.hash)

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

  defp min_pow_checked?(idx, header, tip_entry, p) do
    case HeaderIndex.lookup(idx, header.prev_hash) do
      nil ->
        false

      prev ->
        prev.chain_work + Pow.bits_proof(header.bits) >=
          HeaderIndex.anti_dos_work_threshold(tip_entry, p)
    end
  end

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
    Headers.invalidate(st.headers, hash, st.writer_meta.tip.hash)
    {{:error, reason}, unhold_failed(st)}
  end

  defp have?(st, hash),
    do: MapSet.member?(st.blocks, hash) or Archive.have_block_data?(active_archive(st), hash)

  # --- activation --------------------------------------------------------------

  defp queue_drive(%__MODULE__{drive_queued: true} = st), do: st

  defp queue_drive(st) do
    send(self(), :drive)
    %{st | drive_queued: true}
  end

  defp drive(st) do
    t0 = System.monotonic_time(:microsecond)
    {st, state} = turn(%{st | turn_retired: 0})
    st = hwm(st, :turn_retired_max, st.turn_retired)
    t1 = System.monotonic_time(:microsecond)
    st = Telemetry.cs_time(st, :turn, t1 - t0)

    st = st |> maybe_commit() |> publish() |> flush_round() |> flush_mempool()

    st = Telemetry.cs_time(st, :epilogue, System.monotonic_time(:microsecond) - t1)

    st =
      case state do
        :waiting -> Telemetry.mark_wait(st, wait_reason(st))
        :idle -> Telemetry.mark_wait(st, :no_work)
        :more -> st
      end

    st = note_turn(st, System.monotonic_time(:microsecond) - t0)

    case state do
      :more -> queue_drive(st)
      :idle -> answer_waiters(st)
      :waiting -> st
    end
  end

  defp turn(st) do
    budget = %{
      retire: st.activation_step,
      prepare: st.activation_step + st.pipeline_depth,
      deadline: System.monotonic_time(:millisecond) + st.turn_ms
    }

    turn(st, budget)
  end

  defp turn(%__MODULE__{halted: h} = st, _budget) when h != false, do: {cancel_plan(st), :idle}

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

  defp retired(st), do: %{st | turn_retired: st.turn_retired + 1}

  defp new_plan(st) do
    idx = Headers.index(st.headers)
    tip_entry = HeaderIndex.lookup(idx, st.writer_meta.tip.hash)

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
        a = active_archive(st)
        archived = Enum.any?(path, &(Archive.block_id(a, &1.hash) != nil))
        depth = if archived, do: 0, else: st.prefetch_depth

        ctx = %{
          kv: st.kv,
          params: st.p,
          idx: idx,
          current: current_block(st),
          hint: st.archive_handles.overlay
        }

        plan = %{
          gen: make_ref(),
          todo: path,
          last: List.last(path),
          order: :queue.new(),
          items: %{},
          n: 0,
          bytes: 0,
          new_outputs: 0,
          archived: archived,
          final: false,
          pf: nil
        }

        st = %{st | plan: plan}

        pf =
          Prefetch.start(
            path,
            depth,
            View.view_reader(st.view),
            ctx,
            admit_fun(st),
            st.worker_sup
          )

        {:ok, put_in(st.plan.pf, pf)}
    end
  end

  defp peek_head(%{order: order, items: items}) do
    case :queue.peek(order) do
      {:value, ref} -> {:ok, Map.fetch!(items, ref)}
      :empty -> :empty
    end
  end

  defp step(st) do
    t0 = System.monotonic_time(:microsecond)
    st = dispatch_archive_preps(st)
    st = Telemetry.cs_time(st, :dispatch, System.monotonic_time(:microsecond) - t0)

    case peek_head(st.plan) do
      {:ok, %{state: s} = head} when s in [:ready, :failed] ->
        case await_archive_prep(st, head) do
          {:ok, st, head} ->
            t1 = System.monotonic_time(:microsecond)
            {status, st} = retire(st, head)
            {status, Telemetry.cs_time(st, :retire, System.monotonic_time(:microsecond) - t1)}

          :pending ->
            advance(st)
        end

      _ ->
        advance(st)
    end
  end

  defp advance(st) do
    plan = st.plan

    cond do
      plan.todo != [] and not plan.final and admitted?(st) ->
        t0 = System.monotonic_time(:microsecond)
        {status, st} = prepare_next(st)
        st = Telemetry.cs_time(st, :prepare, System.monotonic_time(:microsecond) - t0)

        case status do
          :wait -> {:waiting, st}
          :ok -> {:prepared, st}
        end

      plan.n == 0 and (plan.todo == [] or plan.final) ->
        {:done, cancel_plan(st)}

      plan.todo == [] and not plan.final and st.retarget ->
        extend_plan(%{st | retarget: false})

      true ->
        {:waiting, st}
    end
  end

  # --- archive preparation -------------------------------------------------

  defp dispatch_archive_preps(%__MODULE__{archive_prep: false} = st), do: st

  defp dispatch_archive_preps(st) do
    plan = st.plan

    {items, _, launched} =
      :queue.fold(
        fn
          _ref, {items, nil, l} ->
            {items, nil, l}

          ref, {items, ids, l} ->
            case Map.fetch!(items, ref) do
              %{apre_next: next} when next != nil ->
                {items, next, l}

              %{res: nil} ->
                {items, nil, l}

              %{state: :failed} ->
                {items, nil, l}

              %{archived: true} ->
                {items, ids, l}

              item ->
                item = launch_archive_prep(st, item, ids)
                {Map.put(items, ref, item), item.apre_next, true}
            end
        end,
        {plan.items, st.writer_meta.next, false},
        plan.order
      )

    if launched, do: put_in(st.plan.items, items), else: st
  end

  defp launch_archive_prep(st, %{ref: ref, block: block, res: res, entry: entry} = item, ids) do
    {nouts, nins} =
      Enum.reduce(block.txs, {0, 0}, fn tx, {o, i} ->
        {o + length(tx.outputs), i + length(tx.inputs)}
      end)

    next = %{block: ids.block + 1, out: ids.out + nouts, inp: ids.inp + nins}
    owner = self()
    tag = {:apre, st.plan.gen, ref}
    reader = Archive.kv_reader(active_archive(st))

    history =
      cond do
        ids.block == entry.height and unique_txids?(st, entry) -> :unique
        item.history == :unique -> nil
        true -> item.history
      end

    body = if is_binary(block.raw), do: {:raw, block.raw}, else: {:decoded, block}
    %{spent: spent, delta: %{created: created, spent: sp}} = res
    delta = %{created: created, spent: sp}
    height = entry.height
    hook = st.test_archive_prep_hook
    launched = System.monotonic_time(:microsecond)

    {:ok, pid} =
      Task.Supervisor.start_child(st.worker_sup, fn ->
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
          after
            Segments.close_all_readers()
          end

        send(owner, {:archive_prep_done, tag, result})
      end)

    mref = Process.monitor(pid)
    %{item | apre: {:pending, tag, pid, mref}, apre_next: next}
  end

  defp await_archive_prep(st, %{ref: ref, state: :ready, apre: {:pending, tag, _, _}}) do
    receive do
      {:archive_prep_done, ^tag, result} ->
        st = archive_prep_result(st, tag, result)
        {:ok, st, Map.fetch!(st.plan.items, ref)}
    after
      0 -> :pending
    end
  end

  defp await_archive_prep(st, head), do: {:ok, st, head}

  defp archive_prep_result(st, {:apre, gen, ref} = tag, result) do
    case st.plan do
      %{gen: ^gen, items: %{^ref => %{apre: {:pending, ^tag, _pid, mref}} = item} = items} ->
        Process.demonitor(mref, [:flush])

        {st, item, us} =
          case result do
            {:ok, p} ->
              st =
                st
                |> Telemetry.cs_time(
                  :apre_latency,
                  System.monotonic_time(:microsecond) - p.launched_at
                )
                |> Telemetry.cs_time(:apre_worker, p.worker_us)

              {st, %{item | apre: {:done, p}}, p.prepare_us}

            {:error, _} ->
              {st, %{item | apre: :none}, 0}
          end

        st = put_in(st.plan.items, %{items | ref => item})

        st
        |> update_pstats(%{archive_prep_us: us, archive_prep_jobs: 1})
        |> queue_drive()

      _ ->
        update_pstat(st, :archive_prep_stale, 1)
    end
  end

  defp archive_prep_down(%__MODULE__{plan: %{items: items}} = st, mref, reason)
       when reason != :normal do
    case Enum.find_value(items, fn {ref, i} ->
           if match?(%{apre: {:pending, _, _, ^mref}}, i), do: {ref, i}
         end) do
      {ref, item} ->
        st = put_in(st.plan.items, %{items | ref => %{item | apre: :none}})
        {:ok, queue_drive(update_pstat(st, :archive_prep_down, 1))}

      nil ->
        :unknown
    end
  end

  defp archive_prep_down(_st, _mref, _reason), do: :unknown

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

  defp plan_bytes(%__MODULE__{plan: %{bytes: b}}), do: b
  defp plan_bytes(_), do: 0

  defp extend_plan(st) do
    plan = st.plan
    idx = Headers.index(st.headers)
    tip_entry = HeaderIndex.lookup(idx, st.writer_meta.tip.hash)

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
            a = active_archive(st)

            if plan.archived or
                 Enum.any?(ext, &(Archive.block_id(a, &1.hash) != nil)) do
              {:waiting, put_in(st.plan.final, true)}
            else
              pf =
                Prefetch.extend(
                  plan.pf,
                  ext,
                  idx,
                  View.view_reader(st.view),
                  admit_fun(st)
                )

              st = update_pstat(st, :extensions, 1)
              {:extended, %{st | plan: %{plan | todo: ext, last: List.last(ext), pf: pf}}}
            end

          true ->
            {:waiting, %{st | plan: %{plan | final: true}, retarget: true}}
        end
    end
  end

  defp cancel_plan(%__MODULE__{plan: nil} = st), do: st

  defp cancel_plan(st) do
    plan = st.plan
    refs = Map.keys(plan.items)
    if refs != [], do: ScriptExec.cancel(st.exec, refs)
    if plan.pf, do: Prefetch.stop(plan.pf)

    for {_ref, %{apre: {:pending, _tag, pid, mref}}} <- plan.items do
      catch_exit(fn -> Task.Supervisor.terminate_child(st.worker_sup, pid) end)
      Process.demonitor(mref, [:flush])
    end

    %{st | plan: nil}
  end

  defp take_prefetched(st, entry) do
    {result, pf} =
      Prefetch.take(st.plan.pf, entry, View.view_reader(st.view), admit_fun(st))

    st = put_in(st.plan.pf, pf)

    case result do
      :wait ->
        {:wait, st}

      {:ok, block, epoch, answers, history, stats} ->
        st = %{
          st
          | pf_work: Telemetry.add_counts(st.pf_work, stats),
            pf_window: Telemetry.add_counts(st.pf_window, stats)
        }

        a = active_archive(st)

        if epoch == a.epoch do
          {block, answers, history, update_in(st.pf_stats.used, &(&1 + 1))}
        else
          case Archive.revalidate(a, epoch, answers, history) do
            {:ok, answers, history, dropped} ->
              st = %{
                st
                | pf_stats: %{
                    st.pf_stats
                    | revalidated: st.pf_stats.revalidated + 1,
                      reval_dropped: st.pf_stats.reval_dropped + dropped
                  }
              }

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

  defp prepare_next(st) do
    [entry | rest] = st.plan.todo
    idx = Headers.index(st.headers)

    loaded =
      try do
        take_prefetched(st, entry)
      rescue
        e -> {:crash, {:crash, e, __STACKTRACE__}, st}
      catch
        kind, reason -> {:crash, {:crash, {kind, reason}, __STACKTRACE__}, st}
      end

    now = System.monotonic_time(:microsecond)

    case loaded do
      {:wait, st} ->
        {:wait, %{st | pf_wait_since: st.pf_wait_since || now}}

      {:crash, crash, st} ->
        {:ok, add_item(st, entry, rest, nil, crash, 0, false, nil)}

      {block, answers, history, st} ->
        since = st.pf_wait_since
        st = %{st | pf_wait_since: nil}
        st = if since, do: Telemetry.add_pfwait(st, now - since), else: st

        t0 = System.monotonic_time(:microsecond)

        view =
          :queue.fold(
            fn ref, acc ->
              case Map.fetch!(st.plan.items, ref).res do
                nil -> acc
                res -> [res.delta | acc]
              end
            end,
            [],
            st.plan.order
          )

        a = active_archive(st)
        spec_out = st.writer_meta.next.out + st.plan.new_outputs
        archived = Archive.block_id(a, entry.hash) != nil

        {result, checkblock, rules_us, connect_us, resolve_us, scripts_us} =
          try do
            tc = System.monotonic_time(:microsecond)

            case unchecked_check_block(st, entry, block) do
              :ok ->
                cb_us = System.monotonic_time(:microsecond) - tc

                with :ok <-
                       BlockRules.contextual_check_block(
                         block,
                         HeaderIndex.prev(idx, entry),
                         st.p,
                         idx
                       ),
                     :ok <- override(st, block, entry) do
                  r_us = System.monotonic_time(:microsecond) - tc

                  scripts =
                    not st.test_skip_scripts and
                      AssumeValid.decide(st.assume_valid, idx, entry, st.p) != :skip

                  opts =
                    [
                      scripts: if(scripts, do: :defer, else: false),
                      view: view,
                      committed: answers
                    ] ++
                      if(archived, do: [], else: [base_out: spec_out])

                  t_conn = System.monotonic_time(:microsecond)
                  r = Connect.connect_block(a, block, entry, st.p, idx, opts)
                  c_us = System.monotonic_time(:microsecond) - t_conn
                  res_us = Process.delete(:perf_resolve_us) || 0
                  sc_us = Process.delete(:perf_scripts_us) || 0
                  {r, cb_us, r_us, c_us, res_us, sc_us}
                else
                  err -> {err, cb_us, System.monotonic_time(:microsecond) - tc, 0, 0, 0}
                end

              err ->
                {err, System.monotonic_time(:microsecond) - tc, 0, 0, 0, 0}
            end
          rescue
            e ->
              {
                {:crash, e, __STACKTRACE__},
                0,
                0,
                0,
                Process.delete(:perf_resolve_us) || 0,
                Process.delete(:perf_scripts_us) || 0
              }
          catch
            kind, reason ->
              {
                {:crash, {kind, reason}, __STACKTRACE__},
                0,
                0,
                0,
                Process.delete(:perf_resolve_us) || 0,
                Process.delete(:perf_scripts_us) || 0
              }
          end

        validate_us = System.monotonic_time(:microsecond) - t0

        st =
          st
          |> Telemetry.add_resolve(resolve_us)
          |> Telemetry.add_scripts(scripts_us)
          |> Telemetry.record_validation_window(checkblock, rules_us, connect_us)
          |> update_pstats(%{prep_rules_us: rules_us, prep_connect_us: connect_us})

        case result do
          {:ok, res} ->
            {:ok, add_item(st, entry, rest, block, {:ok, res}, validate_us, archived, history)}

          other ->
            {:ok, add_item(st, entry, rest, block, other, validate_us, false, nil)}
        end
    end
  end

  defp wait_reason(%__MODULE__{plan: %{} = plan} = st) do
    head =
      case peek_head(plan) do
        {:ok, %{state: :ready, apre: {:pending, _, _, _}}} -> :apre
        {:ok, %{state: s}} -> s
        :empty -> :empty
      end

    why =
      cond do
        st.pf_wait_since != nil -> :prefetch
        plan.todo == [] or plan.final -> :no_blocks
        not admitted?(st) -> :full
        true -> :other
      end

    {head, why}
  end

  defp wait_reason(_st), do: :no_plan

  defp unchecked_check_block(st, entry, block) do
    if MapSet.member?(st.checked, entry.hash) do
      :ok
    else
      case BlockRules.check_block(block, st.p,
             signet_check: &Exnode.Validation.Signet.check(&1, st.p)
           ) do
        {:error, {:crash, r}} -> raise Scripts.LocalError, reason: r
        other -> other
      end
    end
  end

  defp add_item(st, entry, rest, block, result, validate_us, archived, history) do
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
      archived: archived,
      history: if(archived, do: nil, else: history),
      apre: nil,
      apre_next: nil,
      prepared_at: now,
      done_at: now,
      head_at: if(plan.n == 0, do: now)
    }

    {item, final} = settle(st, plan.gen, item, block, result)
    item = if archived, do: %{item | new_outputs: 0}, else: item

    plan = %{
      plan
      | todo: rest,
        order: :queue.in(ref, plan.order),
        items: Map.put(plan.items, ref, item),
        n: plan.n + 1,
        bytes: plan.bytes + item.bytes,
        new_outputs: plan.new_outputs + item.new_outputs,
        final: plan.final or final
    }

    st = %{
      st
      | plan: plan,
        plan_seq: order + 1,
        current_blocks: Map.delete(st.current_blocks, entry.hash)
    }

    note_occupancy(st)
  end

  defp settle(st, gen, item, block, result) do
    ref = item.ref
    order = item.order

    case result do
      {:ok, res} ->
        checks = res.checks || []
        chunks = Enum.chunk_every(checks, Scripts.chunk_size())
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
          {%{item | state: :scripts, pending: length(chunks), res: %{res | checks: nil}}, false}
        end

      {:error, _} = err ->
        {%{item | state: :failed, failure: err}, true}

      {:crash, _, _} = crash ->
        {%{item | state: :failed, failure: crash}, true}
    end
  end

  defp item_bytes(%Block{raw: raw}, res) do
    raw_b = if is_binary(raw), do: byte_size(raw), else: 0

    checks_b =
      Enum.reduce(res.checks || [], 0, fn {_tx, spent}, acc ->
        acc + Enum.reduce(spent, 0, fn {spk, _}, a -> a + byte_size(spk) + 16 end)
      end)

    3 * raw_b + checks_b + 160 * map_size(res.delta.created) + 48 * MapSet.size(res.delta.spent)
  end

  defp script_result(st, {:blk, gen, ref, _i}, outcome, wstats) do
    st =
      update_pstats(st, %{
        script_jobs: 1,
        script_native_us: wstats.native_us,
        script_txs: wstats.txs
      })

    case st.plan do
      %{gen: ^gen, items: %{^ref => %{state: :scripts} = item} = items} ->
        item = record_outcome(item, outcome)

        if match?(%{state: :ready, failure: {:invalid, _}}, item),
          do: ScriptExec.cancel(st.exec, [ref])

        queue_drive(put_in(st.plan.items, %{items | ref => item}))

      %{gen: ^gen} ->
        queue_drive(st)

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
          case Scripts.combine(item.outcomes) do
            :ok -> nil
            f -> f
          end

        %{item | state: :ready, failure: failure, done_at: System.monotonic_time(:microsecond)}

      true ->
        item
    end
  end

  defp prefetch_result(%__MODULE__{plan: %{pf: %Prefetch{} = pf}} = st, tag, result) do
    case Prefetch.reply(pf, tag, result) do
      {:ok, pf} -> queue_drive(put_in(st.plan.pf, pf))
      :unknown -> st
    end
  end

  defp prefetch_result(st, _tag, _result), do: st

  defp handle_down(%__MODULE__{plan: %{pf: %Prefetch{} = pf}} = st, mref, down) do
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

  defp retire(st, item) do
    {{:value, head_ref}, order} = :queue.out(st.plan.order)
    items = Map.delete(st.plan.items, head_ref)
    now0 = System.monotonic_time(:microsecond)

    items =
      case :queue.peek(order) do
        {:value, next_ref} ->
          Map.update!(items, next_ref, &%{&1 | head_at: &1.head_at || now0})

        :empty ->
          items
      end

    st = update_pstat(st, :head_wait_us, max(0, item.done_at - (item.head_at || item.done_at)))

    plan = %{
      st.plan
      | order: order,
        items: items,
        n: st.plan.n - 1,
        bytes: st.plan.bytes - item.bytes,
        new_outputs: st.plan.new_outputs - item.new_outputs
    }

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
          {:ok, st, batch_size, archive_us} ->
            {:retired,
             archive_block(st, item, batch_size, archive_us, item.done_at - item.prepared_at)}

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
        crash = {:crash, {:error, %Scripts.LocalError{reason: reason}}, []}
        {:failed, %{quarantine_block(st, item.entry, item.block, crash) | retarget: true}}

      {:crash, _, _} = crash ->
        Quarantine.raise_if_host_fault(crash)
        st = cancel_plan(st)
        {:failed, %{quarantine_block(st, item.entry, item.block, crash) | retarget: true}}
    end
  end

  # --- pipeline diagnostics ----------------------------------------------------

  defp update_pstat(st, k, n), do: %{st | pstats: Map.update(st.pstats, k, n, &(&1 + n))}
  defp update_pstats(st, m), do: %{st | pstats: Telemetry.add_counts(st.pstats, m)}

  defp hwm(st, k, v), do: %{st | pstats: Map.update(st.pstats, k, v, &max(&1, v))}

  defp note_occupancy(%__MODULE__{plan: plan} = st) do
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

  defp note_wait(%__MODULE__{plan: plan} = st) do
    case plan && peek_head(plan) do
      {:ok, %{state: :scripts}} -> update_pstat(st, :waits_head_scripts, 1)
      _ -> update_pstat(st, :waits_other, 1)
    end
  end

  # --- waiters (synchronous submission, reconsider) ------------------------

  defp answer_waiters(%__MODULE__{waiters: []} = st), do: st

  defp answer_waiters(st) do
    {waiters, st} = {Enum.reverse(st.waiters), %{st | waiters: []}}

    st =
      Enum.reduce(waiters, st, fn
        {:submit, from, hash, raw}, st ->
          reply = submit_outcome(st, hash)

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

  defp submit_outcome(st, hash) do
    a = active_archive(st)

    cond do
      MapSet.member?(st.poisoned, hash) ->
        {:error, {:crash, "validation crashed; block quarantined"}}

      Map.has_key?(st.rejected_seen, hash) ->
        {:error, Map.fetch!(st.rejected_seen, hash)}

      Archive.on_chain?(a, Archive.block_id(a, hash) || -1) ->
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

  defp find_target(st, idx, tip_entry) do
    tip_key = work_key(st, tip_entry)

    candidates =
      st.blocks
      |> MapSet.to_list()
      |> Enum.concat(MapSet.to_list(st.disconnected))
      |> Enum.uniq()
      |> Enum.map(&HeaderIndex.lookup(idx, &1))
      |> Enum.reject(
        &(&1 == nil or &1.status == :failed or not :ets.member(st.availability, &1.hash) or
            work_key(st, &1) >= tip_key or
            MapSet.member?(st.poisoned, &1.hash))
      )
      |> Enum.sort_by(&work_key(st, &1))

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

  defp disconnect_to(st, fork) do
    if st.writer_meta.tip.height > fork.height do
      st = commit(st)
      {:ok, meta, old, txs} = ArchiveWriter.disconnect_tip(st.writer, st.mempool != nil)
      st = %{st | writer_meta: meta}
      st = if txs, do: mempool_event(st, {:disconnected, txs}), else: st
      notify(st, {:block_disconnected, old})
      disconnect_to(%{st | disconnected: MapSet.put(st.disconnected, old)}, fork)
    else
      st
    end
  end

  defp archive_connect(st, %{entry: entry, block: block, res: res} = item) do
    prepared =
      case item do
        %{apre: {:done, p}} -> p
        _ -> nil
      end

    opts = [
      delta: res.delta,
      commit: false,
      history: item.history,
      prepared: prepared,
      unique_txids: unique_txids?(st, entry),
      test_archive_hook: st.test_archive_hook
    ]

    case ArchiveWriter.connect(st.writer, block, entry.height, res.spent, opts) do
      {:ok, reply} ->
        meta = st.writer_meta

        txindex =
          if item.archived do
            meta.batch_txindex
          else
            Enum.reduce(res.delta.txids, meta.batch_txindex, &Map.put(&2, &1, true))
          end

        blockhash =
          if item.archived do
            meta.batch_blockhash
          else
            Map.put(meta.batch_blockhash, entry.hash, reply.tip.id)
          end

        meta = %{
          meta
          | tip: reply.tip,
            next: reply.next,
            batch_n: reply.batch_n,
            batch_bytes: reply.batch_bytes,
            batch_since: reply.batch_since,
            batch_txindex: txindex,
            batch_blockhash: blockhash,
            overwritten: reply.overwritten
        }

        {:ok, %{st | writer_meta: meta}, {reply.batch_n, reply.batch_bytes}, reply.archive_us}

      {:host_fault, kind, reason, stack} ->
        :erlang.raise(kind, reason, stack)

      {:crash, error, stack} ->
        {:crash, error, stack}
    end
  end

  defp unique_txids?(st, entry) do
    if Archive.linear?(active_archive(st)) do
      idx = Headers.index(st.headers)
      prev = HeaderIndex.prev(idx, entry)
      Connect.bip34_unique_txids?(entry, prev, st.p, idx)
    else
      false
    end
  end

  defp archive_crashed(st, %{entry: entry, block: block}, {:crash, error, stack}) do
    hex = Hash.to_hex(entry.hash)
    msg = Quarantine.crash_message(error, stack)

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
         {n, bytes},
         archive_us,
         scripts_us
       ) do
    st =
      st
      |> Telemetry.add_scripts(scripts_us)
      |> Telemetry.perf(block, item.validate_us, archive_us)

    key = if res.scripts_checked, do: :checked, else: :skipped
    st = %{st | script_stats: Map.update!(st.script_stats, key, &(&1 + 1))}
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

    st = %{
      st
      | blocks: MapSet.delete(st.blocks, entry.hash),
        sources: Map.delete(st.sources, entry.hash),
        disconnected: MapSet.delete(st.disconnected, entry.hash),
        checked: MapSet.delete(st.checked, entry.hash),
        uncommitted: [{entry.hash, block.raw} | st.uncommitted]
    }

    if n >= st.batch_blocks or bytes >= st.batch_bytes, do: commit(st), else: st
  end

  defp fail_block(st, entry, block, {:error, {result_kind, reason} = r}) do
    Logger.warning("block #{Hash.to_hex(entry.hash)} at #{entry.height} invalid: #{reason}")
    st = commit(st)

    if result_kind != :mutated,
      do: Headers.invalidate(st.headers, entry.hash, st.writer_meta.tip.hash)

    notify(st, {:block_invalid, entry.hash, r})
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

  defp quarantine_block(st, entry, block, {:crash, error, stack}) do
    hash = entry.hash
    hex = Hash.to_hex(hash)
    msg = Quarantine.crash_message(error, stack)

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

  defp poison(st, entry, block, error, msg) do
    hash = entry.hash
    ArchiveWriter.mark_poisoned(st.writer, st.crash_dir, entry, block, error, msg)
    notify(st, {:block_quarantined, hash, error})
    {source, sources} = Map.pop(st.sources, hash)

    if is_pid(source),
      do: send(source, {:block_checked, hash, {:error, {:crash, "validation crashed locally"}}})

    sources
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

  defp override(%__MODULE__{rule_override: f}, block, entry) when is_function(f, 2),
    do: f.(block, entry)

  defp override(_st, _block, _entry), do: :ok

  defp read_archived(st, hash) do
    a = active_archive(st)

    raw =
      case Archive.read_block(a, Archive.block_id(a, hash)) do
        raw when is_binary(raw) ->
          raw

        {:error, :witness_pruned} ->
          raise "reorg needs block #{Hash.to_hex(hash)}, whose witness data is pruned"
      end

    {:ok, b} = Block.decode_exact(raw)
    b
  end

  defp active_archive(st), do: Archive.active_reader(st.archive_handles, st.writer_meta)

  defp catch_exit(f) do
    f.()
  catch
    :exit, _ -> :ok
  end

  defp notify(st, msg) do
    Enum.each(st.listeners, fn l -> if pid = GenServer.whereis(l), do: send(pid, msg) end)
  end
end
