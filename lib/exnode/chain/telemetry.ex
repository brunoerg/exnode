defmodule Exnode.Chain.Telemetry do
  @moduledoc """
  Callback timing, `:debug_live` heap breakdown, work-counter aggregation and
  periodic 30 s `perf:` log formatting for `Exnode.Chain.State`.
  """

  require Logger

  alias Exnode.Archive
  alias Exnode.Archive.Overlay
  alias Exnode.Chain.GcProbe
  alias Exnode.Validation.Connect

  # --- callback & turn timing --------------------------------------------------

  @doc false
  def timed_cb(msg, sample_queue?, fun) do
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

    if sample_queue? do
      seq = (Process.get(:perf_cb_seq) || 0) + 1
      Process.put(:perf_cb_seq, seq)

      queued? =
        if band_sample?(seq) or t1 - t0 >= 5_000 do
          {:message_queue_len, q} = Process.info(self(), :message_queue_len)
          q > 0
        else
          false
        end

      Process.put(:perf_cb_end, {t1, queued?})
    end

    r
  end

  defp band_sample?(seq), do: rem(seq, 32) == 0

  @doc false
  def cs_timed(key, fun) do
    t0 = System.monotonic_time(:microsecond)
    r = fun.()
    cs_time(key, System.monotonic_time(:microsecond) - t0)
    r
  end

  @doc false
  def cs_time(key, us) do
    m = Process.get(:perf_cs) || %{}
    {n, t} = Map.get(m, key, {0, 0})
    Process.put(:perf_cs, Map.put(m, key, {n + 1, t + us}))
  end

  @doc false
  def mark_wait(reason),
    do: Process.put(:perf_wait, {reason, System.monotonic_time(:microsecond)})

  @doc false
  def record_validation_window(checkblock, rules_us, connect_us) do
    Process.put(
      :perf_vwin,
      add_counts(Process.get(:perf_vwin) || %{}, %{
        checkblock: checkblock,
        contextual: max(rules_us - checkblock, 0),
        connect: connect_us
      })
    )
  end

  # --- work counters & 30 s perf summary ---------------------------------------

  @doc false
  def add_counts(a, b), do: Map.merge(a, b, fn _k, x, y -> x + y end)

  @doc false
  def add_work(a, b) do
    Map.merge(a, b, fn k, x, y ->
      if String.ends_with?(Atom.to_string(k), "_max_us"), do: max(x, y), else: x + y
    end)
  end

  @doc false
  def take_cs_work(st) do
    io = Map.merge(Archive.take_stats(), Connect.take_stats())
    %{st | cs_work: add_work(st.cs_work, io), cs_window: add_work(st.cs_window, io)}
  end

  @doc false
  def perf(st, block, validate_us, archive_us) do
    p =
      st.perf ||
        %{
          blocks: 0,
          txs: 0,
          inputs: 0,
          validate: 0,
          archive: 0,
          scripts: 0,
          resolve: 0,
          pfwait: 0,
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
        archive: p.archive + archive_us,
        scripts: p.scripts + scripts,
        resolve: p.resolve + resolve,
        pfwait: p.pfwait + pfwait
    }

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
      c = st.cs_window
      w = st.pf_window
      g = fn m, k -> Map.get(m, k, 0) end
      pf = fn k -> st.pf_stats[k] - st.pf_logged[k] end
      v = Map.merge(Process.delete(:perf_vwin) || %{}, Connect.take_split())

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
          "skipped #{g.(c, :txindex_skipped)}, hint stale #{g.(c, :txindex_hint_stale)}) overwritten #{ms(g.(c, :append_overwritten_us))}ms " <>
          "record #{ms(g.(c, :append_record_us))}ms overlay #{ms(g.(c, :connect_overlay_us))}ms " <>
          "(spent #{ms(g.(c, :ov_spent_us))}ms created #{ms(g.(c, :ov_created_us))}ms) chain #{ms(g.(c, :connect_chain_us))}ms; " <>
          "validation: check_block #{ms(g.(v, :checkblock))}ms contextual #{ms(g.(v, :contextual))}ms " <>
          "connect #{ms(g.(v, :connect))}ms (resolve #{ms(p.resolve)}ms, loop #{ms(g.(v, :txloop))}ms ages #{ms(g.(v, :ages))}ms " <>
          "finish #{ms(g.(v, :finish))}ms); " <>
          cs_line(Process.delete(:perf_cs) || %{}, round(secs * 1_000_000), st.gc_probe)
      )

      %{st | pf_logged: st.pf_stats, pf_window: %{}, cs_window: %{}, perf: nil}
    else
      %{st | perf: p}
    end
  end

  defp ms(us), do: div(us, 1000)

  defp cs_line(m, window_us, probe) do
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
      gc_line(probe)
  end

  defp gc_line(nil), do: ""

  defp gc_line(probe) do
    g = GcProbe.take(probe)

    "; gc: minor #{g.minor_n}x #{div(g.minor_us, 1000)}ms major #{g.major_n}x " <>
      "#{div(g.major_us, 1000)}ms heap max #{div(g.heap_max_words * :erlang.system_info(:wordsize), 1024 * 1024)}MiB; " <>
      "long schedules: chain-state #{g.own_sched_n}x #{g.own_sched_ms}ms " <>
      "others #{g.sched_n}x #{g.sched_ms}ms; " <>
      "run queue now #{:erlang.statistics(:total_run_queue_lengths_all)}"
  end

  # --- diagnostic heap breakdown (:debug_live) ---------------------------------

  @doc false
  def debug_live(st) do
    w = &:erts_debug.size/1
    a = st.a
    items = if st.plan, do: Map.values(st.plan.items), else: []
    item_part = fn k -> w.(Enum.map(items, &Map.get(&1, k))) end

    parts = %{
      batch_ops: w.(a.batch.ops),
      batch_blocks: w.(a.batch.blocks),
      batch_txindex: w.(a.batch.txindex),
      batch_blockhash: w.(a.batch.blockhash),
      archive_other: w.(%{a | batch: nil}),
      ets_chain: :ets.info(a.chain, :memory) + :ets.info(a.onchain, :memory),
      overlay_native: div(Overlay.native_bytes(a.overlay), :erlang.system_info(:wordsize)),
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
    Map.merge(parts, Map.new(info))
  end
end
