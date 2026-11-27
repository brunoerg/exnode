defmodule Exnode.Archive.Writer do
  @moduledoc """
  Thin I/O and publication actor owning the mutable `Exnode.Archive`, segment
  writer handles, native coin `Overlay`, RocksDB commits, and the published
  `:protected` `Exnode.Chain.View` ETS table.

  Responsibilities are strictly limited to serialized storage mutation,
  view publication, durable quarantine/halt marks, and commit pub/sub:
  * Consensus validation (`Validation.Connect.connect_block/6`) and active
    archive reads run inside `Exnode.Chain.State` against concurrency-safe
    handles returned once by `handles/1`.
  * Only `Archive.Writer` mutates `%Archive{}` or writes to `:chain_view` /
    `:archive_chain` / `:archive_onchain`, keeping `Chain.State`'s heap free
    of batch write-op buffers and segment writer FDs.
  * Exposes a commit-event pub/sub (`subscribe/2`, `unsubscribe/2`) so
    indexers (`Index.BlockFilter`, `Index.Scripthash`) wake immediately when
    a batch commits or a tip disconnects instead of polling.
  """
  use GenServer
  require Logger

  alias Exnode.Archive
  alias Exnode.Archive.Overlay
  alias Exnode.Chain.{Headers, Quarantine, View}
  alias Exnode.Store.KV

  defstruct [
    :a,
    :kv,
    :view,
    :headers,
    :durable_epoch,
    subscribers: %{}
  ]

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  # --- public API --------------------------------------------------------------

  @doc "Subscribes `pid` (default `self()`) to `{:archive_committed, tip}` / `{:archive_disconnected, tip}` notifications. Returns `{:ok, writer_pid}` so subscribers can monitor restarts."
  def subscribe(server, pid \\ self()),
    do: GenServer.call(server, {:subscribe, pid}, 5_000)

  @doc "Unsubscribes `pid` (default `self()`) from commit notifications."
  def unsubscribe(server, pid \\ self()),
    do: GenServer.cast(server, {:unsubscribe, pid})

  @doc """
  One-time startup handshake for `Chain.State`. Loads durable halt/quarantine
  marks into the view and returns `{view, quarantine, handles, meta}` where
  `handles` are static concurrency-safe archive handles (`Archive.handles/1`)
  and `meta` is the initial mutable metadata for `Archive.active_reader/2`.
  """
  def handles(server), do: GenServer.call(server, :handles, :infinity)

  @doc "Returns `{tip, Archive.resolve_many(a, ops)}` (fallback when lock-free `View.resolve_active/2` cannot run)."
  def mempool_view(server, ops), do: GenServer.call(server, {:mempool_view, ops}, :infinity)

  @doc "Appends a validated block to the in-memory batch and updates the view tip."
  def connect(server, block, height, spent, opts),
    do: GenServer.call(server, {:connect, block, height, spent, opts}, :infinity)

  @doc "Flushes the in-memory batch (plus `pending_deletes`) to disk and notifies subscribers."
  def flush(server, pending_deletes),
    do: GenServer.call(server, {:flush, pending_deletes}, :infinity)

  @doc "Disconnects the active tip (and notifies subscribers); returns updated metadata and optional disconnected txs."
  def disconnect_tip(server, read_txs? \\ false),
    do: GenServer.call(server, {:disconnect_tip, read_txs?}, :infinity)

  @doc "Runs `fun.(archive)` after flushing any pending deletes."
  def with_archive(server, pending_deletes, fun),
    do: GenServer.call(server, {:with_archive, pending_deletes, fun}, :infinity)

  @doc "Runs `fun.(archive)` without committing first (tests)."
  def peek_archive(server, fun),
    do: GenServer.call(server, {:peek_archive, fun}, :infinity)

  @doc "Takes and resets Archive process-local I/O stats from the writer process."
  def take_stats(server), do: GenServer.call(server, :take_stats, :infinity)

  @doc "Diagnostic heap breakdown of the writer's archive state."
  def debug_archive(server), do: GenServer.call(server, :debug_archive, :infinity)

  @doc "View mutation helpers routed through the owning writer process."
  def view_op(server, op), do: GenServer.call(server, {:view_op, op}, :infinity)

  @doc "Persist halt mark and update view."
  def put_halt_mark(server, reason),
    do: GenServer.call(server, {:put_halt_mark, reason}, :infinity)

  @doc "Clear halt mark and update view."
  def clear_halt_mark(server), do: GenServer.call(server, :clear_halt_mark, :infinity)

  @doc "Persist quarantine mark and update view."
  def mark_poisoned(server, crash_dir, entry, block, error, msg),
    do:
      GenServer.call(
        server,
        {:mark_poisoned, crash_dir, entry, block, error, msg},
        :infinity
      )

  @doc "Clear quarantine marks and update view."
  def clear_poisoned(server, poisoned, which),
    do: GenServer.call(server, {:clear_poisoned, poisoned, which}, :infinity)

  # --- GenServer callbacks -----------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    p = Keyword.fetch!(opts, :params)
    headers = Keyword.fetch!(opts, :headers)

    kv =
      case Keyword.fetch(opts, :kv) do
        {:ok, kv} -> kv
        :error -> Exnode.Node.Runtime.kv(Keyword.fetch!(opts, :node_name))
      end

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

    view = View.new(kv, Keyword.get(opts, :view_name))
    View.publish(view, a)
    durable_epoch = record_durable_epoch(kv, a)

    {:ok,
     %__MODULE__{
       a: a,
       kv: kv,
       view: view,
       headers: headers,
       durable_epoch: durable_epoch
     }}
  end

  @impl true
  def handle_call({:subscribe, pid}, _from, st) when is_pid(pid) do
    if Map.has_key?(st.subscribers, pid) do
      {:reply, {:ok, self()}, st}
    else
      mref = Process.monitor(pid)
      {:reply, {:ok, self()}, %{st | subscribers: Map.put(st.subscribers, pid, mref)}}
    end
  end

  def handle_call(:handles, _from, st) do
    halted = Quarantine.load_halt(st.kv, st.view)
    poisoned = Quarantine.load_poisoned(st.kv, st.view)
    {:reply, {st.view, {halted, poisoned}, Archive.handles(st.a), writer_meta(st.a)}, st}
  end

  def handle_call({:mempool_view, ops}, _from, st),
    do: {:reply, {Archive.tip(st.a), Archive.resolve_many(st.a, ops)}, st}

  def handle_call({:connect, block, height, spent, opts}, _from, st) do
    t0 = System.monotonic_time(:microsecond)
    hook = Keyword.get(opts, :test_archive_hook)
    connect_opts = Keyword.delete(opts, :test_archive_hook)

    try do
      a =
        View.with_active_mutation(st.view, fn ->
          a = Archive.connect(st.a, block, height, spent, connect_opts)
          View.put_tip(st.view, Archive.tip(a), a.batch.txindex)
          a
        end)

      if hook, do: hook.(block)
      us = System.monotonic_time(:microsecond) - t0
      tip = Archive.tip(a)

      reply = %{
        tip: tip,
        next: Archive.next_ids(a),
        batch_n: a.batch.n,
        batch_bytes: a.batch.bytes,
        batch_since: a.batch.since,
        overwritten: a.overwritten,
        archive_us: us
      }

      {:reply, {:ok, reply}, %{st | a: a}}
    catch
      kind, reason ->
        if Quarantine.host_fault?(kind, reason, __STACKTRACE__) do
          {:reply, {:host_fault, kind, reason, __STACKTRACE__}, st}
        else
          {:reply, {:crash, {kind, reason}, __STACKTRACE__}, st}
        end
    end
  end

  def handle_call({:flush, pending_deletes}, _from, st) do
    st = do_flush(st, pending_deletes)
    {:reply, {:ok, writer_meta(st.a)}, st}
  end

  def handle_call({:disconnect_tip, read_txs?}, _from, st) do
    old_tip = Archive.tip(st.a)

    txs =
      if read_txs? do
        {:ok, b} = Archive.read_block_txs(st.a, old_tip.id)
        b.txs
      else
        nil
      end

    a =
      View.with_active_mutation(st.view, fn ->
        {a, _id} = Archive.disconnect_tip(st.a)
        View.publish(st.view, a)
        a
      end)

    st = %{st | a: a, durable_epoch: record_durable_epoch(st.kv, a)}
    tip = Archive.tip(a)
    notify_subscribers(st, {:archive_disconnected, tip})
    {:reply, {:ok, writer_meta(a), old_tip.hash, txs}, st}
  end

  def handle_call({:with_archive, pending_deletes, fun}, _from, st) do
    st = if pending_deletes != [], do: do_flush(st, pending_deletes), else: st
    {:reply, fun.(st.a), st}
  end

  def handle_call({:peek_archive, fun}, _from, st) do
    {:reply, fun.(st.a), st}
  end

  def handle_call(:take_stats, _from, st) do
    {:reply, Archive.take_stats(), st}
  end

  def handle_call(:debug_archive, _from, st) do
    w = &:erts_debug.size/1
    a = st.a

    parts = %{
      batch_ops: w.(a.batch.ops),
      batch_blocks: w.(a.batch.blocks),
      batch_txindex: w.(a.batch.txindex),
      batch_blockhash: w.(a.batch.blockhash),
      archive_other: w.(%{a | batch: nil}),
      ets_chain: :ets.info(a.chain, :memory) + :ets.info(a.onchain, :memory),
      overlay_native: div(Overlay.native_bytes(a.overlay), :erlang.system_info(:wordsize))
    }

    {:reply, parts, st}
  end

  def handle_call({:view_op, op}, _from, st) do
    case op do
      :publish -> View.publish(st.view, st.a)
      {:hold, h} -> View.hold(st.view, h)
      {:hold_many, hs} -> View.hold_many(st.view, hs)
      {:unhold, h} -> View.unhold(st.view, h)
      {:unhold_many, hs} -> View.unhold_many(st.view, hs)
      {:put_halted, v} -> View.put_halted(st.view, v)
    end

    {:reply, :ok, st}
  end

  def handle_call({:put_halt_mark, reason}, _from, st) do
    mark = Quarantine.put_halt_mark(st.kv, st.view, reason, Archive.tip(st.a))
    {:reply, mark, st}
  end

  def handle_call(:clear_halt_mark, _from, st) do
    :ok = Quarantine.clear_halt_mark(st.kv, st.view)
    {:reply, :ok, st}
  end

  def handle_call({:mark_poisoned, crash_dir, entry, block, error, msg}, _from, st) do
    :ok = Quarantine.mark_poisoned(st.kv, crash_dir, st.view, entry, block, error, msg)
    {:reply, :ok, st}
  end

  def handle_call({:clear_poisoned, poisoned, which}, _from, st) do
    res = Quarantine.clear_poisoned(st.kv, st.view, poisoned, which)
    {:reply, res, st}
  end

  @impl true
  def handle_cast({:unsubscribe, pid}, st) do
    case Map.pop(st.subscribers, pid) do
      {nil, _} ->
        {:noreply, st}

      {mref, subscribers} ->
        Process.demonitor(mref, [:flush])
        {:noreply, %{st | subscribers: subscribers}}
    end
  end

  @impl true
  def handle_info({:DOWN, _mref, :process, pid, _reason}, st) do
    {:noreply, %{st | subscribers: Map.delete(st.subscribers, pid)}}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  @impl true
  def terminate(reason, st) do
    {n, _} = Archive.batch_size(st.a)

    # Flush uncommitted blocks only on clean shutdown (:normal, :shutdown, or
    # a non-archive-crash {:shutdown, _}). On abnormal exits (e.g. :kill from
    # a crashed Chain.State, or an archive-crashed shutdown), discard the
    # in-memory batch so restart replays cleanly from the last durable commit.
    clean_stop? =
      reason in [:normal, :shutdown] or
        (match?({:shutdown, _}, reason) and not match?({:shutdown, {:archive_crashed, _}}, reason))

    if n > 0 and clean_stop? do
      if durable_current?(st) do
        try do
          do_flush(st, [])
        catch
          kind, err ->
            Logger.warning(
              "archive writer stopped without committing (the restart resumes from the disk): " <>
                Exception.format_banner(kind, err, __STACKTRACE__)
            )
        end
      else
        Logger.warning(
          "archive writer stopped with an archive state older than its last commit; " <>
            "not committing it (the restart resumes from the disk)"
        )
      end
    end

    :ok
  end

  # --- internals ---------------------------------------------------------------

  defp writer_meta(a) do
    last_commit =
      case a.last_commit do
        %{from: from, txids: txids, spent: spent} ->
          %{from: from, txids: Map.new(Map.keys(txids), &{&1, true}), spent: spent}

        nil ->
          nil
      end

    %{
      tip: Archive.tip(a),
      committed_tip: Archive.committed_tip(a),
      next: Archive.next_ids(a),
      epoch: Archive.epoch(a),
      batch_n: a.batch.n,
      batch_bytes: a.batch.bytes,
      batch_since: a.batch.since,
      batch_txindex: Map.new(Map.keys(a.batch.txindex), &{&1, true}),
      batch_blockhash: a.batch.blockhash,
      last_commit: last_commit,
      overwritten: a.overwritten,
      wpruned: a.wpruned
    }
  end

  defp do_flush(st, pending_deletes) do
    {n, _} = Archive.batch_size(st.a)

    if n == 0 and pending_deletes == [] do
      st
    else
      :ok = Headers.flush(st.headers)

      a =
        View.with_active_mutation(st.view, fn ->
          a = Archive.flush(st.a, for(h <- pending_deletes, do: {:delete, :pending, h}))
          if pending_deletes != [], do: View.unhold_many(st.view, pending_deletes)
          View.put_committed(st.view, a)
          a
        end)

      st = %{st | a: a, durable_epoch: record_durable_epoch(st.kv, a)}
      notify_subscribers(st, {:archive_committed, Archive.committed_tip(a)})
      st
    end
  end

  defp notify_subscribers(%{subscribers: subs}, msg) do
    for {pid, _mref} <- subs, do: send(pid, msg)
    :ok
  end

  defp durable_current?(%__MODULE__{a: a, kv: kv, durable_epoch: epoch}) do
    Archive.epoch(a) == epoch and
      case KV.get(kv, :meta, "durable_epoch") do
        {:ok, <<stored::64>>} -> stored == epoch
        :not_found -> true
      end
  end

  defp record_durable_epoch(kv, a) do
    epoch = Archive.epoch(a)
    :ok = KV.write(kv, [{:put, :meta, "durable_epoch", <<epoch::64>>}], sync: false)
    epoch
  end
end
