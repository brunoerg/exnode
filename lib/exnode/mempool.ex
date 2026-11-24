defmodule Exnode.Mempool do
  @moduledoc """
  The mempool process: owns the pool (`Exnode.Mempool.Pool`) and applies
  `Exnode.Mempool.Accept`. Like Core's `cs_main` + `mempool.cs`, every
  change to the pool and every block update runs serialized here.

  Single-tx acceptance (`accept/3`, the P2P and `sendrawtransaction` path)
  does not hold the process during script verification, as Core runs it on
  its script-check threads (`-par`):
  * the context-free checks (`Accept.precheck_context_free/2`) run before
    any chain-state call, and coins are read only when `PreChecks` reaches
    them (no prefetch);
  * the scripts run in a task (`:verify_sup`); the caller gets its reply
    when it ends. Meanwhile the tx's inputs are pending: an accept spending
    one of them (or the pending tx itself) waits for it, so concurrent
    accepts get the verdicts of Core's serialized order;
  * at the end the tx goes through `Accept.prepare/4` again against the pool
    and tip of that moment (the verdict of the scripts is reused when their
    inputs and flags are unchanged), so nothing is added from a stale view.
    If the tip moved and the chain state is still ahead of the updates
    applied here, the answer is `:reconsiderable` "tip-changed";
  * at most 128 accepts are pending (running or waiting); beyond that the
    answer is `:reconsiderable` "mempool busy". Neither answer is a
    consensus or policy verdict, so neither is punished.

  `test_accept/2`, `submit_package/2` and the reorg re-adds stay
  synchronous, as all of Core's acceptance does under `cs_main`. Packages
  also come from peers (TxRelay's 1p1c): TxRelay submits one only for a
  parent that failed alone on its fee, and caches a parent or child that
  fails in the package, so each such evaluation costs the peer a new tx.

  The chain state provides the view (tip, unspent coins, script flags) and
  sends `{:mempool_update, tip_hash, events}` after each activation, with
  the blocks it disconnected and connected, in order. The mempool applies
  them as Core does:
  * `removeForBlock` for connected blocks;
  * `MaybeUpdateMempoolForReorg` for disconnected ones: re-add their txs with
    `bypass_limits`, oldest first, then drop txs that are no longer final or
    mature.

  Mempool spends never reach the archive's `spends` index, which records
  confirmed spends only.

  Listeners get `{:mempool_accepted, tx, result, origin}` for each tx
  added by `accept/3` or `submit_package/2`, `origin` being the calling
  process, and the `{:mempool_block, ...}` events.
  """
  use GenServer
  require Logger

  alias Exnode.Chain.{Headers, HeaderIndex}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Codec.Tx
  alias Exnode.Mempool.{Accept, Linearize, Package, Pool}
  alias Exnode.Validation.ScriptFlags

  import Bitwise, only: [&&&: 2]

  @max_pending_verifications 128
  # Txs linearized per idle cache-refresh message (about one full cluster).
  @refresh_lin_txs 64
  # BIP68 SEQUENCE_LOCKTIME_DISABLE_FLAG
  @seq_disable 0x80000000

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  Core `AcceptToMemoryPool` (`sendrawtransaction` path). Returns `{:ok, result}` or `{:error, error}`.
  The submission calls below wait with no timeout, as Core holds `cs_main`
  across them (`ProcessMessages`); a network caller is bounded by its peer's
  inactivity timeout.
  """
  def accept(server, %Tx{} = tx, args \\ []),
    do: GenServer.call(server, {:accept, tx, args}, :infinity)

  @doc "Core `testmempoolaccept`: one tx or a package; results per tx, nothing added."
  def test_accept(server, txs), do: GenServer.call(server, {:test_accept, txs}, :infinity)

  @doc "Core `submitpackage` (child with parents). Returns the package result."
  def submit_package(server, txs), do: GenServer.call(server, {:submit_package, txs}, :infinity)

  @doc "Core `submitpackage` with RPC options (`:unbroadcast`, `:max_feerate`)."
  def submit_package(server, txs, opts),
    do: GenServer.call(server, {:submit_package, txs, opts}, :infinity)

  def txids(server), do: GenServer.call(server, :txids, 5_000)

  @doc """
  The mempool txs paying to or spending from the script with scripthash
  `sh` (`sha256(scriptPubKey)`), oldest first: `[%{txid, tx, spent}]`
  (`spent`: `{value, scripthash}` per input). Needs `index_scripts: true`;
  else `{:error, :not_indexed}`. Copies only those txs out of the mempool;
  with more than `limit` of them, none (`{:error, :too_many}`), so a
  popular script (an anchor, say) costs this process no copy and no sort.
  """
  def script_txs(server, sh, limit \\ :infinity),
    do: GenServer.call(server, {:script_txs, sh, limit}, :infinity)

  @doc "The mempool spenders of `outpoints`: `%{outpoint => {txid, input_index}}` (unspent ones absent)."
  def spenders(server, outpoints), do: GenServer.call(server, {:spenders, outpoints}, :infinity)

  @doc "`{fee, vsize}` of every mempool tx, and the total vsize: `{pairs, total_vsize}`."
  def fee_rates(server), do: GenServer.call(server, :fee_rates, :infinity)

  @doc """
  Esplora `/mempool`: `%{count, vsize, total_fee, fee_histogram}`
  (`fee_histogram`: `[feerate, vsize]` per 0.1 sat/vB band, highest
  first). `count` and `vsize` are current; the fee figures need a pass
  over the pool, so as electrs' backlog stats they are computed at most
  once per 10 s and served from that cache meanwhile.
  """
  def backlog(server), do: GenServer.call(server, :backlog, :infinity)

  @doc "The pool itself (for RPC views)."
  def pool(server), do: GenServer.call(server, :pool, 5_000)

  @doc "Core `CTxMemPool::isSpent`: a mempool tx spends `outpoint`."
  def spent?(server, outpoint), do: GenServer.call(server, {:spent?, outpoint}, 5_000)

  @doc "Core's unbroadcast set: txs submitted locally (RPC) not yet requested by any peer."
  def unbroadcast?(server, txid), do: GenServer.call(server, {:unbroadcast?, txid}, 5_000)
  def unbroadcast_count(server), do: GenServer.call(server, :unbroadcast_count, 5_000)
  def unbroadcast_txids(server), do: GenServer.call(server, :unbroadcast_txids, 5_000)
  def remove_unbroadcast(server, txids), do: GenServer.cast(server, {:remove_unbroadcast, txids})

  @doc "`{mempool min fee rate (sat/kvB), policy opts}` (Core `GetMinFee`, `m_opts`)."
  def fee_info(server), do: GenServer.call(server, :fee_info, 5_000)
  def entry(server, txid), do: GenServer.call(server, {:entry, txid}, 5_000)

  @doc "Summary stats for `getmempoolinfo` in a single call, without copying `%Pool{}`."
  def stats(server), do: GenServer.call(server, :stats, 5_000)

  @doc "Entry details for `entryToJSON` (`getmempoolentry`), without copying `%Pool{}`."
  def entry_details(server, txid), do: GenServer.call(server, {:entry_details, txid}, 5_000)

  @doc """
  `getrawmempool` view without copying `%Pool{}`:
  * `verbose == true`: `[{txid, details_map}, ...]` sorted by `txid`
  * `verbose == false`: `{ordered_txids, mempool_sequence}` in mining order
  """
  def raw_mempool(server, verbose), do: GenServer.call(server, {:raw_mempool, verbose}, 5_000)

  # The queries below are reached from TxRelay while it handles peer
  # traffic: they wait like Core's peer thread on `cs_main` (no timeout).

  @doc "`Pool.extract_best/3` on the current pool: `{entries, rest_txids}`."
  def extract_best(server, txids, n),
    do: GenServer.call(server, {:extract_best, txids, n}, :infinity)

  def size(server), do: GenServer.call(server, :size, 5_000)
  def has?(server, hash, kind \\ :txid), do: GenServer.call(server, {:has, hash, kind}, :infinity)

  def get_tx(server, hash, kind \\ :txid),
    do: GenServer.call(server, {:get_tx, hash, kind}, :infinity)

  @doc "`has?/3` for many hashes in one call: the `MapSet` of those present in the pool."
  def has_many?(server, hashes, kind \\ :txid),
    do: GenServer.call(server, {:has_many, hashes, kind}, :infinity)

  @doc """
  `get_tx/3` for many items (`%{type: :tx | :wtx, hash}`) in one call:
  `{found_txs, missing_items}`, both in the order of `items`.
  """
  def get_txs(server, items), do: GenServer.call(server, {:get_txs, items}, :infinity)

  @doc """
  `get_txs/2` for a peer's getdata (Core `info_for_relay`): only entries
  whose sequence is below `before`, the mempool sequence at the last inv
  sent to that peer (Core `m_last_inv_sequence`).
  """
  def get_txs(server, items, before),
    do: GenServer.call(server, {:get_txs, items, before}, :infinity)

  @doc "The sequence the next entry gets (Core `GetSequence`)."
  def sequence(server), do: GenServer.call(server, :sequence, :infinity)

  @doc """
  BIP152 reconstruction (Core `InitData` mempool pass): the mempool txs
  whose short id (SipHash keyed `{k0, k1}`, of the wtxid) is in `wanted`.
  Returns `%{short_id => tx | :collided}`.
  """
  def match_short_ids(server, keys, wanted) do
    GenServer.call(server, {:match_short_ids, keys, wanted}, :infinity)
  catch
    # Called by peers: a mempool restarting under them is an empty mempool
    # pass (the missing txs are requested), not a dropped peer.
    :exit, _ -> %{}
  end

  @doc "Waits until the mempool has applied the chain state's updates up to `tip_hash`."
  def sync_to(server, tip_hash), do: GenServer.call(server, {:sync_to, tip_hash}, :infinity)

  @impl true
  def init(opts) do
    st = %{
      chain_state: Keyword.fetch!(opts, :chain_state),
      headers: Keyword.fetch!(opts, :headers),
      params: Keyword.fetch!(opts, :params),
      clock: Keyword.get(opts, :clock, fn -> System.os_time(:second) end),
      state: %{
        pool: Pool.new(index_scripts: Keyword.get(opts, :index_scripts, false)),
        fees: Accept.new_fee_state(),
        opts: Map.merge(Accept.default_opts(), Map.new(Keyword.get(opts, :policy, [])))
      },
      tip_hash: nil,
      unbroadcast: MapSet.new(),
      listeners: Keyword.get(opts, :listeners, []),
      verify: Keyword.get(opts, :verify, &Exnode.Kernel.verify_tx_all/3),
      verify_sup: Keyword.get_lazy(opts, :verify_sup, &start_verify_sup/0),
      # task ref => accept waiting for its scripts
      jobs: %{},
      # outpoint => task ref, and the pending txids (Core: their coins are
      # in use until the accept ends)
      pending_spends: %{},
      pending_txids: MapSet.new(),
      # accepts waiting for a pending one they depend on, oldest first
      deferred: :queue.new(),
      # a :refresh_lin message is in the mailbox
      refresh_queued: false,
      # {computed_at_ms, backlog/1's fee figures}
      backlog: nil
    }

    {:ok, st}
  end

  # electrs BACKLOG_STATS_TTL.
  @backlog_ttl_ms 10_000

  defp backlog_fees(pool) do
    pairs = for {_, e} <- pool.entries, do: {e.fee, e.vsize}

    hist =
      pairs
      |> Enum.map(fn {fee, vsize} -> {fee / vsize, vsize} end)
      |> Enum.sort(:desc)
      |> Enum.chunk_by(fn {r, _} -> round(r * 10) end)
      |> Enum.map(fn group ->
        [elem(hd(group), 0), Enum.reduce(group, 0, &(&2 + elem(&1, 1)))]
      end)

    %{total_fee: Enum.reduce(pairs, 0, &(&2 + elem(&1, 0))), fee_histogram: hist}
  end

  # Without a supervisor from the node (tests), one linked to this process.
  defp start_verify_sup do
    {:ok, sup} = Task.Supervisor.start_link()
    sup
  end

  @impl true
  def handle_call({:accept, tx, args}, {origin, _} = from, st) do
    st = sync(st)
    {unbroadcast, args} = Keyword.pop(args, :unbroadcast, false)

    cond do
      # Core: MemPoolAccept::PreChecks' first checks, with no chain access.
      (e = Accept.precheck_context_free(st.state, tx)) != :ok ->
        {:reply, e, st}

      map_size(st.jobs) + :queue.len(st.deferred) >= @max_pending_verifications ->
        {:reply, {:error, Accept.err(:reconsiderable, "mempool busy")}, st}

      true ->
        job = %{from: from, origin: origin, tx: tx, args: args, unbroadcast: unbroadcast}
        {:noreply, start_accept(st, job)}
    end
  end

  def handle_call({:test_accept, txs}, _from, st) do
    st = sync(st)
    chain = chain_context(st, txs)

    reply =
      case txs do
        [tx] -> [single_result(tx, Accept.accept(st.state, tx, chain, test_accept: true))]
        _ -> Package.test_accept(st.state, txs, chain)
      end

    {:reply, reply, st}
  end

  def handle_call({:submit_package, txs}, {origin, _}, st) do
    st = sync(st)
    chain = chain_context(st, txs)
    {reply, s} = Package.accept(st.state, txs, chain)

    for {:ok, tx, res} <- Package.accepted(reply, txs),
        do: notify(st, {:mempool_accepted, tx, res, origin})

    {:reply, reply, %{st | state: s} |> prune_unbroadcast() |> refresh_soon()}
  end

  def handle_call({:submit_package, txs, opts}, {origin, _}, st) do
    st = sync(st)
    chain = chain_context(st, txs)

    {reply, s} =
      submit_package_rpc(st.state, txs, chain, st.verify, Keyword.get(opts, :max_feerate))

    for {:ok, tx, res} <- Package.accepted(reply, txs),
        do: notify(st, {:mempool_accepted, tx, res, origin})

    unbroadcast =
      if Keyword.get(opts, :unbroadcast, false) do
        Enum.reduce(txs, st.unbroadcast, fn tx, acc ->
          if Pool.exists?(s.pool, tx.txid), do: MapSet.put(acc, tx.txid), else: acc
        end)
      else
        st.unbroadcast
      end

    {:reply, reply,
     %{st | state: s, unbroadcast: unbroadcast} |> prune_unbroadcast() |> refresh_soon()}
  end

  def handle_call(:txids, _from, st), do: {:reply, Map.keys(st.state.pool.entries), st}

  def handle_call({:script_txs, sh, limit}, _from, st) do
    st = sync(st)
    pool = st.state.pool

    ids = if Pool.indexes_scripts?(pool), do: Pool.script_txids(pool, sh)

    reply =
      cond do
        ids == nil ->
          {:error, :not_indexed}

        MapSet.size(ids) > limit ->
          {:error, :too_many}

        true ->
          ids
          |> Enum.map(&Pool.get(pool, &1))
          |> Enum.sort_by(& &1.sequence)
          |> Enum.map(&%{txid: &1.txid, tx: &1.tx, spent: &1.spent})
      end

    {:reply, reply, st}
  end

  def handle_call({:spenders, outpoints}, _from, st) do
    st = sync(st)
    pool = st.state.pool

    reply =
      for {txid, v} = op <- outpoints, s = Pool.spender(pool, op), into: %{} do
        tx = Pool.get(pool, s).tx
        {op, {s, Enum.find_index(tx.inputs, &(&1.prev_hash == txid and &1.prev_index == v))}}
      end

    {:reply, reply, st}
  end

  def handle_call(:fee_rates, _from, st) do
    st = sync(st)
    pool = st.state.pool
    {:reply, {for({_, e} <- pool.entries, do: {e.fee, e.vsize}), pool.total_vsize}, st}
  end

  def handle_call(:backlog, _from, st) do
    st = sync(st)
    pool = st.state.pool
    now = System.monotonic_time(:millisecond)

    {fees, st} =
      case st.backlog do
        {at, fees} when now - at < @backlog_ttl_ms ->
          {fees, st}

        _ ->
          fees = backlog_fees(pool)
          {fees, %{st | backlog: {now, fees}}}
      end

    {:reply, Map.merge(fees, %{count: map_size(pool.entries), vsize: pool.total_vsize}), st}
  end

  def handle_call(:pool, _from, st), do: {:reply, st.state.pool, st}

  def handle_call({:spent?, op}, _from, st),
    do: {:reply, Pool.spender(st.state.pool, op) != nil, st}

  def handle_call({:unbroadcast?, txid}, _from, st),
    do: {:reply, MapSet.member?(st.unbroadcast, txid) and Pool.exists?(st.state.pool, txid), st}

  def handle_call(:unbroadcast_count, _from, st),
    do: {:reply, Enum.count(st.unbroadcast, &Pool.exists?(st.state.pool, &1)), st}

  def handle_call(:unbroadcast_txids, _from, st) do
    pool = st.state.pool
    {:reply, Enum.filter(st.unbroadcast, &Pool.exists?(pool, &1)), st}
  end

  def handle_call(:fee_info, _from, st) do
    {rate, fees} = Accept.min_fee(st.state, st.clock.())
    {:reply, {rate, st.state.opts}, %{st | state: %{st.state | fees: fees}}}
  end

  def handle_call(:stats, _from, st) do
    st = sync(st)
    pool = st.state.pool
    {min_fee, fees} = Accept.min_fee(st.state, st.clock.())
    total_fee = Enum.reduce(pool.entries, 0, fn {_, e}, acc -> acc + e.fee end)
    unbroadcast_count = Enum.count(st.unbroadcast, &Pool.exists?(pool, &1))

    reply = %{
      size: Pool.size(pool),
      bytes: pool.total_vsize,
      usage: pool.total_usage,
      total_fee: total_fee,
      min_fee: min_fee,
      opts: st.state.opts,
      unbroadcast_count: unbroadcast_count
    }

    {:reply, reply, %{st | state: %{st.state | fees: fees}}}
  end

  def handle_call({:entry_details, txid}, _from, st) do
    st = sync(st)
    pool = st.state.pool

    reply =
      case Pool.get(pool, txid) do
        nil -> nil
        e -> build_entry_details(pool, st.unbroadcast, e)
      end

    {:reply, reply, st}
  end

  def handle_call({:raw_mempool, true}, _from, st) do
    st = sync(st)
    {pool, _} = Pool.cluster_chunks(st.state.pool)

    reply =
      for t <- Enum.sort(Map.keys(pool.entries)) do
        {t, build_entry_details(pool, st.unbroadcast, pool.entries[t])}
      end

    {:reply, reply, %{st | state: %{st.state | pool: pool}}}
  end

  def handle_call({:raw_mempool, false}, _from, st) do
    st = sync(st)
    {pool, cluster_chunks} = Pool.cluster_chunks(st.state.pool)

    ordered =
      cluster_chunks
      |> Enum.concat()
      |> Enum.sort(fn {{f1, w1}, ids1}, {{f2, w2}, ids2} ->
        case Linearize.ratio_cmp({f1, w1}, {f2, w2}) do
          :gt -> true
          :lt -> false
          :eq -> min_seq(pool, ids1) <= min_seq(pool, ids2)
        end
      end)
      |> Enum.flat_map(fn {_, ids} -> ids end)

    {:reply, {ordered, pool.sequence}, %{st | state: %{st.state | pool: pool}}}
  end

  def handle_call({:match_short_ids, {k0, k1}, wanted}, _from, st) do
    want = MapSet.new(wanted)

    found =
      Enum.reduce(st.state.pool.entries, %{}, fn {_txid, e}, acc ->
        id = Exnode.P2P.CompactBlock.short_id(k0, k1, e.wtxid)

        cond do
          not MapSet.member?(want, id) -> acc
          Map.has_key?(acc, id) -> Map.put(acc, id, :collided)
          true -> Map.put(acc, id, e.tx)
        end
      end)

    {:reply, found, st}
  end

  def handle_call(:size, _from, st), do: {:reply, Pool.size(st.state.pool), st}

  def handle_call({:extract_best, txids, n}, _from, st),
    do: {:reply, Pool.extract_best(st.state.pool, txids, n), st}

  def handle_call({:entry, txid}, _from, st), do: {:reply, Pool.get(st.state.pool, txid), st}

  def handle_call({:has, h, :txid}, _from, st), do: {:reply, Pool.exists?(st.state.pool, h), st}

  def handle_call({:has, h, :wtxid}, _from, st),
    do: {:reply, Pool.exists_wtxid?(st.state.pool, h), st}

  def handle_call({:get_tx, h, kind}, _from, st), do: {:reply, pool_tx(st, h, kind), st}

  def handle_call({:has_many, hashes, kind}, _from, st) do
    has? =
      if kind == :wtxid,
        do: &Pool.exists_wtxid?(st.state.pool, &1),
        else: &Pool.exists?(st.state.pool, &1)

    {:reply, hashes |> Enum.filter(has?) |> MapSet.new(), st}
  end

  def handle_call({:get_txs, items}, from, st), do: handle_call({:get_txs, items, nil}, from, st)

  def handle_call({:get_txs, items, before}, _from, st) do
    {found, missing} =
      Enum.reduce(items, {[], []}, fn i, {found, missing} ->
        case pool_entry(st, i.hash, if(i.type == :wtx, do: :wtxid, else: :txid)) do
          %{sequence: seq} = e when before == nil or seq < before -> {[e.tx | found], missing}
          _ -> {found, [i | missing]}
        end
      end)

    {:reply, {Enum.reverse(found), Enum.reverse(missing)}, st}
  end

  def handle_call(:sequence, _from, st), do: {:reply, st.state.pool.sequence, st}

  def handle_call({:sync_to, tip_hash}, _from, st) do
    {:reply, :ok, sync_until(st, tip_hash)}
  end

  defp pool_tx(st, h, kind) do
    e = pool_entry(st, h, kind)
    e && e.tx
  end

  defp pool_entry(st, h, :wtxid), do: Pool.by_wtxid(st.state.pool, h)
  defp pool_entry(st, h, _txid), do: Pool.get(st.state.pool, h)

  @impl true
  def handle_cast({:remove_unbroadcast, txids}, st),
    do:
      {:noreply, %{st | unbroadcast: Enum.reduce(txids, st.unbroadcast, &MapSet.delete(&2, &1))}}

  @impl true
  def handle_info({:mempool_update, tip_hash, events}, st),
    do: {:noreply, st |> apply_update(tip_hash, events) |> prune_unbroadcast() |> refresh_soon()}

  # A script verification ended.
  def handle_info({ref, kernel_result}, st) when is_map_key(st.jobs, ref) do
    Process.demonitor(ref, [:flush])
    {:noreply, st |> end_job(ref, kernel_result) |> prune_unbroadcast() |> refresh_soon()}
  end

  # It crashed (a bug, not a verdict on the tx): a non-punishable failure.
  def handle_info({:DOWN, ref, :process, _, reason}, st) when is_map_key(st.jobs, ref) do
    Logger.error("mempool script verification crashed: #{inspect(reason)}")
    {:noreply, st |> end_job(ref, {:crash, reason}) |> prune_unbroadcast() |> refresh_soon()}
  end

  # Idle-time linearization of changed clusters (Core TxGraph keeps its
  # main linearizations current), a bounded slice per message so calls
  # interleave. RBF diagrams and mining order then read them from the cache.
  def handle_info(:refresh_lin, st) do
    {pool, _more} = Pool.refresh_stale(st.state.pool, @refresh_lin_txs)
    {:noreply, refresh_soon(%{st | state: %{st.state | pool: pool}, refresh_queued: false})}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  # Core removeUnchecked: a tx leaving the mempool leaves the unbroadcast
  # set. Readers filtered stale entries, but one evicted and later accepted
  # again from P2P still read as unbroadcast, and the set only grew. Run after every handler that changes the pool; the
  # set holds only local submissions.
  defp prune_unbroadcast(st) do
    if Enum.all?(st.unbroadcast, &Pool.exists?(st.state.pool, &1)),
      do: st,
      else: %{st | unbroadcast: MapSet.filter(st.unbroadcast, &Pool.exists?(st.state.pool, &1))}
  end

  defp refresh_soon(%{refresh_queued: true} = st), do: st

  defp refresh_soon(st) do
    if Pool.stale?(st.state.pool) do
      send(self(), :refresh_lin)
      %{st | refresh_queued: true}
    else
      st
    end
  end

  defp single_result(tx, {:ok, res, _}), do: {:ok, tx, res}
  defp single_result(tx, {:error, e, _}), do: {:error, tx, e}

  # Apply every update already in the mailbox, so the pool matches the view
  # the chain state will answer with (Core holds cs_main across both).
  defp sync(st) do
    receive do
      {:mempool_update, tip_hash, events} -> st |> apply_update(tip_hash, events) |> sync()
    after
      0 -> st
    end
  end

  defp sync_until(st, tip_hash) do
    if st.tip_hash == tip_hash do
      st
    else
      receive do
        {:mempool_update, h, events} -> st |> apply_update(h, events) |> sync_until(tip_hash)
      after
        30_000 -> st
      end
    end
  end

  # --- single-tx accept with background script checks ----------------------------

  # Core: AcceptToMemoryPool, with the scripts on another thread. A tx that
  # spends a pending tx's inputs or outputs (or is one) waits for it.
  defp start_accept(st, job) do
    if depends_on_pending?(st, job.tx) do
      %{st | deferred: :queue.in(job, st.deferred)}
    else
      chain = lazy_chain_context(st)
      args = Accept.normalize_args(job.args)

      case Accept.prepare(st.state, job.tx, chain, args) do
        {:error, e} ->
          GenServer.reply(job.from, {:error, e})
          st

        {:ok, ws} ->
          {raw, spent, flags} = Accept.script_input(ws, chain)
          verify = st.verify
          task = Task.Supervisor.async_nolink(st.verify_sup, fn -> verify.(raw, spent, flags) end)

          job =
            Map.merge(job, %{
              ws: ws,
              chain: chain,
              spent: spent,
              flags: flags,
              tip_hash: st.tip_hash,
              # The state prepare/4 judged against (shared, not copied).
              state: st.state
            })

          %{
            st
            | jobs: Map.put(st.jobs, task.ref, job),
              pending_spends:
                Enum.reduce(inputs(job.tx), st.pending_spends, &Map.put(&2, &1, task.ref)),
              pending_txids: MapSet.put(st.pending_txids, job.tx.txid)
          }
      end
    end
  end

  defp inputs(tx), do: for(i <- tx.inputs, do: {i.prev_hash, i.prev_index})

  defp depends_on_pending?(st, tx) do
    MapSet.member?(st.pending_txids, tx.txid) or
      Enum.any?(tx.inputs, fn i ->
        Map.has_key?(st.pending_spends, {i.prev_hash, i.prev_index}) or
          MapSet.member?(st.pending_txids, i.prev_hash)
      end)
  end

  defp end_job(st, ref, kernel_result) do
    {job, jobs} = Map.pop(st.jobs, ref)

    st = %{
      sync(st)
      | jobs: jobs,
        pending_spends: Map.drop(st.pending_spends, inputs(job.tx)),
        pending_txids: MapSet.delete(st.pending_txids, job.tx.txid)
    }

    st = finish_accept(st, job, kernel_result)

    # The accepts that waited on it, in arrival order.
    {waiting, deferred} = {:queue.to_list(st.deferred), :queue.new()}
    Enum.reduce(waiting, %{st | deferred: deferred}, &start_accept(&2, &1))
  end

  # The pool (and maybe the tip) changed while the scripts ran: decide on
  # the state of now, as Core would have, reusing the script verdict when
  # the kernel would get the same inputs.
  defp finish_accept(st, job, kernel_result) do
    chain =
      if st.tip_hash == job.tip_hash,
        do: cached_chain_context(st, job),
        else: lazy_chain_context(st)

    args = Accept.normalize_args(job.args)

    reply =
      cond do
        match?({:crash, _}, kernel_result) ->
          {:error, Accept.err(:reconsiderable, "script-check-crashed")}

        # The tip moved again: the chain state is ahead of the updates here.
        st.tip_hash != job.tip_hash and chain.tip.hash != st.tip_hash ->
          {:error, Accept.err(:reconsiderable, "tip-changed")}

        true ->
          # Nothing changed since prepare/4 (same tip, and the very same
          # state term: `===` is a pointer check then): it would decide the
          # same, so its workspace stands. An attempt that fails its scripts
          # then costs one prepare, not two.
          prepared =
            if st.tip_hash == job.tip_hash and st.state === job.state,
              do: {:ok, job.ws},
              else: Accept.prepare(st.state, job.tx, chain, args)

          case prepared do
            {:error, e} ->
              {:error, e}

            {:ok, ws} ->
              {raw, spent, flags} = Accept.script_input(ws, chain)

              kernel_result =
                if spent == job.spent and flags == job.flags,
                  do: kernel_result,
                  else: st.verify.(raw, spent, flags)

              Accept.complete(st.state, ws, kernel_result, chain, args)
          end
      end

    case reply do
      {:ok, res, s} ->
        notify(st, {:mempool_accepted, job.tx, res, job.origin})
        GenServer.reply(job.from, {:ok, res})

        unbroadcast =
          if job.unbroadcast, do: MapSet.put(st.unbroadcast, job.tx.txid), else: st.unbroadcast

        %{st | state: s, unbroadcast: unbroadcast}

      {:error, e, s} ->
        GenServer.reply(job.from, {:error, e})
        %{st | state: s}

      {:error, e} ->
        GenServer.reply(job.from, {:error, e})
        st
    end
  end

  # The tip, with coins read on demand (`PreChecks` asks only once it gets to
  # them).
  defp lazy_chain_context(st) do
    {tip, _} = ChainState.mempool_view(st.chain_state, [])
    cs = st.chain_state
    tip_context(st, tip, fn ops -> elem(ChainState.mempool_view(cs, ops), 1) end)
  end

  # The job's context again (same tip), its chain coins remembered.
  defp cached_chain_context(st, job) do
    known =
      for {op, c} <- Enum.zip(inputs(job.tx), job.ws.coins),
          c.height != 0x7FFFFFFF,
          into: %{},
          do: {op, {:ok, c}}

    cs = st.chain_state

    %{
      job.chain
      | coins: fn ops ->
          {hit, miss} = Enum.split_with(ops, &Map.has_key?(known, &1))
          more = if miss == [], do: %{}, else: elem(ChainState.mempool_view(cs, miss), 1)
          Map.merge(Map.take(known, hit), more)
        end,
        now: st.clock.()
    }
  end

  defp tip_context(st, tip, coins) do
    idx = Headers.index(st.headers)
    tip_entry = HeaderIndex.lookup(idx, tip.hash)

    %{
      tip: %{
        height: tip.height,
        hash: tip.hash,
        mtp: HeaderIndex.median_time_past(idx, tip_entry)
      },
      idx: idx,
      flags: ScriptFlags.block_flags(st.params, tip.height, tip.hash),
      now: st.clock.(),
      coins: coins
    }
  end

  # --- chain context -------------------------------------------------------------

  defp chain_context(st, txs) do
    ops =
      for tx <- txs,
          op <-
            Enum.map(tx.inputs, &{&1.prev_hash, &1.prev_index}) ++
              for(v <- 0..(length(tx.outputs) - 1)//1, do: {tx.txid, v}),
          uniq: true,
          do: op

    {tip, prefetched} = ChainState.mempool_view(st.chain_state, ops)
    cs = st.chain_state

    tip_context(st, tip, fn ops ->
      {known, missing} = Enum.split_with(ops, &Map.has_key?(prefetched, &1))
      more = if missing == [], do: %{}, else: elem(ChainState.mempool_view(cs, missing), 1)
      Map.merge(Map.take(prefetched, known), more)
    end)
  end

  # --- block updates ---------------------------------------------------------------

  defp apply_update(st, tip_hash, events) do
    now = st.clock.()

    {s, disconnected} =
      Enum.reduce(events, {st.state, []}, fn
        {:disconnected, txs}, {s, dpool} ->
          notify(st, {:mempool_block, :disconnected})
          {s, dpool ++ [txs]}

        {:connected, compact}, {s, dpool} ->
          notify(st, {:mempool_block, :connected, compact, tip_hash})
          confirmed = MapSet.new(compact, & &1.txid)
          dpool = for txs <- dpool, do: Enum.reject(txs, &MapSet.member?(confirmed, &1.txid))
          {Accept.remove_for_block(s, compact, now), dpool}
      end)

    st = %{st | state: s, tip_hash: tip_hash}
    if disconnected == [], do: st, else: update_for_reorg(st, disconnected)
  end

  # Core: Chainstate::MaybeUpdateMempoolForReorg. `disconnected` lists the
  # disconnected blocks' txs, newest block first; re-add oldest first.
  defp update_for_reorg(st, disconnected) do
    chain = chain_context(st, List.flatten(disconnected))
    txs = disconnected |> Enum.reverse() |> Enum.concat() |> Enum.reject(&Tx.coinbase?/1)

    s =
      Enum.reduce(txs, st.state, fn tx, s ->
        case Accept.accept(s, tx, chain, bypass_limits: true) do
          {:ok, _, s} ->
            s

          {:error, %{reason: "txn-already-known"}, s} ->
            # Its outputs are coins in the chain view: a reorg spanning
            # several updates already reconnected it (the view is ahead of
            # these events). Its mempool children are valid; keep them.
            s

          {:error, _, s} ->
            # removeRecursive: drop mempool txs spending its outputs.
            children =
              for v <- 0..(length(tx.outputs) - 1)//1,
                  (c = Pool.spender(s.pool, {tx.txid, v})) != nil,
                  do: c

            %{s | pool: Pool.remove(s.pool, Pool.with_descendants(s.pool, children))}
        end
      end)

    # Re-added txs merged their in-pool children's clusters without a limit
    # check; trim before anything linearizes them.
    readded = for tx <- txs, Pool.exists?(s.pool, tx.txid), do: tx.txid
    {pool, _trimmed} = Pool.trim_oversized(s.pool, readded)
    s = %{s | pool: pool}

    moved = for txs <- disconnected, tx <- txs, into: MapSet.new(), do: tx.txid
    s = remove_not_final_or_immature(s, chain, moved, st.chain_state)
    %{st | state: Accept.limit_size(s, chain.now)}
  end

  # Core: filter_final_and_mature in MaybeUpdateMempoolForReorg. Coins are
  # read, in one call, only for entries whose check depends on them: a
  # coinbase spend, a relative lock, or a chain input a disconnected tx
  # created (Core recomputes those entries' lock points, which needs them).
  defp remove_not_final_or_immature(s, chain, moved, cs) do
    {bad, check} =
      Enum.reduce(s.pool.entries, {[], []}, fn {txid, e}, {bad, check} ->
        cond do
          not Exnode.Validation.Block.final_tx?(e.tx, chain.tip.height + 1, chain.tip.mtp) ->
            {[txid | bad], check}

          coins_matter?(s.pool, e, moved) ->
            {bad, [e | check]}

          true ->
            {bad, check}
        end
      end)

    ops =
      for e <- check,
          i <- e.tx.inputs,
          not Pool.exists?(s.pool, i.prev_hash),
          uniq: true,
          do: {i.prev_hash, i.prev_index}

    chain = if ops == [], do: chain, else: with_coins(chain, cs, ops)
    bad = for e <- check, not Accept.still_valid_at_tip?(s, e, chain), into: bad, do: e.txid

    if bad == [],
      do: s,
      else: %{s | pool: Pool.remove(s.pool, Pool.with_descendants(s.pool, bad))}
  end

  defp coins_matter?(pool, e, moved) do
    e.spends_coinbase or
      Enum.any?(e.tx.inputs, fn i ->
        (e.tx.version >= 2 and (i.sequence &&& @seq_disable) == 0) or
          (MapSet.member?(moved, i.prev_hash) and not Pool.exists?(pool, i.prev_hash))
      end)
  end

  # `chain` with `ops` read ahead in one chain-state call.
  defp with_coins(chain, cs, ops) do
    {_tip, prefetched} = ChainState.mempool_view(cs, ops)
    lazy = chain.coins

    %{
      chain
      | coins: fn ops ->
          {known, missing} = Enum.split_with(ops, &Map.has_key?(prefetched, &1))
          more = if missing == [], do: %{}, else: lazy.(missing)
          Map.merge(Map.take(prefetched, known), more)
        end
    }
  end

  # A listener may be a registered name that is restarting in another
  # subtree; `send/2` to an unregistered name would raise here.
  defp notify(st, msg) do
    Enum.each(st.listeners, fn l -> if pid = GenServer.whereis(l), do: send(pid, msg) end)
  end

  # --- RPC views & submitpackage helpers -------------------------------------------

  defp min_seq(pool, ids), do: ids |> Enum.map(&Pool.get(pool, &1).sequence) |> Enum.min()

  defp build_entry_details(pool, unbroadcast, e) do
    anc = Pool.ancestors(pool, e.txid) |> MapSet.put(e.txid)
    desc = Pool.descendants(pool, e.txid) |> MapSet.put(e.txid)
    sum = fn set, f -> Enum.reduce(set, 0, &(&2 + f.(Pool.get(pool, &1)))) end
    {chunk_fee, chunk_weight} = entry_chunk(pool, e.txid)

    depends =
      for i <- e.tx.inputs, Pool.exists?(pool, i.prev_hash), uniq: true, do: i.prev_hash

    %{
      entry: %{e | parents: MapSet.new(), children: MapSet.new(), spent: nil},
      ancestor_count: MapSet.size(anc),
      ancestor_size: sum.(anc, & &1.vsize),
      ancestor_fee: sum.(anc, & &1.fee),
      descendant_count: MapSet.size(desc),
      descendant_size: sum.(desc, & &1.vsize),
      descendant_fee: sum.(desc, & &1.fee),
      chunk_fee: chunk_fee,
      chunk_weight: chunk_weight,
      depends: depends,
      spentby: MapSet.to_list(e.children),
      unbroadcast: MapSet.member?(unbroadcast, e.txid)
    }
  end

  defp entry_chunk(pool, txid) do
    with cid when cid != nil <- pool.lin.cluster_of[txid],
         %{chunks: chunks} when chunks != nil <- pool.lin.clusters[cid],
         {{fee, w}, _} <- Enum.find(chunks, fn {_, ids} -> txid in ids end) do
      {fee, w}
    else
      _ ->
        {fee, w, _} = Enum.find(Pool.chunks(pool, txid), fn {_, _, ids} -> txid in ids end)
        {fee, w}
    end
  end

  @mempool_height 0x7FFFFFFF

  # Core ProcessNewPackage(test_accept = false, client_maxfeerate): preserves
  # per-subpackage effective feerate/includes and enforces client_maxfeerate.
  defp submit_package_rpc(state, txs, chain, verify, max_feerate) do
    cond do
      (r = Package.well_formed(txs)) != :ok ->
        {%{state: {:policy, elem(r, 1), nil}, txs: %{}}, state}

      length(txs) > 1 and not Package.child_with_parents?(txs) ->
        {%{state: {:policy, "package-not-child-with-parents", nil}, txs: %{}}, state}

      true ->
        {final, nonfinal, quit_early, to_eval, state} =
          Enum.reduce(txs, {%{}, %{}, false, [], state}, fn tx,
                                                            {final, nonfinal, quit, eval, state} ->
            cond do
              Pool.exists_wtxid?(state.pool, tx.wtxid) ->
                e = Pool.get(state.pool, tx.txid)

                {Map.put(final, tx.wtxid, {:mempool, %{vsize: e.vsize, fee: e.fee}}), nonfinal,
                 quit, eval, state}

              Pool.exists?(state.pool, tx.txid) ->
                e = Pool.get(state.pool, tx.txid)

                {Map.put(final, tx.wtxid, {:different_witness, e.wtxid}), nonfinal, quit, eval,
                 state}

              true ->
                case accept_single_in_package(state, tx, chain, verify, max_feerate) do
                  {:ok, res, state} ->
                    res =
                      Map.merge(res, %{
                        effective_feerate: div(res.fee * 1000, res.vsize),
                        effective_includes: [tx.wtxid]
                      })

                    {Map.put(final, tx.wtxid, {:valid, res}), nonfinal, quit, eval, state}

                  {:error, e, state} ->
                    retry = length(txs) > 1 and e.result in [:reconsiderable, :missing_inputs]
                    nonfinal = Map.put(nonfinal, tx.wtxid, {:invalid, e})

                    if retry,
                      do: {final, nonfinal, quit, eval ++ [tx], state},
                      else: {final, nonfinal, true, eval, state}
                end
            end
          end)

        {multi_res, state} =
          cond do
            quit_early ->
              {%{state: {:tx, "transaction failed", nil}, txs: %{}},
               Accept.limit_size(state, chain.now)}

            to_eval == [] ->
              {%{state: :ok, txs: %{}}, Accept.limit_size(state, chain.now)}

            length(to_eval) == 1 ->
              [only] = to_eval

              case accept_single_in_package(state, only, chain, verify, max_feerate) do
                {:ok, res, state} ->
                  res =
                    Map.merge(res, %{
                      effective_feerate: div(res.fee * 1000, res.vsize),
                      effective_includes: [only.wtxid]
                    })

                  {%{state: :ok, txs: %{only.wtxid => {:valid, res}}},
                   Accept.limit_size(state, chain.now)}

                {:error, e, state} ->
                  {%{
                     state: {:tx, "transaction failed", nil},
                     txs: %{only.wtxid => {:invalid, e}}
                   }, Accept.limit_size(state, chain.now)}
              end

            true ->
              case precheck_package_max_feerate(state, to_eval, chain, max_feerate) do
                {:failed, tx, e} ->
                  {%{state: {:tx, "transaction failed", nil}, txs: %{tx.wtxid => {:invalid, e}}},
                   Accept.limit_size(state, chain.now)}

                :ok ->
                  {pkg_res, state} = Package.accept(state, to_eval, chain)
                  {enrich_multi_effective(pkg_res, to_eval), state}
              end
          end

        full = Accept.err(:mempool_policy, "mempool full")

        {pkg_state, results} =
          Enum.reduce(txs, {multi_res.state, %{}}, fn tx, {ps, acc} ->
            cond do
              Map.has_key?(multi_res.txs, tx.wtxid) ->
                case multi_res.txs[tx.wtxid] do
                  {:valid, _} = r ->
                    if Pool.exists_wtxid?(state.pool, tx.wtxid),
                      do: {ps, Map.put(acc, tx.wtxid, r)},
                      else:
                        {{:tx, "transaction failed", nil},
                         Map.put(acc, tx.wtxid, {:invalid, full})}

                  r ->
                    {ps, Map.put(acc, tx.wtxid, r)}
                end

              Map.has_key?(final, tx.wtxid) ->
                if Pool.exists?(state.pool, tx.txid),
                  do: {ps, Map.put(acc, tx.wtxid, final[tx.wtxid])},
                  else:
                    {{:tx, "transaction failed", nil}, Map.put(acc, tx.wtxid, {:invalid, full})}

              Map.has_key?(nonfinal, tx.wtxid) ->
                {ps, Map.put(acc, tx.wtxid, nonfinal[tx.wtxid])}

              true ->
                {ps, acc}
            end
          end)

        {%{state: pkg_state, txs: results}, state}
    end
  end

  defp accept_single_in_package(state, tx, chain, verify, max_feerate) do
    args =
      Accept.normalize_args(
        test_accept: false,
        package_submission: true,
        allow_replacement: true,
        allow_sibling_eviction: true
      )

    case Accept.prepare(state, tx, chain, args) do
      {:error, e} ->
        {:error, e, state}

      {:ok, ws} ->
        if max_feerate != nil and max_feerate > 0 and ws.fee * 1000 > max_feerate * ws.vsize do
          {:error, Accept.err(:mempool_policy, "max feerate exceeded", ""), state}
        else
          {raw, spent, flags} = Accept.script_input(ws, chain)
          Accept.complete(state, ws, verify.(raw, spent, flags), chain, args)
        end
    end
  end

  defp precheck_package_max_feerate(_state, _txs, _chain, max_feerate)
       when max_feerate in [nil, 0],
       do: :ok

  defp precheck_package_max_feerate(state, txs, chain, max_feerate) do
    args =
      Accept.normalize_args(
        package_submission: true,
        package_feerates: true,
        allow_sibling_eviction: false
      )

    res =
      Enum.reduce_while(txs, %{}, fn tx, coins ->
        case Accept.pre_checks(state, tx, chain, %{args | package_coins: coins}) do
          {:error, e} ->
            {:halt, {:failed, tx, e}}

          {:ok, ws} ->
            if ws.fee * 1000 > max_feerate * ws.vsize do
              {:halt, {:failed, tx, Accept.err(:mempool_policy, "max feerate exceeded", "")}}
            else
              new =
                for {o, v} <- Enum.with_index(tx.outputs),
                    into: %{},
                    do:
                      {{tx.txid, v},
                       %{
                         value: o.value,
                         script_pubkey: o.script_pubkey,
                         height: @mempool_height,
                         coinbase: false
                       }}

              {:cont, Map.merge(coins, new)}
            end
        end
      end)

    case res do
      {:failed, _, _} = err -> err
      _ -> :ok
    end
  end

  defp enrich_multi_effective(%{txs: txs_map} = pkg_res, to_eval) do
    valid_entries =
      for tx <- to_eval, match?({:valid, _}, txs_map[tx.wtxid]), do: elem(txs_map[tx.wtxid], 1)

    if valid_entries == [] do
      pkg_res
    else
      includes = Enum.map(to_eval, & &1.wtxid)
      total_fee = Enum.reduce(valid_entries, 0, &(&2 + &1.fee))
      total_vsize = Enum.reduce(valid_entries, 0, &(&2 + &1.vsize))
      eff_rate = div(total_fee * 1000, total_vsize)

      enriched =
        Map.new(txs_map, fn
          {wtxid, {:valid, r}} ->
            {wtxid,
             {:valid, Map.merge(r, %{effective_feerate: eff_rate, effective_includes: includes})}}

          other ->
            other
        end)

      %{pkg_res | txs: enriched}
    end
  end
end
