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
  synchronous (RPC-facing, authenticated, or chain-driven).

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
  alias Exnode.Mempool.{Accept, Package, Pool}
  alias Exnode.Validation.ScriptFlags

  @max_pending_verifications 128
  # Txs linearized per idle cache-refresh message (about one full cluster).
  @refresh_lin_txs 64

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

  def txids(server), do: GenServer.call(server, :txids, 5_000)

  @doc """
  The mempool txs paying to or spending from the script with scripthash
  `sh` (`sha256(scriptPubKey)`), oldest first: `[%{txid, tx, spent}]`
  (`spent`: `{value, scripthash}` per input). Needs `index_scripts: true`;
  else `{:error, :not_indexed}`. Copies only those txs out of the mempool.
  """
  def script_txs(server, sh), do: GenServer.call(server, {:script_txs, sh}, :infinity)

  @doc "The mempool spenders of `outpoints`: `%{outpoint => {txid, input_index}}` (unspent ones absent)."
  def spenders(server, outpoints), do: GenServer.call(server, {:spenders, outpoints}, :infinity)

  @doc "`{fee, vsize}` of every mempool tx, and the total vsize: `{pairs, total_vsize}`."
  def fee_rates(server), do: GenServer.call(server, :fee_rates, :infinity)

  @doc "The pool itself (for RPC views)."
  def pool(server), do: GenServer.call(server, :pool, 5_000)

  @doc "Core `CTxMemPool::isSpent`: a mempool tx spends `outpoint`."
  def spent?(server, outpoint), do: GenServer.call(server, {:spent?, outpoint}, 5_000)

  @doc "Core's unbroadcast set: txs submitted locally (RPC) not yet requested by any peer."
  def unbroadcast?(server, txid), do: GenServer.call(server, {:unbroadcast?, txid}, 5_000)
  def unbroadcast_count(server), do: GenServer.call(server, :unbroadcast_count, 5_000)
  def remove_unbroadcast(server, txids), do: GenServer.cast(server, {:remove_unbroadcast, txids})

  @doc "`{mempool min fee rate (sat/kvB), policy opts}` (Core `GetMinFee`, `m_opts`)."
  def fee_info(server), do: GenServer.call(server, :fee_info, 5_000)
  def entry(server, txid), do: GenServer.call(server, {:entry, txid}, 5_000)

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
    # pass (the missing txs are requested), not a dropped peer (MP-3).
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
      refresh_queued: false
    }

    {:ok, st}
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

  def handle_call(:txids, _from, st), do: {:reply, Map.keys(st.state.pool.entries), st}

  def handle_call({:script_txs, sh}, _from, st) do
    st = sync(st)
    pool = st.state.pool

    reply =
      if Pool.indexes_scripts?(pool) do
        pool
        |> Pool.script_txids(sh)
        |> Enum.map(&Pool.get(pool, &1))
        |> Enum.sort_by(& &1.sequence)
        |> Enum.map(&%{txid: &1.txid, tx: &1.tx, spent: &1.spent})
      else
        {:error, :not_indexed}
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

  def handle_call(:pool, _from, st), do: {:reply, st.state.pool, st}

  def handle_call({:spent?, op}, _from, st),
    do: {:reply, Pool.spender(st.state.pool, op) != nil, st}

  def handle_call({:unbroadcast?, txid}, _from, st),
    do: {:reply, MapSet.member?(st.unbroadcast, txid) and Pool.exists?(st.state.pool, txid), st}

  def handle_call(:unbroadcast_count, _from, st),
    do: {:reply, Enum.count(st.unbroadcast, &Pool.exists?(st.state.pool, &1)), st}

  def handle_call(:fee_info, _from, st) do
    {rate, fees} = Accept.min_fee(st.state, st.clock.())
    {:reply, {rate, st.state.opts}, %{st | state: %{st.state | fees: fees}}}
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
  # again from P2P still read as unbroadcast, and the set only grew (MP-6 in
  # STATE_MACHINES.md). Run after every handler that changes the pool; the
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
          # then costs one prepare, not two (AUD-F2).
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
    # check; trim before anything linearizes them (MP-1b).
    readded = for tx <- txs, Pool.exists?(s.pool, tx.txid), do: tx.txid
    {pool, _trimmed} = Pool.trim_oversized(s.pool, readded)
    s = %{s | pool: pool}

    s = remove_not_final_or_immature(s, chain)
    %{st | state: Accept.limit_size(s, chain.now)}
  end

  # Core: filter_final_and_mature in MaybeUpdateMempoolForReorg.
  defp remove_not_final_or_immature(s, chain) do
    bad =
      for {txid, e} <- s.pool.entries,
          not Exnode.Validation.Block.final_tx?(e.tx, chain.tip.height + 1, chain.tip.mtp) or
            not Accept.still_valid_at_tip?(s, e, chain),
          do: txid

    if bad == [],
      do: s,
      else: %{s | pool: Pool.remove(s.pool, Pool.with_descendants(s.pool, bad))}
  end

  # A listener may be a registered name that is restarting in another
  # subtree; `send/2` to an unregistered name would raise here.
  defp notify(st, msg) do
    Enum.each(st.listeners, fn l -> if pid = GenServer.whereis(l), do: send(pid, msg) end)
  end
end
