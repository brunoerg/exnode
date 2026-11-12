defmodule Exnode.Shadow.Monitor do
  @moduledoc """
  Cross-checks exnode's verdicts against Core's own engine (the shadow
  validator Port, `Exnode.Shadow`).

  After each activation round the chain state calls `round/4` with the
  blocks it connected (in order), the block it rejected (if any) and its new
  tip. They are fed to the shadow in that order. A **divergence** is:
  * the shadow says `invalid` for a block exnode connected
  * the shadow says `valid` for the block exnode rejected (or adopts it as tip)
  * the shadow's tip differs from exnode's at the end of the round
  * the shadow cannot process a block exnode connected
    (`connected_but_shadow_error`), or cannot report its tip
    (`shadow_tip_error`; the tip comparison is skipped that round)

  On divergence, the block (hex), both verdicts and both tips are written to
  `<dir>/divergences/<hash>.json` and logged. With `halt: true` (the default)
  the chain state is told to halt block connection.

  The halt stays pending until the chain state acknowledges it
  (`halt_ack/1`, sent once the durable halt mark is written). Until then it
  is re-sent to the caller of every `round/4`, `shadow_tip/1` and
  `set_ahead/2`, so a halt cast that was lost (the chain state was
  restarting, its name unregistered) reaches the restarted one before its
  first round: CS-6 (STATE_MACHINES.md).

  Backpressure: `round/4` returns at once while fewer than `max_lag` blocks
  are queued, and blocks the caller otherwise.
  """
  use GenServer
  require Logger

  alias Exnode.Crypto.Hash
  alias Exnode.Shadow

  @max_lag 512

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "`connected`: `[{hash, raw}]`; `rejected`: `[{hash, raw, reason}]`; `tip`: hash."
  def round(server, connected, rejected, tip),
    do: GenServer.call(server, {:round, connected, rejected, tip}, :infinity)

  @doc "Blocks until every queued round has been checked. Returns the stats."
  def drain(server), do: GenServer.call(server, :drain, :infinity)

  def stats(server), do: GenServer.call(server, :stats)

  @doc """
  The shadow's tip `{height, hash}` (after the rounds queued so far).

  Startup catch-up is driven by the chain state: it compares this with its
  own tip and either feeds the missing archived blocks as ordinary rounds
  (`round/4`, with backpressure) or reports the shadow ahead (`set_ahead/2`).
  The monitor never calls the chain state, so the two cannot deadlock.
  """
  def shadow_tip(server), do: GenServer.call(server, :shadow_tip, :infinity)

  @doc "The shadow is ahead of exnode at `{height, hash}`: tolerate the tip mismatch until exnode gets there."
  def set_ahead(server, tip), do: GenServer.call(server, {:set_ahead, tip})

  @doc "The chain state has persisted a halt: stop re-sending the pending one."
  def halt_ack(server), do: GenServer.cast(server, :halt_ack)

  @impl true
  def init(opts) do
    # Trap exits so terminate/2 runs on shutdown and waits for the shadow's flush.
    Process.flag(:trap_exit, true)
    dir = Keyword.fetch!(opts, :dir)

    {:ok, shadow} =
      Shadow.start_link(chain: Keyword.fetch!(opts, :chain), datadir: Path.join(dir, "shadow"))

    {:ok,
     %{
       shadow: shadow,
       dir: dir,
       halt: Keyword.get(opts, :halt, true),
       chain_state: Keyword.get(opts, :chain_state),
       headers: Keyword.get(opts, :headers),
       ahead: nil,
       halt_pending: false,
       queue: :queue.new(),
       queued_blocks: 0,
       waiting: [],
       drainers: [],
       tip_waiters: [],
       stats: %{rounds: 0, blocks: 0, divergences: 0},
       max_lag: Keyword.get(opts, :max_lag, @max_lag)
     }}
  end

  # Stop the shadow process with us, so its datadir lock is released.
  @impl true
  def terminate(_reason, %{shadow: shadow}) do
    if Process.alive?(shadow), do: Shadow.stop(shadow)
    :ok
  end

  @impl true
  def handle_call({:round, connected, rejected, tip}, from, st) do
    resend_halt(st, from)
    n = length(connected) + length(rejected)

    st = %{
      st
      | queue: :queue.in({connected, rejected, tip}, st.queue),
        queued_blocks: st.queued_blocks + n
    }

    send(self(), :work)

    if st.queued_blocks > st.max_lag,
      do: {:noreply, %{st | waiting: [from | st.waiting]}},
      else: {:reply, :ok, st}
  end

  def handle_call(:drain, from, st) do
    if :queue.is_empty(st.queue),
      do: {:reply, st.stats, st},
      else: {:noreply, %{st | drainers: [from | st.drainers]}}
  end

  def handle_call(:stats, _from, st), do: {:reply, st.stats, st}

  def handle_call(:shadow_tip, from, st) do
    resend_halt(st, from)
    # Answer after the queued rounds are checked.
    if :queue.is_empty(st.queue),
      do: {:reply, Shadow.tip(st.shadow), st},
      else: {:noreply, %{st | tip_waiters: [from | st.tip_waiters]}}
  end

  def handle_call({:set_ahead, {sh, _} = tip}, from, st) do
    resend_halt(st, from)
    Logger.info("shadow is ahead (at #{sh}); tip comparison resumes there")
    {:reply, :ok, %{st | ahead: tip}}
  end

  def handle_call({:set_chain_state, pid}, _from, st), do: {:reply, :ok, %{st | chain_state: pid}}

  @impl true
  def handle_cast(:halt_ack, st), do: {:noreply, %{st | halt_pending: false}}

  @impl true
  # Trapped exits: the shadow port GenServer dying is fatal; others are ignored.
  def handle_info({:EXIT, pid, reason}, %{shadow: pid} = st),
    do: {:stop, {:shadow_exited, reason}, st}

  def handle_info({:EXIT, _pid, _reason}, st), do: {:noreply, st}

  def handle_info(:work, st) do
    case :queue.out(st.queue) do
      {:empty, _} ->
        Enum.each(st.drainers, &GenServer.reply(&1, st.stats))

        if st.tip_waiters != [],
          do:
            (
              tip = Shadow.tip(st.shadow)
              Enum.each(st.tip_waiters, &GenServer.reply(&1, tip))
            )

        {:noreply, %{st | drainers: [], tip_waiters: []}}

      {{:value, {connected, rejected, tip} = r}, q} ->
        n = length(connected) + length(rejected)
        st = check_round(%{st | queue: q, queued_blocks: st.queued_blocks - n}, r, tip)

        st =
          if st.queued_blocks <= st.max_lag do
            Enum.each(st.waiting, &GenServer.reply(&1, :ok))
            %{st | waiting: []}
          else
            st
          end

        send(self(), :work)
        # Rounds carry raw blocks; release them promptly.
        :erlang.garbage_collect()
        {:noreply, st}
    end
  end

  defp check_round(st, {connected, rejected, _}, tip) do
    rejected_hashes = MapSet.new(rejected, &elem(&1, 0))

    # Every fed block is either connected or rejected by exnode, so an invalid
    # event for anything exnode did not reject is a divergence (this includes
    # events fired late, during a shadow reorg).
    conn_problems =
      Enum.flat_map(connected, fn {hash, raw} ->
        case Shadow.process_block(st.shadow, raw) do
          {:ok, v} ->
            for {h, mode, result} <- v.events,
                mode != :valid,
                not MapSet.member?(rejected_hashes, h),
                do: {:connected_but_shadow_invalid, h, raw, {mode, result}, hash}

          # exnode connected a block Core's engine cannot even process (e.g.
          # :bad_block_encoding): a divergence by definition.
          {:error, reason} ->
            [{:connected_but_shadow_error, hash, raw, reason, hash}]
        end
      end)

    rej_problems =
      Enum.flat_map(rejected, fn {hash, raw, reason} ->
        case Shadow.process_block(st.shadow, raw) do
          {:ok, v} ->
            valid = Enum.any?(v.events, fn {h, m, _} -> h == hash and m == :valid end)

            if valid or elem(v.tip, 1) == hash,
              do: [{:rejected_but_shadow_valid, hash, raw, reason, v.events}],
              else: []

          # Undecodable for Core too: agreement.
          {:error, _} ->
            []
        end
      end)

    # A failed tip query is recorded as a divergence (so it halts, like the
    # others) and the tip comparison is skipped for this round.
    {st, tip_problems} =
      case Shadow.tip(st.shadow) do
        {:ok, {_h, shadow_tip}} ->
          {st, tolerated} = ahead_tolerance(st, tip)

          {st,
           if(shadow_tip == tip or tolerated or shadow_ahead?(st, tip, shadow_tip),
             do: [],
             else: [{:tip_mismatch, tip, shadow_tip}]
           )}

        {:error, reason} ->
          {st, [{:shadow_tip_error, tip, reason}]}
      end

    problems = conn_problems ++ rej_problems ++ tip_problems
    n = length(connected) + length(rejected)

    stats = %{
      st.stats
      | rounds: st.stats.rounds + 1,
        blocks: st.stats.blocks + n,
        divergences: st.stats.divergences + length(problems)
    }

    st = %{st | stats: stats}

    if problems != [] do
      Enum.each(problems, &record(st, &1))

      if st.halt and st.chain_state,
        do: GenServer.cast(st.chain_state, {:halt, :shadow_divergence})
    end

    %{st | halt_pending: st.halt_pending or (problems != [] and st.halt)}
  end

  # Only the chain state calls round/shadow_tip/set_ahead, so the caller is
  # the live chain state process, whatever happened to its name.
  defp resend_halt(%{halt_pending: true}, {pid, _}),
    do: GenServer.cast(pid, {:halt, :shadow_divergence})

  defp resend_halt(_st, _from), do: :ok

  # Startup "ahead" window: tolerate until exnode's tip height reaches it.
  defp ahead_tolerance(%{ahead: nil} = st, _tip), do: {st, false}

  defp ahead_tolerance(%{ahead: {h, _}} = st, tip) do
    tip_h =
      case st.headers &&
             Exnode.Chain.HeaderIndex.lookup(Exnode.Chain.Headers.index(st.headers), tip) do
        %{height: th} -> th
        _ -> 0
      end

    if tip_h < h, do: {st, true}, else: {%{st | ahead: nil}, false}
  end

  # After a restart the shadow can be ahead of exnode (it processed blocks
  # exnode had not committed). That is not a divergence while exnode's tip is
  # an ancestor of the shadow's tip in the header tree. Real disagreements show
  # up as per-block invalid/valid events.
  defp shadow_ahead?(%{headers: nil}, _tip, _shadow_tip), do: false

  defp shadow_ahead?(st, tip, shadow_tip) do
    alias Exnode.Chain.{HeaderIndex, Headers}
    idx = Headers.index(st.headers)

    case {HeaderIndex.lookup(idx, tip), HeaderIndex.lookup(idx, shadow_tip)} do
      {%{} = t, %{} = s} -> s.height > t.height and HeaderIndex.ancestor_of?(idx, t, s)
      _ -> false
    end
  end

  defp record(st, problem) do
    dir = Path.join(st.dir, "divergences")
    File.mkdir_p!(dir)

    {name, doc} =
      case problem do
        {kind, h, raw, detail, _} ->
          {Hash.to_hex(h),
           %{
             kind: kind,
             block: Hash.to_hex(h),
             hex: Base.encode16(raw, case: :lower),
             detail: inspect(detail)
           }}

        {:tip_mismatch, ours, theirs} ->
          {"tip-" <> Hash.to_hex(ours),
           %{kind: :tip_mismatch, exnode_tip: Hash.to_hex(ours), shadow_tip: Hash.to_hex(theirs)}}

        {:shadow_tip_error, ours, reason} ->
          {"tip-error-" <> Hash.to_hex(ours),
           %{kind: :shadow_tip_error, exnode_tip: Hash.to_hex(ours), detail: inspect(reason)}}
      end

    File.write!(Path.join(dir, name <> ".json"), Jason.encode!(doc, pretty: true))
    Logger.error("SHADOW DIVERGENCE #{doc.kind} #{name}, see #{dir}")
  end
end
