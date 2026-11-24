defmodule Exnode.P2P.Peer.HeadersHandler do
  @moduledoc """
  Per-peer headers sync initiation, timeouts, `ProcessHeadersMessage` with
  `HeadersSync` anti-DoS presync/redownload, outbound tip protection, and
  `ConsiderEviction` chain-sync checks (Core v32.1 `net_processing.cpp`).
  """

  import Bitwise
  require Logger

  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Consensus.Pow
  alias Exnode.P2P.{BlockDownload, HeadersSync, Message, Peer, SyncState}
  alias Exnode.P2P.Peer.BlockSync

  @headers_response_time_s 120
  @headers_download_timeout_base_s 15 * 60
  @headers_download_timeout_per_header_ms 1
  @chain_sync_timeout_s 20 * 60

  @doc "Initiates headers sync with this peer when eligible."
  def maybe_start_sync(%{sync_started: true} = st, _t), do: st

  def maybe_start_sync(st, t) do
    can_serve = st.version && (st.version.services &&& Message.service(:network)) != 0

    if Peer.handshake_done?(st) and can_serve do
      idx = Headers.index(st.node.headers)
      best = HeaderIndex.best(idx)
      preferred = not st.inbound
      recent = best.time > t - 24 * 3600

      if SyncState.try_start(st.node.sync, self(), preferred, recent) do
        # Core: m_headers_sync_timeout = now + BASE + PER_HEADER * (now - best.time) / spacing
        expected_headers = div(max(t - best.time, 0), st.p.pow_target_spacing)

        timeout =
          t + @headers_download_timeout_base_s +
            div(expected_headers * @headers_download_timeout_per_header_ms, 1000)

        # Core starts from pindexBestHeader->pprev, so the peer replies with at least one header.
        start = HeaderIndex.prev(idx, best) || best
        st = %{st | sync_started: true, headers_sync_timeout: timeout}
        maybe_send_getheaders(st, HeaderIndex.locator(idx, start))
      else
        st
      end
    else
      st
    end
  end

  @doc "Core `SendMessages` 'Timeout downloading headers' check."
  def check_headers_sync_timeout(%{sync_started: true, headers_sync_timeout: dl} = st, t)
      when is_integer(dl) and t > dl do
    best = Headers.best_header(st.node.headers)

    cond do
      best.time > t - 24 * 3600 ->
        {:noreply, %{st | headers_sync_timeout: nil}}

      SyncState.count(st.node.sync) == 1 and other_preferred_peer?(st) ->
        {:stop, {:shutdown, :headers_sync_timeout}, st}

      true ->
        {:noreply, st}
    end
  end

  def check_headers_sync_timeout(st, _t), do: {:noreply, st}

  @doc "Core `MaybeSendGetHeaders` (`HEADERS_RESPONSE_TIME` throttle)."
  def maybe_send_getheaders(st, locator, force \\ false) do
    t = Peer.now(st)

    if force or st.last_getheaders_at == nil or
         t - st.last_getheaders_at > @headers_response_time_s do
      Peer.push(
        %{st | last_getheaders_at: t},
        {:getheaders, %{locator: locator, hash_stop: <<0::256>>}}
      )
    else
      st
    end
  end

  @doc "Core `PeerManagerImpl::ProcessHeadersMessage`."
  def process_headers_message(st, []) do
    {:ok, %{st | headers_sync: nil, last_getheaders_at: nil}}
  end

  def process_headers_message(st, headers) do
    count = length(headers)
    full = count == Message.max_headers_results()

    # Core: CheckHeadersPoW (HasValidProofOfWork + CheckHeadersAreContinuous)
    cond do
      not Enum.all?(headers, &Pow.check_proof_of_work(&1.hash, &1.bits, st.p.pow_limit)) ->
        Peer.misbehaving(st, "header with invalid proof of work")

      not continuous?(headers) ->
        Peer.misbehaving(st, "non-continuous headers sequence")

      true ->
        {already_validated, headers, st} = continuation_of_low_work_sync(st, headers, full)
        have_headers_sync = st.headers_sync != nil

        if headers == [],
          do: {:ok, st},
          else:
            process_connected_headers(st, headers, count, already_validated, have_headers_sync)
    end
  end

  @doc "Core `GetAntiDoSWorkThreshold`, on the active tip (genesis until blocks connect)."
  def anti_dos_work_threshold(st),
    do: HeaderIndex.anti_dos_work_threshold(active_tip_header(st), st.p)

  @doc "Core `ConsiderEviction` (`CHAIN_SYNC_TIMEOUT`, `HEADERS_RESPONSE_TIME`)."
  def consider_eviction(
        {:noreply, %{chain_sync: %{protect: false}, sync_started: true, conn_type: ct} = st},
        t
      )
      when ct in [:outbound_full_relay, :block_relay] do
    idx = Headers.index(st.node.headers)
    tip = chain_sync_tip(st, idx)
    cs = st.chain_sync
    best = st.best_known

    cond do
      best != nil and best.chain_work >= tip.chain_work ->
        {:noreply,
         %{st | chain_sync: %{cs | timeout: nil, work_header: nil, sent_getheaders: false}}}

      cs.timeout == nil or
          (cs.work_header != nil and best != nil and
             best.chain_work >= cs.work_header.chain_work) ->
        cs = %{cs | timeout: t + @chain_sync_timeout_s, work_header: tip, sent_getheaders: false}
        {:noreply, %{st | chain_sync: cs}}

      t > cs.timeout and cs.sent_getheaders ->
        Logger.info(
          "outbound peer has old chain, best known block = " <>
            if(best, do: Base.encode16(best.hash, case: :lower), else: "<none>")
        )

        {:stop, {:shutdown, :chain_sync_timeout}, st}

      t > cs.timeout ->
        # Core: GetLocator(m_work_header->pprev), through the getheaders throttle.
        start = HeaderIndex.prev(idx, cs.work_header) || cs.work_header
        st = maybe_send_getheaders(st, HeaderIndex.locator(idx, start))
        cs = %{cs | sent_getheaders: true, timeout: t + @headers_response_time_s}
        {:noreply, %{st | chain_sync: cs}}

      true ->
        {:noreply, st}
    end
  end

  def consider_eviction(result, _t), do: result

  # --- internal helpers -------------------------------------------------------

  defp other_preferred_peer?(%{node: %{block_download: bd}}) when bd != nil,
    do: BlockDownload.other_preferred?(bd, self())

  defp other_preferred_peer?(_st), do: false

  defp process_connected_headers(st, headers, count, already_validated, have_headers_sync) do
    idx = Headers.index(st.node.headers)

    case HeaderIndex.lookup(idx, hd(headers).prev_hash) do
      nil ->
        # Core: HandleUnconnectingHeaders
        {:ok, maybe_send_getheaders(st, HeaderIndex.locator(idx, HeaderIndex.best(idx)))}

      chain_start ->
        st = %{st | last_getheaders_at: nil}
        last_received = HeaderIndex.lookup(idx, List.last(headers).hash)

        already_validated =
          already_validated or
            (last_received != nil and
               HeaderIndex.ancestor_of?(idx, last_received, HeaderIndex.best(idx)))

        case not already_validated &&
               try_low_work_headers_sync(st, idx, chain_start, headers, count) do
          {:handled, st} -> {:ok, st}
          _ -> accept_headers(st, headers, count, have_headers_sync)
        end
    end
  end

  defp accept_headers(st, headers, count, have_headers_sync) do
    case Headers.process_headers(st.node.headers, headers,
           min_pow_checked: true,
           now: Peer.now(st)
         ) do
      {:ok, last} ->
        st =
          %{st | best_known: Peer.better(st.best_known, last)}
          |> maybe_update_best_known_block(last)
          |> maybe_protect()

        st =
          if count == Message.max_headers_results() and not have_headers_sync,
            do:
              maybe_send_getheaders(st, HeaderIndex.locator(Headers.index(st.node.headers), last)),
            else: st

        {:ok, st}

      {:error, {result, reason}, _last} ->
        BlockSync.maybe_punish_for_block(st, result, "invalid header received: #{reason}")
    end
  end

  defp maybe_update_best_known_block(st, last) do
    have_block? =
      case st.node[:chain_state] do
        nil ->
          false

        cs ->
          case is_atom(cs) && ChainState.view(cs) do
            nil -> false
            v -> MapSet.member?(ChainState.view_have_many(v, [last.hash]), last.hash)
          end
      end

    if have_block?,
      do: %{st | best_known_block: max(st.best_known_block, last.height)},
      else: st
  end

  # Core: IsContinuationOfLowWorkHeadersSync
  defp continuation_of_low_work_sync(%{headers_sync: nil} = st, headers, _full),
    do: {false, headers, st}

  defp continuation_of_low_work_sync(st, headers, full) do
    {res, hs} = HeadersSync.process_next_headers(st.headers_sync, headers, full)
    st = if res.success, do: %{st | last_getheaders_at: nil}, else: st

    st =
      if res.request_more,
        do: maybe_send_getheaders(st, HeadersSync.next_headers_request_locator(hs), true),
        else: st

    st = %{st | headers_sync: if(HeadersSync.state(hs) == :final, do: nil, else: hs)}

    if res.success, do: {true, res.pow_validated_headers, st}, else: {false, headers, st}
  end

  # Core: TryLowWorkHeadersSync
  defp try_low_work_headers_sync(st, idx, chain_start, headers, count) do
    claimed = Enum.reduce(headers, 0, &(&2 + Pow.bits_proof(&1.bits)))
    threshold = anti_dos_work_threshold(st)

    if chain_start.chain_work + claimed < threshold do
      if count == Message.max_headers_results() do
        hs =
          HeadersSync.new(
            st.p,
            chain_start,
            HeaderIndex.median_time_past(idx, chain_start),
            HeaderIndex.locator(idx, chain_start),
            threshold,
            Peer.now(st)
          )

        {_validated, _headers, st} =
          continuation_of_low_work_sync(%{st | headers_sync: hs}, headers, true)

        {:handled, st}
      else
        # "Ignoring low-work chain"
        {:handled, st}
      end
    else
      :not_low_work
    end
  end

  # The active tip's header entry; nil without a chain state.
  defp active_tip_header(st) do
    if cs = st.node[:chain_state] do
      t =
        if v = is_atom(cs) && ChainState.view(cs),
          do: ChainState.view_tip(v),
          else: ChainState.tip(cs)

      HeaderIndex.lookup(Headers.index(st.node.headers), t.hash)
    end
  end

  # The active tip, genesis without a chain state.
  defp chain_sync_tip(st, idx),
    do: active_tip_header(st) || HeaderIndex.ancestor(idx, HeaderIndex.best(idx), 0)

  # Core: UpdatePeerStateForReceivedHeaders. Up to
  # MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT (4) outbound full-relay
  # peers with a chain at least as good as our tip are exempt from
  # ConsiderEviction; block-relay peers never are.
  defp maybe_protect(
         %{conn_type: :outbound_full_relay, chain_sync: %{protect: false}, best_known: b} = st
       )
       when b != nil do
    tip = chain_sync_tip(st, Headers.index(st.node.headers))

    if b.chain_work >= tip.chain_work and SyncState.try_protect(st.node.sync, self()),
      do: put_in(st.chain_sync.protect, true),
      else: st
  end

  defp maybe_protect(st), do: st

  defp continuous?([_]), do: true
  defp continuous?([a, b | rest]), do: b.prev_hash == a.hash and continuous?([b | rest])
end
