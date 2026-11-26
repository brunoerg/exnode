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
  alias Exnode.P2P.Peer.{BlockSync, Data}
  alias Exnode.P2P.Peer.Data.Proto

  @headers_response_time_s 120
  @headers_download_timeout_base_s 15 * 60
  @headers_download_timeout_per_header_ms 1
  @chain_sync_timeout_s 20 * 60

  @doc "Initiates headers sync with this peer when eligible."
  def maybe_start_sync(%Data{proto: %Proto{sync_started: true}} = data, _t), do: data

  def maybe_start_sync(%Data{proto: %Proto{} = proto} = data, t) do
    v = data.handshake.version
    can_serve = v != nil and (v.services &&& Message.service(:network)) != 0

    if can_serve do
      idx = Headers.index(data.node.headers)
      best = HeaderIndex.best(idx)
      preferred = not data.inbound
      recent = best.time > t - 24 * 3600

      if SyncState.try_start(data.node.sync, self(), preferred, recent) do
        # Core: m_headers_sync_timeout = now + BASE + PER_HEADER * (now - best.time) / spacing
        expected_headers = div(max(t - best.time, 0), data.p.pow_target_spacing)

        timeout =
          t + @headers_download_timeout_base_s +
            div(expected_headers * @headers_download_timeout_per_header_ms, 1000)

        # Core starts from pindexBestHeader->pprev, so the peer replies with at least one header.
        start = HeaderIndex.prev(idx, best) || best
        data = %{data | proto: %{proto | sync_started: true, headers_sync_timeout: timeout}}
        maybe_send_getheaders(data, HeaderIndex.locator(idx, start))
      else
        data
      end
    else
      data
    end
  end

  @doc "Core `SendMessages` 'Timeout downloading headers' check."
  def check_headers_sync_timeout(
        %Data{proto: %Proto{sync_started: true, headers_sync_timeout: dl} = proto} = data,
        t
      )
      when is_integer(dl) and t > dl do
    best = Headers.best_header(data.node.headers)

    cond do
      best.time > t - 24 * 3600 ->
        {:ok, %{data | proto: %{proto | headers_sync_timeout: nil}}}

      SyncState.count(data.node.sync) == 1 and other_preferred_peer?(data) ->
        {:stop, {:shutdown, :headers_sync_timeout}, data}

      true ->
        {:ok, data}
    end
  end

  def check_headers_sync_timeout(data, _t), do: {:ok, data}

  @doc "Core `MaybeSendGetHeaders` (`HEADERS_RESPONSE_TIME` throttle)."
  def maybe_send_getheaders(%Data{proto: %Proto{} = proto} = data, locator, force \\ false) do
    t = Peer.now(data)

    if force or proto.last_getheaders_at == nil or
         t - proto.last_getheaders_at > @headers_response_time_s do
      Peer.push(
        %{data | proto: %{proto | last_getheaders_at: t}},
        {:getheaders, %{locator: locator, hash_stop: <<0::256>>}}
      )
    else
      data
    end
  end

  @doc "Core `PeerManagerImpl::ProcessHeadersMessage`."
  def process_headers_message(%Data{proto: %Proto{} = proto} = data, []) do
    {:ok, %{data | proto: %{proto | headers_sync: nil, last_getheaders_at: nil}}}
  end

  def process_headers_message(%Data{} = data, headers) do
    count = length(headers)
    full = count == Message.max_headers_results()

    # Core: CheckHeadersPoW (HasValidProofOfWork + CheckHeadersAreContinuous)
    cond do
      not Enum.all?(headers, &Pow.check_proof_of_work(&1.hash, &1.bits, data.p.pow_limit)) ->
        Peer.misbehaving(data, "header with invalid proof of work")

      not continuous?(headers) ->
        Peer.misbehaving(data, "non-continuous headers sequence")

      true ->
        {already_validated, headers, data} = continuation_of_low_work_sync(data, headers, full)
        have_headers_sync = data.proto.headers_sync != nil

        if headers == [],
          do: {:ok, data},
          else:
            process_connected_headers(data, headers, count, already_validated, have_headers_sync)
    end
  end

  @doc "Core `GetAntiDoSWorkThreshold`, on the active tip (genesis until blocks connect)."
  def anti_dos_work_threshold(data),
    do: HeaderIndex.anti_dos_work_threshold(active_tip_header(data), data.p)

  @doc "Core `ConsiderEviction` (`CHAIN_SYNC_TIMEOUT`, `HEADERS_RESPONSE_TIME`)."
  def consider_eviction(
        {:ok,
         %Data{
           conn_type: ct,
           proto: %Proto{chain_sync: %{protect: false} = cs, sync_started: true} = proto
         } = data},
        t
      )
      when ct in [:outbound_full_relay, :block_relay] do
    idx = Headers.index(data.node.headers)
    tip = chain_sync_tip(data, idx)
    best = proto.best_known

    cond do
      best != nil and best.chain_work >= tip.chain_work ->
        cs = %{cs | timeout: nil, work_header: nil, sent_getheaders: false}
        {:ok, %{data | proto: %{proto | chain_sync: cs}}}

      cs.timeout == nil or
          (cs.work_header != nil and best != nil and
             best.chain_work >= cs.work_header.chain_work) ->
        cs = %{cs | timeout: t + @chain_sync_timeout_s, work_header: tip, sent_getheaders: false}
        {:ok, %{data | proto: %{proto | chain_sync: cs}}}

      t > cs.timeout and cs.sent_getheaders ->
        Logger.info(
          "outbound peer has old chain, best known block = " <>
            if(best, do: Base.encode16(best.hash, case: :lower), else: "<none>")
        )

        {:stop, {:shutdown, :chain_sync_timeout}, data}

      t > cs.timeout ->
        # Core: GetLocator(m_work_header->pprev), through the getheaders throttle.
        start = HeaderIndex.prev(idx, cs.work_header) || cs.work_header
        data = maybe_send_getheaders(data, HeaderIndex.locator(idx, start))
        cs = %{cs | sent_getheaders: true, timeout: t + @headers_response_time_s}
        {:ok, Data.update_proto(data, &%{&1 | chain_sync: cs})}

      true ->
        {:ok, data}
    end
  end

  def consider_eviction(result, _t), do: result

  # --- internal helpers -------------------------------------------------------

  defp other_preferred_peer?(%Data{node: %{block_download: bd}}) when bd != nil,
    do: BlockDownload.other_preferred?(bd, self())

  defp other_preferred_peer?(_data), do: false

  defp process_connected_headers(data, headers, count, already_validated, have_headers_sync) do
    idx = Headers.index(data.node.headers)

    case HeaderIndex.lookup(idx, hd(headers).prev_hash) do
      nil ->
        # Core: HandleUnconnectingHeaders
        {:ok, maybe_send_getheaders(data, HeaderIndex.locator(idx, HeaderIndex.best(idx)))}

      chain_start ->
        data = Data.update_proto(data, &%{&1 | last_getheaders_at: nil})
        last_received = HeaderIndex.lookup(idx, List.last(headers).hash)

        already_validated =
          already_validated or
            (last_received != nil and
               HeaderIndex.ancestor_of?(idx, last_received, HeaderIndex.best(idx)))

        case not already_validated &&
               try_low_work_headers_sync(data, idx, chain_start, headers, count) do
          {:handled, data} -> {:ok, data}
          _ -> accept_headers(data, headers, count, have_headers_sync)
        end
    end
  end

  defp accept_headers(data, headers, count, have_headers_sync) do
    case Headers.process_headers(data.node.headers, headers,
           min_pow_checked: true,
           now: Peer.now(data)
         ) do
      {:ok, last} ->
        data =
          Data.update_proto(data, &%{&1 | best_known: Peer.better(&1.best_known, last)})
          |> maybe_update_best_known_block(last)
          |> maybe_protect()

        data =
          if count == Message.max_headers_results() and not have_headers_sync,
            do:
              maybe_send_getheaders(
                data,
                HeaderIndex.locator(Headers.index(data.node.headers), last)
              ),
            else: data

        {:ok, data}

      {:error, {result, reason}, _last} ->
        BlockSync.maybe_punish_for_block(data, result, "invalid header received: #{reason}")
    end
  end

  defp maybe_update_best_known_block(data, last) do
    have_block? =
      case data.node[:chain_state] do
        nil ->
          false

        cs ->
          case is_atom(cs) && ChainState.view(cs) do
            nil -> false
            v -> MapSet.member?(ChainState.view_have_many(v, [last.hash]), last.hash)
          end
      end

    if have_block?,
      do:
        Data.update_proto(data, &%{&1 | best_known_block: max(&1.best_known_block, last.height)}),
      else: data
  end

  # Core: IsContinuationOfLowWorkHeadersSync
  defp continuation_of_low_work_sync(%Data{proto: %Proto{headers_sync: nil}} = data, headers, _),
    do: {false, headers, data}

  defp continuation_of_low_work_sync(%Data{proto: %Proto{headers_sync: hs}} = data, headers, full) do
    {res, hs} = HeadersSync.process_next_headers(hs, headers, full)

    data =
      if res.success, do: Data.update_proto(data, &%{&1 | last_getheaders_at: nil}), else: data

    data =
      if res.request_more,
        do: maybe_send_getheaders(data, HeadersSync.next_headers_request_locator(hs), true),
        else: data

    next_hs = if HeadersSync.state(hs) == :final, do: nil, else: hs
    data = Data.update_proto(data, &%{&1 | headers_sync: next_hs})

    if res.success, do: {true, res.pow_validated_headers, data}, else: {false, headers, data}
  end

  # Core: TryLowWorkHeadersSync
  defp try_low_work_headers_sync(data, idx, chain_start, headers, count) do
    claimed = Enum.reduce(headers, 0, &(&2 + Pow.bits_proof(&1.bits)))
    threshold = anti_dos_work_threshold(data)

    if chain_start.chain_work + claimed < threshold do
      if count == Message.max_headers_results() do
        hs =
          HeadersSync.new(
            data.p,
            chain_start,
            HeaderIndex.median_time_past(idx, chain_start),
            HeaderIndex.locator(idx, chain_start),
            threshold,
            Peer.now(data)
          )

        {_validated, _headers, data} =
          continuation_of_low_work_sync(
            Data.update_proto(data, &%{&1 | headers_sync: hs}),
            headers,
            true
          )

        {:handled, data}
      else
        # "Ignoring low-work chain"
        {:handled, data}
      end
    else
      :not_low_work
    end
  end

  # The active tip's header entry; nil without a chain state.
  defp active_tip_header(data) do
    if cs = data.node[:chain_state] do
      t =
        if v = is_atom(cs) && ChainState.view(cs),
          do: ChainState.view_tip(v),
          else: ChainState.tip(cs)

      HeaderIndex.lookup(Headers.index(data.node.headers), t.hash)
    end
  end

  # The active tip, genesis without a chain state.
  defp chain_sync_tip(data, idx),
    do: active_tip_header(data) || HeaderIndex.ancestor(idx, HeaderIndex.best(idx), 0)

  # Core: UpdatePeerStateForReceivedHeaders. Up to
  # MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT (4) outbound full-relay
  # peers with a chain at least as good as our tip are exempt from
  # ConsiderEviction; block-relay peers never are.
  defp maybe_protect(
         %Data{
           conn_type: :outbound_full_relay,
           proto: %Proto{chain_sync: %{protect: false} = cs, best_known: b} = proto
         } = data
       )
       when b != nil do
    tip = chain_sync_tip(data, Headers.index(data.node.headers))

    if b.chain_work >= tip.chain_work and SyncState.try_protect(data.node.sync, self()),
      do: %{data | proto: %{proto | chain_sync: %{cs | protect: true}}},
      else: data
  end

  defp maybe_protect(data), do: data

  defp continuous?([_]), do: true
  defp continuous?([a, b | rest]), do: b.prev_hash == a.hash and continuous?([b | rest])
end
