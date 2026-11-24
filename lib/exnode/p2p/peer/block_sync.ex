defmodule Exnode.P2P.Peer.BlockSync do
  @moduledoc """
  Per-peer block download requests, block reception (`ProcessBlock`), BIP152
  compact block / `blocktxn` reconstruction, partial reconstruction timeouts,
  and block invalidation punishment (`MaybePunishNodeForBlock`).
  """

  import Bitwise
  require Logger

  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Codec.Block
  alias Exnode.Consensus.Pow
  alias Exnode.Crypto.Hash
  alias Exnode.Mempool
  alias Exnode.P2P.{BlockDownload, CompactBlock, HighBandwidth, Message, Peer}
  alias Exnode.P2P.Peer.HeadersHandler

  @max_partials 16
  @max_cmpct_seen 16
  @partial_timeout_s 60

  @doc "Core `SendMessages` block download request pass."
  def maybe_request_blocks(%{node: %{block_download: bd}} = st) when bd != nil do
    serves = st.version && (st.version.services &&& Message.service(:network)) != 0

    if Peer.handshake_done?(st) and serves do
      best = st.best_known && st.best_known.hash
      # (IBD matters only for a non-preferred peer; skip the lookup otherwise.)
      opts = [preferred: not st.inbound, ibd: st.inbound and Peer.initial_block_download?(st)]

      case BlockDownload.request(bd, self(), best, opts) do
        [] ->
          st

        hashes ->
          Peer.push(st, {:getdata, Enum.map(hashes, &%{type: :block, witness: true, hash: &1})})
      end
    else
      st
    end
  end

  def maybe_request_blocks(st), do: st

  @doc "Core `ProcessMessage` `BLOCK`: checks mutation against known parent before processing."
  def received_block(st, b) do
    idx = Headers.index(st.node.headers)

    case HeaderIndex.lookup(idx, b.header.prev_hash) do
      nil ->
        process_block(st, b)

      prev ->
        # DeploymentActiveAfter(prev_block, SEGWIT)
        if CompactBlock.mutated?(b, prev.height + 1 >= st.p.segwit_height),
          do: Peer.misbehaving(st, "mutated block"),
          else: process_block(st, b)
    end
  end

  @doc """
  Core `ProcessBlock` + `MaybePunishNodeForBlock`. `rebuilt` marks a block
  rebuilt from a compact block (`force_processing = true`).
  """
  def process_block(st, %Block{} = b, rebuilt \\ false) do
    st = %{st | partials: Map.delete(st.partials, b.header.hash)}

    in_flight =
      st.node[:block_download] != nil and
        if(rebuilt,
          do:
            BlockDownload.rebuilt(
              st.node.block_download,
              self(),
              b.header.hash,
              byte_size(b.raw || <<>>)
            ),
          else:
            BlockDownload.received(
              st.node.block_download,
              self(),
              b.header.hash,
              byte_size(b.raw || <<>>)
            )
        )

    requested = rebuilt or in_flight
    ibd = Peer.initial_block_download?(st)

    submit = fn cs ->
      case ChainState.precheck_block(cs, b.header, requested) do
        :check ->
          ChainState.submit_block(cs, b,
            checked: ChainState.check_block(b, st.node.params),
            defer: ibd,
            requested: requested,
            source: self()
          )

        reply ->
          reply
      end
    end

    outcome = st.node[:chain_state] && submit.(st.node.chain_state)

    if st.node[:block_download] != nil,
      do:
        BlockDownload.checked(
          st.node.block_download,
          self(),
          b.header.hash,
          outcome in [nil, {:ok, :connected}, {:ok, :stored}, {:ok, :duplicate}]
        )

    st =
      if rebuilt and outcome == {:ok, :stored},
        do: %{
          st
          | rebuilt_deferred: Enum.take([b.header.hash | st.rebuilt_deferred], @max_partials)
        },
        else: st

    case outcome do
      {:error, {result, reason}} ->
        maybe_punish_for_block(st, result, "invalid block: #{reason}", rebuilt)

      reply ->
        st =
          if reply in [{:ok, :connected}, {:ok, :stored}],
            do: Peer.report_stats(st, %{last_block_time: Peer.now(st)}),
            else: st

        idx = Headers.index(st.node.headers)
        e = HeaderIndex.lookup(idx, b.header.hash)

        st =
          if e,
            do: %{
              st
              | best_known: Peer.better(st.best_known, e),
                best_known_block: max(st.best_known_block, e.height)
            },
            else: st

        # BIP152: a peer that delivers a new block becomes high-bandwidth.
        if reply == {:ok, :connected} and st.provides_cmpct and st.node[:high_bandwidth] != nil and
             not Peer.initial_block_download?(st),
           do: HighBandwidth.select(st.node.high_bandwidth, self(), st.inbound)

        {:ok, maybe_request_blocks(st)}
    end
  end

  @doc "Core `ProcessMessage` `CMPCTBLOCK` (receive side)."
  def compact_block(%{provides_cmpct: false} = st, _payload), do: {:ok, st}

  def compact_block(st, payload) do
    case CompactBlock.decode(payload) do
      {:error, why} -> Peer.dropped(st, "cmpctblock", why)
      {:ok, c} -> compact_block_decoded(st, c)
    end
  end

  @doc "Core `ProcessMessage` `BLOCKTXN` -> `ProcessCompactBlockTxns`."
  def block_txn(st, payload) do
    case CompactBlock.decode_blocktxn(payload) do
      {:error, why} ->
        Peer.dropped(st, "blocktxn", why)

      {:ok, hash, txs} ->
        case Map.pop(st.partials, hash) do
          {nil, _} ->
            {:ok, st}

          {%{partial: partial}, rest} ->
            finish_rebuild(%{st | partials: rest}, hash, partial, txs)
        end
    end
  end

  @doc "Expires timed-out or already-received partial compact block reconstructions."
  def expire_partials(%{partials: ps} = st, _t) when map_size(ps) == 0, do: st

  def expire_partials(st, t) do
    have = ChainState.view_have_many(ChainState.view(st.node.chain_state), Map.keys(st.partials))

    Enum.reduce(st.partials, st, fn {hash, p}, acc ->
      cond do
        MapSet.member?(have, hash) ->
          if bd = acc.node[:block_download], do: BlockDownload.cancel(bd, self(), hash)
          %{acc | partials: Map.delete(acc.partials, hash)}

        t - p.started >= @partial_timeout_s ->
          request_full_block(%{acc | partials: Map.delete(acc.partials, hash)}, hash)

        true ->
          acc
      end
    end)
  end

  @doc "Core `MaybePunishNodeForBlock`."
  def maybe_punish_for_block(st, result, msg, via_compact \\ false) do
    case result do
      r when r in [:crash, :quarantined] ->
        {:ok, st}

      r when r in [:consensus, :mutated] ->
        if via_compact, do: {:ok, st}, else: Peer.misbehaving(st, msg)

      r when r in [:invalid_header, :invalid_prev, :missing_prev] ->
        Peer.misbehaving(st, msg)

      :cached_invalid ->
        if st.inbound or via_compact, do: {:ok, st}, else: Peer.misbehaving(st, msg)

      _ ->
        {:ok, st}
    end
  end

  # --- internal helpers -------------------------------------------------------

  defp compact_block_decoded(st, c) do
    idx = Headers.index(st.node.headers)
    prev = HeaderIndex.lookup(idx, c.header.prev_hash)

    cond do
      prev == nil ->
        {:ok,
         if(Peer.initial_block_download?(st),
           do: st,
           else:
             HeadersHandler.maybe_send_getheaders(
               st,
               HeaderIndex.locator(idx, HeaderIndex.best(idx))
             )
         )}

      prev.chain_work + Pow.bits_proof(c.header.bits) < HeadersHandler.anti_dos_work_threshold(st) ->
        {:ok, st}

      true ->
        case Headers.process_headers(st.node.headers, [c.header],
               min_pow_checked: true,
               now: Peer.now(st)
             ) do
          {:error, {result, reason}, _} ->
            maybe_punish_for_block(st, result, "invalid header via cmpctblock: #{reason}", true)

          {:error, {result, reason}} ->
            maybe_punish_for_block(st, result, "invalid header via cmpctblock: #{reason}", true)

          {:ok, _} ->
            compact_block_header_ok(st, c)
        end
    end
  end

  defp compact_block_header_ok(st, c) do
    hash = c.header.hash
    idx = Headers.index(st.node.headers)
    e = HeaderIndex.lookup(idx, hash)
    view = ChainState.view(st.node.chain_state)
    tip = ChainState.view_tip(view)
    tip_e = HeaderIndex.lookup(idx, tip.hash)

    st = %{
      st
      | best_known: Peer.better(st.best_known, e),
        best_known_block: max(st.best_known_block, e.height)
    }

    cond do
      MapSet.member?(ChainState.view_have_many(view, [hash]), hash) ->
        {:ok, st}

      Map.has_key?(st.partials, hash) or hash in st.cmpct_seen ->
        {:ok, st}

      true ->
        {owner, already_in_flight, checking} = block_in_flight(st, hash)
        from_this_peer = owner == self()

        cond do
          checking ->
            {:ok, st}

          not from_this_peer and not st.hb_selected ->
            {:ok, st}

          e.chain_work <= tip_e.chain_work ->
            {:ok, if(from_this_peer, do: request_full_block(st, hash), else: st)}

          not already_in_flight and not can_direct_fetch?(st, tip_e) ->
            {:ok, st}

          e.height > tip.height + 2 ->
            {:ok, maybe_request_blocks(st)}

          map_size(st.partials) >= @max_partials ->
            {:ok, request_full_block(st, hash)}

          true ->
            rebuild(%{st | cmpct_seen: Enum.take([hash | st.cmpct_seen], @max_cmpct_seen)}, c)
        end
    end
  end

  defp block_in_flight(%{node: %{block_download: bd}}, hash) when bd != nil do
    case BlockDownload.in_flight_state(bd, hash) do
      nil -> {nil, false, false}
      {:requested, peer} -> {peer, true, false}
      {:checking, peer} -> {peer, true, true}
    end
  end

  defp block_in_flight(_st, _hash), do: {nil, false, false}

  defp can_direct_fetch?(st, tip_e),
    do: tip_e.time > Peer.now(st) - st.p.pow_target_spacing * 20

  defp rebuild(st, c) do
    mp = st.node[:mempool]

    match = fn keys, ids ->
      if mp, do: Mempool.match_short_ids(mp, keys, ids), else: %{}
    end

    case CompactBlock.init(c, match) do
      :invalid ->
        Peer.misbehaving(st, "invalid compact block")

      :failed ->
        {:ok, request_full_block(st, c.header.hash)}

      {:ok, partial} ->
        case CompactBlock.missing(partial) do
          [] ->
            finish_rebuild(st, c.header.hash, partial, [])

          gaps ->
            mark_in_flight(st, c.header.hash)

            {:ok,
             %{
               Peer.push(st, {:getblocktxn, CompactBlock.encode_getblocktxn(c.header.hash, gaps)})
               | partials:
                   Map.put(st.partials, c.header.hash, %{partial: partial, started: Peer.now(st)})
             }}
        end
    end
  end

  defp finish_rebuild(st, hash, partial, txs) do
    idx = Headers.index(st.node.headers)
    prev = HeaderIndex.lookup(idx, partial.header.prev_hash)
    segwit? = prev == nil or prev.height + 1 >= st.p.segwit_height

    case CompactBlock.fill(partial, txs, segwit?) do
      {:ok, b} ->
        Logger.info(
          "compact block #{Hash.to_hex(hash)} rebuilt: #{length(b.txs)} txs, #{length(txs)} requested"
        )

        process_block(st, b, true)

      :invalid ->
        Peer.misbehaving(st, "invalid compact block txns")

      :failed ->
        {:ok, request_full_block(st, hash)}
    end
  end

  defp request_full_block(st, hash) do
    if mark_in_flight(st, hash),
      do: Peer.push(st, {:getdata, [%{type: :block, witness: true, hash: hash}]}),
      else: st
  end

  defp mark_in_flight(st, hash) do
    if bd = st.node[:block_download], do: BlockDownload.mark(bd, self(), hash), else: true
  end
end
