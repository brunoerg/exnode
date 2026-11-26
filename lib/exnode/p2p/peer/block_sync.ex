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
  alias Exnode.P2P.Peer.{Data, HeadersHandler}
  alias Exnode.P2P.Peer.Data.Proto

  @max_partials 16
  @max_cmpct_seen 16
  @partial_timeout_s 60

  @doc "Core `SendMessages` block download request pass."
  def maybe_request_blocks(%Data{node: %{block_download: bd}, proto: %Proto{} = proto} = data)
      when bd != nil do
    v = data.handshake.version
    serves = v != nil and (v.services &&& Message.service(:network)) != 0

    if serves do
      best = proto.best_known && proto.best_known.hash
      # (IBD matters only for a non-preferred peer; skip the lookup otherwise.)
      opts = [
        preferred: not data.inbound,
        ibd: data.inbound and Peer.initial_block_download?(data)
      ]

      case BlockDownload.request(bd, self(), best, opts) do
        [] ->
          data

        hashes ->
          Peer.push(data, {:getdata, Enum.map(hashes, &%{type: :block, witness: true, hash: &1})})
      end
    else
      data
    end
  end

  def maybe_request_blocks(data), do: data

  @doc "Core `ProcessMessage` `BLOCK`: checks mutation against known parent before processing."
  def received_block(%Data{} = data, b) do
    idx = Headers.index(data.node.headers)

    case HeaderIndex.lookup(idx, b.header.prev_hash) do
      nil ->
        process_block(data, b)

      prev ->
        # DeploymentActiveAfter(prev_block, SEGWIT)
        if CompactBlock.mutated?(b, prev.height + 1 >= data.p.segwit_height),
          do: Peer.misbehaving(data, "mutated block"),
          else: process_block(data, b)
    end
  end

  @doc """
  Core `ProcessBlock` + `MaybePunishNodeForBlock`. `rebuilt` marks a block
  rebuilt from a compact block (`force_processing = true`).
  """
  def process_block(%Data{} = data, %Block{} = b, rebuilt \\ false) do
    data = Data.update_proto(data, &%{&1 | partials: Map.delete(&1.partials, b.header.hash)})

    in_flight =
      data.node[:block_download] != nil and
        if(rebuilt,
          do:
            BlockDownload.rebuilt(
              data.node.block_download,
              self(),
              b.header.hash,
              byte_size(b.raw || <<>>)
            ),
          else:
            BlockDownload.received(
              data.node.block_download,
              self(),
              b.header.hash,
              byte_size(b.raw || <<>>)
            )
        )

    requested = rebuilt or in_flight
    ibd = Peer.initial_block_download?(data)

    submit = fn cs ->
      case ChainState.precheck_block(cs, b.header, requested) do
        :check ->
          ChainState.submit_block(cs, b,
            checked: ChainState.check_block(b, data.node.params),
            defer: ibd,
            requested: requested,
            source: self()
          )

        reply ->
          reply
      end
    end

    outcome = data.node[:chain_state] && submit.(data.node.chain_state)

    if data.node[:block_download] != nil,
      do:
        BlockDownload.checked(
          data.node.block_download,
          self(),
          b.header.hash,
          outcome in [nil, {:ok, :connected}, {:ok, :stored}, {:ok, :duplicate}]
        )

    data =
      if rebuilt and outcome == {:ok, :stored},
        do:
          Data.update_proto(data, fn proto ->
            %{
              proto
              | rebuilt_deferred:
                  Enum.take([b.header.hash | proto.rebuilt_deferred], @max_partials)
            }
          end),
        else: data

    case outcome do
      {:error, {result, reason}} ->
        maybe_punish_for_block(data, result, "invalid block: #{reason}", rebuilt)

      reply ->
        data =
          if reply in [{:ok, :connected}, {:ok, :stored}],
            do: Peer.report_stats(data, %{last_block_time: Peer.now(data)}),
            else: data

        idx = Headers.index(data.node.headers)
        e = HeaderIndex.lookup(idx, b.header.hash)

        data =
          if e,
            do:
              Data.update_proto(data, fn proto ->
                %{
                  proto
                  | best_known: Peer.better(proto.best_known, e),
                    best_known_block: max(proto.best_known_block, e.height)
                }
              end),
            else: data

        # BIP152: a peer that delivers a new block becomes high-bandwidth.
        if reply == {:ok, :connected} and data.proto.provides_cmpct and
             data.node[:high_bandwidth] != nil and not Peer.initial_block_download?(data),
           do: HighBandwidth.select(data.node.high_bandwidth, self(), data.inbound)

        {:ok, maybe_request_blocks(data)}
    end
  end

  @doc "Core `ProcessMessage` `CMPCTBLOCK` (receive side)."
  def compact_block(%Data{proto: %Proto{provides_cmpct: false}} = data, _payload),
    do: {:ok, data}

  def compact_block(%Data{} = data, payload) do
    case CompactBlock.decode(payload) do
      {:error, why} -> Peer.dropped(data, "cmpctblock", why)
      {:ok, c} -> compact_block_decoded(data, c)
    end
  end

  @doc "Core `ProcessMessage` `BLOCKTXN` -> `ProcessCompactBlockTxns`."
  def block_txn(%Data{proto: %Proto{} = proto} = data, payload) do
    case CompactBlock.decode_blocktxn(payload) do
      {:error, why} ->
        Peer.dropped(data, "blocktxn", why)

      {:ok, hash, txs} ->
        case Map.pop(proto.partials, hash) do
          {nil, _} ->
            {:ok, data}

          {%{partial: partial}, rest} ->
            finish_rebuild(%{data | proto: %{proto | partials: rest}}, hash, partial, txs)
        end
    end
  end

  @doc "Expires timed-out or already-received partial compact block reconstructions."
  def expire_partials(%Data{proto: %Proto{partials: ps}} = data, _t) when map_size(ps) == 0,
    do: data

  def expire_partials(%Data{proto: %Proto{partials: ps}} = data, t) do
    have = ChainState.view_have_many(ChainState.view(data.node.chain_state), Map.keys(ps))

    Enum.reduce(ps, data, fn {hash, p}, acc ->
      cond do
        MapSet.member?(have, hash) ->
          if bd = acc.node[:block_download], do: BlockDownload.cancel(bd, self(), hash)
          Data.update_proto(acc, &%{&1 | partials: Map.delete(&1.partials, hash)})

        t - p.started >= @partial_timeout_s ->
          acc
          |> Data.update_proto(&%{&1 | partials: Map.delete(&1.partials, hash)})
          |> request_full_block(hash)

        true ->
          acc
      end
    end)
  end

  @doc "Core `MaybePunishNodeForBlock`."
  def maybe_punish_for_block(data, result, msg, via_compact \\ false) do
    case result do
      r when r in [:crash, :quarantined] ->
        {:ok, data}

      r when r in [:consensus, :mutated] ->
        if via_compact, do: {:ok, data}, else: Peer.misbehaving(data, msg)

      r when r in [:invalid_header, :invalid_prev, :missing_prev] ->
        Peer.misbehaving(data, msg)

      :cached_invalid ->
        if data.inbound or via_compact, do: {:ok, data}, else: Peer.misbehaving(data, msg)

      _ ->
        {:ok, data}
    end
  end

  # --- internal helpers -------------------------------------------------------

  defp compact_block_decoded(data, c) do
    idx = Headers.index(data.node.headers)
    prev = HeaderIndex.lookup(idx, c.header.prev_hash)

    cond do
      prev == nil ->
        {:ok,
         if(Peer.initial_block_download?(data),
           do: data,
           else:
             HeadersHandler.maybe_send_getheaders(
               data,
               HeaderIndex.locator(idx, HeaderIndex.best(idx))
             )
         )}

      prev.chain_work + Pow.bits_proof(c.header.bits) <
          HeadersHandler.anti_dos_work_threshold(data) ->
        {:ok, data}

      true ->
        case Headers.process_headers(data.node.headers, [c.header],
               min_pow_checked: true,
               now: Peer.now(data)
             ) do
          {:error, {result, reason}, _} ->
            maybe_punish_for_block(data, result, "invalid header via cmpctblock: #{reason}", true)

          {:error, {result, reason}} ->
            maybe_punish_for_block(data, result, "invalid header via cmpctblock: #{reason}", true)

          {:ok, _} ->
            compact_block_header_ok(data, c)
        end
    end
  end

  defp compact_block_header_ok(data, c) do
    hash = c.header.hash
    idx = Headers.index(data.node.headers)
    e = HeaderIndex.lookup(idx, hash)
    view = ChainState.view(data.node.chain_state)
    tip = ChainState.view_tip(view)
    tip_e = HeaderIndex.lookup(idx, tip.hash)

    data =
      Data.update_proto(data, fn proto ->
        %{
          proto
          | best_known: Peer.better(proto.best_known, e),
            best_known_block: max(proto.best_known_block, e.height)
        }
      end)

    proto = data.proto

    cond do
      MapSet.member?(ChainState.view_have_many(view, [hash]), hash) ->
        {:ok, data}

      Map.has_key?(proto.partials, hash) or hash in proto.cmpct_seen ->
        {:ok, data}

      true ->
        {owner, already_in_flight, checking} = block_in_flight(data, hash)
        from_this_peer = owner == self()

        cond do
          checking ->
            {:ok, data}

          not from_this_peer and not proto.hb_selected ->
            {:ok, data}

          e.chain_work <= tip_e.chain_work ->
            {:ok, if(from_this_peer, do: request_full_block(data, hash), else: data)}

          not already_in_flight and not can_direct_fetch?(data, tip_e) ->
            {:ok, data}

          e.height > tip.height + 2 ->
            {:ok, maybe_request_blocks(data)}

          map_size(proto.partials) >= @max_partials ->
            {:ok, request_full_block(data, hash)}

          true ->
            data =
              Data.update_proto(data, fn p ->
                %{p | cmpct_seen: Enum.take([hash | p.cmpct_seen], @max_cmpct_seen)}
              end)

            rebuild(data, c)
        end
    end
  end

  defp block_in_flight(%Data{node: %{block_download: bd}}, hash) when bd != nil do
    case BlockDownload.in_flight_state(bd, hash) do
      nil -> {nil, false, false}
      {:requested, peer} -> {peer, true, false}
      {:checking, peer} -> {peer, true, true}
    end
  end

  defp block_in_flight(_data, _hash), do: {nil, false, false}

  defp can_direct_fetch?(data, tip_e),
    do: tip_e.time > Peer.now(data) - data.p.pow_target_spacing * 20

  defp rebuild(data, c) do
    mp = data.node[:mempool]

    match = fn keys, ids ->
      if mp, do: Mempool.match_short_ids(mp, keys, ids), else: %{}
    end

    case CompactBlock.init(c, match) do
      :invalid ->
        Peer.misbehaving(data, "invalid compact block")

      :failed ->
        {:ok, request_full_block(data, c.header.hash)}

      {:ok, partial} ->
        case CompactBlock.missing(partial) do
          [] ->
            finish_rebuild(data, c.header.hash, partial, [])

          gaps ->
            mark_in_flight(data, c.header.hash)

            data =
              data
              |> Peer.push({:getblocktxn, CompactBlock.encode_getblocktxn(c.header.hash, gaps)})
              |> Data.update_proto(fn p ->
                %{
                  p
                  | partials:
                      Map.put(p.partials, c.header.hash, %{
                        partial: partial,
                        started: Peer.now(data)
                      })
                }
              end)

            {:ok, data}
        end
    end
  end

  defp finish_rebuild(data, hash, partial, txs) do
    idx = Headers.index(data.node.headers)
    prev = HeaderIndex.lookup(idx, partial.header.prev_hash)
    segwit? = prev == nil or prev.height + 1 >= data.p.segwit_height

    case CompactBlock.fill(partial, txs, segwit?) do
      {:ok, b} ->
        Logger.info(
          "compact block #{Hash.to_hex(hash)} rebuilt: #{length(b.txs)} txs, #{length(txs)} requested"
        )

        process_block(data, b, true)

      :invalid ->
        Peer.misbehaving(data, "invalid compact block txns")

      :failed ->
        {:ok, request_full_block(data, hash)}
    end
  end

  defp request_full_block(data, hash) do
    if mark_in_flight(data, hash),
      do: Peer.push(data, {:getdata, [%{type: :block, witness: true, hash: hash}]}),
      else: data
  end

  defp mark_in_flight(data, hash) do
    if bd = data.node[:block_download], do: BlockDownload.mark(bd, self(), hash), else: true
  end
end
