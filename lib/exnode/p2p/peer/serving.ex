defmodule Exnode.P2P.Peer.Serving do
  @moduledoc """
  Per-peer serving of `getheaders`, `getdata` (batched tx lookups + one block
  item per pass with send-buffer backpressure), `getblocktxn`, and new-tip
  block announcements (`cmpctblock`, `headers`, or `inv`).
  """

  alias Exnode.Archive
  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Codec.{Block, Header, Tx}
  alias Exnode.P2P.{BlockServing, CompactBlock, Message, Peer, TxRelay}

  @max_cmpctblock_depth 5
  @max_blocktxn_depth 10
  @max_blocks_to_announce 8
  @node_network_limited_min_blocks 288
  @getdata_tx_per_pass 1_000

  @doc "Core `ProcessMessage` `GETHEADERS`."
  def serve_getheaders(st, %{locator: loc, hash_stop: stop}) do
    if length(loc) > Message.max_locator_sz() do
      {:stop, {:shutdown, :locator_too_large}, st}
    else
      idx = Headers.index(st.node.headers)
      tip = active_tip_entry(st, idx)

      on_active = fn e ->
        e.height <= tip.height and HeaderIndex.ancestor(idx, tip, e.height).hash == e.hash
      end

      fork =
        Enum.find_value(loc, fn h ->
          e = HeaderIndex.lookup(idx, h)
          e && on_active.(e) && e
        end) || HeaderIndex.ancestor(idx, tip, 0)

      last = min(tip.height, fork.height + Message.max_headers_results())

      headers =
        if last <= fork.height do
          []
        else
          (fork.height + 1)..last
          |> Enum.map(&HeaderIndex.ancestor(idx, tip, &1))
          |> Enum.reduce_while([], fn e, acc ->
            acc = [decode_header(e.raw) | acc]
            if e.hash == stop, do: {:halt, acc}, else: {:cont, acc}
          end)
          |> Enum.reverse()
        end

      {:ok, Peer.push(st, {:headers, headers})}
    end
  end

  @doc "Core `ProcessGetData`: serves leading tx items, then at most one block item."
  def process_getdata(st) do
    {tx_items, q} = take_tx_items(st.getdata_queue, [], 0)
    st = serve_txs(%{st | getdata_queue: q}, tx_items)

    result =
      case :queue.out(st.getdata_queue) do
        _ when st.paused_since != nil ->
          {:ok, st}

        {{:value, %{type: t} = item}, q} when t in [:block, :cmpct_block] ->
          serve_block(%{st | getdata_queue: q}, item)

        {{:value, %{type: t}}, q} when t not in [:tx, :wtx, :block, :cmpct_block] ->
          {:ok, %{st | getdata_queue: q}}

        _ ->
          {:ok, st}
      end

    case result do
      {:ok, st} ->
        if Peer.getdata_pending?(st) and not Peer.paused?(st), do: send(self(), :continue_getdata)
        {:ok, st}

      stop ->
        stop
    end
  end

  @doc "Core `ProcessGetBlockTxn`."
  def serve_getblocktxn(st, payload) do
    case CompactBlock.decode_getblocktxn(payload) do
      {:error, why} ->
        Peer.dropped(st, "getblocktxn", why)

      {:ok, _hash, []} ->
        {:stop, {:shutdown, :empty_getblocktxn}, st}

      {:ok, hash, indexes} ->
        tip_h = ChainState.view_tip(ChainState.view(st.node.chain_state)).height

        case active_block(st, hash) do
          :notfound ->
            {:ok, st}

          {:ok, h, raw} when tip_h - h >= @max_blocktxn_depth ->
            {:ok, Peer.push(st, {:block, raw})}

          {:ok, _h, raw} ->
            {:ok, ranges} = Block.tx_ranges(raw)

            if List.last(indexes) >= tuple_size(ranges) do
              Peer.misbehaving(st, "getblocktxn with out-of-bounds tx indices")
            else
              txs = select_txs(raw, ranges, indexes)
              {:ok, Peer.push(st, {:blocktxn, CompactBlock.encode_blocktxn_raw(hash, txs)})}
            end
        end
    end
  end

  @doc "Slices serialized transactions at `indexes` from `raw` using `ranges`."
  def select_txs(raw, ranges, indexes) do
    Enum.map(indexes, fn i ->
      {offset, len} = elem(ranges, i)
      binary_part(raw, offset, len)
    end)
  end

  @doc "Core `SendMessages` block announcements."
  def maybe_announce_blocks(st) do
    view = st.node[:chain_state] && ChainState.view(st.node.chain_state)
    tip = view && ChainState.view_tip(view)

    cond do
      not st.verack_received or tip == nil or tip.hash == st.announced ->
        st

      st.announced == nil ->
        %{st | announced: tip.hash}

      Peer.initial_block_download?(st) ->
        %{st | announced: tip.hash}

      true ->
        announce_new_blocks(st, tip)
    end
  end

  # --- internal helpers -------------------------------------------------------

  defp active_tip_entry(st, idx) do
    tip = ChainState.view_tip(ChainState.view(st.node.chain_state))
    HeaderIndex.lookup(idx, tip.hash)
  end

  defp active_block_ref(st, hash) do
    reader = ChainState.view_reader(ChainState.view(st.node.chain_state))

    with id when id != nil <- Archive.block_id(reader, hash),
         true <- Archive.on_chain?(reader, id),
         true <- Archive.witness_pruned(reader) < 0 or not Archive.witness_pruned?(reader, id) do
      e = HeaderIndex.lookup(Headers.index(st.node.headers), hash)
      {:ok, reader, id, e.height}
    else
      _ -> :notfound
    end
  end

  defp active_block(st, hash) do
    with {:ok, reader, id, height} <- active_block_ref(st, hash),
         {:ok, {:block, raw}} <-
           cached_block(st, reader, id, hash, :witness, near_tip?(st, height)) do
      {:ok, height, raw}
    else
      _ -> :notfound
    end
  end

  defp cached_block(st, reader, id, hash, format, priority) do
    BlockServing.get(
      st.node[:block_serving],
      reader,
      id,
      hash,
      format,
      Map.get(st.node, :decode_block, &Block.decode_exact/1),
      priority
    )
  end

  defp near_tip?(st, height),
    do:
      ChainState.view_tip(ChainState.view(st.node.chain_state)).height - height <
        @max_blocktxn_depth

  defp take_tx_items(q, acc, n) when n >= @getdata_tx_per_pass, do: {Enum.reverse(acc), q}

  defp take_tx_items(q, acc, n) do
    case :queue.peek(q) do
      {:value, %{type: t} = item} when t in [:tx, :wtx] ->
        take_tx_items(:queue.drop(q), [item | acc], n + 1)

      _ ->
        {Enum.reverse(acc), q}
    end
  end

  defp serve_txs(st, []), do: st

  defp serve_txs(st, tx_items) do
    if st.node[:tx_relay] != nil and st.conn_type != :block_relay and st.version.relay do
      {txs, missing} = TxRelay.lookup(st.node.tx_relay, tx_items)
      {st, rest, notfound} = push_txs(st, tx_items, txs, MapSet.new(missing), [])
      st = if notfound != [], do: Peer.push(st, {:notfound, notfound}), else: st
      %{st | getdata_queue: :queue.join(:queue.from_list(rest), st.getdata_queue)}
    else
      st
    end
  end

  defp push_txs(st, [], _txs, _missing, nf), do: {st, [], Enum.reverse(nf)}

  defp push_txs(st, items, _txs, _missing, nf) when st.paused_since != nil,
    do: {st, items, Enum.reverse(nf)}

  defp push_txs(st, [i | rest], txs, missing, nf) do
    if MapSet.member?(missing, i) do
      push_txs(st, rest, txs, missing, [i | nf])
    else
      [tx | txs] = txs
      push_txs(Peer.push(st, {:tx, tx_bytes(tx, i)}), rest, txs, missing, nf)
    end
  end

  defp tx_bytes(tx, %{type: :tx, witness: false}),
    do: IO.iodata_to_binary(Tx.encode(tx, witness: false))

  defp tx_bytes(tx, _item), do: tx.raw

  defp serve_block(st, item) do
    tip_h = ChainState.view_tip(ChainState.view(st.node.chain_state)).height
    limited = Bitwise.band(st.node.services, Message.service(:network)) == 0

    case active_block_ref(st, item.hash) do
      :notfound ->
        {:ok, Peer.push(st, {:notfound, [item]})}

      {:ok, _, _, h} when limited and tip_h - h > @node_network_limited_min_blocks + 2 ->
        {:stop, {:shutdown, :request_below_network_limited_threshold}, st}

      {:ok, reader, id, h} ->
        format =
          cond do
            item.type == :cmpct_block and tip_h - h < @max_cmpctblock_depth -> :compact
            item.type == :cmpct_block or item.witness -> :witness
            true -> :stripped
          end

        case cached_block(st, reader, id, item.hash, format, tip_h - h < @max_blocktxn_depth) do
          {:ok, msg} -> {:ok, Peer.push(st, msg)}
          :notfound -> {:ok, Peer.push(st, {:notfound, [item]})}
        end
    end
  end

  defp announce_new_blocks(st, tip) do
    idx = Headers.index(st.node.headers)
    tip_e = HeaderIndex.lookup(idx, tip.hash)
    prev = HeaderIndex.lookup(idx, st.announced)

    known =
      [st.best_known, prev]
      |> Enum.filter(
        &(&1 != nil and &1.height <= tip_e.height and
            HeaderIndex.ancestor(idx, tip_e, &1.height).hash == &1.hash)
      )
      |> Enum.max_by(& &1.height, fn -> nil end)

    new =
      case known do
        nil -> nil
        k when k.height >= tip_e.height -> []
        k -> for h <- (k.height + 1)..tip_e.height, do: HeaderIndex.ancestor(idx, tip_e, h)
      end

    st = %{st | announced: tip.hash}

    cond do
      new == [] ->
        st

      st.hb_requested and new != nil and length(new) == 1 ->
        with {:ok, reader, id, _} <- active_block_ref(st, tip.hash),
             {:ok, msg} <- cached_block(st, reader, id, tip.hash, :compact, true) do
          Peer.push(st, msg)
        else
          _ -> Peer.push(st, {:inv, [%{type: :block, hash: tip.hash}]})
        end

      st.prefers_headers and new != nil and length(new) <= @max_blocks_to_announce ->
        Peer.push(st, {:headers, Enum.map(new, &decode_header(&1.raw))})

      true ->
        Peer.push(st, {:inv, [%{type: :block, hash: tip.hash}]})
    end
  end

  defp decode_header(raw) do
    {h, ""} = Header.decode(raw)
    h
  end
end
