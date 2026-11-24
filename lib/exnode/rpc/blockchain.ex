defmodule Exnode.RPC.Blockchain do
  @moduledoc """
  Core v32.1 `rpc/blockchain.cpp` JSON-RPC methods.
  """
  alias Exnode.{Archive, Mempool}
  alias Exnode.Chain.HeaderIndex
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Codec.{Block, Header, Tx}
  alias Exnode.Consensus.Pow
  alias Exnode.RPC.{JSON, Methods, RawTx}
  import Exnode.RPC.JSON, only: [obj: 1, amount: 1, hash_hex: 1, hex: 1]

  @rpc_misc_error -1
  @rpc_invalid_address_or_key -5
  @rpc_invalid_parameter -8

  def getblockcount(_params, ctx), do: {:ok, Methods.tip(ctx).height}
  def getbestblockhash(_params, ctx), do: {:ok, hash_hex(Methods.tip(ctx).hash)}

  def getdifficulty(_params, ctx),
    do: {:ok, JSON.double(Methods.difficulty(Methods.tip_entry(ctx).bits))}

  def getblockhash(params, ctx) do
    h = Methods.arg(params, 0)
    t = Methods.tip_entry(ctx)

    if not is_integer(h) or h < 0 or h > t.height,
      do: {:error, @rpc_invalid_parameter, "Block height out of range"},
      else: {:ok, hash_hex(HeaderIndex.ancestor(Methods.idx(ctx), t, h).hash)}
  end

  # Core: getblockchaininfo
  def getblockchaininfo(_params, ctx) do
    idx = Methods.idx(ctx)
    t = Methods.tip_entry(ctx)
    p = ctx.params
    pruned = Map.get(ctx, :prune_witness, false)

    {:ok,
     obj(
       [
         {"chain", chain_name(p.network)},
         {"blocks", t.height},
         {"headers", HeaderIndex.best(idx).height},
         {"bestblockhash", hash_hex(t.hash)},
         {"bits", bits_hex(t.bits)},
         {"target", target_hex(t.bits, p)},
         {"difficulty", JSON.double(Methods.difficulty(t.bits))},
         {"time", t.time},
         {"mediantime", HeaderIndex.median_time_past(idx, t)},
         {"verificationprogress", JSON.double(verification_progress(ctx, t, idx))},
         {"initialblockdownload",
          ChainState.view_ibd?(ChainState.view(ctx.chain_state), idx, Methods.now(ctx), p)},
         {"chainwork", work_hex(t.chain_work)},
         {"size_on_disk", 0},
         {"pruned", pruned}
       ] ++
         if(p.network == :signet, do: [{"signet_challenge", hex(p.signet_challenge)}], else: []) ++
         [{"warnings", []}]
     )}
  end

  # Core: ChainstateManager::GuessVerificationProgress (validation.cpp).
  defp verification_progress(ctx, t, idx) do
    case Archive.chain_tx_count(Methods.reader(ctx), t.height) do
      n when is_integer(n) and n > 0 ->
        {data_time, data_count, rate} = ctx.params.chain_tx_data
        now = Methods.now(ctx)
        best = HeaderIndex.best(idx)

        block_time =
          if abs(now - t.time) <= 2 * 3600 and best.height >= t.height,
            do: now - (best.height - t.height) * ctx.params.pow_target_spacing,
            else: t.time

        total =
          if n <= data_count,
            do: data_count + (now - data_time) * rate,
            else: n + (now - block_time) * rate

        min(n / total, 1.0)

      _ ->
        0.0
    end
  end

  defp chain_name(:mainnet), do: "main"
  defp chain_name(:testnet), do: "test"
  defp chain_name(n), do: Atom.to_string(n)

  defp bits_hex(bits),
    do: bits |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(8, "0")

  defp target_hex(bits, p) do
    t =
      case Pow.derive_target(bits, p.pow_limit) do
        {:ok, t} -> t
        t when is_integer(t) -> t
        _ -> 0
      end

    t |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(64, "0")
  end

  defp work_hex(w),
    do: w |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(64, "0")

  defp header_of(e), do: e.raw |> Header.decode() |> elem(0)

  # Core: blockheaderToJSON
  defp header_json(ctx, e, n_tx) do
    idx = Methods.idx(ctx)
    t = Methods.tip_entry(ctx)
    active = Methods.on_active?(idx, t, e)
    confirmations = if active, do: t.height - e.height + 1, else: -1
    next = (active and e.height < t.height) && HeaderIndex.ancestor(idx, t, e.height + 1)

    [
      {"hash", hash_hex(e.hash)},
      {"confirmations", confirmations},
      {"height", e.height},
      {"version", e.version},
      {"versionHex",
       e.version
       |> Bitwise.band(0xFFFFFFFF)
       |> Integer.to_string(16)
       |> String.downcase()
       |> String.pad_leading(8, "0")},
      {"merkleroot", hash_hex(header_of(e).merkle_root)},
      {"time", e.time},
      {"mediantime", HeaderIndex.median_time_past(idx, e)},
      {"nonce", header_of(e).nonce},
      {"bits", bits_hex(e.bits)},
      {"target", target_hex(e.bits, ctx.params)},
      {"difficulty", JSON.double(Methods.difficulty(e.bits))},
      {"chainwork", work_hex(e.chain_work)},
      {"nTx", n_tx}
    ] ++
      if(e.height > 0, do: [{"previousblockhash", hash_hex(e.prev_hash)}], else: []) ++
      if(next, do: [{"nextblockhash", hash_hex(next.hash)}], else: [])
  end

  # The block's raw bytes and id, if exnode has its data.
  defp block_data(ctx, hash, need_undo?) do
    a = Methods.reader(ctx)

    case Archive.block_id(a, hash) do
      nil ->
        nil

      id ->
        case Archive.read_block(a, id) do
          {:error, :witness_pruned} = err ->
            {id, err, []}

          raw ->
            spent = if need_undo? and id > 0, do: Archive.spent_outputs(a, id), else: []
            {id, raw, spent}
        end
    end
  end

  # Core: getblockheader
  def getblockheader(params, ctx) do
    with {:ok, h} <- Methods.parse_hash(Methods.arg(params, 0), "hash"),
         {:ok, e} <- Methods.lookup_header(ctx, h) do
      if Methods.arg(params, 1, true) == false do
        {:ok, hex(e.raw)}
      else
        # Core blockheaderToJSON: pindex->nTx, even with pruned block data.
        n_tx = Archive.block_tx_count(Methods.reader(ctx), h)

        {:ok, obj(header_json(ctx, e, n_tx))}
      end
    end
  end

  # Core: getblock (verbosity 0-3)
  def getblock(params, ctx) do
    with {:ok, h} <- Methods.parse_hash(Methods.arg(params, 0), "blockhash"),
         {:ok, e} <- Methods.lookup_header(ctx, h) do
      v = Methods.verbosity(Methods.arg(params, 1), 1)

      case block_data(ctx, h, v >= 2) do
        nil ->
          {:error, @rpc_misc_error, "Block not available (not fully downloaded)"}

        {_id, {:error, :witness_pruned}, _} ->
          {:error, @rpc_misc_error, "Block not available (pruned data)"}

        {_id, raw, spent} ->
          if v <= 0 do
            {:ok, hex(raw)}
          else
            {:ok, b} = Block.decode_exact(raw)
            {:ok, obj(header_json(ctx, e, length(b.txs)) ++ block_fields(ctx, b, spent, v))}
          end
      end
    end
  end

  defp block_fields(ctx, b, spent, v) do
    stripped = IO.iodata_length(Block.encode(b, witness: false))
    [cb | _] = b.txs
    cb_in = hd(cb.inputs)

    coinbase =
      [
        {"version", cb.version},
        {"locktime", cb.locktime},
        {"sequence", cb_in.sequence},
        {"coinbase", hex(cb_in.script_sig)}
      ] ++
        case cb_in.witness do
          [w] -> [{"witness", hex(w)}]
          _ -> []
        end

    txs =
      if v == 1 do
        Enum.map(b.txs, &hash_hex(&1.txid))
      else
        # Undo data: the spent outputs of each non-coinbase tx, in order.
        {undos, []} =
          Enum.map_reduce(b.txs, spent, fn tx, rest ->
            if Tx.coinbase?(tx), do: {nil, rest}, else: Enum.split(rest, length(tx.inputs))
          end)

        for {tx, undo} <- Enum.zip(b.txs, undos),
            do:
              obj(
                RawTx.tx_to_univ(
                  tx,
                  Methods.network(ctx),
                  undo,
                  if(v >= 3, do: :prevout, else: :details),
                  true
                )
              )
      end

    [
      {"strippedsize", stripped},
      {"size", byte_size(b.raw)},
      {"weight", stripped * 3 + byte_size(b.raw)},
      {"coinbase_tx", obj(coinbase)},
      {"tx", txs}
    ]
  end

  # Core: gettxout(txid, n, include_mempool = true)
  def gettxout(params, ctx) do
    n = Methods.arg(params, 1)
    include_mempool = Methods.arg(params, 2, true)

    with :ok <- Methods.check_type(n, "number", &is_number/1),
         :ok <- Methods.check_type(include_mempool, "bool", &is_boolean/1),
         {:ok, txid} <- Methods.parse_hash(Methods.arg(params, 0), "txid"),
         :ok <- Methods.check_uint32(n) do
      op = {txid, n}

      mem_out = include_mempool && mempool_output(ctx, txid, n)

      coin =
        cond do
          include_mempool and Mempool.spent?(ctx.mempool, op) ->
            nil

          mem_out ->
            {mem_out, Methods.tip(ctx), 0}

          true ->
            case ChainState.mempool_view(ctx.chain_state, [op]) do
              {t, %{^op => {:ok, c}}} -> {c, t, t.height - c.height + 1}
              _ -> nil
            end
        end

      case coin do
        nil ->
          {:ok, nil}

        {c, t, conf} ->
          {:ok,
           obj([
             {"bestblock", hash_hex(t.hash)},
             {"confirmations", conf},
             {"value", amount(c.value)},
             {"scriptPubKey", obj(JSON.script_to_univ(c.script_pubkey, Methods.network(ctx)))},
             {"coinbase", c.coinbase}
           ])}
      end
    end
  end

  defp mempool_output(ctx, txid, n) do
    case Mempool.get_tx(ctx.mempool, txid) do
      %Tx{outputs: outs} when n >= 0 and n < length(outs) ->
        o = Enum.at(outs, n)
        %{value: o.value, script_pubkey: o.script_pubkey, coinbase: false}

      _ ->
        nil
    end
  end

  # --- block filters (BIP158) -------------------------------------------------------

  def getblockfilter(params, ctx) do
    ft = Methods.arg(params, 1, "basic")

    with {:ok, h} <- Methods.parse_hash(Methods.arg(params, 0), "blockhash"),
         :ok <- Methods.check_type(ft, "string", &is_binary/1),
         :ok <- check_filtertype(ft),
         {:ok, _e} <- Methods.lookup_header(ctx, h) do
      case ctx[:filter_index] && Exnode.Index.BlockFilter.get(ctx.filter_index, h) do
        disabled when disabled in [nil, false] ->
          {:error, @rpc_misc_error, "Index is not enabled for filtertype basic"}

        :not_found ->
          {:error, @rpc_invalid_address_or_key,
           "Filter not found. Block filters are still in the process of being indexed."}

        {:ok, filter, header} ->
          {:ok, obj([{"filter", hex(filter)}, {"header", hash_hex(header)}])}
      end
    end
  end

  defp check_filtertype("basic"), do: :ok
  defp check_filtertype(ft), do: {:error, @rpc_invalid_parameter, "Unknown filtertype #{ft}"}
end
