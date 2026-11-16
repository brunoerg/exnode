defmodule Exnode.RPC.Methods do
  @moduledoc """
  Core-compatible JSON-RPC methods (a subset), with Core v32.1's result
  shapes, field order and error codes/messages: rpc/blockchain.cpp,
  rpc/rawtransaction.cpp, rpc/mempool.cpp, rpc/net.cpp, core_io.cpp.

  `ctx` holds the node's process names and chain params. Each method returns
  `{:ok, json}` or `{:error, code, message}`.
  """
  import Bitwise

  alias Exnode.{Archive, Mempool}
  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Codec.{Block, Header, Tx}
  alias Exnode.Consensus.Pow
  alias Exnode.Mempool.{Linearize, Pool}
  alias Exnode.RPC.JSON
  import Exnode.RPC.JSON, only: [obj: 1, amount: 1, hash_hex: 1, hex: 1]

  # rpc/protocol.h
  @rpc_misc_error -1
  @rpc_type_error -3
  @rpc_invalid_address_or_key -5
  @rpc_invalid_parameter -8
  @rpc_deserialization_error -22
  @rpc_verify_error -25
  @rpc_verify_rejected -26
  @rpc_verify_already_in_utxo_set -27

  @methods ~w(getblockchaininfo getbestblockhash getblockcount getblockhash getblockheader getblock gettxout
              getrawtransaction decoderawtransaction decodescript getrawmempool getmempoolentry getmempoolinfo
              testmempoolaccept sendrawtransaction getpeerinfo getnetworkinfo getconnectioncount getdifficulty uptime
              getblockfilter setmocktime)

  def known?(m), do: m in @methods

  def call(method, params, ctx) do
    if known?(method),
      do: apply(__MODULE__, String.to_atom(method), [params, ctx]),
      else: {:error, -32601, "Method not found"}
  rescue
    e in [ArgumentError, FunctionClauseError] ->
      {:error, @rpc_type_error, Exception.message(e)}

    e ->
      # Core: RPC_INTERNAL_ERROR (-32603) for unexpected failures.
      require Logger
      Logger.error("RPC #{method} failed: " <> Exception.format(:error, e, __STACKTRACE__))
      {:error, -32603, Exception.message(e)}
  catch
    # A node component restarting (its name unregistered, or it died during
    # the call): an error for this request only, not a dropped connection
    # and lost batch (SVC-4 in STATE_MACHINES.md).
    :exit, reason ->
      require Logger
      Logger.warning("RPC #{method}: node component unavailable: #{inspect(reason, limit: 5)}")
      {:error, -32603, "node component unavailable, retry"}
  end

  # --- helpers -------------------------------------------------------------------

  defp idx(ctx), do: Headers.index(ctx.headers)
  # The committed tip, from the lock-free reader: block data up to it is readable.
  defp tip(ctx), do: Archive.tip(reader(ctx))
  defp reader(ctx), do: ChainState.reader(ctx.chain_state)
  defp tip_entry(ctx), do: HeaderIndex.lookup(idx(ctx), tip(ctx).hash)
  defp network(ctx), do: ctx.params.network
  # The node's clock (Exnode.Clock; Core GetTime / NodeClock): mockable.
  defp now(ctx), do: Exnode.Clock.now(ctx[:clock])

  defp arg(params, i, default \\ nil) do
    case Enum.at(params, i) do
      nil -> default
      v -> v
    end
  end

  # Core ParseHashV.
  defp parse_hash(v, name) when is_binary(v) do
    cond do
      byte_size(v) != 64 ->
        {:error, @rpc_invalid_parameter,
         "#{name} must be of length 64 (not #{byte_size(v)}, for '#{v}')"}

      not String.match?(v, ~r/^[0-9a-fA-F]+$/) ->
        {:error, @rpc_invalid_parameter, "#{name} must be hexadecimal string (not '#{v}')"}

      true ->
        {:ok, Exnode.Crypto.Hash.from_hex(String.downcase(v))}
    end
  end

  defp parse_hash(v, name),
    do: {:error, @rpc_type_error, "#{name} must be a string, got #{inspect(v)}"}

  # Verbosity args may be numbers or (legacy) booleans.
  defp verbosity(nil, default), do: default
  defp verbosity(true, _), do: 1
  defp verbosity(false, _), do: 0
  defp verbosity(n, _) when is_integer(n), do: n

  defp on_active?(idx, tip_e, e),
    do: e.height <= tip_e.height and HeaderIndex.ancestor(idx, tip_e, e.height).hash == e.hash

  defp chain_name(:mainnet), do: "main"
  defp chain_name(:testnet), do: "test"
  defp chain_name(n), do: Atom.to_string(n)

  # Core GetDifficulty
  def difficulty(bits) do
    shift = bits >>> 24 &&& 0xFF
    d = 0x0000FFFF / (bits &&& 0x00FFFFFF)
    d = Enum.reduce(1..max(29 - shift, 0)//1, d, fn _, d -> d * 256.0 end)
    Enum.reduce(1..max(shift - 29, 0)//1, d, fn _, d -> d / 256.0 end)
  end

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

  # --- blockchain -------------------------------------------------------------------

  def getblockcount(_params, ctx), do: {:ok, tip(ctx).height}
  def getbestblockhash(_params, ctx), do: {:ok, hash_hex(tip(ctx).hash)}
  def getdifficulty(_params, ctx), do: {:ok, JSON.double(difficulty(tip_entry(ctx).bits))}
  def uptime(_params, ctx), do: {:ok, now(ctx) - Map.get(ctx, :started_at, now(ctx))}

  def getblockhash(params, ctx) do
    h = arg(params, 0)
    t = tip_entry(ctx)

    if not is_integer(h) or h < 0 or h > t.height,
      do: {:error, @rpc_invalid_parameter, "Block height out of range"},
      else: {:ok, hash_hex(HeaderIndex.ancestor(idx(ctx), t, h).hash)}
  end

  # Core: getblockchaininfo
  def getblockchaininfo(_params, ctx) do
    idx = idx(ctx)
    t = tip_entry(ctx)
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
         {"difficulty", JSON.double(difficulty(t.bits))},
         {"time", t.time},
         {"mediantime", HeaderIndex.median_time_past(idx, t)},
         {"verificationprogress", JSON.double(verification_progress(ctx, t, idx))},
         {"initialblockdownload",
          ChainState.view_ibd?(ChainState.view(ctx.chain_state), idx, now(ctx), p)},
         {"chainwork", work_hex(t.chain_work)},
         {"size_on_disk", 0},
         {"pruned", pruned}
       ] ++
         if(p.network == :signet, do: [{"signet_challenge", hex(p.signet_challenge)}], else: []) ++
         [{"warnings", []}]
     )}
  end

  # Core: ChainstateManager::GuessVerificationProgress (validation.cpp). The
  # share of all transactions, now, that the tip's chain contains: the known
  # total is extrapolated from the chain params' ChainTxData, or from the tip
  # when it is past that point. 0.0 when the tip's tx count is unknown.
  defp verification_progress(ctx, t, idx) do
    case Archive.chain_tx_count(reader(ctx), t.height) do
      n when is_integer(n) and n > 0 ->
        {data_time, data_count, rate} = ctx.params.chain_tx_data
        now = now(ctx)
        best = HeaderIndex.best(idx)

        # Near the tip, a height-based time (Core: so the value is quantized
        # close to 1.0, and less dependent on miners' timestamps).
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

  defp bits_hex(bits),
    do: bits |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(8, "0")

  # Core: blockheaderToJSON
  defp header_json(ctx, e, n_tx) do
    idx = idx(ctx)
    t = tip_entry(ctx)
    active = on_active?(idx, t, e)
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
      {"difficulty", JSON.double(difficulty(e.bits))},
      {"chainwork", work_hex(e.chain_work)},
      {"nTx", n_tx}
    ] ++
      if(e.height > 0, do: [{"previousblockhash", hash_hex(e.prev_hash)}], else: []) ++
      if(next, do: [{"nextblockhash", hash_hex(next.hash)}], else: [])
  end

  # The block's raw bytes and id, if exnode has its data.
  defp block_data(ctx, hash) do
    a = reader(ctx)

    case Archive.block_id(a, hash) do
      nil ->
        nil

      id ->
        {id, Archive.read_block(a, id), if(id > 0, do: Archive.spent_outputs(a, id), else: [])}
    end
  end

  defp lookup_header(ctx, hash) do
    case HeaderIndex.lookup(idx(ctx), hash) do
      nil -> {:error, @rpc_invalid_address_or_key, "Block not found"}
      e -> {:ok, e}
    end
  end

  # Core: getblockheader
  def getblockheader(params, ctx) do
    with {:ok, h} <- parse_hash(arg(params, 0), "hash"),
         {:ok, e} <- lookup_header(ctx, h) do
      if arg(params, 1, true) == false do
        {:ok, hex(e.raw)}
      else
        # Core blockheaderToJSON: pindex->nTx, even with pruned block data.
        # No segment reads, block reconstruction or spent-output resolution.
        n_tx = Archive.block_tx_count(reader(ctx), h)

        {:ok, obj(header_json(ctx, e, n_tx))}
      end
    end
  end

  # Core: getblock (verbosity 0-3)
  def getblock(params, ctx) do
    with {:ok, h} <- parse_hash(arg(params, 0), "blockhash"),
         {:ok, e} <- lookup_header(ctx, h) do
      v = verbosity(arg(params, 1), 1)

      case block_data(ctx, h) do
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
                tx_to_univ(tx, network(ctx), undo, if(v >= 3, do: :prevout, else: :details), true)
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

  @doc "Core `TxToUniv(tx, block_hash = null, entry, include_hex, txundo, verbosity)`."
  # Core: TxToUniv (core_io.cpp)
  def tx_to_univ(tx, network, undo, verbosity, include_hex) do
    weight = Tx.weight(tx)

    vin =
      tx.inputs
      |> Enum.with_index()
      |> Enum.map(fn {i, n} ->
        base =
          if Tx.coinbase?(tx),
            do: [{"coinbase", hex(i.script_sig)}],
            else: [
              {"txid", hash_hex(i.prev_hash)},
              {"vout", i.prev_index},
              {"scriptSig",
               obj([{"asm", JSON.asm(i.script_sig, true)}, {"hex", hex(i.script_sig)}])}
            ]

        wit = if i.witness != [], do: [{"txinwitness", Enum.map(i.witness, &hex/1)}], else: []

        prevout =
          if undo != nil and verbosity == :prevout do
            c = Enum.at(undo, n)

            [
              {"prevout",
               obj([
                 {"generated", c.coinbase},
                 {"height", c.height},
                 {"value", amount(c.value)},
                 {"scriptPubKey", obj(JSON.script_to_univ(c.script_pubkey, network))}
               ])}
            ]
          else
            []
          end

        obj(base ++ wit ++ prevout ++ [{"sequence", i.sequence}])
      end)

    vout =
      for {o, n} <- Enum.with_index(tx.outputs) do
        obj([
          {"value", amount(o.value)},
          {"n", n},
          {"scriptPubKey", obj(JSON.script_to_univ(o.script_pubkey, network))}
        ])
      end

    fee =
      if undo != nil do
        [
          {"fee",
           amount(
             Enum.reduce(undo, 0, &(&2 + &1.value)) - Enum.reduce(tx.outputs, 0, &(&2 + &1.value))
           )}
        ]
      else
        []
      end

    [
      {"txid", hash_hex(tx.txid)},
      {"hash", hash_hex(tx.wtxid)},
      {"version", tx.version},
      {"size", byte_size(tx.raw)},
      {"vsize", div(weight + 3, 4)},
      {"weight", weight},
      {"locktime", tx.locktime},
      {"vin", vin},
      {"vout", vout}
    ] ++
      fee ++ if(include_hex, do: [{"hex", hex(tx.raw)}], else: [])
  end

  # Core: gettxout(txid, n, include_mempool = true)
  def gettxout(params, ctx) do
    with {:ok, txid} <- parse_hash(arg(params, 0), "txid") do
      n = arg(params, 1)
      include_mempool = arg(params, 2, true)
      op = {txid, n}

      mem_out = include_mempool && mempool_output(ctx, txid, n)

      coin =
        cond do
          include_mempool and Mempool.spent?(ctx.mempool, op) ->
            nil

          mem_out ->
            {:mempool, mem_out}

          true ->
            case ChainState.mempool_view(ctx.chain_state, [op]) do
              {_tip, %{^op => {:ok, c}}} -> {:chain, c}
              _ -> nil
            end
        end

      t = tip(ctx)

      case coin do
        nil ->
          {:ok, nil}

        {kind, c} ->
          conf = if kind == :mempool, do: 0, else: t.height - c.height + 1

          {:ok,
           obj([
             {"bestblock", hash_hex(t.hash)},
             {"confirmations", conf},
             {"value", amount(c.value)},
             {"scriptPubKey", obj(JSON.script_to_univ(c.script_pubkey, network(ctx)))},
             {"coinbase", c.coinbase}
           ])}
      end
    end
  end

  defp mempool_output(ctx, txid, n) do
    case Mempool.get_tx(ctx.mempool, txid) do
      %Tx{outputs: outs} when n < length(outs) ->
        o = Enum.at(outs, n)
        %{value: o.value, script_pubkey: o.script_pubkey, coinbase: false}

      _ ->
        nil
    end
  end

  # --- raw transactions -----------------------------------------------------------

  # Core: getrawtransaction(txid, verbosity = 0, blockhash)
  def getrawtransaction(params, ctx) do
    with {:ok, txid} <- parse_hash(arg(params, 0), "parameter 1") do
      v = verbosity(arg(params, 1), 0)

      found =
        case Mempool.get_tx(ctx.mempool, txid) do
          %Tx{} = tx -> {:mempool, tx}
          nil -> chain_tx(ctx, txid)
        end

      case found do
        nil ->
          {:error, @rpc_invalid_address_or_key,
           "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."}

        {:mempool, tx} when v <= 0 ->
          {:ok, hex(tx.raw)}

        {:block, tx, _, _, _} when v <= 0 ->
          {:ok, hex(tx.raw)}

        {:mempool, tx} ->
          e = Mempool.entry(ctx.mempool, tx.txid)

          {:ok,
           obj([{"vsize_adjusted", e.vsize} | tx_to_univ(tx, network(ctx), nil, :details, true)])}

        {:block, tx, block_hash, height, undo} ->
          t = tip(ctx)
          undo = if v >= 2, do: undo, else: nil

          base =
            tx_to_univ(tx, network(ctx), undo, if(v >= 2, do: :prevout, else: :details), true)

          e = HeaderIndex.lookup(idx(ctx), block_hash)
          active = on_active?(idx(ctx), tip_entry(ctx), e)

          extra =
            [{"blockhash", hash_hex(block_hash)}] ++
              if(active,
                do: [
                  {"confirmations", 1 + t.height - height},
                  {"time", e.time},
                  {"blocktime", e.time}
                ],
                else: [{"confirmations", 0}]
              )

          {:ok, obj(base ++ extra)}
      end
    end
  end

  defp chain_tx(ctx, txid) do
    a = reader(ctx)

    case Archive.tx_location(a, txid) do
      :missing ->
        nil

      {:ok, id, pos} ->
        raw = Archive.read_block(a, id)
        {:ok, b} = Block.decode_exact(raw)
        tx = Enum.at(b.txs, pos)
        rec = Archive.block_record!(a, id)

        undo =
          if pos == 0 do
            nil
          else
            skip =
              b.txs |> Enum.take(pos) |> Enum.drop(1) |> Enum.reduce(0, &(&2 + length(&1.inputs)))

            a |> Archive.spent_outputs(id) |> Enum.drop(skip) |> Enum.take(length(tx.inputs))
          end

        {:block, tx, rec.hash, rec.height, undo}
    end
  end

  # Core: decoderawtransaction(hexstring, iswitness)
  def decoderawtransaction(params, ctx) do
    with {:ok, tx} <- decode_tx(arg(params, 0)) do
      {:ok, obj(tx_to_univ(tx, network(ctx), nil, :details, false))}
    else
      _ -> {:error, @rpc_deserialization_error, "TX decode failed"}
    end
  end

  # Core: decodescript(hexstring)
  def decodescript(params, ctx) do
    case Base.decode16(arg(params, 0, ""), case: :mixed) do
      {:ok, spk} ->
        {:ok,
         obj(
           JSON.script_to_univ(spk, network(ctx), false, true) ++
             decodescript_wrap(spk, network(ctx))
         )}

      :error ->
        {:error, @rpc_type_error, "argument must be hexadecimal string"}
    end
  end

  # Core decodescript: "p2sh" and "segwit" for scripts that can be wrapped.
  defp decodescript_wrap(spk, net) do
    {type, sols} = Exnode.Mempool.Policy.solver(spk)

    can_wrap =
      type in [
        :multisig,
        :nonstandard,
        :pubkey,
        :pubkeyhash,
        :witness_v0_keyhash,
        :witness_v0_scripthash
      ] and
        valid_ops?(spk) and not Exnode.Script.unspendable?(spk) and
        not has_op_success_or_checksigadd?(spk)

    if not can_wrap do
      []
    else
      p2sh =
        Exnode.Address.from_script(
          <<0xA9, 20>> <> Exnode.Crypto.Hash.hash160(spk) <> <<0x87>>,
          net
        )

      can_wsh =
        case type do
          t when t in [:multisig, :pubkey] ->
            Enum.all?(sols, &(byte_size(&1) == 1 or byte_size(&1) == 33))

          t when t in [:nonstandard, :pubkeyhash] ->
            true

          _ ->
            false
        end

      segwit =
        if can_wsh do
          seg =
            case {type, sols} do
              {:pubkey, [pk]} -> <<0, 20>> <> Exnode.Crypto.Hash.hash160(pk)
              {:pubkeyhash, [h]} -> <<0, 20>> <> h
              _ -> <<0, 32>> <> :crypto.hash(:sha256, spk)
            end

          # The provider knows the witness script (FlatSigningProvider): a
          # multisig of compressed keys infers as wsh(multi(...)).
          univ = JSON.script_to_univ(seg, net)

          univ =
            case type do
              :multisig ->
                inner = JSON.infer_descriptor(spk, net) |> String.split("#") |> hd()
                desc = "wsh(" <> inner <> ")"
                List.keyreplace(univ, "desc", 0, {"desc", desc <> "#" <> JSON.checksum(desc)})

              _ ->
                univ
            end

          p2sh_segwit =
            Exnode.Address.from_script(
              <<0xA9, 20>> <> Exnode.Crypto.Hash.hash160(seg) <> <<0x87>>,
              net
            )

          [{"segwit", obj(univ ++ [{"p2sh-segwit", p2sh_segwit}])}]
        else
          []
        end

      [{"p2sh", p2sh}] ++ segwit
    end
  end

  # Core CScript::HasValidOps: every op parses, is <= MAX_OPCODE (0xb9), pushes <= 520 bytes.
  defp valid_ops?(<<>>), do: true

  defp valid_ops?(s) do
    case Exnode.Script.get_op(s) do
      {:ok, op, d, rest} -> op <= 0xB9 and byte_size(d) <= 520 and valid_ops?(rest)
      :error -> false
    end
  end

  defp has_op_success_or_checksigadd?(<<>>), do: false

  defp has_op_success_or_checksigadd?(s) do
    {:ok, op, _, rest} = Exnode.Script.get_op(s)
    op == 0xBA or op_success?(op) or has_op_success_or_checksigadd?(rest)
  end

  # Core IsOpSuccess (script/script.cpp)
  defp op_success?(op),
    do:
      op == 80 or op == 98 or op in 126..129 or op in 131..134 or op in 137..138 or op in 141..142 or
        op in 149..153 or op in 187..254

  defp decode_tx(h) when is_binary(h) do
    with {:ok, raw} <- Base.decode16(h, case: :mixed), {:ok, tx} <- Tx.decode_exact(raw) do
      {:ok, tx}
    else
      _ -> :error
    end
  end

  defp decode_tx(_), do: :error

  # --- mempool --------------------------------------------------------------------

  # Core: getrawmempool(verbose = false, mempool_sequence = false)
  def getrawmempool(params, ctx) do
    if arg(params, 0, false) == true do
      pool = Mempool.pool(ctx.mempool)

      {:ok,
       obj(
         for t <- Enum.sort(Map.keys(pool.entries)),
             do: {hash_hex(t), obj(entry_json(pool, pool.entries[t], ctx))}
       )}
    else
      {:ok, ctx.mempool |> Mempool.pool() |> mining_order() |> Enum.map(&hash_hex/1)}
    end
  end

  # Core GetSortedScoreWithTopology (CompareMainOrder): chunks by feerate,
  # best first; ties by entry order (Core's txgraph tie-breaks are internal).
  defp mining_order(pool) do
    pool.entries
    |> Map.keys()
    |> Enum.reduce({MapSet.new(), []}, fn t, {seen, acc} ->
      if MapSet.member?(seen, t),
        do: {seen, acc},
        else:
          (
            c = Pool.cluster(pool, t)
            {MapSet.union(seen, c), [Pool.chunks(pool, t) | acc]}
          )
    end)
    |> elem(1)
    |> Enum.concat()
    |> Enum.sort(fn {f1, w1, ids1}, {f2, w2, ids2} ->
      case Linearize.ratio_cmp({f1, w1}, {f2, w2}) do
        :gt -> true
        :lt -> false
        :eq -> min_seq(pool, ids1) <= min_seq(pool, ids2)
      end
    end)
    |> Enum.flat_map(fn {_, _, ids} -> ids end)
  end

  defp min_seq(pool, ids), do: ids |> Enum.map(&Pool.get(pool, &1).sequence) |> Enum.min()

  # Core: getmempoolentry(txid)
  def getmempoolentry(params, ctx) do
    with {:ok, txid} <- parse_hash(arg(params, 0), "txid") do
      pool = Mempool.pool(ctx.mempool)

      case Pool.get(pool, txid) do
        nil -> {:error, @rpc_invalid_address_or_key, "Transaction not in mempool"}
        e -> {:ok, obj(entry_json(pool, e, ctx))}
      end
    end
  end

  # Core: entryToJSON
  defp entry_json(pool, e, ctx) do
    anc = Pool.ancestors(pool, e.txid) |> MapSet.put(e.txid)
    desc = Pool.descendants(pool, e.txid) |> MapSet.put(e.txid)
    sum = fn set, f -> Enum.reduce(set, 0, &(&2 + f.(Pool.get(pool, &1)))) end

    {chunk_fee, chunk_w, _} =
      Enum.find(Pool.chunks(pool, e.txid), fn {_, _, ids} -> e.txid in ids end)

    raw_weight = Tx.weight(e.tx)

    depends =
      for(
        i <- e.tx.inputs,
        Pool.exists?(pool, i.prev_hash),
        uniq: true,
        do: hash_hex(i.prev_hash)
      )
      |> Enum.sort()

    spentby = e.children |> Enum.map(&hash_hex/1) |> Enum.sort()

    [
      {"vsize_adjusted", e.vsize},
      {"vsize", e.vsize},
      {"vsize_bip141", div(raw_weight + 3, 4)},
      {"weight", raw_weight},
      {"time", e.time},
      {"height", e.height},
      {"descendantcount", MapSet.size(desc)},
      {"descendantsize", sum.(desc, & &1.vsize)},
      {"ancestorcount", MapSet.size(anc)},
      {"ancestorsize", sum.(anc, & &1.vsize)},
      {"wtxid", hash_hex(e.wtxid)},
      {"chunkweight", chunk_w},
      {"fees",
       obj([
         {"base", amount(e.fee)},
         {"modified", amount(e.fee)},
         {"ancestor", amount(sum.(anc, & &1.fee))},
         {"descendant", amount(sum.(desc, & &1.fee))},
         {"chunk", amount(chunk_fee)}
       ])},
      {"depends", depends},
      {"spentby", spentby},
      {"unbroadcast", Mempool.unbroadcast?(ctx.mempool, e.txid)}
    ]
    |> tap(fn _ -> _ = Linearize end)
  end

  # Core: getmempoolinfo (MempoolInfoToJSON)
  def getmempoolinfo(_params, ctx) do
    pool = Mempool.pool(ctx.mempool)
    {min_fee, opts} = Mempool.fee_info(ctx.mempool)
    total_fee = Enum.reduce(pool.entries, 0, fn {_, e}, acc -> acc + e.fee end)

    {:ok,
     obj([
       {"loaded", true},
       {"size", Pool.size(pool)},
       {"bytes", pool.total_vsize},
       {"usage", pool.total_usage},
       {"total_fee", amount(total_fee)},
       {"maxmempool", opts.max_size},
       {"mempoolminfee", amount(max(min_fee, opts.min_relay))},
       {"minrelaytxfee", amount(opts.min_relay)},
       {"incrementalrelayfee", amount(opts.incremental)},
       {"unbroadcastcount", Mempool.unbroadcast_count(ctx.mempool)},
       {"permitbaremultisig", opts.bare_multisig},
       {"maxdatacarriersize", opts.max_datacarrier || 0},
       {"limitclustercount", Pool.cluster_count_limit()},
       {"limitclustersize", div(Pool.cluster_weight_limit(), 4)},
       {"optimal", true}
     ])}
  end

  # Core: testmempoolaccept(rawtxs, maxfeerate = 0.10)
  def testmempoolaccept(params, ctx) do
    raws = arg(params, 0, [])
    max_rate = fee_rate_arg(arg(params, 1), 10_000_000)

    case Enum.map(raws, &decode_tx/1) do
      decoded ->
        if Enum.any?(decoded, &(&1 == :error)) do
          {:error, @rpc_deserialization_error,
           "TX decode failed: #{raws |> Enum.zip(decoded) |> Enum.find(fn {_, d} -> d == :error end) |> elem(0)}"}
        else
          txs = Enum.map(decoded, &elem(&1, 1))
          results = Mempool.test_accept(ctx.mempool, txs)
          {:ok, test_accept_json(txs, results, max_rate)}
        end
    end
  end

  defp test_accept_json([_] = txs, [r], max_rate) do
    [tx] = txs
    [one_result(tx, r, max_rate)]
  end

  defp test_accept_json(txs, %{state: pkg_state, txs: res}, max_rate) do
    pkg_err =
      case pkg_state do
        {:policy, reason, _} -> [{"package-error", reason}]
        _ -> []
      end

    {out, _} =
      Enum.map_reduce(txs, false, fn tx, exit_early ->
        base = [{"txid", hash_hex(tx.txid)}, {"wtxid", hash_hex(tx.wtxid)}] ++ pkg_err

        case {exit_early, res[tx.wtxid]} do
          {true, _} -> {obj(base), true}
          {_, nil} -> {obj(base), exit_early}
          {_, {:valid, r}} -> one_result_kv(base, tx, {:ok, tx, r}, max_rate)
          {_, {:invalid, e}} -> one_result_kv(base, tx, {:error, tx, e}, max_rate)
        end
      end)

    out
  end

  defp one_result(tx, r, max_rate) do
    {o, _} =
      one_result_kv([{"txid", hash_hex(tx.txid)}, {"wtxid", hash_hex(tx.wtxid)}], tx, r, max_rate)

    o
  end

  defp one_result_kv(base, tx, {:ok, _, r}, max_rate) do
    if max_rate > 0 and r.fee > Exnode.Mempool.Policy.fee_for(max_rate, r.vsize) do
      {obj(base ++ [{"allowed", false}, {"reject-reason", "max-fee-exceeded"}]), true}
    else
      rate = div(r.fee * 1000, r.vsize)

      {obj(
         base ++
           [
             {"allowed", true},
             {"vsize_adjusted", r.vsize},
             {"vsize", r.vsize},
             {"vsize_bip141", div(Tx.weight(tx) + 3, 4)},
             {"fees",
              obj([
                {"base", amount(r.fee)},
                {"effective-feerate", amount(rate)},
                {"effective-includes", [hash_hex(tx.wtxid)]}
              ])}
           ]
       ), false}
    end
  end

  defp one_result_kv(base, _tx, {:error, _, e}, _max_rate) do
    reason = if e.result == :missing_inputs, do: "missing-inputs", else: e.reason

    details =
      (e[:detail] && e.detail != "" && [{"reject-details", "#{reason}, #{e.detail}"}]) ||
        [{"reject-details", reason}]

    {obj(base ++ [{"allowed", false}, {"reject-reason", reason}] ++ details), false}
  end

  # BTC/kvB amounts (JSON numbers) to sat/kvB.
  defp fee_rate_arg(nil, default), do: default
  defp fee_rate_arg(v, _) when is_number(v), do: round(v * 100_000_000)

  # Core: sendrawtransaction(hexstring, maxfeerate = 0.10, maxburnamount = 0)
  def sendrawtransaction(params, ctx) do
    max_rate = fee_rate_arg(arg(params, 1), 10_000_000)

    case decode_tx(arg(params, 0)) do
      :error ->
        {:error, @rpc_deserialization_error,
         "TX decode failed. Make sure the tx has at least one input."}

      {:ok, tx} ->
        cond do
          Mempool.has?(ctx.mempool, tx.txid) ->
            {:ok, hash_hex(tx.txid)}

          true ->
            case Mempool.test_accept(ctx.mempool, [tx]) do
              [{:ok, _, r}] when max_rate > 0 ->
                if r.fee > Exnode.Mempool.Policy.fee_for(max_rate, r.vsize),
                  do: {:error, @rpc_verify_rejected, "max-fee-exceeded"},
                  else: submit(ctx, tx)

              _ ->
                submit(ctx, tx)
            end
        end
    end
  end

  defp submit(ctx, tx) do
    case Mempool.accept(ctx.mempool, tx, unbroadcast: true) do
      {:ok, _} ->
        {:ok, hash_hex(tx.txid)}

      {:error, %{result: :missing_inputs}} ->
        {:error, @rpc_verify_error, "bad-txns-inputs-missingorspent"}

      {:error, %{reason: "txn-already-known"}} ->
        {:error, @rpc_verify_already_in_utxo_set, "Transaction outputs already in utxo set"}

      {:error, e} ->
        msg = if e[:detail] in [nil, ""], do: e.reason, else: "#{e.reason}, #{e.detail}"
        {:error, @rpc_verify_rejected, msg}
    end
  end

  # --- control ---------------------------------------------------------------------

  # Core: setmocktime (rpc/node.cpp). The node's clock (Exnode.Clock) only:
  # timers keep their pace; Exnode.Node.tick/1 runs them now (tests).
  @max_mocktime 0xFFFFFFFF
  def setmocktime(params, ctx) do
    t = arg(params, 0)

    cond do
      ctx.params.network != :regtest ->
        {:error, @rpc_misc_error, "setmocktime is for regression testing (-regtest mode) only"}

      not is_integer(t) ->
        {:error, @rpc_type_error,
         "JSON value of type #{json_type(t)} is not of expected type number"}

      t < 0 or t > @max_mocktime ->
        {:error, @rpc_invalid_parameter,
         "Mocktime must be in the range [0, #{@max_mocktime}], not #{t}."}

      true ->
        Exnode.Clock.set(ctx.clock, t)
        {:ok, nil}
    end
  end

  defp json_type(nil), do: "null"
  defp json_type(v) when is_binary(v), do: "string"
  defp json_type(v) when is_boolean(v), do: "bool"
  defp json_type(v) when is_list(v), do: "array"
  defp json_type(v) when is_map(v), do: "object"
  defp json_type(_), do: "number"

  # --- network ---------------------------------------------------------------------

  def getconnectioncount(_params, ctx), do: {:ok, map_size(Exnode.P2P.Connman.peers(ctx.connman))}

  # Core: getnetworkinfo (field set; values are exnode's)
  def getnetworkinfo(_params, ctx) do
    services = ctx.services
    peers = Exnode.P2P.Connman.peers(ctx.connman)
    inbound = Enum.count(peers, fn {_, p} -> p.type == :inbound end)

    {:ok,
     obj([
       {"version", 320_100},
       {"subversion", ctx.user_agent},
       {"protocolversion", Exnode.P2P.Message.protocol_version()},
       {"localservices",
        services |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(16, "0")},
       {"localservicesnames", service_names(services)},
       {"localrelay", true},
       {"timeoffset", 0},
       # exnode has no inbound inventory token bucket: Core's
       # default rate is reported, with empty buckets.
       {"tx_send_rate", 14},
       {"inv_buckets",
        obj([
          {"inbound", obj([{"backlog", 0}, {"count_tok", 0}, {"size_tok", 0}])},
          {"outbound", obj([{"backlog", 0}, {"count_tok", 0}, {"size_tok", 0}])}
        ])},
       {"networkactive", true},
       {"connections", map_size(peers)},
       {"connections_in", inbound},
       {"connections_out", map_size(peers) - inbound},
       {"networks",
        for(
          n <- ~w(ipv4 ipv6 onion i2p cjdns),
          do:
            obj([
              {"name", n},
              {"limited", n not in ~w(ipv4 ipv6)},
              {"reachable", n in ~w(ipv4 ipv6)},
              {"proxy", ""},
              {"proxy_randomize_credentials", false}
            ])
        )},
       {"relayfee", amount(1000 * 0 + Exnode.Mempool.Policy.default_min_relay_tx_fee())},
       {"incrementalfee", amount(Exnode.Mempool.Policy.default_incremental_relay_fee())},
       {"localaddresses", []},
       {"warnings", []}
     ])}
  end

  defp service_names(s) do
    for {name, bit} <- [
          {"NETWORK", 1},
          {"BLOOM", 4},
          {"WITNESS", 8},
          {"COMPACT_FILTERS", 64},
          {"NETWORK_LIMITED", 1024},
          {"P2P_V2", 2048}
        ],
        (s &&& bit) != 0,
        do: name
  end

  # Core: getpeerinfo (Core's field set; values from exnode's peer state)
  def getpeerinfo(_params, ctx) do
    peers = Exnode.P2P.Connman.peers(ctx.connman)

    list =
      peers
      |> Enum.with_index()
      |> Enum.map(fn {{pid, p}, id} ->
        info =
          try do
            Exnode.P2P.Peer.info(pid)
          catch
            :exit, _ -> %{}
          end

        {host, port} = p.target || {"", 0}
        svc = info[:services] || 0

        ping =
          if info[:ping_ms],
            do: [{"pingtime", info.ping_ms / 1000}, {"minping", info.ping_ms / 1000}],
            else: []

        obj(
          [
            {"id", id},
            {"addr", "#{host}:#{port}"},
            {"network", if(String.contains?("#{host}", ":"), do: "ipv6", else: "ipv4")},
            {"services",
             svc |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(16, "0")},
            {"servicesnames", service_names(svc)},
            {"relaytxes", p.type != :block_relay and Map.get(info, :relay, true)},
            {"last_inv_sequence", 0},
            {"inv_to_send", 0},
            {"lastsend", info[:last_send] || 0},
            {"lastrecv", info[:last_recv] || 0},
            {"last_transaction", 0},
            {"last_block", 0},
            {"bytessent", info[:bytes_sent] || 0},
            {"bytesrecv", info[:bytes_recv] || 0},
            {"conntime", info[:conntime] || 0},
            {"timeoffset", info[:timeoffset] || 0}
          ] ++
            ping ++
            [
              {"version", info[:version] || 0},
              {"subver", info[:user_agent] || ""},
              {"inbound", p.type == :inbound},
              {"bip152_hb_to", Map.get(info, :hb_to, false)},
              {"bip152_hb_from", false},
              {"startingheight", info[:start_height] || -1},
              {"presynced_headers", -1},
              {"synced_headers", info[:best_known] || -1},
              {"synced_blocks", info[:best_known] || -1},
              {"inflight", []},
              {"addr_relay_enabled", p.type != :block_relay},
              {"addr_processed", 0},
              {"addr_rate_limited", 0},
              {"permissions", []},
              {"minfeefilter", amount(0)},
              {"bytessent_per_msg", obj([])},
              {"bytesrecv_per_msg", obj([])},
              {"connection_type", conn_type(p.type)},
              {"transport_protocol_type", info[:transport_protocol_type] || "v1"},
              # Core: the hex session id for v2, "" otherwise.
              {"session_id",
               if(info[:session_id], do: Base.encode16(info.session_id, case: :lower), else: "")}
            ]
        )
      end)

    {:ok, list}
  end

  defp conn_type(:inbound), do: "inbound"
  defp conn_type(:block_relay), do: "block-relay-only"
  defp conn_type(:manual), do: "manual"
  defp conn_type(_), do: "outbound-full-relay"

  # --- block filters (BIP158) -------------------------------------------------------

  def getblockfilter(params, ctx) do
    with {:ok, h} <- parse_hash(arg(params, 0), "blockhash"),
         {:ok, _e} <- lookup_header(ctx, h) do
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
end
