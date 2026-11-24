defmodule Exnode.RPC.RawTx do
  @moduledoc """
  Core v32.1 `rpc/rawtransaction.cpp`, `rpc/mempool.cpp` (`sendrawtransaction`)
  and `core_io.cpp` (`TxToUniv`) JSON-RPC methods.
  """
  alias Exnode.{Archive, Mempool}
  alias Exnode.Chain.HeaderIndex
  alias Exnode.Codec.Tx
  alias Exnode.RPC.{JSON, Methods}
  import Exnode.RPC.JSON, only: [obj: 1, amount: 1, hash_hex: 1, hex: 1]

  @rpc_misc_error -1
  @rpc_type_error -3
  @rpc_invalid_address_or_key -5
  @rpc_deserialization_error -22
  @rpc_verify_error -25
  @rpc_verify_rejected -26
  @rpc_verify_already_in_utxo_set -27

  @doc "Core `TxToUniv(tx, block_hash = null, entry, include_hex, txundo, verbosity)`."
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

  # Core: getrawtransaction(txid, verbosity = 0, blockhash)
  def getrawtransaction(params, ctx) do
    with {:ok, txid} <- Methods.parse_hash(Methods.arg(params, 0), "parameter 1"),
         {:ok, block_hash} <- Methods.parse_optional_hash(Methods.arg(params, 2), "parameter 3") do
      v = Methods.verbosity(Methods.arg(params, 1), 0)

      found =
        if block_hash != nil do
          chain_tx_in_block(ctx, txid, block_hash, v >= 2)
        else
          case Mempool.get_tx(ctx.mempool, txid) do
            %Tx{} = tx -> {:mempool, tx}
            nil -> chain_tx(ctx, txid, v >= 2)
          end
        end

      case found do
        {:error, _, _} = err ->
          err

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
           obj([
             {"vsize_adjusted", e.vsize}
             | tx_to_univ(tx, Methods.network(ctx), nil, :details, true)
           ])}

        {:block, tx, bh, height, undo} ->
          t = Methods.tip(ctx)
          undo = if v >= 2, do: undo, else: nil

          base =
            tx_to_univ(
              tx,
              Methods.network(ctx),
              undo,
              if(v >= 2, do: :prevout, else: :details),
              true
            )

          idx = Methods.idx(ctx)
          e = HeaderIndex.lookup(idx, bh)
          active = Methods.on_active?(idx, Methods.tip_entry(ctx), e)

          extra =
            [{"blockhash", hash_hex(bh)}] ++
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

  defp chain_tx(ctx, txid, need_undo?) do
    a = Methods.reader(ctx)

    case Archive.tx_location(a, txid) do
      :missing -> nil
      {:ok, id, pos} -> load_chain_tx(a, id, pos, need_undo?)
    end
  end

  defp chain_tx_in_block(ctx, txid, block_hash, need_undo?) do
    if HeaderIndex.lookup(Methods.idx(ctx), block_hash) == nil do
      {:error, @rpc_invalid_address_or_key, "Block hash not found"}
    else
      a = Methods.reader(ctx)

      case Archive.block_id(a, block_hash) do
        nil ->
          {:error, @rpc_misc_error, "Block not available (not fully downloaded)"}

        id ->
          if Archive.witness_pruned?(a, id) do
            {:error, @rpc_misc_error, "Block not available (pruned data)"}
          else
            case Archive.tx_location_in_block(a, txid, id) do
              :missing ->
                {:error, @rpc_invalid_address_or_key,
                 "No such transaction found in the provided block"}

              {:ok, pos} ->
                load_chain_tx(a, id, pos, need_undo?)
            end
          end
      end
    end
  end

  defp load_chain_tx(a, id, pos, need_undo?) do
    case Archive.read_tx_strict(a, id, pos) do
      {:error, :witness_pruned} ->
        {:error, @rpc_misc_error, "Block not available (pruned data)"}

      {:ok, tx, rec} ->
        undo =
          if need_undo? and pos > 0 do
            skip =
              rec.txs
              |> Enum.take(pos)
              |> Enum.drop(1)
              |> Enum.reduce(0, fn {_, _, ni, _, _}, acc -> acc + ni end)

            Archive.spent_outputs_slice(a, rec, skip, length(tx.inputs))
          else
            nil
          end

        {:block, tx, rec.hash, rec.height, undo}
    end
  end

  # Core: decoderawtransaction(hexstring, iswitness)
  def decoderawtransaction(params, ctx) do
    with {:ok, tx} <- Methods.decode_tx(Methods.arg(params, 0)) do
      {:ok, obj(tx_to_univ(tx, Methods.network(ctx), nil, :details, false))}
    else
      _ -> {:error, @rpc_deserialization_error, "TX decode failed"}
    end
  end

  # Core: decodescript(hexstring)
  def decodescript(params, ctx) do
    case Base.decode16(Methods.arg(params, 0, ""), case: :mixed) do
      {:ok, spk} ->
        net = Methods.network(ctx)

        {:ok,
         obj(
           JSON.script_to_univ(spk, net, false, true) ++
             decodescript_wrap(spk, net)
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
        Methods.valid_ops?(spk) and not Exnode.Script.unspendable?(spk) and
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

  # Core: sendrawtransaction(hexstring, maxfeerate = 0.10, maxburnamount = 0)
  def sendrawtransaction(params, ctx) do
    with {:ok, max_rate} <- Methods.parse_feerate(Methods.arg(params, 1), 10_000_000),
         {:ok, max_burn} <- Methods.parse_optional_amount(Methods.arg(params, 2), 0) do
      case Methods.decode_hex_tx(Methods.arg(params, 0)) do
        :error ->
          {:error, @rpc_deserialization_error,
           "TX decode failed. Make sure the tx has at least one input."}

        {:ok, tx} ->
          cond do
            burn_exceeds?(tx, max_burn) ->
              {:error, @rpc_verify_rejected,
               "Unspendable output exceeds maximum configured by user (maxburnamount)"}

            Mempool.has?(ctx.mempool, tx.txid) ->
              {:ok, hash_hex(tx.txid)}

            true ->
              submit(ctx, tx, max_rate)
          end
      end
    end
  end

  defp burn_exceeds?(tx, max_burn),
    do:
      Enum.any?(
        tx.outputs,
        &((Exnode.Script.unspendable?(&1.script_pubkey) or
             not Methods.valid_ops?(&1.script_pubkey)) and
            &1.value > max_burn)
      )

  defp submit(ctx, tx, max_rate) do
    case Mempool.accept(ctx.mempool, tx, unbroadcast: true, max_feerate: max_rate) do
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
end
