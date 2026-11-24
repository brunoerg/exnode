defmodule Exnode.RPC.MempoolRPC do
  @moduledoc """
  Core v32.1 `rpc/mempool.cpp` JSON-RPC methods.
  """
  alias Exnode.Codec.Tx
  alias Exnode.Mempool
  alias Exnode.Mempool.{Package, Policy, Pool}
  alias Exnode.RPC.Methods
  import Exnode.RPC.JSON, only: [obj: 1, amount: 1, hash_hex: 1]

  @rpc_invalid_address_or_key -5
  @rpc_invalid_parameter -8
  @rpc_deserialization_error -22
  @rpc_verify_error -25

  @max_package_count 25

  # Core: getrawmempool(verbose = false, mempool_sequence = false)
  def getrawmempool(params, ctx) do
    verbose = Methods.arg(params, 0, false)
    mempool_seq = Methods.arg(params, 1, false)

    with :ok <- Methods.check_type(verbose, "bool", &is_boolean/1),
         :ok <- Methods.check_type(mempool_seq, "bool", &is_boolean/1) do
      cond do
        verbose and mempool_seq ->
          {:error, @rpc_invalid_parameter,
           "Verbose results cannot contain mempool sequence values."}

        verbose ->
          entries = Mempool.raw_mempool(ctx.mempool, true)

          {:ok,
           obj(
             for {t, d} <- entries,
                 do: {hash_hex(t), obj(entry_json(d))}
           )}

        true ->
          {txids, seq} = Mempool.raw_mempool(ctx.mempool, false)
          hashes = Enum.map(txids, &hash_hex/1)

          if mempool_seq,
            do: {:ok, obj([{"txids", hashes}, {"mempool_sequence", seq}])},
            else: {:ok, hashes}
      end
    end
  end

  # Core: getmempoolentry(txid)
  def getmempoolentry(params, ctx) do
    with {:ok, txid} <- Methods.parse_hash(Methods.arg(params, 0), "txid") do
      case Mempool.entry_details(ctx.mempool, txid) do
        nil -> {:error, @rpc_invalid_address_or_key, "Transaction not in mempool"}
        d -> {:ok, obj(entry_json(d))}
      end
    end
  end

  # Core: entryToJSON
  defp entry_json(d) do
    e = d.entry
    raw_weight = Tx.weight(e.tx)
    depends = d.depends |> Enum.map(&hash_hex/1) |> Enum.sort()
    spentby = d.spentby |> Enum.map(&hash_hex/1) |> Enum.sort()

    [
      {"vsize_adjusted", e.vsize},
      {"vsize", e.vsize},
      {"vsize_bip141", div(raw_weight + 3, 4)},
      {"weight", raw_weight},
      {"time", e.time},
      {"height", e.height},
      {"descendantcount", d.descendant_count},
      {"descendantsize", d.descendant_size},
      {"ancestorcount", d.ancestor_count},
      {"ancestorsize", d.ancestor_size},
      {"wtxid", hash_hex(e.wtxid)},
      {"chunkweight", d.chunk_weight},
      {"fees",
       obj([
         {"base", amount(e.fee)},
         {"modified", amount(e.fee)},
         {"ancestor", amount(d.ancestor_fee)},
         {"descendant", amount(d.descendant_fee)},
         {"chunk", amount(d.chunk_fee)}
       ])},
      {"depends", depends},
      {"spentby", spentby},
      {"unbroadcast", d.unbroadcast}
    ]
  end

  # Core: getmempoolinfo (MempoolInfoToJSON)
  def getmempoolinfo(_params, ctx) do
    s = Mempool.stats(ctx.mempool)
    opts = s.opts

    {:ok,
     obj([
       {"loaded", true},
       {"size", s.size},
       {"bytes", s.bytes},
       {"usage", s.usage},
       {"total_fee", amount(s.total_fee)},
       {"maxmempool", opts.max_size},
       {"mempoolminfee", amount(max(s.min_fee, opts.min_relay))},
       {"minrelaytxfee", amount(opts.min_relay)},
       {"incrementalrelayfee", amount(opts.incremental)},
       {"unbroadcastcount", s.unbroadcast_count},
       {"permitbaremultisig", opts.bare_multisig},
       {"maxdatacarriersize", opts.max_datacarrier || 0},
       {"limitclustercount", Pool.cluster_count_limit()},
       {"limitclustersize", div(Pool.cluster_weight_limit(), 4)},
       {"optimal", true}
     ])}
  end

  # Core: testmempoolaccept(rawtxs, maxfeerate = 0.10)
  def testmempoolaccept(params, ctx) do
    raws = Methods.arg(params, 0)

    with :ok <- Methods.check_type(raws, "array", &is_list/1),
         :ok <- check_all_strings(raws),
         {:ok, max_rate} <- Methods.parse_feerate(Methods.arg(params, 1), 10_000_000) do
      decoded = Enum.map(raws, &Methods.decode_hex_tx/1)

      if Enum.any?(decoded, &(&1 == :error)) do
        bad = raws |> Enum.zip(decoded) |> Enum.find(fn {_, d} -> d == :error end) |> elem(0)
        {:error, @rpc_deserialization_error, "TX decode failed: #{bad}"}
      else
        txs = Enum.map(decoded, &elem(&1, 1))
        results = Mempool.test_accept(ctx.mempool, txs)
        {:ok, test_accept_json(txs, results, max_rate)}
      end
    end
  end

  defp check_all_strings(list) do
    Enum.find_value(list, :ok, fn item ->
      case Methods.check_type(item, "string", &is_binary/1) do
        :ok -> nil
        err -> err
      end
    end)
  end

  defp test_accept_json([tx], [r], max_rate), do: [one_result(tx, r, max_rate)]

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
    if max_rate > 0 and r.fee > Policy.fee_for(max_rate, r.vsize) do
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

  # Core: submitpackage(package, maxfeerate = 0.10, maxburnamount = 0)
  def submitpackage(params, ctx) do
    raws = Methods.arg(params, 0)

    with :ok <- Methods.check_type(raws, "array", &is_list/1),
         :ok <- check_package_count(raws),
         {:ok, max_rate} <- Methods.parse_feerate(Methods.arg(params, 1), 10_000_000),
         {:ok, max_burn} <- Methods.parse_optional_amount(Methods.arg(params, 2), 0),
         {:ok, txs} <- decode_package_txs(raws, max_burn),
         :ok <- check_package_topology(txs) do
      pkg_res =
        Mempool.submit_package(ctx.mempool, txs,
          unbroadcast: true,
          max_feerate: if(max_rate > 0, do: max_rate)
        )

      submitpackage_json(txs, pkg_res)
    end
  end

  defp check_package_count(raws)
       when raws == [] or length(raws) > @max_package_count,
       do:
         {:error, @rpc_invalid_parameter,
          "Array must contain between 1 and #{@max_package_count} transactions."}

  defp check_package_count(_raws), do: :ok

  defp decode_package_txs(raws, max_burn) do
    res =
      Enum.reduce_while(raws, [], fn rawtx, acc ->
        case Methods.check_type(rawtx, "string", &is_binary/1) do
          {:error, _, _} = err ->
            {:halt, err}

          :ok ->
            case Methods.decode_hex_tx(rawtx) do
              :error ->
                {:halt,
                 {:error, @rpc_deserialization_error,
                  "TX decode failed: #{rawtx} Make sure the tx has at least one input."}}

              {:ok, tx} ->
                if Enum.any?(tx.outputs, fn o ->
                     (Exnode.Script.unspendable?(o.script_pubkey) or
                        not Methods.valid_ops?(o.script_pubkey)) and o.value > max_burn
                   end) do
                  {:halt,
                   {:error, @rpc_verify_error,
                    "Unspendable output exceeds maximum configured by user (maxburnamount)"}}
                else
                  {:cont, [tx | acc]}
                end
            end
        end
      end)

    case res do
      {:error, _, _} = err -> err
      list when is_list(list) -> {:ok, Enum.reverse(list)}
    end
  end

  defp check_package_topology(txs) when length(txs) <= 1, do: :ok

  defp check_package_topology(txs) do
    if child_with_parents_tree?(txs) do
      :ok
    else
      {:error, @rpc_verify_error,
       "package topology disallowed. not child-with-parents or parents depend on each other."}
    end
  end

  # Core IsChildWithParentsTree (policy/packages.cpp)
  defp child_with_parents_tree?(txs) do
    parents = Enum.drop(txs, -1)
    parent_txids = MapSet.new(parents, & &1.txid)

    Package.child_with_parents?(txs) and
      Enum.all?(parents, fn ptx ->
        not Enum.any?(ptx.inputs, &MapSet.member?(parent_txids, &1.prev_hash))
      end)
  end

  defp submitpackage_json(txs, %{state: pkg_state, txs: results}) do
    case pkg_state do
      {:mempool_error, reason, _} ->
        {:error, @rpc_verify_error,
         if(reason in [nil, ""], do: "Mempool internal error", else: reason)}

      _ ->
        package_msg =
          case pkg_state do
            :ok -> "success"
            {_kind, reason, detail} when detail in [nil, ""] -> reason
            {_kind, reason, detail} -> "#{reason}, #{detail}"
          end

        {tx_results, replaced_set} =
          Enum.map_reduce(txs, MapSet.new(), fn tx, replaced ->
            wtxid_hex = hash_hex(tx.wtxid)
            base = [{"txid", hash_hex(tx.txid)}]

            case Map.get(results, tx.wtxid) do
              nil ->
                {{wtxid_hex, obj(base ++ [{"error", "package-not-validated"}])}, replaced}

              {:different_witness, other_wtxid} ->
                {{wtxid_hex, obj(base ++ [{"other-wtxid", hash_hex(other_wtxid)}])}, replaced}

              {:invalid, e} ->
                {{wtxid_hex, obj(base ++ [{"error", state_to_string(e)}])}, replaced}

              {:mempool, r} ->
                inner =
                  base ++
                    [
                      {"vsize_adjusted", r.vsize},
                      {"vsize", r.vsize},
                      {"vsize_bip141", div(Tx.weight(tx) + 3, 4)},
                      {"fees", obj([{"base", amount(r.fee)}])}
                    ]

                {{wtxid_hex, obj(inner)}, replaced}

              {:valid, r} ->
                eff_rate =
                  Map.get_lazy(r, :effective_feerate, fn -> div(r.fee * 1000, r.vsize) end)

                eff_inc = Map.get_lazy(r, :effective_includes, fn -> [tx.wtxid] end)

                fees =
                  obj([
                    {"base", amount(r.fee)},
                    {"effective-feerate", amount(eff_rate)},
                    {"effective-includes", Enum.map(eff_inc, &hash_hex/1)}
                  ])

                inner =
                  base ++
                    [
                      {"vsize_adjusted", r.vsize},
                      {"vsize", r.vsize},
                      {"vsize_bip141", div(Tx.weight(tx) + 3, 4)},
                      {"fees", fees}
                    ]

                replaced = Enum.reduce(Map.get(r, :replaced, []), replaced, &MapSet.put(&2, &1))
                {{wtxid_hex, obj(inner)}, replaced}
            end
          end)

        deduped_tx_results =
          Enum.reduce(tx_results, [], fn {k, v}, acc ->
            if List.keymember?(acc, k, 0),
              do: List.keyreplace(acc, k, 0, {k, v}),
              else: acc ++ [{k, v}]
          end)

        replaced_list = replaced_set |> Enum.sort() |> Enum.map(&hash_hex/1)

        {:ok,
         obj([
           {"package_msg", package_msg},
           {"tx-results", obj(deduped_tx_results)},
           {"replaced-transactions", replaced_list}
         ])}
    end
  end

  defp state_to_string(e) do
    reason =
      e[:reason] ||
        if(e[:result] == :missing_inputs, do: "bad-txns-inputs-missingorspent", else: "")

    if e[:detail] in [nil, ""], do: reason, else: "#{reason}, #{e.detail}"
  end
end
