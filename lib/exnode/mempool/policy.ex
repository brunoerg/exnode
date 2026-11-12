defmodule Exnode.Mempool.Policy do
  @moduledoc """
  Standardness policy. Ports of Core v32.1 `policy/policy.cpp`,
  `script/solver.cpp` and the constants of `policy/policy.h`.

  Policy is not consensus: these rules decide what the mempool accepts and
  relays, never block validity. Script execution policy flags
  (`STANDARD_SCRIPT_VERIFY_FLAGS`) are not available through the kernel's C
  API, so the mempool checks scripts with the tip's consensus flags only and
  accepts some scripts Core rejects as non-standard (non-minimal pushes,
  high-S, NULLFAIL, discouraged upgradable NOPs and witness versions,
  CLEANSTACK, MINIMALIF, CONST_SCRIPTCODE, taproot policy). Script failures
  report `mempool-script-verify-flag-failed` without Core's
  `(<ScriptError>)` suffix.
  """
  import Bitwise

  alias Exnode.Codec.{CompactSize, Tx}
  alias Exnode.Script

  # policy/policy.h
  @max_standard_tx_weight 400_000
  @min_standard_tx_nonwitness_size 65
  @max_p2sh_sigops 15
  @max_standard_tx_sigops_cost div(80_000, 5)
  @max_tx_legacy_sigops 2_500
  @default_bytes_per_sigop 20
  @max_standard_p2wsh_stack_items 100
  @max_standard_p2wsh_stack_item_size 80
  @max_standard_tapscript_stack_item_size 80
  @max_standard_p2wsh_script_size 3600
  @max_standard_scriptsig_size 1650
  @dust_relay_tx_fee 3000
  @default_min_relay_tx_fee 100
  @default_incremental_relay_fee 100
  @max_op_return_relay div(@max_standard_tx_weight, 4)
  @max_dust_outputs_per_tx 1
  @tx_min_standard_version 1
  @tx_max_standard_version 3

  # script/script.h, interpreter.h
  @max_script_element_size 520
  @max_stack_size 1000
  @max_pubkeys_per_multisig 20
  @annex_tag 0x50
  @taproot_leaf_mask 0xFE
  @taproot_leaf_tapscript 0xC0

  def min_standard_tx_nonwitness_size, do: @min_standard_tx_nonwitness_size
  def max_standard_tx_sigops_cost, do: @max_standard_tx_sigops_cost
  def dust_relay_tx_fee, do: @dust_relay_tx_fee
  def default_min_relay_tx_fee, do: @default_min_relay_tx_fee
  def default_incremental_relay_fee, do: @default_incremental_relay_fee
  def max_op_return_relay, do: @max_op_return_relay
  def bytes_per_sigop, do: @default_bytes_per_sigop

  # --- fee rates (policy/feerate.cpp, util/feefrac.h) ---------------------------

  @doc """
  Core `CFeeRate(rate_per_kvb).GetFee(vbytes)`: the fee for `vbytes` at
  `rate` sat/kvB, rounded **up** (`FeeFrac::EvaluateFeeUp`).
  """
  # Core: CFeeRate::GetFee (policy/feerate.cpp)
  def fee_for(_rate, 0), do: 0
  def fee_for(rate, vbytes) when rate >= 0, do: div(rate * vbytes + 999, 1000)

  def fee_for(rate, vbytes) do
    # Negative rates: FeeFrac's Div rounds towards +infinity for "up".
    q = -div(-rate * vbytes, 1000)
    if q == 0, do: -1, else: q
  end

  # --- solver (script/solver.cpp) -----------------------------------------------

  @doc """
  Core `Solver`. Returns `{type, solutions}` with `type` one of
  `:scripthash, :witness_v0_keyhash, :witness_v0_scripthash,
  :witness_v1_taproot, :anchor, :witness_unknown, :null_data, :pubkey,
  :pubkeyhash, :multisig, :nonstandard`.
  """
  # Core: Solver (script/solver.cpp)
  def solver(<<0xA9, 0x14, h::binary-size(20), 0x87>>), do: {:scripthash, [h]}

  def solver(spk) do
    case Script.witness_program(spk) do
      {:ok, 0, p} when byte_size(p) == 20 -> {:witness_v0_keyhash, [p]}
      {:ok, 0, p} when byte_size(p) == 32 -> {:witness_v0_scripthash, [p]}
      {:ok, 1, p} when byte_size(p) == 32 -> {:witness_v1_taproot, [p]}
      {:ok, 1, <<0x4E, 0x73>>} -> {:anchor, []}
      {:ok, v, p} when v != 0 -> {:witness_unknown, [<<v>>, p]}
      {:ok, 0, _} -> {:nonstandard, []}
      :error -> solve_legacy(spk)
    end
  end

  defp solve_legacy(<<0x6A, rest::binary>>) do
    if Script.push_only?(rest), do: {:null_data, []}, else: solve_legacy2(<<0x6A, rest::binary>>)
  end

  defp solve_legacy(spk), do: solve_legacy2(spk)

  defp solve_legacy2(spk) do
    cond do
      (pk = match_pay_to_pubkey(spk)) != nil -> {:pubkey, [pk]}
      (h = match_pay_to_pubkey_hash(spk)) != nil -> {:pubkeyhash, [h]}
      (ms = match_multisig(spk)) != nil -> ms
      true -> {:nonstandard, []}
    end
  end

  # Core: MatchPayToPubkey
  defp match_pay_to_pubkey(<<65, pk::binary-size(65), 0xAC>>),
    do: if(valid_pubkey_size?(pk), do: pk)

  defp match_pay_to_pubkey(<<33, pk::binary-size(33), 0xAC>>),
    do: if(valid_pubkey_size?(pk), do: pk)

  defp match_pay_to_pubkey(_), do: nil

  # Core: MatchPayToPubkeyHash
  defp match_pay_to_pubkey_hash(<<0x76, 0xA9, 20, h::binary-size(20), 0x88, 0xAC>>), do: h
  defp match_pay_to_pubkey_hash(_), do: nil

  # Core: CPubKey::ValidSize / GetLen
  defp valid_pubkey_size?(<<h, _::binary>> = pk) when h in [2, 3], do: byte_size(pk) == 33
  defp valid_pubkey_size?(<<h, _::binary>> = pk) when h in [4, 6, 7], do: byte_size(pk) == 65
  defp valid_pubkey_size?(_), do: false

  # Core: MatchMultisig
  defp match_multisig(spk) when byte_size(spk) < 1, do: nil

  defp match_multisig(spk) do
    if :binary.last(spk) != 0xAE do
      nil
    else
      with {:ok, op, data, rest} <- Script.get_op(spk),
           {:ok, req} <- script_number(op, data, 1, @max_pubkeys_per_multisig),
           {keys, op2, data2, rest2} <- take_keys(rest, []),
           {:ok, n} <- script_number(op2, data2, req, @max_pubkeys_per_multisig),
           true <- length(keys) == n,
           <<0xAE>> <- rest2 do
        {:multisig, [<<req>>] ++ keys ++ [<<n>>]}
      else
        _ -> nil
      end
    end
  end

  # `while (GetOp(...) && ValidSize(data)) pubkeys.push(data)`: returns the
  # keys and the first op that is not a valid key push (GetOp must succeed).
  defp take_keys(script, acc) do
    case Script.get_op(script) do
      {:ok, op, data, rest} ->
        if valid_pubkey_size?(data),
          do: take_keys(rest, [data | acc]),
          else: {Enum.reverse(acc), op, data, rest}

      :error ->
        :error
    end
  end

  # Core: GetScriptNumber (script/solver.cpp)
  defp script_number(op, data, min, max) do
    count =
      cond do
        op >= 0x51 and op <= 0x60 ->
          {:ok, op - 0x50}

        op > 0x00 and op <= 0x4E ->
          if(minimal_push?(data, op), do: script_num(data), else: :error)

        true ->
          :error
      end

    case count do
      {:ok, c} when c >= min and c <= max -> {:ok, c}
      _ -> :error
    end
  end

  @doc "Core `CheckMinimalPush`."
  # Core: CheckMinimalPush (script/script.cpp)
  def minimal_push?(<<>>, op), do: op == 0x00
  def minimal_push?(<<b>>, _op) when b >= 1 and b <= 16, do: false
  def minimal_push?(<<0x81>>, _op), do: false
  def minimal_push?(d, op) when byte_size(d) <= 75, do: op == byte_size(d)
  def minimal_push?(d, op) when byte_size(d) <= 255, do: op == 0x4C
  def minimal_push?(d, op) when byte_size(d) <= 65_535, do: op == 0x4D
  def minimal_push?(_d, _op), do: true

  # Core: CScriptNum(vch, fRequireMinimal = true) with nMaxNumSize = 4, getint()
  defp script_num(d) when byte_size(d) > 4, do: :error
  defp script_num(<<>>), do: {:ok, 0}

  defp script_num(d) do
    last = :binary.last(d)
    n = byte_size(d)

    minimal =
      (last &&& 0x7F) != 0 or (n > 1 and (:binary.at(d, n - 2) &&& 0x80) != 0)

    if minimal do
      v = :binary.decode_unsigned(d, :little)
      sign_bit = 1 <<< (8 * n - 1)
      {:ok, if((v &&& sign_bit) != 0, do: -(v &&& sign_bit - 1), else: v)}
    else
      :error
    end
  end

  @doc "Core `IsStandard(scriptPubKey, whichType)`: `{:ok, type}` or `{:error, type}`."
  # Core: IsStandard (policy/policy.cpp)
  def standard_output(spk) do
    case solver(spk) do
      {:nonstandard, _} = t ->
        {:error, elem(t, 0)}

      {:multisig, sols} ->
        <<m>> = hd(sols)
        <<n>> = List.last(sols)
        if n < 1 or n > 3 or m < 1 or m > n, do: {:error, :multisig}, else: {:ok, :multisig}

      {type, _} ->
        {:ok, type}
    end
  end

  # --- dust ---------------------------------------------------------------------

  @doc "Core `GetDustThreshold(txout, dustRelayFee)`."
  # Core: GetDustThreshold (policy/policy.cpp)
  def dust_threshold(%Tx.Out{script_pubkey: spk}, rate \\ @dust_relay_tx_fee) do
    if Script.unspendable?(spk) do
      0
    else
      # GetSerializeSize(txout) = 8 (value) + CompactSize(len) + len
      size = 8 + IO.iodata_length(CompactSize.encode_bytes(spk))

      size =
        case Script.witness_program(spk) do
          {:ok, _, _} -> size + (32 + 4 + 1 + div(107, 4) + 4)
          :error -> size + (32 + 4 + 1 + 107 + 4)
        end

      fee_for(rate, size)
    end
  end

  @doc "Core `IsDust`."
  def dust?(%Tx.Out{value: v} = out, rate \\ @dust_relay_tx_fee),
    do: v < dust_threshold(out, rate)

  @doc "Core `GetDust`: indices of dust outputs."
  def dust_outputs(%Tx{outputs: outs}, rate \\ @dust_relay_tx_fee) do
    for {o, i} <- Enum.with_index(outs), dust?(o, rate), do: i
  end

  # --- IsStandardTx ---------------------------------------------------------------

  @doc """
  Core `IsStandardTx(tx, max_datacarrier_bytes, permit_bare_multisig,
  dust_relay_fee, reason)`. Returns `:ok` or `{:error, reason}`.
  Options: `:max_datacarrier_bytes` (default `MAX_OP_RETURN_RELAY`; `nil`
  disables data carrier outputs), `:permit_bare_multisig` (default true),
  `:dust_relay_fee` (default 3000 sat/kvB).
  """
  # Core: IsStandardTx (policy/policy.cpp)
  def standard_tx(%Tx{} = tx, opts \\ []) do
    datacarrier = Keyword.get(opts, :max_datacarrier_bytes, @max_op_return_relay)
    bare_multisig = Keyword.get(opts, :permit_bare_multisig, true)
    dust_rate = Keyword.get(opts, :dust_relay_fee, @dust_relay_tx_fee)

    cond do
      tx.version > @tx_max_standard_version or tx.version < @tx_min_standard_version ->
        {:error, "version"}

      Tx.weight(tx) > @max_standard_tx_weight ->
        {:error, "tx-size"}

      (r = check_inputs(tx.inputs)) != :ok ->
        r

      (r = check_outputs(tx.outputs, datacarrier || 0, bare_multisig)) != :ok ->
        r

      length(dust_outputs(tx, dust_rate)) > @max_dust_outputs_per_tx ->
        {:error, "dust"}

      true ->
        :ok
    end
  end

  defp check_inputs(inputs) do
    Enum.find_value(inputs, :ok, fn i ->
      cond do
        byte_size(i.script_sig) > @max_standard_scriptsig_size -> {:error, "scriptsig-size"}
        not Script.push_only?(i.script_sig) -> {:error, "scriptsig-not-pushonly"}
        true -> nil
      end
    end)
  end

  defp check_outputs([], _left, _bare), do: :ok

  defp check_outputs([o | rest], left, bare) do
    case standard_output(o.script_pubkey) do
      {:error, _} ->
        {:error, "scriptpubkey"}

      {:ok, :null_data} ->
        size = byte_size(o.script_pubkey)
        if size > left, do: {:error, "datacarrier"}, else: check_outputs(rest, left - size, bare)

      {:ok, :multisig} when not bare ->
        {:error, "bare-multisig"}

      {:ok, _} ->
        check_outputs(rest, left, bare)
    end
  end

  # --- inputs (need the spent outputs) -----------------------------------------

  @doc """
  Core `ValidateInputsStandardness(tx, view)`. `coins` are the spent outputs'
  scriptPubKeys, in input order. Returns `:ok` or
  `{:error, "bad-txns-nonstandard-inputs", detail}`.
  """
  # Core: ValidateInputsStandardness (policy/policy.cpp)
  def inputs_standard(%Tx{} = tx, spks) do
    if not sigops_bip54_ok?(tx, spks) do
      {:error, "bad-txns-nonstandard-inputs", "non-witness sigops exceed bip54 limit"}
    else
      tx.inputs
      |> Enum.zip(spks)
      |> Enum.with_index()
      |> Enum.find_value(:ok, fn {{input, spk}, i} -> input_standard(input, spk, i) end)
    end
  end

  defp input_standard(input, spk, i) do
    case solver(spk) do
      {:nonstandard, _} ->
        {:error, "bad-txns-nonstandard-inputs", "input #{i} script unknown"}

      {:witness_unknown, _} ->
        {:error, "bad-txns-nonstandard-inputs", "input #{i} witness program is undefined"}

      {:scripthash, _} ->
        case eval_push_only(input.script_sig) do
          {:error, e} ->
            {:error, "bad-txns-nonstandard-inputs", "p2sh scriptsig malformed (input #{i}: #{e})"}

          {:ok, []} ->
            {:error, "bad-txns-nonstandard-inputs", "input #{i} P2SH redeemscript missing"}

          {:ok, stack} ->
            n = Script.sigop_count(List.last(stack), true)

            if n > @max_p2sh_sigops,
              do:
                {:error, "bad-txns-nonstandard-inputs",
                 "p2sh redeemscript sigops exceed limit (input #{i}: #{n} > #{@max_p2sh_sigops})"},
              else: nil
        end

      _ ->
        nil
    end
  end

  # Core: CheckSigopsBIP54 (policy/policy.cpp)
  defp sigops_bip54_ok?(tx, spks) do
    tx.inputs
    |> Enum.zip(spks)
    |> Enum.reduce_while(0, fn {i, spk}, acc ->
      acc = acc + Script.sigop_count(i.script_sig, true) + spk_sigops_for(spk, i.script_sig)
      if acc > @max_tx_legacy_sigops, do: {:halt, :over}, else: {:cont, acc}
    end)
    |> Kernel.!=(:over)
  end

  # Core: CScript::GetSigOpCount(const CScript& scriptSig): the accurate
  # count of a P2SH redeem script, else the accurate count of the script.
  defp spk_sigops_for(spk, script_sig) do
    if Script.p2sh?(spk),
      do: Script.p2sh_sigop_count(spk, script_sig),
      else: Script.sigop_count(spk, true)
  end

  @doc """
  Core `EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE, ...)` restricted to
  what a push-only scriptSig can do: push data, OP_1NEGATE and OP_1..OP_16;
  OP_RESERVED fails. Returns `{:ok, stack}` (bottom first) or
  `{:error, script_error_string}`.
  """
  # Core: EvalScript (script/interpreter.cpp), push-only subset
  def eval_push_only(script) when byte_size(script) > 10_000, do: {:error, "Script is too big"}
  def eval_push_only(script), do: eval_pushes(script, [], 0)

  defp eval_pushes(<<>>, acc, _n), do: {:ok, Enum.reverse(acc)}

  defp eval_pushes(script, acc, n) do
    case Script.get_op(script) do
      :error ->
        {:error, "Opcode missing or not understood"}

      {:ok, op, data, rest} ->
        cond do
          byte_size(data) > @max_script_element_size -> {:error, "Push value size limit exceeded"}
          op <= 0x4E -> push(rest, [data | acc], n + 1)
          op == 0x4F -> push(rest, [<<0x81>> | acc], n + 1)
          op >= 0x51 and op <= 0x60 -> push(rest, [<<op - 0x50>> | acc], n + 1)
          # OP_RESERVED (and anything else) executed: bad opcode. Callers
          # have already required push-only, so nothing else reaches here.
          true -> {:error, "Opcode missing or not understood"}
        end
    end
  end

  defp push(rest, acc, n) when n > @max_stack_size,
    do:
      (
        _ = rest
        _ = acc
        {:error, "Stack size limit exceeded"}
      )

  defp push(rest, acc, n), do: eval_pushes(rest, acc, n)

  @doc "Core `IsWitnessStandard(tx, view)`. `spks` in input order."
  # Core: IsWitnessStandard (policy/policy.cpp)
  def witness_standard?(%Tx{} = tx, spks) do
    tx.inputs
    |> Enum.zip(spks)
    |> Enum.all?(fn {input, spk} ->
      input.witness == [] or input_witness_standard?(input, spk)
    end)
  end

  defp input_witness_standard?(input, spk) do
    if spk == <<0x51, 0x02, 0x4E, 0x73>> do
      # Witness stuffing on a pay-to-anchor output.
      false
    else
      {script, p2sh} =
        if Script.p2sh?(spk) do
          case eval_push_only_any(input.script_sig) do
            {:ok, [_ | _] = stack} -> {List.last(stack), true}
            _ -> {nil, true}
          end
        else
          {spk, false}
        end

      script != nil and witness_program_standard?(script, p2sh, input.witness)
    end
  end

  # IsWitnessStandard does not require push-only here; IsStandardTx did
  # earlier in PreChecks, so the push-only evaluator suffices.
  defp eval_push_only_any(script_sig), do: eval_push_only(script_sig)

  defp witness_program_standard?(script, p2sh, witness) do
    case Script.witness_program(script) do
      :error ->
        false

      {:ok, 0, prog} when byte_size(prog) == 32 ->
        items = Enum.drop(witness, -1)

        byte_size(List.last(witness)) <= @max_standard_p2wsh_script_size and
          length(items) <= @max_standard_p2wsh_stack_items and
          Enum.all?(items, &(byte_size(&1) <= @max_standard_p2wsh_stack_item_size))

      {:ok, 1, prog} when byte_size(prog) == 32 and not p2sh ->
        taproot_witness_standard?(witness)

      {:ok, _, _} ->
        true
    end
  end

  defp taproot_witness_standard?(stack) do
    n = length(stack)
    last = List.last(stack)

    cond do
      n >= 2 and last != <<>> and :binary.first(last) == @annex_tag ->
        false

      n >= 2 ->
        [control | rev_rest] = Enum.reverse(stack)
        [_script | rev_items] = rev_rest

        cond do
          control == <<>> ->
            false

          (:binary.first(control) &&& @taproot_leaf_mask) == @taproot_leaf_tapscript ->
            Enum.all?(rev_items, &(byte_size(&1) <= @max_standard_tapscript_stack_item_size))

          true ->
            true
        end

      n == 1 ->
        true

      true ->
        false
    end
  end

  @doc "Core `SpendsNonAnchorWitnessProg(tx, view)`."
  # Core: SpendsNonAnchorWitnessProg (policy/policy.cpp)
  def spends_non_anchor_witness_prog?(%Tx{} = tx, spks) do
    tx.inputs
    |> Enum.zip(spks)
    |> Enum.any?(fn {input, spk} ->
      case Script.witness_program(spk) do
        {:ok, 1, <<0x4E, 0x73>>} ->
          false

        {:ok, _, _} ->
          true

        :error ->
          Script.p2sh?(spk) and
            match?({:ok, [_ | _]}, eval_push_only(input.script_sig)) and
            match?(
              {:ok, _, _},
              Script.witness_program(List.last(elem(eval_push_only(input.script_sig), 1)))
            )
      end
    end)
  end

  # --- sizes ---------------------------------------------------------------------

  @doc "Core `GetVirtualTransactionSize(weight, sigop_cost, bytes_per_sigop)`."
  # Core: GetVirtualTransactionSize / GetSigOpsAdjustedWeight (policy/policy.cpp)
  def vsize(weight, sigop_cost, bytes_per_sigop \\ @default_bytes_per_sigop),
    do: div(max(weight, sigop_cost * bytes_per_sigop) + 3, 4)
end
