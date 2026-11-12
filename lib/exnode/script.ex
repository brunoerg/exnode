defmodule Exnode.Script do
  @moduledoc """
  Script *parsing* helpers. Ports of Core v32.1 `script/script.cpp` and
  `script/interpreter.cpp` functions that inspect scripts without executing
  them. Scripts are always executed by the kernel, never here.
  """

  @op_0 0x00
  @op_pushdata1 0x4C
  @op_pushdata2 0x4D
  @op_pushdata4 0x4E
  @op_1 0x51
  @op_16 0x60
  @op_return 0x6A
  @op_equal 0x87
  @op_hash160 0xA9
  @op_checksig 0xAC
  @op_checksigverify 0xAD
  @op_checkmultisig 0xAE
  @op_checkmultisigverify 0xAF
  @op_invalidopcode 0xFF

  # script/script.h
  @max_pubkeys_per_multisig 20
  @max_script_size 10_000

  def max_script_size, do: @max_script_size

  @doc """
  Core `GetScriptOp`. Returns `{:ok, opcode, data, rest}` or `:error`.
  `data` is the pushed bytes for push opcodes, `<<>>` otherwise.
  """
  # Core: GetScriptOp (script/script.cpp)
  def get_op(<<>>), do: :error

  def get_op(<<op, rest::binary>>) when op < @op_pushdata1 do
    case rest do
      <<d::binary-size(op), r::binary>> -> {:ok, op, d, r}
      _ -> :error
    end
  end

  def get_op(<<@op_pushdata1, n, rest::binary>>), do: take_push(@op_pushdata1, n, rest)
  def get_op(<<@op_pushdata2, n::little-16, rest::binary>>), do: take_push(@op_pushdata2, n, rest)
  def get_op(<<@op_pushdata4, n::little-32, rest::binary>>), do: take_push(@op_pushdata4, n, rest)

  def get_op(<<op, _::binary>>) when op in [@op_pushdata1, @op_pushdata2, @op_pushdata4],
    do: :error

  def get_op(<<op, rest::binary>>), do: {:ok, op, <<>>, rest}

  defp take_push(op, n, rest) do
    case rest do
      <<d::binary-size(n), r::binary>> -> {:ok, op, d, r}
      _ -> :error
    end
  end

  @doc "Core `CScript::GetSigOpCount(bool fAccurate)`."
  # Core: CScript::GetSigOpCount(bool) (script/script.cpp)
  def sigop_count(script, accurate), do: count(script, accurate, @op_invalidopcode, 0)

  defp count(script, accurate, last, n) do
    case get_op(script) do
      :error ->
        n

      {:ok, op, _d, rest} ->
        n =
          cond do
            op in [@op_checksig, @op_checksigverify] ->
              n + 1

            op in [@op_checkmultisig, @op_checkmultisigverify] ->
              if accurate and last >= @op_1 and last <= @op_16,
                do: n + decode_op_n(last),
                else: n + @max_pubkeys_per_multisig

            true ->
              n
          end

        count(rest, accurate, op, n)
    end
  end

  @doc "Core `CScript::GetSigOpCount(const CScript& scriptSig)` (P2SH-accurate count)."
  # Core: CScript::GetSigOpCount(const CScript&) (script/script.cpp)
  def p2sh_sigop_count(spk, script_sig) do
    if not p2sh?(spk) do
      sigop_count(spk, true)
    else
      case last_push_if_push_only(script_sig) do
        {:ok, data} -> sigop_count(data, true)
        :error -> 0
      end
    end
  end

  # Walks the script with GetOp: vData is the data of the *last* opcode
  # (cleared by non-push opcodes). Fails if any opcode is above OP_16 or a
  # GetOp fails.
  defp last_push_if_push_only(script), do: last_push(script, <<>>)

  defp last_push(<<>>, data), do: {:ok, data}

  defp last_push(script, _data) do
    case get_op(script) do
      :error -> :error
      {:ok, op, _d, _} when op > @op_16 -> :error
      {:ok, _op, d, rest} -> last_push(rest, d)
    end
  end

  @doc "Core `CScript::IsPayToScriptHash`."
  def p2sh?(<<@op_hash160, 0x14, _::binary-size(20), @op_equal>>), do: true
  def p2sh?(_), do: false

  @doc "Core `CScript::IsWitnessProgram`. Returns `{:ok, version, program}` or `:error`."
  def witness_program(<<v, len, program::binary>> = s)
      when byte_size(s) >= 4 and byte_size(s) <= 42 and
             (v == @op_0 or (v >= @op_1 and v <= @op_16)) do
    if len + 2 == byte_size(s), do: {:ok, decode_op_n(v), program}, else: :error
  end

  def witness_program(_), do: :error

  @doc "Core `CScript::IsPushOnly()`."
  def push_only?(<<>>), do: true

  def push_only?(script) do
    case get_op(script) do
      :error -> false
      {:ok, op, _, _} when op > @op_16 -> false
      {:ok, _, _, rest} -> push_only?(rest)
    end
  end

  @doc "Core `CScript::IsUnspendable()`: starts with OP_RETURN or is longer than MAX_SCRIPT_SIZE."
  def unspendable?(<<@op_return, _::binary>>), do: true
  def unspendable?(s), do: byte_size(s) > @max_script_size

  @doc "Core `CountWitnessSigOps(scriptSig, scriptPubKey, witness, flags)`. `witness?` is the WITNESS flag."
  # Core: CountWitnessSigOps (script/interpreter.cpp)
  def witness_sigops(_script_sig, _spk, _witness, false), do: 0

  def witness_sigops(script_sig, spk, witness, true) do
    case witness_program(spk) do
      {:ok, v, prog} ->
        witness_sigops_for(v, prog, witness)

      :error ->
        with true <- p2sh?(spk) and push_only?(script_sig),
             {:ok, data} <- last_push_if_push_only(script_sig),
             {:ok, v, prog} <- witness_program(data) do
          witness_sigops_for(v, prog, witness)
        else
          _ -> 0
        end
    end
  end

  # Core: WitnessSigOps
  defp witness_sigops_for(0, prog, _w) when byte_size(prog) == 20, do: 1

  defp witness_sigops_for(0, prog, [_ | _] = w) when byte_size(prog) == 32,
    do: sigop_count(List.last(w), true)

  defp witness_sigops_for(_, _, _), do: 0

  defp decode_op_n(@op_0), do: 0
  defp decode_op_n(op) when op >= @op_1 and op <= @op_16, do: op - (@op_1 - 1)

  @doc "Core `CScript() << n` for a non-negative block height (BIP34 coinbase prefix)."
  def push_int(n) when n == 0, do: <<@op_0>>
  def push_int(n) when n >= 1 and n <= 16, do: <<n + (@op_1 - 1)>>
  def push_int(-1), do: <<0x4F>>

  def push_int(n) do
    data = scriptnum(n)
    <<byte_size(data)>> <> data
  end

  # CScriptNum::serialize
  defp scriptnum(n) do
    import Bitwise
    neg = n < 0
    bytes = :binary.encode_unsigned(abs(n), :little)
    last = :binary.last(bytes)

    cond do
      (last &&& 0x80) != 0 -> bytes <> <<if(neg, do: 0x80, else: 0)>>
      neg -> binary_part(bytes, 0, byte_size(bytes) - 1) <> <<last ||| 0x80>>
      true -> bytes
    end
  end
end
