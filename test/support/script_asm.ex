defmodule Exnode.Test.ScriptAsm do
  @moduledoc """
  Test-only port of Core v32.1 `ParseScript` (src/core_io.cpp), used to decode
  the scriptPubKeys in Core's JSON test vectors.

  The opcode map is built like `OpCodeParser`: opcodes 0x61 (OP_NOP) through
  MAX_OPCODE (OP_NOP10 = 0xb9), plus OP_RESERVED. Each is accepted with and
  without the `OP_` prefix.
  """
  import Bitwise

  # script/script.h opcodetype values with GetOpName names (script/script.cpp).
  @names ~w(OP_NOP OP_VER OP_IF OP_NOTIF OP_VERIF OP_VERNOTIF OP_ELSE OP_ENDIF OP_VERIFY OP_RETURN
            OP_TOALTSTACK OP_FROMALTSTACK OP_2DROP OP_2DUP OP_3DUP OP_2OVER OP_2ROT OP_2SWAP OP_IFDUP
            OP_DEPTH OP_DROP OP_DUP OP_NIP OP_OVER OP_PICK OP_ROLL OP_ROT OP_SWAP OP_TUCK OP_CAT
            OP_SUBSTR OP_LEFT OP_RIGHT OP_SIZE OP_INVERT OP_AND OP_OR OP_XOR OP_EQUAL OP_EQUALVERIFY
            OP_RESERVED1 OP_RESERVED2 OP_1ADD OP_1SUB OP_2MUL OP_2DIV OP_NEGATE OP_ABS OP_NOT
            OP_0NOTEQUAL OP_ADD OP_SUB OP_MUL OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT OP_BOOLAND OP_BOOLOR
            OP_NUMEQUAL OP_NUMEQUALVERIFY OP_NUMNOTEQUAL OP_LESSTHAN OP_GREATERTHAN OP_LESSTHANOREQUAL
            OP_GREATERTHANOREQUAL OP_MIN OP_MAX OP_WITHIN OP_RIPEMD160 OP_SHA1 OP_SHA256 OP_HASH160
            OP_HASH256 OP_CODESEPARATOR OP_CHECKSIG OP_CHECKSIGVERIFY OP_CHECKMULTISIG
            OP_CHECKMULTISIGVERIFY OP_NOP1 OP_CHECKLOCKTIMEVERIFY OP_CHECKSEQUENCEVERIFY OP_NOP4
            OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10)

  @opmap @names
         |> Enum.with_index(0x61)
         |> Enum.concat([{"OP_RESERVED", 0x50}])
         |> Enum.flat_map(fn {n, op} -> [{n, op}, {String.replace_prefix(n, "OP_", ""), op}] end)
         |> Map.new()

  def parse(s) do
    s
    |> String.split([" ", "\t", "\n"])
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&word/1)
    |> IO.iodata_to_binary()
  end

  defp word(w) do
    cond do
      Regex.match?(~r/^-?\d+$/, w) and w != "-" ->
        n = String.to_integer(w)
        if n > 0xFFFFFFFF or n < -0xFFFFFFFF, do: raise("script parse error: numeric range")
        push_int64(n)

      String.starts_with?(w, "0x") and byte_size(w) > 2 ->
        Base.decode16!(binary_part(w, 2, byte_size(w) - 2), case: :mixed)

      byte_size(w) >= 2 and String.starts_with?(w, "'") and String.ends_with?(w, "'") ->
        push_data(binary_part(w, 1, byte_size(w) - 2))

      true ->
        case Map.fetch(@opmap, w) do
          {:ok, op} -> <<op>>
          :error -> raise "script parse error: unknown opcode #{w}"
        end
    end
  end

  # CScript::push_int64
  defp push_int64(n) when n == -1 or (n >= 1 and n <= 16), do: <<n + 0x50>>
  defp push_int64(0), do: <<0>>
  defp push_int64(n), do: push_data(scriptnum_serialize(n))

  # CScriptNum::serialize
  def scriptnum_serialize(0), do: <<>>

  def scriptnum_serialize(n) do
    neg = n < 0
    bytes = abs(n) |> :binary.encode_unsigned(:little)
    last = :binary.last(bytes)

    cond do
      (last &&& 0x80) != 0 -> bytes <> <<if(neg, do: 0x80, else: 0)>>
      neg -> binary_part(bytes, 0, byte_size(bytes) - 1) <> <<last ||| 0x80>>
      true -> bytes
    end
  end

  # CScript::operator<<(std::span<const std::byte>)
  def push_data(d) when byte_size(d) < 0x4C, do: <<byte_size(d)>> <> d
  def push_data(d) when byte_size(d) <= 0xFF, do: <<0x4C, byte_size(d)>> <> d
  def push_data(d) when byte_size(d) <= 0xFFFF, do: <<0x4D, byte_size(d)::little-16>> <> d
  def push_data(d), do: <<0x4E, byte_size(d)::little-32>> <> d
end
