defmodule Exnode.RPC.JSON do
  @moduledoc """
  JSON encoding helpers that reproduce Core v32.1's RPC output:
  `ValueFromAmount` (exact 8-decimal numbers), `ScriptToAsmStr`,
  `ScriptToUniv`, `InferDescriptor` with the dummy signing provider, and
  `DescriptorChecksum` (core_io.cpp, script/descriptor.cpp).

  Objects are `Jason.OrderedObject`s, so keys come out in Core's order.
  """
  import Bitwise

  alias Exnode.Mempool.Policy
  alias Exnode.Script

  def obj(kv), do: Jason.OrderedObject.new(kv)

  @doc "Core `ValueFromAmount`: satoshis as a JSON number with exactly 8 decimals."
  # Core: ValueFromAmount (core_io.cpp)
  def amount(sat) do
    sign = if sat < 0, do: "-", else: ""
    a = abs(sat)

    Jason.Fragment.new(
      sign <> "#{div(a, 100_000_000)}." <> String.pad_leading("#{rem(a, 100_000_000)}", 8, "0")
    )
  end

  @doc """
  A double as UniValue prints it: C++ `ostream << setprecision(16)`, i.e.
  `%.16g` (16 significant digits, trailing zeros dropped).
  """
  def double(x) when is_integer(x), do: double(x * 1.0)
  def double(x) when x == 0, do: Jason.Fragment.new("0")

  def double(x) do
    sci = :erlang.float_to_binary(x, [{:scientific, 15}])
    [mant, exp] = String.split(sci, "e")
    e = String.to_integer(exp)

    text =
      if e < -4 or e >= 16 do
        m = mant |> String.trim_trailing("0") |> String.trim_trailing(".")
        sign = if e < 0, do: "-", else: "+"
        m <> "e" <> sign <> String.pad_leading(Integer.to_string(abs(e)), 2, "0")
      else
        :erlang.float_to_binary(x, [{:decimals, max(15 - e, 0)}]) |> trim_fixed()
      end

    Jason.Fragment.new(text)
  end

  defp trim_fixed(s),
    do:
      if(String.contains?(s, "."),
        do: s |> String.trim_trailing("0") |> String.trim_trailing("."),
        else: s
      )

  @doc "Display hex of a hash (byte-reversed)."
  def hash_hex(h), do: Exnode.Crypto.Hash.to_hex(h)
  def hex(b), do: Base.encode16(b, case: :lower)

  # --- asm -----------------------------------------------------------------------

  @names %{
    0x00 => "0",
    0x4C => "OP_PUSHDATA1",
    0x4D => "OP_PUSHDATA2",
    0x4E => "OP_PUSHDATA4",
    0x4F => "-1",
    0x50 => "OP_RESERVED",
    0xFF => "OP_INVALIDOPCODE"
  }
  @ops_61 ~w(OP_NOP OP_VER OP_IF OP_NOTIF OP_VERIF OP_VERNOTIF OP_ELSE OP_ENDIF OP_VERIFY OP_RETURN OP_TOALTSTACK
             OP_FROMALTSTACK OP_2DROP OP_2DUP OP_3DUP OP_2OVER OP_2ROT OP_2SWAP OP_IFDUP OP_DEPTH OP_DROP OP_DUP OP_NIP
             OP_OVER OP_PICK OP_ROLL OP_ROT OP_SWAP OP_TUCK OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_SIZE OP_INVERT OP_AND
             OP_OR OP_XOR OP_EQUAL OP_EQUALVERIFY OP_RESERVED1 OP_RESERVED2 OP_1ADD OP_1SUB OP_2MUL OP_2DIV OP_NEGATE
             OP_ABS OP_NOT OP_0NOTEQUAL OP_ADD OP_SUB OP_MUL OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT OP_BOOLAND OP_BOOLOR
             OP_NUMEQUAL OP_NUMEQUALVERIFY OP_NUMNOTEQUAL OP_LESSTHAN OP_GREATERTHAN OP_LESSTHANOREQUAL
             OP_GREATERTHANOREQUAL OP_MIN OP_MAX OP_WITHIN OP_RIPEMD160 OP_SHA1 OP_SHA256 OP_HASH160 OP_HASH256
             OP_CODESEPARATOR OP_CHECKSIG OP_CHECKSIGVERIFY OP_CHECKMULTISIG OP_CHECKMULTISIGVERIFY OP_NOP1
             OP_CHECKLOCKTIMEVERIFY OP_CHECKSEQUENCEVERIFY OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10
             OP_CHECKSIGADD)

  @doc "Core `GetOpName`."
  def op_name(op) when op >= 0x51 and op <= 0x60, do: Integer.to_string(op - 0x50)
  def op_name(op) when op >= 0x61 and op <= 0xBA, do: Enum.at(@ops_61, op - 0x61)
  def op_name(op), do: Map.get(@names, op, "OP_UNKNOWN")

  @sighash %{
    0x01 => "ALL",
    0x81 => "ALL|ANYONECANPAY",
    0x02 => "NONE",
    0x82 => "NONE|ANYONECANPAY",
    0x03 => "SINGLE",
    0x83 => "SINGLE|ANYONECANPAY"
  }

  @doc "Core `ScriptToAsmStr(script, fAttemptSighashDecode)`."
  # Core: ScriptToAsmStr (core_io.cpp)
  def asm(script, sighash_decode \\ false) do
    unspendable = Script.unspendable?(script)
    asm_loop(script, sighash_decode and not unspendable, [])
  end

  defp asm_loop(<<>>, _sd, acc), do: acc |> Enum.reverse() |> Enum.join(" ")

  defp asm_loop(script, sd, acc) do
    case Script.get_op(script) do
      :error ->
        [Enum.join(Enum.reverse(acc), " "), "[error]"]
        |> Enum.reject(&(&1 == ""))
        |> Enum.join(" ")

      {:ok, op, data, rest} when op <= 0x4E ->
        s =
          cond do
            byte_size(data) <= 4 ->
              Integer.to_string(script_num(data))

            sd and strict_sig?(data) and Map.has_key?(@sighash, :binary.last(data)) ->
              hex(binary_part(data, 0, byte_size(data) - 1)) <>
                "[" <> @sighash[:binary.last(data)] <> "]"

            true ->
              hex(data)
          end

        asm_loop(rest, sd, [s | acc])

      {:ok, op, _, rest} ->
        asm_loop(rest, sd, [op_name(op) | acc])
    end
  end

  # CScriptNum(vch, fRequireMinimal = false).getint()
  defp script_num(<<>>), do: 0

  defp script_num(d) do
    n = byte_size(d)
    v = :binary.decode_unsigned(d, :little)
    sign = 1 <<< (8 * n - 1)
    r = if (v &&& sign) != 0, do: -(v &&& sign - 1), else: v
    max(min(r, 0x7FFFFFFF), -0x80000000)
  end

  # CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC): DER, then a defined hashtype.
  defp strict_sig?(sig), do: der?(sig) and band(:binary.last(sig), bnot(0x80)) in 1..3

  # Core: IsValidSignatureEncoding (script/interpreter.cpp)
  defp der?(sig) do
    n = byte_size(sig)

    with true <- n >= 9 and n <= 73,
         <<0x30, len, 0x02, len_r, _::binary>> <- sig,
         true <- len == n - 3,
         true <- 5 + len_r < n,
         len_s = :binary.at(sig, 5 + len_r),
         true <- len_r + len_s + 7 == n,
         true <- len_r != 0,
         r0 = :binary.at(sig, 4),
         true <- (r0 &&& 0x80) == 0,
         true <- not (len_r > 1 and r0 == 0 and (:binary.at(sig, 5) &&& 0x80) == 0),
         true <- :binary.at(sig, len_r + 4) == 0x02,
         true <- len_s != 0,
         s0 = :binary.at(sig, len_r + 6),
         true <- (s0 &&& 0x80) == 0,
         true <- not (len_s > 1 and s0 == 0 and (:binary.at(sig, len_r + 7) &&& 0x80) == 0) do
      true
    else
      _ -> false
    end
  end

  # --- ScriptToUniv / descriptors --------------------------------------------------------

  @types %{
    pubkey: "pubkey",
    pubkeyhash: "pubkeyhash",
    scripthash: "scripthash",
    multisig: "multisig",
    null_data: "nulldata",
    witness_v0_keyhash: "witness_v0_keyhash",
    witness_v0_scripthash: "witness_v0_scripthash",
    witness_v1_taproot: "witness_v1_taproot",
    witness_unknown: "witness_unknown",
    anchor: "anchor",
    nonstandard: "nonstandard"
  }

  @doc "Core `GetTxnOutputType`."
  def type_name(type), do: Map.fetch!(@types, type)

  @doc "Core `ScriptToUniv(script, out, include_hex, include_address)` (dummy provider)."
  # Core: ScriptToUniv (core_io.cpp)
  def script_to_univ(spk, network, include_hex \\ true, include_address \\ true) do
    {type, _} = Policy.solver(spk)
    address = include_address and type != :pubkey and Exnode.Address.from_script(spk, network)

    [{"asm", asm(spk)}] ++
      if(include_address, do: [{"desc", infer_descriptor(spk, network)}], else: []) ++
      if(include_hex, do: [{"hex", hex(spk)}], else: []) ++
      if(address, do: [{"address", address}], else: []) ++
      [{"type", type_name(type)}]
  end

  @doc "Core `InferDescriptor(script, DUMMY_SIGNING_PROVIDER)->ToString()`, with checksum."
  # Core: InferScript (script/descriptor.cpp), TOP context, no keys or scripts known.
  def infer_descriptor(spk, network) do
    desc =
      case Policy.solver(spk) do
        {:pubkey, [pk]} ->
          if valid_non_hybrid?(pk), do: "pk(#{hex(pk)})", else: addr_or_raw(spk, network)

        {:multisig, [<<k>> | rest]} ->
          keys = Enum.drop(rest, -1)

          if Enum.all?(keys, &valid_non_hybrid?/1),
            do: "multi(#{k},#{Enum.map_join(keys, ",", &hex/1)})",
            else: addr_or_raw(spk, network)

        {:witness_v1_taproot, [x]} ->
          if xonly_valid?(x), do: "rawtr(#{hex(x)})", else: addr_or_raw(spk, network)

        _ ->
          addr_or_raw(spk, network)
      end

    desc <> "#" <> checksum(desc)
  end

  defp addr_or_raw(spk, network) do
    case Exnode.Address.from_script(spk, network) do
      nil -> "raw(#{hex(spk)})"
      a -> "addr(#{a})"
    end
  end

  # CPubKey::IsValidNonHybrid: compressed (02/03, 33 bytes) or uncompressed (04, 65 bytes).
  defp valid_non_hybrid?(<<h, _::binary-size(32)>>) when h in [2, 3], do: true
  defp valid_non_hybrid?(<<4, _::binary-size(64)>>), do: true
  defp valid_non_hybrid?(_), do: false

  @p 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

  # XOnlyPubKey::IsFullyValid: x < p and x^3 + 7 is a square mod p.
  defp xonly_valid?(<<x::256>>) when x < @p do
    rhs = rem(:crypto.mod_pow(x, 3, @p) |> :binary.decode_unsigned() |> Kernel.+(7), @p)
    rhs == 0 or :binary.decode_unsigned(:crypto.mod_pow(rhs, div(@p - 1, 2), @p)) == 1
  end

  defp xonly_valid?(_), do: false

  @input_charset ~c"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
  @checksum_charset ~c"qpzry9x8gf2tvdw0s3jn54khce6mua7l"

  @doc "Core `DescriptorChecksum`."
  # Core: DescriptorChecksum (script/descriptor.cpp)
  def checksum(desc) do
    {c, cls, count} =
      desc
      |> String.to_charlist()
      |> Enum.reduce({1, 0, 0}, fn ch, {c, cls, count} ->
        pos = Enum.find_index(@input_charset, &(&1 == ch))
        c = polymod(c, pos &&& 31)
        cls = cls * 3 + (pos >>> 5)
        if count + 1 == 3, do: {polymod(c, cls), 0, 0}, else: {c, cls, count + 1}
      end)

    c = if count > 0, do: polymod(c, cls), else: c
    c = Enum.reduce(1..8, c, fn _, c -> polymod(c, 0) end) |> bxor(1)
    List.to_string(for j <- 0..7, do: Enum.at(@checksum_charset, c >>> (5 * (7 - j)) &&& 31))
  end

  defp polymod(c, val) do
    c0 = c >>> 35
    c = bxor((c &&& 0x7FFFFFFFF) <<< 5, val)
    c = if (c0 &&& 1) != 0, do: bxor(c, 0xF5DEE51989), else: c
    c = if (c0 &&& 2) != 0, do: bxor(c, 0xA9FDCA3312), else: c
    c = if (c0 &&& 4) != 0, do: bxor(c, 0x1BAB10E32D), else: c
    c = if (c0 &&& 8) != 0, do: bxor(c, 0x3706B1677A), else: c
    if (c0 &&& 16) != 0, do: bxor(c, 0x644D626FFD), else: c
  end
end
