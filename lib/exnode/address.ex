defmodule Exnode.Address do
  @moduledoc """
  Addresses: Core v32.1 `key_io.cpp` (`EncodeDestination` / `DecodeDestination`),
  `base58.cpp`, `bech32.cpp` (BIP173 bech32 for witness v0, BIP350 bech32m
  for v1+), and `script/solver.cpp` `ExtractDestination` / `GetScriptForDestination`.
  """
  import Bitwise

  alias Exnode.Script

  @b58 ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @b32 ~c"qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  @bech32_const 1
  @bech32m_const 0x2BC830A3

  # chainparams.cpp base58Prefixes / bech32_hrp
  def prefixes(:mainnet), do: %{pkh: 0x00, sh: 0x05, hrp: "bc"}
  def prefixes(:regtest), do: %{pkh: 0x6F, sh: 0xC4, hrp: "bcrt"}
  def prefixes(_testnets), do: %{pkh: 0x6F, sh: 0xC4, hrp: "tb"}

  # --- destinations ------------------------------------------------------------------

  @doc """
  Core `ExtractDestination` + `EncodeDestination`: the address of a
  scriptPubKey, or nil (P2PK, multisig, null data, non-standard).
  """
  def from_script(spk, network) do
    pre = prefixes(network)

    case Exnode.Mempool.Policy.solver(spk) do
      {:pubkeyhash, [h]} -> base58check(<<pre.pkh>> <> h)
      {:scripthash, [h]} -> base58check(<<pre.sh>> <> h)
      {:witness_v0_keyhash, [p]} -> segwit(pre.hrp, 0, p)
      {:witness_v0_scripthash, [p]} -> segwit(pre.hrp, 0, p)
      {:witness_v1_taproot, [p]} -> segwit(pre.hrp, 1, p)
      {:anchor, _} -> segwit(pre.hrp, 1, <<0x4E, 0x73>>)
      {:witness_unknown, [<<v>>, p]} -> segwit(pre.hrp, v, p)
      _ -> nil
    end
  end

  @doc "Core `DecodeDestination` + `GetScriptForDestination`: `{:ok, scriptPubKey}` or `{:error, reason}`."
  def to_script(addr, network) do
    pre = prefixes(network)

    case decode_segwit(pre.hrp, addr) do
      {:ok, v, p} ->
        {:ok, Script.push_int(v) <> <<byte_size(p)>> <> p}

      {:error, :not_segwit} ->
        case base58check_decode(addr) do
          {:ok, <<v, h::binary-size(20)>>} when v == pre.pkh ->
            {:ok, <<0x76, 0xA9, 20>> <> h <> <<0x88, 0xAC>>}

          {:ok, <<v, h::binary-size(20)>>} when v == pre.sh ->
            {:ok, <<0xA9, 20>> <> h <> <<0x87>>}

          _ ->
            {:error, :invalid}
        end

      {:error, _} = e ->
        e
    end
  end

  # --- base58 ------------------------------------------------------------------------

  def base58check(payload) do
    <<ck::binary-size(4), _::binary>> = Exnode.Crypto.Hash.hash256(payload)
    base58(payload <> ck)
  end

  def base58(bin) do
    leading = bin |> :binary.bin_to_list() |> Enum.take_while(&(&1 == 0)) |> length()
    n = :binary.decode_unsigned(bin)
    body = if n == 0, do: [], else: b58_digits(n, [])
    List.to_string(List.duplicate(?1, leading) ++ body)
  end

  defp b58_digits(0, acc), do: acc
  defp b58_digits(n, acc), do: b58_digits(div(n, 58), [Enum.at(@b58, rem(n, 58)) | acc])

  def base58check_decode(str) do
    chars = String.to_charlist(str)

    with true <- Enum.all?(chars, &(&1 in @b58)) || :error do
      leading = Enum.take_while(chars, &(&1 == ?1)) |> length()
      n = Enum.reduce(chars, 0, fn c, acc -> acc * 58 + Enum.find_index(@b58, &(&1 == c)) end)
      bin = :binary.copy(<<0>>, leading) <> if(n == 0, do: <<>>, else: :binary.encode_unsigned(n))

      case bin do
        <<payload::binary-size(byte_size(bin) - 4), ck::binary-size(4)>>
        when byte_size(bin) >= 4 ->
          if binary_part(Exnode.Crypto.Hash.hash256(payload), 0, 4) == ck,
            do: {:ok, payload},
            else: {:error, :checksum}

        _ ->
          {:error, :invalid}
      end
    else
      _ -> {:error, :invalid}
    end
  end

  # --- bech32 / bech32m -------------------------------------------------------------------

  @doc "Segwit address (BIP173 for v0, BIP350 for v1+)."
  def segwit(hrp, version, program) do
    data = [version | convert_bits(:binary.bin_to_list(program), 8, 5, true)]
    const = if version == 0, do: @bech32_const, else: @bech32m_const
    checksum = create_checksum(hrp, data, const)
    hrp <> "1" <> List.to_string(for d <- data ++ checksum, do: Enum.at(@b32, d))
  end

  @doc "Decodes a segwit address for `hrp`: `{:ok, version, program}` or `{:error, reason}`."
  def decode_segwit(hrp, addr) do
    lower = String.downcase(addr)

    cond do
      not String.starts_with?(lower, hrp <> "1") -> {:error, :not_segwit}
      addr != lower and addr != String.upcase(addr) -> {:error, :mixed_case}
      true -> decode_segwit_data(hrp, lower)
    end
  end

  defp decode_segwit_data(hrp, lower) do
    data_part = String.slice(lower, (String.length(hrp) + 1)..-1//1) |> String.to_charlist()
    values = Enum.map(data_part, fn c -> Enum.find_index(@b32, &(&1 == c)) end)

    with false <- Enum.any?(values, &is_nil/1) or length(values) < 7 or String.length(lower) > 90,
         [version | _] = values,
         payload = Enum.drop(values, -6),
         const = polymod(hrp_expand(hrp) ++ values),
         true <-
           (version == 0 and const == @bech32_const) or (version > 0 and const == @bech32m_const),
         {:ok, prog} <- convert_back(tl(payload)),
         true <- version <= 16 and byte_size(prog) in 2..40,
         true <- version != 0 or byte_size(prog) in [20, 32] do
      {:ok, version, prog}
    else
      _ -> {:error, :invalid}
    end
  end

  defp convert_back(values) do
    case convert_bits(values, 5, 8, false) do
      :error -> :error
      bytes -> {:ok, :binary.list_to_bin(bytes)}
    end
  end

  defp polymod(values) do
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

    Enum.reduce(values, 1, fn v, chk ->
      b = chk >>> 25
      chk = bxor((chk &&& 0x1FFFFFF) <<< 5, v)

      Enum.reduce(Enum.with_index(gen), chk, fn {g, i}, c ->
        if (b >>> i &&& 1) == 1, do: bxor(c, g), else: c
      end)
    end)
  end

  defp hrp_expand(hrp) do
    cs = String.to_charlist(hrp)
    for(c <- cs, do: c >>> 5) ++ [0] ++ for(c <- cs, do: c &&& 31)
  end

  defp create_checksum(hrp, data, const) do
    pm = bxor(polymod(hrp_expand(hrp) ++ data ++ [0, 0, 0, 0, 0, 0]), const)
    for i <- 0..5, do: pm >>> (5 * (5 - i)) &&& 31
  end

  defp convert_bits(data, from, to, pad) do
    maxv = (1 <<< to) - 1

    {acc, bits, out} =
      Enum.reduce_while(data, {0, 0, []}, fn v, {acc, bits, out} ->
        if v < 0 or v >>> from != 0 do
          {:halt, {:error, 0, :error}}
        else
          acc = acc <<< from ||| v
          bits = bits + from
          {out, bits} = emit(acc, bits, to, maxv, out)
          {:cont, {acc, bits, out}}
        end
      end)

    cond do
      out == :error -> :error
      pad and bits > 0 -> Enum.reverse([acc <<< (to - bits) &&& maxv | out])
      pad -> Enum.reverse(out)
      bits >= from or (acc <<< (to - bits) &&& maxv) != 0 -> :error
      true -> Enum.reverse(out)
    end
  end

  defp emit(acc, bits, to, maxv, out) when bits >= to,
    do: emit(acc, bits - to, to, maxv, [acc >>> (bits - to) &&& maxv | out])

  defp emit(_acc, bits, _to, _maxv, out), do: {out, bits}
end
