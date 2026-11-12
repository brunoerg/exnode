defmodule Exnode.Crypto.SipHash do
  @moduledoc """
  SipHash-2-4 (64-bit output), as Core v32.1 `crypto/siphash.cpp`
  (`CSipHasher`, `SipHashUint256`). Used for BIP152 short transaction ids.
  `k0`/`k1` are 64-bit integers; the message is a binary (a uint256 is its
  32 internal bytes).
  """
  import Bitwise

  @mask 0xFFFFFFFFFFFFFFFF

  # Core: CSipHasher (crypto/siphash.cpp)
  def hash(k0, k1, msg) when is_binary(msg) do
    v =
      {bxor(0x736F6D6570736575, k0), bxor(0x646F72616E646F6D, k1), bxor(0x6C7967656E657261, k0),
       bxor(0x7465646279746573, k1)}

    len = byte_size(msg)
    full = div(len, 8) * 8
    <<blocks::binary-size(full), tail::binary>> = msg
    v = for <<m::little-64 <- blocks>>, reduce: v, do: (vv -> compress(vv, m))

    last = (len &&& 0xFF) <<< 56 ||| :binary.decode_unsigned(tail, :little)
    {v0, v1, v2, v3} = compress(v, last)

    {v0, v1, v2, v3} =
      {v0, v1, bxor(v2, 0xFF), v3} |> sipround() |> sipround() |> sipround() |> sipround()

    bxor(bxor(v0, v1), bxor(v2, v3))
  end

  defp compress({v0, v1, v2, v3}, m) do
    {v0, v1, v2, v3} = {v0, v1, v2, bxor(v3, m)} |> sipround() |> sipround()
    {bxor(v0, m), v1, v2, v3}
  end

  defp sipround({v0, v1, v2, v3}) do
    v0 = v0 + v1 &&& @mask
    v1 = rotl(v1, 13)
    v1 = bxor(v1, v0)
    v0 = rotl(v0, 32)
    v2 = v2 + v3 &&& @mask
    v3 = rotl(v3, 16)
    v3 = bxor(v3, v2)
    v0 = v0 + v3 &&& @mask
    v3 = rotl(v3, 21)
    v3 = bxor(v3, v0)
    v2 = v2 + v1 &&& @mask
    v1 = rotl(v1, 17)
    v1 = bxor(v1, v2)
    v2 = rotl(v2, 32)
    {v0, v1, v2, v3}
  end

  defp rotl(x, b), do: (x <<< b ||| x >>> (64 - b)) &&& @mask
end
