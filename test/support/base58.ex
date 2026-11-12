defmodule Exnode.Test.Base58 do
  @moduledoc "Test-only Base58Check (for WIF keys)."
  @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  def check_encode(payload) do
    <<ck::binary-size(4), _::binary>> = Exnode.Crypto.Hash.hash256(payload)
    encode(payload <> ck)
  end

  def encode(bin) do
    zeros = for <<0 <- bin>>, reduce: 0, do: (n -> n + 1)
    leading = bin |> :binary.bin_to_list() |> Enum.take_while(&(&1 == 0)) |> length()
    _ = zeros
    n = :binary.decode_unsigned(bin)
    body = if n == 0, do: [], else: digits(n, [])
    List.to_string(List.duplicate(?1, leading) ++ body)
  end

  defp digits(0, acc), do: acc
  defp digits(n, acc), do: digits(div(n, 58), [Enum.at(@alphabet, rem(n, 58)) | acc])

  @doc "Regtest/testnet WIF for a compressed private key."
  def wif(priv32), do: check_encode(<<0xEF>> <> priv32 <> <<1>>)
end
