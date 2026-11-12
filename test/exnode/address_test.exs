defmodule Exnode.AddressTest do
  @moduledoc "BIP173 / BIP350 reference vectors, and base58check."
  use ExUnit.Case, async: true

  alias Exnode.Address

  @valid [
    {"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "bc",
     "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
    {"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "tb",
     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
    {"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "bc",
     "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
    {"BC1SW50QGDZ25J", "bc", "6002751e"},
    {"bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "bc", "5210751e76e8199196d454941c45d1b3a323"},
    {"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "tb",
     "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
    {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "bc",
     "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}
  ]

  @invalid [
    # bech32 checksum on v1 / bech32m on v0
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
    # invalid character, too short program, v0 wrong length, mixed case, empty data
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    "bc1pw5dgrnzv",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu"
  ]

  defp network("bc"), do: :mainnet
  defp network("tb"), do: :testnet

  test "BIP173/BIP350 valid addresses decode to their scriptPubKey and re-encode" do
    for {addr, hrp, spk_hex} <- @valid do
      spk = Base.decode16!(spk_hex, case: :lower)
      assert {:ok, ^spk} = Address.to_script(addr, network(hrp)), addr
      # Lowercase canonical encoding round trip.
      assert Address.from_script(spk, network(hrp)) == String.downcase(addr)
    end
  end

  test "BIP173/BIP350 invalid addresses are rejected" do
    for addr <- @invalid do
      hrp = if String.downcase(addr) |> String.starts_with?("tb"), do: :testnet, else: :mainnet
      assert {:error, _} = Address.to_script(addr, hrp), addr
    end
  end

  test "base58 P2PKH / P2SH and regtest prefixes" do
    h = Base.decode16!("77bff20c60e522dfaa3350c39b030a5d004e839a", case: :lower)
    pkh = <<0x76, 0xA9, 20>> <> h <> <<0x88, 0xAC>>
    assert Address.from_script(pkh, :mainnet) == "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    assert {:ok, ^pkh} = Address.to_script("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", :mainnet)
    assert {:error, :checksum} = Address.base58check_decode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3")
    assert "bcrt1q" <> _ = Address.from_script(<<0, 20>> <> h, :regtest)
    assert Address.from_script(<<0x6A, 1, 1>>, :mainnet) == nil
  end
end
