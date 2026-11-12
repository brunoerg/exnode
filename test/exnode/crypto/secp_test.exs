defmodule Exnode.Crypto.SecpTest do
  @moduledoc """
  ElligatorSwift through the NIF, against libsecp256k1's own vectors, read
  from the vendored `src/modules/ellswift/tests_impl.h`: decoding
  (`ellswift_decode_tests`, an x coordinate and y parity per encoding) and
  BIP324 ECDH (`ellswift_xdh_tests_bip324`). Also invalid secret keys, the
  redraw of an invalid random key, and encode-then-decode against the
  public key of the secret key.
  """
  use ExUnit.Case, async: true

  alias Exnode.Crypto.Secp

  @src Path.expand(
         "../../../vendor/bitcoin/src/secp256k1/src/modules/ellswift/tests_impl.h",
         __DIR__
       )
  # The secp256k1 group order.
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  # The initializer of the C array `name`.
  defp array(name) do
    [_, body] = String.split(File.read!(@src), "#{name}[] = {", parts: 2)
    hd(String.split(body, "\n};", parts: 2))
  end

  defp bytes(list),
    do:
      list
      |> String.split(",")
      |> Enum.map(&(&1 |> String.trim() |> String.to_integer()))
      |> :binary.list_to_bin()

  defp fe(words) do
    for w <- String.split(words, ","),
        into: <<>>,
        do: <<String.to_integer(String.trim(w) |> String.trim_leading("0x"), 16)::32>>
  end

  defp decode_vectors do
    Regex.scan(
      ~r/\{\{([^}]*)\}, SECP256K1_FE_CONST\(([^)]*)\), ([01])\}/,
      array("ellswift_decode_tests"),
      capture: :all_but_first
    )
    |> Enum.map(fn [enc, x, odd] ->
      %{enc: hexb(enc), x: fe(x), odd: odd == "1"}
    end)
  end

  defp xdh_vectors do
    Regex.scan(
      ~r/\{\{([^}]*)\}, \{([^}]*)\}, \{([^}]*)\}, ([01]), \{([^}]*)\}\}/,
      array("ellswift_xdh_tests_bip324"),
      capture: :all_but_first
    )
    |> Enum.map(fn [priv, ours, theirs, init, secret] ->
      %{
        priv: hexb(priv),
        ours: hexb(ours),
        theirs: hexb(theirs),
        init: init == "1",
        secret: hexb(secret)
      }
    end)
  end

  # "0x00, 0xd3, ..." -> the bytes.
  defp hexb(list), do: list |> hex_list() |> bytes()

  defp hex_list(list) do
    list
    |> String.split(",")
    |> Enum.map_join(
      ",",
      &(&1
        |> String.trim()
        |> String.trim_leading("0x")
        |> String.to_integer(16)
        |> Integer.to_string())
    )
  end

  # The compressed public key of `sk` (OTP crypto, independent of the NIF).
  defp pubkey(sk) do
    {<<4, x::binary-32, y::binary-32>>, _} = :crypto.generate_key(:ecdh, :secp256k1, sk)
    <<if(rem(:binary.last(y), 2) == 1, do: 3, else: 2)>> <> x
  end

  test "decoding vectors" do
    vs = decode_vectors()
    # Every entry of the array (a parse that skipped some would pass silently).
    assert length(vs) == 76

    for v <- vs do
      assert Secp.ellswift_decode(v.enc) == <<if(v.odd, do: 3, else: 2)>> <> v.x,
             Base.encode16(v.enc)
    end
  end

  test "BIP324 ECDH vectors" do
    vs = xdh_vectors()
    assert length(vs) == 7

    for v <- vs do
      assert Secp.bip324_ecdh(v.priv, v.ours, v.theirs, v.init) == {:ok, v.secret}
    end
  end

  test "an encoding decodes to the public key of its secret key; both sides agree" do
    {ska, ella} = Secp.new_ellswift_key()
    {skb, ellb} = Secp.new_ellswift_key()
    assert Secp.ellswift_decode(ella) == pubkey(ska)
    assert Secp.ellswift_decode(ellb) == pubkey(skb)
    assert {:ok, s} = Secp.bip324_ecdh(ska, ella, ellb, true)
    assert Secp.bip324_ecdh(skb, ellb, ella, false) == {:ok, s}
  end

  test "secret keys outside 1..n-1 are refused" do
    aux = <<7::256>>
    {:ok, ell} = Secp.ellswift_create(<<1::256>>, aux)

    for sk <- [<<0::256>>, <<@n::256>>, <<@n + 1::256>>, <<-1::256>>] do
      assert Secp.ellswift_create(sk, aux) == :error
      assert Secp.bip324_ecdh(sk, ell, ell, true) == :error
    end

    assert {:ok, _} = Secp.ellswift_create(<<@n - 1::256>>, aux)
  end

  test "an invalid random key is drawn again" do
    # The first draw is 0 (not a key); then key 1 and its entropy.
    {:ok, agent} = Agent.start_link(fn -> [<<0::256>>, <<9::256>>, <<1::256>>, <<9::256>>] end)
    rand = fn 32 -> Agent.get_and_update(agent, fn [b | rest] -> {b, rest} end) end
    assert {<<1::256>>, ell} = Secp.new_ellswift_key(rand)
    assert Secp.ellswift_decode(ell) == pubkey(<<1::256>>)
  end
end
