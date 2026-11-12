defmodule Exnode.P2P.V2.CipherTest do
  @moduledoc """
  BIP324 cipher against Core v32.1's packet vectors, read from the vendored
  `src/test/bip324_tests.cpp` (`TestBIP324PacketVector`), with the same
  checks: session id and garbage terminators, ciphertext after seeking
  `in_idx` packets, self-decryption, and rejection of corrupted packets.
  """
  use ExUnit.Case, async: true

  alias Exnode.Crypto.Secp
  alias Exnode.P2P.V2.Cipher

  @src Path.expand("../../../vendor/bitcoin/src/test/bip324_tests.cpp", __DIR__)
  # Core's BasicTestingSetup runs on mainnet: its message start.
  @magic <<0xF9, 0xBE, 0xB4, 0xD9>>

  defp vectors do
    body = File.read!(@src)

    Regex.scan(~r/TestBIP324PacketVector\(\s*(\d.*?)\);/s, body, capture: :all_but_first)
    |> Enum.map(fn [args] ->
      args = args |> String.split(",") |> Enum.map(&String.trim/1)

      args =
        Enum.map(args, fn a ->
          if String.starts_with?(a, "\""),
            do: Base.decode16!(String.trim(a, "\""), case: :lower),
            else: a
        end)

      [
        idx,
        priv,
        ours,
        theirs,
        init,
        contents,
        mult,
        aad,
        ignore,
        send_gt,
        recv_gt,
        session,
        ct,
        ct_end
      ] = args

      %{
        idx: String.to_integer(idx),
        priv: priv,
        ours: ours,
        theirs: theirs,
        init: init == "true",
        contents: contents,
        mult: String.to_integer(mult),
        aad: aad,
        ignore: ignore == "true",
        send_gt: send_gt,
        recv_gt: recv_gt,
        session: session,
        ct: ct,
        ct_end: ct_end
      }
    end)
  end

  defp seek(c, 0), do: c
  defp seek(c, n), do: c |> Cipher.encrypt(<<>>, <<>>, true) |> elem(0) |> seek(n - 1)

  # Decrypts one packet given its bytes: {cipher, result}.
  defp decrypt_packet(c, <<len3::binary-size(3), rest::binary>>, aad) do
    {c, len} = Cipher.decrypt_length(c, len3)
    if len + 17 != byte_size(rest), do: {c, :bad_length}, else: Cipher.decrypt(c, rest, aad)
  end

  test "Core's vectors are all parsed" do
    assert length(vectors()) == 7
  end

  test "packet vectors: keys, terminators, ciphertext, decryption, corruption" do
    for v <- vectors() do
      c = Cipher.init(v.priv, v.ours, v.theirs, v.init, @magic)
      assert c.session_id == v.session
      assert c.send_garbage_terminator == v.send_gt
      assert c.recv_garbage_terminator == v.recv_gt

      contents = :binary.copy(v.contents, v.mult)
      {_c, ct} = c |> seek(v.idx) |> Cipher.encrypt(contents, v.aad, v.ignore)

      if v.ct != "",
        do: assert(ct == v.ct, "vector idx=#{v.idx}"),
        else:
          assert(
            binary_part(ct, byte_size(ct) - byte_size(v.ct_end), byte_size(v.ct_end)) == v.ct_end
          )

      # Self-decryption, after seeking with the same dummy packets. Cipher
      # values are linear (OpenSSL stream state), so each check starts from
      # a freshly initialised and seeked decrypter.
      fresh = Cipher.init(v.priv, v.ours, v.theirs, v.init, @magic)

      {dummies, _} =
        Enum.map_reduce(1..v.idx//1, fresh, fn _, c ->
          Cipher.encrypt(c, <<>>, <<>>, true) |> then(fn {c, p} -> {p, c} end)
        end)

      dec = fn initiating ->
        d = Cipher.init(v.priv, v.ours, v.theirs, initiating, @magic, true)
        Enum.reduce(dummies, d, fn p, d -> elem(decrypt_packet(d, p, <<>>), 0) end)
      end

      assert elem(decrypt_packet(dec.(v.init), ct, v.aad), 1) == {:ok, v.ignore, contents}

      # Wrong side, a flipped bit in the tag or the length, a changed aad: rejected.
      assert elem(decrypt_packet(dec.(not v.init), ct, v.aad), 1) != {:ok, v.ignore, contents}
      flip = byte_size(ct) - 1
      <<pre::binary-size(flip), last>> = ct
      assert {_, :error} = decrypt_packet(dec.(v.init), pre <> <<Bitwise.bxor(last, 1)>>, v.aad)
      <<l0, post::binary>> = ct

      assert elem(decrypt_packet(dec.(v.init), <<Bitwise.bxor(l0, 1)>> <> post, v.aad), 1) !=
               {:ok, v.ignore, contents}

      assert {_, :error} = decrypt_packet(dec.(v.init), ct, v.aad <> <<0>>)
    end
  end

  test "two fresh ciphers talk to each other across rekeys, in both directions" do
    {ska, ella} = Secp.new_ellswift_key()
    {skb, ellb} = Secp.new_ellswift_key()
    a = Cipher.init(ska, ella, ellb, true, @magic)
    b = Cipher.init(skb, ellb, ella, false, @magic)
    assert a.session_id == b.session_id
    assert a.send_garbage_terminator == b.recv_garbage_terminator
    assert a.recv_garbage_terminator == b.send_garbage_terminator

    # 500 packets: past the 224-packet rekey of both ciphers, twice.
    {a, b} =
      Enum.reduce(1..500, {a, b}, fn i, {a, b} ->
        msg = :crypto.strong_rand_bytes(rem(i * 37, 300))
        {a, p} = Cipher.encrypt(a, msg, <<>>, false)
        {b, {:ok, false, ^msg}} = decrypt_packet(b, p, <<>>)
        {b, q} = Cipher.encrypt(b, msg, <<>>, rem(i, 3) == 0)
        ign = rem(i, 3) == 0
        {a, {:ok, ^ign, ^msg}} = decrypt_packet(a, q, <<>>)
        {a, b}
      end)

    assert %Cipher{} = a
    assert %Cipher{} = b
  end
end
