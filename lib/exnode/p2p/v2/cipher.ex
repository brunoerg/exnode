defmodule Exnode.P2P.V2.Cipher do
  @moduledoc """
  BIP324 packet cipher. Port of Core v32.1 `bip324.cpp` `BIP324Cipher`, with
  `crypto/chacha20.cpp` `FSChaCha20` (length cipher),
  `crypto/chacha20poly1305.cpp` `FSChaCha20Poly1305` (packet AEAD) and
  `crypto/hkdf_sha256_32.cpp` `CHKDF_HMAC_SHA256_L32`.

  ChaCha20 and ChaCha20-Poly1305 (RFC 8439) come from OTP `:crypto`
  (OpenSSL). Core's 96-bit nonce `{first, second}` is
  `<<first::32-little, second::64-little>>`; OpenSSL's ChaCha20 IV is the
  32-bit block counter followed by that nonce.

  The length ciphers hold an OpenSSL stream state, which is mutable: a
  cipher value must be used linearly (always continue from the value the
  last call returned) and only in the process that created it.
  """

  import Bitwise

  @rekey_interval 224
  @length_len 3
  @header_len 1
  @tag_len 16
  @ignore_bit 0x80
  @garbage_terminator_len 16

  @doc "Bytes a packet adds to its contents: length, header and tag (Core `EXPANSION`)."
  def expansion, do: @length_len + @header_len + @tag_len
  def length_len, do: @length_len
  def garbage_terminator_len, do: @garbage_terminator_len

  defstruct [
    :send_l,
    :send_p,
    :recv_l,
    :recv_p,
    :send_garbage_terminator,
    :recv_garbage_terminator,
    :session_id
  ]

  @doc """
  Core `BIP324Cipher::Initialize`. `sk`/`ours`: our ephemeral secret key and
  its ElligatorSwift encoding; `theirs`: the peer's; `magic`: the network's
  4 message-start bytes. `self_decrypt` (tests) swaps the send and receive
  keys so a cipher can decrypt its own output.
  """
  def init(sk, ours, theirs, initiating, magic, self_decrypt \\ false) do
    {:ok, ecdh} = Exnode.Crypto.Secp.bip324_ecdh(sk, ours, theirs, initiating)
    prk = :crypto.mac(:hmac, :sha256, "bitcoin_v2_shared_secret" <> magic, ecdh)
    expand = fn info -> :crypto.mac(:hmac, :sha256, prk, info <> <<1>>) end
    side = initiating != self_decrypt

    {il, ip, rl, rp} =
      {fs_chacha20(expand.("initiator_L")), aead(expand.("initiator_P")),
       fs_chacha20(expand.("responder_L")), aead(expand.("responder_P"))}

    <<first::binary-size(@garbage_terminator_len),
      _::binary-size(32 - 2 * @garbage_terminator_len),
      last::binary-size(@garbage_terminator_len)>> = expand.("garbage_terminators")

    {send_l, send_p, recv_l, recv_p} = if side, do: {il, ip, rl, rp}, else: {rl, rp, il, ip}
    {send_gt, recv_gt} = if initiating, do: {first, last}, else: {last, first}

    %__MODULE__{
      send_l: send_l,
      send_p: send_p,
      recv_l: recv_l,
      recv_p: recv_p,
      send_garbage_terminator: send_gt,
      recv_garbage_terminator: recv_gt,
      session_id: expand.("session_id")
    }
  end

  @doc "Core `BIP324Cipher::Encrypt`: `{cipher, encrypted length <> aead(header <> contents)}`."
  def encrypt(%__MODULE__{} = c, contents, aad, ignore) when byte_size(contents) < 1 <<< 24 do
    {send_l, len} = fs_crypt(c.send_l, <<byte_size(contents)::24-little>>)
    header = if ignore, do: <<@ignore_bit>>, else: <<0>>
    {send_p, body} = aead_encrypt(c.send_p, header <> contents, aad)
    {%{c | send_l: send_l, send_p: send_p}, len <> body}
  end

  @doc "Core `BIP324Cipher::DecryptLength`: the contents length of the next packet."
  def decrypt_length(%__MODULE__{} = c, <<_::binary-size(@length_len)>> = input) do
    {recv_l, <<len::24-little>>} = fs_crypt(c.recv_l, input)
    {%{c | recv_l: recv_l}, len}
  end

  @doc """
  Core `BIP324Cipher::Decrypt` for the packet after its length (header,
  contents and tag): `{cipher, {:ok, ignore, contents}}` or `{cipher, :error}`.
  The packet counter advances either way, as in Core.
  """
  def decrypt(%__MODULE__{} = c, input, aad) when byte_size(input) >= @header_len + @tag_len do
    {recv_p, result} = aead_decrypt(c.recv_p, input, aad)

    case result do
      {:ok, <<header, contents::binary>>} ->
        {%{c | recv_p: recv_p}, {:ok, (header &&& @ignore_bit) == @ignore_bit, contents}}

      :error ->
        {%{c | recv_p: recv_p}, :error}
    end
  end

  # --- FSChaCha20 (crypto/chacha20.cpp) -------------------------------------

  defp fs_chacha20(key), do: %{key: key, rekey: 0, chunk: 0, stream: chacha_stream(key, 0)}

  # ChaCha20 at nonce {0, rekey}, block 0.
  defp chacha_stream(key, rekey),
    do: :crypto.crypto_init(:chacha20, key, <<0::32, 0::32, rekey::64-little>>, true)

  # FSChaCha20::Crypt: XOR with the continuing keystream; after
  # @rekey_interval chunks the next 32 keystream bytes become the key and
  # the nonce moves to {0, rekey + 1}.
  defp fs_crypt(st, input) do
    out = :crypto.crypto_update(st.stream, input)

    if st.chunk + 1 == @rekey_interval do
      new_key = :crypto.crypto_update(st.stream, <<0::256>>)
      rekey = st.rekey + 1
      {%{st | key: new_key, rekey: rekey, chunk: 0, stream: chacha_stream(new_key, rekey)}, out}
    else
      {%{st | chunk: st.chunk + 1}, out}
    end
  end

  # --- FSChaCha20Poly1305 (crypto/chacha20poly1305.cpp) ---------------------

  defp aead(key), do: %{key: key, packet: 0, rekey: 0}

  defp nonce(st), do: <<st.packet::32-little, st.rekey::64-little>>

  defp aead_encrypt(st, plain, aad) do
    {ct, tag} =
      :crypto.crypto_one_time_aead(
        :chacha20_poly1305,
        st.key,
        nonce(st),
        plain,
        aad,
        @tag_len,
        true
      )

    {next_packet(st), ct <> tag}
  end

  defp aead_decrypt(st, input, aad) do
    ct_len = byte_size(input) - @tag_len
    <<ct::binary-size(ct_len), tag::binary-size(@tag_len)>> = input

    result =
      case :crypto.crypto_one_time_aead(
             :chacha20_poly1305,
             st.key,
             nonce(st),
             ct,
             aad,
             tag,
             false
           ) do
        :error -> :error
        plain -> {:ok, plain}
      end

    {next_packet(st), result}
  end

  # FSChaCha20Poly1305::NextPacket: after @rekey_interval packets, the key
  # becomes the first 32 bytes of the keystream at nonce {0xFFFFFFFF, rekey},
  # block 1 (block 0 is the Poly1305 key block).
  defp next_packet(st) do
    if st.packet + 1 == @rekey_interval do
      iv = <<1::32-little, 0xFFFFFFFF::32-little, st.rekey::64-little>>
      new_key = :crypto.crypto_one_time(:chacha20, st.key, iv, <<0::256>>, true)
      %{st | key: new_key, packet: 0, rekey: st.rekey + 1}
    else
      %{st | packet: st.packet + 1}
    end
  end
end
