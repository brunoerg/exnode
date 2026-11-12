defmodule Exnode.P2P.V2.TransportTest do
  @moduledoc """
  V2Transport state machine (Core net.cpp `V2Transport`): handshake between
  an initiator and a responder with bytes delivered in arbitrary chunks,
  short and long message types, messages queued before the handshake,
  decoys, v1 detection, and the error cases Core disconnects on.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.P2P.V2.{Cipher, Transport}

  @magic <<0xFA, 0xBF, 0xB5, 0xDA>>

  # Delivers `bytes` to `t` in the given chunk sizes; collects output and messages.
  defp feed(t, bytes, chunks) do
    {parts, rest} =
      Enum.reduce(chunks, {[], bytes}, fn n, {acc, b} ->
        n = min(n, byte_size(b))
        <<p::binary-size(n), r::binary>> = b
        {[p | acc], r}
      end)

    Enum.reduce(Enum.reverse([rest | parts]), {t, <<>>, []}, fn p, {t, out, msgs} ->
      {:ok, t, o, m} = Transport.received(t, p)
      {t, out <> o, msgs ++ m}
    end)
  end

  property "handshake and messages survive any chunking, in both directions" do
    check all(
            chunks_a <- list_of(integer(1..200), max_length: 40),
            chunks_b <- list_of(integer(1..200), max_length: 40),
            ga <- binary(max_length: 300),
            gb <- binary(max_length: 300),
            payloads <- list_of(binary(max_length: 500), min_length: 1, max_length: 6),
            max_runs: 60
          ) do
      {a, a_out} = Transport.new(true, @magic, garbage: ga)
      {b, <<>>} = Transport.new(false, @magic, garbage: gb)

      # A queues messages before the handshake (as a peer pushes `version` at once).
      {a, <<>>} = Transport.send_message(a, "version", hd(payloads))
      {a, <<>>} = Transport.send_message(a, "wtxidrelay", <<>>)

      {b, b_out, []} = feed(b, a_out, chunks_b)
      {a, a_out2, []} = feed(a, b_out, chunks_a)
      {b, b_out2, msgs_b} = feed(b, a_out2, chunks_b)
      assert msgs_b == [{:msg, "version", hd(payloads)}, {:msg, "wtxidrelay", <<>>}]
      assert b_out2 == <<>>
      assert Transport.established?(b)
      # A's version packet from B arrived with b_out; nothing more needed.
      assert Transport.established?(a)
      assert Transport.session_id(a) == Transport.session_id(b)

      # Short ids (inv, tx, headers) and long ones (version, sendheaders), both ways.
      cmds = Stream.cycle(~w(inv tx sendheaders headers block version feature))
      sends = Enum.zip(cmds, payloads)

      {_b, wire} =
        Enum.reduce(sends, {b, <<>>}, fn {c, p}, {b, w} ->
          {b, o} = Transport.send_message(b, c, p)
          {b, w <> o}
        end)

      {_a, <<>>, got} = feed(a, wire, chunks_a)
      assert got == for({c, p} <- sends, do: {:msg, c, p})
    end
  end

  defp pair do
    {a, a_out} = Transport.new(true, @magic, garbage: <<>>)
    {b, <<>>} = Transport.new(false, @magic, garbage: <<>>)
    {:ok, b, b_out, []} = Transport.received(b, a_out)
    {:ok, a, a_out2, []} = Transport.received(a, b_out)
    {:ok, b, <<>>, []} = Transport.received(b, a_out2)
    {a, b}
  end

  test "short ids are one byte, unknown types use the 12-byte long form" do
    {a, b} = pair()
    {_a, short} = Transport.send_message(a, "ping", <<1::64>>)
    {_b, long} = Transport.send_message(b, "sendheaders", <<>>)
    assert byte_size(short) == 1 + 8 + Cipher.expansion()
    assert byte_size(long) == 1 + 12 + Cipher.expansion()
  end

  test "decoy packets are skipped; an invalid message type is rejected, not fatal" do
    {a, b} = pair()
    {c, decoy} = Cipher.encrypt(a.cipher, "noise", <<>>, true)
    {c, bad_short} = Cipher.encrypt(c, <<200, 1, 2>>, <<>>, false)
    {c, bad_long} = Cipher.encrypt(c, <<0, "ver\x01sion", 0, 0, 0, 0>>, <<>>, false)
    {c, empty_long} = Cipher.encrypt(c, <<0, 0::96, "x">>, <<>>, false)
    a = %{a | cipher: c}
    {_a, ping} = Transport.send_message(a, "ping", <<7::64>>)

    {:ok, _b, <<>>, msgs} =
      Transport.received(b, decoy <> bad_short <> bad_long <> empty_long <> ping)

    assert msgs == [:reject, :reject, {:msg, "", "x"}, {:msg, "ping", <<7::64>>}]
  end

  test "a decoy before the version packet does not consume the garbage AAD" do
    {a, a_out} = Transport.new(true, @magic, garbage: "gg")
    {b, <<>>} = Transport.new(false, @magic, garbage: "hh")
    {:ok, b, b_out, []} = Transport.received(b, a_out)

    # A's reply is terminator + version packet; slip a decoy (AAD = garbage, as the first packet) before it.
    {:ok, _a2, a_out2, []} = Transport.received(a, b_out)
    tl = Cipher.garbage_terminator_len()
    <<term::binary-size(tl), _version::binary>> = a_out2

    # Rebuild A's first packets by hand from a fresh cipher state: decoy with AAD, then version without.
    c = Cipher.init(a.sk, a.ours, binary_part(b_out, 0, 64), true, @magic)
    {c, decoy} = Cipher.encrypt(c, "x", "gg", true)
    {_c, version} = Cipher.encrypt(c, <<>>, <<>>, false)
    {:ok, b, <<>>, []} = Transport.received(b, term <> decoy <> version)
    assert Transport.established?(b)
  end

  test "a responder detects a v1 version header and hands back every byte" do
    {b, <<>>} = Transport.new(false, @magic)
    hdr = @magic <> "version" <> <<0, 0, 0, 0, 0>> <> "more bytes"
    {:ok, b, <<>>, []} = Transport.received(b, binary_part(hdr, 0, 10))
    assert {:v1, ^hdr} = Transport.received(b, binary_part(hdr, 10, byte_size(hdr) - 10))
  end

  test "a v1 header with another network's magic is an error; a v2 key that starts like magic is not" do
    {b, <<>>} = Transport.new(false, @magic)

    assert {:error, :v1_peer_wrong_network} =
             Transport.received(b, <<1, 2, 3, 4>> <> "version" <> <<0::40>>)

    {b, <<>>} = Transport.new(false, @magic)
    # Still a v1 prefix: undecided, nothing sent.
    {:ok, b, <<>>, []} = Transport.received(b, @magic <> "vers")
    # Diverges from v1 at the 8th byte: a v2 key; the responder answers.
    {:ok, b, out, []} = Transport.received(b, "x")
    assert byte_size(out) >= 64 and b.recv_state == :key
  end

  test "garbage longer than 4095 bytes without a terminator disconnects; 4095 with one is fine" do
    {a, a_out} = Transport.new(true, @magic, garbage: :binary.copy(<<7>>, 4095))
    {b, <<>>} = Transport.new(false, @magic)
    {:ok, b, b_out, []} = Transport.received(b, a_out)
    {:ok, _a, a_out2, []} = Transport.received(a, b_out)
    {:ok, b2, <<>>, []} = Transport.received(b, a_out2)
    assert Transport.established?(b2)

    {a, a_out} = Transport.new(true, @magic, garbage: <<>>)
    {b, <<>>} = Transport.new(false, @magic)
    {:ok, b, _b_out, []} = Transport.received(b, a_out)

    assert {:error, :missing_garbage_terminator} =
             Transport.received(b, :binary.copy(<<7>>, 4095 + 16))

    _ = a
  end

  test "a corrupted packet and an oversized length disconnect" do
    {a, b} = pair()
    {_a, p} = Transport.send_message(a, "ping", <<1::64>>)
    <<pre::binary-size(byte_size(p) - 1), last>> = p
    assert {:error, :decryption_failure} = Transport.received(b, pre <> <<Bitwise.bxor(last, 1)>>)

    {a, b} = pair()

    {c, <<len::binary-size(3), _::binary>>} =
      Cipher.encrypt(a.cipher, :binary.copy(<<0>>, 4_000_014), <<>>, false)

    _ = c
    assert {:error, {:packet_too_large, 4_000_014}} = Transport.received(b, len)
  end

  test "ShouldReconnectV1: an initiator that sent its key and received nothing" do
    {a, out} = Transport.new(true, @magic)
    assert byte_size(out) >= 64
    assert Transport.should_reconnect_v1?(a)
    {:ok, a, _, _} = Transport.received(a, <<1>>)
    refute Transport.should_reconnect_v1?(a)
    {b, <<>>} = Transport.new(false, @magic)
    refute Transport.should_reconnect_v1?(b)
  end

  test "a large packet dribbled one byte at a time decodes, in linear time" do
    {a, b} = pair()
    payload = :crypto.strong_rand_bytes(500_000)
    {_a, wire} = Transport.send_message(a, "block", payload)

    {us, {_b, msgs}} =
      :timer.tc(fn ->
        Enum.reduce(:binary.bin_to_list(wire), {b, []}, fn byte, {b, acc} ->
          {:ok, b, <<>>, m} = Transport.received(b, <<byte>>)
          {b, acc ++ m}
        end)
      end)

    assert msgs == [{:msg, "block", payload}]
    assert us < 20_000_000, "took #{div(us, 1000)} ms"
  end
end
