defmodule Exnode.P2P.MessageTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.ChainParams
  alias Exnode.Codec.CompactSize
  alias Exnode.P2P.{Frame, Message}

  @magic ChainParams.get(:mainnet).magic

  defp roundtrip(msg) do
    {cmd, payload} = Message.encode(msg)
    framed = IO.iodata_to_binary(Frame.encode(@magic, cmd, payload))
    assert {:ok, ^cmd, body, ""} = Frame.decode(@magic, framed)
    Message.decode(cmd, body)
  end

  test "round-trips" do
    v = %{
      version: 70017,
      services: 1033,
      time: 1_700_000_000,
      addr_recv: %{services: 0, net: :ipv4, addr: <<1, 2, 3, 4>>, port: 8333},
      nonce: 42,
      user_agent: "/exnode:0.1/",
      start_height: 5,
      relay: false
    }

    assert {:ok, {:version, got}} = roundtrip({:version, v})
    assert Map.take(got, Map.keys(v)) == v

    for m <- [
          :verack,
          :sendheaders,
          :wtxidrelay,
          :sendaddrv2,
          :getaddr,
          {:ping, 7},
          {:pong, 7},
          {:sendcmpct, %{announce: true, version: 2}},
          {:feefilter, 1000}
        ] do
      assert {:ok, ^m} = roundtrip(m)
    end

    gh =
      {:getheaders, %{version: 70017, locator: [<<1::256>>, <<2::256>>], hash_stop: <<0::256>>}}

    assert {:ok, ^gh} = roundtrip(gh)

    inv =
      {:inv,
       [
         %{type: :block, witness: false, hash: <<3::256>>},
         %{type: :tx, witness: true, hash: <<4::256>>}
       ]}

    assert {:ok, ^inv} = roundtrip(inv)

    a2 =
      {:addrv2,
       [
         %{time: 1, services: 9, net: :torv3, addr: <<5::256>>, port: 9050},
         %{time: 2, services: 1, net: :ipv4, addr: <<8, 8, 8, 8>>, port: 8333}
       ]}

    assert {:ok, ^a2} = roundtrip(a2)

    g = ChainParams.get(:mainnet).genesis.header
    assert {:ok, {:headers, [h]}} = roundtrip({:headers, [g]})
    assert h.hash == g.hash
  end

  describe "framing" do
    test "wrong magic and oversized length disconnect" do
      framed = IO.iodata_to_binary(Frame.encode(@magic, "verack", ""))
      assert {:error, :bad_magic} = Frame.decode(<<1, 2, 3, 4>>, framed)
      assert {:error, :bad_magic} = Frame.decode(@magic, <<0xF9, 0>>)
      big = <<@magic::binary, "block", 0::56, 4_000_001::little-32, 0::32>>
      assert {:error, :oversized} = Frame.decode(@magic, big)
    end

    test "bad checksum or invalid command drops the message, keeps the stream" do
      <<hdr::binary-size(20), _ck::binary-size(4)>> =
        IO.iodata_to_binary(Frame.encode(@magic, "verack", ""))

      next = IO.iodata_to_binary(Frame.encode(@magic, "verack", ""))
      assert {:reject, "verack", ^next} = Frame.decode(@magic, hdr <> <<0, 0, 0, 0>> <> next)
      bad_cmd = IO.iodata_to_binary(Frame.encode(@magic, "ver\0ack", ""))
      assert {:reject, _, ""} = Frame.decode(@magic, bad_cmd)
    end

    test "partial frames need more bytes" do
      framed = IO.iodata_to_binary(Frame.encode(@magic, "ping", <<1::64>>))

      for n <- 0..(byte_size(framed) - 1),
          do: assert(:more == Frame.decode(@magic, binary_part(framed, 0, n)))
    end
  end

  describe "limits (Core rejects these)" do
    test "more than 2000 headers" do
      assert {:error, {:too_many_headers, 2001}} =
               Message.decode("headers", CompactSize.encode(2001))
    end

    test "inv larger than MAX_INV_SZ" do
      assert {:error, {:inv_too_large, 50001}} = Message.decode("inv", CompactSize.encode(50001))
    end

    test "user agent longer than 256" do
      v =
        <<70017::little-32, 0::64, 0::64, 0::208, 0::208, 0::64>> <>
          IO.iodata_to_binary(CompactSize.encode_bytes(String.duplicate("a", 257)))

      assert {:error, :string_too_long} = Message.decode("version", v)
    end

    test "addrv2 with a wrong length for a known network" do
      p =
        IO.iodata_to_binary([<<1>>, <<0::32>>, <<1>>, <<1>>, <<5>>, <<1, 2, 3, 4, 5>>, <<0::16>>])

      assert {:error, :addrv2_bad_length} = Message.decode("addrv2", p)
    end
  end

  @commands ~w(version verack ping pong sendheaders sendcmpct wtxidrelay sendaddrv2 getaddr feefilter
               getheaders getblocks headers inv getdata notfound addr addrv2 block tx bogus)

  property "decoders never raise on arbitrary payloads" do
    check all(cmd <- member_of(@commands), payload <- binary(max_length: 300), max_runs: 5000) do
      result = Message.decode(cmd, payload)

      assert match?({:ok, _}, result) or match?({:error, _}, result) or
               match?({:unknown, _}, result)
    end
  end

  property "framing never raises on arbitrary streams" do
    check all(prefix <- member_of([<<>>, @magic]), bin <- binary(max_length: 200), max_runs: 5000) do
      r = Frame.decode(@magic, prefix <> bin)

      assert r == :more or match?({:error, _}, r) or match?({:reject, _, _}, r) or
               match?({:ok, _, _, _}, r)
    end
  end

  property "headers payloads made of valid-looking structure never raise" do
    check all(n <- integer(0..5), junk <- binary(max_length: 100), max_runs: 1000) do
      payload =
        IO.iodata_to_binary([CompactSize.encode(n), :crypto.strong_rand_bytes(81 * n), junk])

      r = Message.decode("headers", payload)
      assert match?({:ok, {:headers, _}}, r) or match?({:error, _}, r)
    end
  end
end
