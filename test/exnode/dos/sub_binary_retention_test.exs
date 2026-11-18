defmodule Exnode.DoS.SubBinaryRetentionTest do
  @moduledoc """
  Regression: a slice of 64 bytes or more of a binary references the whole
  binary, so a small long-lived value can keep a large received one alive.

  * the version `user_agent` (up to 256 bytes) is kept for the
    connection's lifetime; it was a slice of the version payload, which may
    carry up to 4 MB of trailing bytes (Core ignores them).
  * after a frame (v1) or packet (v2), the receive buffer's remainder
    was copied only under 4 KiB: a remainder of 4 KiB or more kept the
    ~4 MB message before it alive while the next one filled. Now it is
    copied whenever its binary is more than twice its size.
  """
  use ExUnit.Case, async: true
  @moduletag :dos

  alias Exnode.P2P.{Frame, FrameBuffer, Message}
  alias Exnode.P2P.V2.Transport

  @magic Exnode.ChainParams.get(:regtest).magic
  @big 1_000_000
  @tail 10_000

  # Bytes the process holds for f's result after a GC: heap plus the
  # off-heap binaries it references (as in recv_buffer_memory_test.exs).
  defp held_memory(f) do
    parent = self()

    spawn_link(fn ->
      state = f.()
      :erlang.garbage_collect()
      {:memory, heap} = Process.info(self(), :memory)
      {:binary, bins} = Process.info(self(), :binary)
      send(parent, {:held, heap + Enum.sum(for {_, size, _} <- bins, do: size)})
      _ = :erlang.phash2(state)
    end)

    receive do
      {:held, n} -> n
    end
  end

  test "the version user agent does not keep the version payload alive" do
    ua = String.duplicate("/Satoshi:99.0.0/", 16)
    assert byte_size(ua) == 256

    {"version", payload} =
      Message.encode(
        {:version,
         %{
           version: 70016,
           services: 1,
           time: 0,
           addr_recv: %{services: 1, net: :ipv4, addr: <<1, 2, 3, 4>>, port: 8333},
           nonce: 1,
           user_agent: ua,
           start_height: 0,
           relay: true
         }}
      )

    # Trailing bytes after the relay flag: Core ignores them, so does exnode.
    payload = IO.iodata_to_binary(payload) <> :binary.copy(<<0>>, @big)
    {:ok, {:version, v}} = Message.decode("version", payload)
    assert v.user_agent == ua
    assert :binary.referenced_byte_size(v.user_agent) == byte_size(ua)
  end

  test "v1: a remainder of 4 KiB or more does not keep the frame before it alive" do
    frame = IO.iodata_to_binary(Frame.encode(@magic, "block", :binary.copy(<<7>>, @big)))
    # The start of the next frame: its header and @tail bytes of payload.
    next = IO.iodata_to_binary(Frame.encode(@magic, "block", :binary.copy(<<8>>, 2 * @tail)))
    <<partial::binary-size(@tail), _::binary>> = next

    held =
      held_memory(fn ->
        fb = FrameBuffer.append(FrameBuffer.new(), frame <> partial)
        {:ok, "block", _payload, fb} = FrameBuffer.next(fb, @magic)
        {:more, fb} = FrameBuffer.next(fb, @magic)
        fb
      end)

    IO.puts("v1 remainder: #{@tail} B held in #{held} B")
    assert held < 10 * @tail
  end

  test "v2: a remainder of 4 KiB or more does not keep the packet before it alive" do
    {a, a_out} = Transport.new(true, @magic, garbage: <<>>)
    {b, <<>>} = Transport.new(false, @magic, garbage: <<>>)
    {:ok, b, b_out, []} = Transport.received(b, a_out)
    {:ok, a, a_out2, []} = Transport.received(a, b_out)
    {:ok, b, <<>>, []} = Transport.received(b, a_out2)

    {a, first} = Transport.send_message(a, "block", :binary.copy(<<7>>, @big))
    {_a, second} = Transport.send_message(a, "block", :binary.copy(<<8>>, 2 * @tail))
    <<partial::binary-size(@tail), _::binary>> = IO.iodata_to_binary(second)
    wire = IO.iodata_to_binary(first) <> partial

    held =
      held_memory(fn ->
        {:ok, b, <<>>, [_block]} = Transport.received(b, wire)
        b
      end)

    IO.puts("v2 remainder: #{@tail} B held in #{held} B")
    assert held < 10 * @tail
  end
end
