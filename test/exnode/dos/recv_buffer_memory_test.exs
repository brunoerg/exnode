defmodule Exnode.DoS.RecvBufferMemoryTest do
  @moduledoc """
  AUD-F3 (STATE_MACHINES.md; regression): a peer that announces a 4 MB
  frame and trickles its payload in 1-byte TCP segments must cost about one
  byte of memory per byte held, as Core's ~4 MB per connection. The receive
  buffers used to cons each segment onto an iodata list, ~48 B of heap per
  byte (~200 MB per connection for one 4 MB frame; tens of connections OOM
  the node). Both transports are covered: the v1 `FrameBuffer` and the v2
  `Transport` tail. Memory is measured in a fresh process after a GC: heap
  plus the off-heap binaries it references.
  """
  use ExUnit.Case, async: true
  @moduletag :dos

  alias Exnode.P2P.{Frame, FrameBuffer}
  alias Exnode.P2P.V2.Transport

  @magic Exnode.ChainParams.get(:regtest).magic
  @bytes 400_000
  # Bytes of memory allowed per payload byte held (binary capacity doubling
  # gives up to ~2; the iodata list gave ~48).
  @max_per_byte 3

  # Runs `f` in a new process; returns the memory it holds for f's result.
  defp held_memory(f) do
    parent = self()

    spawn_link(fn ->
      state = f.()
      :erlang.garbage_collect()
      {:memory, heap} = Process.info(self(), :memory)
      {:binary, bins} = Process.info(self(), :binary)
      send(parent, {:held, heap + Enum.sum(for {_, size, _} <- bins, do: size)})
      # Keep `state` alive until measured.
      _ = :erlang.phash2(state)
    end)

    receive do
      {:held, n} -> n
    end
  end

  test "v1: a trickled frame costs about one byte per byte" do
    header = IO.iodata_to_binary(Frame.encode(@magic, "block", <<>>))
    <<head::binary-16, _len::32, _cksum::binary>> = header
    header = <<head::binary, 4_000_000::little-32, 0::32>>

    held =
      held_memory(fn ->
        Enum.reduce(1..@bytes, FrameBuffer.append(FrameBuffer.new(), header), fn i, fb ->
          {:more, fb} = FrameBuffer.next(FrameBuffer.append(fb, <<i::8>>), @magic)
          fb
        end)
      end)

    IO.puts("v1 trickle: #{@bytes} B held in #{held} B (#{Float.round(held / @bytes, 2)} B/B)")
    assert held < @max_per_byte * @bytes
  end

  test "v2: a trickled packet costs about one byte per byte" do
    {a, a_out} = Transport.new(true, @magic, garbage: <<>>)
    {b, <<>>} = Transport.new(false, @magic, garbage: <<>>)
    {:ok, b, b_out, []} = Transport.received(b, a_out)
    {:ok, a, a_out2, []} = Transport.received(a, b_out)
    {:ok, b, <<>>, []} = Transport.received(b, a_out2)

    {_a, wire} = Transport.send_message(a, "block", :binary.copy(<<7>>, @bytes + 100))
    <<partial::binary-size(@bytes), _::binary>> = wire

    held =
      held_memory(fn ->
        Enum.reduce(:binary.bin_to_list(partial), b, fn byte, b ->
          {:ok, b, <<>>, []} = Transport.received(b, <<byte>>)
          b
        end)
      end)

    IO.puts("v2 trickle: #{@bytes} B held in #{held} B (#{Float.round(held / @bytes, 2)} B/B)")
    assert held < @max_per_byte * @bytes
  end
end
