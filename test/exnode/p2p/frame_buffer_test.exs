defmodule Exnode.P2P.FrameBufferTest do
  @moduledoc """
  v1 receive buffer: `FrameBuffer` decodes any chunking of a byte stream
  exactly as one-shot `Frame.decode/2`, keeps the early errors (bad magic from the first
  bytes, oversized length as soon as the header is complete, before any
  payload), resynchronises after a checksum reject, and stays linear for a
  message dribbled byte by byte.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.P2P.{Frame, FrameBuffer}

  @magic <<0xFA, 0xBF, 0xB5, 0xDA>>

  defp frame(cmd, payload, corrupt) do
    bin = IO.iodata_to_binary(Frame.encode(@magic, cmd, payload))

    if corrupt do
      # Flip a checksum byte: the frame is rejected, not fatal.
      <<h::binary-size(20), c, rest::binary>> = bin
      <<h::binary, Bitwise.bxor(c, 0xFF), rest::binary>>
    else
      bin
    end
  end

  # One-shot reference: Frame.decode over the whole stream.
  defp one_shot(bin, acc \\ []) do
    case Frame.decode(@magic, bin) do
      {:ok, cmd, payload, rest} -> one_shot(rest, [{:ok, cmd, payload} | acc])
      {:reject, cmd, rest} -> one_shot(rest, [{:reject, cmd} | acc])
      :more -> Enum.reverse(acc)
      {:error, e} -> Enum.reverse([{:error, e} | acc])
    end
  end

  # Feeds `chunks` of `bin`, draining after each, as Peer does.
  defp chunked(bin, sizes) do
    {chunks, rest} =
      Enum.reduce(sizes, {[], bin}, fn n, {acc, b} ->
        n = min(n, byte_size(b))
        <<c::binary-size(n), r::binary>> = b
        {[c | acc], r}
      end)

    Enum.reduce_while(Enum.reverse([rest | chunks]), {FrameBuffer.new(), []}, fn c, {fb, out} ->
      case drain(FrameBuffer.append(fb, c), out) do
        {:error, _} = e -> {:halt, {nil, out ++ [e]}}
        {fb, out} -> {:cont, {fb, out}}
      end
    end)
    |> elem(1)
  end

  defp drain(fb, out) do
    case FrameBuffer.next(fb, @magic) do
      {:ok, cmd, payload, fb} -> drain(fb, out ++ [{:ok, cmd, payload}])
      {:reject, cmd, fb} -> drain(fb, out ++ [{:reject, cmd}])
      {:more, fb} -> {fb, out}
      {:error, e} -> {:error, e}
    end
  end

  property "any chunking decodes like one-shot decoding" do
    check all(
            msgs <-
              list_of(
                {member_of(~w(ping inv tx block headers)), binary(max_length: 3_000), boolean()},
                min_length: 1,
                max_length: 12
              ),
            sizes <-
              list_of(one_of([constant(1), integer(1..50), integer(1..5_000)]), max_length: 400),
            max_runs: 300
          ) do
      bin = msgs |> Enum.map(fn {c, p, bad} -> frame(c, p, bad) end) |> IO.iodata_to_binary()
      expected = one_shot(bin)
      assert chunked(bin, sizes) == expected
      assert Enum.count(expected, &match?({:reject, _}, &1)) == Enum.count(msgs, &elem(&1, 2))
    end
  end

  test "bad magic is refused from the first bytes" do
    assert {:error, :bad_magic} =
             FrameBuffer.next(FrameBuffer.append(FrameBuffer.new(), <<0xFA, 0x00>>), @magic)

    assert {:more, _} =
             FrameBuffer.next(FrameBuffer.append(FrameBuffer.new(), <<0xFA, 0xBF>>), @magic)
  end

  test "an oversized length is refused once the header is complete, with no payload buffered" do
    header = @magic <> "block" <> <<0::56>> <> <<4_000_001::little-32>> <> <<0::32>>

    {fb, :ok} =
      Enum.reduce(:binary.bin_to_list(binary_part(header, 0, 23)), {FrameBuffer.new(), :ok}, fn b,
                                                                                                {fb,
                                                                                                 _} ->
        fb = FrameBuffer.append(fb, <<b>>)
        {:more, fb} = FrameBuffer.next(fb, @magic)
        {fb, :ok}
      end)

    assert {:error, :oversized} =
             FrameBuffer.next(FrameBuffer.append(fb, binary_part(header, 23, 1)), @magic)
  end

  test "a 1 MB message dribbled one byte at a time is linear" do
    payload = :crypto.strong_rand_bytes(1_000_000)
    bin = frame("block", payload, false)

    {us, result} =
      :timer.tc(fn ->
        Enum.reduce(:binary.bin_to_list(bin), {FrameBuffer.new(), nil}, fn b, {fb, got} ->
          case FrameBuffer.next(FrameBuffer.append(fb, <<b>>), @magic) do
            {:more, fb} -> {fb, got}
            {:ok, "block", p, fb} -> {fb, p}
          end
        end)
      end)

    assert elem(result, 1) == payload
    # Quadratic copying would move ~5e11 bytes here; linear is well under a second.
    assert us < 20_000_000, "took #{div(us, 1000)} ms"
  end
end
