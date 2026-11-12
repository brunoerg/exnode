defmodule Exnode.P2P.FrameBuffer do
  @moduledoc """
  Receive buffer for the v1 transport, linear in the bytes received however
  the TCP stream is split, in both time and memory. The buffer is a
  single binary grown by appending, which the VM amortises (in-place append
  with spare capacity), so appending is amortised O(segment) and the buffer
  costs about 1-2 bytes per byte held. An iodata list instead cost about 48
  bytes of heap per byte for 1-byte segments, ~200 MB for one trickled 4 MB
  frame (AUD-F3). Decoding happens only when it can make
  progress: once the 24-byte header is complete (to learn the length, and
  refuse a bad magic or an oversized length right there, as `Frame.decode/2`
  does), and once the whole frame is there.

  Decoding itself is `Frame.decode/2`, whose results are returned unchanged.
  """

  alias Exnode.P2P.Frame

  # A remainder smaller than this, left after a large frame, is copied so it
  # does not keep the large binary alive. Likewise a payload that would leave
  # at least this many bytes of its parent binary referenced is copied: a
  # small message (e.g. a tx kept as an orphan or in the mempool) must not
  # pin the ~4 MB receive buffer it was sliced from. Each
  # payload is copied at most once, so receiving stays linear.
  @copy_below 4096

  defstruct data: <<>>, bytes: 0, expected: nil

  def new, do: %__MODULE__{}

  @doc "A buffer starting with `bin` (bytes already received)."
  def from_binary(bin) when is_binary(bin), do: %__MODULE__{data: bin, bytes: byte_size(bin)}

  def append(%__MODULE__{data: buf} = fb, data) do
    data = IO.iodata_to_binary(data)
    %{fb | data: <<buf::binary, data::binary>>, bytes: fb.bytes + byte_size(data)}
  end

  def size(%__MODULE__{bytes: n}), do: n

  @doc """
  The next frame: `{:ok, command, payload, fb}`, `{:reject, command, fb}`,
  `{:more, fb}`, or `{:error, reason}` (the caller disconnects).
  """
  def next(%__MODULE__{} = fb, magic) do
    header = Frame.header_size()

    cond do
      # Before the header is complete: at most 24 bytes, so flattening is cheap;
      # Frame.decode checks the magic as soon as its bytes are there.
      fb.expected == nil and fb.bytes < header ->
        case Frame.decode(magic, fb.data) do
          :more -> {:more, fb}
          err -> err
        end

      fb.expected == nil ->
        case Frame.peek_length(magic, fb.data) do
          {:ok, len} -> next(%{fb | expected: header + len}, magic)
          err -> err
        end

      fb.bytes < fb.expected ->
        {:more, fb}

      true ->
        bin = fb.data

        case Frame.decode(magic, bin) do
          {:ok, cmd, payload, rest} ->
            {:ok, cmd, own_payload(payload, bin), rest_buffer(rest, bin)}

          {:reject, cmd, rest} ->
            {:reject, cmd, rest_buffer(rest, bin)}

          err ->
            err
        end
    end
  end

  defp own_payload(payload, parent) do
    if byte_size(parent) - byte_size(payload) >= @copy_below,
      do: :binary.copy(payload),
      else: payload
  end

  defp rest_buffer(rest, parent) do
    rest =
      if byte_size(rest) < @copy_below and byte_size(parent) > 2 * @copy_below,
        do: :binary.copy(rest),
        else: rest

    from_binary(rest)
  end
end
