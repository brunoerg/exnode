defmodule Exnode.P2P.Frame do
  @moduledoc """
  V1 transport framing. Port of Core v32.1 `V1Transport` (net.cpp) and
  `CMessageHeader` (protocol.h/.cpp).

  Header: magic(4) | command(12, NUL-padded) | length(u32 LE) | checksum(4)

  Receive-side outcomes, as in Core:
  * wrong magic, or length > MAX_PROTOCOL_MESSAGE_LENGTH (4,000,000):
    `{:error, reason}`, and the caller disconnects
  * wrong checksum or invalid command: `{:reject, command, rest}`; the
    message is dropped and the connection stays up
  """
  alias Exnode.Crypto.Hash

  # net.h MAX_PROTOCOL_MESSAGE_LENGTH; serialize.h MAX_SIZE is larger.
  @max_len 4_000_000
  @header_size 24

  def max_message_length, do: @max_len

  @doc "Frames `payload` for `command` (≤ 12 ASCII bytes)."
  def encode(magic, command, payload) when byte_size(command) <= 12 do
    payload = IO.iodata_to_binary(payload)
    <<checksum::binary-size(4), _::binary>> = Hash.hash256(payload)
    pad = 12 - byte_size(command)
    [magic, command, <<0::size(pad * 8)>>, <<byte_size(payload)::little-32>>, checksum, payload]
  end

  @doc """
  Extracts one message from the front of `buf`.

  Returns `{:ok, command, payload, rest}`, `{:reject, command, rest}`,
  `:more` (incomplete), or `{:error, reason}` (disconnect).
  `payload` is a sub-binary of `buf`.
  """
  # Core: V1Transport::readHeader / readData / GetReceivedMessage (net.cpp)
  def decode(magic, buf) when byte_size(buf) < @header_size do
    # Check the magic as soon as it is complete, so a garbage stream is dropped early.
    n = min(byte_size(buf), 4)
    if binary_part(buf, 0, n) == binary_part(magic, 0, n), do: :more, else: {:error, :bad_magic}
  end

  def decode(
        magic,
        <<m::binary-size(4), cmd::binary-size(12), len::little-32, checksum::binary-size(4),
          rest::binary>>
      ) do
    cond do
      m != magic ->
        {:error, :bad_magic}

      len > @max_len ->
        {:error, :oversized}

      byte_size(rest) < len ->
        :more

      true ->
        <<payload::binary-size(len), rest::binary>> = rest
        <<expected::binary-size(4), _::binary>> = Hash.hash256(payload)
        command = cmd |> :binary.split(<<0>>) |> hd()

        if expected != checksum or not valid_command?(cmd),
          do: {:reject, command, rest},
          else: {:ok, command, payload, rest}
    end
  end

  @doc """
  The header checks of `decode/2` alone (Core V1Transport::readHeader): for a
  buffer holding at least the 24-byte header, `{:ok, payload_length}` or the
  same early `{:error, :bad_magic | :oversized}`; `:more` before that (with
  the magic checked as soon as its bytes are there, as `decode/2` does).
  """
  def peek_length(magic, buf) when byte_size(buf) < @header_size do
    case decode(magic, buf) do
      :more -> :more
      err -> err
    end
  end

  def peek_length(magic, <<m::binary-size(4), _cmd::binary-size(12), len::little-32, _::binary>>) do
    cond do
      m != magic -> {:error, :bad_magic}
      len > @max_len -> {:error, :oversized}
      true -> {:ok, len}
    end
  end

  def header_size, do: @header_size

  # Core: CMessageHeader::IsMessageTypeValid. Printable ASCII, then only NULs
  # after the first NUL.
  defp valid_command?(cmd) do
    {name, padding} =
      case :binary.match(cmd, <<0>>) do
        {pos, _} -> {binary_part(cmd, 0, pos), binary_part(cmd, pos, 12 - pos)}
        :nomatch -> {cmd, <<>>}
      end

    for(<<c <- name>>, reduce: true, do: (ok -> ok and c >= 0x20 and c <= 0x7E)) and
      for(<<c <- padding>>, reduce: true, do: (ok -> ok and c == 0))
  end
end
