defmodule Exnode.Crypto.Hash do
  @moduledoc "Bitcoin hash helpers. Hashes are kept in internal (little-endian) byte order."

  @doc "SHA256(SHA256(data)), Core `Hash` / `CHash256`. Accepts iodata."
  def hash256(iodata), do: :crypto.hash(:sha256, :crypto.hash(:sha256, iodata))

  @doc "RIPEMD160(SHA256(data)), Core `Hash160`."
  def hash160(iodata), do: :crypto.hash(:ripemd160, :crypto.hash(:sha256, iodata))

  def sha256(iodata), do: :crypto.hash(:sha256, iodata)

  @doc "Internal byte order -> display hex (reversed), as RPC prints it."
  def to_hex(<<_::binary-size(32)>> = h), do: h |> reverse() |> Base.encode16(case: :lower)

  @doc "Display hex -> internal byte order."
  def from_hex(hex) when byte_size(hex) == 64,
    do: hex |> Base.decode16!(case: :mixed) |> reverse()

  def reverse(bin), do: bin |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()
end
