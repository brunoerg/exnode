defmodule Exnode.P2P.PeerFile do
  @moduledoc """
  The files that keep peer data across restarts: `peers.dat` (the address
  book) and `anchors.dat` (block-relay peers to reconnect first). Layout as
  Core's `addrdb.cpp` `SerializeFileDB` (network magic, data, then a
  double-SHA-256 checksum of both), with exnode's own data encoding:

      "exnode-peers" · version (1 byte) · network magic (4) · data · SHA256d(all before)

  `data` is an Erlang external term. Writes go to a temporary file in the
  same directory, are fsynced, then renamed over the target, so a crash
  leaves either the old file or the new one. A missing file reads as
  `:missing`; a wrong magic, version or checksum as `{:error, reason}`, and
  the caller starts empty (as Core does with a corrupt peers.dat).
  """

  @tag "exnode-peers"
  @version 1

  @doc "Writes `term` atomically."
  def write(path, magic, term) do
    body = [@tag, <<@version>>, magic, :erlang.term_to_binary(term, [:compressed])]
    data = [body, Exnode.Crypto.Hash.hash256(body)]
    tmp = path <> ".#{:erlang.unique_integer([:positive])}.tmp"
    File.mkdir_p!(Path.dirname(path))

    with {:ok, f} <- :file.open(tmp, [:write, :raw, :binary]),
         :ok <- :file.write(f, data),
         :ok <- :file.sync(f),
         :ok <- :file.close(f),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      err ->
        File.rm(tmp)
        {:error, err}
    end
  end

  # Decoding is `:safe` (no new atoms from a file). The atoms a peers file
  # holds (entry fields, network names) exist once these modules are loaded,
  # which at node start-up they may not be yet.
  @atom_modules [Exnode.P2P.AddrMan.Table, Exnode.P2P.NetAddr, Exnode.P2P.Message]

  @doc "Reads a file written by `write/3`: `{:ok, term}`, `:missing` or `{:error, reason}`."
  def read(path, magic) do
    Enum.each(@atom_modules, &Code.ensure_loaded/1)

    case File.read(path) do
      {:error, :enoent} -> :missing
      {:error, e} -> {:error, e}
      {:ok, bin} -> decode(bin, magic)
    end
  end

  defp decode(bin, magic) when byte_size(bin) > 32 do
    body = binary_part(bin, 0, byte_size(bin) - 32)
    sum = binary_part(bin, byte_size(bin) - 32, 32)

    cond do
      Exnode.Crypto.Hash.hash256(body) != sum ->
        {:error, :checksum}

      true ->
        case body do
          <<@tag, @version, ^magic::binary-size(4), data::binary>> ->
            try do
              {:ok, :erlang.binary_to_term(data, [:safe])}
            rescue
              _ -> {:error, :undecodable}
            end

          <<@tag, @version, _::binary-size(4), _::binary>> ->
            {:error, :wrong_network}

          _ ->
            {:error, :unknown_format}
        end
    end
  end

  defp decode(_, _), do: {:error, :truncated}
end
