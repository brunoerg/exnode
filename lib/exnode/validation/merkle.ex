defmodule Exnode.Validation.Merkle do
  @moduledoc "Merkle roots. Port of Core v32.1 `consensus/merkle.cpp`."

  alias Exnode.Crypto.Hash

  @doc """
  Core `ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated)`.

  Returns `{root, mutated?}`. `mutated?` is true if any level has an equal
  adjacent pair (CVE-2012-2459). Every level is checked, as in Core.
  An empty list gives the zero hash.
  """
  # Core: ComputeMerkleRoot (consensus/merkle.cpp)
  def compute_root(hashes), do: compute(hashes, false)

  defp compute([], m), do: {<<0::256>>, m}
  defp compute([root], m), do: {root, m}

  defp compute(hashes, m) do
    m = m or equal_pair?(hashes)
    hashes = if rem(length(hashes), 2) == 1, do: hashes ++ [List.last(hashes)], else: hashes
    compute(pair_up(hashes, []), m)
  end

  # Pairs at positions (0,1), (2,3), ... (Core: pos += 2).
  defp equal_pair?([a, a | _]), do: true
  defp equal_pair?([_, _ | rest]), do: equal_pair?(rest)
  defp equal_pair?(_), do: false

  defp pair_up([], acc), do: Enum.reverse(acc)
  defp pair_up([a, b | rest], acc), do: pair_up(rest, [Hash.hash256([a, b]) | acc])

  @doc "Core `BlockMerkleRoot`: returns `{root, mutated?}` over txids."
  def block_root(txs), do: txs |> Enum.map(& &1.txid) |> compute_root()

  @doc "Core `BlockWitnessMerkleRoot`: the coinbase wtxid is taken as zero."
  def block_witness_root([_cb | rest]) do
    {root, _} = compute_root([<<0::256>> | Enum.map(rest, & &1.wtxid)])
    root
  end
end
