defmodule Exnode.Validation.MerkleTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Crypto.Hash
  alias Exnode.Validation.Merkle

  # A literal transcription of Core v32.1 consensus/merkle.cpp ComputeMerkleRoot.
  defp ref_root([]), do: {<<0::256>>, false}
  defp ref_root([h]), do: {h, false}

  defp ref_root(hashes) do
    mutated =
      hashes
      |> Enum.chunk_every(2)
      |> Enum.any?(fn
        [a, b] -> a == b
        [_] -> false
      end)

    padded = if rem(length(hashes), 2) == 1, do: hashes ++ [List.last(hashes)], else: hashes
    next = padded |> Enum.chunk_every(2) |> Enum.map(fn [a, b] -> Hash.hash256([a, b]) end)
    {root, m2} = ref_root(next)
    {root, mutated or m2}
  end

  defp h(n), do: <<n::256>>

  test "empty list is the zero hash, not mutated" do
    assert Merkle.compute_root([]) == {<<0::256>>, false}
  end

  test "single hash is returned as-is" do
    assert Merkle.compute_root([h(7)]) == {h(7), false}
  end

  test "CVE-2012-2459: [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6] share a root; the latter is mutated" do
    txs = Enum.map(1..6, &h/1)
    {root6, false} = Merkle.compute_root(txs)
    {root8, mutated8} = Merkle.compute_root(txs ++ [h(5), h(6)])
    assert root8 == root6
    assert mutated8
  end

  test "an odd trailing pair formed by padding alone is NOT mutation (Core checks pairs before padding)" do
    # [A,B,A]: level 0 pairs are (A,B) only; the (A,A) pair exists only after
    # the odd-duplication, and Core's per-level check runs before padding.
    assert {_root, false} = Merkle.compute_root([h(1), h(2), h(1)])
    assert {_root, false} = Merkle.compute_root([h(1), h(2), h(3)])
  end

  test "adjacent duplicates at level 0 are mutation" do
    assert {_root, true} = Merkle.compute_root([h(9), h(9)])
  end

  test "mutation at a higher level (pair of equal subtree hashes)" do
    # [A, A, B, C]: level 0 pairs (A,A),(B,C) -> mutated already at level 0.
    # [A, B, A, B]: no equal adjacent at level 0; level 1 = [h(A,B), h(A,B)] -> mutated.
    assert {_root, false} = Merkle.compute_root([h(1), h(2), h(3), h(4)])
    assert {_root, true} = Merkle.compute_root([h(1), h(2), h(1), h(2)])
  end

  property "matches the literal ComputeMerkleRoot transcription" do
    check all(
            hashes <- list_of(binary(length: 32), length: :rand.uniform(25)),
            dup_pos <- integer(0..24)
          ) do
      # Sometimes force a duplicate at a random position to exercise mutation.
      hashes =
        if hashes != [] and :rand.uniform(2) == 1 do
          List.replace_at(hashes, rem(dup_pos, length(hashes)), hd(hashes))
        else
          hashes
        end

      assert Merkle.compute_root(hashes) == ref_root(hashes)
    end
  end
end
