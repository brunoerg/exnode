defmodule Exnode.Util.RollingBloomTest do
  @moduledoc """
  `RollingBloom` as Core's `CRollingBloomFilter`: sizes from Core's
  formulas, the last `n` keys always remembered, older generations
  forgotten, and a false positive rate near the target.
  """
  use ExUnit.Case, async: true

  alias Exnode.Util.RollingBloom

  defp keys(n, tag), do: for(i <- 1..n, do: :crypto.hash(:sha256, <<tag::32, i::32>>))

  test "Core's sizes for the per-peer known filter (50,000, 10^-6)" do
    f = RollingBloom.new(50_000, 1.0e-6)
    assert f.k == 20
    assert f.per_gen == 25_000
    # Core: nFilterBits = 2,156,646; data.resize(CeilDiv(nFilterBits, 64) << 1).
    assert f.words == 67_396
    assert RollingBloom.bytes(f) == 539_168
  end

  test "the last n keys are remembered; keys three generations old are forgotten" do
    n = 1_000
    f = RollingBloom.new(n, 1.0e-6, tweak: <<1::128>>)
    old = keys(n, 1)
    for k <- old, do: RollingBloom.insert(f, k)
    assert Enum.all?(old, &RollingBloom.contains?(f, &1))

    # n more: still within the last 1.5 n, the newest n always remembered.
    newer = keys(n, 2)
    for k <- newer, do: RollingBloom.insert(f, k)
    assert Enum.all?(newer, &RollingBloom.contains?(f, &1))

    # Another 2 n: the generations holding `old` are cleared.
    newest = keys(2 * n, 3)
    for k <- newest, do: RollingBloom.insert(f, k)
    assert Enum.all?(Enum.take(newest, -n), &RollingBloom.contains?(f, &1))
    assert Enum.count(old, &RollingBloom.contains?(f, &1)) <= 1
  end

  test "false positives stay near the target rate" do
    # 1 % to keep the count measurable.
    f = RollingBloom.new(10_000, 0.01, tweak: <<2::128>>)
    for k <- keys(10_000, 4), do: RollingBloom.insert(f, k)
    fp = Enum.count(keys(20_000, 5), &RollingBloom.contains?(f, &1))
    assert fp < 20_000 * 0.02, "#{fp} false positives in 20,000"
  end

  test "insert returns the same handle: no state to thread through" do
    f = RollingBloom.new(100, 1.0e-6)
    assert RollingBloom.insert(f, "a") == f
    assert RollingBloom.contains?(f, "a")
    refute RollingBloom.contains?(f, "b")
  end
end
