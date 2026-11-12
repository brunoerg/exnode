defmodule Exnode.P2P.InvBucketTest do
  @moduledoc """
  Tx announcements:
  * `Util.TokenBucket`: Core v32.1 `src/test/util_tests.cpp` token_bucket_*
    cases, ported.
  * `P2P.InvBucket` (Core `InvToSendBucket`): the counts Core's
    `test/functional/p2p_tx_relay_rate_limit.py` relies on: a burst
    released at once while tokens last, then `rate` per second; the tx that
    runs a bucket out is still released; outbound gets 2.5x the rate; the
    size bucket limits large txs; mining order is kept.
  """
  use ExUnit.Case, async: true

  alias Exnode.P2P.InvBucket
  alias Exnode.Util.TokenBucket, as: TB

  describe "TokenBucket (Core util_tests.cpp)" do
    test "initial value is clamped to cap" do
      assert TB.value(TB.new(1, 100, 10)) == 10
      assert TB.value(TB.new(1, 5, 10)) == 5
    end

    test "first increment sets the baseline only" do
      b = TB.new(100, 0, 1000) |> TB.increment(10_000)
      assert TB.value(b) == 0
      assert TB.value(TB.increment(b, 15_000)) == 500
    end

    test "refill caps" do
      assert TB.new(10, 90, 100) |> TB.increment(1_000) |> TB.increment(100_000) |> TB.value() ==
               100
    end

    test "time going backwards" do
      b = TB.new(10, 50, 200) |> TB.increment(10_000) |> TB.increment(5_000)
      assert TB.value(b) == 50
      assert TB.value(TB.increment(b, 15_000)) == 150
    end

    test "decrement without debt" do
      b = TB.new(1, 3, 10)
      {b, true} = TB.decrement(b, 1)
      {b, true} = TB.decrement(b, 1)
      {b, false} = TB.decrement(b, 1)
      assert TB.value(b) == 0
      {b, false} = TB.decrement(b, 1)
      assert TB.value(b) == -1
    end

    test "decrement with debt" do
      b = TB.new(1, 2, 10)
      {b, true} = TB.decrement(b, 1, -3)
      {b, true} = TB.decrement(b, 1, -3)
      {b, true} = TB.decrement(b, 1, -3)
      {b, true} = TB.decrement(b, 1, -3)
      {b, false} = TB.decrement(b, 1, -3)
      assert TB.value(b) == -3
    end

    test "drain and refill" do
      {b, _} = TB.decrement(TB.new(10, 20, 100), 20)
      assert TB.value(b) == 0
      assert b |> TB.increment(1_000) |> TB.increment(4_000) |> TB.value() == 30
    end
  end

  # A stand-in for the mempool: txids are integers, mining order = ascending.
  defp extract(sizes) do
    fn txids, n ->
      sorted = txids |> Enum.uniq() |> Enum.filter(&Map.has_key?(sizes, &1)) |> Enum.sort()
      {best, rest} = Enum.split(sorted, n)
      {Enum.map(best, &{&1, sizes[&1]}), rest}
    end
  end

  defp fill(b, txids), do: Enum.reduce(txids, b, &InvBucket.push(&2, &1))

  test "burst while tokens last, then the rate; the tx that runs out is still released" do
    sizes = Map.new(1..2000, &{&1, 200})
    b = InvBucket.new(14, 1.0) |> fill(Enum.shuffle(1..2000)) |> InvBucket.increment(0)
    # count starts at 14 * 30 = 420 and may go to -14 * 5 = -70: 490 released.
    {b, out} = InvBucket.take(b, extract(sizes))
    assert out == Enum.to_list(1..490)
    assert length(InvBucket.backlog(b)) == 1510
    # Out of tokens: nothing more until time passes.
    assert {_, []} = InvBucket.take(b, extract(sizes))
    # 10 s later: +140 tokens, so 140 more (back to -70), in mining order.
    {b, out} = b |> InvBucket.increment(10_000) |> InvBucket.take(extract(sizes))
    assert out == Enum.to_list(491..630)
    # Steady state: 14 per second.
    {_b, total} =
      Enum.reduce(1..60, {b, 0}, fn s, {b, n} ->
        {b, out} = b |> InvBucket.increment(10_000 + s * 1_000) |> InvBucket.take(extract(sizes))
        {b, n + length(out)}
      end)

    assert total == 60 * 14
  end

  test "outbound buckets refill 2.5 times faster" do
    sizes = Map.new(1..3000, &{&1, 200})
    b = InvBucket.new(14, InvBucket.outbound_mult()) |> fill(1..3000) |> InvBucket.increment(0)
    {b, _} = InvBucket.take(b, extract(sizes))
    {_b, out} = b |> InvBucket.increment(10_000) |> InvBucket.take(extract(sizes))
    assert length(out) == 350
  end

  test "the size bucket limits large txs: 12 MB initially, down to -50 kB" do
    sizes = Map.new(1..500, &{&1, 100_000})
    b = InvBucket.new(14, 1.0) |> fill(1..500) |> InvBucket.increment(0)
    # 120 txs bring it to 0 (> -50 kB, still ok); the 121st runs it out and is released.
    {b, out} = InvBucket.take(b, extract(sizes))
    assert length(out) == 121
    assert {_, []} = InvBucket.take(b, extract(sizes))
  end

  test "txs no longer in the mempool are dropped from the backlog" do
    sizes = Map.new(1..10, &{&1, 200})
    b = InvBucket.new(14, 1.0) |> fill(Enum.to_list(1..10) ++ [99, 98]) |> InvBucket.increment(0)
    {b, out} = InvBucket.take(b, extract(sizes))
    assert out == Enum.to_list(1..10)
    assert InvBucket.backlog(b) == []
  end
end
