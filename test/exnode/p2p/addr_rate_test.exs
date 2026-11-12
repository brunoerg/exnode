defmodule Exnode.P2P.AddrRateTest do
  @moduledoc "Core ProcessAddrs token bucket."
  use ExUnit.Case, async: true

  alias Exnode.P2P.AddrRate

  test "one token at start, 0.1 per second, capped at 1000, +1000 after getaddr" do
    r = AddrRate.new(0)
    {r, acc, lim} = AddrRate.received(r, Enum.to_list(1..1000), 0)
    assert {length(acc), lim} == {1, 999}
    # 100 s later: 10 tokens.
    {r, acc, lim} = AddrRate.received(r, Enum.to_list(1..1000), 100_000)
    assert {length(acc), lim} == {10, 990}
    # A day later the bucket is capped at 1000.
    {r, acc, _} = AddrRate.received(r, Enum.to_list(1..5000), 100_000 + 86_400_000)
    assert length(acc) == 1000
    # After getaddr: a full 1000-address reply is processed even with the bucket empty.
    {_r, acc, lim} =
      r
      |> AddrRate.getaddr_sent()
      |> AddrRate.received(Enum.to_list(1..1000), 100_000 + 86_400_000)

    assert {length(acc), lim} == {1000, 0}
  end

  test "the getaddr bonus is not capped by the refill cap" do
    r = AddrRate.new(0) |> AddrRate.getaddr_sent()
    {_r, acc, _} = AddrRate.received(r, Enum.to_list(1..2000), 0)
    assert length(acc) == 1001
  end

  test "accepted addresses are a random subset" do
    seen =
      for _ <- 1..30, into: MapSet.new() do
        {_r, [a], _} = AddrRate.received(AddrRate.new(0), Enum.to_list(1..1000), 0)
        a
      end

    assert MapSet.size(seen) > 1
  end
end
