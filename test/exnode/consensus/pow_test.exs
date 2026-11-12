defmodule Exnode.Consensus.PowTest do
  @moduledoc "Vectors from Core v32.1 src/test/pow_tests.cpp and arith_uint256_tests.cpp (bignum_SetCompact)."
  use ExUnit.Case, async: true
  import Bitwise

  alias Exnode.ChainParams
  alias Exnode.Consensus.Pow

  # {compact, value, GetCompact(negative?) arg, expected GetCompact, negative?, overflow?}
  @set_compact [
    {0, 0, false, 0, false, false},
    {0x00123456, 0, false, 0, false, false},
    {0x01003456, 0, false, 0, false, false},
    {0x02000056, 0, false, 0, false, false},
    {0x03000000, 0, false, 0, false, false},
    {0x04000000, 0, false, 0, false, false},
    {0x00923456, 0, false, 0, false, false},
    {0x01803456, 0, false, 0, false, false},
    {0x02800056, 0, false, 0, false, false},
    {0x03800000, 0, false, 0, false, false},
    {0x04800000, 0, false, 0, false, false},
    {0x01123456, 0x12, false, 0x01120000, false, false},
    {0x01FEDCBA, 0x7E, true, 0x01FE0000, true, false},
    {0x02123456, 0x1234, false, 0x02123400, false, false},
    {0x03123456, 0x123456, false, 0x03123456, false, false},
    {0x04123456, 0x12345600, false, 0x04123456, false, false},
    {0x04923456, 0x12345600, true, 0x04923456, true, false},
    {0x05009234, 0x92340000, false, 0x05009234, false, false},
    {0x20123456, 0x123456 <<< (8 * 29), false, 0x20123456, false, false}
  ]

  test "bignum_SetCompact / GetCompact" do
    for {c, v, neg_arg, back, neg, ovf} <- @set_compact do
      assert {^v, ^neg, ^ovf} = Pow.set_compact(c), "SetCompact(#{Integer.to_string(c, 16)})"
      assert Pow.get_compact(v, neg_arg) == back
    end

    assert {_, false, true} = Pow.set_compact(0xFF123456)
    # Core: num = 0x80; GetCompact() == 0x02008000
    assert Pow.get_compact(0x80) == 0x02008000
  end

  setup do: %{main: ChainParams.get(:mainnet)}

  # pow_tests.cpp get_next_work*
  for {name, first_time, height, time, bits, expected, invalid} <- [
        {"get_next_work", 1_261_130_161, 32255, 1_262_152_739, 0x1D00FFFF, 0x1D00D86A, nil},
        {"get_next_work_pow_limit", 1_231_006_505, 2015, 1_233_061_996, 0x1D00FFFF, 0x1D00FFFF,
         nil},
        {"get_next_work_lower_limit_actual", 1_279_008_237, 68543, 1_279_297_671, 0x1C05A3F4,
         0x1C0168FD, -1},
        {"get_next_work_upper_limit_actual", 1_263_163_443, 46367, 1_269_211_443, 0x1C387F6F,
         0x1D00E1FD, 1}
      ] do
    test name, %{main: p} do
      last = %{height: unquote(height), time: unquote(time), bits: unquote(bits)}
      assert Pow.calculate_next_work_required(last, unquote(first_time), p) == unquote(expected)

      assert Pow.permitted_difficulty_transition?(
               p,
               unquote(height) + 1,
               unquote(bits),
               unquote(expected)
             )

      if unquote(invalid) do
        refute Pow.permitted_difficulty_transition?(
                 p,
                 unquote(height) + 1,
                 unquote(bits),
                 unquote(expected) + unquote(invalid)
               )
      end
    end
  end

  describe "CheckProofOfWork" do
    test "negative target", %{main: p} do
      refute Pow.check_proof_of_work(
               <<1::little-256>>,
               Pow.get_compact(p.pow_limit, true),
               p.pow_limit
             )
    end

    test "overflow target", %{main: p} do
      refute Pow.check_proof_of_work(
               <<1::little-256>>,
               bnot(0x00800000) &&& 0xFFFFFFFF,
               p.pow_limit
             )
    end

    test "too easy target", %{main: p} do
      refute Pow.check_proof_of_work(
               <<1::little-256>>,
               Pow.get_compact(p.pow_limit * 2),
               p.pow_limit
             )
    end

    test "hash bigger than target", %{main: p} do
      bits = Pow.get_compact(p.pow_limit)
      refute Pow.check_proof_of_work(<<p.pow_limit * 2::little-256>>, bits, p.pow_limit)
    end

    test "zero target", %{main: p} do
      refute Pow.check_proof_of_work(<<0::256>>, Pow.get_compact(0), p.pow_limit)
    end

    test "mainnet genesis passes", %{main: p} do
      assert Pow.check_proof_of_work(p.genesis_hash, p.genesis.header.bits, p.pow_limit)
    end
  end

  test "work of the genesis difficulty is 0x100010001 (Core chainwork of block 0)" do
    assert Pow.bits_proof(0x1D00FFFF) == 0x100010001
  end

  describe "GetNextWorkRequired min-difficulty (testnet) rules" do
    setup do
      p = ChainParams.get(:testnet)
      limit = Pow.get_compact(p.pow_limit)
      # Chain: height 2016 is a retarget block with real bits, then min-diff blocks.
      real = %{height: 2016, time: 1_000_000, bits: 0x1C00FFFF}
      md1 = %{height: 2017, time: 1_000_600, bits: limit}
      md2 = %{height: 2018, time: 1_001_200, bits: limit}
      parents = %{2018 => md1, 2017 => real, 2016 => nil}
      prev = fn e -> parents[e.height] end
      %{p: p, limit: limit, md2: md2, prev: prev}
    end

    test "a block more than 20 minutes after its parent may use the pow limit", c do
      assert Pow.next_work_required(c.md2, c.md2.time + 1201, c.p, c.prev, nil) == c.limit
    end

    test "otherwise walk back to the last non-min-difficulty block", c do
      assert Pow.next_work_required(c.md2, c.md2.time + 1200, c.p, c.prev, nil) == 0x1C00FFFF
    end
  end

  test "BIP94 retarget uses the first block's nBits, not the last's" do
    p = ChainParams.get(:testnet4)
    first = %{height: 0, time: 0, bits: 0x1C00FFFF}
    last = %{height: 2015, time: p.pow_target_timespan, bits: 0x1D00FFFF}
    # Exact timespan: the retarget keeps the first block's target.
    assert Pow.calculate_next_work_required(last, first.time, p, fn -> first end) == 0x1C00FFFF
    # Without BIP94 (testnet3) it would keep the last block's target.
    assert Pow.calculate_next_work_required(last, first.time, ChainParams.get(:testnet)) ==
             0x1D00FFFF
  end

  test "regtest never retargets" do
    p = ChainParams.get(:regtest)
    last = %{height: 143, time: 999_999_999, bits: 0x207FFFFF}
    assert Pow.calculate_next_work_required(last, 0, p) == 0x207FFFFF
  end
end
