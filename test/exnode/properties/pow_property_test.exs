defmodule Exnode.Properties.PowPropertyTest do
  @moduledoc """
  Difficulty retargeting properties (Core `pow` / `pow_transition` fuzz
  targets):

  * every retarget `next_work_required` computes is a transition
    `permitted_difficulty_transition?` accepts (the assertion in Core's
    `pow_transition`), and stays within the pow limit;
  * `next_work_required` equals a literal transcription of Core v32.1
    `GetNextWorkRequired` / `CalculateNextWorkRequired` (pow.cpp), with its
    own `arith_uint256` compact conversion, on random chains of every
    network: min-difficulty blocks and the walk back past them (testnet,
    testnet4), BIP94's first-block nBits (testnet4), no retargeting
    (regtest), and timespans clamped on both sides.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Exnode.ChainParams
  alias Exnode.Consensus.Pow

  @mask256 (1 <<< 256) - 1

  # --- reference: Core v32.1 pow.cpp and arith_uint256.cpp, transcribed ------------

  # arith_uint256::SetCompact: {value, negative, overflow}. For nSize <= 3
  # nWord is shifted in place, and the flags read the shifted nWord.
  defp ref_set_compact(n) do
    size = n >>> 24
    word = n &&& 0x007FFFFF

    {word, value} =
      if size <= 3 do
        w = word >>> (8 * (3 - size))
        {w, w}
      else
        {word, word <<< (8 * (size - 3)) &&& @mask256}
      end

    negative = word != 0 and (n &&& 0x00800000) != 0

    overflow =
      word != 0 and
        (size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32))

    {value, negative, overflow}
  end

  # arith_uint256::GetCompact(false); nCompact is a uint32_t.
  defp ref_get_compact(v) do
    size = div(bits_of(v) + 7, 8)

    compact =
      if size <= 3,
        do: (v &&& 0xFFFFFFFFFFFFFFFF) <<< (8 * (3 - size)) &&& 0xFFFFFFFF,
        else: v >>> (8 * (size - 3)) &&& 0xFFFFFFFF

    {compact, size} =
      if (compact &&& 0x00800000) != 0, do: {compact >>> 8, size + 1}, else: {compact, size}

    compact ||| size <<< 24
  end

  defp bits_of(0), do: 0
  defp bits_of(v), do: length(Integer.digits(v, 2))

  defp interval(p), do: div(p.pow_target_timespan, p.pow_target_spacing)

  # GetNextWorkRequired; `chain` is height => %{height, time, bits}.
  defp ref_next(chain, last, block_time, p) do
    limit = ref_get_compact(p.pow_limit)

    if rem(last.height + 1, interval(p)) != 0 do
      if p.pow_allow_min_difficulty_blocks do
        if block_time > last.time + p.pow_target_spacing * 2 do
          limit
        else
          ref_walk(chain, last, limit, p).bits
        end
      else
        last.bits
      end
    else
      first = chain[last.height - (interval(p) - 1)]
      ref_calculate(chain, last, first.time, p)
    end
  end

  # while (pindex->pprev && pindex->nHeight % interval != 0 && pindex->nBits == limit)
  defp ref_walk(chain, idx, limit, p) do
    prev = chain[idx.height - 1]

    if prev != nil and rem(idx.height, interval(p)) != 0 and idx.bits == limit,
      do: ref_walk(chain, prev, limit, p),
      else: idx
  end

  # CalculateNextWorkRequired
  defp ref_calculate(chain, last, first_time, p) do
    if p.pow_no_retargeting do
      last.bits
    else
      actual = last.time - first_time

      actual =
        if actual < div(p.pow_target_timespan, 4), do: div(p.pow_target_timespan, 4), else: actual

      actual = if actual > p.pow_target_timespan * 4, do: p.pow_target_timespan * 4, else: actual

      base_bits =
        if p.enforce_bip94,
          do: chain[last.height - (interval(p) - 1)].bits,
          else: last.bits

      {bn, _, _} = ref_set_compact(base_bits)
      bn = bn * actual &&& @mask256
      bn = div(bn, p.pow_target_timespan)
      bn = if bn > p.pow_limit, do: p.pow_limit, else: bn
      ref_get_compact(bn)
    end
  end

  # --- generators -----------------------------------------------------------------

  defp network, do: member_of([:mainnet, :testnet, :testnet4, :signet, :regtest])

  # Bits near the network's real range, the pow limit itself, or anything.
  defp bits(p) do
    limit = Pow.get_compact(p.pow_limit)

    frequency([
      {3, constant(limit)},
      # A positive target (sign bit clear).
      {4, map(integer(0x1700_0000..0x1D00_FFFF), &(&1 &&& Bitwise.bnot(0x0080_0000)))},
      {1, integer(0..0xFFFF_FFFF)}
    ])
  end

  # A chain of `len` blocks (heights 0..len-1); time steps may be negative.
  defp chain(p, len) do
    gen all(
          start <- integer(1_231_006_505..1_900_000_000),
          # Per-chain drift, so a period's timespan lands below, inside and
          # above the clamps (spacing clamps at 150 s and 2,400 s per block).
          drift <- member_of([-200, 0, 400, 600, 900, 3_000]),
          steps <- list_of(integer(-3_600..4_000), length: len),
          bs <- list_of(bits(p), length: len)
        ) do
      {chain, _} =
        steps
        |> Enum.zip(bs)
        |> Enum.with_index()
        |> Enum.reduce({%{}, start}, fn {{dt, b}, h}, {acc, t} ->
          t = max(t + dt + drift, 0)
          {Map.put(acc, h, %{height: h, time: t, bits: b}), t}
        end)

      chain
    end
  end

  # --- properties -------------------------------------------------------------------

  property "pow_transition: every computed retarget is a permitted transition and within the limit" do
    check all(
            net <- member_of([:mainnet, :signet, :testnet, :testnet4]),
            p = ChainParams.get(net),
            old_bits <- integer(0..0xFFFF_FFFF),
            old_time <- integer(0..0xFFFF_FFFF),
            new_time <- integer(0..0xFFFF_FFFF),
            max_runs: 2_000
          ) do
      # As Core's target: an old target above the pow limit is clamped.
      {old_target, _, _} = Pow.set_compact(old_bits)
      old_bits = if old_target > p.pow_limit, do: Pow.get_compact(p.pow_limit), else: old_bits
      n = interval(p)
      first = %{height: 0, time: old_time, bits: old_bits}
      last = %{height: n - 1, time: new_time, bits: old_bits}
      ancestor = fn _, 0 -> first end
      prev = fn _ -> nil end

      new_bits = Pow.next_work_required(last, new_time, p, prev, ancestor)
      assert Pow.permitted_difficulty_transition?(p, n, old_bits, new_bits)

      {target, negative, overflow} = Pow.set_compact(new_bits)
      refute negative or overflow
      assert target <= p.pow_limit
    end
  end

  property "next_work_required equals Core's GetNextWorkRequired on random chains of every network" do
    check all(
            net <- network(),
            p = ChainParams.get(net),
            extra <- integer(0..60),
            chain <- chain(p, interval(p) + extra),
            offsets <- list_of(integer(0..(interval(p) + extra - 1)), length: 40),
            late <- list_of(integer(-1_200..3_000), length: 40),
            max_runs: 60
          ) do
      prev_fun = fn e -> chain[e.height - 1] end
      ancestor_fun = fn _e, h -> chain[h] end

      # Every retarget boundary in the chain, plus random heights.
      heights = Enum.uniq([interval(p) - 1 | offsets])

      for {h, dt} <- Enum.zip(heights, Stream.cycle(late)),
          last = chain[h],
          # A retarget needs the period's first block in the chain.
          rem(h + 1, interval(p)) != 0 or h - (interval(p) - 1) >= 0 do
        t = last.time + dt
        want = ref_next(chain, last, t, p)
        got = Pow.next_work_required(last, t, p, prev_fun, ancestor_fun)

        hit(branch(chain, last, t, p))

        assert got == want,
               "#{net} height #{h + 1}: exnode #{Integer.to_string(got, 16)} vs Core #{Integer.to_string(want, 16)}"
      end
    end

    hits =
      for k <-
            ~w(retarget retarget_bip94 clamp_low clamp_high no_retarget same_bits min_difficulty walk_back no_walk)a,
          into: %{},
          do: {k, Process.get({:hit, k}, 0)}

    IO.puts("retarget property branches: #{inspect(hits)}")
    for {k, n} <- hits, do: assert(n > 0, "branch #{k} never exercised")
  end

  defp hit(k), do: Process.put({:hit, k}, Process.get({:hit, k}, 0) + 1)

  # Which rule decided the result, for the coverage check.
  defp branch(chain, last, t, p) do
    limit = ref_get_compact(p.pow_limit)

    cond do
      rem(last.height + 1, interval(p)) == 0 and p.pow_no_retargeting ->
        :no_retarget

      rem(last.height + 1, interval(p)) == 0 ->
        span = last.time - chain[last.height - (interval(p) - 1)].time

        cond do
          span < div(p.pow_target_timespan, 4) -> :clamp_low
          span > p.pow_target_timespan * 4 -> :clamp_high
          p.enforce_bip94 -> :retarget_bip94
          true -> :retarget
        end

      not p.pow_allow_min_difficulty_blocks ->
        :same_bits

      t > last.time + p.pow_target_spacing * 2 ->
        :min_difficulty

      ref_walk(chain, last, limit, p).height < last.height ->
        :walk_back

      true ->
        :no_walk
    end
  end

  property "the transcribed compact conversion agrees with Pow's on all bits" do
    check all(n <- integer(0..0xFFFF_FFFF), max_runs: 5_000) do
      assert Pow.set_compact(n) == ref_set_compact(n)
      {v, _, _} = ref_set_compact(n)
      assert Pow.get_compact(v) == ref_get_compact(v)
    end
  end
end
