defmodule Exnode.Consensus.Pow do
  @moduledoc """
  Proof of work. Ports of Core v32.1 `pow.cpp`, `arith_uint256.cpp`
  (compact encoding) and `chain.cpp` (`GetBitsProof`).

  `arith_uint256` arithmetic wraps modulo 2^256. Every shift and multiply
  that can exceed 256 bits is masked the same way, so results match Core
  bit for bit, even where Core would silently overflow.

  Ancestor access goes through a `lookup` function supplied by the caller,
  so this module is independent of how the header tree is stored:

      ancestor_at(index, height) :: index_entry
      prev(index) :: index_entry | nil

  An index entry is any map with `:height`, `:time`, `:bits`.
  """
  import Bitwise

  @mask256 (1 <<< 256) - 1

  # --- arith_uint256 compact encoding --------------------------------------

  @doc """
  Core `arith_uint256::SetCompact(nCompact, &fNegative, &fOverflow)`.
  Returns `{value, negative?, overflow?}`. `value` is the 256-bit magnitude.
  """
  # Core: arith_uint256::SetCompact (arith_uint256.cpp)
  def set_compact(n) when is_integer(n) and n >= 0 and n <= 0xFFFFFFFF do
    size = n >>> 24
    word = n &&& 0x007FFFFF

    # For nSize <= 3 Core shifts nWord in place, and the flags below use
    # that shifted nWord.
    word = if size <= 3, do: word >>> (8 * (3 - size)), else: word
    value = if size <= 3, do: word, else: word <<< (8 * (size - 3)) &&& @mask256

    negative = word != 0 and (n &&& 0x00800000) != 0

    overflow =
      word != 0 and (size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32))

    {value, negative, overflow}
  end

  @doc "Core `arith_uint256::GetCompact(bool fNegative)`."
  # Core: arith_uint256::GetCompact (arith_uint256.cpp)
  def get_compact(value, negative \\ false) when value >= 0 and value <= @mask256 do
    size = div(bit_length(value) + 7, 8)

    compact =
      if size <= 3,
        do: value <<< (8 * (3 - size)) &&& 0xFFFFFFFF,
        else: value >>> (8 * (size - 3)) &&& 0xFFFFFFFF

    {compact, size} =
      if (compact &&& 0x00800000) != 0, do: {compact >>> 8, size + 1}, else: {compact, size}

    compact = compact ||| size <<< 24
    if negative and (compact &&& 0x007FFFFF) != 0, do: compact ||| 0x00800000, else: compact
  end

  defp bit_length(0), do: 0
  defp bit_length(v), do: length(Integer.digits(v, 2))

  # --- targets and work ----------------------------------------------------

  @doc "Core `DeriveTarget(nBits, pow_limit)`: `{:ok, target}` or `:error`."
  # Core: DeriveTarget (pow.cpp)
  def derive_target(bits, pow_limit) do
    {target, negative, overflow} = set_compact(bits)
    if negative or target == 0 or overflow or target > pow_limit, do: :error, else: {:ok, target}
  end

  @doc "Core `CheckProofOfWorkImpl(hash, nBits, params)`. `hash` is in internal byte order."
  # Core: CheckProofOfWorkImpl (pow.cpp)
  def check_proof_of_work(<<_::binary-size(32)>> = hash, bits, pow_limit) do
    case derive_target(bits, pow_limit) do
      {:ok, target} -> :binary.decode_unsigned(hash, :little) <= target
      :error -> false
    end
  end

  @doc "Core `GetBitsProof(bits)`: the work an nBits value represents, `2^256 / (target + 1)`."
  # Core: GetBitsProof (chain.cpp)
  def bits_proof(bits) do
    {target, negative, overflow} = set_compact(bits)
    if negative or overflow or target == 0, do: 0, else: div(1 <<< 256, target + 1)
  end

  # --- retargeting ---------------------------------------------------------

  def difficulty_adjustment_interval(p), do: div(p.pow_target_timespan, p.pow_target_spacing)

  @doc """
  Core `GetNextWorkRequired(pindexLast, pblock, params)`.

  `last` is the previous index entry. `block_time` is the new header's time.
  `prev_fun.(entry)` returns the parent entry or nil. `ancestor_fun.(entry, h)`
  returns the ancestor of `entry` at height `h`.
  """
  # Core: GetNextWorkRequired (pow.cpp)
  def next_work_required(last, block_time, p, prev_fun, ancestor_fun) do
    interval = difficulty_adjustment_interval(p)
    pow_limit_compact = get_compact(p.pow_limit)

    if rem(last.height + 1, interval) != 0 do
      if p.pow_allow_min_difficulty_blocks do
        if block_time > last.time + p.pow_target_spacing * 2 do
          pow_limit_compact
        else
          # Return the last non-special-min-difficulty-rules block.
          walk_back(last, interval, pow_limit_compact, prev_fun).bits
        end
      else
        last.bits
      end
    else
      height_first = last.height - (interval - 1)
      true = height_first >= 0
      first = ancestor_fun.(last, height_first)
      calculate_next_work_required(last, first.time, p, fn -> first end)
    end
  end

  defp walk_back(idx, interval, limit, prev_fun) do
    parent = prev_fun.(idx)

    if parent != nil and rem(idx.height, interval) != 0 and idx.bits == limit,
      do: walk_back(parent, interval, limit, prev_fun),
      else: idx
  end

  @doc """
  Core `CalculateNextWorkRequired(pindexLast, nFirstBlockTime, params)`.

  `first_fun` returns the first block of the period. Only BIP94 needs it,
  for that block's nBits.
  """
  # Core: CalculateNextWorkRequired (pow.cpp)
  def calculate_next_work_required(last, first_block_time, p, first_fun \\ nil) do
    if p.pow_no_retargeting do
      last.bits
    else
      actual =
        (last.time - first_block_time)
        |> max(div(p.pow_target_timespan, 4))
        |> min(p.pow_target_timespan * 4)

      {base, _, _} =
        if p.enforce_bip94, do: set_compact(first_fun.().bits), else: set_compact(last.bits)

      # arith_uint256: *= wraps mod 2^256, then /=
      new = div(base * actual &&& @mask256, p.pow_target_timespan)
      new = if new > p.pow_limit, do: p.pow_limit, else: new
      get_compact(new)
    end
  end

  @doc "Core `PermittedDifficultyTransition(params, height, old_nbits, new_nbits)`."
  # Core: PermittedDifficultyTransition (pow.cpp)
  def permitted_difficulty_transition?(p, height, old_bits, new_bits) do
    cond do
      p.pow_allow_min_difficulty_blocks ->
        true

      rem(height, difficulty_adjustment_interval(p)) == 0 ->
        smallest = div(p.pow_target_timespan, 4)
        largest = p.pow_target_timespan * 4
        {observed, _, _} = set_compact(new_bits)
        {old, _, _} = set_compact(old_bits)

        max_target = old |> scale(largest, p) |> min(p.pow_limit)
        {maximum_new, _, _} = set_compact(get_compact(max_target))

        min_target = old |> scale(smallest, p) |> min(p.pow_limit)
        {minimum_new, _, _} = set_compact(get_compact(min_target))

        not (maximum_new < observed) and not (minimum_new > observed)

      true ->
        old_bits == new_bits
    end
  end

  defp scale(t, timespan, p), do: div(t * timespan &&& @mask256, p.pow_target_timespan)
end
