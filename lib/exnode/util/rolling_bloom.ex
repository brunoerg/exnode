defmodule Exnode.Util.RollingBloom do
  @moduledoc """
  Core's `CRollingBloomFilter` (common/bloom.cpp): remembers at least the
  last `n` keys inserted, with false positive rate `fp`, in a fixed size.

  Keys go into one of three generations of `n / 2` entries; each of the
  filter's `nFilterBits` slots holds the 2-bit generation that last set it
  (0: unset). Starting a fourth generation clears the slots of the oldest.
  Sizes follow Core's formulas: for `n = 50,000`, `fp = 10⁻⁶`, 20 hash
  functions, 2,156,646 slots, 67,396 words (539,168 bytes), as Core.

  Layout: Core keeps a slot's two bits in two parallel words (two reads and
  two writes per hash function). Here they are adjacent in one word (32
  slots per word): the same size and rate, half the `:atomics` calls, which
  dominate the cost in the VM.

  The words and the generation counters live in an `:atomics` array: off
  the owner's heap (not copied by its garbage collections), changed in
  place, so `insert/2` returns the same handle. Only the owning process
  uses it (TxRelay).

  Positions differ from Core's: instead of MurmurHash3 seeded per hash
  function with a random tweak, a SHA-256 of a random tweak and the key
  gives two 32-bit values combined by double hashing. The rates are the
  same; nothing depends on the exact positions.
  """
  import Bitwise

  defstruct [:a, :slots, :words, :k, :per_gen, :tweak]

  # :atomics indexes: entries in this generation, generation (1..3), data.
  @entries 1
  @gen 2
  @data 3
  # The low bit of every 2-bit field.
  @low 0x5555555555555555

  @doc "A filter remembering at least the last `n` keys, false positive rate `fp`."
  def new(n, fp, opts \\ []) do
    log_fp = :math.log(fp)
    k = max(1, min(round(log_fp / :math.log(0.5)), 50))
    per_gen = div(n + 1, 2)
    max_elements = per_gen * 3

    slots =
      trunc(Float.ceil(-1.0 * k * max_elements / :math.log(1.0 - :math.exp(log_fp / k))))

    # Core: data.resize(CeilDiv(nFilterBits, 64) << 1) words of 64 bits.
    words = div(slots + 63, 64) <<< 1
    a = :atomics.new(words + @data - 1, signed: false)
    :atomics.put(a, @gen, 1)
    tweak = Keyword.get_lazy(opts, :tweak, fn -> :crypto.strong_rand_bytes(16) end)
    %__MODULE__{a: a, slots: slots, words: words, k: k, per_gen: per_gen, tweak: tweak}
  end

  @doc "Bytes of filter data (off-heap)."
  def bytes(%__MODULE__{words: w}), do: w * 8

  @doc "Core `insert`. Returns the filter (the same handle)."
  def insert(%__MODULE__{a: a} = f, key) do
    if :atomics.get(a, @entries) == f.per_gen, do: next_generation(f)
    :atomics.add(a, @entries, 1)
    {x, y} = seeds(f, key)
    set(a, f, x, y, :atomics.get(a, @gen), 0)
    f
  end

  defp set(_a, %{k: k}, _x, _y, _gen, i) when i == k, do: :ok

  defp set(a, f, x, y, gen, i) do
    {w, shift} = slot(f, x, y, i)
    :atomics.put(a, w, (:atomics.get(a, w) &&& bnot(3 <<< shift)) ||| gen <<< shift)
    set(a, f, x, y, gen, i + 1)
  end

  @doc "Core `contains`: false is certain; true may be a false positive."
  def contains?(%__MODULE__{a: a} = f, key) do
    {x, y} = seeds(f, key)
    contains?(a, f, x, y, 0)
  end

  defp contains?(_a, %{k: k}, _x, _y, i) when i == k, do: true

  defp contains?(a, f, x, y, i) do
    {w, shift} = slot(f, x, y, i)

    if (:atomics.get(a, w) >>> shift &&& 3) != 0,
      do: contains?(a, f, x, y, i + 1),
      else: false
  end

  # Core: start the next generation (1 -> 2 -> 3 -> 1) and clear the slots
  # last set by it, i.e. by the generation before the previous two.
  defp next_generation(%__MODULE__{a: a, words: words}) do
    :atomics.put(a, @entries, 0)
    gen = rem(:atomics.get(a, @gen), 3) + 1
    :atomics.put(a, @gen, gen)
    clear(a, gen * @low, @data, words + @data - 1)
  end

  # In each word, the 2-bit fields equal to the generation (`pattern`: it in
  # every field) become 0.
  defp clear(_a, _pattern, i, last) when i > last, do: :ok

  defp clear(a, pattern, i, last) do
    w = :atomics.get(a, i)

    if w != 0 do
      x = bxor(w, pattern)
      equal = bnot(x ||| x >>> 1) &&& @low
      :atomics.put(a, i, w &&& bnot(equal ||| equal <<< 1))
    end

    clear(a, pattern, i + 1, last)
  end

  defp seeds(f, key) do
    <<x::32, y::32, _::binary>> = :crypto.hash(:sha256, [f.tweak, key])
    {x, y}
  end

  # The i-th double hash, mapped onto a slot (Core FastRange32): its word
  # (an :atomics index) and the shift of its 2-bit field.
  defp slot(f, x, y, i) do
    s = ((x + i * y &&& 0xFFFFFFFF) * f.slots) >>> 32
    {(s >>> 5) + @data, (s &&& 31) <<< 1}
  end
end
