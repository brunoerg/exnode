defmodule Exnode.Validation.Header do
  @moduledoc """
  Header acceptance. Ports of Core v32.1 `validation.cpp`:
  `CheckBlockHeader`, `ContextualCheckBlockHeader`,
  `ChainstateManager::AcceptBlockHeader` and `ProcessNewBlockHeaders`.

  Failures return `{:error, {result, reject_reason}}`, where `result` is
  Core's `BlockValidationResult` category (as an atom) and `reject_reason`
  is Core's exact string.
  """
  import Bitwise, only: [&&&: 2]

  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex, as: Index
  alias Exnode.Codec.Header
  alias Exnode.Consensus.Pow

  # chain.h
  @max_future_block_time 2 * 60 * 60
  # consensus/consensus.h (BIP94)
  @max_timewarp 600

  def max_future_block_time, do: @max_future_block_time

  @doc "Core `CheckBlockHeader`: proof of work matches the claimed target."
  # Core: CheckBlockHeader (validation.cpp)
  def check_block_header(%Header{} = h, %ChainParams{} = p) do
    if Pow.check_proof_of_work(h.hash, h.bits, p.pow_limit),
      do: :ok,
      else: {:error, {:invalid_header, "high-hash"}}
  end

  @doc """
  Core `ContextualCheckBlockHeader(block, state, chainman, pindexPrev)`.
  `now` is the node clock in Unix seconds.
  """
  # Core: ContextualCheckBlockHeader (validation.cpp)
  def contextual_check_block_header(
        %Header{} = h,
        %Index.Entry{} = prev,
        %ChainParams{} = p,
        %Index{} = idx,
        now
      ) do
    height = prev.height + 1
    interval = Pow.difficulty_adjustment_interval(p)

    expected_bits =
      Pow.next_work_required(prev, h.time, p, &Index.prev(idx, &1), &Index.ancestor(idx, &1, &2))

    cond do
      h.bits != expected_bits ->
        {:error, {:invalid_header, "bad-diffbits"}}

      h.time <= Index.median_time_past(idx, prev) ->
        {:error, {:invalid_header, "time-too-old"}}

      p.enforce_bip94 and rem(height, interval) == 0 and h.time < prev.time - @max_timewarp ->
        {:error, {:invalid_header, "time-timewarp-attack"}}

      h.time > now + @max_future_block_time ->
        {:error, {:time_future, "time-too-new"}}

      # DeploymentActiveAfter(pindexPrev, X) is (pindexPrev->nHeight + 1) >= height(X).
      (h.version < 2 and height >= p.bip34_height) or
        (h.version < 3 and height >= p.bip66_height) or
          (h.version < 4 and height >= p.bip65_height) ->
        {:error, {:invalid_header, "bad-version(0x#{hex32(h.version)})"}}

      true ->
        :ok
    end
  end

  # strprintf("%08x") of an int32 prints its two's-complement bit pattern.
  defp hex32(v),
    do:
      (v &&& 0xFFFFFFFF)
      |> Integer.to_string(16)
      |> String.downcase()
      |> String.pad_leading(8, "0")

  @doc """
  Core `ChainstateManager::AcceptBlockHeader(block, state, ppindex, min_pow_checked)`.

  Returns `{:ok, entry, new?, index}`. `new?` is false when the header was
  already known. Otherwise returns `{:error, {result, reason}}`.
  """
  # Core: ChainstateManager::AcceptBlockHeader (validation.cpp)
  def accept_block_header(%Index{} = idx, %Header{} = h, %ChainParams{} = p, min_pow_checked, now) do
    case Index.lookup(idx, h.hash) do
      %Index.Entry{status: :failed} when h.hash != p.genesis_hash ->
        {:error, {:cached_invalid, "duplicate-invalid"}}

      %Index.Entry{} = e ->
        {:ok, e, false, idx}

      nil ->
        with :ok <- check_block_header(h, p),
             {:ok, prev} <- find_prev(idx, h),
             :ok <- contextual_check_block_header(h, prev, p, idx, now),
             :ok <-
               if(min_pow_checked,
                 do: :ok,
                 else: {:error, {:header_low_work, "too-little-chainwork"}}
               ) do
          e = Index.make_entry(h, prev)
          {:ok, e, true, Index.insert(idx, e)}
        end
    end
  end

  defp find_prev(idx, h) do
    case Index.lookup(idx, h.prev_hash) do
      nil -> {:error, {:missing_prev, "prev-blk-not-found"}}
      %Index.Entry{status: :failed} -> {:error, {:invalid_prev, "bad-prevblk"}}
      prev -> {:ok, prev}
    end
  end

  @doc """
  Core `ProcessNewBlockHeaders`: accepts headers in order and stops at the
  first failure. Returns `{:ok, last_entry, index}` or
  `{:error, reason, last_accepted_entry_or_nil, index}`.
  """
  # Core: ChainstateManager::ProcessNewBlockHeaders (validation.cpp)
  def process_new_block_headers(idx, headers, p, min_pow_checked, now) do
    Enum.reduce_while(headers, {:ok, nil, idx}, fn h, {:ok, last, idx} ->
      case accept_block_header(idx, h, p, min_pow_checked, now) do
        {:ok, e, _new?, idx} -> {:cont, {:ok, e, idx}}
        {:error, reason} -> {:halt, {:error, reason, last, idx}}
      end
    end)
  end
end
