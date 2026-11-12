defmodule Exnode.P2P.HeadersSync do
  @moduledoc """
  Low-work headers sync anti-DoS. Port of Core v32.1 `HeadersSyncState`
  (`headerssync.cpp`).

  A peer whose headers chain has not yet shown enough work is synced in two
  passes:
  * PRESYNC: headers are checked only for continuity and permitted
    difficulty transitions. Total work is accumulated. One secret bit
    (commitment) is stored every `commitment_period` headers.
  * REDOWNLOAD: once enough work is seen, the same chain is downloaded again
    and checked against the stored commitments. Headers are released for
    full validation only after `redownload_buffer_size` more have been
    buffered, or once the minimum work is reached again.

  This bounds memory per peer while still refusing to store a low-work chain.

  Difference from Core: the commitment hash is HMAC-SHA256 with a random local
  key instead of SipHash (`SaltedUint256Hasher`). Only the low bit of a secret,
  local hash is used, so this has no consensus or wire effect.
  """
  import Bitwise

  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex.Entry
  alias Exnode.Codec.Header
  alias Exnode.Consensus.Pow
  alias Exnode.Validation.Header, as: HeaderRules

  defstruct [
    :params,
    :commitment_period,
    :redownload_buffer_size,
    :commit_offset,
    :key,
    :chain_start,
    :chain_start_locator,
    :minimum_required_work,
    :current_chain_work,
    :last_header_hash,
    :last_header_bits,
    :current_height,
    :max_commitments,
    header_commitments: :queue.new(),
    commitments_len: 0,
    state: :presync,
    redownloaded: :queue.new(),
    redownloaded_len: 0,
    redownload_last_bits: nil,
    redownload_buffer_last_height: 0,
    redownload_buffer_last_hash: nil,
    redownload_chain_work: 0,
    process_all_remaining: false
  ]

  @type t :: %__MODULE__{}

  @doc """
  Core `HeadersSyncState::HeadersSyncState(...)`.

  `chain_start` is the index entry the peer's headers connect to.
  `chain_start_mtp` is its median-time-past. `chain_start_locator` is
  `LocatorEntries(chain_start)`. `now` is in Unix seconds.
  """
  # Core: HeadersSyncState::HeadersSyncState (headerssync.cpp)
  def new(
        %ChainParams{headers_sync: {period, buffer}} = p,
        %Entry{} = chain_start,
        chain_start_mtp,
        chain_start_locator,
        minimum_required_work,
        now
      ) do
    true = period > 0
    max_seconds_since_start = now - chain_start_mtp + HeaderRules.max_future_block_time()

    if max_seconds_since_start < 0 do
      # Core throws SystemClockError here and the node aborts.
      raise "System clock is more than #{div(HeaderRules.max_future_block_time(), 60)} minutes behind chain start MTP"
    end

    %__MODULE__{
      params: p,
      commitment_period: period,
      redownload_buffer_size: buffer,
      commit_offset: :rand.uniform(period) - 1,
      key: :crypto.strong_rand_bytes(32),
      chain_start: chain_start,
      chain_start_locator: chain_start_locator,
      minimum_required_work: minimum_required_work,
      current_chain_work: chain_start.chain_work,
      last_header_hash: chain_start.hash,
      last_header_bits: chain_start.bits,
      current_height: chain_start.height,
      # Core: m_max_commitments = 6 * max_seconds_since_start / commitment_period (int64 division)
      max_commitments: div(6 * max_seconds_since_start, period)
    }
  end

  def state(%__MODULE__{state: s}), do: s
  def presync_height(%__MODULE__{current_height: h}), do: h

  @doc "`\"presync@H\"` or `\"redownload@H\"`: the phase and the height it reached (status lines)."
  def progress(%__MODULE__{state: :redownload} = st),
    do: "redownload@#{st.redownload_buffer_last_height}"

  def progress(%__MODULE__{} = st), do: "#{st.state}@#{st.current_height}"
  def presync_work(%__MODULE__{current_chain_work: w}), do: w

  @doc """
  Core `ProcessNextHeaders(received_headers, full_headers_message)`.

  Returns `{result, state}` with
  `result = %{success: bool, request_more: bool, pow_validated_headers: [Header]}`.
  When the sync ends, success or not, the state becomes `:final`.
  """
  # Core: HeadersSyncState::ProcessNextHeaders (headerssync.cpp)
  def process_next_headers(%__MODULE__{} = st, [], _full), do: {result(false, false, []), st}

  def process_next_headers(%__MODULE__{state: :final} = st, _h, _full),
    do: {result(false, false, []), st}

  def process_next_headers(%__MODULE__{state: :presync} = st, headers, full) do
    case validate_and_store_headers_commitments(st, headers) do
      {:ok, st} ->
        request_more = full or st.state == :redownload
        finish(result(true, request_more, []), st)

      :error ->
        finish(result(false, false, []), st)
    end
  end

  def process_next_headers(%__MODULE__{state: :redownload} = st, headers, full) do
    Enum.reduce_while(headers, {:ok, st}, fn h, {:ok, st} ->
      case validate_and_store_redownloaded_header(st, h) do
        {:ok, st} -> {:cont, {:ok, st}}
        :error -> {:halt, {:error, st}}
      end
    end)
    |> case do
      {:ok, st} ->
        {ready, st} = pop_headers_ready_for_acceptance(st)
        request_more = not (st.redownloaded_len == 0 and st.process_all_remaining) and full
        finish(result(true, request_more, ready), st)

      {:error, st} ->
        finish(result(false, false, []), st)
    end
  end

  defp result(success, request_more, headers),
    do: %{success: success, request_more: request_more, pow_validated_headers: headers}

  defp finish(res, st) do
    if res.success and res.request_more, do: {res, st}, else: {res, finalize(st)}
  end

  # Core: HeadersSyncState::Finalize
  defp finalize(st) do
    %{
      st
      | header_commitments: :queue.new(),
        commitments_len: 0,
        redownloaded: :queue.new(),
        redownloaded_len: 0,
        process_all_remaining: false,
        current_height: 0,
        state: :final
    }
  end

  # Core: HeadersSyncState::ValidateAndStoreHeadersCommitments
  defp validate_and_store_headers_commitments(st, [first | _] = headers) do
    if first.prev_hash != st.last_header_hash do
      :error
    else
      Enum.reduce_while(headers, {:ok, st}, fn h, {:ok, st} ->
        case validate_and_process_single_header(st, h) do
          {:ok, st} -> {:cont, {:ok, st}}
          :error -> {:halt, :error}
        end
      end)
      |> case do
        {:ok, st} ->
          if st.current_chain_work >= st.minimum_required_work do
            {:ok,
             %{
               st
               | redownloaded: :queue.new(),
                 redownloaded_len: 0,
                 redownload_buffer_last_height: st.chain_start.height,
                 redownload_buffer_last_hash: st.chain_start.hash,
                 redownload_last_bits: st.chain_start.bits,
                 redownload_chain_work: st.chain_start.chain_work,
                 state: :redownload
             }}
          else
            {:ok, st}
          end

        :error ->
          :error
      end
    end
  end

  # Core: HeadersSyncState::ValidateAndProcessSingleHeader
  defp validate_and_process_single_header(st, %Header{} = h) do
    next_height = st.current_height + 1

    if not Pow.permitted_difficulty_transition?(
         st.params,
         next_height,
         st.last_header_bits,
         h.bits
       ) do
      :error
    else
      st =
        if rem(next_height, st.commitment_period) == st.commit_offset do
          %{
            st
            | header_commitments: :queue.in(commitment(st, h.hash), st.header_commitments),
              commitments_len: st.commitments_len + 1
          }
        else
          st
        end

      if st.commitments_len > st.max_commitments do
        :error
      else
        {:ok,
         %{
           st
           | current_chain_work: st.current_chain_work + Pow.bits_proof(h.bits),
             last_header_hash: h.hash,
             last_header_bits: h.bits,
             current_height: next_height
         }}
      end
    end
  end

  # Core: HeadersSyncState::ValidateAndStoreRedownloadedHeader
  defp validate_and_store_redownloaded_header(st, %Header{} = h) do
    next_height = st.redownload_buffer_last_height + 1

    cond do
      h.prev_hash != st.redownload_buffer_last_hash ->
        :error

      not Pow.permitted_difficulty_transition?(
        st.params,
        next_height,
        st.redownload_last_bits,
        h.bits
      ) ->
        :error

      true ->
        work = st.redownload_chain_work + Pow.bits_proof(h.bits)
        process_all = st.process_all_remaining or work >= st.minimum_required_work
        st = %{st | redownload_chain_work: work, process_all_remaining: process_all}

        check_commitment? =
          not process_all and rem(next_height, st.commitment_period) == st.commit_offset

        with {:ok, st} <- if(check_commitment?, do: check_commitment(st, h), else: {:ok, st}) do
          {:ok,
           %{
             st
             | redownloaded: :queue.in(h, st.redownloaded),
               redownloaded_len: st.redownloaded_len + 1,
               redownload_buffer_last_height: next_height,
               redownload_buffer_last_hash: h.hash,
               redownload_last_bits: h.bits
           }}
        end
    end
  end

  defp check_commitment(st, h) do
    case :queue.out(st.header_commitments) do
      {:empty, _} ->
        # commitment overrun
        :error

      {{:value, expected}, rest} ->
        if commitment(st, h.hash) == expected,
          do: {:ok, %{st | header_commitments: rest, commitments_len: st.commitments_len - 1}},
          else: :error
    end
  end

  # Core: HeadersSyncState::PopHeadersReadyForAcceptance
  defp pop_headers_ready_for_acceptance(st), do: pop(st, [])

  defp pop(st, acc) do
    if st.redownloaded_len > st.redownload_buffer_size or
         (st.redownloaded_len > 0 and st.process_all_remaining) do
      {{:value, h}, q} = :queue.out(st.redownloaded)
      pop(%{st | redownloaded: q, redownloaded_len: st.redownloaded_len - 1}, [h | acc])
    else
      {Enum.reverse(acc), st}
    end
  end

  @doc "Core `NextHeadersRequestLocator()`."
  # Core: HeadersSyncState::NextHeadersRequestLocator
  def next_headers_request_locator(%__MODULE__{state: :final}), do: []

  def next_headers_request_locator(%__MODULE__{state: :presync} = st),
    do: [st.last_header_hash | st.chain_start_locator]

  def next_headers_request_locator(%__MODULE__{state: :redownload} = st),
    do: [st.redownload_buffer_last_hash | st.chain_start_locator]

  defp commitment(st, hash),
    do: :crypto.mac(:hmac, :sha256, st.key, hash) |> :binary.first() |> band(1)
end
