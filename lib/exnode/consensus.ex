defmodule Exnode.Consensus do
  @moduledoc "Consensus constants, copied from Core v32.1 `consensus/consensus.h` and `consensus/amount.h`."

  # consensus/amount.h
  @coin 100_000_000
  @max_money 21_000_000 * @coin
  def coin, do: @coin
  def max_money, do: @max_money

  @doc "Core `MoneyRange`."
  def money_range?(v), do: v >= 0 and v <= @max_money

  # consensus/consensus.h
  def max_block_weight, do: 4_000_000
  def max_block_sigops_cost, do: 80_000
  def coinbase_maturity, do: 100
  def witness_scale_factor, do: 4
  def min_transaction_weight, do: 4 * 60
  def min_serializable_transaction_weight, do: 4 * 10

  # script/script.h
  def locktime_threshold, do: 500_000_000

  @bip30_repeats [
    {91_842, "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"},
    {91_880, "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"}
  ]

  @doc "Core IsBIP30Repeat: only the two exact historical height/hash pairs."
  def bip30_repeat?(height, hash),
    do:
      Enum.any?(@bip30_repeats, fn {h, hex} ->
        height == h and hash == Exnode.Crypto.Hash.from_hex(hex)
      end)
end

defmodule Exnode.Validation.TxCheck do
  @moduledoc "Context-free transaction checks. Port of Core v32.1 `consensus/tx_check.cpp`."

  alias Exnode.Codec.Tx
  alias Exnode.Consensus

  @null_hash <<0::256>>
  @null_index 0xFFFFFFFF

  @doc """
  Core `CheckTransaction(const CTransaction& tx, TxValidationState& state)`.

  Returns `:ok` or `{:error, reject_reason}` with Core's reject-reason string.
  """
  # Core: CheckTransaction (consensus/tx_check.cpp)
  @spec check_transaction(Tx.t()) :: :ok | {:error, String.t()}
  def check_transaction(%Tx{} = tx) do
    cond do
      tx.inputs == [] ->
        {:error, "bad-txns-vin-empty"}

      tx.outputs == [] ->
        {:error, "bad-txns-vout-empty"}

      # Size limit without witness.
      Tx.base_size(tx) * Consensus.witness_scale_factor() > Consensus.max_block_weight() ->
        {:error, "bad-txns-oversize"}

      true ->
        with :ok <- check_outputs(tx.outputs, 0),
             :ok <- check_duplicate_inputs(tx.inputs) do
          check_coinbase_or_prevouts(tx)
        end
    end
  end

  # Negative or overflowing output values (CVE-2010-5139). The running sum is
  # range-checked at each step, as in Core, so int64 overflow cannot happen.
  defp check_outputs([], _sum), do: :ok

  defp check_outputs([%Tx.Out{value: v} | rest], sum) do
    cond do
      v < 0 ->
        {:error, "bad-txns-vout-negative"}

      v > Consensus.max_money() ->
        {:error, "bad-txns-vout-toolarge"}

      not Consensus.money_range?(sum + v) ->
        {:error, "bad-txns-txouttotal-toolarge"}

      true ->
        check_outputs(rest, sum + v)
    end
  end

  # Duplicate inputs (CVE-2018-17144).
  defp check_duplicate_inputs(inputs) do
    inputs
    |> Enum.reduce_while(MapSet.new(), fn %Tx.In{prev_hash: h, prev_index: i}, seen ->
      key = {h, i}
      if MapSet.member?(seen, key), do: {:halt, :dup}, else: {:cont, MapSet.put(seen, key)}
    end)
    |> case do
      :dup -> {:error, "bad-txns-inputs-duplicate"}
      _ -> :ok
    end
  end

  defp check_coinbase_or_prevouts(tx) do
    if Tx.coinbase?(tx) do
      len = byte_size(hd(tx.inputs).script_sig)
      if len < 2 or len > 100, do: {:error, "bad-cb-length"}, else: :ok
    else
      if Enum.any?(tx.inputs, &(&1.prev_hash == @null_hash and &1.prev_index == @null_index)),
        do: {:error, "bad-txns-prevout-null"},
        else: :ok
    end
  end
end
