defmodule Exnode.Kernel do
  @moduledoc """
  Thin wrapper over the libbitcoinkernel C API (Bitcoin Core v32.1, experimental).

  This module and `native/kernel_nif/kernel_nif.c` are the only places that
  know the kernel API, so a kernel API change touches just these two files.

  Script flags are the `btck_ScriptVerificationFlags` bits from the pinned
  `bitcoinkernel.h`. The kernel exposes only the consensus flags listed
  below. Policy-only flags (STRICTENC, LOW_S, CLEANSTACK, MINIMALDATA, ...)
  cannot be passed through this API.
  """

  import Bitwise

  @on_load :load_nif

  # bitcoinkernel.h (v32.1) btck_ScriptVerificationFlags_*
  @flags %{
    p2sh: 1 <<< 0,
    dersig: 1 <<< 2,
    nulldummy: 1 <<< 4,
    checklocktimeverify: 1 <<< 9,
    checksequenceverify: 1 <<< 10,
    witness: 1 <<< 11,
    taproot: 1 <<< 17
  }
  @all Enum.reduce(Map.values(@flags), 0, &Bitwise.bor/2)

  def load_nif do
    path = :filename.join(:code.priv_dir(:exnode), ~c"native/kernel_nif")
    :erlang.load_nif(path, 0)
  end

  @doc "Map of flag name -> bit."
  def flags, do: @flags
  def flags_all, do: @all

  @doc "Converts a list of flag atoms to a bitfield."
  def flags_to_int(names),
    do: Enum.reduce(names, 0, fn n, acc -> acc ||| Map.fetch!(@flags, n) end)

  @type spent_output :: {script_pubkey :: binary(), amount :: integer()}
  @type input_result :: :ok | :invalid | {:error, atom()}

  @doc """
  Verifies every input of `raw_tx` against its spent output.

  `spent_outputs` must have exactly one `{script_pubkey, amount}` per input, in
  input order. `flags` must be a subset of `flags_all/0`. Both are checked
  here and again in the NIF before the kernel is called, because the kernel
  asserts on them.

  Returns `{:ok, [input_result]}` or `{:error, reason}`.
  """
  @spec verify_tx(binary(), [spent_output()], non_neg_integer()) ::
          {:ok, [input_result()]} | {:error, atom()}
  def verify_tx(raw_tx, spent_outputs, flags)
      when is_binary(raw_tx) and is_list(spent_outputs) and is_integer(flags) do
    cond do
      flags < 0 or (flags &&& bnot(@all)) != 0 ->
        {:error, :unsupported_flags}

      not Enum.all?(spent_outputs, &valid_spent_output?/1) ->
        {:error, :bad_spent_outputs}

      true ->
        try do
          verify_tx_nif(raw_tx, spent_outputs, flags)
        rescue
          ArgumentError -> {:error, :input_count_mismatch}
        end
    end
  end

  @int64_min -0x8000000000000000
  @int64_max 0x7FFFFFFFFFFFFFFF
  defp valid_spent_output?({spk, amt}) when is_binary(spk) and is_integer(amt),
    do: amt >= @int64_min and amt <= @int64_max

  defp valid_spent_output?(_), do: false

  @doc "Verifies a tx and folds the per-input results into `:ok` or `{:error, {input_index, reason}}`."
  def verify_tx_all(raw_tx, spent_outputs, flags) do
    with {:ok, results} <- verify_tx(raw_tx, spent_outputs, flags) do
      results
      |> Enum.with_index()
      |> Enum.find_value(:ok, fn
        {:ok, _} -> nil
        {r, i} -> {:error, {i, r}}
      end)
    end
  end

  defp verify_tx_nif(_tx, _spent, _flags), do: :erlang.nif_error(:nif_not_loaded)
  def flags_all_nif, do: :erlang.nif_error(:nif_not_loaded)
end
