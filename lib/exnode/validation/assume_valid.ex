defmodule Exnode.Validation.AssumeValid do
  @moduledoc """
  assumevalid. Port of the `script_check_reason` computation in Core v32.1
  `Chainstate::ConnectBlock` (validation.cpp). Scripts are skipped for a block
  only if *all* of these hold:

  1. an assumevalid hash is configured (`-assumevalid=0` disables it)
  2. that hash is in the header tree
  3. the block is an ancestor of the assumevalid block
  4. the block is an ancestor of the best header
  5. the best header's chain work ≥ nMinimumChainWork
  6. `GetBlockProofEquivalentTime(best, block, best)` > two weeks

  Returns `{:check, reason}` (Core's log string) or `:skip`.
  """
  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex, as: Index
  alias Exnode.Consensus.Pow

  @two_weeks 60 * 60 * 24 * 7 * 2
  @int64_max 0x7FFFFFFFFFFFFFFF

  @doc """
  `assume_valid` is a hash (internal byte order) or nil. Use `resolve/2` to
  turn a config value into one.
  """
  # Core: Chainstate::ConnectBlock, script_check_reason
  def decide(nil, _idx, _entry, _p), do: {:check, "assumevalid=0 (always verify)"}

  def decide(av_hash, %Index{} = idx, %Index.Entry{} = entry, %ChainParams{} = p) do
    av = Index.lookup(idx, av_hash)
    best = Index.best(idx)

    cond do
      av == nil ->
        {:check, "assumevalid hash not in headers"}

      not same?(Index.ancestor(idx, av, entry.height), entry) ->
        {:check,
         if(entry.height > av.height,
           do: "block height above assumevalid height",
           else: "block not in assumevalid chain"
         )}

      not same?(Index.ancestor(idx, best, entry.height), entry) ->
        {:check, "block not in best header chain"}

      best.chain_work < p.minimum_chain_work ->
        {:check, "best header chainwork below minimumchainwork"}

      proof_equivalent_time(best, entry, best, p) <= @two_weeks ->
        {:check, "block too recent relative to best header"}

      true ->
        :skip
    end
  end

  defp same?(%Index.Entry{hash: h}, %Index.Entry{hash: h}), do: true
  defp same?(_, _), do: false

  @doc "Core `GetBlockProofEquivalentTime(to, from, tip, params)` (chain.cpp)."
  # Core: GetBlockProofEquivalentTime (chain.cpp)
  def proof_equivalent_time(to, from, tip, p) do
    {r, sign} =
      if to.chain_work > from.chain_work,
        do: {to.chain_work - from.chain_work, 1},
        else: {from.chain_work - to.chain_work, -1}

    r = div(r * p.pow_target_spacing, Pow.bits_proof(tip.bits))
    if r > @int64_max, do: sign * @int64_max, else: sign * r
  end

  @doc "Config value → hash: `nil` or `:default` uses the chain default; `\"0\"` disables; else display hex."
  def resolve(value, %ChainParams{} = p) do
    case value do
      v when v in [nil, :default] ->
        if p.default_assume_valid == <<0::256>>, do: nil, else: p.default_assume_valid

      "0" ->
        nil

      0 ->
        nil

      hex when is_binary(hex) and byte_size(hex) == 64 ->
        Exnode.Crypto.Hash.from_hex(hex)
    end
  end
end
