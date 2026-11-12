defmodule Exnode.Validation.Block do
  @moduledoc """
  Context-free and contextual block checks. Ports of Core v32.1
  `validation.cpp`: `CheckBlock`, `CheckMerkleRoot`, `ContextualCheckBlock`,
  `CheckWitnessMalleation`, plus `GetWitnessCommitmentIndex` and
  `GetBlockWeight` (consensus/validation.h).

  Errors are `{:error, {result, reject_reason}}`. `result` is Core's
  BlockValidationResult (`:mutated`, `:consensus`, `:invalid_header`).
  MUTATED failures must not mark the block hash permanently invalid.
  """
  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex, as: Index
  alias Exnode.Codec.{Block, CompactSize, Tx}
  alias Exnode.Consensus
  alias Exnode.Crypto.Hash
  alias Exnode.Script
  alias Exnode.Validation.{Header, Merkle, TxCheck}

  @sequence_final 0xFFFFFFFF
  @min_witness_commitment 38

  @doc """
  Core `CheckBlock(block, state, params, fCheckPOW, fCheckMerkleRoot)`.
  Signet's `CheckSignetBlockSolution` needs script verification; the caller
  passes it as the `signet_check` option.
  """
  # Core: CheckBlock (validation.cpp)
  def check_block(%Block{} = b, %ChainParams{} = p, opts \\ []) do
    check_pow = Keyword.get(opts, :check_pow, true)
    check_merkle = Keyword.get(opts, :check_merkle, true)
    signet_check = Keyword.get(opts, :signet_check)

    with :ok <- if(check_pow, do: Header.check_block_header(b.header, p), else: :ok),
         :ok <- signet(p, b, check_pow, signet_check),
         :ok <- if(check_merkle, do: check_merkle_root(b), else: :ok),
         :ok <- check_size_limits(b),
         :ok <- check_coinbases(b),
         :ok <- check_transactions(b.txs) do
      check_legacy_sigops(b.txs)
    end
  end

  # A solution the kernel could not check (`{:local, r}`, an API error) is
  # not bad-signet-blksig: it is reported as a local `:crash` result, which
  # peers never punish and the chain state quarantines instead of marking
  # the header failed.
  defp signet(%ChainParams{signet_blocks: true}, b, true, f) when is_function(f, 1) do
    case f.(b) do
      true -> :ok
      false -> {:error, {:consensus, "bad-signet-blksig"}}
      {:local, r} -> {:error, {:crash, "signet solution not checked locally: #{inspect(r)}"}}
    end
  end

  defp signet(_p, _b, _pow, _f), do: :ok

  # Core: CheckMerkleRoot
  def check_merkle_root(%Block{} = b) do
    {root, mutated} = Merkle.block_root(b.txs)

    cond do
      root != b.header.merkle_root -> {:error, {:mutated, "bad-txnmrklroot"}}
      mutated -> {:error, {:mutated, "bad-txns-duplicate"}}
      true -> :ok
    end
  end

  defp check_size_limits(%Block{txs: txs} = b) do
    max = Consensus.max_block_weight()

    if txs == [] or length(txs) * 4 > max or base_size(b) * 4 > max,
      do: {:error, {:consensus, "bad-blk-length"}},
      else: :ok
  end

  defp check_coinbases(%Block{txs: [cb | rest]}) do
    cond do
      not Tx.coinbase?(cb) -> {:error, {:consensus, "bad-cb-missing"}}
      Enum.any?(rest, &Tx.coinbase?/1) -> {:error, {:consensus, "bad-cb-multiple"}}
      true -> :ok
    end
  end

  defp check_transactions(txs) do
    Enum.find_value(txs, :ok, fn tx ->
      case TxCheck.check_transaction(tx) do
        :ok -> nil
        {:error, reason} -> {:error, {:consensus, reason}}
      end
    end)
  end

  defp check_legacy_sigops(txs) do
    n = Enum.reduce(txs, 0, &(&2 + legacy_sigop_count(&1)))

    if n * 4 > Consensus.max_block_sigops_cost(),
      do: {:error, {:consensus, "bad-blk-sigops"}},
      else: :ok
  end

  @doc "Core `GetLegacySigOpCount(tx)`."
  # Core: GetLegacySigOpCount (consensus/tx_verify.cpp)
  def legacy_sigop_count(%Tx{} = tx) do
    Enum.reduce(tx.inputs, 0, &(&2 + Script.sigop_count(&1.script_sig, false))) +
      Enum.reduce(tx.outputs, 0, &(&2 + Script.sigop_count(&1.script_pubkey, false)))
  end

  @doc "Serialized size without witness (Core `GetSerializeSize(TX_NO_WITNESS(block))`)."
  def base_size(%Block{txs: txs}),
    do: 80 + CompactSize.size(length(txs)) + Enum.reduce(txs, 0, &(&2 + Tx.base_size(&1)))

  def total_size(%Block{txs: txs}),
    do: 80 + CompactSize.size(length(txs)) + Enum.reduce(txs, 0, &(&2 + Tx.total_size(&1)))

  @doc "Core `GetBlockWeight`."
  def weight(b), do: base_size(b) * 3 + total_size(b)

  @doc """
  Core `ContextualCheckBlock(block, state, chainman, pindexPrev)`.
  `prev` is the parent's index entry (nil only for genesis).
  """
  # Core: ContextualCheckBlock (validation.cpp)
  def contextual_check_block(%Block{} = b, prev, %ChainParams{} = p, %Index{} = idx) do
    height = if prev, do: prev.height + 1, else: 0

    # DeploymentActiveAfter(pindexPrev, X) == height >= DeploymentHeight(X)
    cutoff =
      if prev && height >= p.csv_height,
        do: Index.median_time_past(idx, prev),
        else: b.header.time

    cond do
      not Enum.all?(b.txs, &final_tx?(&1, height, cutoff)) ->
        {:error, {:consensus, "bad-txns-nonfinal"}}

      height >= p.bip34_height and not bip34_prefix?(b, height) ->
        {:error, {:consensus, "bad-cb-height"}}

      true ->
        with :ok <- check_witness_malleation(b, height >= p.segwit_height) do
          if weight(b) > Consensus.max_block_weight(),
            do: {:error, {:consensus, "bad-blk-weight"}},
            else: :ok
        end
    end
  end

  defp bip34_prefix?(%Block{txs: [cb | _]}, height) do
    expect = Script.push_int(height)
    sig = hd(cb.inputs).script_sig
    byte_size(sig) >= byte_size(expect) and binary_part(sig, 0, byte_size(expect)) == expect
  end

  @doc "Core `IsFinalTx(tx, nBlockHeight, nBlockTime)`."
  # Core: IsFinalTx (consensus/tx_verify.cpp)
  def final_tx?(%Tx{locktime: 0}, _h, _t), do: true

  def final_tx?(%Tx{locktime: lt} = tx, height, time) do
    lt < if(lt < Consensus.locktime_threshold(), do: height, else: time) or
      Enum.all?(tx.inputs, &(&1.sequence == @sequence_final))
  end

  @doc "Core `GetWitnessCommitmentIndex`: the index of the *last* matching coinbase output, or nil."
  def witness_commitment_index(%Block{txs: [cb | _]}) do
    cb.outputs
    |> Enum.with_index()
    |> Enum.reduce(nil, fn
      {%Tx.Out{script_pubkey: <<0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED, _::binary>> = spk}, i}, _acc
      when byte_size(spk) >= @min_witness_commitment ->
        i

      _, acc ->
        acc
    end)
  end

  def witness_commitment_index(_), do: nil

  # Core: CheckWitnessMalleation
  def check_witness_malleation(%Block{} = b, expect_commitment) do
    commit = if expect_commitment, do: witness_commitment_index(b), else: nil

    if commit != nil do
      [cb | _] = b.txs

      case hd(cb.inputs).witness do
        [nonce] when byte_size(nonce) == 32 ->
          root = Merkle.block_witness_root(b.txs)
          expected = Hash.hash256([root, nonce])

          <<_::binary-size(6), committed::binary-size(32), _::binary>> =
            Enum.at(cb.outputs, commit).script_pubkey

          if committed == expected,
            do: :ok,
            else: {:error, {:mutated, "bad-witness-merkle-match"}}

        _ ->
          {:error, {:mutated, "bad-witness-nonce-size"}}
      end
    else
      if Enum.any?(b.txs, & &1.has_witness),
        do: {:error, {:mutated, "unexpected-witness"}},
        else: :ok
    end
  end
end
