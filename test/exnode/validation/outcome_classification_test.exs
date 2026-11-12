defmodule Exnode.Validation.OutcomeClassificationTest do
  @moduledoc """
  Kernel outcomes are classified before they decide anything: only a script
  the kernel ran and found false is a consensus failure. An API, status or
  argument error is local (our bug or bad local data) and must not become
  `block-script-verify-flag-failed` or `bad-signet-blksig`, i.e. must not
  mark a header failed or get a peer punished. The chain-state side
  (quarantine, source told `:crash`) is in
  `Exnode.Chain.ActivationPlanTest`.
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Validation.{ScriptExec, Scripts, Signet}
  alias Exnode.Validation.Block, as: BlockRules
  alias Exnode.Test.BlockBuilder, as: BB

  test "classification table" do
    assert Scripts.classify(:ok) == :ok

    assert Scripts.classify({:error, {3, :invalid}}) ==
             {:invalid, "block-script-verify-flag-failed"}

    assert Scripts.classify({:error, {0, {:error, :spent_outputs_required}}}) ==
             {:local, {:kernel_status, 0, :spent_outputs_required}}

    for r <- [:bad_tx, :unsupported_flags, :bad_spent_outputs, :input_count_mismatch],
        do: assert(Scripts.classify({:error, r}) == {:local, {:kernel_api, r}})

    # A chunk: proof wins over a local error, wherever it is.
    assert Scripts.combine([:ok, {:local, :x}, {:invalid, "r"}]) == {:invalid, "r"}
    assert Scripts.combine([:ok, {:local, :x}]) == {:local, :x}
    assert Scripts.combine([:ok, :ok]) == :ok
  end

  test "standalone verify_all: invalid is a consensus error, local raises (crash containment)" do
    tx = BB.spend_op_true(<<1::256>>, 0, 1_000)
    assert Scripts.verify_all([{tx.raw, [{<<0x51>>, 2_000}]}], 0) == :ok

    assert Scripts.verify_all([{tx.raw, [{<<0x00>>, 2_000}]}], 0) ==
             {:error, {:consensus, "block-script-verify-flag-failed"}}

    assert_raise Scripts.LocalError, fn -> Scripts.verify_all([{tx.raw, []}], 0) end
  end

  test "signet: a kernel API error is not a bad solution; CheckBlock reports it as :crash" do
    p = ChainParams.get(:signet)
    [b | _] = signet_blocks()
    assert Signet.check(b, p) == true
    assert Signet.check(b, p, fn _, _, _ -> {:error, {0, :invalid}} end) == false

    assert Signet.check(b, p, fn _, _, _ -> {:error, :bad_tx} end) ==
             {:local, {:kernel_api, :bad_tx}}

    assert BlockRules.check_block(b, p,
             signet_check: fn _ -> {:local, {:kernel_api, :bad_tx}} end
           ) ==
             {:error, {:crash, "signet solution not checked locally: {:kernel_api, :bad_tx}"}}

    assert BlockRules.check_block(b, p, signet_check: fn _ -> false end) ==
             {:error, {:consensus, "bad-signet-blksig"}}
  end

  test "mempool path through the executor keeps the kernel's result shape" do
    {:ok, ex} = ScriptExec.start_link(workers: 1)
    tx = BB.spend_op_true(<<1::256>>, 0, 1_000)
    assert ScriptExec.verify(ex, tx.raw, [{<<0x51>>, 2_000}], 0) == :ok
    assert ScriptExec.verify(ex, tx.raw, [{<<0x00>>, 2_000}], 0) == {:error, {0, :invalid}}
    assert ScriptExec.verify(ex, tx.raw, [], 0) == {:error, :input_count_mismatch}
    assert ScriptExec.stats(ex).done_other == 3
  end

  defp signet_blocks do
    path = Path.expand("../../fixtures/signet/blocks1-100.bin", __DIR__)
    for raw <- BB.read_chain(path), do: elem(Exnode.Codec.Block.decode_exact(raw), 1)
  end
end
