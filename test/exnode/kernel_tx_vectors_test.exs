defmodule Exnode.KernelTxVectorsTest do
  @moduledoc """
  Runs Core v32.1 `tx_valid.json` / `tx_invalid.json` through the kernel NIF,
  plus the Elixir `CheckTransaction` port for the BADTX cases.

  The kernel C API exposes only the 7 consensus script flags. Each vector's
  flags are projected onto that set, and the expected kernel verdict follows
  from properties Core's own test (src/test/transaction_tests.cpp) asserts.
  No vector is skipped:

  * tx_valid: valid under (ALL & ~excluded). The kernel projection is a subset
    of that set, so it must be valid (soft-fork flags only add restrictions).
  * tx_invalid with only kernel flags: the projection equals verify_flags, so
    it must be invalid.
  * tx_invalid with any policy-only flag P: Core asserts minimality (the
    vector is valid with any one flag removed). The kernel projection is a
    subset of verify_flags minus P, so it must be valid.

  Every vector is also checked for flag monotonicity in kernel space, as Core does.
  """
  use ExUnit.Case, async: true
  import Bitwise

  alias Exnode.Codec.Tx
  alias Exnode.Crypto.Hash
  alias Exnode.Kernel
  alias Exnode.Test.ScriptAsm
  alias Exnode.Validation.TxCheck

  @fixtures Path.expand("../fixtures/core-v32.1", __DIR__)

  # script/interpreter.cpp ScriptFlagNamesToEnum (v32.1)
  @core_flag_names ~w(P2SH STRICTENC DERSIG LOW_S SIGPUSHONLY MINIMALDATA NULLDUMMY
    DISCOURAGE_UPGRADABLE_NOPS CLEANSTACK MINIMALIF NULLFAIL CHECKLOCKTIMEVERIFY
    CHECKSEQUENCEVERIFY WITNESS DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM WITNESS_PUBKEYTYPE
    CONST_SCRIPTCODE TAPROOT DISCOURAGE_UPGRADABLE_PUBKEYTYPE DISCOURAGE_OP_SUCCESS
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION)

  @kernel_names %{
    "P2SH" => :p2sh,
    "DERSIG" => :dersig,
    "NULLDUMMY" => :nulldummy,
    "CHECKLOCKTIMEVERIFY" => :checklocktimeverify,
    "CHECKSEQUENCEVERIFY" => :checksequenceverify,
    "WITNESS" => :witness,
    "TAPROOT" => :taproot
  }

  defp load(file) do
    Path.join(@fixtures, file)
    |> File.read!()
    |> Jason.decode!()
    |> Enum.filter(&match?([[_ | _] | _], &1))
  end

  # Returns {kernel_flag_bits, has_policy_flag?}
  defp parse_flags("NONE"), do: {0, false}

  defp parse_flags(s) do
    names = String.split(s, ",")
    for n <- names, do: assert(n in @core_flag_names, "unknown flag #{n}")
    kernel = names |> Enum.flat_map(&List.wrap(@kernel_names[&1])) |> Kernel.flags_to_int()
    {kernel, Enum.any?(names, &(not Map.has_key?(@kernel_names, &1)))}
  end

  defp p2sh, do: Kernel.flags().p2sh
  defp witness, do: Kernel.flags().witness

  # transaction_tests.cpp TrimFlags restricted to kernel flags (WITNESS requires P2SH).
  defp trim(f), do: if((f &&& p2sh()) == 0, do: f &&& bnot(witness()), else: f)
  # FillFlags: WITNESS implies P2SH.
  defp fill(f), do: if((f &&& witness()) != 0, do: f ||| p2sh(), else: f)

  defp prevout_map(inputs) do
    Map.new(inputs, fn [hash, idx, spk | rest] ->
      amount = List.first(rest, 0)
      {{Hash.from_hex(hash), idx &&& 0xFFFFFFFF}, {ScriptAsm.parse(spk), amount}}
    end)
  end

  defp spent_outputs(tx, map),
    do: Enum.map(tx.inputs, &Map.fetch!(map, {&1.prev_hash, &1.prev_index}))

  # Core CheckTxScripts semantics: the tx is valid iff every input verifies.
  defp kernel_valid?(tx, spent, flags) do
    {:ok, results} = Kernel.verify_tx(tx.raw, spent, flags)
    Enum.all?(results, &(&1 == :ok))
  end

  defp decode!(hex) do
    {:ok, tx} = hex |> Base.decode16!(case: :mixed) |> Tx.decode_exact()
    tx
  end

  test "tx_valid.json" do
    vectors = load("tx_valid.json")
    all = Kernel.flags_all()

    failures =
      for [inputs, hex, excluded] = v <- vectors, reduce: [] do
        acc ->
          tx = decode!(hex)
          spent = spent_outputs(tx, prevout_map(inputs))
          {excl, _policy?} = parse_flags(excluded)
          flags = trim(all &&& bnot(excl))

          errs =
            [
              TxCheck.check_transaction(tx) == :ok || :check_transaction,
              kernel_valid?(tx, spent, flags) || {:invalid, flags},
              # Removing any flag must not invalidate a valid tx.
              Enum.all?(
                Map.values(Kernel.flags()),
                &kernel_valid?(tx, spent, trim(flags &&& bnot(&1)))
              ) ||
                :not_monotonic
            ]
            |> Enum.reject(&(&1 == true))

          if errs == [], do: acc, else: [{v, errs} | acc]
      end

    assert failures == [],
           "#{length(failures)}/#{length(vectors)} failed: #{inspect(failures, limit: 5)}"

    IO.puts("\n  tx_valid: #{length(vectors)} vectors passed")
  end

  test "tx_invalid.json" do
    vectors = load("tx_invalid.json")

    {failures, stats} =
      for [inputs, hex, flag_str] = v <- vectors,
          reduce: {[], %{badtx: 0, kernel_invalid: 0, policy_only: 0}} do
        {acc, st} ->
          tx = decode!(hex)

          case TxCheck.check_transaction(tx) do
            {:error, _} ->
              if flag_str == "BADTX",
                do: {acc, Map.update!(st, :badtx, &(&1 + 1))},
                else: {[{v, :unexpected_badtx} | acc], st}

            :ok ->
              if flag_str == "BADTX" do
                {[{v, :expected_badtx} | acc], st}
              else
                spent = spent_outputs(tx, prevout_map(inputs))
                {flags, policy?} = parse_flags(flag_str)

                if policy? do
                  # Valid under the kernel projection (see moduledoc).
                  ok = kernel_valid?(tx, spent, trim(flags))

                  if ok,
                    do: {acc, Map.update!(st, :policy_only, &(&1 + 1))},
                    else: {[{v, :policy_only_but_invalid} | acc], st}
                else
                  errs =
                    [
                      not kernel_valid?(tx, spent, flags) || :unexpectedly_valid,
                      # Adding any flag must not validate an invalid tx.
                      Enum.all?(
                        Map.values(Kernel.flags()),
                        &(not kernel_valid?(tx, spent, fill(flags ||| &1)))
                      ) ||
                        :not_monotonic,
                      # Minimality: removing any set flag makes it valid.
                      Enum.all?(
                        set_bits(flags),
                        &kernel_valid?(tx, spent, trim(flags &&& bnot(&1)))
                      ) ||
                        :flags_not_minimal
                    ]
                    |> Enum.reject(&(&1 == true))

                  if errs == [],
                    do: {acc, Map.update!(st, :kernel_invalid, &(&1 + 1))},
                    else: {[{v, errs} | acc], st}
                end
              end
          end
      end

    assert failures == [],
           "#{length(failures)}/#{length(vectors)} failed: #{inspect(failures, limit: 5)}"

    IO.puts("\n  tx_invalid: #{length(vectors)} vectors passed #{inspect(stats)}")
  end

  defp set_bits(f), do: for(b <- Map.values(Kernel.flags()), (f &&& b) != 0, do: b)

  describe "argument guards (kernel asserts on these)" do
    setup do
      [[inputs, hex, _] | _] = load("tx_valid.json")
      tx = decode!(hex)
      %{tx: tx, spent: spent_outputs(tx, prevout_map(inputs))}
    end

    test "flags outside the kernel set are rejected before the NIF", %{tx: tx, spent: spent} do
      assert {:error, :unsupported_flags} = Kernel.verify_tx(tx.raw, spent, 1 <<< 1)
      assert {:error, :unsupported_flags} = Kernel.verify_tx(tx.raw, spent, -1)
    end

    test "spent output count mismatch is rejected", %{tx: tx, spent: spent} do
      assert {:error, :input_count_mismatch} = Kernel.verify_tx(tx.raw, spent ++ spent, 0)
      assert {:error, :input_count_mismatch} = Kernel.verify_tx(tx.raw, [], 0)
    end

    test "malformed spent outputs and amounts", %{tx: tx} do
      assert {:error, :bad_spent_outputs} = Kernel.verify_tx(tx.raw, [{"x", 1 <<< 63}], 0)
      assert {:error, :bad_spent_outputs} = Kernel.verify_tx(tx.raw, [:nope], 0)
    end

    test "garbage tx bytes" do
      assert {:error, :bad_tx} = Kernel.verify_tx(<<1, 2, 3>>, [], 0)
    end

    test "invalid flag combination is reported, not asserted", %{tx: tx, spent: spent} do
      assert {:ok, [{:error, :invalid_flags_combination} | _]} =
               Kernel.verify_tx(tx.raw, spent, Kernel.flags().witness)
    end
  end
end
