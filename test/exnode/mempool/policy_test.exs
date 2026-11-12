defmodule Exnode.Mempool.PolicyTest do
  @moduledoc "Ported from Core v32.1 src/test/transaction_tests.cpp `test_IsStandard` (and solver cases)."
  use ExUnit.Case, async: true

  alias Exnode.Codec.Tx
  alias Exnode.Mempool.Policy

  @cent 1_000_000
  @max_money 21_000_000 * 100_000_000
  @p2pkh <<0x76, 0xA9, 20, 0::160, 0x88, 0xAC>>

  # CScript() << bytes: the minimal push for `data`.
  defp push(data) when byte_size(data) <= 75, do: <<byte_size(data)>> <> data
  defp push(data) when byte_size(data) <= 255, do: <<0x4C, byte_size(data)>> <> data
  defp push(data), do: <<0x4D, byte_size(data)::little-16>> <> data

  defp base_tx do
    %Tx{
      version: 2,
      locktime: 0,
      inputs: [
        %Tx.In{
          prev_hash: <<1::256>>,
          prev_index: 1,
          script_sig: push(:binary.copy(<<0>>, 65)),
          sequence: 0xFFFFFFFF
        }
      ],
      outputs: [%Tx.Out{value: 90 * @cent, script_pubkey: @p2pkh}]
    }
  end

  # Re-encode and decode, so raw/base_size are consistent.
  defp fin(tx), do: tx |> Tx.encode() |> IO.iodata_to_binary() |> Tx.decode_exact() |> elem(1)

  defp std(tx, opts \\ []), do: Policy.standard_tx(fin(tx), opts)
  defp out(tx, i, f), do: %{tx | outputs: List.update_at(tx.outputs, i, f)}

  test "dust, versions, rounding" do
    t = base_tx()
    assert std(t) == :ok
    assert Policy.fee_for(3000, 182) == 546

    # One dust output (MAX_DUST_OUTPUTS_PER_TX) is still standard.
    t = %{t | outputs: t.outputs ++ [%Tx.Out{value: 0, script_pubkey: @p2pkh}]}
    assert std(t) == :ok
    assert std(out(t, 0, &%{&1 | value: 545})) == {:error, "dust"}
    assert std(out(t, 0, &%{&1 | value: 546})) == :ok

    t = out(t, 0, &%{&1 | value: 546})
    for v <- [0xFFFFFFFF, 0, 4], do: assert(std(%{t | version: v}) == {:error, "version"})
    for v <- [1, 2], do: assert(std(%{t | version: v}) == :ok)

    # Odd dust relay fee: 182 * 3702 / 1000 rounded up = 674.
    assert std(out(t, 0, &%{&1 | value: 673}), dust_relay_fee: 3702) == {:error, "dust"}
    assert std(out(t, 0, &%{&1 | value: 674}), dust_relay_fee: 3702) == :ok
  end

  test "scriptPubKey types and data carrier" do
    t = base_tx()
    assert std(out(t, 0, &%{&1 | script_pubkey: <<0x51>>})) == {:error, "scriptpubkey"}

    d83 = <<0x6A>> <> push(:binary.copy(<<0x04>>, 80))
    assert byte_size(d83) == 83
    assert std(out(t, 0, &%{&1 | script_pubkey: d83}), max_datacarrier_bytes: 83) == :ok

    assert std(out(t, 0, &%{&1 | script_pubkey: d83}), max_datacarrier_bytes: 82) ==
             {:error, "datacarrier"}

    for spk <- [
          <<0x6A, 0x00>>,
          <<0x6A, 1, 0, 1, 1>>,
          # OP_RESERVED counts as a push for IsPushOnly
          <<0x6A, 0x50, 0x4F, 0x00, 1, 1, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
            0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60>>,
          <<0x6A>>
        ] do
      assert std(out(t, 0, &%{&1 | script_pubkey: spk})) == :ok, inspect(spk)
    end

    assert std(out(t, 0, &%{&1 | script_pubkey: <<0x6A, 0x6A>>})) == {:error, "scriptpubkey"}

    # Several data carrier outputs share one budget.
    d = <<0x6A>> <> push(:binary.copy(<<0x04>>, 160))

    t2 = %{
      t
      | outputs: [%Tx.Out{value: 0, script_pubkey: d}, %Tx.Out{value: 0, script_pubkey: d}]
    }

    total = 2 * byte_size(d)
    assert std(t2) == :ok
    assert std(t2, max_datacarrier_bytes: total) == :ok
    assert std(t2, max_datacarrier_bytes: total - 1) == {:error, "datacarrier"}
  end

  test "scriptSig size and push-only" do
    t = %{base_tx() | outputs: [%Tx.Out{value: @max_money, script_pubkey: @p2pkh}]}
    in0 = fn t, ss -> %{t | inputs: [%{hd(t.inputs) | script_sig: ss}]} end
    assert std(in0.(t, push(:binary.copy(<<0>>, 1647)))) == :ok
    assert std(in0.(t, push(:binary.copy(<<0>>, 1648)))) == {:error, "scriptsig-size"}

    ss =
      <<0x51, 0x00, 0x4F, 0x60>> <>
        push(:binary.copy(<<0>>, 75)) <>
        push(:binary.copy(<<0>>, 235)) <>
        push(:binary.copy(<<0>>, 1234)) <> <<0x59>>

    assert std(in0.(t, ss)) == :ok

    # Replace a single-byte push op with non-push ops.
    for op <- [0x61, 0x69, 0x63, 0x7B, 0x6F, 0x82, 0x87, 0x93, 0x94, 0xAA, 0xAB, 0xAC, 0xB1] do
      assert std(in0.(t, <<op>> <> binary_part(ss, 1, byte_size(ss) - 1))) ==
               {:error, "scriptsig-not-pushonly"}
    end
  end

  test "tx-size at exactly 400000 weight units" do
    ins =
      for _ <- 1..2438,
          do: %Tx.In{prev_hash: <<1::256>>, prev_index: 1, script_sig: <<>>, sequence: 0xFFFFFFFF}

    t = %{
      base_tx()
      | inputs: ins,
        outputs: [%Tx.Out{value: 0, script_pubkey: <<0x6A>> <> push(<<0::152>>)}]
    }

    assert Tx.weight(fin(t)) == 400_000
    assert std(t) == :ok
    t = %{t | outputs: [%Tx.Out{value: 0, script_pubkey: <<0x6A>> <> push(<<0::160>>)}]}
    assert Tx.weight(fin(t)) == 400_004
    assert std(t) == {:error, "tx-size"}
  end

  test "bare multisig and dust thresholds per output type" do
    pk = <<0x02>> <> :binary.copy(<<0x11>>, 32)
    ms = <<0x51>> <> push(pk) <> <<0x51, 0xAE>>
    t = %{base_tx() | outputs: [%Tx.Out{value: 90 * @cent, script_pubkey: ms}]}
    assert std(t) == :ok
    assert std(t, permit_bare_multisig: false) == {:error, "bare-multisig"}

    t = %{t | outputs: t.outputs ++ [%Tx.Out{value: 0, script_pubkey: ms}]}

    cases = [
      {push(:binary.copy(<<0x02>>, 33)) <> <<0xAC>>, 576},
      {push(:binary.copy(<<0x04>>, 65)) <> <<0xAC>>, 672},
      {@p2pkh, 546},
      {<<0xA9, 20, 0::160, 0x87>>, 540},
      {<<0x00, 20, 0::160>>, 294},
      {<<0x00, 32, 0::256>>, 330},
      {<<0x51, 32, 0::256>>, 330}
    ]

    for {spk, threshold} <- cases do
      assert std(out(t, 0, &%{&1 | script_pubkey: spk, value: threshold})) == :ok, inspect(spk)

      assert std(out(t, 0, &%{&1 | script_pubkey: spk, value: threshold - 1})) == {:error, "dust"},
             inspect(spk)
    end

    # Future witness versions with 2-byte programs.
    for op <- 0x51..0x60 do
      spk = <<op, 2, 0, 0>>
      assert std(out(t, 0, &%{&1 | script_pubkey: spk, value: 240})) == :ok
      assert std(out(t, 0, &%{&1 | script_pubkey: spk, value: 239})) == {:error, "dust"}
    end
  end

  test "solver types" do
    pk33 = <<0x03>> <> :binary.copy(<<1>>, 32)
    pk65 = <<0x04>> <> :binary.copy(<<1>>, 64)
    assert {:pubkey, [^pk33]} = Policy.solver(push(pk33) <> <<0xAC>>)
    assert {:pubkey, [^pk65]} = Policy.solver(push(pk65) <> <<0xAC>>)

    assert {:nonstandard, _} =
             Policy.solver(push(<<0x05>> <> :binary.copy(<<1>>, 32)) <> <<0xAC>>)

    assert {:pubkeyhash, [<<0::160>>]} = Policy.solver(@p2pkh)
    assert {:scripthash, _} = Policy.solver(<<0xA9, 20, 0::160, 0x87>>)
    assert {:witness_v0_keyhash, _} = Policy.solver(<<0, 20, 0::160>>)
    assert {:witness_v0_scripthash, _} = Policy.solver(<<0, 32, 0::256>>)
    assert {:nonstandard, _} = Policy.solver(<<0, 21, 0::168>>)
    assert {:witness_v1_taproot, _} = Policy.solver(<<0x51, 32, 0::256>>)
    assert {:anchor, []} = Policy.solver(<<0x51, 2, 0x4E, 0x73>>)
    assert {:witness_unknown, [<<1>>, <<0, 0>>]} = Policy.solver(<<0x51, 2, 0, 0>>)
    assert {:null_data, []} = Policy.solver(<<0x6A, 1, 7>>)
    # 2-of-3 multisig; non-minimal key count is not multisig.
    ms = <<0x52>> <> push(pk33) <> push(pk33) <> push(pk33) <> <<0x53, 0xAE>>
    assert {:multisig, [<<2>>, _, _, _, <<3>>]} = Policy.solver(ms)

    assert {:nonstandard, _} =
             Policy.solver(<<1, 2>> <> push(pk33) <> push(pk33) <> <<0x52, 0xAE>>)

    assert Policy.standard_output(
             <<0x51>> <> push(pk33) <> push(pk33) <> push(pk33) <> push(pk33) <> <<0x54, 0xAE>>
           ) ==
             {:error, :multisig}
  end

  test "input standardness: P2SH sigops, unknown scripts, witness limits" do
    redeem16 = :binary.copy(<<0xAC>>, 16)
    redeem15 = :binary.copy(<<0xAC>>, 15)
    tx = fn ss -> %{base_tx() | inputs: [%{hd(base_tx().inputs) | script_sig: ss}]} end
    p2sh = <<0xA9, 20, 0::160, 0x87>>
    assert Policy.inputs_standard(tx.(push(redeem15)), [p2sh]) == :ok

    assert {:error, "bad-txns-nonstandard-inputs",
            "p2sh redeemscript sigops exceed limit (input 0: 16 > 15)"} =
             Policy.inputs_standard(tx.(push(redeem16)), [p2sh])

    assert {:error, "bad-txns-nonstandard-inputs", "input 0 P2SH redeemscript missing"} =
             Policy.inputs_standard(tx.(<<>>), [p2sh])

    assert {:error, _, "input 0 script unknown"} = Policy.inputs_standard(tx.(<<>>), [<<0x51>>])

    assert {:error, _, "input 0 witness program is undefined"} =
             Policy.inputs_standard(tx.(<<>>), [<<0x52, 2, 0, 0>>])

    # P2WSH: script <= 3600 bytes, <= 100 items, items <= 80 bytes.
    p2wsh = <<0, 32, 0::256>>

    w = fn wit ->
      %{base_tx() | inputs: [%{hd(base_tx().inputs) | script_sig: <<>>, witness: wit}]}
    end

    assert Policy.witness_standard?(w.([<<0::640>>, <<0x51>>]), [p2wsh])
    refute Policy.witness_standard?(w.([<<0::648>>, <<0x51>>]), [p2wsh])
    refute Policy.witness_standard?(w.([<<0x51>>, :binary.copy(<<0>>, 3601)]), [p2wsh])
    refute Policy.witness_standard?(w.(List.duplicate(<<>>, 101) ++ [<<0x51>>]), [p2wsh])
    # Witness on a non-witness output; witness stuffing on an anchor.
    refute Policy.witness_standard?(w.([<<1>>]), [@p2pkh])
    refute Policy.witness_standard?(w.([<<1>>]), [<<0x51, 2, 0x4E, 0x73>>])
    # Taproot: annex is non-standard; tapscript items <= 80 bytes.
    p2tr = <<0x51, 32, 0::256>>
    refute Policy.witness_standard?(w.([<<1>>, <<0x50, 1>>]), [p2tr])
    assert Policy.witness_standard?(w.([<<0::640>>, <<0x51>>, <<0xC0>> <> <<0::256>>]), [p2tr])
    refute Policy.witness_standard?(w.([<<0::648>>, <<0x51>>, <<0xC0>> <> <<0::256>>]), [p2tr])
    assert Policy.witness_standard?(w.([<<0::648>>, <<0x51>>, <<0xC2>> <> <<0::256>>]), [p2tr])
  end

  test "vsize with sigops (bytes_per_sigop 20)" do
    assert Policy.vsize(400, 0) == 100
    assert Policy.vsize(401, 0) == 101
    assert Policy.vsize(400, 80) == 400
  end

  # Core amount_tests.cpp GetFeeTest: CFeeRate::GetFee rounds up; a negative
  # rate rounds towards zero, but never to 0 for a non-zero size.
  test "fee for a size at a rate" do
    for {rate, cases} <- [
          {0, [{0, 0}, {100_000, 0}]},
          {1000, [{0, 0}, {1, 1}, {121, 121}, {999, 999}, {1000, 1000}, {9000, 9000}]},
          {-1000, [{0, 0}, {1, -1}, {121, -121}, {999, -999}, {1000, -1000}, {9000, -9000}]},
          {123,
           [{0, 0}, {8, 1}, {9, 2}, {121, 15}, {122, 16}, {999, 123}, {1000, 123}, {9000, 1107}]},
          {-123, [{0, 0}, {8, -1}, {9, -1}]}
        ],
        {vbytes, fee} <- cases do
      assert Policy.fee_for(rate, vbytes) == fee, "#{rate} sat/kvB, #{vbytes} vB"
    end
  end

  # Core script_standard_tests.cpp script_standard_Solver_failure (the
  # multisig and size cases), plus key counts pushed as numbers (Core
  # GetScriptNumber: up to 20 keys).
  test "solver failures and multisig key counts" do
    pk = <<0x03>> <> :binary.copy(<<1>>, 32)
    ms = fn m, keys, n -> m <> Enum.map_join(keys, &push/1) <> n <> <<0xAE>> end

    for spk <- [
          push(:binary.copy(<<1>>, 30)) <> <<0xAC>>,
          <<0x76, 0xA9>> <> push(pk) <> <<0x88, 0xAC>>,
          <<0xA9>> <> push(:binary.copy(<<1>>, 21)) <> <<0x87>>,
          # 0 of 1, 2 of 1, 1 of 2 with one key, 1 of 1 with no key
          ms.(<<0>>, [pk], <<0x51>>),
          ms.(<<0x52>>, [pk], <<0x51>>),
          ms.(<<0x51>>, [pk], <<0x52>>),
          ms.(<<0x51>>, [], <<0x51>>),
          <<0x6A, 1, 75, 0x93>>,
          <<0>> <> push(:binary.copy(<<1>>, 19)),
          <<>>,
          # A count that is not a number opcode or push (OP_NOP).
          ms.(<<0x61>>, [pk], <<0x51>>),
          # Counts pushed non-minimally, too long, negative, or over 20.
          ms.(<<2, 1, 0>>, [pk], <<0x51>>),
          ms.(<<5, 1, 0, 0, 0, 0>>, [pk], <<0x51>>),
          ms.(<<1, 0x91>>, [pk], <<0x51>>),
          ms.(<<1, 21>>, [pk], <<0x51>>),
          # A truncated push among the keys.
          <<0x51>> <> push(pk) <> <<0x4C, 0xAE>>
        ] do
      assert {:nonstandard, []} = Policy.solver(spk), inspect(spk)
    end

    assert {:witness_unknown, _} = Policy.solver(<<0x51>> <> push(:binary.copy(<<1>>, 31)))
    assert {:witness_unknown, _} = Policy.solver(<<0x51>> <> push(:binary.copy(<<1>>, 33)))

    # 17 of 17: the counts are pushed (OP_16 is the largest number opcode).
    keys = List.duplicate(pk, 17)
    assert {:multisig, [<<17>> | _]} = Policy.solver(ms.(<<1, 17>>, keys, <<1, 17>>))
    assert Policy.standard_output(ms.(<<1, 17>>, keys, <<1, 17>>)) == {:error, :multisig}
  end

  # Core CheckMinimalPush.
  test "minimal pushes" do
    for {data, op, minimal} <- [
          {<<>>, 0x00, true},
          {<<>>, 0x4C, false},
          {<<5>>, 0x01, false},
          {<<0x81>>, 0x01, false},
          {<<0x82>>, 0x01, true},
          {:binary.copy(<<1>>, 75), 75, true},
          {:binary.copy(<<1>>, 75), 0x4C, false},
          {:binary.copy(<<1>>, 76), 0x4C, true},
          {:binary.copy(<<1>>, 76), 0x4D, false},
          {:binary.copy(<<1>>, 256), 0x4D, true},
          {:binary.copy(<<1>>, 256), 0x4E, false},
          {:binary.copy(<<1>>, 65_536), 0x4E, true}
        ] do
      assert Policy.minimal_push?(data, op) == minimal, "#{byte_size(data)} bytes, op #{op}"
    end
  end

  # EvalScript over a push-only scriptSig (Core ScriptErrorString texts).
  test "push-only evaluation" do
    assert Policy.eval_push_only(<<0x4F, 0x51, 0x60, 2, 7, 8>>) ==
             {:ok, [<<0x81>>, <<1>>, <<16>>, <<7, 8>>]}

    assert Policy.eval_push_only(<<0x50>>) == {:error, "Opcode missing or not understood"}
    assert Policy.eval_push_only(<<0x4C>>) == {:error, "Opcode missing or not understood"}

    assert Policy.eval_push_only(push(:binary.copy(<<1>>, 521))) ==
             {:error, "Push value size limit exceeded"}

    assert {:ok, _} = Policy.eval_push_only(:binary.copy(<<0x51>>, 1000))

    assert Policy.eval_push_only(:binary.copy(<<0x51>>, 1001)) ==
             {:error, "Stack size limit exceeded"}

    assert Policy.eval_push_only(:binary.copy(<<0x51>>, 10_001)) == {:error, "Script is too big"}

    # A P2SH input whose scriptSig does not evaluate.
    tx = %{base_tx() | inputs: [%{hd(base_tx().inputs) | script_sig: <<0x4C>>}]}

    assert Policy.inputs_standard(tx, [<<0xA9, 20, 0::160, 0x87>>]) ==
             {:error, "bad-txns-nonstandard-inputs",
              "p2sh scriptsig malformed (input 0: Opcode missing or not understood)"}
  end

  # Core CheckSigopsBIP54: at most 2,500 legacy sigops over all inputs.
  test "legacy sigops over all inputs" do
    spk = :binary.copy(<<0xAC>>, 1250)

    tx = fn n ->
      %{base_tx() | inputs: List.duplicate(%{hd(base_tx().inputs) | script_sig: <<>>}, n)}
    end

    assert Policy.inputs_standard(tx.(2), [spk, spk]) ==
             {:error, "bad-txns-nonstandard-inputs", "input 0 script unknown"}

    assert Policy.inputs_standard(tx.(3), [spk, spk, spk]) ==
             {:error, "bad-txns-nonstandard-inputs", "non-witness sigops exceed bip54 limit"}
  end

  test "witness standardness: P2SH-wrapped and other programs, taproot key path" do
    w = fn ss, wit ->
      %{base_tx() | inputs: [%{hd(base_tx().inputs) | script_sig: ss, witness: wit}]}
    end

    p2sh = fn redeem -> <<0xA9, 20>> <> hash160(redeem) <> <<0x87>> end
    p2wsh = <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)

    # P2SH-P2WSH: the redeem script is the program; its witness limits apply.
    assert Policy.witness_standard?(w.(push(p2wsh), [<<0x51>>]), [p2sh.(p2wsh)])
    refute Policy.witness_standard?(w.(push(p2wsh), [<<0::648>>, <<0x51>>]), [p2sh.(p2wsh)])
    # No redeem script, or one that is not a witness program.
    refute Policy.witness_standard?(w.(<<>>, [<<1>>]), [p2sh.(p2wsh)])
    refute Policy.witness_standard?(w.(push(<<0x51>>), [<<1>>]), [p2sh.(<<0x51>>)])
    # P2WPKH and future versions: no limits here.
    assert Policy.witness_standard?(w.(<<>>, [<<0::648>>, <<0::264>>]), [<<0, 20, 0::160>>])
    assert Policy.witness_standard?(w.(<<>>, [<<0::648>>]), [<<0x52, 2, 0, 0>>])
    # Taproot: a key path spend; an empty control block.
    p2tr = <<0x51, 32, 0::256>>
    assert Policy.witness_standard?(w.(<<>>, [<<0::512>>]), [p2tr])
    refute Policy.witness_standard?(w.(<<>>, [<<0x51>>, <<>>]), [p2tr])
  end

  # Core transaction_tests.cpp spends_witness_prog.
  test "spends a witness program other than an anchor" do
    pk = <<0x03>> <> :binary.copy(<<1>>, 32)
    p2sh = fn redeem -> <<0xA9, 20>> <> hash160(redeem) <> <<0x87>> end

    spends? = fn spk, ss ->
      Policy.spends_non_anchor_witness_prog?(
        %{base_tx() | inputs: [%{hd(base_tx().inputs) | script_sig: ss}]},
        [spk]
      )
    end

    p2wsh = <<0, 32>> <> :crypto.hash(:sha256, <<0x5C, 0xA9, 0x76, 0x87>>)
    p2wpkh = <<0, 20>> <> hash160(pk)
    p2tr = <<0x51, 32>> <> binary_part(pk, 1, 32)
    anchor = <<0x51, 2, 0x4E, 0x73>>
    unknown = <<0x51, 2, 0x42, 0x42>>

    refute spends?.(push(pk) <> <<0xAC>>, <<>>)
    refute spends?.(<<0x76, 0xA9, 20>> <> hash160(pk) <> <<0x88, 0xAC>>, <<>>)
    refute spends?.(p2sh.(<<0x51, 0xAC>>), <<0>> <> push(<<0x51, 0xAC>>))
    refute spends?.(anchor, <<>>)

    for prog <- [p2wsh, p2wpkh, p2tr, unknown] do
      assert spends?.(prog, <<>>)
      # Wrapped in P2SH: only with the redeem script in the scriptSig.
      assert spends?.(p2sh.(prog), push(prog))
      refute spends?.(p2sh.(prog), <<>>)
    end

    assert spends?.(p2sh.(anchor), push(anchor))
  end

  test "default dust relay fee and options" do
    o = %Tx.Out{value: 545, script_pubkey: @p2pkh}
    assert Policy.dust_threshold(o) == 546
    assert Policy.dust_outputs(%Tx{base_tx() | outputs: [o, %{o | value: 546}]}) == [0]
    assert Policy.standard_tx(fin(base_tx())) == :ok
  end

  defp hash160(data), do: :crypto.hash(:ripemd160, :crypto.hash(:sha256, data))
end
