defmodule Exnode.Interop.ScriptInteropTest do
  @moduledoc """
  Kernel script verification in block validation, against bitcoind
  v32.1. Spends of P2PKH, P2WPKH and P2TR (key path) outputs are signed by
  bitcoind's `signrawtransactionwithkey`. Valid spends must be accepted by
  both; corrupted signatures must be rejected by both. exnode's reason is
  Core's prefix `block-script-verify-flag-failed`, since the kernel does not
  expose the ScriptError.
  """
  use Exnode.InteropCase

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.{Block, Tx}
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Test.{Base58, BlockBuilder}
  alias Exnode.Validation.Connect

  @moduletag timeout: 300_000
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @priv :crypto.hash(:sha256, "exnode phase 3 test key")

  setup_all do
    dir = Path.join(System.tmp_dir!(), "exnode-scripts-#{System.unique_integer([:positive])}")
    btc = Bitcoind.start(Path.join(dir, "btc"))

    on_exit(fn ->
      Bitcoind.stop(btc)
      File.rm_rf!(dir)
    end)

    wif = Base58.wif(@priv)

    descs =
      for kind <- ~w(pkh wpkh tr), into: %{} do
        {kind, Bitcoind.json(btc, ["getdescriptorinfo", "#{kind}(#{wif})"])["descriptor"]}
      end

    # 5 coinbases per key type, then maturity.
    # Explicit order: heights 1-5 pkh, 6-10 wpkh, 11-15 tr.
    for k <- ~w(pkh wpkh tr), do: Bitcoind.mine(btc, 5, descs[k])
    Bitcoind.mine(btc, 110)

    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "arch"))

    for h <- 1..Bitcoind.json(btc, ["getblockcount"]),
        do: {:ok, :connected} = State.submit_block(cs, Bitcoind.block(btc, h))

    # coins[kind] = list of {txid, spk}
    coins =
      for {kind, i} <- Enum.with_index(~w(pkh wpkh tr)), into: %{} do
        list =
          for h <- (i * 5 + 1)..(i * 5 + 5),
              b = Bitcoind.block(btc, h),
              cb = hd(b.txs),
              do: {cb.txid, hd(cb.outputs).script_pubkey}

        {kind, list}
      end

    {:ok, pool} = Agent.start_link(fn -> coins end)
    %{btc: btc, cs: cs, wif: wif, pool: pool}
  end

  defp coin(ctx, kind) do
    {_txid, spk} =
      c = Agent.get_and_update(ctx.pool, fn m -> {hd(m[kind]), Map.update!(m, kind, &tl/1)} end)

    # Guard against mixing up key types: check the output script's shape.
    case {kind, spk} do
      {"pkh", <<0x76, 0xA9, 0x14, _::binary-size(20), 0x88, 0xAC>>} -> c
      {"wpkh", <<0x00, 0x14, _::binary-size(20)>>} -> c
      {"tr", <<0x51, 0x20, _::binary-size(32)>>} -> c
    end
  end

  # Spend {txid, 0} (50 BTC) to OP_TRUE, signed by bitcoind.
  defp signed_spend(ctx, {txid, spk}, fee \\ 1000) do
    unsigned = BlockBuilder.tx([{txid, 0}], [{50 * @coin - fee, <<0x51>>}])
    hex = Base.encode16(IO.iodata_to_binary(Tx.encode(unsigned)), case: :lower)

    signed_hex =
      case spk do
        # Taproot key path: signrawtransactionwithkey cannot derive the tweaked
        # key from a WIF, so sign through a PSBT with the private tr() descriptor.
        <<0x51, 0x20, _::binary>> ->
          psbt = Bitcoind.cli(ctx.btc, ["converttopsbt", hex])
          desc = fix_checksum(ctx, "tr(#{ctx.wif})")
          psbt = Bitcoind.cli(ctx.btc, ["utxoupdatepsbt", psbt, Jason.encode!([desc])])
          res = Bitcoind.json(ctx.btc, ["descriptorprocesspsbt", psbt, Jason.encode!([desc])])
          assert res["complete"], inspect(res)
          res["hex"]

        _ ->
          prev = [
            %{
              txid: Hash.to_hex(txid),
              vout: 0,
              scriptPubKey: Base.encode16(spk, case: :lower),
              amount: 50
            }
          ]

          res =
            Bitcoind.json(ctx.btc, [
              "signrawtransactionwithkey",
              hex,
              Jason.encode!([ctx.wif]),
              Jason.encode!(prev)
            ])

          assert res["complete"], inspect(res)
          res["hex"]
      end

    {:ok, tx} = signed_hex |> Base.decode16!(case: :lower) |> Tx.decode_exact()
    tx
  end

  # A private descriptor needs the checksum of its private form, which
  # getdescriptorinfo reports as "checksum".
  defp fix_checksum(ctx, body),
    do: body <> "#" <> Bitcoind.json(ctx.btc, ["getdescriptorinfo", body])["checksum"]

  # Flips one bit inside the signature (scriptSig push for legacy, witness[0] for segwit).
  defp corrupt(%Tx{inputs: [i]} = tx) do
    i =
      if i.witness != [] do
        [sig | rest] = i.witness
        %{i | witness: [flip(sig, 10) | rest]}
      else
        %{i | script_sig: flip(i.script_sig, 10)}
      end

    BlockBuilder.finalize(%{tx | inputs: [i]})
  end

  defp flip(bin, pos),
    do:
      binary_part(bin, 0, pos) <>
        <<Bitwise.bxor(:binary.at(bin, pos), 1)>> <>
        binary_part(bin, pos + 1, byte_size(bin) - pos - 1)

  defp next_block(ctx, txs, fees, opts \\ []) do
    {prev, h} =
      {Bitcoind.block(ctx.btc, Bitcoind.json(ctx.btc, ["getblockcount"])).header,
       Bitcoind.json(ctx.btc, ["getblockcount"])}

    reward = Connect.subsidy(h + 1, @p) + fees + Keyword.get(opts, :overpay, 0)

    cb_fun = fn extra, wit ->
      BlockBuilder.coinbase_with(h + 1, 0, outputs: [{reward, <<0x51>>} | extra], witness: wit)
    end

    if Enum.any?(txs, & &1.has_witness),
      do: BlockBuilder.build_segwit(prev, cb_fun, txs),
      else: BlockBuilder.build(prev, [cb_fun.([], []) | txs])
  end

  defp verdicts(ctx, %Block{} = b) do
    btc =
      case Bitcoind.cli_stdin(ctx.btc, "submitblock", Base.encode16(b.raw, case: :lower)) do
        "" -> nil
        r -> r
      end

    ex =
      case State.submit_block(ctx.cs, b) do
        {:ok, :connected} -> nil
        {:error, {_, r}} -> r
      end

    assert Hash.from_hex(Bitcoind.cli(ctx.btc, ["getbestblockhash"])) == State.tip(ctx.cs).hash
    {btc, ex}
  end

  for kind <- ~w(pkh wpkh tr) do
    test "#{kind}: signed spend accepted by both; corrupted signature rejected by both", ctx do
      good = signed_spend(ctx, coin(ctx, unquote(kind)))
      bad = corrupt(signed_spend(ctx, coin(ctx, unquote(kind))))

      {btc, ex} = verdicts(ctx, next_block(ctx, [bad], 1000))
      assert "block-script-verify-flag-failed" <> _ = btc
      assert ex == "block-script-verify-flag-failed"

      assert {nil, nil} = verdicts(ctx, next_block(ctx, [good], 1000))
    end
  end

  test "ordering as Core's parallel check queue: coinbase overpay and later input errors win over scripts",
       ctx do
    bad = corrupt(signed_spend(ctx, coin(ctx, "wpkh")))

    assert {"bad-cb-amount", "bad-cb-amount"} =
             verdicts(ctx, next_block(ctx, [bad], 1000, overpay: 1))

    missing = BlockBuilder.spend_op_true(<<99::256>>, 0, 1)

    assert {"bad-txns-inputs-missingorspent", "bad-txns-inputs-missingorspent"} =
             verdicts(ctx, next_block(ctx, [bad, missing], 1000))
  end
end
