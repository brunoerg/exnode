defmodule Exnode.Interop.InvalidBlockCorpusTest do
  @moduledoc """
  Invalid-block corpus: one crafted block per non-script rule.
  Each block goes to bitcoind v32.1 (`submitblock`) and to exnode, and the
  verdict strings must be identical (null / "inconclusive" / "duplicate" /
  reject reason). All spends use OP_TRUE outputs, so scripts are valid and
  only the rule under test can fail.
  """
  use Exnode.InteropCase

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Test.{BlockBuilder, ScriptAsm}
  alias Exnode.Validation.Connect

  @moduletag timeout: 300_000
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @op_true <<0x51>>

  setup_all do
    dir = Path.join(System.tmp_dir!(), "exnode-corpus-#{System.unique_integer([:positive])}")
    btc = Bitcoind.start(Path.join(dir, "btc"))

    on_exit(fn ->
      Bitcoind.stop(btc)
      File.rm_rf!(dir)
    end)

    Bitcoind.mine(btc, 200)

    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "arch"))

    blocks =
      for h <- 1..200 do
        hash = Bitcoind.cli(btc, ["getblockhash", "#{h}"])

        {:ok, b} =
          btc
          |> Bitcoind.cli(["getblock", hash, "0"])
          |> Base.decode16!(case: :lower)
          |> Block.decode_exact()

        {:ok, :connected} = State.submit_block(cs, b)
        b
      end

    # Mature OP_TRUE coins: the coinbases of blocks 1..100 (50 BTC each).
    coins = for b <- Enum.take(blocks, 100), do: hd(b.txs).txid
    {:ok, pool} = Agent.start_link(fn -> coins end)
    %{btc: btc, cs: cs, pool: pool}
  end

  defp take_coin(pool), do: Agent.get_and_update(pool, fn [c | rest] -> {c, rest} end)

  defp tip(btc) do
    hash = Bitcoind.cli(btc, ["getbestblockhash"])

    {:ok, b} =
      btc
      |> Bitcoind.cli(["getblock", hash, "0"])
      |> Base.decode16!(case: :lower)
      |> Block.decode_exact()

    {b.header, Bitcoind.json(btc, ["getblockcount"])}
  end

  defp exnode_verdict(cs, b) do
    case State.submit_block(cs, b) do
      {:ok, :connected} -> nil
      {:ok, :stored} -> "inconclusive"
      {:ok, :duplicate} -> "duplicate"
      {:error, {:cached_invalid, r}} -> r
      {:error, {_, r}} -> r
    end
  end

  defp btc_verdict(btc, b) do
    case Bitcoind.cli_stdin(btc, "submitblock", Base.encode16(b.raw, case: :lower)) do
      "" -> nil
      r -> r
    end
  end

  # Submits to both and asserts identical verdicts. Returns the verdict.
  defp check(ctx, %Block{} = b, expected) do
    btc = btc_verdict(ctx.btc, b)
    ex = exnode_verdict(ctx.cs, b)
    assert btc == expected, "bitcoind said #{inspect(btc)}, test expected #{inspect(expected)}"
    assert ex == btc, "exnode #{inspect(ex)} != bitcoind #{inspect(btc)}"
    assert Hash.from_hex(Bitcoind.cli(ctx.btc, ["getbestblockhash"])) == State.tip(ctx.cs).hash
    btc
  end

  defp subsidy(h), do: Connect.subsidy(h, @p)

  defp next(ctx, txs, opts \\ []) do
    {prev, height} = tip(ctx.btc)
    h = height + 1
    fees = Keyword.get(opts, :fees, 0)
    cb = Keyword.get_lazy(opts, :coinbase, fn -> BlockBuilder.coinbase(h, subsidy(h) + fees) end)
    BlockBuilder.build(prev, [cb | txs], Keyword.drop(opts, [:fees, :coinbase]))
  end

  test "corpus", ctx do
    pool = ctx.pool
    sp = fn value -> BlockBuilder.spend_op_true(take_coin(pool), 0, value) end

    # --- accepted cases ---
    t1 = sp.(50 * @coin - 1000)
    t2 = BlockBuilder.spend_op_true(t1.txid, 0, 50 * @coin - 3000)
    check(ctx, next(ctx, [t1, t2], fees: 3000), nil)

    # --- CheckBlock ---
    check(ctx, next(ctx, [], fees: 1), "bad-cb-amount")
    {prev, h} = tip(ctx.btc)
    check(ctx, BlockBuilder.build(prev, [sp.(50 * @coin)]), "bad-cb-missing")
    cb = BlockBuilder.coinbase(h + 1, subsidy(h + 1))

    check(
      ctx,
      BlockBuilder.build(prev, [cb, BlockBuilder.coinbase(h + 1, 1, <<0x52>>)]),
      "bad-cb-multiple"
    )

    check(ctx, next(ctx, [sp.(50 * @coin)], merkle_root: <<1::256>>), "bad-txnmrklroot")

    c1 = sp.(50 * @coin)
    c2 = sp.(50 * @coin)
    {prev, h} = tip(ctx.btc)
    cb = BlockBuilder.coinbase(h + 1, subsidy(h + 1))

    check(
      ctx,
      BlockBuilder.build(prev, [cb, c1, c2, c2], merkle_txs: [cb, c1, c2]),
      "bad-txns-duplicate"
    )

    big =
      BlockBuilder.coinbase_with(h + 1, 0,
        outputs: [{subsidy(h + 1), @op_true}, {0, :binary.copy(<<0x6A>>, 1_000_000)}]
      )

    check(ctx, BlockBuilder.build(prev, [big]), "bad-blk-length")

    sigops =
      BlockBuilder.coinbase_with(h + 1, 0,
        outputs: [{subsidy(h + 1), :binary.copy(<<0xAC>>, 20_001)}]
      )

    check(ctx, BlockBuilder.build(prev, [sigops]), "bad-blk-sigops")

    # CheckTransaction inside CheckBlock
    check(
      ctx,
      next(ctx, [BlockBuilder.tx([{take_coin(pool), 0}], [{-1, @op_true}])]),
      "bad-txns-vout-negative"
    )

    check(
      ctx,
      next(ctx, [BlockBuilder.tx([{take_coin(pool), 0}], [{21_000_000 * @coin + 1, @op_true}])]),
      "bad-txns-vout-toolarge"
    )

    check(
      ctx,
      next(ctx, [
        BlockBuilder.tx([{take_coin(pool), 0}], [{21_000_000 * @coin, @op_true}, {1, @op_true}])
      ]),
      "bad-txns-txouttotal-toolarge"
    )

    coin = take_coin(pool)

    check(
      ctx,
      next(ctx, [BlockBuilder.tx([{coin, 0}, {coin, 0}], [{1, @op_true}])]),
      "bad-txns-inputs-duplicate"
    )

    check(
      ctx,
      next(ctx, [
        BlockBuilder.tx([{<<0::256>>, 0xFFFFFFFF}, {take_coin(pool), 0}], [{1, @op_true}])
      ]),
      "bad-txns-prevout-null"
    )

    long_cb =
      BlockBuilder.coinbase_with(h + 1, subsidy(h + 1),
        script_sig: ScriptAsm.parse("#{h + 1}") <> :binary.copy(<<0>>, 98)
      )

    check(ctx, BlockBuilder.build(prev, [long_cb]), "bad-cb-length")

    # --- ContextualCheckBlock ---
    wrong_height =
      BlockBuilder.coinbase_with(h + 1, subsidy(h + 1),
        script_sig: ScriptAsm.parse("#{h + 7}") <> <<0>>
      )

    check(ctx, BlockBuilder.build(prev, [wrong_height]), "bad-cb-height")

    nonfinal =
      BlockBuilder.tx([{take_coin(pool), 0, sequence: 0}], [{1, @op_true}], locktime: h + 1)

    check(ctx, next(ctx, [nonfinal]), "bad-txns-nonfinal")

    # BIP141 witness commitment rules
    wit_spend =
      BlockBuilder.tx([{take_coin(pool), 0, witness: [<<1>>]}], [{50 * @coin, @op_true}])

    check(ctx, next(ctx, [wit_spend]), "unexpected-witness")

    cbf = fn h ->
      fn extra, wit ->
        BlockBuilder.coinbase_with(h + 1, 0,
          outputs: [{subsidy(h + 1), @op_true} | extra],
          witness: wit
        )
      end
    end

    check(
      ctx,
      BlockBuilder.build_segwit(prev, cbf.(h), [wit_spend], nonce: <<0::248>>),
      "bad-witness-nonce-size"
    )

    check(
      ctx,
      BlockBuilder.build_segwit(prev, cbf.(h), [wit_spend], commitment: <<7::256>>),
      "bad-witness-merkle-match"
    )

    # Weight = base*3 + total: base is tiny, so a 4 MB witness pushes it over 4M.
    heavy =
      BlockBuilder.tx([{take_coin(pool), 0, witness: [:binary.copy(<<0>>, 4_000_000)]}], [
        {50 * @coin, @op_true}
      ])

    check(ctx, BlockBuilder.build_segwit(prev, cbf.(h), [heavy]), "bad-blk-weight")

    # --- ConnectBlock ---
    check(
      ctx,
      next(ctx, [BlockBuilder.spend_op_true(<<42::256>>, 0, 1)]),
      "bad-txns-inputs-missingorspent"
    )

    check(ctx, next(ctx, [sp.(50 * @coin + 1)]), "bad-txns-in-belowout")

    {_, h} = tip(ctx.btc)
    young = Bitcoind.cli(ctx.btc, ["getblockhash", "#{h - 10}"])

    {:ok, yb} =
      ctx.btc
      |> Bitcoind.cli(["getblock", young, "0"])
      |> Base.decode16!(case: :lower)
      |> Block.decode_exact()

    check(
      ctx,
      next(ctx, [BlockBuilder.spend_op_true(hd(yb.txs).txid, 0, 1)]),
      "bad-txns-premature-spend-of-coinbase"
    )

    # BIP68: a relative height lock of 500 blocks on a coin that is ~300 deep.
    bip68 = BlockBuilder.tx([{take_coin(pool), 0, sequence: 500}], [{1, @op_true}], version: 2)
    check(ctx, next(ctx, [bip68], fees: 50 * @coin - 1), "bad-txns-nonfinal")
    # Same lock with version 1: BIP68 does not apply, so it is accepted.
    v1 =
      BlockBuilder.tx([{take_coin(pool), 0, sequence: 500}], [{50 * @coin, @op_true}], version: 1)

    check(ctx, next(ctx, [v1]), nil)

    # BIP30: re-including a tx whose outputs are still unspent.
    check(ctx, next(ctx, [v1]), "bad-txns-BIP30")

    # P2SH-accurate sigops in ConnectBlock: two inputs whose redeem script is
    # 520 × OP_CHECKMULTISIG (20 sigops each without a preceding OP_N).
    redeem = :binary.copy(<<0xAE>>, 520)
    p2sh = <<0xA9, 0x14>> <> Hash.hash160(redeem) <> <<0x87>>

    fund =
      BlockBuilder.tx([{take_coin(pool), 0}], [
        {10 * @coin, p2sh},
        {10 * @coin, p2sh},
        {30 * @coin, @op_true}
      ])

    check(ctx, next(ctx, [fund]), nil)
    push = ScriptAsm.push_data(redeem)

    spend =
      BlockBuilder.tx([{fund.txid, 0, script_sig: push}, {fund.txid, 1, script_sig: push}], [
        {20 * @coin, @op_true}
      ])

    check(ctx, next(ctx, [spend]), "bad-blk-sigops")

    # --- header rules, through submitblock ---
    {prev, _} = tip(ctx.btc)
    check(ctx, next(ctx, [], bits: 0x207FFFFE), "bad-diffbits")
    check(ctx, next(ctx, [], version: 3), "bad-version(0x00000003)")
    check(ctx, next(ctx, [], time: prev.time - 3600), "time-too-old")
    check(ctx, next(ctx, [], bad_pow: true), "high-hash")

    # --- bookkeeping verdicts ---
    ok = next(ctx, [])
    check(ctx, ok, nil)
    check(ctx, ok, "duplicate")
    bad = next(ctx, [], fees: 5)
    check(ctx, bad, "bad-cb-amount")
    check(ctx, bad, "duplicate-invalid")
    {_, h} = tip(ctx.btc)
    child = BlockBuilder.build(bad.header, [BlockBuilder.coinbase(h + 2, subsidy(h + 2))])
    check(ctx, child, "bad-prevblk")

    # A competing block at the same height: stored, not connected.
    {prev, h} = tip(ctx.btc)

    {:ok, parent} =
      Exnode.Chain.State.with_archive(ctx.cs, fn a ->
        Exnode.Archive.read_block(a, Exnode.Archive.id_at(a, h - 1)) |> Block.decode_exact()
      end)

    side =
      BlockBuilder.build(parent.header, [BlockBuilder.coinbase(h, subsidy(h), <<0x53>>)],
        time: prev.time + 5
      )

    check(ctx, side, "inconclusive")
  end
end
