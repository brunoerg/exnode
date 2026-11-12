defmodule Exnode.Interop.ConsensusBoundaryTest do
  @moduledoc """
  Audit differential test: consensus-rule boundary conditions, compared
  verdict-for-verdict with the pinned bitcoind v32.1 (`submitblock`).

  On regtest BIP34/65/66/112/141 are active from height 1, maturity is 100,
  halving every 150. Covered boundaries:
    * BIP113: nLockTime == prev MTP (nonfinal) vs MTP - 1 (final)
    * nLockTime height form: == new height (nonfinal) vs height - 1 (final)
    * nLockTime ignored when every input's sequence is final
    * BIP68 height lock == coin depth (valid) vs depth + 1 (nonfinal)
    * BIP68 time lock: largest valid N vs N + 1
    * BIP68 disable bit (1 << 31) suppresses an otherwise-failing lock
    * coinbase maturity exactly 100 (valid) vs 99 (premature)
    * block weight exactly MAX_BLOCK_WEIGHT (valid) vs + 1 (bad-blk-weight)
    * witness commitment: last-of-many is used; trailing bytes allowed;
      commitment with a witness-less coinbase is bad-witness-nonce-size
    * coinbase scriptSig 100 bytes (valid) vs 101 (bad-cb-length)
  """
  use Exnode.InteropCase

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Test.{BlockBuilder, ScriptAsm}
  alias Exnode.Validation.{Connect, Merkle}

  @moduletag timeout: 300_000
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @op_true <<0x51>>
  @hdr <<0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED>>

  setup_all do
    dir = Path.join(System.tmp_dir!(), "exnode-boundary-#{System.unique_integer([:positive])}")
    btc = Bitcoind.start(Path.join(dir, "btc"))

    on_exit(fn ->
      Bitcoind.stop(btc)
      File.rm_rf!(dir)
    end)

    Bitcoind.mine(btc, 130)

    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "arch"))

    for h <- 1..130 do
      {:ok, :connected} = State.submit_block(cs, Bitcoind.block(btc, h))
    end

    # Mature OP_TRUE coinbases (50 BTC) from blocks 1..100, as {txid, height}.
    coins = for h <- 1..100, do: {hd(Bitcoind.block(btc, h).txs).txid, h}
    {:ok, pool} = Agent.start_link(fn -> coins end)
    %{btc: btc, cs: cs, pool: pool}
  end

  defp take_coin(pool), do: Agent.get_and_update(pool, fn [c | rest] -> {c, rest} end)

  defp tip(btc), do: Bitcoind.block(btc, Bitcoind.json(btc, ["getblockcount"]))

  defp height(btc), do: Bitcoind.json(btc, ["getblockcount"])

  # Median time past of the current tip (Core CBlockIndex::GetMedianTimePast).
  defp mtp(btc), do: Bitcoind.json(btc, ["getblockheader", Bitcoind.tip(btc)])["mediantime"]

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

  defp check(ctx, %Block{} = b, expected) do
    btc = btc_verdict(ctx.btc, b)
    ex = exnode_verdict(ctx.cs, b)
    assert btc == expected, "bitcoind said #{inspect(btc)}, test expected #{inspect(expected)}"
    assert ex == btc, "exnode #{inspect(ex)} != bitcoind #{inspect(btc)}"
    assert Hash.from_hex(Bitcoind.tip(ctx.btc)) == State.tip(ctx.cs).hash
    btc
  end

  # A block on the current tip; the coinbase pays subsidy + `fees`.
  defp next(ctx, txs, opts \\ []) do
    prev = tip(ctx.btc)
    h = height(ctx.btc)
    fees = Keyword.get(opts, :fees, 0)
    cb = BlockBuilder.coinbase(h + 1, Connect.subsidy(h + 1, @p) + fees)
    BlockBuilder.build(prev.header, [cb | txs], Keyword.drop(opts, [:fees]))
  end

  # Finds (k, v1, v2) so `build.(base_pad, k, v1, v2)` weighs exactly `target`.
  # With v1 = v2 = <<>> the weight is w0; replacing them by items of sizes s1,
  # s2 adds f(s1) - 1 + f(s2) - 1 where f(s) = CompactSize.size(s) + s, so we
  # need f(s1) + f(s2) = target - w0 + 2. k is stepped down from the op limit
  # (398) until the residue is solvable.
  defp solve_witness(build, base_pad, target) do
    solve_witness_k(build, base_pad, target, 398)
  end

  defp solve_witness_k(build, base_pad, target, k) do
    w0 = Exnode.Validation.Block.weight(build.(base_pad, k, <<>>, <<>>))
    need = target - w0 + 2

    case solve_pair(need) do
      nil when k > 0 -> solve_witness_k(build, base_pad, target, k - 1)
      {s1, s2} -> {k, :binary.copy(<<1>>, s1), :binary.copy(<<1>>, s2)}
    end
  end

  defp solve_pair(need) do
    Enum.find_value(520..0//-1, fn s1 ->
      f1 = fsize(s1)

      case un_fsize(need - f1) do
        nil -> nil
        s2 -> {s1, s2}
      end
    end)
  end

  defp fsize(s), do: Exnode.Codec.CompactSize.size(s) + s

  defp un_fsize(f) do
    cond do
      f >= 1 and f <= 253 -> f - 1
      f >= 256 and f <= 523 -> f - 3
      true -> nil
    end
  end

  # Iterates `build.(pad)` until the block is exactly `target` bytes.
  defp tune_size(build, target, pad, tries_left \\ 5)
  defp tune_size(_build, _target, _pad, 0), do: raise("size did not converge")

  defp tune_size(build, target, pad, tries_left) do
    b = build.(pad)

    case byte_size(b.raw) do
      ^target -> b
      got -> tune_size(build, target, pad + (target - got), tries_left - 1)
    end
  end

  test "consensus boundaries", ctx do
    pool = ctx.pool

    # --- BIP113: nLockTime vs prev MTP (time form, lt >= 500_000_000) -------
    m = mtp(ctx.btc)

    t =
      BlockBuilder.tx([{elem(take_coin(pool), 0), 0, sequence: 0}], [{1, @op_true}], locktime: m)

    check(ctx, next(ctx, [t], fees: 50 * @coin - 1), "bad-txns-nonfinal")

    m = mtp(ctx.btc)

    t =
      BlockBuilder.tx([{elem(take_coin(pool), 0), 0, sequence: 0}], [{50 * @coin, @op_true}],
        locktime: m - 1
      )

    check(ctx, next(ctx, [t]), nil)

    # --- nLockTime in height form -------------------------------------------
    h = height(ctx.btc)

    t =
      BlockBuilder.tx([{elem(take_coin(pool), 0), 0, sequence: 0}], [{1, @op_true}],
        locktime: h + 1
      )

    check(ctx, next(ctx, [t], fees: 50 * @coin - 1), "bad-txns-nonfinal")

    h = height(ctx.btc)

    t =
      BlockBuilder.tx([{elem(take_coin(pool), 0), 0, sequence: 0}], [{50 * @coin, @op_true}],
        locktime: h
      )

    check(ctx, next(ctx, [t]), nil)

    # Unsatisfied nLockTime but every sequence final: final (nLockTime ignored).
    h = height(ctx.btc)

    t =
      BlockBuilder.tx(
        [{elem(take_coin(pool), 0), 0, sequence: 0xFFFFFFFF}],
        [{50 * @coin, @op_true}],
        locktime: h + 1000
      )

    check(ctx, next(ctx, [t]), nil)

    # --- BIP68 height locks ---------------------------------------------------
    {txid, ch} = take_coin(pool)
    h = height(ctx.btc)
    depth = h + 1 - ch
    # lock == depth: min_height = ch + depth - 1 = h < h + 1 -> valid.
    t = BlockBuilder.tx([{txid, 0, sequence: depth}], [{50 * @coin, @op_true}], version: 2)
    check(ctx, next(ctx, [t]), nil)

    # lock == depth + 1: min_height = h + 1 >= h + 1 -> nonfinal.
    {txid, ch} = take_coin(pool)
    h = height(ctx.btc)
    depth = h + 1 - ch
    t = BlockBuilder.tx([{txid, 0, sequence: depth + 1}], [{1, @op_true}], version: 2)
    check(ctx, next(ctx, [t], fees: 50 * @coin - 1), "bad-txns-nonfinal")

    # disable bit (1 << 31) suppresses the same failing lock.
    {txid, ch} = take_coin(pool)
    h = height(ctx.btc)
    depth = h + 1 - ch

    t =
      BlockBuilder.tx(
        [{txid, 0, sequence: Bitwise.bor(0x80000000, depth + 1)}],
        [{50 * @coin, @op_true}],
        version: 2
      )

    check(ctx, next(ctx, [t]), nil)

    # --- BIP68 time locks -----------------------------------------------------
    # Coin in block K; min_time = MTP(K-1) + N*512 - 1; valid iff < MTP(tip).
    {txid, ch} = take_coin(pool)
    m_tip = mtp(ctx.btc)

    m_coin =
      Bitcoind.json(ctx.btc, [
        "getblockheader",
        Bitcoind.cli(ctx.btc, ["getblockhash", "#{ch - 1}"])
      ])["mediantime"]

    n_valid = div(max(m_tip - m_coin, 0), 512)

    t =
      BlockBuilder.tx(
        [{txid, 0, sequence: Bitwise.bor(0x00400000, n_valid)}],
        [{50 * @coin, @op_true}],
        version: 2
      )

    check(ctx, next(ctx, [t]), nil)

    {txid, ch} = take_coin(pool)
    m_tip = mtp(ctx.btc)

    m_coin =
      Bitcoind.json(ctx.btc, [
        "getblockheader",
        Bitcoind.cli(ctx.btc, ["getblockhash", "#{ch - 1}"])
      ])["mediantime"]

    n_valid = div(max(m_tip - m_coin, 0), 512)

    t =
      BlockBuilder.tx(
        [{txid, 0, sequence: Bitwise.bor(0x00400000, n_valid + 1)}],
        [{1, @op_true}],
        version: 2
      )

    check(ctx, next(ctx, [t], fees: 50 * @coin - 1), "bad-txns-nonfinal")

    # --- coinbase maturity ----------------------------------------------------
    h = height(ctx.btc)
    coinbase_txid = hd(Bitcoind.block(ctx.btc, h - 99).txs).txid
    t = BlockBuilder.tx([{coinbase_txid, 0}], [{50 * @coin, @op_true}], version: 2)
    check(ctx, next(ctx, [t]), nil)

    h = height(ctx.btc)
    coinbase_txid = hd(Bitcoind.block(ctx.btc, h - 98).txs).txid
    t = BlockBuilder.tx([{coinbase_txid, 0}], [{1, @op_true}], version: 2)
    check(ctx, next(ctx, [t], fees: 50 * @coin - 1), "bad-txns-premature-spend-of-coinbase")

    # --- block weight ---------------------------------------------------------
    # (a) No-witness block: weight = 4 * size, and CheckBlock's stripped-size
    # rule (base * 4 > MAX_BLOCK_WEIGHT) fires first: exactly 1,000,000 bytes
    # is valid, 1,000,001 is bad-blk-length (never reaching ContextualCheckBlock).
    for {target_size, expect} <- [{1_000_000, nil}, {1_000_001, "bad-blk-length"}] do
      h = height(ctx.btc)
      sub = Connect.subsidy(h + 1, @p)
      prev = tip(ctx.btc)

      build = fn pad ->
        cb =
          BlockBuilder.coinbase_with(h + 1, 0,
            outputs: [{sub, @op_true}, {0, <<0x6A>> <> :binary.copy(<<0>>, pad)}]
          )

        BlockBuilder.build(prev.header, [cb])
      end

      size0 = byte_size(build.(0).raw)
      # The pad sits behind a CompactSize length that grows as it crosses
      # 252/65535; iterate the correction (rate is 1 byte/byte between hops).
      b = tune_size(build, target_size, target_size - size0)
      assert byte_size(b.raw) == target_size
      check(ctx, b, expect)
    end

    # (b) Segwit block of weight exactly 4,000,000 (then +1), proving witness
    # bytes count once: base ~950,000 (3,800,000 alone) + ~200,000 witness.
    # The witness sits in a P2WSH spend: k pads of 520 bytes plus two variable
    # items, all dropped by the witness script (MAX_SCRIPT_ELEMENT_SIZE = 520,
    # 201-op budget => k + 2 <= 400 stack items).
    witness_script = fn k ->
      # Drops k items: OP_2DROP for pairs, OP_DROP for the odd one, OP_TRUE.
      :binary.copy(<<0x6D>>, div(k, 2)) <>
        if(rem(k, 2) == 1, do: <<0x75>>, else: <<>>) <> <<0x51>>
    end

    # Fund P2WSH outputs for every candidate k (0-value outputs are legal).
    ks = 360..398
    coin = elem(take_coin(pool), 0)
    fund_outs = for k <- ks, do: {0, <<0x00, 0x20>> <> Hash.sha256(witness_script.(k + 2))}
    fund = BlockBuilder.tx([{coin, 0}], fund_outs ++ [{50 * @coin - 1000, @op_true}])
    check(ctx, next(ctx, [fund], fees: 1000), nil)

    build_sw = fn base_pad, k, v1, v2 ->
      h = height(ctx.btc)
      sub = Connect.subsidy(h + 1, @p)
      prev = tip(ctx.btc)
      pads = for _ <- 1..k, do: :binary.copy(<<1>>, 520)
      script = witness_script.(k + 2)
      vout = Enum.find_index(ks, &(&1 == k))

      spend =
        BlockBuilder.tx(
          [{fund.txid, vout, witness: pads ++ [v1, v2, script]}],
          [{0, @op_true}],
          version: 2
        )

      nonce = <<0::256>>
      commit = Hash.hash256([Merkle.block_witness_root([:placeholder, spend]), nonce])

      cb =
        BlockBuilder.coinbase_with(h + 1, 0,
          outputs: [
            {sub, @op_true},
            {0, <<0x6A>> <> :binary.copy(<<0>>, base_pad)},
            {0, @hdr <> commit}
          ],
          witness: [nonce]
        )

      BlockBuilder.build(prev.header, [cb, spend])
    end

    # Fix the base size, then solve (k, v1, v2) so the total weight is exact.
    base0 = Exnode.Validation.Block.base_size(build_sw.(0, 360, <<>>, <<>>))
    base_pad = 950_000 - base0

    for {target, expect} <- [{4_000_000, nil}, {4_000_001, "bad-blk-weight"}] do
      {k, v1, v2} = solve_witness(build_sw, base_pad, target)
      b = build_sw.(base_pad, k, v1, v2)
      assert Exnode.Validation.Block.weight(b) == target
      check(ctx, b, expect)
    end

    # --- witness commitment: last-of-many, trailing bytes, missing nonce -----
    # Legal witness spends need a real witness program (witness data on a
    # non-witness script fails script verification): fund P2WSH OP_TRUE outputs.
    wscript = <<0x51>>
    wp2wsh = <<0x00, 0x20>> <> Hash.sha256(wscript)

    wfund =
      BlockBuilder.tx(
        [{elem(take_coin(pool), 0), 0}],
        for(_ <- 1..4, do: {0, wp2wsh}) ++ [{50 * @coin - 1000, @op_true}]
      )

    check(ctx, next(ctx, [wfund], fees: 1000), nil)

    # Fresh spend per case; commitment computed for that spend. `outs` entries:
    # :good | {:good, trailing} | {:bad, hash}.
    commitment_block = fn vout ->
      h = height(ctx.btc)
      sub = Connect.subsidy(h + 1, @p)
      prev = tip(ctx.btc)
      nonce = <<0::256>>
      spend = BlockBuilder.tx([{wfund.txid, vout, witness: [wscript]}], [{0, @op_true}])
      good = Hash.hash256([Merkle.block_witness_root([:placeholder, spend]), nonce])

      fn outs ->
        cb_outs =
          for o <- outs do
            case o do
              :good -> {0, @hdr <> good}
              {:good, trailing} -> {0, @hdr <> good <> trailing}
              {:bad, hash} -> {0, @hdr <> hash}
            end
          end

        cb =
          BlockBuilder.coinbase_with(h + 1, 0,
            outputs: [{sub, @op_true} | cb_outs],
            witness: [nonce]
          )

        {BlockBuilder.build(prev.header, [cb, spend]), good, spend}
      end
    end

    # [garbage, good]: the last commitment is used -> valid.
    {b, _, _} = commitment_block.(0).([{:bad, <<7::256>>}, :good])
    check(ctx, b, nil)

    # [good, garbage]: the last commitment is used -> bad-witness-merkle-match.
    {b, _, _} = commitment_block.(1).([:good, {:bad, <<7::256>>}])
    check(ctx, b, "bad-witness-merkle-match")

    # Trailing junk after the 32 committed bytes: only bytes 6..38 matter.
    {b, _, _} = commitment_block.(2).([{:good, <<0x00>>}])
    check(ctx, b, nil)

    # Commitment present but the coinbase nonce is malformed (two stack
    # items): bad-witness-nonce-size. (Core's submitblock RPC inserts a zero
    # nonce when the coinbase has NO witness at all — UpdateUncommittedBlock-
    # Structures — but the P2P path, which is all exnode implements, rejects
    # every malformed or missing nonce.)
    {_b, good, spend} = commitment_block.(3).([:good])
    h = height(ctx.btc)
    sub = Connect.subsidy(h + 1, @p)
    prev = tip(ctx.btc)

    cb0 =
      BlockBuilder.coinbase_with(h + 1, 0,
        outputs: [{sub, @op_true}, {0, @hdr <> good}],
        witness: [<<0::256>>, <<0::256>>]
      )

    check(ctx, BlockBuilder.build(prev.header, [cb0, spend]), "bad-witness-nonce-size")

    # A segwit commitment in a coinbase-only block: the witness root is the
    # single zero hash (the coinbase's wtxid is always zero in the tree).
    h = height(ctx.btc)
    sub = Connect.subsidy(h + 1, @p)
    prev = tip(ctx.btc)
    nonce = <<1::256>>
    commit = Hash.hash256([<<0::256>>, nonce])

    cb =
      BlockBuilder.coinbase_with(h + 1, 0,
        outputs: [{sub, @op_true}, {0, @hdr <> commit}],
        witness: [nonce]
      )

    check(ctx, BlockBuilder.build(prev.header, [cb]), nil)

    # --- misc structural edges -------------------------------------------------
    # Empty block: no transactions at all (merkle root zero) -> bad-blk-length.
    prev = tip(ctx.btc)
    check(ctx, BlockBuilder.build(prev.header, [], merkle_root: <<0::256>>), "bad-blk-length")

    # First tx has a null prevout but two inputs: not a coinbase (IsCoinBase
    # requires exactly one input) -> bad-cb-missing.
    prev = tip(ctx.btc)

    fake_cb =
      BlockBuilder.tx(
        [{<<0::256>>, 0xFFFFFFFF}, {elem(take_coin(pool), 0), 0}],
        [{50 * @coin, @op_true}],
        version: 2
      )

    check(ctx, BlockBuilder.build(prev.header, [fake_cb]), "bad-cb-missing")

    # The same tx twice, NOT adjacent: no merkle mutation is detected (the
    # root commits to the duplicated list), but the second copy's inputs are
    # spent by the first -> bad-txns-inputs-missingorspent in ConnectBlock.
    t1 =
      BlockBuilder.tx([{elem(take_coin(pool), 0), 0}], [
        {25 * @coin, @op_true},
        {25 * @coin, @op_true}
      ])

    t2 = BlockBuilder.tx([{elem(take_coin(pool), 0), 0}], [{50 * @coin, @op_true}])
    h = height(ctx.btc)
    prev = tip(ctx.btc)
    sub = Connect.subsidy(h + 1, @p)

    check(
      ctx,
      BlockBuilder.build(prev.header, [BlockBuilder.coinbase(h + 1, sub), t1, t2, t1]),
      "bad-txns-inputs-missingorspent"
    )

    # --- coinbase scriptSig length: 100 ok, 101 bad-cb-length -----------------
    h = height(ctx.btc)
    prev = tip(ctx.btc)
    prefix = ScriptAsm.parse("#{h + 1}")

    ok =
      BlockBuilder.coinbase_with(h + 1, Connect.subsidy(h + 1, @p),
        script_sig: prefix <> :binary.copy(<<0>>, 100 - byte_size(prefix))
      )

    check(ctx, BlockBuilder.build(prev.header, [ok]), nil)

    h = height(ctx.btc)
    prev = tip(ctx.btc)
    prefix = ScriptAsm.parse("#{h + 1}")

    bad =
      BlockBuilder.coinbase_with(h + 1, Connect.subsidy(h + 1, @p),
        script_sig: prefix <> :binary.copy(<<0>>, 101 - byte_size(prefix))
      )

    check(ctx, BlockBuilder.build(prev.header, [bad]), "bad-cb-length")
  end
end
