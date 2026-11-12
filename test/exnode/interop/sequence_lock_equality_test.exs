defmodule Exnode.Interop.SequenceLockEqualityTest do
  @moduledoc """
  BIP68 relative time lock exactly at the boundary, verdict for verdict
  with the pinned bitcoind v32.1 (`submitblock`). Core
  EvaluateSequenceLocks: nonfinal when `min_time >= prev MTP`, with
  `min_time = MTP(coin height - 1) + units * 512 - 1`.

  Ordinary regtest timestamps cannot make the two equal, so 11 blocks
  with chosen strictly increasing times put the tip's MTP exactly at
  `min_time`: the spender is nonfinal for both nodes. One more block
  moves the MTP to `min_time + 1`: the same spender is then final.
  """
  use Exnode.InteropCase

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder
  alias Exnode.Validation.Connect

  @moduletag timeout: 300_000
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @op_true <<0x51>>

  setup do
    dir = Path.join(System.tmp_dir!(), "exnode-seqeq-#{System.unique_integer([:positive])}")
    btc = Bitcoind.start(Path.join(dir, "btc"))

    on_exit(fn ->
      Bitcoind.stop(btc)
      File.rm_rf!(dir)
    end)

    Bitcoind.mine(btc, 110)

    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "arch"))
    for h <- 1..110, do: {:ok, :connected} = State.submit_block(cs, Bitcoind.block(btc, h))
    %{btc: btc, cs: cs, hs: hs}
  end

  defp btc_mtp(btc, hash_hex), do: Bitcoind.json(btc, ["getblockheader", hash_hex])["mediantime"]
  defp btc_mtp_at(btc, h), do: btc_mtp(btc, Bitcoind.cli(btc, ["getblockhash", "#{h}"]))

  defp ex_mtp(hs, hash) do
    idx = Headers.index(hs)
    HeaderIndex.median_time_past(idx, HeaderIndex.lookup(idx, hash))
  end

  defp submit_both(ctx, b) do
    btc =
      case Bitcoind.cli_stdin(ctx.btc, "submitblock", Base.encode16(b.raw, case: :lower)) do
        "" -> nil
        r -> r
      end

    ex =
      case State.submit_block(ctx.cs, b) do
        {:ok, :connected} -> nil
        {:error, {:cached_invalid, r}} -> r
        {:error, {_, r}} -> r
        other -> inspect(other)
      end

    {btc, ex}
  end

  defp empty(prev, h, time),
    do: BlockBuilder.build(prev, [BlockBuilder.coinbase(h, Connect.subsidy(h, @p))], time: time)

  test "time lock at prev MTP == min_time is nonfinal; at min_time + 1 it is final", ctx do
    btc = ctx.btc
    coin_h = 5
    coin = hd(Bitcoind.block(btc, coin_h).txs).txid
    m_coin = btc_mtp_at(btc, coin_h - 1)
    assert ex_mtp(ctx.hs, Bitcoind.block(btc, coin_h - 1).header.hash) == m_coin
    m_tip = btc_mtp(btc, Bitcoind.tip(btc))
    units = div(m_tip - m_coin, 512) + 2
    min_time = m_coin + units * 512 - 1

    # Blocks 111..121 at min_time - 5 .. min_time + 5: MTP(121) = min_time.
    {last, _} =
      Enum.reduce(111..121, {Bitcoind.block(btc, 110).header, nil}, fn h, {prev, _} ->
        b = empty(prev, h, min_time + h - 116)
        assert submit_both(ctx, b) == {nil, nil}
        {b.header, b}
      end)

    assert btc_mtp(btc, Bitcoind.tip(btc)) == min_time
    assert ex_mtp(ctx.hs, last.hash) == min_time

    tx =
      BlockBuilder.tx(
        [{coin, 0, sequence: Bitwise.bor(0x00400000, units)}],
        [{50 * @coin, @op_true}],
        version: 2
      )

    spender = fn prev, h, time ->
      BlockBuilder.build(prev, [BlockBuilder.coinbase(h, Connect.subsidy(h, @p)), tx], time: time)
    end

    assert submit_both(ctx, spender.(last, 122, min_time + 6)) ==
             {"bad-txns-nonfinal", "bad-txns-nonfinal"}

    # One more block: MTP(122) = min_time + 1, the same lock is satisfied.
    b122 = empty(last, 122, min_time + 6)
    assert submit_both(ctx, b122) == {nil, nil}
    assert btc_mtp(btc, Bitcoind.tip(btc)) == min_time + 1
    assert ex_mtp(ctx.hs, b122.header.hash) == min_time + 1
    assert submit_both(ctx, spender.(b122.header, 123, min_time + 7)) == {nil, nil}
    assert Hash.from_hex(Bitcoind.tip(btc)) == State.tip(ctx.cs).hash
  end
end
