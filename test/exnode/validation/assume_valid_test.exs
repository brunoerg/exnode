defmodule Exnode.Validation.AssumeValidTest do
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Validation.Connect

  @moduletag :tmp_dir
  @moduletag timeout: 300_000
  @p ChainParams.get(:regtest)
  @op_false <<0x00>>

  # 2400 regtest blocks. The coinbases of blocks 1 and 2 pay to OP_FALSE (any
  # spend fails script verification). Block 102 spends cb1, block 200 spends cb2.
  setup_all do
    {blocks, _} =
      Enum.map_reduce(1..2400, {@p.genesis.header, %{}}, fn h, {prev, cbs} ->
        spk = if h in [1, 2], do: @op_false, else: <<0x51>>
        cb = BB.coinbase(h, Connect.subsidy(h, @p), spk)
        cbs = Map.put(cbs, h, cb.txid)

        spends =
          case h do
            102 -> [BB.spend_op_true(cbs[1], 0, 50 * 100_000_000)]
            200 -> [BB.spend_op_true(cbs[2], 0, 50 * 100_000_000)]
            _ -> []
          end

        b = BB.build(prev, [cb | spends])
        {b, {b.header, cbs}}
      end)

    %{blocks: blocks}
  end

  defp run(dir, blocks, assume_valid) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    # All headers first, so the best header is far ahead (as in IBD).
    {:ok, _} = Headers.process_headers(hs, Enum.map(blocks, & &1.header))

    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "a"),
        assume_valid: assume_valid
      )

    result =
      Enum.reduce_while(blocks, nil, fn b, _ ->
        case State.submit_block(cs, b) do
          {:ok, _} -> {:cont, nil}
          {:error, r} -> {:halt, r}
        end
      end)

    {result, State.tip(cs).height, GenServer.call(cs, :script_stats)}
  end

  test "below the assumevalid block scripts are skipped; above it they are checked", %{
    tmp_dir: dir,
    blocks: blocks
  } do
    av = Hash.to_hex(Enum.at(blocks, 149).header.hash)
    assert {{:consensus, "block-script-verify-flag-failed"}, 199, stats} = run(dir, blocks, av)
    # Blocks 1..150 skipped, 151..199 checked (block 200 failed).
    assert stats == %{skipped: 150, checked: 49}
  end

  test "assumevalid=0 verifies everything: the bad spend at 102 is rejected", %{
    tmp_dir: dir,
    blocks: blocks
  } do
    assert {{:consensus, "block-script-verify-flag-failed"}, 101, %{skipped: 0}} =
             run(dir, blocks, "0")
  end

  test "decide/4: each of Core's script_check_reason conditions", %{tmp_dir: dir, blocks: blocks} do
    alias Exnode.Chain.HeaderIndex
    alias Exnode.Validation.AssumeValid
    {:ok, kv} = KV.open(Path.join(dir, "kv2"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, _} = Headers.process_headers(hs, Enum.map(blocks, & &1.header))
    side = BB.next_header(Enum.at(blocks, 8).header, merkle_root: <<5::256>>)
    {:ok, _} = Headers.process_headers(hs, [side])
    idx = Headers.index(hs)
    e = fn h -> HeaderIndex.lookup(idx, HeaderIndex.hash_at(idx, h)) end
    tip = List.last(blocks).header.hash
    at150 = Enum.at(blocks, 149).header.hash

    assert AssumeValid.decide(nil, idx, e.(10), @p) == {:check, "assumevalid=0 (always verify)"}

    assert AssumeValid.decide(<<1::256>>, idx, e.(10), @p) ==
             {:check, "assumevalid hash not in headers"}

    assert AssumeValid.decide(at150, idx, e.(151), @p) ==
             {:check, "block height above assumevalid height"}

    assert AssumeValid.decide(tip, idx, HeaderIndex.lookup(idx, side.hash), @p) ==
             {:check, "block not in assumevalid chain"}

    # 10 blocks below the best header = 6000 s of equivalent work < 2 weeks.
    assert AssumeValid.decide(tip, idx, e.(2390), @p) ==
             {:check, "block too recent relative to best header"}

    # 2016 regtest blocks are exactly 2 weeks: still checked (<=); one more is skipped.
    assert AssumeValid.decide(tip, idx, e.(2400 - 2016), @p) ==
             {:check, "block too recent relative to best header"}

    assert AssumeValid.decide(tip, idx, e.(2400 - 2017), @p) == :skip
    assert AssumeValid.decide(tip, idx, e.(10), @p) == :skip

    # Best header below nMinimumChainWork: always check.
    p = %{@p | minimum_chain_work: idx.best.chain_work + 1}

    assert AssumeValid.decide(tip, idx, e.(10), p) ==
             {:check, "best header chainwork below minimumchainwork"}
  end
end
