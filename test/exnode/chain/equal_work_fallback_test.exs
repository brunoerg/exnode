defmodule Exnode.Chain.EqualWorkFallbackTest do
  @moduledoc """
  Regression (found by the consensus differential
  property): A and B are equal-work siblings, A received first and active.
  C, an invalid child of B, makes the node reorg to B and then fail C. Core
  (CBlockIndexWorkComparator keeps A, the earlier body, ranked above the
  tip B) returns to A; exnode stayed on B.
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Shadow
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Validation.Connect

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)

  test "after a failed reorg to an equal-work branch, the first-seen branch is active again (as Core)",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "arch"))
    {:ok, sh} = Shadow.start_link(chain: :regtest, datadir: Path.join(dir, "shadow"))
    now = System.os_time(:second)

    submit = fn b ->
      r = State.submit_block(cs, b, requested: true)
      {:ok, v} = Shadow.process_block(sh, b.raw)
      {r, v.tip}
    end

    tip =
      Enum.reduce(1..10, @p.genesis.header, fn h, prev ->
        b = BB.build(prev, [BB.coinbase(h, Connect.subsidy(h, @p))], time: now - 100 + h)
        {{:ok, :connected}, _} = submit.(b)
        b.header
      end)

    a = BB.build(tip, [BB.coinbase(11, Connect.subsidy(11, @p))], time: tip.time + 1)
    b = BB.build(tip, [BB.coinbase(11, Connect.subsidy(11, @p) - 1)], time: tip.time + 1)
    c = BB.build(b.header, [BB.coinbase(12, Connect.subsidy(12, @p) + 1)], time: tip.time + 2)

    assert {{:ok, :connected}, {11, a_hash}} = submit.(a)
    assert a_hash == a.header.hash
    assert {{:ok, :stored}, {11, ^a_hash}} = submit.(b)
    assert {{:error, {:consensus, "bad-cb-amount"}}, core_tip} = submit.(c)

    assert core_tip == {11, a.header.hash}
    assert State.tip(cs).hash == a.header.hash
  end
end
