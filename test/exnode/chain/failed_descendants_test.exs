defmodule Exnode.Chain.FailedDescendantsTest do
  @moduledoc """
  Regression: when a block failed ConnectBlock, its descendants were marked
  failed in the header index but only the failed block was unheld, so
  stored descendants stayed in `pending`, the held set and the view for
  good, and were held again on every restart. A synchronous submission of
  such a descendant was also answered with the ancestor's failure (the
  chain state's last failure), so the peer that relayed it was punished
  for a block that Core accepts (ProcessNewBlock returns true; only the
  block that failed is reported, through BlockChecked).
  """
  use Exnode.NodeCase, async: true
  import ExUnit.CaptureLog

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  defp start_cs(dir, kv, hs, opts) do
    {:ok, cs} =
      State.start_link([params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot")] ++ opts)

    cs
  end

  defp status(hs, hash), do: HeaderIndex.lookup(Headers.index(hs), hash).status

  # Tip a151; a fork f151 (invalid on connect, equal work: not tried) and f152.
  defp setup_fork(dir) do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    top = List.last(bs).header

    a151 =
      BB.build(top, [
        BB.coinbase(151, 25 * @coin),
        BB.spend_op_true(hd(hd(bs).txs).txid, 0, 50 * @coin)
      ])

    f151 = BB.build(top, [BB.coinbase(151, 1 * @coin)])
    f152 = BB.build(f151.header, [BB.coinbase(152, 1 * @coin)])
    bad = f151.header.hash

    rule = fn block, _ ->
      if block.header.hash == bad, do: {:error, {:consensus, "injected-invalid"}}, else: :ok
    end

    cs = start_cs(dir, kv, hs, rule_override: rule)
    for x <- bs ++ [a151], do: {:ok, :connected} = State.submit_block(cs, x)
    %{cs: cs, kv: kv, hs: hs, a151: a151, f151: f151, f152: f152, rule: rule}
  end

  test "a descendant of a block that fails on connect is unheld, and its relayer not blamed",
       %{tmp_dir: dir} do
    %{cs: cs, kv: kv, hs: hs, a151: a151, f151: f151, f152: f152, rule: rule} = setup_fork(dir)

    # Equal work with the tip: stored, not tried.
    assert {:ok, :stored} = State.submit_block(cs, f151)

    # f152 makes the fork better: activation tries f151, which fails. f152
    # itself was accepted (Core ProcessNewBlock returns true): not an error.
    capture_log(fn -> assert {:ok, :stored} = State.submit_block(cs, f152) end)

    assert State.tip(cs).hash == a151.header.hash
    assert status(hs, f151.header.hash) == :failed
    assert status(hs, f152.header.hash) == :failed
    assert GenServer.call(cs, :debug).held == []
    assert KV.get(kv, :pending, f152.header.hash) == :not_found
    refute State.have_block?(cs, f152.header.hash)

    # A restart drops pending copies of failed blocks (as left by an
    # earlier run) instead of holding them again.
    GenServer.stop(cs)
    :ok = KV.write(kv, [{:put, :pending, f152.header.hash, f152.raw}], sync: true)
    cs2 = start_cs(dir, kv, hs, rule_override: rule)
    assert GenServer.call(cs2, :debug).held == []
    assert KV.get(kv, :pending, f152.header.hash) == :not_found
    assert State.tip(cs2).hash == a151.header.hash
  end

  test "the block that failed on connect still gets its own failure", %{tmp_dir: dir} do
    %{cs: cs, kv: kv, hs: hs, f151: f151, f152: f152} = setup_fork(dir)

    # f152 first (f151's header only), then f151 completes the better fork.
    {:ok, _} = Headers.process_headers(hs, [f151.header])
    assert {:ok, :stored} = State.submit_block(cs, f152)

    capture_log(fn ->
      assert {:error, {:consensus, "injected-invalid"}} = State.submit_block(cs, f151)
    end)

    assert status(hs, f152.header.hash) == :failed
    assert GenServer.call(cs, :debug).held == []
    assert KV.get(kv, :pending, f152.header.hash) == :not_found
  end
end
