defmodule Exnode.Chain.HeaderDurabilityTest do
  @moduledoc """
  Regression: `Headers` writes accepted headers through `Headers.Writer`
  without waiting, and nothing waited for those writes before the chain
  state's synced archive commit. A crash in between left a committed tip
  without a stored header: `Chain.State.init` then failed on every start.
  A pending block stored ahead of its header was held again at restart but
  never linked, nor downloaded again.
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

  defp start_cs(dir, kv, hs) do
    State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"))
  end

  defp setup_chain(dir) do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = start_cs(dir, kv, hs)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    next = BB.build(List.last(bs).header, [BB.coinbase(151, 25 * @coin)])
    %{kv: kv, hs: hs, cs: cs, next: next}
  end

  test "a commit waits for the headers of the blocks it makes durable", %{tmp_dir: dir} do
    Process.flag(:trap_exit, true)
    %{kv: kv, hs: hs, cs: cs, next: next} = setup_chain(dir)
    hash = next.header.hash

    # The writer lags (stands in for it not being scheduled yet): the
    # header write stays queued while the block is connected and committed.
    w = :sys.get_state(hs).writer
    :ok = :sys.suspend(w)
    me = self()

    spawn(fn ->
      send(me, {:submitted, State.submit_block(cs, next)})
    end)

    receive do: ({:submitted, _} -> :ok), after: (500 -> :ok)

    # Crash: the queued header write is lost; what reached the KV survives.
    for pid <- [w, hs, cs], do: Process.exit(pid, :kill)

    {:ok, hs2} = Headers.start_link(params: @p, kv: kv)
    idx = Headers.index(hs2)

    capture_log(fn ->
      assert {:ok, cs2} = start_cs(dir, kv, hs2)
      tip = State.tip(cs2)
      assert HeaderIndex.lookup(idx, tip.hash) != nil
      refute tip.hash == hash
    end)
  end

  test "a pending block whose header was lost is dropped at start-up", %{tmp_dir: dir} do
    %{kv: kv, hs: hs, cs: cs, next: next} = setup_chain(dir)
    hash = next.header.hash
    GenServer.stop(cs)

    # Stored ahead of its header, which the crash lost.
    :ok = KV.write(kv, [{:put, :pending, hash, next.raw}], sync: true)
    assert HeaderIndex.lookup(Headers.index(hs), hash) == nil

    {:ok, cs2} = start_cs(dir, kv, hs)
    assert GenServer.call(cs2, :debug).held == []
    refute State.have_block?(cs2, hash)
    assert KV.get(kv, :pending, hash) == :not_found
  end
end
