defmodule Exnode.Shadow.MonitorTest do
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Shadow.Monitor
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp blocks, do: for(raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1))

  defp start(dir, state_opts) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, mon} = Monitor.start_link(chain: :regtest, dir: dir, headers: hs)

    {:ok, cs} =
      State.start_link(
        [
          params: @p,
          headers: hs,
          kv: kv,
          hot: Path.join(dir, "a"),
          shadow_monitor: mon,
          catch_up_chunk: 30
        ] ++ state_opts
      )

    :ok = GenServer.call(mon, {:set_chain_state, cs})
    %{cs: cs, mon: mon, hs: hs, kv: kv}
  end

  defp stop(n) do
    for p <- [n.cs, n.mon, n.hs], do: GenServer.stop(p)
    KV.close(n.kv)
  end

  test "restart with the shadow behind (its data lost): catch-up from the archive, no divergence",
       %{tmp_dir: dir} do
    bs = blocks()
    n = start(dir, [])
    for b <- Enum.take(bs, 100), do: State.submit_block(n.cs, b)
    Monitor.drain(n.mon)
    stop(n)
    File.rm_rf!(Path.join(dir, "shadow"))

    n = start(dir, [])
    for b <- Enum.drop(bs, 100), do: {:ok, :connected} = State.submit_block(n.cs, b)
    assert %{divergences: 0, blocks: 150} = Monitor.drain(n.mon)
  end

  test "restart with pending blocks reconnected at init and the shadow far behind: catch-up first",
       %{tmp_dir: dir} do
    bs = blocks()
    n = start(dir, [])
    for b <- Enum.take(bs, 60), do: {:ok, :connected} = State.submit_block(n.cs, b)
    Monitor.drain(n.mon)
    # Blocks 61..150 arrive with headers known ahead and stay uncommitted
    # (no commit at the tip); then the chain state dies.
    stop(n)
    n = start(dir, batch_blocks: 1000, commit_at_tip: false)
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(bs, & &1.header))
    for b <- Enum.drop(bs, 60), do: {:ok, :connected} = State.submit_block(n.cs, b)
    Process.unlink(n.cs)
    Process.exit(n.cs, :kill)
    for p <- [n.mon, n.hs], do: GenServer.stop(p)
    KV.close(n.kv)
    # The shadow also lost its data (as when it died without flushing), so it
    # is behind the oldest reconnected block.
    File.rm_rf!(Path.join(dir, "shadow"))

    # Restart: init reconnects 61..150 from `pending` while the shadow is at 0.
    n = start(dir, [])
    assert State.tip(n.cs).height == 150
    assert %{divergences: 0} = Monitor.drain(n.mon)
    assert GenServer.call(n.cs, :halted) == false
  end

  test "restart with the shadow ahead of exnode: tolerated until exnode catches up", %{
    tmp_dir: dir
  } do
    bs = blocks()
    n = start(dir, [])
    for b <- Enum.take(bs, 100), do: State.submit_block(n.cs, b)
    Monitor.drain(n.mon)
    stop(n)

    # The shadow processed 10 blocks exnode never committed.
    {:ok, sh} = Exnode.Shadow.start_link(chain: :regtest, datadir: Path.join(dir, "shadow"))

    for b <- bs |> Enum.drop(100) |> Enum.take(10),
        do: {:ok, _} = Exnode.Shadow.process_block(sh, b.raw)

    Exnode.Shadow.stop(sh)

    n = start(dir, [])
    for b <- Enum.drop(bs, 100), do: {:ok, :connected} = State.submit_block(n.cs, b)
    assert %{divergences: 0} = Monitor.drain(n.mon)
    assert GenServer.call(n.cs, :halted) == false
  end

  test "rounds carry the committed tip, not the in-memory tip (batch partly uncommitted)", %{
    tmp_dir: dir
  } do
    bs = blocks()
    n = start(dir, batch_blocks: 10)
    # Headers first; then 2..145 (stored) and 1: one activation connects
    # 1..145, committing every 10 blocks, so 141..145 stay uncommitted while
    # the best header (150) is ahead.
    {:ok, _} = Headers.process_headers(n.hs, Enum.map(bs, & &1.header))
    for b <- bs |> Enum.take(145) |> tl(), do: {:ok, :stored} = State.submit_block(n.cs, b)
    {:ok, :connected} = State.submit_block(n.cs, hd(bs))
    assert State.tip(n.cs).height == 145
    assert %{divergences: 0} = Monitor.drain(n.mon)
    for b <- Enum.drop(bs, 145), do: {:ok, :connected} = State.submit_block(n.cs, b)
    assert %{divergences: 0, blocks: 150} = Monitor.drain(n.mon)
    assert GenServer.call(n.cs, :halted) == false
  end

  test "agreement: 150 blocks plus a rejected one, zero divergences", %{tmp_dir: dir} do
    n = start(dir, [])
    bs = blocks()
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)
    bad = BB.build(List.last(bs).header, [BB.coinbase(151, 25 * 100_000_000 + 1)])
    {:error, {:consensus, "bad-cb-amount"}} = State.submit_block(n.cs, bad)
    assert %{divergences: 0, blocks: 151} = Monitor.drain(n.mon)
    assert GenServer.call(n.cs, :halted) == false
  end

  test "exnode rejects a block Core accepts: detected, recorded, connection halted", %{
    tmp_dir: dir
  } do
    bs = blocks()
    target = Enum.at(bs, 99).header.hash

    override = fn b, _e ->
      if b.header.hash == target, do: {:error, {:consensus, "injected"}}, else: :ok
    end

    n = start(dir, rule_override: override)
    for b <- Enum.take(bs, 100), do: State.submit_block(n.cs, b)
    stats = Monitor.drain(n.mon)
    assert stats.divergences >= 1
    assert GenServer.call(n.cs, :halted) == :shadow_divergence

    assert File.exists?(
             Path.join([dir, "divergences", Exnode.Crypto.Hash.to_hex(target) <> ".json"])
           )

    # Halted: a valid block on the tip (height 99) is stored, not connected.
    tip_before = State.tip(n.cs)
    sibling = BB.build(Enum.at(bs, 98).header, [BB.coinbase(100, 50 * 100_000_000, <<0x52>>)])
    assert {:ok, :stored} = State.submit_block(n.cs, sibling)
    assert State.tip(n.cs) == tip_before
  end

  test "exnode accepts a block Core rejects (scripts skipped): detected and halted", %{
    tmp_dir: dir
  } do
    bs = blocks()
    n = start(dir, test_skip_scripts: true)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.cs, b)
    # Spend block 1's OP_TRUE coinbase with scriptSig OP_0 OP_RETURN: the script fails.
    cb1 = hd(hd(bs).txs).txid
    bad_tx = BB.tx([{cb1, 0, script_sig: <<0x00, 0x6A>>}], [{50 * 100_000_000, <<0x51>>}])
    b = BB.build(List.last(bs).header, [BB.coinbase(151, 25 * 100_000_000), bad_tx])
    assert {:ok, :connected} = State.submit_block(n.cs, b)
    assert Monitor.drain(n.mon).divergences >= 1
    assert GenServer.call(n.cs, :halted) == :shadow_divergence
  end

  describe "shadow errors are recorded, not crashed on" do
    # A proxy shadow: blocks go to the real one; tip queries fail.
    defmodule TipFails do
      use GenServer
      def init(real), do: {:ok, real}
      def handle_call({:req, <<2>>}, _from, real), do: {:reply, {:error, :tip_unavailable}, real}
      def handle_call(req, _from, real), do: {:reply, GenServer.call(real, req, :infinity), real}
      def terminate(_, real), do: GenServer.stop(real)
    end

    defp monitor(dir) do
      {:ok, mon} = Monitor.start_link(chain: :regtest, dir: dir)
      # This test process stands in for the chain state, to see the halt cast.
      :ok = GenServer.call(mon, {:set_chain_state, self()})
      mon
    end

    defp divergence_files(dir) do
      d = Path.join(dir, "divergences")
      if File.dir?(d), do: d |> File.ls!() |> Enum.sort(), else: []
    end

    defp read_doc(dir, name), do: Jason.decode!(File.read!(Path.join([dir, "divergences", name])))

    test "a connected block the shadow cannot decode: recorded, every one, halt sent, monitor alive",
         %{tmp_dir: dir} do
      mon = monitor(dir)
      genesis = @p.genesis.header.hash
      {h1, h2} = {:crypto.hash(:sha256, "a"), :crypto.hash(:sha256, "b")}
      :ok = Monitor.round(mon, [{h1, <<1, 2, 3>>}, {h2, <<4, 5, 6>>}], [], genesis)

      assert %{divergences: 2, rounds: 1} = Monitor.drain(mon)
      assert Process.alive?(mon)

      assert divergence_files(dir) ==
               Enum.sort([
                 Exnode.Crypto.Hash.to_hex(h1) <> ".json",
                 Exnode.Crypto.Hash.to_hex(h2) <> ".json"
               ])

      doc = read_doc(dir, Exnode.Crypto.Hash.to_hex(h1) <> ".json")
      assert doc["kind"] == "connected_but_shadow_error"
      assert doc["block"] == Exnode.Crypto.Hash.to_hex(h1)
      assert doc["hex"] == "010203"
      assert doc["detail"] =~ "bad_block_encoding"
      assert_received {:"$gen_cast", {:halt, :shadow_divergence}}
      GenServer.stop(mon)
    end

    test "a failed shadow tip query: recorded, round completes, no crash", %{tmp_dir: dir} do
      mon = monitor(dir)
      {:ok, proxy} = GenServer.start(TipFails, :sys.get_state(mon).shadow)
      :sys.replace_state(mon, &%{&1 | shadow: proxy})
      genesis = @p.genesis.header.hash

      :ok = Monitor.round(mon, [], [], genesis)
      assert %{divergences: 1, rounds: 1} = Monitor.drain(mon)
      assert Process.alive?(mon)
      doc = read_doc(dir, "tip-error-" <> Exnode.Crypto.Hash.to_hex(genesis) <> ".json")
      assert doc["kind"] == "shadow_tip_error"
      assert doc["detail"] =~ "tip_unavailable"
      assert_received {:"$gen_cast", {:halt, :shadow_divergence}}
      GenServer.stop(mon)
    end

    # Regression: the halt cast went to the chain state's
    # registered name once. While the chain state was restarting (name
    # unregistered) it was dropped, and the restarted chain state, finding
    # the shadow ahead, tolerated the divergence and kept connecting.
    test "a halt lost while the chain state restarts reaches the restarted one", %{tmp_dir: dir} do
      {:ok, mon} =
        Monitor.start_link(chain: :regtest, dir: dir, chain_state: :cs6_unregistered_chain_state)

      genesis = @p.genesis.header.hash
      :ok = Monitor.round(mon, [{:crypto.hash(:sha256, "x"), <<1, 2, 3>>}], [], genesis)
      assert %{divergences: 1} = Monitor.drain(mon)
      refute_received {:"$gen_cast", {:halt, _}}

      # The restarted chain state's first call is shadow_tip (catch-up).
      {:ok, _} = Monitor.shadow_tip(mon)
      assert_received {:"$gen_cast", {:halt, :shadow_divergence}}
      # Re-sent on every call until the chain state acknowledges it.
      :ok = Monitor.round(mon, [], [], genesis)
      assert_received {:"$gen_cast", {:halt, :shadow_divergence}}
      Monitor.halt_ack(mon)
      {:ok, _} = Monitor.shadow_tip(mon)
      refute_received {:"$gen_cast", {:halt, _}}
      GenServer.stop(mon)
    end

    test "agreeing rounds: no files, no halt", %{tmp_dir: dir} do
      mon = monitor(dir)
      [b1, b2 | _] = blocks()
      :ok = Monitor.round(mon, [{b1.header.hash, b1.raw}], [], b1.header.hash)
      :ok = Monitor.round(mon, [{b2.header.hash, b2.raw}], [], b2.header.hash)
      assert %{divergences: 0, rounds: 2} = Monitor.drain(mon)
      assert divergence_files(dir) == []
      refute_received {:"$gen_cast", {:halt, _}}
      GenServer.stop(mon)
    end
  end
end
