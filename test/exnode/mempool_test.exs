defmodule Exnode.MempoolTest do
  @moduledoc """
  The mempool process under load (fix-03 WS2): context-free checks before
  any chain-state call, script checks off the process (with an injected,
  latch-controlled `verify`), pending inputs, the tip moving during a
  verification, and the bound on pending accepts. Real chain state and
  headers on a regtest chain built here, coinbases to P2WSH(OP_TRUE).
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Tx
  alias Exnode.Mempool
  alias Exnode.Mempool.Accept
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @spk <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)

  defp spend({txid, vout, value}, fee, n \\ 1) do
    ins = [
      %Tx.In{
        prev_hash: txid,
        prev_index: vout,
        script_sig: <<>>,
        sequence: 0xFFFFFFFD,
        witness: [<<0x51>>]
      }
    ]

    outs = for _ <- 1..n, do: %Tx.Out{value: div(value - fee, n), script_pubkey: @spk}
    BB.finalize(%Tx{version: 2, inputs: ins, outputs: outs, locktime: 0})
  end

  # A `verify` that tells the test it started, then waits for the gate
  # (an atomic: 0 closed, 1 open) before running the real kernel.
  defp gated_verify(test, gate) do
    fn raw, spent, flags ->
      send(test, {:verifying, self()})
      wait_gate(gate)
      Exnode.Kernel.verify_tx_all(raw, spent, flags)
    end
  end

  defp wait_gate(gate) do
    if :atomics.get(gate, 1) == 0, do: Process.sleep(5) && wait_gate(gate)
  end

  defp setup_chain(dir) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    name = :"mp_#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), mempool: name)

    {blocks, _} =
      Enum.map_reduce(1..120, @p.genesis.header, fn h, prev ->
        b =
          BB.build(prev, [
            BB.coinbase_with(h, 50 * 100_000_000, outputs: [{50 * 100_000_000, @spk}])
          ])

        {b, b.header}
      end)

    for b <- blocks, do: {:ok, :connected} = State.submit_block(cs, b)
    coins = for b <- Enum.take(blocks, 20), do: {hd(b.txs).txid, 0, 50 * 100_000_000}
    %{cs: cs, hs: hs, name: name, coins: coins, last: List.last(blocks)}
  end

  defp start_mp(c, opts) do
    {:ok, mp} =
      Mempool.start_link([name: c.name, chain_state: c.cs, headers: c.hs, params: @p] ++ opts)

    mp
  end

  defp pending(mp) do
    st = :sys.get_state(mp)
    map_size(st.jobs) + :queue.len(st.deferred)
  end

  defp wait_until(f, n \\ 400) do
    cond do
      f.() -> :ok
      n == 0 -> flunk("condition not reached")
      true -> Process.sleep(10) && wait_until(f, n - 1)
    end
  end

  # A chain state that records every call and has no chain.
  defmodule SpyChain do
    use GenServer
    def start_link(test), do: GenServer.start_link(__MODULE__, test)
    def init(test), do: {:ok, test}

    def handle_call(msg, _from, test) do
      send(test, {:chain_state_called, msg})
      {:reply, {:error, :spy}, test}
    end
  end

  test "context-free failures are answered without any chain-state call" do
    {:ok, spy} = SpyChain.start_link(self())
    {:ok, mp} = Mempool.start_link(chain_state: spy, headers: spy, params: @p)
    good = spend({:crypto.hash(:sha256, "c"), 0, 100_000}, 1_000)
    empty_vin = %{good | inputs: []}

    big_out = %{
      good
      | outputs: [%Tx.Out{value: 21_000_000 * 100_000_000 + 1, script_pubkey: @spk}]
    }

    coinbase = %{
      good
      | inputs: [
          %{hd(good.inputs) | prev_hash: <<0::256>>, prev_index: 0xFFFFFFFF, script_sig: <<1, 1>>}
        ]
    }

    oversize = %{
      good
      | outputs: [%Tx.Out{value: 1, script_pubkey: :binary.copy(<<0x51>>, 1_000_001)}]
    }

    state = :sys.get_state(mp).state

    # An empty-vin tx does not round-trip through the codec (it reads as a
    # witness marker), so it keeps the fields of `good` but its inputs.
    txs = [empty_vin | Enum.map([big_out, coinbase, oversize], &BB.finalize/1)]
    reasons = ["bad-txns-vin-empty", "bad-txns-vout-toolarge", "coinbase", "bad-txns-oversize"]

    for {tx, reason} <- Enum.zip(txs, reasons) do
      assert {:error, %{reason: ^reason} = e} = Mempool.accept(mp, tx)
      # The same verdict as the full pre-checks (the same function runs first there).
      assert {:error, e} == Accept.precheck_context_free(state, tx)
      assert e.result in [:consensus, :not_standard]
    end

    refute_received {:chain_state_called, _}
  end

  test "script lookups: the txs touching a script with the outputs they spend; spenders; fee rates",
       %{tmp_dir: dir} do
    c = setup_chain(dir)
    sh = :crypto.hash(:sha256, @spk)
    other = <<0, 32>> <> :crypto.hash(:sha256, "other")

    # Without the index the lookup says so (rather than answering empty).
    plain = start_mp(c, [])
    assert Mempool.script_txs(plain, sh) == {:error, :not_indexed}
    GenServer.stop(plain)

    mp = start_mp(c, index_scripts: true)
    [c1, c2 | _] = c.coins
    # a pays to @spk; b spends a coinbase output of @spk to another script.
    a = spend(c1, 1_000)

    b =
      BB.finalize(%{
        spend(c2, 2_000)
        | outputs: [%Tx.Out{value: 50 * 100_000_000 - 2_000, script_pubkey: other}]
      })

    for t <- [a, b], do: assert({:ok, _} = Mempool.accept(mp, t))

    assert [%{txid: ta, spent: [{_, ^sh}]}, %{txid: tb}] = Mempool.script_txs(mp, sh)
    assert {ta, tb} == {a.txid, b.txid}
    assert [%{txid: ^tb}] = Mempool.script_txs(mp, :crypto.hash(:sha256, other))
    assert Mempool.script_txs(mp, <<0::256>>) == []

    ch = spend({a.txid, 0, 50 * 100_000_000 - 1_000}, 1_000)
    assert {:ok, _} = Mempool.accept(mp, ch)

    assert Mempool.spenders(mp, [{a.txid, 0}, {a.txid, 1}, {c1 |> elem(0), 0}]) ==
             %{{a.txid, 0} => {ch.txid, 0}, {elem(c1, 0), 0} => {a.txid, 0}}

    {pairs, vsize} = Mempool.fee_rates(mp)
    assert Enum.sort(for {f, _} <- pairs, do: f) == [1_000, 1_000, 2_000]
    assert vsize == Enum.sum(for {_, v} <- pairs, do: v)
  end

  test "two concurrent accepts of the same input: exactly one succeeds", %{tmp_dir: dir} do
    c = setup_chain(dir)
    gate = :atomics.new(1, [])
    mp = start_mp(c, verify: gated_verify(self(), gate))
    coin = hd(c.coins)
    a = spend(coin, 1_000)
    b = spend(coin, 1_000, 2)

    ta = Task.async(fn -> Mempool.accept(mp, a) end)
    assert_receive {:verifying, _}, 5_000
    tb = Task.async(fn -> Mempool.accept(mp, b) end)
    wait_until(fn -> pending(mp) == 2 end)
    # B waits for A (it spends A's input) instead of verifying alongside.
    refute_received {:verifying, _}
    :atomics.put(gate, 1, 1)

    results = [Task.await(ta, 10_000), Task.await(tb, 10_000)]
    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert {:ok, _} = hd(results)
    assert Mempool.has?(mp, a.txid)
    refute Mempool.has?(mp, b.txid)
    assert pending(mp) == 0
  end

  test "the process answers while a verification runs; the accept then completes",
       %{tmp_dir: dir} do
    c = setup_chain(dir)
    gate = :atomics.new(1, [])
    mp = start_mp(c, verify: gated_verify(self(), gate))
    a = spend(hd(c.coins), 1_000)
    ta = Task.async(fn -> Mempool.accept(mp, a) end)
    assert_receive {:verifying, _}, 5_000

    {us, reply} =
      :timer.tc(fn -> Mempool.accept(mp, %{a | inputs: []}) end)

    assert {:error, %{reason: "bad-txns-vin-empty"}} = reply
    assert us < 1_000_000
    assert Mempool.txids(mp) == []
    assert Mempool.pool(mp).entries == %{}
    refute Task.yield(ta, 0)

    :atomics.put(gate, 1, 1)
    assert {:ok, %{txid: txid}} = Task.await(ta, 10_000)
    assert txid == a.txid
    assert Mempool.txids(mp) == [a.txid]
  end

  test "a block during verification: the accept is decided again at the new tip",
       %{tmp_dir: dir} do
    c = setup_chain(dir)
    gate = :atomics.new(1, [])
    mp = start_mp(c, verify: gated_verify(self(), gate))
    coin = hd(c.coins)
    a = spend(coin, 1_000)
    # A conflicting spend of A's input, mined while A's scripts run.
    a2 = spend(coin, 3_000, 2)
    ta = Task.async(fn -> Mempool.accept(mp, a) end)
    assert_receive {:verifying, _}, 5_000

    cb = fn extra, wit ->
      BB.coinbase_with(121, 0,
        outputs: [{50 * 100_000_000 + 3_000, @spk} | extra],
        witness: wit
      )
    end

    blk = BB.build_segwit(c.last.header, cb, [a2])
    {:ok, :connected} = State.submit_block(c.cs, blk)
    :ok = Mempool.sync_to(mp, blk.header.hash)
    :atomics.put(gate, 1, 1)

    # Never added from the old view: its input is spent at the new tip.
    assert {:error, e} = Task.await(ta, 10_000)
    assert e.result in [:missing_inputs, :reconsiderable]
    refute Mempool.has?(mp, a.txid)
    assert Mempool.size(mp) == 0
  end

  test "pending accepts are bounded; beyond the bound the answer is fast and not punishable",
       %{tmp_dir: dir} do
    c = setup_chain(dir)
    gate = :atomics.new(1, [])
    mp = start_mp(c, verify: gated_verify(self(), gate))
    coin = hd(c.coins)
    # One verification held; 127 more spends of the same coin wait behind it.
    tasks = for i <- 1..128, do: Task.async(fn -> Mempool.accept(mp, spend(coin, 1_000 + i)) end)
    wait_until(fn -> pending(mp) == 128 end)

    {us, reply} = :timer.tc(fn -> Mempool.accept(mp, spend(Enum.at(c.coins, 1), 1_000)) end)
    assert {:error, %{result: :reconsiderable, reason: "mempool busy"}} = reply
    assert us < 1_000_000

    :atomics.put(gate, 1, 1)
    for t <- tasks, do: Task.await(t, 30_000)
    assert pending(mp) == 0
    # Room again.
    assert {:ok, _} = Mempool.accept(mp, spend(Enum.at(c.coins, 1), 1_000))
  end
end
