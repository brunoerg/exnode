defmodule Exnode.DoS.OrphanReconsiderStallTest do
  @moduledoc """
  Regression: orphans spending an
  accepted tx used to be reconsidered inline, one synchronous
  `Mempool.accept` per child (script verification included) inside the
  single TxRelay handler that accepted the parent. Attackers filling the
  orphanage (within its caps) with children of P built to fail script checks
  late, then relaying P, stalled TxRelay for the sum of their verification
  times, and with it every peer blocked in a TxRelay call (inv, tx,
  notfound, getdata), and the blocks queued behind those calls. Repeatable
  every round.

  Core (`AddChildrenToWorkSet`, `ProcessOrphanTx`) puts each child in the
  work set of one of its announcers and reconsiders at most one decisive
  orphan per peer turn, so honest peers interleave. Here the work sets are
  drained a step at a time, between the calls TxRelay serves.
  """
  use ExUnit.Case, async: false
  @moduletag :dos

  alias Exnode.Codec.Tx
  alias Exnode.P2P.TxRelay

  # Every child accepted after its parent costs this long, then fails as
  # consensus-invalid: an orphan crafted to fail late in script checks.
  @verify_ms 25
  @children 200

  defmodule SlowMempool do
    use GenServer
    def start_link(arg), do: GenServer.start_link(__MODULE__, arg)

    def init({parent_wtxid, ctr, verify_ms}),
      do: {:ok, %{parent: parent_wtxid, have_parent: false, ctr: ctr, ms: verify_ms}}

    def handle_call({:has, _h, _k}, _f, st), do: {:reply, false, st}
    def handle_call({:has_many, _hs, _k}, _f, st), do: {:reply, MapSet.new(), st}
    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}
    def handle_call({:submit_package, _}, _f, st), do: {:reply, %{state: :error}, st}

    def handle_call({:accept, tx, _}, _f, st) do
      cond do
        tx.wtxid == st.parent ->
          {:reply, {:ok, %{}}, %{st | have_parent: true}}

        not st.have_parent ->
          {:reply, {:error, %{result: :missing_inputs, reason: "missing-inputs"}}, st}

        true ->
          verify(st.ms)
          :counters.add(st.ctr, 1, 1)

          {:reply, {:error, %{result: :consensus, reason: "mandatory-script-verify-flag-failed"}},
           st}
      end
    end

    # `{:gate, pid}`: tells pid it is verifying and holds until `:go`.
    defp verify({:gate, pid}) do
      send(pid, {:verifying, self()})
      receive do: (:go -> :ok)
    end

    defp verify(ms), do: Process.sleep(ms)
  end

  defp tx(inputs, tag) do
    {:ok, tx} =
      %Tx{
        version: 2,
        locktime: tag,
        inputs:
          for(
            {h, i} <- inputs,
            do: %Tx.In{prev_hash: h, prev_index: i, script_sig: <<>>, sequence: 0xFFFFFFFF}
          ),
        outputs: [%Tx.Out{value: 10_000, script_pubkey: <<0, 20, 0::160>>}]
      }
      |> Tx.encode()
      |> IO.iodata_to_binary()
      |> Tx.decode_exact()

    tx
  end

  defp peer(relay) do
    pid = spawn(fn -> Process.sleep(:infinity) end)

    TxRelay.connected(relay, pid, %{
      wtxid_relay: true,
      preferred: false,
      relay_txs: true,
      inbound: true
    })

    pid
  end

  test "reconsidering many slow orphans does not stall other peers' TxRelay calls" do
    parent = tx([{:crypto.strong_rand_bytes(32), 0}], 0)
    ctr = :counters.new(1, [])
    {:ok, mp} = SlowMempool.start_link({parent.wtxid, ctr, @verify_ms})
    {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)

    # Three attacker connections hold the children of `parent` as orphans.
    attackers = for _ <- 1..3, do: peer(r)

    for {i, a} <- Enum.zip(1..@children, Stream.cycle(attackers)) do
      :ok = TxRelay.received_tx(r, a, tx([{parent.txid, i}], i))
    end

    assert length(TxRelay.orphans(r)) == @children

    honest = peer(r)
    other = peer(r)

    # Anyone relays the parent; meanwhile another peer makes an ordinary call.
    relay_parent =
      Task.async(fn -> :timer.tc(fn -> TxRelay.received_tx(r, honest, parent) end) end)

    # The inv must arrive while the children are being reconsidered.
    await(fn -> :counters.get(ctr, 1) >= 1 end)
    item = %{type: :wtx, hash: :crypto.strong_rand_bytes(32)}
    {inv_us, :ok} = :timer.tc(fn -> TxRelay.inv(r, other, [item]) end)
    {parent_us, :ok} = Task.await(relay_parent, 60_000)

    IO.puts(
      "#{@children} orphans x #{@verify_ms} ms: relaying the parent took #{div(parent_us, 1000)} ms, " <>
        "another peer's inv #{div(inv_us, 1000)} ms"
    )

    # Inline: the inv waits for every child (~#{@children * @verify_ms} ms).
    # Stepped: it waits for at most one child.
    assert inv_us < 1_000_000
    assert parent_us < 1_000_000

    # The work still gets done: every child reconsidered, and gone.
    deadline = System.monotonic_time(:millisecond) + 30_000
    wait_all(r, ctr, deadline)
    assert :counters.get(ctr, 1) == @children
    assert TxRelay.orphans(r) == []
  end

  defmodule ChainMempool do
    use GenServer
    def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
    # Accepts a tx once every tx it spends from `chain` is in.
    def init(chain), do: {:ok, %{chain: MapSet.new(chain, & &1.txid), have: MapSet.new()}}

    def handle_call({:has, _h, _k}, _f, st), do: {:reply, false, st}
    def handle_call({:has_many, _hs, _k}, _f, st), do: {:reply, MapSet.new(), st}
    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}
    def handle_call({:submit_package, _}, _f, st), do: {:reply, %{state: :error}, st}

    def handle_call({:accept, tx, _}, _f, st) do
      parents = for i <- tx.inputs, MapSet.member?(st.chain, i.prev_hash), do: i.prev_hash

      if Enum.all?(parents, &MapSet.member?(st.have, &1)) do
        {:reply, {:ok, %{}}, %{st | have: MapSet.put(st.have, tx.txid)}}
      else
        {:reply, {:error, %{result: :missing_inputs, reason: "missing-inputs"}}, st}
      end
    end
  end

  defp await(f, deadline \\ System.monotonic_time(:millisecond) + 5_000) do
    cond do
      f.() -> :ok
      System.monotonic_time(:millisecond) > deadline -> flunk("condition not reached")
      true -> Process.sleep(10) && await(f, deadline)
    end
  end

  test "a chain of orphans resolves step by step once its root arrives" do
    root = tx([{:crypto.strong_rand_bytes(32), 0}], 0)
    child = tx([{root.txid, 0}], 1)
    grandchild = tx([{child.txid, 0}], 2)
    {:ok, mp} = ChainMempool.start_link([root, child, grandchild])
    {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)
    a = peer(r)

    :ok = TxRelay.received_tx(r, a, grandchild)
    :ok = TxRelay.received_tx(r, a, child)
    assert Enum.sort(TxRelay.orphans(r)) == Enum.sort([child.wtxid, grandchild.wtxid])

    :ok = TxRelay.received_tx(r, peer(r), root)
    await(fn -> TxRelay.orphans(r) == [] end)
    assert MapSet.member?(:sys.get_state(mp).have, grandchild.txid)
  end

  test "an announcer that disconnects takes its queued reconsideration with it" do
    parent = tx([{:crypto.strong_rand_bytes(32), 0}], 0)
    ctr = :counters.new(1, [])
    {:ok, mp} = SlowMempool.start_link({parent.wtxid, ctr, {:gate, self()}})
    {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)
    a = peer(r)
    for i <- 1..5, do: :ok = TxRelay.received_tx(r, a, tx([{parent.txid, i}], i))

    # The first child is being verified when the announcer goes: TxRelay
    # has the DOWN queued before that verification returns.
    :ok = TxRelay.received_tx(r, peer(r), parent)
    assert_receive {:verifying, ^mp}, 5_000
    Process.exit(a, :kill)
    await(fn -> down_queued?(r, a) end)
    send(mp, :go)
    await(fn -> :sys.get_state(r).orphan_work == %{} end)

    st = :sys.get_state(r)
    assert MapSet.size(st.orphan_work_set) == 0
    assert :queue.is_empty(st.orphan_work_peers)
    # Only the child already in verification was reconsidered (Core
    # EraseForPeer); the orphans themselves went with their only announcer.
    assert :counters.get(ctr, 1) == 1
    assert TxRelay.orphans(r) == []
  end

  defp down_queued?(r, pid) do
    {:messages, msgs} = Process.info(r, :messages)
    Enum.any?(msgs, &match?({:DOWN, _, :process, ^pid, _}, &1))
  end

  defp wait_all(r, ctr, deadline) do
    cond do
      :counters.get(ctr, 1) >= @children and TxRelay.orphans(r) == [] ->
        :ok

      System.monotonic_time(:millisecond) > deadline ->
        flunk("children not all reconsidered: #{:counters.get(ctr, 1)} of #{@children}")

      true ->
        Process.sleep(20)
        wait_all(r, ctr, deadline)
    end
  end
end
