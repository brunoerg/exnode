defmodule Exnode.Mempool.ActiveViewRaceTest do
  @moduledoc """
  Tests for lock-free `Chain.View` active coin reads (`Chain.View.resolve_active/2`
  seqlock) and non-blocking `Mempool.sync_to/2` (Plan 02).
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State, View}
  alias Exnode.Codec.Tx
  alias Exnode.Mempool
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @spk <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)

  defp spend({txid, vout, value}, fee \\ 2_000) do
    ins = [
      %Tx.In{
        prev_hash: txid,
        prev_index: vout,
        script_sig: <<>>,
        sequence: 0xFFFFFFFD,
        witness: [<<0x51>>]
      }
    ]

    outs = [%Tx.Out{value: value - fee, script_pubkey: @spk}]
    BB.finalize(%Tx{version: 2, inputs: ins, outputs: outs, locktime: 0})
  end

  defp build_chain(prev, heights) do
    Enum.map_reduce(heights, prev, fn h, prev_hdr ->
      b =
        BB.build(prev_hdr, [
          BB.coinbase_with(h, 50 * 100_000_000, outputs: [{50 * 100_000_000, @spk}])
        ])

      {b, b.header}
    end)
  end

  test "mempool_view reads lock-free from Chain.View even when Chain.State is suspended", %{
    tmp_dir: dir
  } do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs_name = :"cs_lockfree_#{System.unique_integer([:positive])}"
    mp_name = :"mp_lockfree_#{System.unique_integer([:positive])}"

    {:ok, cs_pid} =
      State.start_link(
        name: cs_name,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        mempool: mp_name,
        commit_at_tip: false,
        batch_blocks: 500
      )

    {blocks, _} = build_chain(@p.genesis.header, 1..105)
    for b <- blocks, do: {:ok, :connected} = State.submit_block(cs_name, b)

    # Confirm blocks are uncommitted in overlay/batch (committed height < 105).
    view = View.view(cs_name)
    assert View.view_tip(view).height == 105
    assert rem(View.view_active_gen(view), 2) == 0

    {:ok, mp} =
      Mempool.start_link(
        name: mp_name,
        chain_state: cs_name,
        headers: hs,
        params: @p
      )

    # Suspend Chain.State to prove mempool_view + Mempool.accept do not call into Chain.State.
    :ok = :sys.suspend(cs_pid)

    try do
      cb1 = hd(hd(blocks).txs)
      cb_last = hd(List.last(blocks).txs)
      missing_op = {:crypto.strong_rand_bytes(32), 0}
      bad_vout_op = {cb_last.txid, 99}

      {tip, coins} =
        State.mempool_view(cs_name, [{cb1.txid, 0}, {cb_last.txid, 0}, missing_op, bad_vout_op])

      assert tip.height == 105
      assert {:ok, %{value: 5_000_000_000, height: 1, coinbase: true}} = coins[{cb1.txid, 0}]

      assert {:ok, %{value: 5_000_000_000, height: 105, coinbase: true}} =
               coins[{cb_last.txid, 0}]

      assert coins[missing_op] == :missing
      assert coins[bad_vout_op] == :missing

      # A full Mempool.accept succeeds while Chain.State is completely suspended.
      tx = spend({cb1.txid, 0, 50 * 100_000_000})
      assert {:ok, _} = Mempool.accept(mp, tx)
      assert Mempool.has?(mp, tx.txid)
    after
      :sys.resume(cs_pid)
    end
  end

  test "concurrent mempool_view reads during connects, commits, and reorgs stay consistent", %{
    tmp_dir: dir
  } do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs_name = :"cs_race_#{System.unique_integer([:positive])}"

    {:ok, _cs} =
      State.start_link(
        name: cs_name,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        commit_at_tip: false,
        batch_blocks: 10
      )

    {base, hdr10} = build_chain(@p.genesis.header, 1..10)
    for b <- base, do: {:ok, :connected} = State.submit_block(cs_name, b)
    base_op = {hd(hd(base).txs).txid, 0}

    {branch_a, _} = build_chain(hdr10, 11..15)
    # Alternate longer fork from height 10 with distinct coinbase script.
    alt_spk = <<0, 32>> <> :crypto.hash(:sha256, <<0x52>>)

    {branch_b, _} =
      Enum.map_reduce(11..18, hdr10, fn h, prev_hdr ->
        b =
          BB.build(
            prev_hdr,
            [BB.coinbase_with(h, 49 * 100_000_000, outputs: [{49 * 100_000_000, alt_spk}])],
            time: prev_hdr.time + 1
          )

        {b, b.header}
      end)

    a_op = {hd(hd(branch_a).txs).txid, 0}
    b_op = {hd(hd(branch_b).txs).txid, 0}

    stop = :atomics.new(1, [])

    reader =
      Task.async(fn ->
        Stream.repeatedly(fn -> :atomics.get(stop, 1) end)
        |> Stream.take_while(&(&1 == 0))
        |> Enum.reduce(0, fn _, n ->
          {tip, coins} = State.mempool_view(cs_name, [base_op, a_op, b_op])
          assert match?({:ok, %{height: 1}}, coins[base_op])
          # Branch A and Branch B coinbases can never both exist simultaneously.
          refute match?({:ok, _}, coins[a_op]) and match?({:ok, _}, coins[b_op])
          assert tip.height >= 10
          n + 1
        end)
      end)

    for b <- branch_a, do: {:ok, :connected} = State.submit_block(cs_name, b)
    State.commit_now(cs_name)
    {:ok, _} = Headers.process_headers(hs, Enum.map(branch_b, & &1.header))

    for b <- branch_b do
      res = State.submit_block(cs_name, b, requested: true)
      assert match?({:ok, _}, res), "unexpected submit_block result: #{inspect(res)}"
    end

    assert State.tip(cs_name).height == 18
    State.commit_now(cs_name)

    :atomics.put(stop, 1, 1)
    reads = Task.await(reader, 10_000)
    assert reads > 0

    {tip, coins} = State.mempool_view(cs_name, [base_op, a_op, b_op])
    assert tip.height == 18
    assert coins[a_op] == :missing
    assert match?({:ok, %{height: 11}}, coins[b_op])
  end

  test "Mempool.sync_to/2 does not block other Mempool calls while waiting for tip", %{
    tmp_dir: dir
  } do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    cs_name = :"cs_syncto_#{System.unique_integer([:positive])}"
    mp_name = :"mp_syncto_#{System.unique_integer([:positive])}"

    {:ok, _cs} =
      State.start_link(
        name: cs_name,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        mempool: mp_name
      )

    {:ok, mp} =
      Mempool.start_link(
        name: mp_name,
        chain_state: cs_name,
        headers: hs,
        params: @p
      )

    {blocks, _} = build_chain(@p.genesis.header, 1..2)
    [b1, b2] = blocks

    waiter = Task.async(fn -> Mempool.sync_to(mp, b2.header.hash) end)

    # While waiter is blocked on sync_to(b2), other Mempool calls return immediately.
    {size_us, 0} = :timer.tc(fn -> Mempool.size(mp) end)
    assert size_us < 200_000

    {:ok, :connected} = State.submit_block(cs_name, b1)
    {:ok, :connected} = State.submit_block(cs_name, b2)

    assert :ok = Task.await(waiter, 5_000)
    assert :sys.get_state(mp).tip_hash == b2.header.hash
  end
end
