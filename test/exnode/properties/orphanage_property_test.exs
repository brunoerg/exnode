defmodule Exnode.Properties.OrphanagePropertyTest do
  @moduledoc """
  Stateful property for TxRelay's orphanage (Core `txorphan` /
  `txorphanage_sim` fuzz targets): random sequences of orphans received,
  floods, invs (single and fan-out), parents accepted, blocks confirming or
  conflicting, and peers connecting and disconnecting. After every step:

  * the incremental accounting (age order, per-peer weight, latency score
    and announcements, total score) equals a recount from the orphans
    (AUD-H1);
  * the limits hold: at most 1,000 orphans, each peer's weight at most
    404,000 WU, the total latency score at most 3,000;
  * the parent index matches the orphans;
  * every orphan has an announcer, and every announcer is a registered peer
    (a disconnected peer owns nothing);
  * right after a block, no orphan spends an outpoint it spent (Core
    EraseForBlock). Later the same tx may be stored again: the orphanage
    does not consult the UTXO set, in Core either.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exnode.Codec.Tx
  alias Exnode.P2P.TxRelay

  # Accepts every parent; a child (orphan) is accepted on reconsideration
  # when its wtxid hashes into the accepted third, else its inputs are
  # still missing. Everything else answers "not had".
  defmodule StubMempool do
    use GenServer
    def start_link(parents), do: GenServer.start_link(__MODULE__, parents)
    def init(parents), do: {:ok, %{parents: parents}}

    def handle_call({:has, _h, _k}, _f, st), do: {:reply, false, st}
    def handle_call({:has_many, _hs, _k}, _f, st), do: {:reply, MapSet.new(), st}
    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}
    def handle_call({:submit_package, _}, _f, st), do: {:reply, %{state: :error, txs: %{}}, st}
    def handle_call({:get_txs, items}, _f, st), do: {:reply, {[], items}, st}

    def handle_call({:accept, tx, _}, _f, st) do
      cond do
        MapSet.member?(st.parents, tx.wtxid) -> {:reply, {:ok, %{}}, st}
        :erlang.phash2(tx.wtxid, 3) == 0 -> {:reply, {:ok, %{}}, st}
        true -> {:reply, {:error, %{result: :missing_inputs}}, st}
      end
    end

    def handle_cast(_, st), do: {:noreply, st}
  end

  @n_parents 40

  defp mk_tx(inputs, out_spk, tag) do
    {:ok, tx} =
      %Tx{
        version: 2,
        locktime: tag,
        inputs:
          for(
            {h, i} <- inputs,
            do: %Tx.In{prev_hash: h, prev_index: i, script_sig: <<>>, sequence: 0xFFFFFFFF}
          ),
        outputs: [%Tx.Out{value: 10_000, script_pubkey: out_spk}]
      }
      |> Tx.encode()
      |> IO.iodata_to_binary()
      |> Tx.decode_exact()

    tx
  end

  # Parents: txs whose own inputs exist nowhere, accepted by the stub.
  defp parent(j), do: mk_tx([{:crypto.hash(:sha256, <<"root", j::32>>), 0}], <<0x51>>, j)

  # Orphan i spends 1..3 parent outputs. Every 20th also spends 20..29
  # non-existent outpoints (a latency score of 3), and every 100th is large
  # (~40 kWU). Mostly small orphans keep each limit reachable: the count cap
  # by storms from a few peers, each peer's weight cap by its floods, the
  # total score by fan-outs (small orphans carry the most score per WU).
  defp orphan(i, parents) do
    ps =
      for k <- 0..rem(i, 3),
          do: {Enum.at(parents, rem(i * 7 + k * 13, @n_parents)).txid, rem(i + k, 4)}

    n_ghosts = if rem(i, 20) == 0, do: 20 + rem(i, 10), else: 0
    ghosts = for k <- 1..n_ghosts//1, do: {:crypto.hash(:sha256, <<"ghost", i::32, k::32>>), 0}
    spk = if rem(i, 100) == 0, do: :binary.copy(<<0x51>>, 10_000), else: <<0x51>>
    mk_tx(ps ++ ghosts, spk, 1_000_000 + i)
  end

  defp op do
    frequency([
      {2, constant(:connect)},
      {6, tuple({constant(:orphan), integer(0..20), integer(0..5_000)})},
      {3, tuple({constant(:flood), integer(0..20), integer(0..5_000), integer(100..1_200)})},
      {4, tuple({constant(:inv), integer(0..20), list_of(integer(0..5_000), max_length: 20)})},
      {5, tuple({constant(:inv_all), integer(0..20)})},
      {2, tuple({constant(:parent), integer(0..20), integer(0..(@n_parents - 1))})},
      {2,
       tuple(
         {constant(:block), list_of(integer(0..(@n_parents - 1)), max_length: 3), integer(0..5)}
       )},
      {2, tuple({constant(:disconnect), integer(0..20)})},
      # Pressure: several peers flood 400 fresh orphans each (count cap), or
      # each announce every orphan (score cap).
      {1, tuple({constant(:storm), integer(0..5_000), integer(3..8)})},
      {1, tuple({constant(:fanout), integer(4..12)})}
    ])
  end

  defp new_peer(r) do
    pid = spawn(fn -> Process.sleep(:infinity) end)

    TxRelay.connected(r, pid, %{
      wtxid_relay: true,
      preferred: false,
      relay_txs: true,
      inbound: true
    })

    pid
  end

  defp at(list, i), do: Enum.at(list, rem(i, length(list)))

  defp step(:connect, ctx), do: %{ctx | peers: ctx.peers ++ [new_peer(ctx.r)]}

  defp step({:orphan, p, i}, ctx) do
    :ok = TxRelay.received_tx(ctx.r, at(ctx.peers, p), orphan(i, ctx.parents))
    ctx
  end

  defp step({:flood, p, base, n}, ctx) do
    peer = at(ctx.peers, p)

    for i <- base..(base + n - 1),
        do: :ok = TxRelay.received_tx(ctx.r, peer, orphan(i, ctx.parents))

    ctx
  end

  defp step({:inv, p, is}, ctx) do
    items = for i <- is, do: %{type: :wtx, hash: orphan(i, ctx.parents).wtxid}
    :ok = TxRelay.inv(ctx.r, at(ctx.peers, p), items)
    ctx
  end

  defp step({:inv_all, p}, ctx) do
    items = for w <- TxRelay.orphans(ctx.r), do: %{type: :wtx, hash: w}
    :ok = TxRelay.inv(ctx.r, at(ctx.peers, p), items)
    ctx
  end

  defp step({:storm, base, k}, ctx) do
    for {peer, n} <- Enum.with_index(Enum.take(ctx.peers, k)),
        i <- (base + n * 400)..(base + n * 400 + 399),
        do: :ok = TxRelay.received_tx(ctx.r, peer, orphan(i, ctx.parents))

    ctx
  end

  defp step({:fanout, k}, ctx) do
    items = for w <- TxRelay.orphans(ctx.r), do: %{type: :wtx, hash: w}
    for peer <- Enum.take(ctx.peers, k), do: :ok = TxRelay.inv(ctx.r, peer, items)
    ctx
  end

  defp step({:parent, p, j}, ctx) do
    :ok = TxRelay.received_tx(ctx.r, at(ctx.peers, p), Enum.at(ctx.parents, j))
    ctx
  end

  # A block confirming parents `js` and spending an outpoint of `k` current
  # orphans (conflicts). Its spent outpoints are checked at this step only.
  defp step({:block, js, k}, ctx) do
    st = :sys.get_state(ctx.r)
    victims = st.orphans |> Map.values() |> Enum.sort_by(& &1.seq) |> Enum.take(k)
    spent = for o <- victims, do: (i = hd(o.tx.inputs)) && {i.prev_hash, i.prev_index}

    confirmed = for j <- js, do: Enum.at(ctx.parents, j)

    conflict = %{
      txid: :crypto.strong_rand_bytes(32),
      wtxid: :crypto.strong_rand_bytes(32),
      prevouts: spent
    }

    txs =
      [
        conflict
        | for(
            t <- confirmed,
            do: %{
              txid: t.txid,
              wtxid: t.wtxid,
              prevouts: Enum.map(t.inputs, &{&1.prev_hash, &1.prev_index})
            }
          )
      ]

    send(ctx.r, {:mempool_block, :connected, txs, :crypto.strong_rand_bytes(32)})
    _ = TxRelay.orphans(ctx.r)
    %{ctx | spent: MapSet.new(spent), conflicted: Enum.map(victims, & &1.tx.wtxid)}
  end

  defp step({:disconnect, p}, ctx) do
    case ctx.peers do
      [_] ->
        ctx

      peers ->
        peer = at(peers, p)
        Process.exit(peer, :kill)
        wait_unregistered(ctx.r, peer)
        %{ctx | peers: List.delete(peers, peer), gone: [peer | ctx.gone]}
    end
  end

  defp wait_unregistered(r, peer) do
    if Map.has_key?(:sys.get_state(r).peers, peer) do
      Process.sleep(1)
      wait_unregistered(r, peer)
    end
  end

  # --- invariants ---------------------------------------------------------------

  defp check_invariants(ctx, label) do
    st = :sys.get_state(ctx.r)
    input_score = fn o -> div(length(o.tx.inputs), 10) end

    recount =
      for {w, o} <- st.orphans, p <- o.announcers, reduce: %{} do
        acc ->
          Map.update(
            acc,
            p,
            %{weight: o.weight, score: 1 + input_score.(o), anns: [{o.seq, w}]},
            &%{
              &1
              | weight: &1.weight + o.weight,
                score: &1.score + 1 + input_score.(o),
                anns: [{o.seq, w} | &1.anns]
            }
          )
      end

    got =
      Map.new(st.orphan_peers, fn {p, i} ->
        {p, %{i | anns: Enum.sort(:gb_sets.to_list(i.anns))}}
      end)

    want = Map.new(recount, fn {p, i} -> {p, %{i | anns: Enum.sort(i.anns)}} end)
    assert got == want, "#{label}: per-peer accounting differs from a recount"

    score = Enum.sum(for {_, o} <- st.orphans, do: MapSet.size(o.announcers) + input_score.(o))

    assert st.orphan_score == score,
           "#{label}: total score #{st.orphan_score} vs recount #{score}"

    assert Enum.sort(:gb_sets.to_list(st.orphan_order)) ==
             Enum.sort(for {w, o} <- st.orphans, do: {o.seq, w}),
           "#{label}: age order differs from the orphans"

    by_parent =
      for {w, o} <- st.orphans,
          h <- Enum.uniq(Enum.map(o.tx.inputs, & &1.prev_hash)),
          reduce: %{} do
        acc -> Map.update(acc, h, MapSet.new([w]), &MapSet.put(&1, w))
      end

    assert st.orphan_by_parent == by_parent, "#{label}: parent index differs from the orphans"

    assert map_size(st.orphans) <= 1_000, "#{label}: #{map_size(st.orphans)} orphans"
    assert st.orphan_score <= 3_000, "#{label}: score #{st.orphan_score}"

    for {p, i} <- st.orphan_peers,
        do: assert(i.weight <= 404_000, "#{label}: peer #{inspect(p)} weight #{i.weight}")

    for {w, o} <- st.orphans do
      assert MapSet.size(o.announcers) > 0, "#{label}: orphan without announcer"

      assert Enum.all?(o.announcers, &Map.has_key?(st.peers, &1)),
             "#{label}: orphan #{Base.encode16(w)} announced by an unregistered peer"

      refute Enum.any?(o.tx.inputs, &MapSet.member?(ctx.spent, {&1.prev_hash, &1.prev_index})),
             "#{label}: orphan spends an outpoint a block spent"
    end

    refute Enum.any?(ctx.conflicted, &Map.has_key?(st.orphans, &1)),
           "#{label}: an orphan conflicting with the block is still stored"

    peak(:orphans, map_size(st.orphans))
    peak(:score, st.orphan_score)

    peak(
      :peer_weight,
      st.orphan_peers |> Map.values() |> Enum.map(& &1.weight) |> Enum.max(fn -> 0 end)
    )

    peak(
      :announcers,
      st.orphans |> Map.values() |> Enum.map(&MapSet.size(&1.announcers)) |> Enum.max(fn -> 0 end)
    )

    peak(:conflicted, length(ctx.conflicted))
    peak(:gone, length(ctx.gone))

    for p <- ctx.gone,
        do:
          refute(
            Map.has_key?(st.orphan_peers, p),
            "#{label}: a disconnected peer still owns orphans"
          )
  end

  defp peak(k, v), do: Process.put({:peak, k}, max(v, Process.get({:peak, k}, 0)))

  property "the orphanage's accounting, limits and indexes hold through random peer traffic" do
    check all(ops <- list_of(op(), min_length: 5, max_length: 60), max_runs: 40) do
      parents = for j <- 0..(@n_parents - 1), do: parent(j)
      {:ok, mp} = StubMempool.start_link(MapSet.new(parents, & &1.wtxid))
      {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)

      ctx = %{
        r: r,
        parents: parents,
        peers: for(_ <- 1..12, do: new_peer(r)),
        gone: [],
        spent: MapSet.new(),
        conflicted: []
      }

      try do
        ops
        |> Enum.with_index()
        |> Enum.reduce(ctx, fn {op, i}, ctx ->
          ctx = step(op, %{ctx | spent: MapSet.new(), conflicted: []})
          check_invariants(ctx, "op #{i} #{inspect(op, limit: 5)}")
          ctx
        end)
      after
        GenServer.stop(r)
        GenServer.stop(mp)
      end
    end

    peaks =
      for k <- ~w(orphans score peer_weight announcers conflicted gone)a,
          into: %{},
          do: {k, Process.get({:peak, k}, 0)}

    IO.puts("orphanage property peaks: #{inspect(peaks)}")

    # The runs reached every limit, so the trims were exercised, not only
    # the bookkeeping.
    assert peaks.orphans == 1_000
    assert peaks.score > 2_900
    assert peaks.peer_weight > 360_000
    assert peaks.conflicted > 0 and peaks.gone > 0
  end
end
