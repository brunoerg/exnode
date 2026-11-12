defmodule Exnode.Index.ScripthashReuseTest.Ref do
  @moduledoc """
  The scripthash rows as the index built them before read reuse, from the
  strict full readers (the block's transactions from `read_block_txs/2`,
  `Archive.block_scripts/2` for the spent scripts, then one
  `Archive.read_output/2` per spent output for its value): the reference the
  current generator (`Archive.read_index_facts/3`, `Archive.undo_outputs/2`)
  must reproduce exactly.
  """
  alias Exnode.Archive
  alias Exnode.Index.Scripthash

  def ops(height, id, reader, op) do
    {:ok, b} = Archive.read_block_txs(reader, id)
    {_outs, spent} = Archive.block_scripts(reader, id)

    values =
      for out_id <- Archive.block_record!(reader, id).undo,
          do: elem(Archive.read_output(reader, out_id), 0)

    info = Enum.zip(spent, values)

    {ops, []} =
      b.txs
      |> Enum.with_index()
      |> Enum.flat_map_reduce(info, fn {tx, pos}, rest ->
        funding =
          for {o, vout} <- Enum.with_index(tx.outputs),
              do:
                kv(
                  op,
                  <<Scripthash.scripthash(o.script_pubkey)::binary, height::32, pos::32, 0,
                    vout::32>>,
                  <<tx.txid::binary, o.value::64>>
                )

        if pos == 0 do
          {funding, rest}
        else
          {mine, rest} = Enum.split(rest, length(tx.inputs))

          spending =
            for {{i, {spk, value}}, vin} <- Enum.with_index(Enum.zip(tx.inputs, mine)),
                do:
                  kv(
                    op,
                    <<Scripthash.scripthash(spk)::binary, height::32, pos::32, 1, vin::32>>,
                    <<tx.txid::binary, i.prev_hash::binary, i.prev_index::32, value::64>>
                  )

          {funding ++ spending, rest}
        end
      end)

    ops
  end

  defp kv(:put, k, v), do: {:put, :scripthash, k, v}
  defp kv(:delete, k, _v), do: {:delete, :scripthash, k}

  @doc """
  The whole index column family the reference implies for the reader's
  active chain: its rows, block hashes and tip, and each script's totals
  recomputed from the rows (`<<"t", sh, k>>` -> integer, zeros omitted;
  txs counted by `{height, pos}`) with the `"totals"` mark.
  """
  def expected_cf(reader) do
    tip = Archive.tip(reader)

    rows =
      for h <- 0..tip.height//1,
          id = Archive.id_at(reader, h),
          rec = Archive.block_record!(reader, id),
          {:put, :scripthash, k, v} <-
            ops(h, id, reader, :put) ++ [{:put, :scripthash, <<"h", h::32>>, rec.hash}],
          do: {k, v}

    totals =
      rows
      |> Enum.filter(fn {k, _} -> byte_size(k) == 45 end)
      |> Enum.group_by(fn {k, _} -> binary_part(k, 0, 32) end)
      |> Enum.flat_map(fn {sh, rs} ->
        vals =
          for {<<_::binary-32, h::32, pos::32, kind, _::32>>, v} <- rs,
              do: {kind, :binary.decode_unsigned(binary_part(v, byte_size(v) - 8, 8)), {h, pos}}

        f = for {0, val, _} <- vals, do: val
        sp = for {1, val, _} <- vals, do: val
        txs = vals |> Enum.map(&elem(&1, 2)) |> Enum.uniq() |> length()

        for {n, k} <- Enum.with_index([length(f), Enum.sum(f), length(sp), Enum.sum(sp), txs]),
            n != 0,
            do: {<<"t", sh::binary, k>>, n}
      end)

    Map.new([{"tip", <<tip.height::32, tip.hash::binary>>}, {"totals", <<1>>} | rows] ++ totals)
  end
end

defmodule Exnode.Index.ScripthashReuseTest do
  @moduledoc """
  Read reuse in the scripthash index (`Archive.undo_outputs/2`, one block
  record read): every row, key and value, equals the reference generator's
  (`Ref`), for live, disconnected and overwritten block ids at the storage
  level, and as whole column families built by the real follower across a
  multi-block reorg and back (archived blocks reconnected), restart and
  catch-up, a clean rebuild, witness pruning, a cold datadir and segment
  rollover. The read counters show the spent outputs read once per group,
  and an undo list that does not match the inputs raises.
  """
  use ExUnit.Case, async: true
  import Exnode.Test.Wait

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Index.{Follower, Scripthash}
  alias Exnode.Index.ScripthashReuseTest.Ref
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Test.SpendChain

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @op_true <<0x51>>

  defp sorted(ops), do: Enum.sort(ops)

  # --- storage level ------------------------------------------------------

  test "storage fixtures: duplicate txids, same-block chains, repeated ids and scripts; disconnected ids too",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    a = Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis)
    cb = BB.coinbase(1, 50 * @coin)
    b1 = BB.build(@p.genesis.header, [cb])
    # BIP30-style duplicate coinbase (overwrites b1's output).
    b2 = BB.build(b1.header, [cb])
    a = Archive.connect(a, b1, 1, [])
    a = Archive.connect(a, b2, 2, [])
    base = Archive.next_ids(a).out
    # Funding-only block: three outputs, two with the same script.
    f = BB.coinbase_with(3, 50 * @coin, outputs: [{1, @op_true}, {2, <<0x52>>}, {3, @op_true}])
    b3 = BB.build(b2.header, [f])
    a = Archive.connect(a, b3, 3, [])
    # A same-block chain (t2 spends t1) and a tx whose two inputs the
    # storage fixture maps to the same spent id; spends outputs of b3.
    t1 = BB.tx([{f.txid, 0}, {f.txid, 1}], [{3, @op_true}])
    t2 = BB.tx([{t1.txid, 0}], [{3, <<0x52>>}])
    t3 = BB.tx([{f.txid, 2}, {f.txid, 2}], [{3, @op_true}])
    b4 = BB.build(b3.header, [BB.coinbase(4, 50 * @coin), t1, t2, t3])
    t1_out = base + 3 + 1
    a = Archive.connect(a, b4, 4, [base + 1, base + 2, t1_out, base + 3, base + 3])
    # Disconnect b4 and connect a fork block spending the same outputs
    # (the disconnected b4 keeps its archived id and record).
    {a, _} = Archive.disconnect_tip(a)
    b4f = BB.build(b3.header, [BB.coinbase(4, 49 * @coin), t1])
    a = Archive.connect(a, b4f, 4, [base + 1, base + 2])
    a = Archive.flush(a)
    r = Archive.reader(a)

    ids = for h <- 0..4, do: {h, Archive.id_at(r, h)}
    b4_id = Archive.block_id(r, b4.header.hash)

    for {h, id} <- [{4, b4_id} | ids], op <- [:put, :delete] do
      assert sorted(Scripthash.block_ops(h, id, r, op)) == sorted(Ref.ops(h, id, r, op)),
             "block #{id} at #{h} #{op}"
    end

    # Read work for the block with spends: the new path reads the spent
    # outputs once (and no funding outputs); the reference reads them twice.
    Archive.take_stats()
    Scripthash.block_ops(4, b4_id, r, :put)
    new = Archive.take_stats()
    Ref.ops(4, b4_id, r, :put)
    old = Archive.take_stats()
    assert new.preads < old.preads
    assert new.pread_bytes < old.pread_bytes
    assert new.output_groups >= 1

    # An undo list that does not match the inputs raises (both directions).
    rec = Archive.block_record!(r, b4_id)

    for bad <- [Enum.drop(rec.undo, 1), rec.undo ++ [base]] do
      :ok =
        KV.write(kv, [{:put, :blocks, <<b4_id::32>>, :erlang.term_to_binary(%{rec | undo: bad})}])

      assert_raise ArgumentError, fn ->
        Scripthash.block_ops(4, b4_id, Archive.reader(a), :put)
      end
    end

    Archive.close(a)
    KV.close(kv)
  end

  test "undo_outputs keeps the undo order, duplicates included, and equals point reads", %{
    tmp_dir: dir
  } do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    a = Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis, max: 300)
    # Many outputs over several segments and sparse groups.
    {a, prev, _} =
      Enum.reduce(1..6, {a, @p.genesis.header, 0}, fn h, {a, prev, _} ->
        cb =
          BB.coinbase_with(h, 50 * @coin,
            outputs: for(v <- 1..400, do: {v, <<0x51, h, rem(v, 7)>>})
          )

        b = BB.build(prev, [cb])
        {Archive.connect(a, b, h, []), b.header, 0}
      end)

    _ = prev
    a = Archive.flush(a)
    r = Archive.reader(a)
    n = Archive.next_ids(r).out
    undo = [n - 1, 5, 1500, 5, 0, 2399, 1024, 1023, n - 1, 777]
    want = for id <- undo, do: Archive.read_output(r, id)
    assert Archive.undo_outputs(r, %{undo: undo}) == want
    assert Archive.undo_outputs(r, %{undo: []}) == []
    Archive.close(a)
    KV.close(kv)
  end

  # --- follower level -----------------------------------------------------

  defp start(dir, opts) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    u = System.unique_integer([:positive])
    cs = :"sh_reuse_cs_#{u}"

    {:ok, _} =
      State.start_link(
        [name: cs, params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot")] ++ opts
      )

    %{kv: kv, hs: hs, cs: cs, idx: nil, u: u}
  end

  defp start_index(n) do
    name = :"sh_reuse_idx_#{n.u}_#{System.unique_integer([:positive])}"
    {:ok, _} = Scripthash.start_link(name: name, kv: n.kv, chain_state: n.cs)
    %{n | idx: name}
  end

  defp stop_index(%{idx: nil} = n), do: n

  defp stop_index(n) do
    GenServer.stop(n.idx)
    %{n | idx: nil}
  end

  defp stop(n) do
    stop_index(n)
    GenServer.stop(n.cs)
    GenServer.stop(n.hs)
    KV.close(n.kv)
  end

  # Submits `blocks`, waits until the tip is `tip` (default: the last
  # block; activation is asynchronous) and commits.
  defp submit(n, blocks, tip \\ nil) do
    for b <- blocks, do: assert({:ok, _} = State.submit_block(n.cs, b, requested: true))
    tip = tip || List.last(blocks).header.hash
    assert wait_until(fn -> State.tip(n.cs).hash == tip end, 30_000)
    State.commit_now(n.cs)
  end

  defp synced(n) do
    :ok = Scripthash.sync_to(n.idx, State.tip(n.cs).hash, 60_000)
    n
  end

  # The column family, totals decoded and zero totals left out (a script
  # whose txs were all disconnected keeps zeroed totals).
  defp cf(n) do
    KV.fold_prefix(n.kv, :scripthash, "", %{}, fn
      {<<"t", _::binary-32, _>> = k, v}, m ->
        case :erlang.binary_to_term(v) do
          0 -> m
          t -> Map.put(m, k, t)
        end

      {k, v}, m ->
        Map.put(m, k, v)
    end)
  end

  # Totals and their mark removed, as in an index built before them.
  defp drop_totals(n) do
    keys =
      KV.fold_prefix(n.kv, :scripthash, "t", [], fn {k, _}, acc ->
        if byte_size(k) == 34, do: [k | acc], else: acc
      end)

    :ok = KV.write(n.kv, for(k <- ["totals" | keys], do: {:delete, :scripthash, k}))
  end

  defp assert_matches_reference(n) do
    expected = Ref.expected_cf(State.reader(n.cs))
    actual = cf(n)
    assert map_size(actual) == map_size(expected)
    assert actual == expected
    actual
  end

  defp segwit_block(prev, height, txs) do
    cb = fn extra, wit ->
      BB.coinbase_with(height, 0, outputs: [{50 * @coin, SpendChain.spk()} | extra], witness: wit)
    end

    BB.build_segwit(prev, cb, txs)
  end

  # SpendChain 1..130, then 131 with a same-block chain (a parent and its
  # child) plus a repeated-script output, 132 spending the child.
  defp chain do
    {bs, cbs} = SpendChain.build(@p.genesis.header, 130)
    {t, 0, v, s} = Enum.at(cbs, 30)

    parent =
      SpendChain.spend([{t, 0, v, s}], [{v - 1000, SpendChain.spk()}, {500, SpendChain.spk()}])

    child =
      SpendChain.spend([{parent.txid, 0, v - 1000, SpendChain.spk()}], [
        {v - 3000, SpendChain.spk2()}
      ])

    b131 = segwit_block(List.last(bs).header, 131, [parent, child])

    grand =
      SpendChain.spend([{child.txid, 0, v - 3000, SpendChain.spk2()}], [
        {v - 5000, SpendChain.spk()}
      ])

    b132 = segwit_block(b131.header, 132, [grand])
    %{bs: bs ++ [b131, b132], cbs: cbs, parent: parent}
  end

  defp run_reorg_cycle(n, c) do
    main = c.bs
    b129 = Enum.at(main, 128)
    # A longer fork from 129 (3 main blocks disconnected); it holds the
    # same parent tx as main's 131 (the same txid on both branches).
    f130 = segwit_block(b129.header, 130, [])
    f131 = segwit_block(f130.header, 131, [c.parent])
    f132 = segwit_block(f131.header, 132, [])
    f133 = segwit_block(f132.header, 133, [])
    submit(n, [f130, f131, f132, f133])
    assert State.tip(n.cs).hash == f133.header.hash
    synced(n)
    assert_matches_reference(n)

    # Back to the main branch: its archived blocks 130..132 reconnect.
    m133 = segwit_block(List.last(main).header, 133, [])
    m134 = segwit_block(m133.header, 134, [])
    submit(n, [m133, m134])
    assert State.tip(n.cs).hash == m134.header.hash
    synced(n)
    assert_matches_reference(n)
  end

  for {label, opts} <- [
        plain: [],
        pruned_cold_rollover: [segment_max: 200, prune_witness: true, prune_keep: 5, cold: :cold]
      ] do
    test "follower rows equal the reference: #{label} (incremental, reorg and back, restart, rebuild)",
         %{tmp_dir: dir} do
      opts =
        for {k, v} <- unquote(opts),
            do: if(v == :cold, do: {k, Path.join(dir, "cold")}, else: {k, v})

      c = chain()
      {first, rest} = Enum.split(c.bs, 100)

      # Incremental: the index runs while blocks are connected.
      n = start(Path.join(dir, "inc"), opts) |> start_index()
      submit(n, first)
      synced(n)
      submit(n, rest)
      synced(n)
      inc = assert_matches_reference(n)

      # Spending blocks whose witnesses are pruned were indexed (the facts
      # reader reads no witnesses; the reference used the pruned fallback).
      if opts[:prune_witness] do
        State.with_archive(n.cs, fn a ->
          assert Archive.read_block(a, Archive.id_at(a, 115)) == {:error, :witness_pruned}
        end)
      end

      # Restart at an indexed prefix, then catch up after more blocks.
      n = stop_index(n)
      extra = segwit_block(List.last(c.bs).header, 133, [])
      submit(n, [extra])
      n = n |> start_index() |> synced()
      assert_matches_reference(n)
      n = stop_index(n)
      stop(n)

      # Reorg cycle on a fresh store with the index following.
      n = start(Path.join(dir, "reorg"), opts) |> start_index()
      submit(n, c.bs)
      synced(n)
      run_reorg_cycle(n, c)

      # An index from before the totals: one scan of the rows gives them.
      n = stop_index(n)
      drop_totals(n)
      assert KV.get(n.kv, :scripthash, "totals") == :not_found
      Scripthash.backfill_totals(n.kv)
      assert_matches_reference(n)
      stop(n)

      # Clean rebuild: the same blocks, the index started only afterwards.
      n = start(Path.join(dir, "rebuild"), opts)
      submit(n, c.bs)
      assert Follower.tip(n.kv, :scripthash) == {-1, nil}
      n = n |> start_index() |> synced()
      assert assert_matches_reference(n) == inc
      stop(n)
    end
  end
end
