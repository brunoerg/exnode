defmodule Exnode.REST.EsploraTest do
  @moduledoc """
  Esplora REST cost (fix-03 WS3) on a regtest chain with spends and a
  populated mempool: every response is byte-identical to the pre-fix router
  (`Exnode.Test.EsploraOracle`), while
  * `/tx/:txid` rebuilds no block (`Archive.read_block*` never called);
  * address endpoints make one mempool call (its script index) and no
    archive read for mempool prevouts; `/address` reads the index's
    per-script totals, not the script's history;
  * no endpoint copies the whole mempool (`Mempool.pool/1`), and
    `/outspends` reads no address history;
  * `/txs` and `/txs/chain/:last` pages are disjoint, ordered and complete,
    with the scripthash index process never called;
  * a `POST /tx` flood of bad-signature txs is rejected while reads answer.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Address, Archive, Mempool}
  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Tx
  alias Exnode.Index.Scripthash
  alias Exnode.REST.Esplora
  alias Exnode.Store.KV
  alias Exnode.Test.{EsploraOracle, SpendChain}

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000

  defp start(dir, mp_opts \\ []) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    u = System.unique_integer([:positive])
    {cs_name, mp_name, idx_name} = {:"cs_#{u}", :"mp_#{u}", :"sh_#{u}"}

    {:ok, _} =
      State.start_link(
        name: cs_name,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        mempool: mp_name
      )

    {bs, cbs} = SpendChain.build(@p.genesis.header, 130)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs_name, b)
    State.commit_now(cs_name)

    {:ok, _} =
      Mempool.start_link(
        [name: mp_name, chain_state: cs_name, headers: hs, params: @p, index_scripts: true] ++
          mp_opts
      )

    {:ok, idx} = Scripthash.start_link(name: idx_name, kv: kv, chain_state: cs_name)
    :ok = Scripthash.sync_to(idx_name, List.last(bs).header.hash)

    ctx = %{
      chain_state: cs_name,
      headers: hs,
      mempool: mp_name,
      params: @p,
      scripthash_index: idx_name
    }

    %{ctx: ctx, bs: bs, cbs: cbs, mp: mp_name, idx: idx}
  end

  # Unspent outputs of the chain (not coinbases, so no maturity): each
  # split's spk2 output, and each chained spend's spk output.
  defp free_coins(n) do
    for b <- Enum.slice(n.bs, 111..129), {tx, k} <- Enum.with_index(tl(b.txs)) do
      if k == 0,
        do: {tx.txid, 1, 25 * @coin - 1_000, SpendChain.spk2()},
        else: {tx.txid, 0, 25 * @coin - 1_000, SpendChain.spk()}
    end
  end

  # Mempool: m1 spends a chained spend's spk output (to spk and spk2), m2
  # spends m1:0 (a mempool prevout), m3 spends the 11-input tx's spk2 output.
  defp fill_mempool(n) do
    coin = Enum.find(free_coins(n), &(elem(&1, 3) == SpendChain.spk()))

    m1 =
      SpendChain.spend([coin], [
        {20 * @coin, SpendChain.spk()},
        {5 * @coin - 2_000, SpendChain.spk2()}
      ])

    m2 =
      SpendChain.spend([{m1.txid, 0, 20 * @coin, SpendChain.spk()}], [
        {20 * @coin - 1_000, SpendChain.spk()}
      ])

    many = many(n)

    m3 =
      SpendChain.spend([{many.txid, 1, 200 * @coin, SpendChain.spk2()}], [
        {200 * @coin - 1_000, SpendChain.spk()}
      ])

    for tx <- [m1, m2, m3], do: {:ok, _} = Mempool.accept(n.mp, tx)
    [m1, m2, m3]
  end

  defp many(n), do: Enum.at(Enum.at(n.bs, 110).txs, 1)

  defp req(mod, ctx, method, path, body \\ nil) do
    conn = Plug.Test.conn(method, path, body) |> mod.call(mod.init(%{ctx: ctx}))
    {conn.status, conn.resp_body}
  end

  defp same(ctx, path) do
    new = req(Esplora, ctx, :get, path)
    assert new == req(EsploraOracle, ctx, :get, path), "differs: #{path}"
    new
  end

  # Calls to `mfas` made by this process while `fun` runs (Plug.Test runs
  # the router here), counted per function.
  defp calls(mfas, fun) do
    {result, calls} = Exnode.Test.CallTrace.calls(mfas, fun)
    {result, Enum.frequencies_by(calls, fn {m, f, args} -> {m, f, length(args)} end)}
  end

  # The counter counts (so an empty count means no call).
  test "the call counter sees calls" do
    {_, counts} = calls([{Archive, :outputs, 2}], fn -> Archive.outputs(nil, []) end)
    assert counts == %{{Archive, :outputs, 2} => 1}
  end

  @rebuilds [{Archive, :read_block_txs, 2}, {Archive, :read_block, 2}]

  test "/tx/:txid: the same JSON, and no block is rebuilt", %{tmp_dir: dir} do
    n = start(dir)
    [_m1, m2, m3] = fill_mempool(n)
    chained = Enum.at(Enum.at(n.bs, 125).txs, 2)
    coinbase = hd(Enum.at(n.bs, 120).txs)

    for tx <- [many(n), chained, coinbase, m2, m3],
        suffix <- ["", "/status", "/hex", "/outspends"] do
      path = "/tx/#{Exnode.Crypto.Hash.to_hex(tx.txid)}#{suffix}"
      {{status, body}, counts} = calls(@rebuilds, fn -> req(Esplora, n.ctx, :get, path) end)
      assert status == 200
      assert counts == %{}, "#{path} rebuilt a block"
      assert {status, body} == req(EsploraOracle, n.ctx, :get, path)
    end

    # The 11-input tx: every prevout resolved (fee = inputs - outputs).
    {200, body} = req(Esplora, n.ctx, :get, "/tx/#{Exnode.Crypto.Hash.to_hex(many(n).txid)}")
    json = Jason.decode!(body)
    assert length(json["vin"]) == 11 and Enum.all?(json["vin"], & &1["prevout"])
    assert json["fee"] == 11_000
    assert same(n.ctx, "/tx/#{String.duplicate("ab", 32)}") |> elem(0) == 404
  end

  test "no endpoint copies the whole mempool", %{tmp_dir: dir} do
    n = start(dir)
    [m1, m2, _m3] = fill_mempool(n)
    hex = &Exnode.Crypto.Hash.to_hex/1
    addr = "/address/#{Address.from_script(SpendChain.spk(), :regtest)}"

    for path <- [
          "/mempool",
          "/tx/#{hex.(m1.txid)}",
          "/tx/#{hex.(m1.txid)}/outspends",
          "/tx/#{hex.(m2.txid)}/outspends",
          "/tx/#{hex.(many(n).txid)}/outspends",
          addr,
          addr <> "/utxo",
          addr <> "/txs",
          addr <> "/txs/chain/#{hex.(many(n).txid)}"
        ] do
      {{status, _}, counts} =
        calls([{Mempool, :pool, 1}], fn -> req(Esplora, n.ctx, :get, path) end)

      assert status == 200, path
      assert counts == %{}, "#{path} copied the mempool"
      assert {^status, _} = same(n.ctx, path)
    end

    # Confirmed spenders come from the archive's spend records, not from the
    # outputs' address histories (many(n) has outputs spent on the chain).
    for tx <- [m1, many(n), hd(Enum.at(n.bs, 5).txs)] do
      path = "/tx/#{hex.(tx.txid)}/outspends"
      {_, counts} = calls([{Scripthash, :history, 2}], fn -> req(Esplora, n.ctx, :get, path) end)
      assert counts == %{}, "#{path} read an address history"
    end
  end

  test "address endpoints with a mempool: same JSON, one script-index call, totals not history",
       %{tmp_dir: dir} do
    n = start(dir)
    _ = fill_mempool(n)
    unused = <<0, 32>> <> :crypto.hash(:sha256, "unused")

    for spk <- [SpendChain.spk(), SpendChain.spk2(), unused],
        base <- [
          "/address/#{Address.from_script(spk, :regtest)}",
          "/scripthash/#{Base.encode16(Scripthash.scripthash(spk), case: :lower)}"
        ],
        suffix <- ["", "/utxo", "/txs"] do
      assert {200, _} = same(n.ctx, base <> suffix)
    end

    addr = "/address/#{Address.from_script(SpendChain.spk(), :regtest)}"

    {{200, body}, counts} =
      calls(
        [
          {Mempool, :get_tx, 3},
          {Mempool, :get_tx, 2},
          {Mempool, :get_txs, 2},
          {Mempool, :pool, 1},
          {Mempool, :script_txs, 3},
          {Archive, :outputs, 2},
          {Scripthash, :history, 2},
          {Scripthash, :totals, 2}
        ],
        fn -> req(Esplora, n.ctx, :get, addr) end
      )

    # The mempool txs touching the script come from its script index, with
    # the outputs they spend: no archive read for them, no copy of the pool.
    # The confirmed stats are the index's totals: no history scan.
    assert counts == %{{Mempool, :script_txs, 3} => 1, {Scripthash, :totals, 2} => 1}
    stats = Jason.decode!(body)["mempool_stats"]
    # m1, m2 and m3 fund spk; m1 spends a confirmed spk output, m2 spends m1:0
    # (a mempool prevout).
    assert stats["funded_txo_count"] == 3 and stats["spent_txo_count"] == 2
    assert stats["spent_txo_sum"] == 25 * @coin - 1_000 + 20 * @coin
    assert stats["tx_count"] == 3
  end

  test "/txs pages: disjoint, newest first, complete; the index process is not called",
       %{tmp_dir: dir} do
    n = start(dir)
    _ = fill_mempool(n)
    sh = Scripthash.scripthash(SpendChain.spk())
    base = "/scripthash/#{Base.encode16(sh, case: :lower)}/txs"

    want =
      Scripthash.history(n.ctx.scripthash_index, sh)
      |> Enum.map(&{&1.height, &1.pos, &1.txid})
      |> Enum.uniq()
      |> Enum.sort(:desc)
      |> Enum.map(&Exnode.Crypto.Hash.to_hex(elem(&1, 2)))

    assert length(want) > 75
    # Pages never wait on the index process: it is suspended meanwhile (a
    # call into it, as before the fix, would block).
    :sys.suspend(n.idx)

    {200, first} = same(n.ctx, base)
    first = first |> Jason.decode!() |> Enum.filter(& &1["status"]["confirmed"])
    assert length(first) == 25

    pages =
      Stream.unfold(first, fn
        [] ->
          nil

        page ->
          # No call reached the index process. Its own :tick timer may land
          # while it is suspended (a slow page under load), which is not a call.
          {:messages, queued} = Process.info(n.idx, :messages)
          assert Enum.reject(queued, &(&1 == :tick)) == []
          {200, body} = same(n.ctx, "#{base}/chain/#{List.last(page)["txid"]}")
          {page, Jason.decode!(body)}
      end)
      |> Enum.to_list()

    got = pages |> List.flatten() |> Enum.map(& &1["txid"])
    assert got == want
    assert length(Enum.uniq(got)) == length(got)
    assert Enum.all?(Enum.drop(pages, 1) |> Enum.drop(-1), &(length(&1) == 25))

    # A tx outside the history: nothing after it; an unparsable one: the first page.
    assert {200, "[]"} =
             same(n.ctx, "#{base}/chain/#{Exnode.Crypto.Hash.to_hex(hd(fill_hashes()))}")

    assert {200, _} = same(n.ctx, "#{base}/chain/zz")
    :sys.resume(n.idx)
  end

  defp fill_hashes, do: [:crypto.hash(:sha256, "not in history")]

  test "POST /tx flood of bad-signature txs: all rejected, reads keep answering",
       %{tmp_dir: dir} do
    test = self()

    slow = fn raw, spent, flags ->
      send(test, :verifying)
      Process.sleep(100)
      Exnode.Kernel.verify_tx_all(raw, spent, flags)
    end

    n = start(dir, verify: slow)

    # Real, mature coins with a witness that does not match the script.
    bad =
      for {_, _, value, _} = coin <- Enum.take(free_coins(n), 30) do
        tx = SpendChain.spend([coin], [{value - 1_000, SpendChain.spk()}])

        %{tx | inputs: Enum.map(tx.inputs, &%{&1 | witness: [<<0x52>>]})}
        |> Tx.encode()
        |> IO.iodata_to_binary()
        |> Base.encode16(case: :lower)
      end

    flush_verifying()
    flood = for hex <- bad, do: Task.async(fn -> req(Esplora, n.ctx, :post, "/tx", hex) end)
    # The reads go in while the mempool is verifying the flood.
    assert_receive :verifying, 5_000

    for path <- ["/blocks/tip/hash", "/mempool"] do
      {us, {200, _}} = :timer.tc(fn -> req(Esplora, n.ctx, :get, path) end)
      assert us < 500_000, "#{path} took #{us} us during the flood"
    end

    for t <- flood do
      assert {400, msg} = Task.await(t, 30_000)
      assert msg =~ "mempool-script-verify-flag-failed"
    end

    assert Mempool.size(n.mp) == 0
  end

  # Any verification before the flood (setup) does not count.
  defp flush_verifying do
    receive do
      :verifying -> flush_verifying()
    after
      0 -> :ok
    end
  end

  # Regression: /utxo took each row's block from the active
  # chain at the row's height. Between a disconnect and the index's rewind
  # the index still holds the rows of the replaced blocks: they were
  # reported under the new blocks' hashes, or with a 500 when the height
  # was above the tip. Rows whose indexed block is not active are skipped.
  test "/utxo skips rows of blocks a reorg replaced before the index rewound", %{tmp_dir: dir} do
    n = start(dir)
    # The index stops following: its rows for 129 and 130 stay.
    GenServer.stop(n.idx)
    addr = "/address/#{Address.from_script(SpendChain.spk(), :regtest)}/utxo"
    {200, before} = req(Esplora, n.ctx, :get, addr)

    heights = fn body ->
      body |> Jason.decode!() |> Enum.map(& &1["status"]["block_height"]) |> MapSet.new()
    end

    assert MapSet.member?(heights.(before), 130)

    # A heavier branch from 128: 129 and 130 are replaced.
    b128 = Enum.at(n.bs, 127)

    {fork, _} =
      Enum.map_reduce(129..131, b128.header, fn h, prev ->
        b =
          Exnode.Test.BlockBuilder.build(prev, [
            Exnode.Test.BlockBuilder.coinbase(h, 25 * @coin, <<0x52>>)
          ])

        {b, b.header}
      end)

    {:ok, _} = Headers.process_headers(n.ctx.headers, Enum.map(fork, & &1.header))
    for b <- fork, do: {:ok, _} = State.submit_block(n.ctx.chain_state, b, requested: true)
    State.commit_now(n.ctx.chain_state)
    assert State.tip(n.ctx.chain_state).hash == List.last(fork).header.hash

    {200, after_reorg} = req(Esplora, n.ctx, :get, addr)
    fork_hashes = MapSet.new(fork, &Exnode.Crypto.Hash.to_hex(&1.header.hash))

    for u <- Jason.decode!(after_reorg),
        do:
          refute(
            MapSet.member?(fork_hashes, u["status"]["block_hash"]),
            "a replaced block's row under #{u["status"]["block_hash"]}"
          )

    refute MapSet.member?(heights.(after_reorg), 129) or
             MapSet.member?(heights.(after_reorg), 130)
  end

  # Regression: Scripthash.sync_to waited for the indexed
  # tip to equal the hash, so a caller asking for a block the index had
  # already passed waited until its timeout.
  test "Scripthash.sync_to returns at once for a block below the indexed tip", %{tmp_dir: dir} do
    n = start(dir)
    assert Scripthash.sync_to(n.ctx.scripthash_index, Enum.at(n.bs, 99).header.hash, 1_000) == :ok
    assert Scripthash.sync_to(n.ctx.scripthash_index, List.last(n.bs).header.hash, 1_000) == :ok
  end
end
