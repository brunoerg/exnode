defmodule Exnode.REST.RequestBoundsTest do
  @moduledoc """
  The unauthenticated Esplora server bounds what one request can make the
  node do: request bodies and address paths are checked before they are
  parsed, history scans and mempool copies stop at a limit (a 400, as
  electrs), `/mempool` does not pass over the pool on every request, and
  block reconstructions wait for a node-wide budget.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Address, ChainParams, Mempool}
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Crypto.Hash
  alias Exnode.Index.Scripthash
  alias Exnode.P2P.DecodeBudget
  alias Exnode.REST.Esplora
  alias Exnode.Store.KV
  alias Exnode.Test.{EsploraOracle, SpendChain}

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000

  defp start(dir) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    u = System.unique_integer([:positive])
    {cs, mp, idx} = {:"cs_#{u}", :"mp_#{u}", :"sh_#{u}"}

    start_supervised!(
      {Exnode.Node.Runtime, kv: kv, cleanup_keys: [{State, cs}, {Scripthash, idx}]},
      id: :"rt_#{u}"
    )

    hs = start_supervised!({Headers, params: @p, kv: kv}, id: :"hs_#{u}")

    start_supervised!(
      {State, name: cs, params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), mempool: mp},
      id: cs
    )

    {bs, _} = SpendChain.build(@p.genesis.header, 130)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    State.commit_now(cs)

    start_supervised!(
      {Mempool, name: mp, chain_state: cs, headers: hs, params: @p, index_scripts: true},
      id: mp
    )

    start_supervised!({Scripthash, name: idx, kv: kv, chain_state: cs}, id: idx)
    :ok = Scripthash.sync_to(idx, List.last(bs).header.hash)

    %{
      bs: bs,
      mp: mp,
      idx: idx,
      ctx: %{chain_state: cs, headers: hs, mempool: mp, params: @p, scripthash_index: idx}
    }
  end

  # The chained spends' spk outputs (not coinbases, so no maturity).
  defp free_coins(n) do
    for b <- Enum.slice(n.bs, 112..129), {tx, k} <- Enum.with_index(tl(b.txs)), k > 0 do
      {tx.txid, 0, 25 * @coin - 1_000, SpendChain.spk()}
    end
  end

  defp accept_spends(n, coins) do
    for {_, _, value, _} = coin <- coins do
      tx = SpendChain.spend([coin], [{value - 1_000, SpendChain.spk()}])
      {:ok, _} = Mempool.accept(n.mp, tx)
      tx
    end
  end

  defp req(mod, ctx, method, path, body \\ nil) do
    conn = Plug.Test.conn(method, path, body) |> mod.call(mod.init(%{ctx: ctx}))
    {conn.status, conn.resp_body}
  end

  defp addr, do: "/address/#{Address.from_script(SpendChain.spk(), :regtest)}"

  # Regression: `POST /tx` read the body with `{:ok, body, conn} =
  # read_body(conn)`: a body over Plug's 8 MB default came back as
  # `{:more, ...}` and the request crashed with a MatchError (a 500 and an
  # error report each), after reading 8 MB into the process. The body is
  # now read up to the hex of a standard-size tx; past it, a 413.
  test "POST /tx: a body over the limit is a 413, not a crash", %{tmp_dir: dir} do
    n = start(dir)

    for size <- [9_000_000, 1_000_000] do
      assert req(Esplora, n.ctx, :post, "/tx", String.duplicate("a", size)) ==
               {413, "Request body too large"}
    end

    assert req(Esplora, n.ctx, :post, "/tx", "zz") == {400, "Invalid transaction hex"}
  end

  # Regression: an address path that was not valid UTF-8 raised
  # (`String.to_charlist/1` in the base58 decoder: a 500), and base58 input
  # of any length was decoded into one integer, quadratic in its length.
  # As Core's `DecodeBase58Check` with its maximum payload, overlong input
  # is now rejected before decoding, and invalid UTF-8 is a 400.
  test "address paths: invalid UTF-8 and overlong input are a 400", %{tmp_dir: dir} do
    n = start(dir)

    for path <- ["/address/%FF%FE", "/address/bcrt1%FF", "/address/1%C3", "/address/%FF/utxo"] do
      assert req(Esplora, n.ctx, :get, path) == {400, "Invalid Bitcoin address"}, path
    end

    long = String.duplicate("z", 300_000)
    {us, result} = :timer.tc(fn -> Address.base58check_decode(long) end)
    assert result == {:error, :invalid}
    assert us < 100_000, "took #{us} us"
    assert Address.to_script(long, :regtest) == {:error, :invalid}

    # Within the bounds addresses decode as before.
    assert {200, _} = req(Esplora, n.ctx, :get, addr())
    pkh = Address.base58check(<<0x6F>> <> :binary.copy(<<7>>, 20))
    assert {:ok, <<0x76, 0xA9, 20, _::binary>>} = Address.to_script(pkh, :regtest)
  end

  # Regression: `/utxo` stopped only past 500 *unspent* outputs, so a
  # script whose outputs are swept as they come (few unspent, millions of
  # history rows) had its whole history scanned on every request. The scan
  # now stops past a row budget (`:utxos_scan_limit`), answering electrs'
  # "Too many history entries".
  test "/utxo: past the scan limit of history rows, a 400", %{tmp_dir: dir} do
    n = start(dir)
    sh = Scripthash.scripthash(SpendChain.spk())
    rows = Scripthash.fold_history(n.idx, sh, 0, fn _, k -> k + 1 end)
    assert rows > 10

    assert Scripthash.utxos(n.idx, sh, 10_000, 10) == {:error, :too_many_rows}
    assert {:ok, _} = Scripthash.utxos(n.idx, sh, 10_000, rows)

    path = addr() <> "/utxo"
    small = Map.put(n.ctx, :utxos_scan_limit, 10)
    assert req(Esplora, small, :get, path) == {400, "Too many history entries"}

    {200, body} = req(Esplora, Map.put(n.ctx, :utxos_scan_limit, rows), :get, path)
    assert {200, body} == req(EsploraOracle, n.ctx, :get, path)
  end

  # Regression: the address endpoints asked the mempool for every tx
  # touching the script: the single mempool process sorted and copied them
  # all into each request (thousands for a shared script such as an
  # anchor) before `/txs` kept 50. The request now passes a limit, and past
  # it the mempool copies nothing and the answer is a 400.
  test "address endpoints: past the mempool tx limit, a 400 and no copy", %{tmp_dir: dir} do
    n = start(dir)
    _ = accept_spends(n, Enum.take(free_coins(n), 3))
    sh = Scripthash.scripthash(SpendChain.spk())

    assert Mempool.script_txs(n.mp, sh, 2) == {:error, :too_many}
    assert length(Mempool.script_txs(n.mp, sh, 3)) == 3

    for suffix <- ["", "/utxo", "/txs"] do
      path = addr() <> suffix

      assert req(Esplora, Map.put(n.ctx, :mempool_txs_limit, 2), :get, path) ==
               {400, "Too many history entries"},
             path

      {200, body} = req(Esplora, Map.put(n.ctx, :mempool_txs_limit, 3), :get, path)
      assert {200, body} == req(EsploraOracle, n.ctx, :get, path), path
    end
  end

  # Regression: every `GET /mempool` built a `{fee, vsize}` pair for each
  # mempool tx inside the mempool process and copied the list out. Its
  # count and vsize are now read directly, and the fee figures, as
  # electrs' backlog stats, are computed at most once per 10 s.
  test "/mempool: the same JSON, fee figures cached, count current", %{tmp_dir: dir} do
    n = start(dir)
    [c1, c2, c3] = Enum.take(free_coins(n), 3)
    _ = accept_spends(n, [c1, c2])

    {200, body} = req(Esplora, n.ctx, :get, "/mempool")
    assert {200, body} == req(EsploraOracle, n.ctx, :get, "/mempool")
    first = Jason.decode!(body)
    assert first["count"] == 2

    _ = accept_spends(n, [c3])
    {200, body} = req(Esplora, n.ctx, :get, "/mempool")
    second = Jason.decode!(body)
    assert second["count"] == 3 and second["vsize"] > first["vsize"]
    # Served from the cache: no pass over the pool for it.
    assert second["total_fee"] == first["total_fee"]
    assert second["fee_histogram"] == first["fee_histogram"]
  end

  # Regression: every `/block/:hash`, `/raw`, `/txids` and
  # `/tx/:txid/merkle-proof` rebuilt and decoded its block from the archive
  # (several times its 4 MB on the heap) with nothing bounding how many ran
  # at once: 16 connections asking for large blocks held over a gigabyte.
  # They now take a node-wide budget (`:block_budget`) first; `/txids` and
  # the merkle proof read only the base records.
  test "block endpoints wait for the block budget", %{tmp_dir: dir} do
    n = start(dir)
    budget = :"rest_budget_#{System.unique_integer([:positive])}"
    {:ok, _} = DecodeBudget.start_link(name: budget, bytes: Esplora.block_budget_bytes())
    ctx = Map.put(n.ctx, :block_budget, budget)
    b = Enum.at(n.bs, 110)
    hash = Hash.to_hex(b.header.hash)
    tx = Hash.to_hex(Enum.at(b.txs, 1).txid)

    paths = [
      "/block/#{hash}",
      "/block/#{hash}/raw",
      "/block/#{hash}/txids",
      "/tx/#{tx}/merkle-proof"
    ]

    for path <- paths, do: assert({200, _} = same(ctx, path))

    # Another holder has the whole budget: the requests wait for it.
    me = self()

    holder =
      spawn(fn ->
        DecodeBudget.with_budget(budget, 2 * Esplora.block_budget_bytes(), fn ->
          send(me, :holding)
          receive do: (:release -> :ok)
        end)
      end)

    assert_receive :holding
    tasks = for path <- paths, do: Task.async(fn -> req(Esplora, ctx, :get, path) end)
    assert Enum.all?(Task.yield_many(tasks, 300), fn {_, r} -> r == nil end)
    assert DecodeBudget.info(budget).waiting == length(paths)

    send(holder, :release)

    for {t, path} <- Enum.zip(tasks, paths),
        do: assert(Task.await(t, 10_000) == req(EsploraOracle, n.ctx, :get, path))
  end

  defp same(ctx, path) do
    new = req(Esplora, ctx, :get, path)
    assert new == req(EsploraOracle, ctx, :get, path), "differs: #{path}"
    new
  end
end
