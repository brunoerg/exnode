defmodule Exnode.REST.UtxoLimitTest do
  @moduledoc """
  Regression: `/address/:addr/utxo`
  and `/scripthash/:sh/utxo` loaded the script's whole confirmed history
  into the request's process (a list of row maps, then a set of every
  spent outpoint): the heaviest mainnet scripts cost over a gigabyte per
  request, and 16 concurrent requests (the connection cap) could run the
  node out of memory. As electrs (`utxo_delta`, `--utxos-limit`), the rows
  are now streamed holding only the outputs unspent so far, and past the
  limit (500, `:utxos_limit` in the context) the answer is a 400.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Address, ChainParams, Mempool}
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Index.Scripthash
  alias Exnode.REST.Esplora
  alias Exnode.Store.KV
  alias Exnode.Test.{EsploraOracle, SpendChain}

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)

  defp start(dir) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    u = System.unique_integer([:positive])
    {cs, mp, idx} = {:"cs_#{u}", :"mp_#{u}", :"sh_#{u}"}

    {:ok, _} =
      State.start_link(
        name: cs,
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        mempool: mp
      )

    {bs, _} = SpendChain.build(@p.genesis.header, 130)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    State.commit_now(cs)

    {:ok, _} =
      Mempool.start_link(
        name: mp,
        chain_state: cs,
        headers: hs,
        params: @p,
        index_scripts: true
      )

    {:ok, _} = Scripthash.start_link(name: idx, kv: kv, chain_state: cs)
    :ok = Scripthash.sync_to(idx, List.last(bs).header.hash)

    %{
      kv: kv,
      ctx: %{chain_state: cs, headers: hs, mempool: mp, params: @p, scripthash_index: idx}
    }
  end

  defp req(mod, ctx, path) do
    conn = Plug.Test.conn(:get, path) |> mod.call(mod.init(%{ctx: ctx}))
    {conn.status, conn.resp_body}
  end

  # `fun` in a process killed if its heap passes `words`: whether it fits.
  defp within_heap(words, fun) do
    {pid, ref} =
      spawn_monitor(fn ->
        Process.flag(:max_heap_size, %{size: words, kill: true, error_logger: false})
        exit({:done, fun.()})
      end)

    receive do
      {:DOWN, ^ref, :process, ^pid, {:done, result}} -> {:ok, result}
      {:DOWN, ^ref, :process, ^pid, :killed} -> :killed
    after
      60_000 -> flunk("timed out")
    end
  end

  test "past the limit /utxo answers 400; within it, the same JSON as before", %{tmp_dir: dir} do
    n = start(dir)
    path = "/address/#{Address.from_script(SpendChain.spk(), :regtest)}/utxo"

    {200, body} = req(Esplora, n.ctx, path)
    assert body == elem(req(EsploraOracle, n.ctx, path), 1)
    count = length(Jason.decode!(body))
    assert count > 3

    assert {400, msg} = req(Esplora, Map.put(n.ctx, :utxos_limit, 3), path)
    assert msg == "Too many unspent transaction outputs (>3). Contact support to raise limits."

    # As electrs, the limit holds at every point of the scan, not only at
    # its end: this script had more unspent outputs before some were spent.
    assert {400, _} = req(Esplora, Map.put(n.ctx, :utxos_limit, count), path)
    assert {200, ^body} = req(Esplora, Map.put(n.ctx, :utxos_limit, 2 * count), path)
  end

  test "a long history with few unspent outputs is answered in bounded memory",
       %{tmp_dir: dir} do
    n = start(dir)
    spk = <<0, 32>> <> :crypto.hash(:sha256, "busy")
    sh = Scripthash.scripthash(spk)

    # 100,000 outputs to the script, each spent by the next tx, in the
    # (active) blocks 1..100: 200,000 rows, one output left unspent.
    pairs = 100_000

    for chunk <- Enum.chunk_every(0..(pairs - 1), 10_000) do
      ops =
        Enum.flat_map(chunk, fn i ->
          {h, pos} = {1 + div(i, 1_000), 2 * rem(i, 1_000) + 1}
          txid = :crypto.hash(:sha256, <<i::32>>)
          prev = :crypto.hash(:sha256, <<i - 1::32>>)

          fund =
            {:put, :scripthash, <<sh::binary, h::32, pos::32, 0, 0::32>>,
             <<txid::binary, 1_000::64>>}

          spend =
            {:put, :scripthash, <<sh::binary, h::32, pos::32, 1, 0::32>>,
             <<txid::binary, prev::binary, 0::32, 1_000::64>>}

          if i == 0, do: [fund], else: [spend, fund]
        end)

      :ok = KV.write(n.kv, ops)
    end

    path = "/scripthash/#{Base.encode16(sh, case: :lower)}/utxo"
    # 2 M words (16 MiB): the history alone is several times that.
    words = 2_000_000

    assert {:ok, {200, body}} = within_heap(words, fn -> req(Esplora, n.ctx, path) end)
    last = :crypto.hash(:sha256, <<pairs - 1::32>>)
    assert [%{"txid" => txid, "value" => 1_000}] = Jason.decode!(body)
    assert txid == Exnode.Crypto.Hash.to_hex(last)

    # Before: the router held the whole history and was killed.
    assert within_heap(words, fn -> req(EsploraOracle, n.ctx, path) end) == :killed
  end
end
