defmodule Exnode.REST.DisabledIndexTest do
  @moduledoc """
  Regression: with address indexing disabled the node passed
  `scripthash_index: false` to the Esplora routes; `/tx/:txid/outspends`
  treated `false` as an index and answered 500 for every tx with an output
  not spent in the mempool. Confirmed spenders now come from the archive,
  so they are reported with the index disabled too.
  """
  use ExUnit.Case, async: true

  alias Exnode.{ChainParams, Mempool}
  alias Exnode.Chain.{Headers, State}
  alias Exnode.REST.Esplora
  alias Exnode.Store.KV
  alias Exnode.Test.SpendChain

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)

  test "/tx/:txid/outspends with address indexing disabled: 200, confirmed spenders reported",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    u = System.unique_integer([:positive])
    {cs, mp} = {:"svc1_cs_#{u}", :"svc1_mp_#{u}"}

    start_supervised!({Exnode.Store.KVOwner, {kv, [{State, cs}]}}, id: :"kvo_#{u}")
    hs = start_supervised!({Headers, params: @p, kv: kv}, id: :"hs_#{u}")

    start_supervised!(
      {State, name: cs, params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), mempool: mp},
      id: cs
    )

    {bs, _} = SpendChain.build(@p.genesis.header, 111)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    State.commit_now(cs)
    start_supervised!({Mempool, name: mp, chain_state: cs, headers: hs, params: @p}, id: mp)

    hex = &Exnode.Crypto.Hash.to_hex/1
    # A coinbase output never spent, and an output block 111's tx spends.
    unspent = hd(List.last(bs).txs)
    spender = Enum.at(Enum.at(bs, 110).txs, 1)
    spent = hd(spender.inputs)

    for disabled <- [false, nil] do
      ctx = %{chain_state: cs, headers: hs, mempool: mp, params: @p, scripthash_index: disabled}
      get = fn path -> Plug.Test.conn(:get, path) |> Esplora.call(Esplora.init(%{ctx: ctx})) end

      conn = get.("/tx/#{hex.(unspent.txid)}/outspends")
      assert conn.status == 200, "scripthash_index: #{inspect(disabled)} -> #{conn.status}"
      assert [%{"spent" => false} | _] = Jason.decode!(conn.resp_body)

      conn = get.("/tx/#{hex.(spent.prev_hash)}/outspends")
      assert conn.status == 200

      assert %{
               "spent" => true,
               "txid" => txid,
               "vin" => 0,
               "status" => %{"confirmed" => true, "block_height" => 111}
             } =
               Enum.at(Jason.decode!(conn.resp_body), spent.prev_index)

      assert txid == hex.(spender.txid)
    end
  end
end
