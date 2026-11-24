defmodule Exnode.RPC.MethodsTest do
  @moduledoc """
  Coverage for RPC methods and Esplora REST service resilience:
  * `getrawtransaction`: witness-pruned blocks return a clean `-1` error
    instead of crashing; 3rd `blockhash` parameter validates block membership;
    single-tx read never reconstructs the full block (`Archive.read_block`
    not called);
  * `getblock`: verbosity `0` and `1` skip `Archive.spent_outputs`;
  * `sendrawtransaction`: enforces `maxfeerate` and `maxburnamount`;
  * `submitpackage`: accepts a 1p1c CPFP package and reports `package_msg`
    and `tx-results`;
  * `getrawmempool`: `mempool_sequence` option (`{txids, mempool_sequence}`
    when `verbose == false`, `-8` when `verbose == true`);
  * `getblockfilter`: rejects unknown `filtertype` with `-8`;
  * `REST.Esplora`: returns `503` instead of crashing when a node service
    is restarting/unavailable.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Archive, ChainParams, Mempool}
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.{Block, Tx}
  alias Exnode.Crypto.Hash
  alias Exnode.Index.BlockFilter
  alias Exnode.REST.Esplora
  alias Exnode.RPC.Methods
  alias Exnode.Store.{KV, KVOwner}
  alias Exnode.Test.{BlockBuilder, CallTrace, SpendChain}

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  defp start_env(dir, cs_opts \\ []) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    u = System.unique_integer([:positive])
    {cs, mp, bf} = {:"rpc_cs_#{u}", :"rpc_mp_#{u}", :"rpc_bf_#{u}"}

    start_supervised!({KVOwner, {kv, [{State, cs}, {BlockFilter, bf}]}}, id: :"kvo_#{u}")
    hs = start_supervised!({Headers, params: @p, kv: kv}, id: :"hs_#{u}")

    start_supervised!(
      {State,
       [name: cs, params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), mempool: mp] ++
         cs_opts},
      id: cs
    )

    {bs, _} = SpendChain.build(@p.genesis.header, 120)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    State.commit_now(cs)

    start_supervised!({Mempool, name: mp, chain_state: cs, headers: hs, params: @p}, id: mp)
    start_supervised!({BlockFilter, name: bf, kv: kv, chain_state: cs}, id: bf)
    :ok = BlockFilter.sync_to(bf, List.last(bs).header.hash)

    ctx = %{
      chain_state: cs,
      headers: hs,
      mempool: mp,
      params: @p,
      filter_index: bf
    }

    %{ctx: ctx, bs: bs, cs: cs, mp: mp}
  end

  defp decode_rpc({:ok, val}), do: {:ok, Jason.decode!(Jason.encode!(val))}
  defp decode_rpc(err), do: err

  defp raw_hex(%Tx{} = tx),
    do: tx |> Tx.encode() |> IO.iodata_to_binary() |> Base.encode16(case: :lower)

  test "getblock v=0 and v=1 skip spent_outputs; getrawtransaction skips read_block and validates blockhash",
       %{tmp_dir: dir} do
    %{ctx: ctx, bs: bs} = start_env(dir)
    b115 = Enum.at(bs, 114)
    bh_hex = Hash.to_hex(b115.header.hash)
    other_bh_hex = Hash.to_hex(Enum.at(bs, 113).header.hash)
    tx = Enum.at(b115.txs, 1)
    txid_hex = Hash.to_hex(tx.txid)

    for v <- [0, 1] do
      {{:ok, _}, traced} =
        CallTrace.calls([{Archive, :spent_outputs, 2}], fn ->
          Methods.call("getblock", [bh_hex, v], ctx)
        end)

      assert traced == []
    end

    # v=2 resolves undo outputs so fee is reported.
    assert {:ok, b_json} = decode_rpc(Methods.call("getblock", [bh_hex, 2], ctx))
    assert is_number(Enum.at(b_json["tx"], 1)["fee"])

    # getrawtransaction reads a single tx without reconstructing the whole block.
    {{:ok, hex_str}, rb_calls} =
      CallTrace.calls([{Archive, :read_block, 2}], fn ->
        Methods.call("getrawtransaction", [txid_hex, 0], ctx)
      end)

    assert rb_calls == []
    assert hex_str == raw_hex(tx)

    # Matching blockhash succeeds; wrong blockhash and unknown blockhash fail with -5.
    assert {:ok, ^hex_str} = Methods.call("getrawtransaction", [txid_hex, 0, bh_hex], ctx)

    assert {:error, -5, msg1} =
             Methods.call("getrawtransaction", [txid_hex, 0, other_bh_hex], ctx)

    assert msg1 =~ "No such transaction found in the provided block"

    assert {:error, -5, "Block hash not found"} =
             Methods.call("getrawtransaction", [txid_hex, 0, String.duplicate("aa", 32)], ctx)
  end

  test "getrawtransaction on a witness-pruned block returns -1 instead of crashing", %{
    tmp_dir: dir
  } do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    u = System.unique_integer([:positive])
    {cs, mp} = {:"rpcp_cs_#{u}", :"rpcp_mp_#{u}"}
    start_supervised!({KVOwner, {kv, [{State, cs}]}}, id: :"kvo_p_#{u}")
    hs = start_supervised!({Headers, params: @p, kv: kv}, id: :"hs_p_#{u}")

    start_supervised!(
      {State,
       name: cs,
       params: @p,
       headers: hs,
       kv: kv,
       hot: Path.join(dir, "hot"),
       mempool: mp,
       segment_max: 200,
       prune_witness: true,
       prune_keep: 20},
      id: cs
    )

    bs = for raw <- BlockBuilder.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(cs, b)
    State.commit_now(cs)
    start_supervised!({Mempool, name: mp, chain_state: cs, headers: hs, params: @p}, id: mp)
    ctx = %{chain_state: cs, headers: hs, mempool: mp, params: @p}

    assert State.with_archive(cs, &Archive.witness_pruned/1) >= 0

    pruned_block = Enum.at(bs, 9)
    txid_hex = Hash.to_hex(hd(pruned_block.txs).txid)

    assert {:error, -1, msg} = Methods.call("getrawtransaction", [txid_hex, 0], ctx)
    assert msg =~ "pruned"
    assert {:error, -1, _} = Methods.call("getrawtransaction", [txid_hex, 2], ctx)
  end

  test "sendrawtransaction maxfeerate/maxburnamount, submitpackage CPFP, getrawmempool sequence, and getblockfilter filtertype",
       %{tmp_dir: dir} do
    %{ctx: ctx, bs: bs} = start_env(dir)

    # Free non-coinbase outputs from blocks 112..115.
    coins =
      for b <- Enum.slice(bs, 112..115), {tx, k} <- Enum.with_index(tl(b.txs)), k > 0 do
        {tx.txid, 0, 25 * @coin - 1_000, SpendChain.spk()}
      end

    [c1, c2, c3 | _] = coins

    # 1. maxfeerate: huge fee (1 BTC) rejected at default maxfeerate, accepted with maxfeerate = 0.
    {_, _, v1, _} = c1
    high_fee_tx = SpendChain.spend([c1], [{v1 - 1 * @coin, SpendChain.spk()}])

    assert {:error, -26, "max-fee-exceeded"} =
             Methods.call("sendrawtransaction", [raw_hex(high_fee_tx)], ctx)

    assert {:ok, _} = Methods.call("sendrawtransaction", [raw_hex(high_fee_tx), 0], ctx)

    # 2. maxburnamount: OP_RETURN burning 1000 sats rejected at default 0, accepted when allowed.
    {_, _, v2, _} = c2
    op_ret = <<0x6A, 4, "burn">>

    burn_tx =
      SpendChain.spend([c2], [
        {1_000, op_ret},
        {v2 - 2_000, SpendChain.spk()}
      ])

    assert {:error, -26, burn_msg} = Methods.call("sendrawtransaction", [raw_hex(burn_tx)], ctx)
    assert burn_msg =~ "maxburnamount"

    assert {:ok, _} =
             Methods.call("sendrawtransaction", [raw_hex(burn_tx), 0.10, 0.0001], ctx)

    # 3. submitpackage: 0-fee parent + high-fee child (1p1c CPFP).
    {_, _, v3, _} = c3
    parent = SpendChain.spend([c3], [{v3, SpendChain.spk()}])

    child =
      SpendChain.spend([{parent.txid, 0, v3, SpendChain.spk()}], [{v3 - 5_000, SpendChain.spk()}])

    assert {:ok, pkg_res} =
             decode_rpc(Methods.call("submitpackage", [[raw_hex(parent), raw_hex(child)]], ctx))

    assert pkg_res["package_msg"] == "success"
    assert Map.has_key?(pkg_res["tx-results"], Hash.to_hex(parent.wtxid))
    assert Map.has_key?(pkg_res["tx-results"], Hash.to_hex(child.wtxid))

    # 4. getrawmempool with mempool_sequence.
    assert {:ok, %{"txids" => txids, "mempool_sequence" => seq}} =
             decode_rpc(Methods.call("getrawmempool", [false, true], ctx))

    assert is_list(txids) and length(txids) >= 4
    assert is_integer(seq) and seq > 0
    assert {:error, -8, _} = Methods.call("getrawmempool", [true, true], ctx)

    # 5. getblockfilter filtertype check.
    bh_hex = Hash.to_hex(List.last(bs).header.hash)

    assert {:ok, %{"filter" => _}} =
             decode_rpc(Methods.call("getblockfilter", [bh_hex, "basic"], ctx))

    assert {:error, -8, _} = Methods.call("getblockfilter", [bh_hex, "extended"], ctx)
  end

  test "Esplora REST answers 503 instead of crashing when a node service is unavailable" do
    ctx = %{
      chain_state: :no_such_cs_for_rest,
      headers: :no_such_hs_for_rest,
      mempool: :no_such_mp_for_rest,
      params: @p,
      scripthash_index: nil
    }

    for path <- ["/blocks/tip/height", "/mempool"] do
      conn = Plug.Test.conn(:get, path) |> Esplora.call(Esplora.init(%{ctx: ctx}))
      assert conn.status == 503
    end
  end
end
