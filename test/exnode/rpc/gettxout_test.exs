defmodule Exnode.RPC.GettxoutTest do
  @moduledoc """
  Regression: `gettxout` passed `n` through unchecked. A non-integer or an
  integer outside uint32 (negative, nil, 2^32, a string, a float) reached
  the overlay NIF inside ChainState and raised `badarg` there, so one RPC
  call restarted ChainState and everything after it in the node tree. For a
  mempool tx, `n = -1` answered its last output (`Enum.at/2` from the end).
  Core reads `n` with `getInt<uint32_t>` after the RPCHelpMan type check:
  a non-number is RPC_TYPE_ERROR, anything outside [0, 2^32 - 1] (or with a
  fraction) is RPC_MISC_ERROR "JSON integer out of range".
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Codec.Tx
  alias Exnode.Crypto.Hash
  alias Exnode.RPC.Methods
  alias Exnode.Test.BlockBuilder, as: BB

  @p Exnode.ChainParams.get(:regtest)
  @spk <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)

  setup %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)

    # Coinbases pay to P2WSH(OP_TRUE): the first is mature at 101.
    {blocks, _} =
      Enum.map_reduce(1..101, @p.genesis.header, fn h, prev ->
        b =
          BB.build(prev, [
            BB.coinbase_with(h, 50 * 100_000_000, outputs: [{50 * 100_000_000, @spk}])
          ])

        {b, b.header}
      end)

    for b <- blocks, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)

    ctx = %{
      chain_state: n.chain_state,
      headers: n.headers,
      mempool: n.mempool,
      params: @p
    }

    %{n: n, ctx: ctx, blocks: blocks}
  end

  # A two-output spend of block `i`'s coinbase.
  defp spend(blocks, i) do
    cb = hd(Enum.at(blocks, i).txs)

    BB.finalize(%Tx{
      version: 2,
      inputs: [
        %Tx.In{
          prev_hash: cb.txid,
          prev_index: 0,
          script_sig: <<>>,
          sequence: 0xFFFFFFFD,
          witness: [<<0x51>>]
        }
      ],
      outputs: [
        %Tx.Out{value: 10 * 100_000_000, script_pubkey: @spk},
        %Tx.Out{value: 40 * 100_000_000 - 10_000, script_pubkey: @spk}
      ],
      locktime: 0
    })
  end

  @bad_n [
    {-1, -1, "JSON integer out of range"},
    {4_294_967_296, -1, "JSON integer out of range"},
    {0.5, -1, "JSON integer out of range"},
    {1.0, -1, "JSON integer out of range"},
    {"0", -3, "JSON value of type string is not of expected type number"},
    {nil, -3, "JSON value of type null is not of expected type number"},
    {true, -3, "JSON value of type bool is not of expected type number"}
  ]

  test "an out-of-range or non-integer n is an RPC error and ChainState survives",
       %{n: n, ctx: ctx, blocks: blocks} do
    pid = Process.whereis(n.chain_state) || n.chain_state
    ref = Process.monitor(pid)
    coinbase = Hash.to_hex(hd(hd(blocks).txs).txid)
    unknown = Hash.to_hex(:crypto.strong_rand_bytes(32))

    for txid <- [coinbase, unknown], {v, code, msg} <- @bad_n, mempool <- [true, false] do
      assert {:error, ^code, ^msg} = Methods.call("gettxout", [txid, v, mempool], ctx)
    end

    # n omitted.
    assert {:error, -3, _} = Methods.call("gettxout", [coinbase], ctx)

    # The ChainState boundary itself: such an outpoint is missing.
    cb = hd(hd(blocks).txs).txid
    good = {cb, 0}

    assert {_, %{{^cb, -1} => :missing, {^cb, nil} => :missing, ^good => {:ok, _}}} =
             State.mempool_view(n.chain_state, [{cb, -1}, {cb, nil}, good])

    refute_received {:DOWN, ^ref, _, _, _}
    assert Process.alive?(pid)

    assert {:ok, out} = Methods.call("gettxout", [coinbase, 0], ctx)
    assert {"confirmations", 101} in out
    assert {:ok, nil} = Methods.call("gettxout", [coinbase, 4_294_967_295], ctx)
  end

  test "n = -1 does not answer a mempool tx's last output", %{n: n, ctx: ctx, blocks: blocks} do
    tx = spend(blocks, 0)
    {:ok, _} = Exnode.Mempool.accept(n.mempool, tx)
    txid = Hash.to_hex(tx.txid)

    assert {:ok, out} = Methods.call("gettxout", [txid, 1], ctx)
    assert {"confirmations", 0} in out
    assert {:ok, nil} = Methods.call("gettxout", [txid, 2], ctx)
    assert {:error, -1, "JSON integer out of range"} = Methods.call("gettxout", [txid, -1], ctx)
  end
end
