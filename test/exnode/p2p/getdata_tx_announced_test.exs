defmodule Exnode.P2P.GetdataTxAnnouncedTest do
  @moduledoc """
  Regression: a tx getdata is served
  as Core's `ProcessGetData` / `FindTxForGetData`:

  * only a tx that entered the mempool before the last inv we sent the
    peer (`m_last_inv_sequence`, against the entry's sequence): any other
    is `notfound`. Before, any mempool tx was handed to any peer, so a spy
    could probe the mempool and learn a locally submitted tx before it was
    announced (Core's trickle exists to hide that);
  * nothing at all for a peer without tx relay (block-relay-only, or
    `fRelay = false`): Core keeps no `TxRelay` for it and skips the item;
  * `MSG_TX` (no witness flag) gets the tx without witness.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Codec.Tx
  alias Exnode.P2P.{Frame, Message}
  alias Exnode.Test.BlockBuilder, as: BB

  @p Exnode.ChainParams.get(:regtest)
  @spk <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)

  setup %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)

    # Coinbases pay to P2WSH(OP_TRUE): the first ones are mature at 120.
    {blocks, _} =
      Enum.map_reduce(1..120, @p.genesis.header, fn h, prev ->
        b =
          BB.build(prev, [
            BB.coinbase_with(h, 50 * 100_000_000, outputs: [{50 * 100_000_000, @spk}])
          ])

        {b, b.header}
      end)

    for b <- blocks, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)
    %{n: n, blocks: blocks}
  end

  # A segwit spend of block `i`'s coinbase (its witness makes txid != wtxid).
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
      outputs: [%Tx.Out{value: 50 * 100_000_000 - 10_000, script_pubkey: @spk}],
      locktime: 0
    })
  end

  defp connect(n, opts \\ []) do
    {pid, sock} =
      FakePeer.connect_from(
        n,
        [
          node: %{tx_relay: n.tx_relay, mempool: n.mempool},
          version: %{start_height: 120, relay: Keyword.get(opts, :relay, true)}
        ] ++ Keyword.take(opts, [:conn_type])
      )

    FakePeer.recv(sock, ["verack"], 1)
    wait_until(fn -> :sys.get_state(pid).verack_received end)
    {pid, sock}
  end

  # TxRelay announces nothing to `pid` until `release_trickle/2`.
  defp hold_trickle(n, pid) do
    wait_until(fn -> Map.has_key?(:sys.get_state(n.tx_relay).peers, pid) end)

    :sys.replace_state(n.tx_relay, fn st ->
      put_in(st.peers[pid].next_inv_at, :infinity)
    end)
  end

  defp release_trickle(n, pid) do
    # TxRelay's own clock (monotonic: may be negative).
    :sys.replace_state(n.tx_relay, fn st -> put_in(st.peers[pid].next_inv_at, st.now.()) end)
    send(n.tx_relay, :tick)
  end

  # Commands (and payloads) received before the pong of a ping sent now.
  defp before_pong(sock) do
    nonce = System.unique_integer([:positive])
    :ok = FakePeer.send_msgs(sock, {:ping, nonce})
    collect(sock, nonce, <<>>, [])
  end

  defp collect(sock, nonce, buf, acc) do
    case Frame.decode(@p.magic, buf) do
      {:ok, "pong", <<^nonce::little-64>>, _} ->
        Enum.reverse(acc)

      {:ok, cmd, payload, rest} ->
        collect(sock, nonce, rest, [{cmd, payload} | acc])

      _ ->
        {:ok, more} = :gen_tcp.recv(sock, 0, 10_000)
        collect(sock, nonce, buf <> more, acc)
    end
  end

  defp wtx(tx), do: %{type: :wtx, witness: false, hash: tx.wtxid}

  test "a tx not yet announced to the peer is notfound; once announced it is served",
       %{n: n, blocks: blocks} do
    {pid, sock} = connect(n)
    hold_trickle(n, pid)
    tx = spend(blocks, 0)
    {:ok, _} = Exnode.Mempool.accept(n.mempool, tx)

    # Before any inv to this peer: Core's FindTxForGetData finds nothing.
    :ok = FakePeer.send_msgs(sock, {:getdata, [wtx(tx)]})
    got = before_pong(sock)
    refute Enum.any?(got, &match?({"tx", _}, &1))
    assert [{"notfound", nf}] = for({"notfound", _} = m <- got, do: m)
    assert {:ok, {:notfound, [%{hash: h}]}} = Message.decode("notfound", nf)
    assert h == tx.wtxid

    # The trickle announces it: now the same getdata is answered.
    release_trickle(n, pid)
    [{"inv", _}] = FakePeer.recv(sock, ["inv"], 1)
    :ok = FakePeer.send_msgs(sock, {:getdata, [wtx(tx)]})
    assert [{"tx", raw}] = for({"tx", _} = m <- before_pong(sock), do: m)
    assert raw == tx.raw
  end

  test "a peer without tx relay gets nothing for a tx getdata, not even notfound",
       %{n: n, blocks: blocks} do
    tx = spend(blocks, 1)
    {:ok, _} = Exnode.Mempool.accept(n.mempool, tx)

    for opts <- [[conn_type: :block_relay], [relay: false]] do
      {_pid, sock} = connect(n, opts)
      :ok = FakePeer.send_msgs(sock, {:getdata, [wtx(tx)]})
      got = before_pong(sock)

      refute Enum.any?(got, fn {cmd, _} -> cmd in ["tx", "notfound"] end),
             "#{inspect(opts)}: #{inspect(Enum.map(got, &elem(&1, 0)))}"
    end
  end

  test "MSG_TX without the witness flag gets the tx without witness", %{n: n, blocks: blocks} do
    {pid, sock} = connect(n)
    hold_trickle(n, pid)
    tx = spend(blocks, 2)
    {:ok, _} = Exnode.Mempool.accept(n.mempool, tx)
    release_trickle(n, pid)
    [{"inv", _}] = FakePeer.recv(sock, ["inv"], 1)

    :ok = FakePeer.send_msgs(sock, {:getdata, [%{type: :tx, witness: false, hash: tx.txid}]})
    assert [{"tx", stripped}] = for({"tx", _} = m <- before_pong(sock), do: m)
    assert stripped == IO.iodata_to_binary(Tx.encode(tx, witness: false))

    :ok = FakePeer.send_msgs(sock, {:getdata, [%{type: :tx, witness: true, hash: tx.txid}]})
    assert [{"tx", full}] = for({"tx", _} = m <- before_pong(sock), do: m)
    assert full == tx.raw
  end
end
