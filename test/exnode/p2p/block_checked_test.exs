defmodule Exnode.P2P.BlockCheckedTest do
  @moduledoc """
  In IBD a peer submits blocks deferred: the chain state replies `:stored`
  and connects later. A block that then fails on connect must still cost
  its sender, as Core `BlockChecked` calls `MaybePunishNodeForBlock` for the
  peer in `mapBlockSource`. A fake remote peer sends a block that passes
  CheckBlock and ContextualCheckBlock but spends a missing coin.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.State
  alias Exnode.Codec.Block
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  test "a block found invalid after a deferred submission gets its sender disconnected", %{
    tmp_dir: dir
  } do
    %{n: n} = TestNode.start(dir)

    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    # The tip is over 24 h old: the node is in IBD, so the peer defers.
    assert List.last(bs).header.time < System.os_time(:second) - 24 * 3600

    tip = List.last(bs).header

    bad =
      BB.build(tip, [
        BB.coinbase(151, 25 * 100_000_000),
        BB.spend_op_true(:crypto.strong_rand_bytes(32), 0, 1000)
      ])

    {pid, sock} = FakePeer.connect_from(n, handshake: false)
    ref = Process.monitor(pid)
    send_msg = fn m -> :ok = FakePeer.send_msgs(sock, m) end

    send_msg.({:version, FakePeer.version(user_agent: "/evil/", start_height: 150)})
    send_msg.(:verack)
    send_msg.({:headers, [bad.header]})
    send_msg.({:block, bad.raw})

    assert_receive {:DOWN, ^ref, :process, ^pid,
                    {:shutdown, {:misbehaving, "invalid block: bad-txns-inputs-missingorspent"}}},
                   5000

    assert State.tip(n.chain_state).hash == tip.hash
  end
end
