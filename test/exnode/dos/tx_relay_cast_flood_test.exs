defmodule Exnode.DoS.TxRelayCastFloodTest do
  @moduledoc """
  Regression: `notfound` and `feefilter` used to be casts to
  the shared TxRelay with no item cap and no change check, so while TxRelay
  was busy its mailbox grew with the attacker's upload. Now both are calls
  (the peer waits, as for inv), a notfound with more than
  MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER = 5016 items
  is ignored (Core net_processing.cpp), and a feefilter is forwarded only
  when it changes and is in MoneyRange.
  """
  use Exnode.NodeCase
  @moduletag :dos

  # The process is waiting for a GenServer.call reply.
  defp in_call?(pid) do
    case :erlang.process_info(pid, [:status, :current_stacktrace]) do
      [status: :waiting, current_stacktrace: st] ->
        Enum.any?(st, &match?({:gen, :do_call, _, _}, &1))

      _ ->
        false
    end
  end

  test "notfound / feefilter floods do not queue in a busy TxRelay", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    {pid, sock} = FakePeer.connect_from(n, node: %{tx_relay: n.tx_relay}, version: %{relay: true})
    FakePeer.recv(sock, ["verack"], 1)
    relay = Process.whereis(n.tx_relay)
    wait_until(fn -> Map.has_key?(:sys.get_state(relay).peers, pid) end)

    :ok = :sys.suspend(relay)

    try do
      items = for i <- 1..10_000, do: %{type: :wtx, hash: :crypto.hash(:sha256, <<i::32>>)}
      small = Enum.take(items, 100)

      wire =
        for(_ <- 1..100, do: {:notfound, items}) ++
          for(_ <- 1..1_000, do: {:feefilter, 1_000}) ++
          [{:feefilter, -1}, {:notfound, small}] ++
          for(i <- 1..100, do: {:notfound, [Enum.at(items, i)]})

      magic = Exnode.ChainParams.get(:regtest).magic

      bin =
        for m <- wire, into: <<>> do
          {c, p} = Exnode.P2P.Message.encode(m)
          IO.iodata_to_binary(Exnode.P2P.Frame.encode(magic, c, p))
        end

      :ok = :gen_tcp.send(sock, bin)
      # Oversized notfounds and repeated feefilters cost TxRelay nothing; the
      # first real one blocks the peer in its call while TxRelay is busy.
      # Blocked there, the peer cannot add anything more to the mailbox: no
      # need to wait and see.
      wait_until(fn ->
        in_call?(pid) and elem(:erlang.process_info(relay, :message_queue_len), 1) >= 1
      end)

      {:message_queue_len, q} = :erlang.process_info(relay, :message_queue_len)
      IO.puts("flood of #{byte_size(bin)} B while TxRelay is busy -> TxRelay mailbox #{q} msgs")
      assert q <= 2
    after
      :sys.resume(relay)
    end

    # Once TxRelay is free the peer goes on: feefilter 1000 stored once, -1 ignored.
    :ok = FakePeer.send_msgs(sock, [{:ping, 9}])
    FakePeer.recv(sock, ["pong"], 1, timeout: 30_000)
    assert :sys.get_state(relay).peers[pid].feefilter == 1_000
  end
end
