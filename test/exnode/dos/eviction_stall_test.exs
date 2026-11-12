defmodule Exnode.DoS.EvictionStallTest do
  @moduledoc """
  Regression: eviction only sent `{:disconnect, :evicted}`
  to the peer process. A peer blocked in a call (e.g. on a busy TxRelay)
  never acted on it, so its socket stayed open while Connman accepted a
  replacement, and inbound connections grew past max_inbound without bound
  during a stall. Now an evicted peer still alive after the grace period
  is killed (closing its socket, as Core's DisconnectNodes does whatever
  the message thread is doing), and while 8 evictions are pending a full
  inbound side refuses new connections instead of evicting more.

  Stand-in peers that never read their mailbox play the blocked peers.
  """
  use ExUnit.Case, async: false
  @moduletag :dos
  @moduletag :tmp_dir

  alias Exnode.P2P.Connman

  @p Exnode.ChainParams.get(:regtest)

  test "blocked evicted peers are killed after the grace; pending evictions are capped",
       %{tmp_dir: dir} do
    {:ok, sup} = DynamicSupervisor.start_link(strategy: :one_for_one)
    # 51 connections - 8 full-relay - 2 block-relay - 1 feeler = 40 inbound.
    {:ok, cm} =
      Connman.start_link(
        node: %{
          params: @p,
          addrman: nil,
          services: 9,
          nonce: 1,
          user_agent: "/t/",
          headers: nil,
          sync: nil
        },
        peer_sup: sup,
        connect: [],
        magic: @p.magic,
        max_connections: 51,
        evict_grace_ms: 300,
        discouraged_path: Path.join(dir, "discouraged.dat")
      )

    stuck = fn -> spawn(fn -> Process.sleep(:infinity) end) end

    pids =
      for i <- 1..40 do
        pid = stuck.()
        Connman.register_inbound(cm, pid, {"10.#{i}.0.1", 8333})
        pid
      end

    _ = Connman.peers(cm)

    # Full: each accepted connection evicts one blocked peer, up to the cap.
    accepted = Enum.take_while(1..20, fn _ -> Connman.accept_inbound?(cm, {"20.0.0.1", 1}) end)
    evicting = for {pid, p} <- Connman.peers(cm), p.evicting, do: pid

    IO.puts(
      "full inbound, blocked peers: #{length(accepted)} accepted before refusal, #{length(evicting)} evictions pending"
    )

    assert length(accepted) == 8
    assert length(evicting) == 8
    assert Enum.all?(evicting, &Process.alive?/1)

    # After the grace they are killed and leave; new connections are accepted again.
    refs = for pid <- evicting, do: Process.monitor(pid)
    for ref <- refs, do: assert_receive({:DOWN, ^ref, _, _, :killed}, 2_000)
    _ = Connman.peers(cm)
    assert map_size(Connman.peers(cm)) == 40 - 8
    assert Connman.accept_inbound?(cm, {"20.0.0.2", 1})
    assert Enum.count(pids, &Process.alive?/1) == 40 - 8
  end
end
