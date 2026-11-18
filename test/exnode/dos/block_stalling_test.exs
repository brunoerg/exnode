defmodule Exnode.DoS.BlockStallingTest do
  @moduledoc """
  Regression (real sockets, full node): an
  attacker that announces the real chain, is asked for the window's first
  16 blocks and withholds only the first, keeps free slots and so is itself
  window-blocked on every request. It used to be exempt from stall
  detection for that reason, and IBD sat still until the generic 600 s
  download timeout, once per window. Like Core it must be disconnected
  after the stall timeout (2 s), and the honest peer asked for the block.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Chain.State
  alias Exnode.P2P.{Frame, Message}
  alias Exnode.Test.BlockBuilder, as: BB

  # More than the 1,024-block window, so the window can run out.
  @n 1100
  @magic Exnode.ChainParams.get(:regtest).magic

  defp chain do
    g = Exnode.ChainParams.get(:regtest).genesis.header

    {blocks, _} =
      Enum.map_reduce(1..@n, g, fn h, prev ->
        b = BB.build(prev, [BB.coinbase(h, Bitwise.bsr(50 * 100_000_000, div(h, 150)))])
        {b, b.header}
      end)

    blocks
  end

  # Reads frames until `timeout` ms of silence; returns decoded messages.
  defp drain(sock, timeout, buf \\ <<>>, acc \\ []) do
    case Frame.decode(@magic, buf) do
      {:ok, cmd, pl, rest} ->
        m =
          case Message.decode(cmd, pl) do
            {:ok, m} -> m
            _ -> {:raw, cmd}
          end

        drain(sock, timeout, rest, [m | acc])

      _ ->
        case :gen_tcp.recv(sock, 0, timeout) do
          {:ok, d} -> drain(sock, timeout, buf <> d, acc)
          {:error, :timeout} -> Enum.reverse(acc)
          {:error, r} -> Enum.reverse(acc) ++ [{:closed, r}]
        end
    end
  end

  defp getdata_hashes(msgs), do: for({:getdata, items} <- msgs, %{hash: h} <- items, do: h)

  # Answers pings and serves the requested blocks not in `skip`; returns the requested hashes.
  defp serve(sock, by_hash, msgs, skip \\ MapSet.new()) do
    for {:ping, n} <- msgs, do: FakePeer.send_msgs(sock, {:pong, n})
    hs = getdata_hashes(msgs)

    for h <- hs,
        not MapSet.member?(skip, h),
        do: :ok = FakePeer.send_msgs(sock, {:block, by_hash[h].raw})

    hs
  end

  @tag timeout: 300_000
  test "a peer withholding the window's first block is disconnected as a staller", %{tmp_dir: dir} do
    blocks = chain()
    by_hash = Map.new(blocks, &{&1.header.hash, &1})
    headers = Enum.map(blocks, & &1.header)
    first = hd(blocks).header.hash
    withhold = MapSet.new([first])

    %{n: n, clock: clock, name: name, port: port} = TestNode.start(dir, listen: 0)
    Exnode.Clock.advance(clock, 0)

    # Attacker: announces the chain, serves every request but the first block.
    asock = FakePeer.dial(port)
    FakePeer.recv(asock, ["verack"], 1)
    [apid] = for {_, pid, _, _} <- DynamicSupervisor.which_children(n.peer_sup), do: pid
    aref = Process.monitor(apid)
    :ok = FakePeer.send_msgs(asock, {:headers, headers})
    m0 = drain(asock, 1000)
    :ok = Exnode.Node.tick(name)
    a_req = serve(asock, by_hash, m0 ++ drain(asock, 1000), withhold)
    assert first in a_req

    # Honest peer: serves everything, until the rest of the window is done.
    hsock = FakePeer.dial(port, version: %{relay: false})
    FakePeer.recv(hsock, ["verack"], 1)
    :ok = FakePeer.send_msgs(hsock, {:headers, headers})

    Enum.reduce_while(1..200, 0, fn _, acc ->
      msgs = drain(hsock, 300)
      serve(asock, by_hash, drain(asock, 10), withhold)
      k = length(serve(hsock, by_hash, msgs))
      :ok = Exnode.Node.tick(name)
      if k == 0 and acc > 0, do: {:halt, acc}, else: {:cont, acc + k}
    end)

    assert State.tip(n.chain_state).height == 0

    # Within the stall timeout (2 s, plus a tick) the attacker is dropped.
    for _ <- 1..4 do
      Exnode.Clock.advance(clock, 1)
      :ok = Exnode.Node.tick(name)
    end

    assert_receive {:DOWN, ^aref, _, _, {:shutdown, :block_stalling}}, 5_000

    # The honest peer is asked for the withheld block, and the tip moves.
    asked =
      Enum.reduce_while(1..50, false, fn _, _ ->
        hs = serve(hsock, by_hash, drain(hsock, 200))
        :ok = Exnode.Node.tick(name)
        if first in hs, do: {:halt, true}, else: {:cont, false}
      end)

    assert asked
    Exnode.Test.Wait.wait_until(fn -> State.tip(n.chain_state).height > 0 end, 30_000)
  end
end
