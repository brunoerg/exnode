defmodule Exnode.DoS.FrameRetentionTest do
  @moduledoc """
  Regression: a small v1 payload decoded out of a large
  receive buffer (here a tx right after a ~4 MB frame) must not keep that
  buffer alive: `FrameBuffer` copies it. Before the fix each ~100-byte
  orphan pinned ~4 MB, invisible to the orphan weight cap. End to end, the
  orphans come from a peer that sent version fRelay = false; since #6 that
  peer is registered with TxRelay, so its orphans go when it disconnects.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Codec.Tx
  alias Exnode.P2P.{Frame, FrameBuffer, Message}

  @magic Exnode.ChainParams.get(:regtest).magic

  defp orphan(i) do
    {:ok, tx} =
      %Tx{
        version: 2,
        locktime: 0,
        inputs: [
          %Tx.In{
            prev_hash: :crypto.hash(:sha256, <<i::64>>),
            prev_index: 0,
            script_sig: <<>>,
            sequence: 0xFFFFFFFF
          }
        ],
        outputs: [%Tx.Out{value: 10_000, script_pubkey: <<0, 20, i::160>>}]
      }
      |> Tx.encode()
      |> IO.iodata_to_binary()
      |> Tx.decode_exact()

    tx
  end

  defp frame(cmd, payload), do: IO.iodata_to_binary(Frame.encode(@magic, cmd, payload))

  defp burst(tx),
    do:
      frame("zzzz", :binary.copy(<<0>>, 3_990_000)) <>
        frame("tx", tx.raw) <> frame("zzzy", :binary.copy(<<0>>, 5_000))

  test "unit: the tx payload after a 4 MB frame does not reference the 4 MB binary" do
    tx = orphan(1)
    fb = FrameBuffer.append(FrameBuffer.new(), burst(tx))
    {:ok, "zzzz", _, fb} = FrameBuffer.next(fb, @magic)
    {:ok, "tx", payload, _fb} = FrameBuffer.next(fb, @magic)
    {:ok, decoded} = Tx.decode_exact(payload)
    ref = :binary.referenced_byte_size(decoded.raw)
    IO.puts("frame retention (unit): tx.raw #{byte_size(decoded.raw)} B references #{ref} B")
    assert ref < 4096
  end

  test "end to end: orphans from a fRelay=0 peer pin nothing and go with the connection", %{
    tmp_dir: dir
  } do
    %{n: n} = TestNode.start(dir)
    g = Exnode.ChainParams.get(:regtest).genesis.header
    clock = Exnode.Clock.new()
    Exnode.Clock.set(clock, g.time + 3600)
    # Out of IBD from the peer's view (tip time within 24 h).
    {pid, sock} =
      FakePeer.connect_from(n,
        node: %{tx_relay: n.tx_relay, mempool: n.mempool, clock: clock}
      )

    FakePeer.recv(sock, ["verack"], 1)

    k = 15
    # The tail of the big frame and the tx go in one write, so they arrive in
    # the same receive chunk (an attacker controls its write boundaries):
    # the head is read by the peer (its byte count) before the tail is sent.
    recv0 = :sys.get_state(pid).bytes_recv

    Enum.reduce(1..k, recv0, fn i, recv ->
      b = burst(orphan(i))
      cut = 3_990_000 - 100
      :ok = :gen_tcp.send(sock, binary_part(b, 0, cut))
      wait_until(fn -> :sys.get_state(pid).bytes_recv >= recv + cut end)
      :ok = :gen_tcp.send(sock, binary_part(b, cut, byte_size(b) - cut))
      recv + byte_size(b)
    end)

    {c, pl} = Message.encode({:ping, 5})
    :ok = :gen_tcp.send(sock, frame(c, pl))
    FakePeer.recv(sock, ["pong"], 1, timeout: 20_000)
    wait_until(fn -> length(Exnode.P2P.TxRelay.orphans(n.tx_relay)) == k end)

    st = :sys.get_state(n.tx_relay)
    refs = for {_, o} <- st.orphans, do: :binary.referenced_byte_size(o.tx.raw)

    IO.puts(
      "frame retention (e2e): referenced sizes #{inspect(Enum.sort(refs), charlists: :as_lists)}"
    )

    assert Enum.all?(refs, &(&1 < 4096))

    :gen_tcp.close(sock)
    wait_until(fn -> not Process.alive?(pid) end)
    wait_until(fn -> Exnode.P2P.TxRelay.orphans(n.tx_relay) == [] end)
  end
end
