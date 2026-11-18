defmodule Exnode.P2P.HighBandwidthTest do
  @moduledoc """
  Regression: BIP152 high-bandwidth selection had no
  outbound protection (Core keeps the last outbound HB peer when an inbound
  one is added), and a select for a peer that had already exited demoted a
  live peer, then left the slot to the dead one.
  """
  use ExUnit.Case, async: true

  alias Exnode.P2P.HighBandwidth

  defp peer do
    test = self()
    spawn(fn -> forward(test) end)
  end

  defp forward(test) do
    receive do
      m -> send(test, {:to_peer, self(), m}) && forward(test)
    end
  end

  defp demoted?(p),
    do:
      receive(
        do: ({:to_peer, ^p, {:send, {:sendcmpct, %{announce: false}}}} -> true),
        after: (100 -> false)
      )

  setup do
    {:ok, hb} = HighBandwidth.start_link([])
    %{hb: hb}
  end

  test "an inbound peer does not displace the only outbound high-bandwidth peer", %{hb: hb} do
    [out, in1, in2, in3] = for _ <- 1..4, do: peer()
    HighBandwidth.select(hb, out, false)
    HighBandwidth.select(hb, in1, true)
    HighBandwidth.select(hb, in2, true)
    HighBandwidth.select(hb, in3, true)
    assert HighBandwidth.peers(hb) == [out, in2, in3]
    assert demoted?(in1)
    refute demoted?(out)
  end

  test "an outbound peer can still displace the oldest", %{hb: hb} do
    [out, in1, in2, out2] = for _ <- 1..4, do: peer()

    for {p, inb} <- [{out, false}, {in1, true}, {in2, true}, {out2, false}],
        do: HighBandwidth.select(hb, p, inb)

    assert HighBandwidth.peers(hb) == [in1, in2, out2]
    assert demoted?(out)
  end

  test "a select for a peer that is already gone demotes nobody", %{hb: hb} do
    ps = for _ <- 1..3, do: peer()
    for p <- ps, do: HighBandwidth.select(hb, p, false)
    dead = spawn(fn -> :ok end)
    ref = Process.monitor(dead)
    assert_receive {:DOWN, ^ref, _, _, _}
    HighBandwidth.select(hb, dead, false)
    assert HighBandwidth.peers(hb) == ps
    refute demoted?(hd(ps))
  end
end
