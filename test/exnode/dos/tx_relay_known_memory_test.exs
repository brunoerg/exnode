defmodule Exnode.DoS.TxRelayKnownMemoryTest do
  @moduledoc """
  AUD-A4-3 (SECURITY_AUDIT_REPORT.md; regression): each peer's
  known-inventory filter was an exact set of up to 50,000 32-byte hashes
  plus a FIFO queue, ~141 B per entry (6.9 MB per peer) on the singleton
  TxRelay's heap, filled by one 50,000-item inv. With the default 200
  connections that is over a gigabyte that every major collection of
  TxRelay copies, pausing every peer's tx path. Core keeps a rolling bloom
  filter of fixed size (`m_tx_inventory_known_filter`, 50,000 at 10⁻⁶,
  ~527 KiB); so does TxRelay now, off its heap.
  """
  use ExUnit.Case, async: false
  @moduletag :dos

  alias Exnode.P2P.TxRelay
  alias Exnode.Util.RollingBloom

  defmodule EmptyMempool do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil)
    def init(_), do: {:ok, nil}
    def handle_call({:has, _, _}, _f, st), do: {:reply, false, st}
    def handle_call({:has_many, _, _}, _f, st), do: {:reply, MapSet.new(), st}
    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}
  end

  @peers 5
  @items 50_000

  defp heap(r) do
    :erlang.garbage_collect(r)
    {:memory, m} = Process.info(r, :memory)
    m
  end

  test "a peer's 50,000-item inv costs TxRelay's heap little; its filter is fixed-size, off-heap" do
    {:ok, mp} = EmptyMempool.start_link(nil)
    {:ok, r} = TxRelay.start_link(mempool: mp, tick_ms: nil)
    base = heap(r)

    peers =
      for n <- 1..@peers do
        p = spawn_link(fn -> Process.sleep(:infinity) end)

        TxRelay.connected(r, p, %{
          wtxid_relay: true,
          preferred: false,
          relay_txs: true,
          inbound: true
        })

        items =
          for i <- 1..@items, do: %{type: :wtx, hash: :crypto.hash(:sha256, <<n::32, i::32>>)}

        :ok = TxRelay.inv(r, p, items)
        p
      end

    per_peer = div(heap(r) - base, @peers)

    IO.puts(
      "TxRelay heap per peer after a #{@items}-item inv: #{div(per_peer, 1024)} KiB " <>
        "(+ #{div(RollingBloom.bytes(RollingBloom.new(50_000, 1.0e-6)), 1024)} KiB off-heap filter)"
    )

    # Before: ~9.7 MiB per peer after a GC (the exact set alone 6.9 MB).
    # After: ~3.2-3.9 MiB (heap sizes grow in steps), the 5,000
    # announcements a peer may keep (`ann`, the `ready` tree and the
    # `ann_peers` index), not the known filter.
    assert per_peer < 5 * 1024 * 1024

    # Every hash the peer announced is known to it.
    st = :sys.get_state(r)
    k = st.peers[hd(peers)].known_in

    assert Enum.all?(
             1..@items//997,
             &RollingBloom.contains?(k, :crypto.hash(:sha256, <<1::32, &1::32>>))
           )
  end
end
