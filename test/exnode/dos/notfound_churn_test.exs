defmodule Exnode.DoS.NotfoundChurnTest do
  @moduledoc """
  Regression: a response to a tx
  request (`notfound`, the tx itself) and a request's expiry deleted the
  peer's announcement. Core (`TxRequestTracker::ReceivedResponse`,
  `MakeCompleted`) marks it COMPLETED instead, and `ReceivedInv` from the same
  peer for the same hash is then a no-op, until no announcement of the hash
  is left uncompleted (then all of them are forgotten).

  With deletion, a peer could re-announce the same hashes right after its
  `notfound`, and each round parked new entries behind another peer's
  request in `waiting`, where the old ones stayed until that request ended
  (up to 60 s): ~5,000 entries per round per connection, re-inserted all at
  once when the request expired.
  """
  use ExUnit.Case, async: true
  @moduletag :dos

  alias Exnode.P2P.TxRelay

  defmodule EmptyMempool do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil)
    def init(_), do: {:ok, nil}
    def handle_call({:has, _, _}, _f, st), do: {:reply, false, st}
    def handle_call({:has_many, _, _}, _f, st), do: {:reply, MapSet.new(), st}
    def handle_call({:extract_best, txids, _n}, _f, st), do: {:reply, {[], txids}, st}
  end

  @n 100
  @rounds 20

  defp peer(r) do
    pid = spawn_link(fn -> drain() end)

    TxRelay.connected(r, pid, %{
      wtxid_relay: true,
      preferred: false,
      relay_txs: true,
      inbound: true
    })

    pid
  end

  defp drain do
    receive do
      _ -> drain()
    end
  end

  defp tick(r) do
    send(r, :tick)
    :sys.get_state(r)
  end

  test "re-announcing after notfound parks nothing new; expiry then forgets the hashes" do
    clock = :atomics.new(1, [])
    :atomics.put(clock, 1, 1_000_000)
    advance = fn ms -> :atomics.add(clock, 1, ms) end
    {:ok, mp} = EmptyMempool.start_link(nil)

    {:ok, r} =
      TxRelay.start_link(mempool: mp, clock: fn -> :atomics.get(clock, 1) end, tick_ms: nil)

    hashes = for i <- 1..@n, do: :crypto.hash(:sha256, <<i::32>>)
    items = for h <- hashes, do: %{type: :wtx, hash: h}

    # X announces and is asked for every hash, then never answers.
    x = peer(r)
    :ok = TxRelay.inv(r, x, items)
    advance.(2_100)
    st = tick(r)
    assert map_size(st.requested) == @n

    # B announces the same hashes, waits behind X's requests, sends notfound,
    # and announces them again.
    b = peer(r)

    for _ <- 1..@rounds do
      :ok = TxRelay.inv(r, b, items)
      advance.(2_100)
      tick(r)
      :ok = TxRelay.notfound(r, b, items)
    end

    st = :sys.get_state(r)
    parked = Enum.sum(for {_, l} <- st.waiting, do: length(l))
    IO.puts("after #{@rounds} rounds: #{parked} entries parked behind #{@n} requests")
    # Core: B's announcement of each hash is COMPLETED; its re-announcements do nothing.
    assert parked <= @n
    assert map_size(st.ann[b]) == @n
    assert Enum.all?(st.ann[b], fn {_, a} -> a.state == :completed end)

    # X's requests expire: X's announcements were the last uncompleted ones,
    # so every announcement of these hashes is forgotten.
    advance.(61_000)
    st = tick(r)
    assert st.ann == %{}
    assert st.waiting == %{}
    assert st.requested == %{}
  end
end
