defmodule Exnode.P2P.SyncStateTest do
  @moduledoc """
  `SyncState` (Core `nSyncStarted`): the first headers sync goes to a
  preferred (outbound) peer; while one runs, another starts only if our best
  header is within 24h. A peer counts once and stops counting when it exits.
  """
  use ExUnit.Case, async: true

  import Exnode.Test.Wait

  alias Exnode.P2P.SyncState

  setup do
    %{s: start_supervised!(SyncState)}
  end

  # A stand-in peer process.
  defp peer, do: spawn(fn -> receive do: (:stop -> :ok) end)

  test "the first sync needs a preferred peer, or a recent best header", %{s: s} do
    refute SyncState.try_start(s, peer(), false, false)
    assert SyncState.count(s) == 0
    assert SyncState.try_start(s, peer(), false, true)
    assert SyncState.count(s) == 1

    s2 = start_supervised!(SyncState, id: :other)
    assert SyncState.try_start(s2, peer(), true, false)
  end

  test "while one sync runs, another starts only with a recent best header", %{s: s} do
    assert SyncState.try_start(s, peer(), true, false)
    refute SyncState.try_start(s, peer(), true, false)
    assert SyncState.try_start(s, peer(), false, true)
    assert SyncState.count(s) == 2
  end

  test "a peer that already started is not counted twice", %{s: s} do
    p = peer()
    assert SyncState.try_start(s, p, true, false)
    refute SyncState.try_start(s, p, true, true)
    assert SyncState.count(s) == 1
  end

  test "a peer that exits stops counting, and the next preferred peer may start", %{s: s} do
    p = peer()
    assert SyncState.try_start(s, p, true, false)
    send(p, :stop)
    wait_until(fn -> SyncState.count(s) == 0 end)
    assert SyncState.try_start(s, peer(), true, false)
  end
end
