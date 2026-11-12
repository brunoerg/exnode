defmodule Exnode.DoS.BlockRequestStealTest do
  @moduledoc """
  Regression: `BlockDownload.received/3` used to remove
  the in-flight entry of whichever peer owned it, so any peer sending a
  (garbage-body) block for a public header cancelled an honest peer's
  request. As Core's `RemoveBlockRequest(hash, pfrom.GetId())`
  (net_processing.cpp), only the sender's own request is removed; the
  reply still says whether anyone requested it (`IsBlockRequested`).
  """
  use ExUnit.Case, async: true
  @moduletag :dos

  alias Exnode.Chain.HeaderIndex
  alias Exnode.Codec.Header
  alias Exnode.P2P.BlockDownload

  defmodule StubHeaders do
    use GenServer
    def init(idx), do: {:ok, idx}
    def handle_call(:index, _f, idx), do: {:reply, idx, idx}
  end

  defmodule StubChain do
    use GenServer
    def init(tip), do: {:ok, tip}
    def handle_call(:tip, _f, tip), do: {:reply, tip, tip}
    def handle_call({:have_many, _}, _f, tip), do: {:reply, MapSet.new(), tip}
  end

  test "a block from peer B leaves peer A's in-flight request" do
    {idx, entries} =
      Enum.reduce(0..20, {HeaderIndex.new(), []}, fn h, {idx, acc} ->
        prev = List.first(acc)

        hdr = %Header{
          version: 1,
          prev_hash: (prev && prev.hash) || <<0::256>>,
          merkle_root: <<h::256>>,
          time: h,
          bits: 0x207FFFFF,
          nonce: 0,
          hash: :crypto.hash(:sha256, <<h::32>>),
          raw: <<h::32>>
        }

        e = HeaderIndex.make_entry(hdr, prev)
        {HeaderIndex.insert(idx, e), [e | acc]}
      end)

    entries = Enum.reverse(entries)
    {:ok, headers} = GenServer.start_link(StubHeaders, idx)
    {:ok, chain} = GenServer.start_link(StubChain, hd(entries))

    {:ok, bd} =
      BlockDownload.start_link(headers: headers, chain: chain, params: %{pow_target_spacing: 600})

    honest = spawn(fn -> Process.sleep(:infinity) end)
    attacker = spawn(fn -> Process.sleep(:infinity) end)
    [h | _] = BlockDownload.request(bd, honest, List.last(entries).hash)
    assert {^honest, _, _} = BlockDownload.in_flight(bd)[h]

    assert BlockDownload.received(bd, attacker, h) == true

    IO.puts(
      "block request steal: honest peer's in-flight entry after attacker's block: #{inspect(BlockDownload.in_flight(bd)[h])}"
    )

    # Core keeps the honest peer's request.
    assert {^honest, _, _} = BlockDownload.in_flight(bd)[h]
    # The honest peer's own delivery clears it.
    assert BlockDownload.received(bd, honest, h) == true
    assert BlockDownload.in_flight(bd)[h] == nil
    assert BlockDownload.received(bd, honest, h) == false
  end
end
