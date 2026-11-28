defmodule Exnode.P2P.RequestedBlockTest do
  @moduledoc """
  The BLOCK message path passes Core's `fRequested` to the chain state:
  a block in flight in `BlockDownload` when it arrives is requested
  (`IsBlockRequested`), and skips `AcceptBlock`'s gates for unrequested
  blocks; one never requested does not. Here the gate is `fTooFarAhead`
  (more than 288 above the tip): the node holds blocks 152..440 but not 151,
  so the download requests 151 and then 441.., past the gate.
  """
  use Exnode.NodeCase

  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.P2P.BlockDownload
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  test "a block in flight is stored past the too-far-ahead gate; an unrequested one is not",
       %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)

    {more, _} =
      Enum.map_reduce(151..470, List.last(bs).header, fn h, prev ->
        b = BB.build(prev, [BB.coinbase(h, 25 * 100_000_000)])
        {b, b.header}
      end)

    at = fn h -> Enum.at(more, h - 151) end
    {:ok, _} = Headers.process_headers(n.headers, Enum.map(more, & &1.header))
    # Held, not connected (151 is missing): the download skips them.
    for h <- 152..440,
        do: {:ok, :stored} = State.submit_block(n.chain_state, at.(h), requested: true)

    {pid, sock} = FakePeer.connect_from(n, node: %{block_download: n.block_download})
    :erlang.trace_pattern({State, :check_block, 2}, true, [])
    :erlang.trace(:new_processes, true, [:call])
    :erlang.trace(pid, true, [:call])

    on_exit(fn ->
      :erlang.trace(:new_processes, false, [:call])
      :erlang.trace_pattern({State, :check_block, 2}, false, [])
    end)

    picked = BlockDownload.request(n.block_download, pid, List.last(more).header.hash)
    assert hd(picked) == at.(151).header.hash
    assert at.(441).header.hash in picked
    refute at.(460).header.hash in picked

    held? = fn h -> State.have_many(n.chain_state, [at.(h).header.hash]) |> MapSet.size() == 1 end
    # Unrequested 460 first: the same peer processes in order, so once 441
    # is held, 460 has been handled too.
    :ok = FakePeer.send_msgs(sock, [{:block, at.(460).raw}, {:block, at.(441).raw}])
    wait_until(fn -> held?.(441) end)
    refute held?.(460)
    assert Process.alive?(pid)
    refute Map.has_key?(BlockDownload.in_flight(n.block_download), at.(441).header.hash)
    assert_receive {:trace, _worker_or_peer, :call, {State, :check_block, [checked, _]}}
    assert checked.header.hash == at.(441).header.hash
    refute_receive {:trace, _, :call, {State, :check_block, _}}, 50
  end
end
