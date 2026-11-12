defmodule Exnode.P2P.FilterBatchTest do
  use Exnode.NodeCase
  import Bitwise

  alias Exnode.Chain.State
  alias Exnode.Codec.Block
  alias Exnode.Index.BlockFilter, as: Index
  alias Exnode.P2P.Message
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  test "BIP157 range requests are served from the caller, including the previous header", %{
    tmp_dir: dir
  } do
    %{n: n} = TestNode.start(dir, block_filter_index: true, peer_block_filters: true)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)
    stop = List.last(bs).header.hash
    :ok = Index.sync_to(n.filter_index, stop)

    hashes = [
      Exnode.ChainParams.get(:regtest).genesis.header.hash | Enum.map(bs, & &1.header.hash)
    ]

    filters = Enum.map(hashes, &Index.get(n.filter_index, &1))
    {:ok, _, prev_header} = hd(filters)

    expected = %{
      filter_type: 0,
      stop_hash: stop,
      prev_header: prev_header,
      filter_hashes: for({:ok, f, _} <- tl(filters), do: Exnode.BlockFilter.filter_hash(f))
    }

    {"cfheaders", encoded} = Message.encode({:cfheaders, expected})
    expected_raw = IO.iodata_to_binary(encoded)

    {_, sock} =
      FakePeer.connect_from(n,
        node: %{filter_index: n.filter_index, services: 9 ||| Message.service(:compact_filters)}
      )

    _ = FakePeer.recv(sock, ["verack"], 1)
    index_pid = GenServer.whereis(n.filter_index)
    :erlang.trace(index_pid, true, [:receive])

    :ok =
      FakePeer.send_msgs(
        sock,
        {:getcfheaders, %{filter_type: 0, start_height: 1, stop_hash: stop}}
      )

    assert [{"cfheaders", ^expected_raw}] = FakePeer.recv(sock, ["cfheaders"], 1)

    :ok =
      FakePeer.send_msgs(
        sock,
        {:getcfilters, %{filter_type: 0, start_height: 148, stop_hash: stop}}
      )

    got = FakePeer.recv(sock, ["cfilter"], 3)
    # Reads run in the peer: the index process is not called.
    refute_receive {:trace, ^index_pid, :receive, {:"$gen_call", _, _}}, 100

    expected =
      for {hash, {:ok, filter, _}} <- Enum.zip(Enum.take(hashes, -3), Enum.take(filters, -3)) do
        {cmd, payload} =
          Message.encode({:cfilter, %{filter_type: 0, block_hash: hash, filter: filter}})

        {cmd, IO.iodata_to_binary(payload)}
      end

    assert got == expected
    :erlang.trace(index_pid, false, [:receive])
    # Batch results retain duplicates and missing slots.
    assert Index.get_many(n.filter_index, [stop, <<9::256>>, stop]) ==
             [List.last(filters), :not_found, List.last(filters)]
  end

  # getcfheaders / getcfcheckpt read the 64-byte summary
  # records, never the filters; an index built before them is backfilled.
  test "cfheaders and cfcheckpt need no filter reads; summaries are backfilled", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir, block_filter_index: true, peer_block_filters: true)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)
    stop = List.last(bs).header.hash
    :ok = Index.sync_to(n.filter_index, stop)
    kv = :persistent_term.get({Index, n.filter_index})

    hashes = [
      Exnode.ChainParams.get(:regtest).genesis.header.hash | Enum.map(bs, & &1.header.hash)
    ]

    summaries = Index.get_headers(n.filter_index, hashes)
    assert Enum.all?(summaries, &match?({:ok, _, _}, &1))

    {_, sock} =
      FakePeer.connect_from(n,
        node: %{filter_index: n.filter_index, services: 9 ||| Message.service(:compact_filters)}
      )

    _ = FakePeer.recv(sock, ["verack"], 1)

    :ok =
      FakePeer.send_msgs(
        sock,
        {:getcfheaders, %{filter_type: 0, start_height: 1, stop_hash: stop}}
      )

    [{"cfheaders", before}] = FakePeer.recv(sock, ["cfheaders"], 1)

    # Without the filters, cfheaders is answered identically.
    :ok = Exnode.Store.KV.write(kv, for(h <- hashes, do: {:delete, :filters, "f" <> h}))

    :ok =
      FakePeer.send_msgs(
        sock,
        {:getcfheaders, %{filter_type: 0, start_height: 1, stop_hash: stop}}
      )

    assert [{"cfheaders", ^before}] = FakePeer.recv(sock, ["cfheaders"], 1)
    assert Index.get_many(n.filter_index, [stop]) == [:not_found]
    assert Index.get_headers(n.filter_index, hashes) == summaries
    :ok = FakePeer.send_msgs(sock, {:getcfcheckpt, %{filter_type: 0, stop_hash: stop}})
    assert [{"cfcheckpt", _}] = FakePeer.recv(sock, ["cfcheckpt"], 1)
  end

  test "an index without summary records is backfilled", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir, block_filter_index: true)
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    for b <- bs, do: {:ok, :connected} = State.submit_block(n.chain_state, b)
    State.commit_now(n.chain_state)
    stop = List.last(bs).header.hash
    :ok = Index.sync_to(n.filter_index, stop)
    kv = :persistent_term.get({Index, n.filter_index})

    hashes = [
      Exnode.ChainParams.get(:regtest).genesis.header.hash | Enum.map(bs, & &1.header.hash)
    ]

    summaries = Index.get_headers(n.filter_index, hashes)

    # As an index built before the summaries existed.
    :ok =
      Exnode.Store.KV.write(
        kv,
        [{:delete, :filters, "sfill"} | for(h <- hashes, do: {:delete, :filters, "s" <> h})]
      )

    # Missing summaries fall back to the filters meanwhile.
    assert Index.get_headers(n.filter_index, hashes) == summaries
    wait_until(fn -> Exnode.Store.KV.get(kv, :filters, "sfill") == {:ok, "done"} end)
    assert Enum.all?(hashes, &match?({:ok, _}, Exnode.Store.KV.get(kv, :filters, "s" <> &1)))
    assert Index.get_headers(n.filter_index, hashes) == summaries
  end
end
