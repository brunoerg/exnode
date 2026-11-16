defmodule Exnode.Chain.HeadersTest do
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp fixture_headers do
    for raw <- BB.read_chain(@chain) do
      {:ok, b} = Block.decode_exact(raw)
      b.header
    end
  end

  setup do
    {:ok, hs} = Headers.start_link(params: ChainParams.get(:regtest))
    headers = fixture_headers()
    {:ok, last} = Headers.process_headers(hs, headers)
    %{hs: hs, headers: headers, tip: List.last(headers), last: last}
  end

  test "bitcoind's 150 regtest headers are accepted in order", %{hs: hs, tip: tip, last: last} do
    assert last.height == 150 and last.hash == tip.hash
    assert Headers.best_header(hs).hash == tip.hash
  end

  test "retained header entries do not pin padded P2P payloads", %{tip: tip} do
    payload = tip.raw <> :binary.copy(<<0>>, 1_000_000)
    {h, _} = Exnode.Codec.Header.decode(payload)
    assert :binary.referenced_byte_size(h.raw) > 80
    entry = HeaderIndex.make_entry(h, nil)
    assert entry.raw == h.raw
    assert :binary.referenced_byte_size(entry.raw) == 80
    assert :binary.referenced_byte_size(entry.prev_hash) == 32
    assert :binary.referenced_byte_size(entry.hash) == 32
  end

  test "locator: 11 consecutive hashes, then doubling steps, ending at genesis", %{
    hs: hs,
    last: last
  } do
    idx = Headers.index(hs)
    heights = idx |> HeaderIndex.locator(last) |> Enum.map(&HeaderIndex.lookup(idx, &1).height)

    assert heights == [
             150,
             149,
             148,
             147,
             146,
             145,
             144,
             143,
             142,
             141,
             140,
             139,
             137,
             133,
             125,
             109,
             77,
             13,
             0
           ]
  end

  describe "reject reasons (ContextualCheckBlockHeader / AcceptBlockHeader)" do
    test "high-hash", %{hs: hs, tip: tip} do
      bad = BB.unmine_header(%{BB.next_header(tip) | nonce: 0})
      assert {:error, {:invalid_header, "high-hash"}, nil} = Headers.process_headers(hs, [bad])
    end

    test "bad-diffbits", %{hs: hs, tip: tip} do
      bad = BB.next_header(tip, bits: 0x207FFFFE)
      assert {:error, {:invalid_header, "bad-diffbits"}, nil} = Headers.process_headers(hs, [bad])
    end

    test "time-too-old: timestamp equal to median-time-past", %{hs: hs, tip: tip} do
      idx = Headers.index(hs)
      mtp = HeaderIndex.median_time_past(idx, HeaderIndex.best(idx))

      assert {:error, {:invalid_header, "time-too-old"}, nil} =
               Headers.process_headers(hs, [BB.next_header(tip, time: mtp)])

      assert {:ok, _} = Headers.process_headers(hs, [BB.next_header(tip, time: mtp + 1)])
    end

    test "time-too-new: more than 2h in the future", %{hs: hs, tip: tip} do
      h = BB.next_header(tip)

      assert {:error, {:time_future, "time-too-new"}, nil} =
               Headers.process_headers(hs, [h], now: h.time - 7201)

      assert {:ok, _} = Headers.process_headers(hs, [h], now: h.time - 7200)
    end

    test "bad-version once BIP34/66/65 are active (regtest: height 1)", %{hs: hs, tip: tip} do
      for v <- [1, 2, 3] do
        assert {:error, {:invalid_header, reason}, nil} =
                 Headers.process_headers(hs, [BB.next_header(tip, version: v)])

        assert reason == "bad-version(0x0000000#{v})"
      end

      assert {:error, {:invalid_header, "bad-version(0xffffffff)"}, nil} =
               Headers.process_headers(hs, [BB.next_header(tip, version: -1)])

      assert {:ok, _} = Headers.process_headers(hs, [BB.next_header(tip, version: 4)])
    end

    test "prev-blk-not-found", %{hs: hs, tip: tip} do
      orphan = BB.next_header(%{tip | hash: <<9::256>>})

      assert {:error, {:missing_prev, "prev-blk-not-found"}, nil} =
               Headers.process_headers(hs, [orphan])
    end

    test "too-little-chainwork when the anti-DoS PoW check was not done", %{hs: hs, tip: tip} do
      assert {:error, {:header_low_work, "too-little-chainwork"}, nil} =
               Headers.process_headers(hs, [BB.next_header(tip)], min_pow_checked: false)
    end

    test "processing stops at the first bad header and reports the last good one", %{
      hs: hs,
      tip: tip
    } do
      a = BB.next_header(tip)
      b = BB.next_header(a, bits: 0x207FFFFE)
      c = BB.next_header(b)

      assert {:error, {:invalid_header, "bad-diffbits"}, last} =
               Headers.process_headers(hs, [a, b, c])

      assert last.hash == a.hash
      assert HeaderIndex.lookup(Headers.index(hs), c.hash) == nil
    end

    test "already-known headers are accepted again without change", %{hs: hs, headers: headers} do
      assert {:ok, %{height: 150}} = Headers.process_headers(hs, headers)
    end
  end

  test "best header follows most work; on equal work the first seen wins", %{
    hs: hs,
    headers: headers,
    tip: tip
  } do
    fork_base = Enum.at(headers, 147)
    # Two-header fork from 148: reaches 150 too, equal work, so not selected.
    f1 = BB.next_header(fork_base, merkle_root: <<1::256>>)
    f2 = BB.next_header(f1)
    assert {:ok, %{height: 150}} = Headers.process_headers(hs, [f1, f2])
    assert Headers.best_header(hs).hash == tip.hash

    # Extending the fork to 151 makes it the best header (reorg of the height table).
    f3 = BB.next_header(f2)
    assert {:ok, %{height: 151}} = Headers.process_headers(hs, [f3])
    idx = Headers.index(hs)
    assert HeaderIndex.best(idx).hash == f3.hash
    assert HeaderIndex.hash_at(idx, 149) == f1.hash
    assert HeaderIndex.hash_at(idx, 148) == fork_base.hash
    # The old tip stays in the tree as a side chain; ancestor walks still work.
    old = HeaderIndex.lookup(idx, tip.hash)
    assert HeaderIndex.ancestor(idx, old, 148).hash == fork_base.hash

    assert HeaderIndex.last_common_ancestor(idx, old, HeaderIndex.best(idx)).hash ==
             fork_base.hash
  end

  @tag :tmp_dir
  test "headers persist across restarts", %{tmp_dir: dir, headers: headers, tip: tip} do
    {:ok, kv} = KV.open(dir)
    {:ok, hs} = Headers.start_link(params: ChainParams.get(:regtest), kv: kv)
    {:ok, _} = Headers.process_headers(hs, headers)
    GenServer.stop(hs)
    {:ok, hs} = Headers.start_link(params: ChainParams.get(:regtest), kv: kv)
    best = Headers.best_header(hs)
    assert best.height == 150 and best.hash == tip.hash
  end
end
