defmodule Exnode.P2P.HeadersSyncTest do
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex
  alias Exnode.Consensus.Pow
  alias Exnode.P2P.HeadersSync
  alias Exnode.Test.BlockBuilder, as: BB

  @p ChainParams.get(:regtest)

  # One shared chain of 3000 mined regtest headers from genesis.
  setup_all do
    headers =
      Enum.scan(1..3000, @p.genesis.header, fn _, prev -> BB.next_header(prev) end)

    %{chain: headers}
  end

  defp start(min_work_headers, opts \\ []) do
    g = HeaderIndex.make_entry(@p.genesis.header, nil)
    min_work = g.chain_work + min_work_headers * Pow.bits_proof(0x207FFFFF)
    now = Keyword.get(opts, :now, g.time + 1_000_000_000)
    HeadersSync.new(@p, g, g.time, [g.hash], min_work, now)
  end

  defp feed(st, headers, chunk \\ 2000) do
    headers
    |> Enum.chunk_every(chunk)
    |> Enum.reduce({st, [], []}, fn batch, {st, released, results} ->
      {res, st} = HeadersSync.process_next_headers(st, batch, length(batch) == 2000)
      {st, released ++ res.pow_validated_headers, results ++ [res]}
    end)
  end

  test "presync -> redownload -> all headers released in order once min work is seen twice", %{
    chain: chain
  } do
    st = start(2500)
    {st, released, results} = feed(st, chain)
    assert Enum.map(results, &{&1.success, &1.request_more}) == [{true, true}, {true, true}]
    assert released == []
    assert HeadersSync.state(st) == :redownload
    assert HeadersSync.next_headers_request_locator(st) == [@p.genesis_hash, @p.genesis_hash]

    {st, released, results} = feed(st, chain)
    assert List.last(results).success
    assert Enum.map(released, & &1.hash) == Enum.map(chain, & &1.hash)
    assert HeadersSync.state(st) == :final
  end

  test "redownload buffers headers until redownload_buffer_size is exceeded", %{chain: chain} do
    # Min work beyond the chain: presync never finishes, so test the buffer
    # directly. Reach redownload with a low threshold, then raise it.
    st = start(1000)
    {st, [], _} = feed(st, Enum.take(chain, 2000))
    assert HeadersSync.state(st) == :redownload

    st = %{
      st
      | minimum_required_work: st.minimum_required_work * 10,
        redownload_buffer_size: 1500
    }

    {res, st} = HeadersSync.process_next_headers(st, Enum.take(chain, 2000), true)
    assert res.success and res.request_more
    # 2000 buffered, 1500 kept: the oldest 500 are released.
    assert Enum.map(res.pow_validated_headers, & &1.hash) ==
             Enum.map(Enum.take(chain, 500), & &1.hash)

    assert st.redownloaded_len == 1500
  end

  test "commitment mismatch during redownload aborts", %{chain: chain} do
    st = start(2500)
    {st, _, _} = feed(st, chain)
    assert st.commitments_len > 0

    flipped =
      st.header_commitments |> :queue.to_list() |> Enum.map(&(1 - &1)) |> :queue.from_list()

    st = %{st | header_commitments: flipped}
    {st, released, results} = feed(st, chain)
    refute Enum.all?(results, & &1.success)
    assert released == []
    assert HeadersSync.state(st) == :final
  end

  test "an incomplete headers message during presync ends the sync", %{chain: chain} do
    {res, st} = HeadersSync.process_next_headers(start(2500), Enum.take(chain, 100), false)
    assert res.success and not res.request_more
    assert HeadersSync.state(st) == :final
  end

  test "headers that do not continue from the last one fail", %{chain: chain} do
    {res, st} =
      HeadersSync.process_next_headers(start(2500), Enum.drop(chain, 1) |> Enum.take(10), true)

    refute res.success
    assert HeadersSync.state(st) == :final
  end

  test "max commitments bounds memory: a long chain soon after chain start is rejected", %{
    chain: chain
  } do
    g = HeaderIndex.make_entry(@p.genesis.header, nil)
    # max_commitments = 6 * (now - mtp + 7200) / 275 = 6 * 100 / 275 = 2
    st = start(2500, now: g.time - 7200 + 100)
    assert st.max_commitments == 2
    {res, _st} = HeadersSync.process_next_headers(st, Enum.take(chain, 2000), true)
    refute res.success
  end

  test "a system clock far behind the chain start raises, as Core aborts" do
    g = HeaderIndex.make_entry(@p.genesis.header, nil)
    assert_raise RuntimeError, ~r/System clock/, fn -> start(1, now: g.time - 7201) end
  end
end
