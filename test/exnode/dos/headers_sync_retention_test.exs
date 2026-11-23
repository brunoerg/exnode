defmodule Exnode.DoS.HeadersSyncRetentionTest do
  @moduledoc """
  Regression: the low-work headers sync buffers up to
  `redownload_buffer_size` (15,400 on mainnet) redownloaded headers per
  peer. Each header's 80-byte `raw` was a slice of the received `headers`
  payload, which may carry trailing bytes up to the 4 MB message limit
  (Core ignores them). A peer padding every `headers` message kept each
  ~4 MB payload alive for as long as one of its headers stayed buffered:
  8 padded messages pinned ~32 MB per peer, across all inbound peers
  during IBD. The buffer now holds copies of `raw`.
  """
  use ExUnit.Case, async: true
  @moduletag :dos

  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex
  alias Exnode.Consensus.Pow
  alias Exnode.P2P.{HeadersSync, Message}
  alias Exnode.Test.BlockBuilder, as: BB

  @p ChainParams.get(:regtest)
  @pad 1_000_000

  defp padded_headers(headers) do
    {"headers", payload} = Message.encode({:headers, headers})
    payload = IO.iodata_to_binary(payload) <> :binary.copy(<<0>>, @pad)
    {:ok, {:headers, decoded}} = Message.decode("headers", payload)
    decoded
  end

  test "buffered redownloaded headers do not keep the padded headers payload alive" do
    chain = Enum.scan(1..2000, @p.genesis.header, fn _, prev -> BB.next_header(prev) end)
    g = HeaderIndex.make_entry(@p.genesis.header, nil)
    min_work = g.chain_work + 1000 * Pow.bits_proof(0x207FFFFF)
    st = HeadersSync.new(@p, g, g.time, [g.hash], min_work, g.time + 1_000_000_000)

    {_, st} = HeadersSync.process_next_headers(st, chain, true)
    assert HeadersSync.state(st) == :redownload
    # Keep everything buffered: min work out of reach, buffer larger than the batch.
    st = %{st | minimum_required_work: min_work * 10, redownload_buffer_size: 15_400}

    {res, st} = HeadersSync.process_next_headers(st, padded_headers(chain), true)
    assert res.success and res.pow_validated_headers == []
    assert st.redownloaded_len == 2000

    pinned =
      st.redownloaded
      |> :queue.to_list()
      |> Enum.map(&:binary.referenced_byte_size(&1.raw))
      |> Enum.max()

    IO.puts("headers sync retention: a buffered header.raw references #{pinned} B")
    assert pinned == 80
  end
end
