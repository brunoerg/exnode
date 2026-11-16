defmodule Exnode.Chain.HeadersNoCallTest do
  @moduledoc """
  `Headers.index/1` and `Headers.best_header/1` must not call the Headers
  process for a registered server: it can be blocked for seconds (its KV
  writes queue behind a chain-state commit), and a 5 s call timeout there
  crashed `P2P.BlockDownload` (`select/3`) and with it the P2P subtree, on a
  mainnet IBD with large commit batches.

  The best header lives in ETS, so a handle taken earlier sees later best
  header changes.
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Codec.Block
  alias Exnode.P2P.BlockDownload
  alias Exnode.Test.BlockBuilder, as: BB

  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defmodule StubChain do
    use GenServer
    def init(tip), do: {:ok, tip}
    def handle_call(:tip, _f, tip), do: {:reply, tip, tip}
    def handle_call({:have_many, _}, _f, tip), do: {:reply, MapSet.new(), tip}
  end

  defp headers do
    for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1).header
  end

  defp start_headers(name) do
    {:ok, hs} = Headers.start_link(params: @p, name: name)
    hs
  end

  # Runs `fun` in another process; fails unless it returns within `ms`.
  defp within(ms, fun) do
    task = Task.async(fun)

    case Task.yield(task, ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      _ -> flunk("did not return within #{ms} ms (called the suspended Headers process?)")
    end
  end

  test "index/1 and best_header/1 answer while the Headers process is blocked" do
    name = :"headers_no_call_#{System.unique_integer([:positive])}"
    hs = start_headers(name)
    hdrs = headers()
    {:ok, _} = Headers.process_headers(hs, hdrs)
    tip = List.last(hdrs)

    :ok = :sys.suspend(hs)

    try do
      idx = within(1_000, fn -> Headers.index(name) end)
      assert HeaderIndex.best(idx).hash == tip.hash
      assert within(1_000, fn -> Headers.best_header(name) end).hash == tip.hash
    after
      :sys.resume(hs)
    end
  end

  test "a handle taken earlier reads the current best header" do
    name = :"headers_no_call_#{System.unique_integer([:positive])}"
    hs = start_headers(name)
    {first, rest} = Enum.split(headers(), 10)

    {:ok, _} = Headers.process_headers(hs, first)
    idx = Headers.index(name)
    assert HeaderIndex.best(idx).hash == List.last(first).hash

    {:ok, _} = Headers.process_headers(hs, rest)
    assert HeaderIndex.best(idx).hash == List.last(rest).hash
    assert HeaderIndex.best(idx).height == length(first) + length(rest)
  end

  test "BlockDownload picks blocks while the Headers process is blocked" do
    name = :"headers_no_call_#{System.unique_integer([:positive])}"
    hs = start_headers(name)
    hdrs = headers()
    {:ok, _} = Headers.process_headers(hs, hdrs)

    genesis = HeaderIndex.lookup(Headers.index(name), @p.genesis.header.hash)
    {:ok, chain} = GenServer.start_link(StubChain, genesis)

    {:ok, bd} =
      BlockDownload.start_link(
        headers: name,
        chain: chain,
        params: %{pow_target_spacing: 600},
        clock: Exnode.Clock.new()
      )

    Process.flag(:trap_exit, true)
    :ok = :sys.suspend(hs)

    try do
      # Before the fix: BlockDownload exited after 5 s (GenServer.call
      # timeout on Headers) and the request with it.
      picks = within(2_000, fn -> BlockDownload.request(bd, self(), List.last(hdrs).hash) end)
      assert picks != []
      assert Process.alive?(bd)
    after
      :sys.resume(hs)
    end
  end
end
