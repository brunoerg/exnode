defmodule Exnode.Chain.HeadersWriterTest do
  @moduledoc """
  `Headers` persists through `Headers.Writer`, so accepting headers never
  waits on the KV (whose writes queue behind a chain-state commit). The
  writes still land, in order, and none is lost on an orderly stop or when
  `Headers` dies.
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp headers do
    for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1).header
  end

  defp writer(hs), do: :sys.get_state(hs).writer

  # Resumes the suspended writer once a call matching `call?` is queued
  # behind the writes it holds (resumes anyway after 5 s, so a failing test
  # does not hang).
  defp resume_once_called(w, call?) do
    spawn(fn ->
      Exnode.Test.Wait.until?(fn ->
        {:messages, msgs} = Process.info(w, :messages)
        Enum.any?(msgs, call?)
      end)

      :sys.resume(w)
    end)
  end

  defp persisted(kv), do: KV.fold_keys(kv, :headers, <<>>, MapSet.new(), &MapSet.put(&2, &1))

  defp within(ms, fun) do
    task = Task.async(fun)

    case Task.yield(task, ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      _ -> flunk("did not return within #{ms} ms (waited on the KV write?)")
    end
  end

  setup %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    %{kv: kv}
  end

  test "headers are accepted while the KV write is held up, and land once it proceeds",
       %{kv: kv} do
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    hdrs = headers()
    w = writer(hs)

    # Stands in for RocksDB holding the write behind a long commit.
    :ok = :sys.suspend(w)

    try do
      assert {:ok, %{height: 150}} = within(2_000, fn -> Headers.process_headers(hs, hdrs) end)
      assert HeaderIndex.best(Headers.index(hs)).hash == List.last(hdrs).hash
      refute MapSet.member?(persisted(kv), List.last(hdrs).hash)
    after
      :sys.resume(w)
    end

    :ok = Headers.flush(hs)
    assert MapSet.subset?(MapSet.new(hdrs, & &1.hash), persisted(kv))
  end

  test "an orderly stop writes everything queued", %{kv: kv} do
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    hdrs = headers()
    w = writer(hs)
    :ok = :sys.suspend(w)
    {:ok, _} = Headers.process_headers(hs, hdrs)
    # terminate/2 waits for the writer, which drains once resumed.
    resume_once_called(w, &match?({:"$gen_call", _, :stop}, &1))
    :ok = GenServer.stop(hs)
    refute Process.alive?(w)

    {:ok, hs2} = Headers.start_link(params: @p, kv: kv)
    assert HeaderIndex.best(Headers.index(hs2)).hash == List.last(hdrs).hash
  end

  # Not suspended here: a suspended process acts on its parent's exit at
  # once (sys), which a running writer never sees ahead of queued writes.
  test "writes queued before Headers is killed still land", %{kv: kv} do
    Process.flag(:trap_exit, true)
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    hdrs = headers()
    w = writer(hs)
    ref = Process.monitor(w)
    # One write per header, then killed right after the last reply.
    for h <- hdrs, do: {:ok, _} = Headers.process_headers(hs, [h])
    Process.exit(hs, :kill)
    assert_receive {:DOWN, ^ref, :process, ^w, :killed}, 5_000

    {:ok, hs2} = Headers.start_link(params: @p, kv: kv)
    assert HeaderIndex.best(Headers.index(hs2)).hash == List.last(hdrs).hash
    assert MapSet.subset?(MapSet.new(hdrs, & &1.hash), persisted(kv))
  end

  test "a failed mark is not overtaken by an older queued put", %{kv: kv} do
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    hdrs = headers()
    bad = Enum.at(hdrs, 100)
    fallback = Enum.at(hdrs, 99)

    # The puts stay queued behind the suspended writer; the mark queues after them.
    w = writer(hs)
    :ok = :sys.suspend(w)
    {:ok, _} = Headers.process_headers(hs, hdrs)
    resume_once_called(w, &match?({:"$gen_call", _, {:write, _}}, &1))
    :ok = Headers.invalidate(hs, bad.hash, fallback.hash)
    :ok = GenServer.stop(hs)

    {:ok, hs2} = Headers.start_link(params: @p, kv: kv)
    idx = Headers.index(hs2)
    assert HeaderIndex.lookup(idx, bad.hash).status == :failed
    assert HeaderIndex.lookup(idx, List.last(hdrs).hash).status == :failed
    assert HeaderIndex.best(idx).hash == fallback.hash
  end
end
