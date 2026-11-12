defmodule Exnode.ShadowTest do
  use ExUnit.Case, async: true

  alias Exnode.Codec.Block
  alias Exnode.Shadow
  alias Exnode.Test.BlockBuilder, as: BB

  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  # Regtest halves every 150 blocks (kernel/chainparams.cpp CRegTestParams).
  @subsidy_after_150 25 * 100_000_000

  @moduletag :tmp_dir

  test "validates regtest blocks: chain, crafted valid, overpay, mutated", %{tmp_dir: dir} do
    {:ok, sh} = Shadow.start_link(chain: :regtest, datadir: dir)

    blocks =
      @chain
      |> BB.read_chain()
      |> Enum.map(fn raw ->
        {:ok, b} = Block.decode_exact(raw)
        b
      end)

    assert length(blocks) == 150

    for {b, h} <- Enum.with_index(blocks, 1) do
      assert {:ok, v} = Shadow.process_block(sh, b.raw)
      assert v.rc == 0 and v.new_block
      assert v.events == [{b.header.hash, :valid, :unset}], "block #{h}: #{inspect(v.events)}"
      assert v.tip == {h, b.header.hash}
    end

    tip = List.last(blocks).header
    [b1, b2 | _] = blocks

    # 151: valid block built in Elixir, spending two matured OP_TRUE coinbases.
    tx1 = BB.spend_op_true(hd(b1.txs).txid, 0, 50 * 100_000_000)
    tx2 = BB.spend_op_true(hd(b2.txs).txid, 0, 50 * 100_000_000)
    cb = BB.coinbase(151, @subsidy_after_150)

    # CVE-2012-2459: [cb, tx1, tx2, tx2] has the same merkle root as [cb, tx1, tx2].
    mutated = BB.build(tip, [cb, tx1, tx2, tx2], merkle_txs: [cb, tx1, tx2])
    assert {:ok, v} = Shadow.process_block(sh, mutated.raw)
    assert [{h, :invalid, :mutated}] = v.events
    assert h == mutated.header.hash
    assert v.tip == {150, tip.hash}

    # The honest block with the same header must still be accepted (mutation
    # must not mark the hash permanently invalid).
    honest = BB.build(tip, [cb, tx1, tx2])
    assert honest.header.hash == mutated.header.hash
    assert {:ok, v} = Shadow.process_block(sh, honest.raw)
    assert v.events == [{honest.header.hash, :valid, :unset}]
    assert v.tip == {151, honest.header.hash}

    # 152: coinbase pays one satoshi too much -> bad-cb-amount (consensus).
    over = BB.build(honest.header, [BB.coinbase(152, @subsidy_after_150 + 1)])
    assert {:ok, v} = Shadow.process_block(sh, over.raw)
    assert [{_, :invalid, :consensus}] = v.events
    assert v.tip == {151, honest.header.hash}

    assert {:error, :bad_block_encoding} = Shadow.process_block(sh, <<1, 2, 3>>)
    assert {:ok, {151, _}} = Shadow.tip(sh)
  end

  test "state persists across restarts of the shadow process", %{tmp_dir: dir} do
    {:ok, sh} = Shadow.start_link(chain: :regtest, datadir: dir)
    [b | _] = BB.read_chain(@chain)
    assert {:ok, %{tip: {1, _}}} = Shadow.process_block(sh, b)
    Shadow.stop(sh)
    {:ok, sh} = Shadow.start_link(chain: :regtest, datadir: dir)
    assert {:ok, {1, _}} = Shadow.tip(sh)
  end

  test "exnode closing the pipe mid-response: the shadow still flushes Core's state", %{
    tmp_dir: dir
  } do
    blocks = @chain |> BB.read_chain()
    exe = Path.join(:code.priv_dir(:exnode), "native/shadow_validator")

    port =
      Port.open({:spawn_executable, exe}, [
        {:packet, 4},
        :binary,
        :exit_status,
        args: ["regtest", dir]
      ])

    {:os_pid, os_pid} = Port.info(port, :os_pid)

    for raw <- Enum.take(blocks, 49) do
      send(port, {self(), {:command, <<1, raw::binary>>}})
      assert_receive {^port, {:data, <<0, _::binary>>}}, 10_000
    end

    # Block 50 is sent and the port closed before its response is read: the
    # shadow's write hits a closed pipe (EPIPE, formerly a fatal SIGPIPE).
    send(port, {self(), {:command, <<1, Enum.at(blocks, 49)::binary>>}})
    Port.close(port)
    # The shadow process exits (it flushes Core's state first).
    alive? = fn ->
      match?({_, 0}, System.cmd("kill", ["-0", "#{os_pid}"], stderr_to_stdout: true))
    end

    Exnode.Test.Wait.wait_until(fn -> not alive?.() end, 120_000, 50)

    # Restart: Core's flushed state has all 50 blocks.
    {:ok, sh} = Shadow.start_link(chain: :regtest, datadir: dir)
    assert {:ok, {50, _}} = Shadow.tip(sh)
  end
end
