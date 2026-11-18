defmodule Exnode.DoS.DecodeAmplificationTest do
  @moduledoc """
  Regression: a decoded message is
  several times its wire size. Measured on 4 MB block payloads:

  * a realistic segwit block ~6.5 B of heap per wire byte;
  * ~444k minimal outputs ~11 B/B, ~78k minimal txs ~10 B/B;
  * one input with ~4M empty witness items 45 B/B held, ~50 B/B at the peak
    (a fresh empty binary per item).

  Every Peer decodes its own messages, in parallel, so ~190 inbound peers
  releasing one such message each reached tens of GB: a remote OOM. Core
  decodes one message at a time on one thread.

  Fixed by: the empty byte vector decoding to the shared literal (18.8 B/B
  held for the witness bomb), and the node-wide `DecodeBudget`. A message of
  64 KiB or more is decoded and handled while it holds its size of the
  budget, so concurrent large decodes are bounded node-wide.

  The witness payload is consensus-serialization-valid (a non-empty witness
  stack, so `HasWitness` is true and no "superfluous witness record" applies)
  and fills `MAX_PROTOCOL_MESSAGE_LENGTH` (4,000,000). It is also how a
  consensus-valid block can look (witness stacks spending unknown witness
  versions are not limited), so decoding must keep working for it.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Codec.{Block, CompactSize, Tx}
  alias Exnode.P2P.{DecodeBudget, Frame}

  @magic Exnode.ChainParams.get(:regtest).magic
  @max_payload 4_000_000
  # Bytes of the block payload outside the witness items: header 80, tx
  # count 1, version 4, marker/flag 2, vin count 1, input 41, vout count 1,
  # output 9, witness count 5, locktime 4.
  @overhead 148
  @items @max_payload - @overhead

  # One segwit tx: 1 input whose witness stack is `n` empty items, 1 output
  # with an empty scriptPubKey.
  defp witness_bomb_tx(n) do
    IO.iodata_to_binary([
      <<2::little-32, 0x00, 0x01>>,
      <<1, :crypto.strong_rand_bytes(32)::binary, 0::little-32, 0, 0xFFFFFFFF::little-32>>,
      <<1, 1_000::little-64, 0>>,
      CompactSize.encode(n),
      :binary.copy(<<0>>, n),
      <<0::little-32>>
    ])
  end

  defp witness_bomb_block(n) do
    header =
      <<4::little-32, :crypto.strong_rand_bytes(32)::binary,
        :crypto.strong_rand_bytes(32)::binary, 1_700_000_000::little-32, 0x207FFFFF::little-32,
        0::little-32>>

    header <> <<1>> <> witness_bomb_tx(n)
  end

  # Runs `f` in a new process; returns the memory it holds for f's result
  # (heap plus referenced off-heap binaries, after a GC).
  defp held_memory(f) do
    parent = self()

    spawn_link(fn ->
      result = f.()
      :erlang.garbage_collect()
      {:memory, heap} = Process.info(self(), :memory)
      {:binary, bins} = Process.info(self(), :binary)
      send(parent, {:held, heap + Enum.sum(for {_, size, _} <- bins, do: size)})
      _ = :erlang.phash2(result)
    end)

    receive do
      {:held, n} -> n
    after
      60_000 -> flunk("decode did not finish")
    end
  end

  test "the attack payloads are well-formed and at the message size limit" do
    block = witness_bomb_block(@items)
    assert byte_size(block) == @max_payload
    assert {:ok, %Block{txs: [tx]}} = Block.decode_exact(block)
    assert [%{witness: w}] = tx.inputs
    assert length(w) == @items
    assert Enum.all?(w, &(&1 == <<>>))

    assert {:ok, %Tx{}} = Tx.decode_exact(witness_bomb_tx(@items))
  end

  test "an empty witness item costs one list cell, not a binary of its own" do
    for {name, payload, decode} <- [
          {"block", witness_bomb_block(@items), &Block.decode_exact/1},
          {"tx", witness_bomb_tx(@items), &Tx.decode_exact/1}
        ] do
      held = held_memory(fn -> decode.(payload) end)
      per_byte = held / byte_size(payload)

      IO.puts(
        "#{name} decode: #{byte_size(payload)} B held in #{held} B (#{Float.round(per_byte, 1)} B/B)"
      )

      # 16 B list cell per item + the payload: ~18.8. A binary per item: ~45.
      assert per_byte < 24
    end
  end

  describe "DecodeBudget" do
    setup do
      name = :"decode_budget_#{System.unique_integer([:positive])}"
      start_supervised!({DecodeBudget, name: name, bytes: 1_000_000})
      %{b: name}
    end

    test "small messages and a nil server bypass the budget", %{b: b} do
      assert DecodeBudget.with_budget(nil, 10_000_000, fn -> :ran end) == :ran
      assert DecodeBudget.with_budget(b, DecodeBudget.min_bytes() - 1, fn -> :ran end) == :ran
      assert %{available: 1_000_000, holders: 0} = DecodeBudget.info(b)
    end

    test "a request waits until the bytes are released, then runs", %{b: b} do
      test = self()

      holder =
        spawn(fn ->
          DecodeBudget.with_budget(b, 700_000, fn ->
            send(test, :holding)
            receive do: (:go -> :ok)
          end)
        end)

      assert_receive :holding
      waiter = Task.async(fn -> DecodeBudget.with_budget(b, 700_000, fn -> :ran end) end)
      Process.sleep(50)
      assert %{available: 300_000, holders: 1, waiting: 1} = DecodeBudget.info(b)
      assert Task.yield(waiter, 0) == nil

      send(holder, :go)
      assert Task.await(waiter) == :ran
      assert %{available: 1_000_000, holders: 0, waiting: 0} = DecodeBudget.info(b)
    end

    test "a holder that dies releases its bytes; a request over the total takes it all", %{b: b} do
      test = self()

      holder =
        spawn(fn ->
          DecodeBudget.with_budget(b, 5_000_000, fn ->
            send(test, :holding)
            Process.sleep(:infinity)
          end)
        end)

      assert_receive :holding
      assert %{available: 0, holders: 1} = DecodeBudget.info(b)
      Process.exit(holder, :kill)
      assert DecodeBudget.with_budget(b, 100_000, fn -> :ran end) == :ran
      assert %{available: 1_000_000, holders: 0} = DecodeBudget.info(b)
    end

    test "a waiter that dies leaves the queue", %{b: b} do
      test = self()

      holder =
        spawn(fn ->
          DecodeBudget.with_budget(b, 1_000_000, fn ->
            send(test, :holding)
            receive do: (:go -> :ok)
          end)
        end)

      assert_receive :holding
      waiter = spawn(fn -> DecodeBudget.with_budget(b, 100_000, fn -> :ok end) end)
      Process.sleep(50)
      assert %{waiting: 1} = DecodeBudget.info(b)
      Process.exit(waiter, :kill)
      Process.sleep(50)
      assert %{waiting: 0} = DecodeBudget.info(b)
      send(holder, :go)
      Process.sleep(50)
      assert %{available: 1_000_000, holders: 0} = DecodeBudget.info(b)
    end

    test "with no server running the caller is told, and fun does not run" do
      assert DecodeBudget.with_budget(:no_such_budget, 1_000_000, fn -> flunk("ran") end) ==
               :unavailable
    end
  end

  @attackers 6

  test "peers releasing witness-item blocks together decode them one budget at a time",
       %{tmp_dir: dir} do
    # A budget of one maximum-size message: the decodes must not overlap.
    %{n: n} = TestNode.start(dir, decode_budget_bytes: @max_payload)
    frame = IO.iodata_to_binary(Frame.encode(@magic, "block", witness_bomb_block(@items)))
    head = binary_part(frame, 0, byte_size(frame) - 1)
    last = binary_part(frame, byte_size(frame), -1)

    # One peer alone: the peak of one decode.
    [single] = connect(n, 1)
    single_peak = release_and_measure([single], head, last)
    IO.puts("one peer, one 4 MB witness-item block: peak #{div(single_peak, 1_000_000)} MB")

    # Several peers, each with the whole frame but its last byte buffered,
    # released at once: the sum of their memory, sampled together.
    peers = connect(n, @attackers)
    total_peak = release_and_measure(peers, head, last)

    IO.puts(
      "#{@attackers} peers released together: summed peak #{div(total_peak, 1_000_000)} MB " <>
        "(#{Float.round(total_peak / single_peak, 2)}x one decode)"
    )

    # Overlapping decodes approach @attackers x; one at a time stays near 1x.
    assert total_peak < 2 * single_peak
  end

  defp connect(n, k) do
    for _ <- 1..k do
      {pid, sock, ref} = FakePeer.connect_from(n, monitor: true)
      FakePeer.recv(sock, ["verack"], 1)
      %{pid: pid, sock: sock, ref: ref}
    end
  end

  # Sends every peer all but the last byte of the frame, then the last bytes
  # together; samples the sum of the peers' memory until every peer has
  # handled its block (each is then disconnected: the block's parent is
  # unknown). Returns the peak sum.
  defp release_and_measure(peers, head, last) do
    for %{sock: s} <- peers, do: :ok = :gen_tcp.send(s, head)
    # Let every peer buffer its partial frame.
    Process.sleep(500)
    test = self()
    pids = for %{pid: p} <- peers, do: p
    sampler = spawn(fn -> sample(pids, 0, test) end)
    for %{sock: s} <- peers, do: :gen_tcp.send(s, last)

    for %{ref: ref} <- peers do
      assert_receive {:DOWN, ^ref, _, _, {:shutdown, {:misbehaving, "invalid block: " <> _}}},
                     120_000
    end

    send(sampler, :stop)
    assert_receive {:peak, peak}, 2_000
    peak
  end

  defp sample(pids, peak, test) do
    receive do
      :stop -> send(test, {:peak, peak})
    after
      1 ->
        total =
          Enum.sum(
            for p <- pids do
              case :erlang.process_info(p, :memory) do
                {:memory, m} -> m
                _ -> 0
              end
            end
          )

        sample(pids, max(total, peak), test)
    end
  end
end
