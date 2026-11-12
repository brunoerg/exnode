defmodule Exnode.DoS.GetblocktxnDecodeTest do
  @moduledoc """
  Regression: `getblocktxn` indexes are `uint16_t` in Core
  (blockencodings.h, DifferenceFormatter throws once an index passes 65535).
  Before the fix one 3 MB message decoded into a list of millions of
  integers (~126 MB) in the peer process and was then silently ignored.
  Now such a payload is refused before anything is built, and an empty
  index list disconnects, as in Core.
  """
  use Exnode.NodeCase
  @moduletag :dos

  alias Exnode.Codec.CompactSize
  alias Exnode.P2P.CompactBlock

  @n 3_000_000

  defp payload(n, diffs),
    do:
      <<:crypto.strong_rand_bytes(32)::binary, IO.iodata_to_binary(CompactSize.encode(n))::binary,
        diffs::binary>>

  test "decode refuses a count or an index beyond uint16" do
    # 3M zero diffs: the count alone is over the bound.
    assert {:error, :malformed} =
             CompactBlock.decode_getblocktxn(payload(@n, :binary.copy(<<0>>, @n)))

    # 65,537 indexes would need index 65,536.
    assert {:error, :malformed} =
             CompactBlock.decode_getblocktxn(payload(65_537, :binary.copy(<<0>>, 65_537)))

    # A single index past 65,535.
    big = IO.iodata_to_binary(CompactSize.encode(65_536))
    assert {:error, :malformed} = CompactBlock.decode_getblocktxn(payload(1, big))

    # The bounds themselves still decode.
    {:ok, _, idx} = CompactBlock.decode_getblocktxn(payload(65_536, :binary.copy(<<0>>, 65_536)))
    assert length(idx) == 65_536 and List.last(idx) == 65_535
    top = IO.iodata_to_binary(CompactSize.encode(65_535))
    assert {:ok, _, [65_535]} = CompactBlock.decode_getblocktxn(payload(1, top))
  end

  test "an oversized getblocktxn costs no memory spike; an empty one disconnects", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    {pid, sock} = FakePeer.connect_from(n)
    FakePeer.recv(sock, ["verack"], 1)

    test = self()
    sampler = spawn(fn -> sample(pid, 0, test) end)
    ref = Process.monitor(pid)
    :ok = FakePeer.send_msgs(sock, [{:getblocktxn, payload(@n, :binary.copy(<<0>>, @n))}])
    assert_receive {:DOWN, ^ref, _, _, _}, 10_000
    send(sampler, :stop)
    assert_receive {:peak, peak}, 2_000
    IO.puts("peer process peak memory on a 3 MB getblocktxn: #{div(peak, 1_000_000)} MB")
    assert peak < 40_000_000

    {pid2, sock2} = FakePeer.connect_from(n)
    FakePeer.recv(sock2, ["verack"], 1)
    ref2 = Process.monitor(pid2)
    :ok = FakePeer.send_msgs(sock2, [{:getblocktxn, payload(0, <<>>)}])
    assert_receive {:DOWN, ^ref2, _, _, {:shutdown, :empty_getblocktxn}}, 5_000
  end

  defp sample(pid, peak, test) do
    receive do
      :stop -> send(test, {:peak, peak})
    after
      1 ->
        m =
          case :erlang.process_info(pid, :memory) do
            {:memory, m} -> m
            _ -> 0
          end

        sample(pid, max(m, peak), test)
    end
  end
end
