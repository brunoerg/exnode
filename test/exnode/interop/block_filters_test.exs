defmodule Exnode.Interop.BlockFiltersTest do
  @moduledoc """
  BIP158 filters and BIP157 serving, against bitcoind
  v32.1 with `-blockfilterindex=1 -peerblockfilters=1`.

  * `getblockfilter` (filter and header) equal at every height, after a reorg too.
  * A raw P2P client sends the same `getcfilters`, `getcfheaders` and
    `getcfcheckpt` to both nodes; the replies must be byte-identical.
  * An invalid request (unknown stop hash) disconnects, as in Core.
  """
  use Exnode.InteropCase

  import Exnode.Test.Coins, only: [hex: 1, p2wsh: 0]

  alias Exnode.Crypto.Hash
  alias Exnode.P2P.Frame

  @moduletag timeout: 900_000
  @moduletag bitcoind: ["-blockfilterindex=1", "-peerblockfilters=1"]
  @magic <<0xFA, 0xBF, 0xB5, 0xDA>>

  # --- a minimal P2P client --------------------------------------------------------

  defp connect(port) do
    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)

    v =
      FakePeer.version(
        version: 70016,
        services: 0,
        user_agent: "/filter-test/",
        addr_recv: %{services: 0, net: :ipv4, addr: <<127, 0, 0, 1>>, port: port}
      )

    send_msg(sock, {:version, v})
    {sock, buf} = await(sock, "verack", <<>>)
    send_msg(sock, :verack)
    {sock, buf}
  end

  defp send_msg(sock, msg), do: :ok = FakePeer.send_msgs(sock, msg, @magic)

  # Collects frames until `count` messages named `cmd` arrived; returns their payloads.
  defp collect(sock, buf, cmd, count, acc \\ []) do
    if length(acc) == count do
      {Enum.reverse(acc), buf}
    else
      case Frame.decode(@magic, buf) do
        {:ok, ^cmd, payload, rest} ->
          collect(sock, rest, cmd, count, [payload | acc])

        {:ok, "ping", payload, rest} ->
          send_msg(sock, {:pong, :binary.decode_unsigned(payload, :little)})
          collect(sock, rest, cmd, count, acc)

        {:ok, _other, _payload, rest} ->
          collect(sock, rest, cmd, count, acc)

        :more ->
          case :gen_tcp.recv(sock, 0, 15_000) do
            {:ok, data} -> collect(sock, buf <> data, cmd, count, acc)
            {:error, reason} -> {:error, reason, Enum.reverse(acc)}
          end
      end
    end
  end

  defp await(sock, cmd, buf) do
    {[_], rest} = collect(sock, buf, cmd, 1)
    {sock, rest}
  end

  # A P2WSH(OP_TRUE) output and a v1 witness output (filters index both).
  defp spend({_, _, value} = coin, fee),
    do:
      Coins.tx([coin], [
        {div(value - fee, 2), p2wsh()},
        {div(value - fee, 2), <<0x51, 32>> <> :binary.copy(<<5>>, 32)}
      ])

  test "filters, headers and BIP157 replies equal bitcoind's", %{tmp_dir: dir, btc: btc} do
    Bitcoind.mine(btc, 30, "raw(#{hex(p2wsh())})")
    Bitcoind.mine(btc, 101)

    coins =
      for h <- 1..30,
          do:
            (
              b = Bitcoind.block(btc, h)
              {hd(b.txs).txid, 0, hd(hd(b.txs).outputs).value}
            )

    for chunk <- Enum.chunk_every(coins, 3),
        do: Bitcoind.generate_block(btc, Enum.map(chunk, &spend(&1, 1_000)), "raw(51)")

    Bitcoind.mine(btc, 1_010 - Bitcoind.json(btc, ["getblockcount"]) + 5)

    %{n: n, port: port} =
      TestNode.start(Path.join(dir, "ex"),
        connect: [{"127.0.0.1", btc.p2p}],
        listen: 0,
        block_filter_index: true,
        peer_block_filters: true,
        rpc_port: rpc_port = TestNode.free_port(),
        rpc_user: "u",
        rpc_password: "p"
      )

    tip = Bitcoind.cli(btc, ["getbestblockhash"])

    assert Bitcoind.wait_until(
             fn -> Hash.to_hex(Exnode.Chain.State.tip(n.chain_state).hash) == tip end,
             120_000
           )

    :ok = Exnode.Index.BlockFilter.sync_to(n.filter_index, Hash.from_hex(tip), 120_000)

    compare_filters = fn ->
      height = Bitcoind.json(btc, ["getblockcount"])

      for h <- 0..height do
        hash = Bitcoind.cli(btc, ["getblockhash", "#{h}"])
        core = Bitcoind.json(btc, ["getblockfilter", hash])
        {:ok, f, hdr} = Exnode.Index.BlockFilter.get(n.filter_index, Hash.from_hex(hash))
        assert hex(f) == core["filter"], "filter at #{h}"
        assert Hash.to_hex(hdr) == core["header"], "filter header at #{h}"
      end
    end

    compare_filters.()

    # The getblockfilter RPC answers as bitcoind's.
    :inets.start()

    rpc = fn hash ->
      body = Jason.encode!(%{jsonrpc: "1.0", id: 1, method: "getblockfilter", params: [hash]})
      hdrs = [{~c"authorization", ~c"Basic " ++ String.to_charlist(Base.encode64("u:p"))}]

      {:ok, {_, _, resp}} =
        :httpc.request(
          :post,
          {~c"http://127.0.0.1:#{rpc_port}/", hdrs, ~c"application/json", body},
          [],
          []
        )

      Jason.decode!(resp)["result"]
    end

    for h <- [0, 1, 500, 1000] do
      hash = Bitcoind.cli(btc, ["getblockhash", "#{h}"])
      assert rpc.(hash) == Bitcoind.json(btc, ["getblockfilter", hash]), "getblockfilter at #{h}"
    end

    # BIP157 over P2P: same requests to both nodes, byte-identical replies.
    stop = Hash.from_hex(tip)
    stop_500 = Hash.from_hex(Bitcoind.cli(btc, ["getblockhash", "500"]))

    replies = fn p2p_port ->
      {sock, buf} = connect(p2p_port)
      send_msg(sock, {:getcfilters, %{filter_type: 0, start_height: 1, stop_hash: stop_500}})
      {filters, buf} = collect(sock, buf, "cfilter", 500)
      send_msg(sock, {:getcfheaders, %{filter_type: 0, start_height: 10, stop_hash: stop}})
      {[headers], buf} = collect(sock, buf, "cfheaders", 1)
      send_msg(sock, {:getcfcheckpt, %{filter_type: 0, stop_hash: stop}})
      {[checkpt], _} = collect(sock, buf, "cfcheckpt", 1)
      :gen_tcp.close(sock)
      {filters, headers, checkpt}
    end

    {cf, ch, cc} = replies.(btc.p2p)
    {ef, eh, ec} = replies.(port)
    assert length(ef) == 500
    assert ef == cf, "cfilter replies differ"
    assert eh == ch, "cfheaders reply differs"
    assert ec == cc, "cfcheckpt reply differs"

    # Unknown stop hash: Core disconnects.
    {sock, buf} = connect(port)
    send_msg(sock, {:getcfilters, %{filter_type: 0, start_height: 0, stop_hash: <<9::256>>}})
    assert {:error, :closed, []} = collect(sock, buf, "cfilter", 1)

    # A reorg: filters follow the new chain.
    Bitcoind.cli(btc, [
      "invalidateblock",
      Bitcoind.cli(btc, ["getblockhash", "#{Bitcoind.json(btc, ["getblockcount"]) - 2}"])
    ])

    for _ <- 1..4, do: Bitcoind.json(btc, ["generateblock", "raw(52)", "[]"])
    tip2 = Bitcoind.cli(btc, ["getbestblockhash"])

    assert Bitcoind.wait_until(
             fn -> Hash.to_hex(Exnode.Chain.State.tip(n.chain_state).hash) == tip2 end,
             60_000
           )

    :ok = Exnode.Index.BlockFilter.sync_to(n.filter_index, Hash.from_hex(tip2), 60_000)
    compare_filters.()
  end
end
