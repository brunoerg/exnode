defmodule Exnode.Interop.RPCShapesTest do
  @moduledoc """
  exnode's JSON-RPC answers equal bitcoind v32.1's.

  bitcoind (`-txindex=1`) builds a regtest chain with outputs of every
  script type and inputs with DER-signature pushes (sighash decoding in
  `asm`), plus a mempool with a chain. exnode syncs it over P2P. Both
  answer the same calls over HTTP JSON-RPC; the parsed results (or errors)
  must be equal, except for fields that are node-specific by nature, listed
  in `@node_specific`. For getpeerinfo and getnetworkinfo only the key sets
  are compared.
  """
  use Exnode.InteropCase
  import Exnode.Test.Coins, only: [hex: 1, p2wsh: 0, finalize: 1]

  alias Exnode.Codec.Tx
  alias Exnode.Crypto.Hash

  @moduletag timeout: 900_000
  @moduletag bitcoind: ["-txindex=1"]
  @ws_true <<0x51>>

  # Fields whose values legitimately differ between two nodes.
  @node_specific %{
    "getblockchaininfo" => ~w(verificationprogress size_on_disk initialblockdownload warnings),
    "getmempoolinfo" => ~w(usage loaded unbroadcastcount),
    "getmempoolentry" => ~w(time unbroadcast),
    "getrawmempool" => ~w(time unbroadcast),
    "testmempoolaccept" => ~w(reject-details)
  }

  defp p2sh_true, do: <<0xA9, 20>> <> Hash.hash160(<<0x51>>) <> <<0x87>>
  defp push(d) when byte_size(d) <= 75, do: <<byte_size(d)>> <> d
  defp push(d), do: <<0x4C, byte_size(d)>> <> d

  defp spend(coins, outs, opts \\ []) do
    ins =
      for {t, v, _, kind} <- coins do
        case kind do
          :wsh ->
            %Tx.In{
              prev_hash: t,
              prev_index: v,
              script_sig: <<>>,
              sequence: 0xFFFFFFFD,
              witness: [@ws_true]
            }

          {:sh, extra} ->
            %Tx.In{
              prev_hash: t,
              prev_index: v,
              script_sig: extra <> push(<<0x51>>),
              sequence: 0xFFFFFFFE,
              witness: []
            }
        end
      end

    finalize(%Tx{
      version: Keyword.get(opts, :version, 2),
      inputs: ins,
      outputs: for({v, s} <- outs, do: %Tx.Out{value: v, script_pubkey: s}),
      locktime: Keyword.get(opts, :locktime, 0)
    })
  end

  # Normalize for comparison: drop node-specific keys (recursively).
  defp strip(v, drop) when is_map(v),
    do: Map.new(Map.drop(v, drop), fn {k, x} -> {k, strip(x, drop)} end)

  defp strip(v, drop) when is_list(v), do: Enum.map(v, &strip(&1, drop))
  defp strip(v, _), do: v

  defp rpc(port, auth, method, params) do
    :inets.start()
    body = Jason.encode!(%{jsonrpc: "1.0", id: 1, method: method, params: params})
    hdrs = [{~c"authorization", ~c"Basic " ++ String.to_charlist(Base.encode64(auth))}]

    {:ok, {{_, _status, _}, _, resp}} =
      :httpc.request(
        :post,
        {~c"http://127.0.0.1:#{port}/", hdrs, ~c"application/json", body},
        [timeout: 60_000],
        []
      )

    r = Jason.decode!(resp)

    if r["error"],
      do: {:error, r["error"]["code"], r["error"]["message"]},
      else: {:ok, r["result"]}
  end

  test "RPC results equal bitcoind's", %{tmp_dir: dir, btc: btc} do
    Bitcoind.mine(btc, 20, "raw(#{hex(p2wsh())})")
    Bitcoind.mine(btc, 5, "raw(#{hex(p2sh_true())})")
    Bitcoind.mine(btc, 101)

    coin = fn h, kind ->
      b = Bitcoind.block(btc, h)
      {hd(b.txs).txid, 0, hd(hd(b.txs).outputs).value, kind}
    end

    # One output of every script type.
    pk33 = <<0x02>> <> :binary.copy(<<0x79>>, 32)
    pk65 = <<0x04>> <> :binary.copy(<<0x79>>, 64)
    hybrid = <<0x06>> <> :binary.copy(<<0x79>>, 64)
    # The secp256k1 generator's x (valid) and an x above p (invalid).
    gx = Base.decode16!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")

    spks = [
      push(pk33) <> <<0xAC>>,
      push(pk65) <> <<0xAC>>,
      push(hybrid) <> <<0xAC>>,
      <<0x76, 0xA9, 20, 0::160, 0x88, 0xAC>>,
      <<0xA9, 20, 1::160, 0x87>>,
      <<0, 20, 2::160>>,
      <<0, 32, 3::256>>,
      <<0x51, 32>> <> gx,
      <<0x51, 32>> <> :binary.copy(<<0xFF>>, 32),
      <<0x52>> <> push(pk33) <> push(pk65) <> <<0x52, 0xAE>>,
      <<0x51>> <> push(hybrid) <> <<0x51, 0xAE>>,
      <<0x6A, 4, 1, 2, 3, 4>>,
      <<0x6A>>,
      <<0x51, 0x52, 0x93>>,
      <<0x53, 2, 9, 9>>,
      <<0x51, 2, 0x4E, 0x73>>,
      <<0x4E, 1, 0>>
    ]

    fanout =
      spend([coin.(1, :wsh)], for(s <- spks, do: {10_000, s}) ++ [{49 * 100_000_000, p2wsh()}])

    # P2SH spends whose scriptSigs carry DER signature-looking pushes with each sighash byte.
    der =
      Base.decode16!(
        "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb",
        case: :lower
      )

    sh_spends =
      for {sighash, h} <- Enum.zip([0x01, 0x81, 0x03, 0x42], 21..24),
          do:
            spend([coin.(h, {:sh, push(der <> <<sighash>>) <> <<0x00, 0x4F>>})], [
              {40 * 100_000_000, p2wsh()}
            ])

    Bitcoind.generate_block(btc, [fanout | sh_spends], "raw(51)")
    Bitcoind.mine(btc, 2)

    # exnode syncs over P2P, with RPC on.
    # An OS-assigned free port (a random one collided with other test daemons).
    port = TestNode.free_port()

    %{n: n} =
      TestNode.start(Path.join(dir, "ex"),
        connect: [{"127.0.0.1", btc.p2p}],
        rpc_port: port,
        rpc_user: "u",
        rpc_password: "p"
      )

    tip = Bitcoind.cli(btc, ["getbestblockhash"])

    assert Bitcoind.wait_until(
             fn -> Hash.to_hex(Exnode.Chain.State.tip(n.chain_state).hash) == tip end,
             60_000
           )

    # A mempool with a chain of three and a sibling, relayed to exnode.
    m1 = spend([coin.(2, :wsh)], [{3_000_000_000, p2wsh()}, {1_999_990_000, p2wsh()}])
    m2 = spend([{m1.txid, 0, 3_000_000_000, :wsh}], [{2_999_995_000, p2wsh()}])
    m3 = spend([{m2.txid, 0, 2_999_995_000, :wsh}], [{2_999_985_000, p2wsh()}])
    m4 = spend([{m1.txid, 1, 1_999_990_000, :wsh}], [{1_999_970_000, p2wsh()}])

    for t <- [m1, m2, m3, m4],
        do: Bitcoind.cli(btc, ["sendrawtransaction", hex(Tx.encode(t) |> IO.iodata_to_binary())])

    assert Bitcoind.wait_until(
             fn -> Enum.all?([m1, m2, m3, m4], &Exnode.Mempool.has?(n.mempool, &1.txid)) end,
             60_000
           )

    cookie = File.read!(Path.join([dir, "btc", "regtest", ".cookie"]))
    core = fn m, ps -> rpc(btc.rpc, cookie, m, ps) end
    ours = fn m, ps -> rpc(port, "u:p", m, ps) end

    height = Bitcoind.json(btc, ["getblockcount"])
    hashes = for h <- [0, 1, 126, 127, height], do: Bitcoind.cli(btc, ["getblockhash", "#{h}"])
    fan_block = Enum.at(hashes, 3)

    txids =
      [hd(Bitcoind.block(btc, 127).txs).txid, fanout.txid | Enum.map(sh_spends, & &1.txid)]
      |> Enum.map(&Hash.to_hex/1)

    mem = Enum.map([m1, m2, m3, m4], &Hash.to_hex(&1.txid))
    raw = fn t -> hex(Tx.encode(t) |> IO.iodata_to_binary()) end
    bad = Hash.to_hex(<<7::256>>)
    test_tx = spend([coin.(3, :wsh)], [{4_999_990_000, p2wsh()}])
    low_fee = spend([coin.(4, :wsh)], [{50 * 100_000_000, p2wsh()}])

    calls =
      [
        {"getblockchaininfo", []},
        {"getbestblockhash", []},
        {"getblockcount", []},
        {"getdifficulty", []},
        {"getblockhash", [0]},
        {"getblockhash", [height]},
        {"getblockhash", [height + 1]},
        {"getblockhash", [-1]},
        {"getblockheader", [bad]},
        {"getblockheader", ["xyz"]},
        {"getblockheader", [String.duplicate("zz", 32)]},
        {"getblock", [bad]},
        {"getmempoolinfo", []},
        {"getrawmempool", []},
        {"getrawmempool", [true]},
        {"getrawtransaction", [bad]},
        {"decoderawtransaction", ["00"]},
        {"getmempoolentry", [bad]},
        {"testmempoolaccept", [[raw.(test_tx)]]},
        {"testmempoolaccept", [[raw.(low_fee)]]},
        {"testmempoolaccept", [[raw.(m1)]]},
        {"testmempoolaccept",
         [
           [
             raw.(test_tx),
             raw.(spend([{test_tx.txid, 0, 4_999_990_000, :wsh}], [{4_999_980_000, p2wsh()}]))
           ]
         ]},
        {"sendrawtransaction", ["00"]},
        {"sendrawtransaction", [raw.(low_fee)]}
      ] ++
        for(h <- hashes, v <- [false, true], do: {"getblockheader", [h, v]}) ++
        for(h <- hashes, v <- [0, 1, 2, 3], do: {"getblock", [h, v]}) ++
        for(t <- txids ++ mem, v <- [0, 1, 2], do: {"getrawtransaction", [t, v]}) ++
        for(t <- mem, do: {"getmempoolentry", [t]}) ++
        for(t <- txids ++ mem, n <- [0, 1, 99], im <- [true, false], do: {"gettxout", [t, n, im]}) ++
        for(s <- spks, do: {"decodescript", [hex(s)]}) ++
        for(t <- [fanout | sh_spends], do: {"decoderawtransaction", [raw.(t)]}) ++
        [{"getblock", [fan_block, 2]}]

    diffs =
      for {m, ps} <- calls,
          a = core.(m, ps),
          b = ours.(m, ps),
          drop = Map.get(@node_specific, m, []),
          norm = fn
            # getrawmempool (list): Core breaks ties between equal-feerate
            # chunks with txgraph internals; compared as a set.
            {:ok, v} when m == "getrawmempool" and is_list(v) -> {:ok, Enum.sort(v)}
            {:ok, v} -> {:ok, strip(v, drop)}
            other -> other
          end,
          norm.(a) != norm.(b),
          do: {m, ps, a, b}

    for {m, ps, a, b} <- diffs |> Enum.uniq_by(&elem(&1, 0)) |> Enum.take(12),
        do:
          IO.puts(
            "\n#{m} #{inspect(ps)}\n core: #{inspect(a, limit: :infinity)}\n ours: #{inspect(b, limit: :infinity)}"
          )

    assert diffs == [],
           "#{length(diffs)} of #{length(calls)} calls differ: #{inspect(Enum.map(diffs, &{elem(&1, 0), elem(&1, 1)}) |> Enum.take(10))}"

    # Field sets only.
    for m <- ~w(getnetworkinfo) do
      {:ok, a} = core.(m, [])
      {:ok, b} = ours.(m, [])

      assert Map.keys(a) -- Map.keys(b) == [],
             "#{m}: missing #{inspect(Map.keys(a) -- Map.keys(b))}"
    end

    # getpeerinfo: every field bitcoind reports for its peer (exnode) exists in
    # exnode's report of its peer (bitcoind). Conditional fields (addrbind,
    # addrlocal, mapped_as, pingwait) are excluded.
    {:ok, [cp | _]} = core.("getpeerinfo", [])
    {:ok, [op | _]} = ours.("getpeerinfo", [])
    missing = (Map.keys(cp) -- ~w(addrbind addrlocal mapped_as pingwait)) -- Map.keys(op)
    assert missing == [], "getpeerinfo: missing #{inspect(missing)}"

    IO.puts("\n  #{length(calls)} RPC calls compared, all equal")
  end
end
