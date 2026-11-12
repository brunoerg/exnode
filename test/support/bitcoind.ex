defmodule Exnode.Test.Bitcoind do
  @moduledoc "Test helper: runs the pinned bitcoind v32.1 (vendor/bitcoin/build/bin) on regtest."

  @bin Path.expand("../../vendor/bitcoin/build/bin", __DIR__)

  def available?, do: File.exists?(Path.join(@bin, "bitcoind"))

  @doc "Starts bitcoind -regtest in `datadir`. Returns a handle map."
  def start(datadir, extra \\ []) do
    File.mkdir_p!(datadir)
    p2p = free_port()
    rpc = free_port()

    args =
      [
        "-regtest",
        "-datadir=#{datadir}",
        "-daemonwait",
        "-listen=1",
        "-bind=127.0.0.1:#{p2p}",
        "-port=#{p2p}",
        "-rpcport=#{rpc}",
        "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1",
        "-fallbackfee=0",
        "-debug=net",
        "-dnsseed=0",
        "-fixedseeds=0",
        "-discover=0"
      ] ++ extra

    {_, 0} = System.cmd(Path.join(@bin, "bitcoind"), args, stderr_to_stdout: true)
    %{datadir: datadir, p2p: p2p, rpc: rpc}
  end

  def stop(h) do
    _ = cli(h, ["stop"])

    wait_until(
      fn -> not File.exists?(Path.join([h.datadir, "regtest", "bitcoind.pid"])) end,
      30_000
    )
  end

  def cli(h, args) do
    {out, code} =
      System.cmd(
        Path.join(@bin, "bitcoin-cli"),
        ["-regtest", "-datadir=#{h.datadir}", "-rpcport=#{h.rpc}" | args],
        stderr_to_stdout: true
      )

    if code == 0, do: String.trim(out), else: raise("bitcoin-cli #{inspect(args)} failed: #{out}")
  end

  def json(h, args), do: h |> cli(args) |> Jason.decode!()

  @doc "Like `cli/2`, but passes `arg` on stdin (`-stdin`), for arguments too large for argv."
  def cli_stdin(h, cmd, arg) do
    file = Path.join(h.datadir, "stdin-#{System.unique_integer([:positive])}")
    File.write!(file, arg <> "\n")
    bin = Path.join(@bin, "bitcoin-cli")

    script =
      ~s(exec "#{bin}" -regtest -datadir="#{h.datadir}" -rpcport=#{h.rpc} -stdin #{cmd} < "#{file}")

    {out, code} = System.cmd("sh", ["-c", script], stderr_to_stdout: true)
    File.rm(file)

    if code == 0,
      do: String.trim(out),
      else: raise("bitcoin-cli #{cmd} (stdin) failed: #{String.slice(out, 0, 500)}")
  end

  @doc "Batched JSON-RPC over HTTP with cookie auth. `calls`: `[{method, params}]`. Returns results in order."
  def rpc_batch(h, calls) do
    :inets.start()
    cookie = File.read!(Path.join([h.datadir, "regtest", ".cookie"]))
    auth = ~c"Basic " ++ String.to_charlist(Base.encode64(cookie))

    calls
    |> Enum.chunk_every(500)
    |> Enum.flat_map(fn chunk ->
      body =
        chunk
        |> Enum.with_index()
        |> Enum.map(fn {{m, ps}, i} -> %{jsonrpc: "1.0", id: i, method: m, params: ps} end)

      {:ok, {{_, 200, _}, _, resp}} =
        :httpc.request(
          :post,
          {~c"http://127.0.0.1:#{h.rpc}/", [{~c"authorization", auth}], ~c"application/json",
           Jason.encode!(body)},
          [timeout: 120_000],
          []
        )

      resp |> Jason.decode!() |> Enum.sort_by(& &1["id"]) |> Enum.map(& &1["result"])
    end)
  end

  def block(h, height) do
    hash = cli(h, ["getblockhash", "#{height}"])

    {:ok, b} =
      h
      |> cli(["getblock", hash, "0"])
      |> Base.decode16!(case: :lower)
      |> Exnode.Codec.Block.decode_exact()

    b
  end

  @doc "Mines one block containing raw `txs` (hex), paying to `descriptor`."
  def generate_block(h, txs, descriptor \\ "raw(51)") do
    json(h, [
      "generateblock",
      descriptor,
      Jason.encode!(
        Enum.map(
          txs,
          &Base.encode16(IO.iodata_to_binary(Exnode.Codec.Tx.encode(&1)), case: :lower)
        )
      )
    ])
  end

  def mine(h, n, descriptor \\ "raw(51)"),
    do: json(h, ["generatetodescriptor", "#{n}", descriptor])

  @doc "Polls `f` until truthy; returns whether it did within `timeout_ms`."
  def wait_until(f, timeout_ms \\ 30_000), do: Exnode.Test.Wait.until?(f, timeout_ms, 100)

  @doc "bitcoind's best block hash (hex)."
  def tip(h), do: cli(h, ["getbestblockhash"])

  defp free_port, do: Exnode.Test.Node.free_port()
end
