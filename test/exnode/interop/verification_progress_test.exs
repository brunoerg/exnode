defmodule Exnode.Interop.VerificationProgressTest do
  @moduledoc """
  `getblockchaininfo.verificationprogress` (Core `GuessVerificationProgress`)
  equals bitcoind v32.1's on the same chain: at genesis, and on the 150-block
  regtest fixture, whose old timestamps put the value well below 1.0. Both
  nodes read the clock a moment apart, so the comparison is relative (1e-4).
  """
  use Exnode.InteropCase

  alias Exnode.Chain.State
  alias Exnode.Codec.Block
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :bitcoind
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  defp rpc(port, method) do
    :inets.start()
    body = Jason.encode!(%{jsonrpc: "1.0", id: 1, method: method, params: []})
    hdrs = [{~c"authorization", ~c"Basic " ++ String.to_charlist(Base.encode64("u:p"))}]

    {:ok, {_, _, resp}} =
      :httpc.request(
        :post,
        {~c"http://127.0.0.1:#{port}/", hdrs, ~c"application/json", body},
        [],
        []
      )

    Jason.decode!(resp)["result"]
  end

  defp assert_close(ours, core, label) do
    assert core > 0 and abs(ours - core) / core < 1.0e-4,
           "#{label}: exnode #{ours}, bitcoind #{core}"
  end

  test "verificationprogress equals bitcoind's, at genesis and on an old chain", %{
    tmp_dir: dir,
    btc: btc
  } do
    %{n: n} =
      TestNode.start(Path.join(dir, "ex"),
        rpc_port: port = TestNode.free_port(),
        rpc_user: "u",
        rpc_password: "p"
      )

    progress = fn ->
      {rpc(port, "getblockchaininfo")["verificationprogress"],
       Bitcoind.json(btc, ["getblockchaininfo"])["verificationprogress"]}
    end

    {ours, core} = progress.()
    assert_close(ours, core, "genesis")

    blocks = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)

    for b <- blocks do
      {:ok, :connected} = State.submit_block(n.chain_state, b)
      "" = Bitcoind.cli_stdin(btc, "submitblock", Base.encode16(b.raw, case: :lower))
    end

    State.commit_now(n.chain_state)
    assert Bitcoind.json(btc, ["getblockcount"]) == 150

    {ours, core} = progress.()
    assert ours < 0.5
    assert_close(ours, core, "height 150")
  end
end
