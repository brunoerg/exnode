defmodule Exnode.RPC.ReaderTest do
  @moduledoc """
  RPC reads go through the lock-free committed reader: they never call into
  the chain state's batch and never force a commit, and what they report is
  the committed chain (whose block data is readable).
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Crypto.Hash
  alias Exnode.RPC.Methods
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)

  test "RPC calls neither force a commit nor see uncommitted blocks", %{tmp_dir: dir} do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    name = :"ReaderTestCS#{System.unique_integer([:positive])}"
    # Batch up to 1000 blocks, no commit at the tip: only the 5 s timer would commit.
    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "a"),
        name: name,
        batch_blocks: 1000,
        commit_at_tip: false
      )

    for b <- Enum.take(bs, 40), do: {:ok, :connected} = State.submit_block(cs, b)
    ctx = %{chain_state: name, headers: hs, params: @p}
    committed = fn -> State.view_committed(State.view(name)) end
    assert State.tip(cs).height == 40
    c0 = committed.()
    assert c0 < 40

    {:ok, count} = Methods.call("getblockcount", [], ctx)
    {:ok, best} = Methods.call("getbestblockhash", [], ctx)
    {:ok, raw} = Methods.call("getblock", [best, 0], ctx)
    assert count == c0

    assert Base.decode16!(raw, case: :lower)
           |> Block.decode_exact()
           |> elem(1)
           |> then(& &1.header.hash) == Hash.from_hex(best)

    # An uncommitted block is not served yet.
    tip40 = Hash.to_hex(State.tip(cs).hash)
    assert {:error, _, "Block not available" <> _} = Methods.call("getblock", [tip40, 0], ctx)
    assert committed.() == c0, "an RPC call forced a commit"

    # Once committed (here: explicitly), RPC sees it.
    State.with_archive(cs, fn _ -> :ok end)
    assert {:ok, 40} = Methods.call("getblockcount", [], ctx)
    assert {:ok, _} = Methods.call("getblock", [tip40, 0], ctx)
  end

  test "getblockheader uses metadata with no usable segment readers, including old records", %{
    tmp_dir: dir
  } do
    b = @chain |> BB.read_chain() |> hd() |> Block.decode_exact() |> elem(1)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    name = :"HeaderMetadataCS#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "a"), name: name)

    {:ok, :connected} = State.submit_block(cs, b)
    State.commit_now(cs)
    ctx = %{chain_state: name, headers: hs, params: @p}
    view = State.view(name)
    reader = State.reader(name)
    # Any attempt to reconstruct a block now fails. Metadata remains readable.
    # Chain.View is :protected, so mutate via the owning Chain.State process.
    :sys.replace_state(cs, fn st ->
      :ets.insert(view, {:reader, %{reader | readers: %{}, wpruned: 1_000}})
      st
    end)

    hash = Hash.to_hex(b.header.hash)
    assert {:ok, header} = Methods.call("getblockheader", [hash], ctx)
    assert Jason.decode!(Jason.encode!(header))["nTx"] == length(b.txs)

    id = Exnode.Archive.block_id(reader, b.header.hash)
    old = reader |> Exnode.Archive.block_record!(id) |> Map.delete(:n_tx)

    KV.write(kv, [
      {:put, :blocks, <<id::32>>, :erlang.term_to_binary(old)},
      {:delete, :meta, "ntx" <> b.header.hash}
    ])

    assert {:ok, header} = Methods.call("getblockheader", [hash], ctx)
    assert Jason.decode!(Jason.encode!(header))["nTx"] == length(b.txs)

    :sys.replace_state(cs, fn st ->
      :ets.insert(view, {:reader, reader})
      st
    end)
  end
end
