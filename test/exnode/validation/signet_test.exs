defmodule Exnode.Validation.SignetTest do
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.{Block, Tx}
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Validation.Signet

  @moduletag :tmp_dir
  @p ChainParams.get(:signet)
  @fixture Path.expand("../../fixtures/signet/blocks1-100.bin", __DIR__)

  defp blocks, do: for(raw <- BB.read_chain(@fixture), do: elem(Block.decode_exact(raw), 1))

  # Flips a bit inside the signet solution, which sits after the 4-byte
  # SIGNET_HEADER in the witness-commitment output.
  defp tamper(%Block{txs: [cb | rest]} = b) do
    idx = Exnode.Validation.Block.witness_commitment_index(b)
    spk = Enum.at(cb.outputs, idx).script_pubkey
    {pos, _} = :binary.match(spk, <<0xEC, 0xC7, 0xDA, 0xA2>>)
    p = pos + 20

    spk =
      binary_part(spk, 0, p) <>
        <<Bitwise.bxor(:binary.at(spk, p), 1)>> <> binary_part(spk, p + 1, byte_size(spk) - p - 1)

    cb =
      BB.finalize(%{cb | outputs: List.update_at(cb.outputs, idx, &%{&1 | script_pubkey: spk})})

    {:ok, b} =
      %Block{header: b.header, txs: [cb | rest]}
      |> Block.encode()
      |> IO.iodata_to_binary()
      |> Block.decode_exact()

    b
  end

  test "the first 100 real signet blocks carry valid BIP325 solutions" do
    assert Enum.all?(blocks(), &Signet.check(&1, @p))
    assert Signet.check(@p.genesis, @p)
  end

  test "a bit flip inside the solution fails the check" do
    refute Signet.check(tamper(Enum.at(blocks(), 0)), @p)
    refute Signet.check(tamper(Enum.at(blocks(), 57)), @p)
  end

  test "blocks without a witness commitment fail (Core requires one)" do
    b = Enum.at(blocks(), 0)
    [cb | rest] = b.txs

    cb =
      BB.finalize(%{
        cb
        | outputs: Enum.take(cb.outputs, 1),
          inputs: Enum.map(cb.inputs, &%{&1 | witness: []})
      })

    {:ok, b} =
      %Block{header: b.header, txs: [cb | rest]}
      |> Block.encode()
      |> IO.iodata_to_binary()
      |> Block.decode_exact()

    refute Signet.check(b, @p)
    _ = Tx
  end

  test "full validation on signet params: real blocks connect; a tampered one is bad-signet-blksig",
       %{tmp_dir: dir} do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "a"))
    [b1 | _] = bs = blocks()
    # As in IBD: the headers come through headers sync (which proves their
    # work), then the blocks are downloaded, so requested. Unrequested, these
    # blocks are below signet's minimum chain work and would not be stored
    # (Core AcceptBlock); without the headers, theirs would be too-little-chainwork.
    headers = Enum.map(bs, & &1.header)
    {:ok, _} = Headers.process_headers(hs, headers)
    # Core runs the signet check before the merkle check in CheckBlock.
    assert {:error, {:consensus, "bad-signet-blksig"}} =
             State.submit_block(cs, tamper(b1), requested: true)

    {:ok, kv2} = KV.open(Path.join(dir, "kv2"))
    {:ok, hs2} = Headers.start_link(params: @p, kv: kv2)
    {:ok, cs2} = State.start_link(params: @p, headers: hs2, kv: kv2, hot: Path.join(dir, "a2"))
    {:ok, _} = Headers.process_headers(hs2, headers)
    for b <- bs, do: assert({:ok, :connected} = State.submit_block(cs2, b, requested: true))
    assert State.tip(cs2).height == 100
  end
end
