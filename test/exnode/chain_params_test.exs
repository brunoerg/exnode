defmodule Exnode.ChainParamsTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias Exnode.ChainParams
  alias Exnode.Crypto.Hash
  alias Exnode.Kernel
  alias Exnode.Validation.ScriptFlags

  # kernel/chainparams.cpp asserts (v32.1)
  @expected %{
    mainnet:
      {"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
       "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"},
    testnet:
      {"000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
       "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"},
    testnet4:
      {"00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
       "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"},
    signet:
      {"00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
       "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"},
    regtest:
      {"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
       "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"}
  }

  for {net, {hash, root}} <- @expected do
    test "#{net} genesis matches Core's asserts" do
      p = ChainParams.get(unquote(net))
      assert Hash.to_hex(p.genesis_hash) == unquote(hash)
      assert Hash.to_hex(p.genesis.header.merkle_root) == unquote(root)
    end
  end

  test "default signet magic is derived from the challenge" do
    assert ChainParams.get(:signet).magic == <<0x0A, 0x03, 0xCF, 0x40>>
  end

  test "regtest genesis matches the bitcoind-mined fixture's parent" do
    [first | _] =
      Exnode.Test.BlockBuilder.read_chain(
        Path.expand("../fixtures/regtest/chain150.bin", __DIR__)
      )

    {:ok, b} = Exnode.Codec.Block.decode_exact(first)
    assert b.header.prev_hash == ChainParams.get(:regtest).genesis_hash
  end

  describe "GetBlockScriptFlags" do
    setup do: %{main: ChainParams.get(:mainnet), f: Kernel.flags()}

    test "genesis-era mainnet block: P2SH|WITNESS|TAPROOT only", %{main: p, f: f} do
      assert ScriptFlags.block_flags(p, 1, <<1::256>>) == (f.p2sh ||| f.witness ||| f.taproot)
    end

    test "BIP16 exception block gets no flags", %{main: p} do
      hash = Hash.from_hex("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22")
      assert ScriptFlags.block_flags(p, 170_060, hash) == 0
    end

    test "taproot exception block: P2SH|WITNESS plus buried deployments", %{main: p, f: f} do
      hash = Hash.from_hex("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad")
      assert ScriptFlags.block_flags(p, 692_261, hash) == (Kernel.flags_all() &&& bnot(f.taproot))
    end

    test "deployment boundaries are inclusive (height >= activation height)", %{main: p, f: f} do
      x = <<2::256>>
      assert (ScriptFlags.block_flags(p, 363_724, x) &&& f.dersig) == 0
      assert (ScriptFlags.block_flags(p, 363_725, x) &&& f.dersig) != 0
      assert (ScriptFlags.block_flags(p, 481_823, x) &&& f.nulldummy) == 0
      assert ScriptFlags.block_flags(p, 481_824, x) == Kernel.flags_all()
    end

    test "regtest: everything on from height 1, NULLDUMMY from 0" do
      p = ChainParams.get(:regtest)
      assert ScriptFlags.block_flags(p, 1, <<3::256>>) == Kernel.flags_all()
    end
  end
end
