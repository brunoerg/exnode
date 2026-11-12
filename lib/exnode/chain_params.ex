defmodule Exnode.ChainParams do
  @moduledoc """
  Chain parameters. Values are copied verbatim from Core v32.1
  `src/kernel/chainparams.cpp` (CMainParams, CTestNetParams, CTestNet4Params,
  SigNetParams, CRegTestParams). Hashes are written as display hex, as in
  Core's `uint256{"..."}` literals, and stored in internal byte order.

  BIP54 (consensus cleanup) is not active in v32.1. It is modelled as a
  deployment that is off by default (`bip54_height: nil`). Nothing reads it yet.
  """
  alias Exnode.Codec.{Block, Header, Tx}
  alias Exnode.Crypto.Hash
  alias Exnode.Validation.Merkle

  @coin 100_000_000

  defstruct [
    :network,
    :magic,
    :default_port,
    :genesis,
    :genesis_hash,
    :pow_limit,
    :pow_target_timespan,
    :pow_target_spacing,
    :pow_allow_min_difficulty_blocks,
    :pow_no_retargeting,
    :enforce_bip94,
    :subsidy_halving_interval,
    :bip34_height,
    :bip34_hash,
    :bip65_height,
    :bip66_height,
    :csv_height,
    :segwit_height,
    :minimum_chain_work,
    :default_assume_valid,
    :signet_blocks,
    :signet_challenge,
    :bech32_hrp,
    dns_seeds: [],
    # Core vFixedSeeds (chainparamsseeds.h), IPv4/IPv6 entries: the
    # bootstrap of last resort (Connman, ThreadOpenConnections).
    fixed_seeds: [],
    # HeadersSyncParams {commitment_period, redownload_buffer_size}
    headers_sync: nil,
    script_flag_exceptions: %{},
    bip54_height: nil,
    # Core ChainTxData {nTime, tx_count, dTxRate}: GuessVerificationProgress.
    chain_tx_data: {0, 0, 0.0}
  ]

  @type t :: %__MODULE__{}
  @networks [:mainnet, :testnet, :testnet4, :signet, :regtest]
  def networks, do: @networks

  defp h(hex), do: Hash.from_hex(hex)
  defp u256(hex), do: hex |> Base.decode16!(case: :lower) |> :binary.decode_unsigned(:big)

  @satoshi_msg "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  @satoshi_pubkey "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"

  # SigNetParams default challenge
  @signet_challenge "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"

  @doc "Returns the parameters for `network`."
  @spec get(atom()) :: t()
  def get(:mainnet) do
    genesis =
      genesis(
        @satoshi_msg,
        p2pk(@satoshi_pubkey),
        1_231_006_505,
        2_083_236_893,
        0x1D00FFFF,
        1,
        50 * @coin
      )

    %__MODULE__{
      network: :mainnet,
      headers_sync: {649, 15400},
      magic: <<0xF9, 0xBE, 0xB4, 0xD9>>,
      default_port: 8333,
      genesis: genesis,
      genesis_hash: genesis.header.hash,
      pow_limit: u256("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      pow_target_timespan: 14 * 24 * 60 * 60,
      pow_target_spacing: 10 * 60,
      pow_allow_min_difficulty_blocks: false,
      pow_no_retargeting: false,
      enforce_bip94: false,
      subsidy_halving_interval: 210_000,
      bip34_height: 227_931,
      bip34_hash: h("000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"),
      bip65_height: 388_381,
      bip66_height: 363_725,
      csv_height: 419_328,
      segwit_height: 481_824,
      minimum_chain_work:
        u256("000000000000000000000000000000000000000145ec036acc5ba740052af1a0"),
      default_assume_valid: h("00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3"),
      # getchaintxstats 4096 00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3
      chain_tx_data: {1_788_925_573, 1_434_982_600, 7.851784479579372},
      signet_blocks: false,
      signet_challenge: <<>>,
      bech32_hrp: "bc",
      script_flag_exceptions: %{
        # BIP16 exception
        h("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22") => [],
        # Taproot exception
        h("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad") => [:p2sh, :witness]
      },
      fixed_seeds: Exnode.ChainParams.FixedSeeds.get(:mainnet),
      dns_seeds:
        ~w(dnsseed.bluematt.me. seed.bitcoin.jonasschnelli.ch. seed.btc.petertodd.net.
        seed.bitcoin.sprovoost.nl. dnsseed.emzy.de. seed.bitcoin.wiz.biz. seed.mainnet.achownodes.xyz.)
    }
  end

  def get(:testnet) do
    genesis =
      genesis(
        @satoshi_msg,
        p2pk(@satoshi_pubkey),
        1_296_688_602,
        414_098_458,
        0x1D00FFFF,
        1,
        50 * @coin
      )

    %__MODULE__{
      network: :testnet,
      headers_sync: {682, 14613},
      magic: <<0x0B, 0x11, 0x09, 0x07>>,
      default_port: 18333,
      genesis: genesis,
      genesis_hash: genesis.header.hash,
      pow_limit: u256("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      pow_target_timespan: 14 * 24 * 60 * 60,
      pow_target_spacing: 10 * 60,
      pow_allow_min_difficulty_blocks: true,
      pow_no_retargeting: false,
      enforce_bip94: false,
      subsidy_halving_interval: 210_000,
      bip34_height: 21_111,
      bip34_hash: h("0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"),
      bip65_height: 581_885,
      bip66_height: 330_776,
      csv_height: 770_112,
      segwit_height: 834_624,
      minimum_chain_work:
        u256("0000000000000000000000000000000000000000000017f49f702147f10c0eb6"),
      default_assume_valid: h("00000000b318a3703d14a844c55ef507f4c2fc8f8766e24271fd43c180c51637"),
      chain_tx_data: {1_788_932_318, 536_748_780, 0.02306697351149596},
      signet_blocks: false,
      signet_challenge: <<>>,
      bech32_hrp: "tb",
      script_flag_exceptions: %{
        # BIP16 exception
        h("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105") => []
      },
      fixed_seeds: Exnode.ChainParams.FixedSeeds.get(:testnet),
      dns_seeds: ~w(testnet-seed.bitcoin.jonasschnelli.ch. seed.tbtc.petertodd.net.
        testnet-seed.bluematt.me. seed.testnet.achownodes.xyz.)
    }
  end

  def get(:testnet4) do
    genesis =
      genesis(
        "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e",
        p2pk(String.duplicate("00", 33)),
        1_714_777_860,
        393_743_547,
        0x1D00FFFF,
        1,
        50 * @coin
      )

    %__MODULE__{
      network: :testnet4,
      headers_sync: {616, 16199},
      magic: <<0x1C, 0x16, 0x3F, 0x28>>,
      default_port: 48333,
      genesis: genesis,
      genesis_hash: genesis.header.hash,
      pow_limit: u256("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      pow_target_timespan: 14 * 24 * 60 * 60,
      pow_target_spacing: 10 * 60,
      pow_allow_min_difficulty_blocks: true,
      pow_no_retargeting: false,
      enforce_bip94: true,
      subsidy_halving_interval: 210_000,
      bip34_height: 1,
      bip34_hash: <<0::256>>,
      bip65_height: 1,
      bip66_height: 1,
      csv_height: 1,
      segwit_height: 1,
      minimum_chain_work:
        u256("000000000000000000000000000000000000000000000e346a558455ade8eca9"),
      default_assume_valid: h("0000000021df65b91665a342e26ceb05e54826ad7d8fcd40316230058fa3b865"),
      chain_tx_data: {1_788_932_739, 14_825_119, 0.1148250171344748},
      signet_blocks: false,
      signet_challenge: <<>>,
      bech32_hrp: "tb",
      fixed_seeds: Exnode.ChainParams.FixedSeeds.get(:testnet4),
      dns_seeds: ~w(seed.testnet4.bitcoin.sprovoost.nl. seed.testnet4.wiz.biz.)
    }
  end

  def get(:signet), do: signet(nil)

  def get(:regtest) do
    genesis =
      genesis(@satoshi_msg, p2pk(@satoshi_pubkey), 1_296_688_602, 2, 0x207FFFFF, 1, 50 * @coin)

    %__MODULE__{
      network: :regtest,
      headers_sync: {275, 7017},
      magic: <<0xFA, 0xBF, 0xB5, 0xDA>>,
      default_port: 18444,
      genesis: genesis,
      genesis_hash: genesis.header.hash,
      pow_limit: u256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      pow_target_timespan: 24 * 60 * 60,
      pow_target_spacing: 10 * 60,
      pow_allow_min_difficulty_blocks: true,
      pow_no_retargeting: true,
      # RegTestOptions.enforce_bip94 defaults to false (-test=bip94 turns it on)
      enforce_bip94: false,
      subsidy_halving_interval: 150,
      bip34_height: 1,
      bip34_hash: <<0::256>>,
      bip65_height: 1,
      bip66_height: 1,
      csv_height: 1,
      segwit_height: 0,
      minimum_chain_work: 0,
      default_assume_valid: <<0::256>>,
      # Core: a non-zero rate to make it testable.
      chain_tx_data: {0, 0, 0.001},
      signet_blocks: false,
      signet_challenge: <<>>,
      bech32_hrp: "bcrt",
      dns_seeds: []
    }
  end

  @doc """
  Signet params (SigNetParams). With `challenge = nil`, the default global
  signet: its challenge, seeds, minimum chain work and assumevalid. With a
  custom challenge, minimum chain work is 0 and there is no assumevalid.
  """
  def signet(challenge) do
    # Core SigNetParams: the default signet has DNS and fixed seeds; a custom
    # challenge has neither (vSeeds / vFixedSeeds cleared).
    {bin, mcw, av, seeds, fixed, tx_data} =
      case challenge do
        nil ->
          {Base.decode16!(@signet_challenge, case: :lower),
           u256("00000000000000000000000000000000000000000000000000001090e9dc1520"),
           h("00000002a5e0ba0498f1e9f4591af0b66b63c654665efe65206fd0ae7bbaf923"),
           ~w(seed.signet.bitcoin.sprovoost.nl. seed.signet.achownodes.xyz.),
           Exnode.ChainParams.FixedSeeds.get(:signet),
           {1_788_925_860, 32_273_793, 0.3977566114505673}}

        c when is_binary(c) ->
          {c, 0, <<0::256>>, [], [], {0, 0, 0.0}}
      end

    genesis =
      genesis(
        @satoshi_msg,
        p2pk(@satoshi_pubkey),
        1_598_918_400,
        52_613_770,
        0x1E0377AE,
        1,
        50 * @coin
      )

    # pchMessageStart: first 4 bytes of HashWriter{} << signet_challenge
    # (the vector is CompactSize-prefixed, then hashed with SHA256d).
    <<magic::binary-size(4), _::binary>> =
      Hash.hash256(Exnode.Codec.CompactSize.encode_bytes(bin))

    %__MODULE__{
      network: :signet,
      headers_sync: {629, 15885},
      magic: magic,
      default_port: 38333,
      genesis: genesis,
      genesis_hash: genesis.header.hash,
      pow_limit: u256("00000377ae000000000000000000000000000000000000000000000000000000"),
      pow_target_timespan: 14 * 24 * 60 * 60,
      pow_target_spacing: 10 * 60,
      pow_allow_min_difficulty_blocks: false,
      pow_no_retargeting: false,
      enforce_bip94: false,
      subsidy_halving_interval: 210_000,
      bip34_height: 1,
      bip34_hash: <<0::256>>,
      bip65_height: 1,
      bip66_height: 1,
      csv_height: 1,
      segwit_height: 1,
      minimum_chain_work: mcw,
      default_assume_valid: av,
      signet_blocks: true,
      signet_challenge: bin,
      bech32_hrp: "tb",
      dns_seeds: seeds,
      fixed_seeds: fixed,
      chain_tx_data: tx_data
    }
  end

  # CScript() << pubkey << OP_CHECKSIG
  defp p2pk(hex) do
    pk = Base.decode16!(hex, case: :lower)
    <<byte_size(pk)>> <> pk <> <<0xAC>>
  end

  # Core: CreateGenesisBlock (kernel/chainparams.cpp)
  defp genesis(msg, out_script, time, nonce, bits, version, reward) do
    # CScript() << 486604799 << CScriptNum(4) << vector(msg)
    script_sig =
      IO.iodata_to_binary([
        <<4, 486_604_799::little-32>>,
        <<1, 4>>,
        push(msg)
      ])

    tx = %Tx{
      version: 1,
      inputs: [
        %Tx.In{
          prev_hash: <<0::256>>,
          prev_index: 0xFFFFFFFF,
          script_sig: script_sig,
          sequence: 0xFFFFFFFF
        }
      ],
      outputs: [%Tx.Out{value: reward, script_pubkey: out_script}],
      locktime: 0
    }

    {:ok, tx} = tx |> Tx.encode() |> IO.iodata_to_binary() |> Tx.decode_exact()
    {root, _} = Merkle.block_root([tx])

    header = %Header{
      version: version,
      prev_hash: <<0::256>>,
      merkle_root: root,
      time: time,
      bits: bits,
      nonce: nonce
    }

    raw = IO.iodata_to_binary(Block.encode(%Block{header: header, txs: [tx]}))
    {:ok, block} = Block.decode_exact(raw)
    block
  end

  defp push(d) when byte_size(d) < 0x4C, do: [<<byte_size(d)>>, d]
  defp push(d) when byte_size(d) <= 0xFF, do: [<<0x4C, byte_size(d)>>, d]
end
