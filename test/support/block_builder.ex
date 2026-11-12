defmodule Exnode.Test.BlockBuilder do
  @moduledoc "Test-only helpers to craft regtest blocks (nBits 0x207fffff, trivial PoW)."
  import Bitwise

  alias Exnode.Codec.{Block, Header, Tx}
  alias Exnode.Test.ScriptAsm
  alias Exnode.Validation.Merkle

  @op_true <<0x51>>
  @regtest_bits 0x207FFFFF

  @doc "Reads a fixture of <<len:32/big, block>> records."
  def read_chain(path), do: path |> File.read!() |> split([])

  defp split(<<>>, acc), do: Enum.reverse(acc)
  defp split(<<len::32, raw::binary-size(len), rest::binary>>, acc), do: split(rest, [raw | acc])

  @doc "Coinbase with BIP34 height and a single output."
  def coinbase(height, value, spk \\ @op_true) do
    script_sig = ScriptAsm.parse("#{height}") <> <<0>>
    script_sig = if byte_size(script_sig) < 2, do: script_sig <> <<0>>, else: script_sig

    finalize(%Tx{
      version: 2,
      inputs: [
        %Tx.In{
          prev_hash: <<0::256>>,
          prev_index: 0xFFFFFFFF,
          script_sig: script_sig,
          sequence: 0xFFFFFFFF
        }
      ],
      outputs: [%Tx.Out{value: value, script_pubkey: spk}],
      locktime: 0
    })
  end

  @doc """
  Generic tx. `inputs`: `[{txid, vout} | {txid, vout, opts}]` with opts
  `:script_sig`, `:sequence`, `:witness`. `outputs`: `[{value, spk}]`.
  """
  def tx(inputs, outputs, opts \\ []) do
    ins =
      for i <- inputs do
        {txid, vout, o} =
          case i do
            {t, v} -> {t, v, []}
            {t, v, o} -> {t, v, o}
          end

        %Tx.In{
          prev_hash: txid,
          prev_index: vout,
          script_sig: Keyword.get(o, :script_sig, <<>>),
          sequence: Keyword.get(o, :sequence, 0xFFFFFFFF),
          witness: Keyword.get(o, :witness, [])
        }
      end

    outs = for {v, spk} <- outputs, do: %Tx.Out{value: v, script_pubkey: spk}

    finalize(%Tx{
      version: Keyword.get(opts, :version, 2),
      inputs: ins,
      outputs: outs,
      locktime: Keyword.get(opts, :locktime, 0)
    })
  end

  @doc """
  Coinbase with options: `:script_sig` (overrides the BIP34 prefix),
  `:outputs` (`[{value, spk}]`, replaces the single output), `:witness`.
  """
  def coinbase_with(height, value, opts) do
    script_sig =
      Keyword.get_lazy(opts, :script_sig, fn -> ScriptAsm.parse("#{height}") <> <<0>> end)

    outs = Keyword.get(opts, :outputs, [{value, @op_true}])

    tx(
      [
        {<<0::256>>, 0xFFFFFFFF, script_sig: script_sig, witness: Keyword.get(opts, :witness, [])}
      ],
      outs,
      version: 2
    )
  end

  @doc """
  Builds a segwit block: adds the BIP141 commitment output to a coinbase
  built by `cb_fun.(extra_outputs, witness)` and puts `nonce` in the coinbase
  witness. `opts[:commitment]` overrides the committed hash.
  """
  def build_segwit(%Header{} = prev, cb_fun, txs, opts \\ []) do
    nonce = Keyword.get(opts, :nonce, <<0::256>>)
    root = Merkle.block_witness_root([:placeholder | txs])

    commit =
      Keyword.get_lazy(opts, :commitment, fn -> Exnode.Crypto.Hash.hash256([root, nonce]) end)

    spk = <<0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED>> <> commit
    cb = cb_fun.([{0, spk}], [nonce])
    build(prev, [cb | txs], Keyword.delete(opts, :nonce))
  end

  @doc "Spends an OP_TRUE output (empty scriptSig) into a new OP_TRUE output."
  def spend_op_true(prev_txid, vout, value) do
    finalize(%Tx{
      version: 2,
      inputs: [
        %Tx.In{prev_hash: prev_txid, prev_index: vout, script_sig: <<>>, sequence: 0xFFFFFFFF}
      ],
      outputs: [%Tx.Out{value: value, script_pubkey: @op_true}],
      locktime: 0
    })
  end

  @doc "Re-decodes a tx built in memory so raw/txid/wtxid are filled in."
  def finalize(%Tx{} = tx) do
    {:ok, tx} = tx |> Tx.encode() |> IO.iodata_to_binary() |> Tx.decode_exact()
    tx
  end

  @doc """
  Builds a block on `prev` with the given txs, grinding the nonce for regtest
  PoW. `merkle_txs` sets the txs the merkle root commits to (default `txs`),
  which lets a test build a mutated block.
  """
  def build(%Header{} = prev, txs, opts \\ []) do
    {root, _} = Merkle.block_root(Keyword.get(opts, :merkle_txs, txs))

    header = %Header{
      version: Keyword.get(opts, :version, 0x20000000),
      prev_hash: prev.hash,
      merkle_root: Keyword.get(opts, :merkle_root, root),
      time: Keyword.get(opts, :time, prev.time + 1),
      bits: Keyword.get(opts, :bits, @regtest_bits),
      nonce: 0
    }

    header = if Keyword.get(opts, :bad_pow, false), do: unmine_header(header), else: grind(header)
    raw = IO.iodata_to_binary(Block.encode(%Block{header: header, txs: txs}))
    {:ok, block} = Block.decode_exact(raw)
    block
  end

  @doc "Mines a header (grinds the nonce) so it satisfies its own nBits."
  def mine_header(%Header{} = h), do: grind(h)

  @doc "Finds a nonce for which the header FAILS proof of work."
  def unmine_header(%Header{} = h) do
    {decoded, ""} = Header.decode(Header.encode(h))
    if pow_ok?(decoded.hash, h.bits), do: unmine_header(%{h | nonce: h.nonce + 1}), else: decoded
  end

  @doc "A header on top of `prev` (regtest bits). `fields` overrides any header field."
  def next_header(%Header{} = prev, fields \\ []) do
    struct(
      %Header{
        version: 0x20000000,
        prev_hash: prev.hash,
        merkle_root: <<7::256>>,
        time: prev.time + 1,
        bits: @regtest_bits,
        nonce: 0
      },
      fields
    )
    |> mine_header()
  end

  defp grind(h) do
    {decoded, ""} = Header.decode(Header.encode(h))
    if pow_ok?(decoded.hash, h.bits), do: decoded, else: grind(%{h | nonce: h.nonce + 1})
  end

  def pow_ok?(hash, bits) do
    exp = bits >>> 24
    mant = bits &&& 0x007FFFFF
    target = mant <<< (8 * (exp - 3))
    :binary.decode_unsigned(hash, :little) <= target
  end
end
