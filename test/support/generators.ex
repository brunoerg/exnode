defmodule Exnode.Test.Generators do
  @moduledoc "StreamData generators shared by the property tests."
  use ExUnitProperties

  alias Exnode.Codec.{Block, Header, Tx}
  alias Exnode.Validation.Merkle

  def hash, do: binary(length: 32)

  def script, do: binary(max_length: 60)

  def witness_stack, do: list_of(binary(max_length: 80), max_length: 4)

  def tx_in(opts \\ []) do
    witness = if Keyword.get(opts, :witness, true), do: witness_stack(), else: constant([])

    gen all(
          prev <- hash(),
          idx <- integer(0..0xFFFFFFFF),
          ss <- script(),
          seq <- integer(0..0xFFFFFFFF),
          w <- witness
        ) do
      %Tx.In{prev_hash: prev, prev_index: idx, script_sig: ss, sequence: seq, witness: w}
    end
  end

  def tx_out do
    gen(
      all(
        v <- integer(0..2_100_000_000_000_000),
        spk <- script(),
        do: %Tx.Out{value: v, script_pubkey: spk}
      )
    )
  end

  @doc "A decoded tx (raw, txid, wtxid set). At least one input: a 0-input tx is ambiguous with the segwit marker."
  def tx(opts \\ []) do
    gen all(
          version <- integer(-0x80000000..0x7FFFFFFF),
          ins <- list_of(tx_in(opts), min_length: 1, max_length: 4),
          outs <- list_of(tx_out(), max_length: 4),
          lt <- integer(0..0xFFFFFFFF)
        ) do
      finish(%Tx{version: version, inputs: ins, outputs: outs, locktime: lt})
    end
  end

  def finish(%Tx{} = tx) do
    {:ok, t} = tx |> Tx.encode() |> IO.iodata_to_binary() |> Tx.decode_exact()
    t
  end

  def coinbase(height) do
    finish(%Tx{
      version: 2,
      locktime: 0,
      inputs: [
        %Tx.In{
          prev_hash: <<0::256>>,
          prev_index: 0xFFFFFFFF,
          script_sig: <<3, height::little-24>>,
          sequence: 0xFFFFFFFF
        }
      ],
      outputs: [%Tx.Out{value: 50, script_pubkey: <<0x51>>}]
    })
  end

  @doc "A decoded block with a coinbase and a correct merkle root (no witnesses)."
  def block(opts \\ []) do
    gen all(
          txs <- list_of(tx(witness: false), max_length: Keyword.get(opts, :max_txs, 12)),
          height <- integer(1..0xFFFFFF),
          prev <- hash(),
          time <- integer(0..0xFFFFFFFF),
          nonce <- integer(0..0xFFFFFFFF)
        ) do
      txs = [coinbase(height) | txs]
      {root, _} = Merkle.block_root(txs)

      h = %Header{
        version: 0x20000000,
        prev_hash: prev,
        merkle_root: root,
        time: time,
        bits: 0x207FFFFF,
        nonce: nonce
      }

      {:ok, b} =
        %Block{header: h, txs: txs}
        |> Block.encode()
        |> IO.iodata_to_binary()
        |> Block.decode_exact()

      b
    end
  end
end
