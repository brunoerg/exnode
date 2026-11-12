defmodule Exnode.Test.Coins do
  @moduledoc """
  Test helper: anyone-can-spend coins for regtest txs, and tx encoding.

  The interop tests pay to P2WSH(OP_TRUE) and spend with the witness
  `[OP_TRUE]`, so neither exnode nor bitcoind needs keys.
  """
  alias Exnode.Codec.Tx

  @op_true <<0x51>>

  @doc "The witness script OP_TRUE."
  def witness_script, do: @op_true

  @doc "scriptPubKey P2WSH(OP_TRUE)."
  def p2wsh, do: <<0x00, 0x20>> <> :crypto.hash(:sha256, @op_true)

  @doc "An input spending P2WSH(OP_TRUE) output `{txid, vout, _value}`, RBF-signalling."
  def input({txid, vout, _value}),
    do: %Tx.In{
      prev_hash: txid,
      prev_index: vout,
      script_sig: <<>>,
      sequence: 0xFFFFFFFD,
      witness: [@op_true]
    }

  @doc """
  A version-2 tx spending `coins` (`{txid, vout, value}`, P2WSH(OP_TRUE))
  into `outputs` (`[{value, spk}]`), decoded back so txid/wtxid/raw are set.
  """
  def tx(coins, outputs, opts \\ []) do
    %Tx{
      version: Keyword.get(opts, :version, 2),
      locktime: Keyword.get(opts, :locktime, 0),
      inputs: Enum.map(coins, &input/1),
      outputs: for({v, spk} <- outputs, do: %Tx.Out{value: v, script_pubkey: spk})
    }
    |> finalize()
  end

  @doc "Re-decodes a tx built in memory so raw/txid/wtxid are filled in."
  def finalize(%Tx{} = tx) do
    {:ok, tx} = tx |> raw() |> Tx.decode_exact()
    tx
  end

  @doc "A tx's serialization (with witness)."
  def raw(%Tx{} = tx), do: tx |> Tx.encode() |> IO.iodata_to_binary()

  @doc "Lowercase hex; nil stays nil."
  def hex(nil), do: nil
  def hex(bin) when is_binary(bin), do: Base.encode16(bin, case: :lower)
end
