defmodule Exnode.Validation.Signet do
  @moduledoc """
  BIP325 signet block solution. Port of Core v32.1 `signet.cpp`
  (`CheckSignetBlockSolution`, `SignetTxs::Create`,
  `FetchAndClearCommitmentSection`, `ComputeModifiedMerkleRoot`).
  The challenge script is executed by the kernel.
  """
  alias Exnode.ChainParams
  alias Exnode.Codec.{Block, CompactSize, Tx}
  alias Exnode.Kernel
  alias Exnode.Script
  alias Exnode.Validation.Merkle

  @signet_header <<0xEC, 0xC7, 0xDA, 0xA2>>

  @doc """
  Core `CheckSignetBlockSolution(block, params)`: true or false, or
  `{:local, reason}` when the kernel could not run the challenge (an API or
  status error, `Exnode.Validation.Scripts.classify/1`). That is not a bad
  solution: the caller must not treat it as `bad-signet-blksig`. `verify`
  is the kernel call (tests inject failures).
  """
  # Core: CheckSignetBlockSolution (signet.cpp)
  def check(%Block{} = b, %ChainParams{} = p, verify \\ &Kernel.verify_tx_all/3) do
    if b.header.hash == p.genesis_hash do
      true
    else
      case signet_txs(b, p.signet_challenge) do
        nil ->
          false

        {to_spend, to_sign} ->
          # BLOCK_SCRIPT_VERIFY_FLAGS = P2SH | WITNESS | DERSIG | NULLDUMMY
          flags = Kernel.flags_to_int([:p2sh, :witness, :dersig, :nulldummy])
          raw = IO.iodata_to_binary(Tx.encode(to_sign))
          spent = [{hd(to_spend.outputs).script_pubkey, 0}]

          case Exnode.Validation.Scripts.classify(verify.(raw, spent, flags)) do
            :ok -> true
            {:invalid, _} -> false
            {:local, _} = local -> local
          end
      end
    end
  end

  @doc "Core `SignetTxs::Create(block, challenge)`. Returns `{to_spend, to_sign}` or nil."
  # Core: SignetTxs::Create (signet.cpp)
  def signet_txs(%Block{txs: []}, _challenge), do: nil

  def signet_txs(%Block{txs: [cb | rest]} = b, challenge) do
    case Exnode.Validation.Block.witness_commitment_index(b) do
      nil ->
        nil

      cidx ->
        commitment = Enum.at(cb.outputs, cidx).script_pubkey

        parsed =
          case fetch_and_clear(commitment) do
            :not_found -> {:ok, commitment, <<>>, []}
            {:found, replacement, solution} -> parse_solution(solution, replacement)
          end

        with {:ok, new_commitment, script_sig, witness} <- parsed do
          outs = List.update_at(cb.outputs, cidx, &%{&1 | script_pubkey: new_commitment})
          modified_cb = finalize(%{cb | outputs: outs})
          {root, _} = Merkle.compute_root([modified_cb.txid | Enum.map(rest, & &1.txid)])
          h = b.header

          block_data =
            <<h.version::little-signed-32, h.prev_hash::binary, root::binary, h.time::little-32>>

          to_spend =
            finalize(%Tx{
              version: 0,
              locktime: 0,
              # CScript(OP_0) << block_data
              inputs: [
                %Tx.In{
                  prev_hash: <<0::256>>,
                  prev_index: 0xFFFFFFFF,
                  script_sig: <<0>> <> push(block_data),
                  sequence: 0
                }
              ],
              outputs: [%Tx.Out{value: 0, script_pubkey: challenge}]
            })

          to_sign =
            finalize(%Tx{
              version: 0,
              locktime: 0,
              inputs: [
                %Tx.In{
                  prev_hash: to_spend.txid,
                  prev_index: 0,
                  script_sig: script_sig,
                  sequence: 0,
                  witness: witness
                }
              ],
              outputs: [%Tx.Out{value: 0, script_pubkey: <<0x6A>>}]
            })

          {to_spend, to_sign}
        else
          _ -> nil
        end
    end
  end

  # SpanReader v{solution}; v >> scriptSig; v >> witness.stack; extra data → fail.
  defp parse_solution(solution, replacement) do
    {script_sig, rest} = CompactSize.decode_bytes(solution)
    {n, rest} = CompactSize.decode(rest)
    {stack, rest} = take(n, rest, [])
    if rest == <<>>, do: {:ok, replacement, script_sig, stack}, else: :error
  catch
    {:codec_error, _} -> :error
  end

  defp take(0, rest, acc), do: {Enum.reverse(acc), rest}

  defp take(n, bin, acc) do
    {item, rest} = CompactSize.decode_bytes(bin)
    take(n - 1, rest, [item | acc])
  end

  @doc """
  Core `FetchAndClearCommitmentSection`. Walks the script with GetOp, stopping
  at the first failed parse (trailing bytes are dropped). The first push
  longer than the header that starts with it is split: the rest becomes the
  solution, and the header alone is kept. Pushes are re-encoded with
  `CScript << vector` and non-push opcodes appended as-is.
  """
  def fetch_and_clear(script), do: walk(script, [], nil)

  defp walk(script, repl, found) do
    case Script.get_op(script) do
      :error ->
        if found, do: {:found, IO.iodata_to_binary(Enum.reverse(repl)), found}, else: :not_found

      {:ok, _op, data, rest} when byte_size(data) > 0 ->
        hs = byte_size(@signet_header)

        if found == nil and byte_size(data) > hs and binary_part(data, 0, hs) == @signet_header do
          walk(rest, [push(@signet_header) | repl], binary_part(data, hs, byte_size(data) - hs))
        else
          walk(rest, [push(data) | repl], found)
        end

      {:ok, op, _data, rest} ->
        walk(rest, [<<op>> | repl], found)
    end
  end

  # CScript::operator<<(std::span<const unsigned char>)
  defp push(d) when byte_size(d) < 0x4C, do: <<byte_size(d)>> <> d
  defp push(d) when byte_size(d) <= 0xFF, do: <<0x4C, byte_size(d)>> <> d
  defp push(d) when byte_size(d) <= 0xFFFF, do: <<0x4D, byte_size(d)::little-16>> <> d
  defp push(d), do: <<0x4E, byte_size(d)::little-32>> <> d

  defp finalize(tx) do
    {:ok, t} = tx |> Tx.encode() |> IO.iodata_to_binary() |> Tx.decode_exact()
    t
  end
end
