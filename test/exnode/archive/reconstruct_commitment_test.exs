defmodule Exnode.Archive.ReconstructCommitmentTest do
  @moduledoc """
  AUD-B5-1 (SECURITY_AUDIT_REPORT.md; regression): reading a block back
  re-checks it against its witness commitment, as a guard against storage
  faults. Whether a commitment is expected used to be guessed from the
  presence of a commitment-shaped coinbase output. A block below segwit
  activation may carry one without a coinbase witness (valid: Core's
  `ContextualCheckBlock` expects a commitment only once segwit is active),
  and its read raised `MatchError` on `bad-witness-nonce-size`: block
  serving answered notfound, RPC and REST failed, and a shadow catch-up
  over it crashed the chain state. Now the expectation is the block's height
  against the segwit height, as Core's.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @op_true <<0x51>>
  # OP_RETURN, push 36, the BIP141 header, then 32 bytes.
  @commitment_shaped <<0x6A, 0x24, 0xAA, 0x21, 0xA9, 0xED>> <> :binary.copy(<<0>>, 32)

  defp open(dir, opts) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    Archive.open(kv, Path.join(dir, "a"), nil, @p.genesis, opts)
  end

  test "a pre-segwit block with a commitment-shaped output and no witness reads back",
       %{tmp_dir: dir} do
    a = open(dir, segwit_height: 10)

    cb =
      BB.coinbase_with(1, 50 * 100_000_000,
        outputs: [{50 * 100_000_000, @op_true}, {0, @commitment_shaped}]
      )

    b = BB.build(@p.genesis.header, [cb])
    refute Enum.any?(b.txs, & &1.has_witness)

    a = a |> Archive.connect(b, 1, []) |> Archive.flush()
    %{id: id} = Archive.tip(a)
    assert Archive.read_block(a, id) == b.raw
  end

  test "at or above the segwit height the commitment is still checked on read",
       %{tmp_dir: dir} do
    # The same block is invalid once segwit is active (bad-witness-nonce-size),
    # so it is never stored there; written directly, reading it back must
    # still fail the self-check rather than serve it.
    a = open(dir, segwit_height: 1)

    cb =
      BB.coinbase_with(1, 50 * 100_000_000,
        outputs: [{50 * 100_000_000, @op_true}, {0, @commitment_shaped}]
      )

    b = BB.build(@p.genesis.header, [cb])
    a = a |> Archive.connect(b, 1, []) |> Archive.flush()
    %{id: id} = Archive.tip(a)
    assert_raise MatchError, fn -> Archive.read_block(a, id) end
  end
end
