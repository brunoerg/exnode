defmodule Exnode.Archive.IndexFactsTest do
  @moduledoc """
  `Archive.read_index_facts/2,3`: base transaction data for indexes, with no
  witness reads and no full-block decode.

  - Agreement with the strict reader (`read_block_txs/2`) on real testnet
    blocks (Core's BIP158 vectors, legacy and witness). There the header's
    merkle root, computed by other software, is the independent check on
    the stripped serialization.
  - The genesis txid as a literal.
  - CompactSize boundaries, signed values and 32-bit fields.
  - Witness pruning, a cold inputs dir and segment rollover.
  - Legacy records, committed-only access and record/block identity.
  - Base-data corruption and metadata faults.
  - Witness corruption: outside this reader's contract, still caught by
    the strict reader.
  """
  use ExUnit.Case, async: true

  alias Exnode.{Archive, ChainParams}
  alias Exnode.Archive.Segments
  alias Exnode.Codec.{Block, Tx}
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @vectors Path.expand("../../fixtures/core-v32.1/blockfilters.json", __DIR__)

  # What the strict reader implies for the facts.
  defp strict_facts(r, id) do
    {:ok, b} = Archive.read_block_txs(r, id)

    for tx <- b.txs,
        do:
          {tx.txid, for(i <- tx.inputs, do: {i.prev_hash, i.prev_index}),
           for(o <- tx.outputs, do: {o.value, o.script_pubkey})}
  end

  defp facts!(r, id) do
    {:ok, f} = Archive.read_index_facts(r, id)
    f.txs
  end

  defp open(dir, opts \\ []) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    cold = if opts[:cold], do: Path.join(dir, "cold")
    a = Archive.open(kv, Path.join(dir, "hot"), cold, @p.genesis, Keyword.delete(opts, :cold))
    {kv, a}
  end

  defp non_coinbase_inputs(%Block{txs: [_ | txs]}),
    do: Enum.reduce(txs, 0, &(length(&1.inputs) + &2))

  # Archives `blocks` at heights 1.. (spent ids are storage fixtures: the
  # facts reader does not use them).
  defp connect_all(a, blocks) do
    blocks
    |> Enum.with_index(1)
    |> Enum.reduce(a, fn {b, h}, a ->
      Archive.connect(a, b, h, List.duplicate(0, non_coinbase_inputs(b)))
    end)
    |> Archive.flush()
  end

  defp segwit_block(prev, height, txs) do
    cb = fn extra, wit ->
      BB.coinbase_with(height, 0, outputs: [{50 * @coin, <<0x51>>} | extra], witness: wit)
    end

    BB.build_segwit(prev, cb, txs)
  end

  # Calls to Segments.read_run/5,6 (the reader's kind) and to the block
  # and transaction decoders, made by this process while `fun` runs.
  defp traced(fun) do
    pats = [{Segments, :read_run, :_}, {Block, :decode_exact, 1}, {Tx, :decode, 1}]
    {result, calls} = Exnode.Test.CallTrace.calls(pats, fun, [:global])

    {result,
     Enum.map(calls, fn
       {Segments, :read_run, [%Segments.Reader{dir: d} | _]} -> {:read, Path.basename(d)}
       {m, f, _} -> {m, f}
     end)}
  end

  # Rewrites the first occurrence of `pattern` in the `kind` segments.
  defp patch_segment(root, kind, pattern, replacement) do
    hit =
      Enum.find_value(Path.wildcard(Path.join([root, kind, "*"])), fn f ->
        bin = File.read!(f)

        case :binary.match(bin, pattern) do
          {pos, _} -> {f, bin, pos}
          :nomatch -> nil
        end
      end)

    {f, bin, pos} = hit || flunk("#{inspect(pattern)} not in #{kind} segments")

    File.write!(f, [
      binary_part(bin, 0, pos),
      replacement,
      binary_part(bin, pos + byte_size(pattern), byte_size(bin) - pos - byte_size(pattern))
    ])
  end

  test "real testnet blocks (BIP158 vectors, legacy and witness): facts equal the strict reader, txids commit to each header",
       %{tmp_dir: dir} do
    [_ | rows] = @vectors |> File.read!() |> Jason.decode!()

    blocks =
      for [_h, hash, hex | _] <- rows,
          do: {hash, hex |> Base.decode16!(case: :lower) |> Block.decode_exact() |> elem(1)}

    # At least one vector carries witness data (txid differs from wtxid).
    assert Enum.any?(blocks, fn {_, b} -> Enum.any?(b.txs, &(&1.txid != &1.wtxid)) end)

    {kv, a} = open(dir)
    a = connect_all(a, Enum.map(blocks, &elem(&1, 1)))
    r = Archive.reader(a)

    for {{hash, b}, h} <- Enum.with_index(blocks, 1) do
      id = Archive.id_at(r, h)
      {:ok, f} = Archive.read_index_facts(r, id)
      assert Hash.to_hex(f.hash) == hash
      assert f.txs == strict_facts(r, id), "vector block #{hash}"
      assert for({txid, _, _} <- f.txs, do: txid) == for(tx <- b.txs, do: tx.txid)
    end

    # Genesis (the regtest genesis coinbase is the mainnet one).
    assert [{txid, [{<<0::256>>, 0xFFFFFFFF}], [{5_000_000_000, _}]}] = facts!(r, 0)
    assert Hash.to_hex(txid) == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    Archive.close(a)
    KV.close(kv)
  end

  test "CompactSize boundaries, signed values and 32-bit fields; witness pruning, cold inputs and rollover change nothing",
       %{tmp_dir: dir} do
    p = <<7::256>>
    big = fn n, byte -> :binary.copy(<<byte>>, n) end

    txs = [
      # 253 inputs and 253 outputs (0xfd counts); scriptSig 253 bytes.
      BB.tx(
        for(
          i <- 0..252,
          do: {p, i, script_sig: if(i == 0, do: big.(253, 1), else: <<i::16>>), sequence: i}
        ),
        for(v <- 0..252, do: {v, <<0x51, v>>})
      ),
      # 0xfe script length, negative value, extreme version/locktime bits.
      BB.tx(
        [{p, 0xFFFFFFFF, script_sig: big.(252, 2), sequence: 0}],
        [{-1, big.(65_536, 3)}, {0x7FFFFFFFFFFFFFFF, big.(0xFFFF, 4)}],
        version: 0xFFFFFFFF,
        locktime: 0xFFFFFFFF
      ),
      BB.tx([{p, 1, witness: [big.(80, 5), <<>>]}], [{1, <<0x00, 0x14>> <> big.(20, 6)}],
        version: 0x80000000,
        locktime: 1
      )
    ]

    blocks =
      Enum.reduce(1..8, [], fn h, acc ->
        prev = if acc == [], do: @p.genesis.header, else: hd(acc).header
        w = BB.tx([{<<h::256>>, 0, witness: [big.(100 + h, 8)]}], [{h, <<0x51>>}])
        [segwit_block(prev, h, if(h == 3, do: txs, else: [w])) | acc]
      end)
      |> Enum.reverse()

    {kv1, a1} = open(Path.join(dir, "plain"))
    a1 = connect_all(a1, blocks)
    r1 = Archive.reader(a1)
    {kv2, a2} = open(Path.join(dir, "pruned"), max: 300, prune_keep: 1, cold: true)
    a2 = connect_all(a2, blocks)
    r2 = Archive.reader(a2)
    assert Archive.witness_pruned(r2) >= 1

    for h <- 0..8 do
      id = Archive.id_at(r1, h)
      assert facts!(r1, id) == strict_facts(r1, id), "height #{h}"
      assert facts!(r2, Archive.id_at(r2, h)) == facts!(r1, id), "pruned, height #{h}"
    end

    b3 = Enum.at(blocks, 2)
    assert Enum.map(facts!(r1, 3), &elem(&1, 0)) == Enum.map(b3.txs, & &1.txid)
    assert Archive.read_block(r2, Archive.id_at(r2, 3)) == {:error, :witness_pruned}

    # The seam: no witness segment read and no block or transaction decode,
    # where the strict reader does both.
    {_, calls} = traced(fn -> Archive.read_index_facts(r1, 3) end)
    assert {:read, "inputs"} in calls and {:read, "outputs"} in calls
    refute {:read, "witness"} in calls
    refute Enum.any?(calls, &match?({Block, _}, &1))
    refute Enum.any?(calls, &match?({Tx, _}, &1))
    {_, strict} = traced(fn -> Archive.read_block_txs(r1, 3) end)
    assert {:read, "witness"} in strict and {Block, :decode_exact} in strict

    for {a, kv} <- [{a1, kv1}, {a2, kv2}],
        do:
          (
            Archive.close(a)
            KV.close(kv)
          )
  end

  test "legacy records, preloaded records, committed-only access, duplicate-subtree mutation", %{
    tmp_dir: dir
  } do
    {kv, a} = open(dir)
    t1 = BB.tx([{<<1::256>>, 0}], [{1, <<0x51>>}])
    t2 = BB.tx([{<<2::256>>, 0}], [{2, <<0x52>>}])
    b1 = BB.build(@p.genesis.header, [BB.coinbase(1, 50 * @coin), t1, t2])
    # [cb, t1, t2, t2] has the root of [cb, t1, t2] (CVE-2012-2459).
    b2 = BB.build(b1.header, [BB.coinbase(2, 50 * @coin), t1, t2, t2])
    a = connect_all(a, [b1, b2])
    r = Archive.reader(a)
    id1 = Archive.id_at(r, 1)
    id2 = Archive.id_at(r, 2)
    rec1 = Archive.block_record!(r, id1)
    want = facts!(r, id1)

    assert Archive.read_index_facts(r, id1, rec1) == Archive.read_index_facts(r, id1)

    assert Archive.read_index_facts(r, id2) ==
             {:error, {:archive_integrity, "bad-txns-duplicate"}}

    # A record of another block, or with a hash its header does not have.
    assert Archive.read_index_facts(r, id2, rec1) ==
             {:error, {:archive_integrity, :record_not_block}}

    assert Archive.read_index_facts(r, id1, %{rec1 | hash: <<0::256>>}) ==
             {:error, {:archive_integrity, :record_hash}}

    # Records written before :hash, :n_tx, :wloc and :wseg existed.
    legacy = Map.drop(rec1, [:hash, :n_tx, :wloc, :wseg])
    :ok = KV.write(kv, [{:put, :blocks, <<id1::32>>, :erlang.term_to_binary(legacy)}])
    assert facts!(Archive.reader(a), id1) == want

    # Metadata faults.
    for bad <- [
          %{legacy | txs: []},
          Map.put(legacy, :n_tx, 2),
          %{legacy | txs: List.update_at(legacy.txs, 1, &put_elem(&1, 2, 0))},
          %{legacy | txs: List.update_at(legacy.txs, 1, &put_elem(&1, 0, 0x100000000))}
        ] do
      assert Archive.read_index_facts(r, id1, bad) == {:error, {:archive_integrity, :tx_metadata}}
    end

    # Shifted counts read other records: the txids no longer commit.
    shifted = %{
      legacy
      | txs:
          legacy.txs
          |> List.update_at(1, &put_elem(&1, 3, 2))
          |> List.update_at(2, &put_elem(&1, 3, 0))
    }

    assert {:error, {:archive_integrity, _}} = Archive.read_index_facts(r, id1, shifted)

    # A block still in the batch is not readable.
    b3 = BB.build(b2.header, [BB.coinbase(3, 50 * @coin)])
    a = Archive.connect(a, b3, 3, [], commit: false, delta: %{created: %{}, spent: []})
    id3 = Archive.block_id(a, b3.header.hash)
    assert_raise RuntimeError, ~r/uncommitted/, fn -> Archive.read_index_facts(a, id3) end
    assert_raise RuntimeError, ~r/uncommitted/, fn -> Archive.read_index_facts(a, id3, %{}) end
    Archive.close(Archive.flush(a))
    KV.close(kv)
  end

  test "base corruption fails the merkle check; witness corruption only fails the strict reader",
       %{tmp_dir: dir} do
    mark = fn n -> :binary.copy(<<0xA5, n>>, 12) end

    t =
      BB.tx(
        [{<<9::256>>, 0, script_sig: mark.(1), sequence: 0x0BADF00D, witness: [mark.(2)]}],
        [{5, <<0x6A>> <> mark.(3)}]
      )

    b1 = segwit_block(@p.genesis.header, 1, [t])

    for {what, kind, from, to} <- [
          {:script_sig, "inputs", mark.(1), mark.(9)},
          {:sequence, "inputs", <<0x0BADF00D::little-32>>, <<0x0BADF00E::little-32>>},
          {:script_pubkey, "outputs", mark.(3), mark.(9)},
          {:witness, "witness", mark.(2), mark.(9)}
        ] do
      d = Path.join(dir, "#{what}")
      {kv, a} = open(d)
      a = connect_all(a, [b1])
      r = Archive.reader(a)
      id = Archive.id_at(r, 1)
      good = facts!(r, id)
      patch_segment(Path.join(d, "hot"), kind, from, to)

      if what == :witness do
        assert facts!(r, id) == good
        assert catch_error(Archive.read_block(r, id))
      else
        assert Archive.read_index_facts(r, id) ==
                 {:error, {:archive_integrity, "bad-txnmrklroot"}},
               "#{what}"

        assert catch_error(Archive.read_block(r, id))
      end

      Archive.close(a)
      KV.close(kv)
    end

    # A truncated inputs segment raises, as in the strict readers.
    d = Path.join(dir, "truncated")
    {kv, a} = open(d)
    a = connect_all(a, [b1])
    r = Archive.reader(a)
    [f | _] = Path.wildcard(Path.join([d, "hot", "inputs", "*"])) |> Enum.reverse()
    File.write!(f, binary_part(File.read!(f), 0, File.stat!(f).size - 10))

    assert_raise RuntimeError, ~r/truncated/, fn ->
      Archive.read_index_facts(r, Archive.id_at(r, 1))
    end

    Archive.close(a)
    KV.close(kv)
  end
end
