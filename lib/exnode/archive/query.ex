defmodule Exnode.Archive.Query do
  @moduledoc """
  Read-side serving, undo, indexer and block-reconstruction queries over an
  `Exnode.Archive` (or `Archive.reader/1`).
  """

  alias Exnode.Archive
  alias Exnode.Archive.{Codec, Segments}
  alias Exnode.Codec.{Block, CompactSize, Header, Tx}
  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV
  alias Exnode.Validation.Block, as: BlockRules
  alias Exnode.Validation.Merkle

  # --- transaction & output serving --------------------------------------------

  @doc """
  Where txid's newest occurrence is (on-chain preferred, as Core's txindex
  returns the active-chain copy): `{:ok, block_id, pos}` or `:missing`.
  """
  def tx_location(%Archive{} = a, txid) do
    case KV.get(a.kv, :txindex, txid) do
      :not_found ->
        :missing

      {:ok, bin} ->
        entries = Codec.decode_txindex(bin)

        on =
          for {b, _, _, _, _} = e <- entries,
              {:ok, h} <- [Archive.chain_height(a, b)],
              do: {h, e}

        pick =
          if on != [],
            do: on |> Enum.max_by(&elem(&1, 0)) |> elem(1),
            else: List.last(entries)

        {b, pos, _, _, _} = pick
        {:ok, b, pos}
    end
  end

  @doc "Position of `txid` inside archived block `block_id`: `{:ok, pos}` or `:missing`."
  def tx_location_in_block(%Archive{} = a, txid, block_id) do
    case KV.get(a.kv, :txindex, txid) do
      :not_found ->
        :missing

      {:ok, bin} ->
        case Enum.find(Codec.decode_txindex(bin), fn {b, _, _, _, _} -> b == block_id end) do
          {^block_id, pos, _, _, _} -> {:ok, pos}
          nil -> :missing
        end
    end
  end

  @doc """
  Output `vout` of `txid` as `%Tx.Out{}`, or nil: unknown txid, `vout`
  out of range, or no occurrence on the selected chain (BIP30: the newest
  on-chain occurrence, as `Archive.resolve/3`). Spent outputs are returned too
  (this serves prevouts; spentness is `Archive.resolve/3`'s business). One output
  read, no block reconstruction and no merkle check: the data was checked
  when the block connected. For serving (REST), not validation.
  """
  def output(%Archive{} = a, txid, vout), do: outputs(a, [{txid, vout}])[{txid, vout}]

  @doc """
  `output/3` for many outpoints: `%{{txid, vout} => %Tx.Out{} | nil}`, one
  txindex `multi_get` and output reads grouped by location.
  """
  def outputs(_a, []), do: %{}

  def outputs(%Archive{} = a, outpoints) do
    outpoints = Enum.uniq(outpoints)
    ids = output_ids(a, outpoints)
    recs = Archive.read_outputs(a, Map.values(ids))

    Map.new(outpoints, fn op ->
      case ids do
        %{^op => id} ->
          (fn {v, spk} -> {op, %Tx.Out{value: v, script_pubkey: spk}} end).(Map.fetch!(recs, id))

        _ ->
          {op, nil}
      end
    end)
  end

  # outpoint => output id, at the txid's newest on-chain occurrence (one
  # txindex multi_get); unknown txids and vouts out of range left out.
  defp output_ids(a, outpoints) do
    txids = outpoints |> Enum.map(&elem(&1, 0)) |> Enum.uniq()

    located =
      txids
      |> Enum.zip(KV.multi_get(a.kv, :txindex, txids))
      |> Enum.flat_map(fn {txid, r} ->
        case Archive.newest_on_chain(a, r) do
          nil -> []
          {_b, _pos, base_out, nout, _} -> [{txid, {base_out, nout}}]
        end
      end)
      |> Map.new()

    for {txid, vout} = op <- outpoints,
        {base, n} = Map.get(located, txid, {nil, 0}),
        vout >= 0 and vout < n,
        into: %{},
        do: {op, base + vout}
  end

  @doc """
  The on-chain spenders of `outpoints` (for serving):
  `%{outpoint => {spending_txid, input_index, header, pos}}`; unspent,
  unknown and BIP30-overwritten outpoints are absent. The outpoint is its
  txid's newest on-chain occurrence (as `outputs/2`); its spend record
  (`spends`, one seek per output, one iterator) in a block on the selected
  chain gives that block and the input id, the block's record the spending
  tx's position and input index, and that tx's base records its txid (one
  tx read per spending tx, no block reconstruction).
  """
  def spenders(_a, []), do: %{}

  def spenders(%Archive{} = a, outpoints) do
    ids = output_ids(a, Enum.uniq(outpoints))
    spends = spend_records(a, Map.values(ids))

    {result, _cache} =
      Enum.reduce(ids, {%{}, %{}}, fn {op, out_id}, {acc, cache} ->
        case spends do
          %{^out_id => {b, input_id}} ->
            {rec, cache} = cached(cache, {:rec, b}, fn -> Archive.block_record!(a, b) end)
            {pos, vin} = input_position(rec.txs, input_id - rec.base_in, 0)
            {txid, cache} = cached(cache, {:txid, b, pos}, fn -> tx_at(a, rec, pos).txid end)
            {header, ""} = Header.decode(rec.header)
            {Map.put(acc, op, {txid, vin, header, pos}), cache}

          _ ->
            {acc, cache}
        end
      end)

    result
  end

  defp cached(cache, k, f) do
    case cache do
      %{^k => v} -> {v, cache}
      _ -> (fn v -> {v, Map.put(cache, k, v)} end).(f.())
    end
  end

  # out_id => {block_id, input_id} of its spend record in an on-chain block.
  defp spend_records(_a, []), do: %{}

  defp spend_records(a, ids) do
    KV.with_iterator(a.kv, :spends, fn it ->
      ids
      |> Enum.sort()
      |> Enum.uniq()
      |> Enum.reduce(%{}, fn id, acc ->
        case spend_record(a, it, KV.iter_move(it, :spends, {:seek, <<id::64>>}), id) do
          nil -> acc
          r -> Map.put(acc, id, r)
        end
      end)
    end)
  end

  defp spend_record(a, it, {:ok, <<id::64, b::32>>, <<input::64>>}, id) do
    if Archive.on_chain?(a, b),
      do: {b, input},
      else: spend_record(a, it, KV.iter_move(it, :spends, :next), id)
  end

  defp spend_record(_a, _it, _, _id), do: nil

  # {tx position, input index} of the block's `k`th input (counting every
  # input, the coinbase's too, as input ids do).
  defp input_position([{_, _, ni, _, _} | txs], k, pos) when k >= ni,
    do: input_position(txs, k - ni, pos + 1)

  defp input_position([_ | _], k, pos), do: {pos, k}

  @doc """
  One tx read from the archive without reconstructing its block, at
  `tx_location/2`: `{:ok, %Tx{}, header, block_id, pos}` or `:missing`. The
  tx is decoded from its exact serialization, as in `read_block_txs/2`
  (witnesses empty when they are pruned).
  """
  def read_tx(%Archive{} = a, txid) do
    case tx_location(a, txid) do
      :missing ->
        :missing

      {:ok, id, pos} ->
        rec = Archive.block_record!(a, id)
        {header, ""} = Header.decode(rec.header)
        {:ok, tx_at(a, rec, pos), header, id, pos}
    end
  end

  defp read_tx_witness(a, rec, in0, ni) do
    if Map.has_key?(rec, :wloc),
      do: Segments.read_run(a.readers.witness, rec.wloc, in0, ni, &Codec.decode_witness/1),
      else: Archive.read_records(a, :witness, rec.base_in + in0, ni, &Codec.decode_witness/1)
  end

  # The tx at `pos` in the block of record `rec`, from its records (its
  # exact serialization; witnesses empty when pruned).
  defp tx_at(a, rec, pos) do
    {before, [{ver, lt, ni, no, _} | _]} = Enum.split(rec.txs, pos)
    in0 = Enum.reduce(before, 0, fn {_, _, n, _, _}, acc -> acc + n end)
    out0 = Enum.reduce(before, 0, fn {_, _, _, n, _}, acc -> acc + n end)
    ins = Archive.read_records(a, :inputs, rec.base_in + in0, ni, &Codec.decode_input/1)

    wits =
      cond do
        Archive.rec_pruned?(a, rec) ->
          List.duplicate([], ni)

        ni == 0 ->
          []

        true ->
          if_not_pruned(
            a,
            rec,
            fn -> read_tx_witness(a, rec, in0, ni) end,
            List.duplicate([], ni)
          )
      end

    outs = Archive.read_records(a, :outputs, rec.base_out + out0, no, &Codec.decode_output/1)

    inputs =
      for {{ph, pi, ss, seq}, w} <- Enum.zip(ins, wits),
          do: %Tx.In{prev_hash: ph, prev_index: pi, script_sig: ss, sequence: seq, witness: w}

    tx = %Tx{
      version: ver,
      inputs: inputs,
      outputs: for({v, spk} <- outs, do: %Tx.Out{value: v, script_pubkey: spk}),
      locktime: lt
    }

    {:ok, tx} = tx |> Tx.encode() |> IO.iodata_to_binary() |> Tx.decode_exact()
    tx
  end

  @doc """
  Reads one full transaction at `{id, pos}` with intact witnesses (for RPC
  `getrawtransaction`): `{:ok, %Tx{}, rec}` or `{:error, :witness_pruned}`.
  """
  def read_tx_strict(%Archive{} = a, id, pos) do
    committed!(a, id)
    rec = Archive.block_record!(a, id)

    if Archive.rec_pruned?(a, rec) do
      {:error, :witness_pruned}
    else
      if_not_pruned(
        a,
        rec,
        fn -> {:ok, tx_at_strict(a, rec, pos), rec} end,
        {:error, :witness_pruned}
      )
    end
  end

  defp tx_at_strict(a, rec, pos) do
    {before, [{ver, lt, ni, no, _} | _]} = Enum.split(rec.txs, pos)
    in0 = Enum.reduce(before, 0, fn {_, _, n, _, _}, acc -> acc + n end)
    out0 = Enum.reduce(before, 0, fn {_, _, _, n, _}, acc -> acc + n end)
    ins = Archive.read_records(a, :inputs, rec.base_in + in0, ni, &Codec.decode_input/1)
    wits = if ni == 0, do: [], else: read_tx_witness(a, rec, in0, ni)
    outs = Archive.read_records(a, :outputs, rec.base_out + out0, no, &Codec.decode_output/1)

    inputs =
      for {{ph, pi, ss, seq}, w} <- Enum.zip(ins, wits),
          do: %Tx.In{prev_hash: ph, prev_index: pi, script_sig: ss, sequence: seq, witness: w}

    tx = %Tx{
      version: ver,
      inputs: inputs,
      outputs: for({v, spk} <- outs, do: %Tx.Out{value: v, script_pubkey: spk}),
      locktime: lt
    }

    {:ok, tx} = tx |> Tx.encode() |> IO.iodata_to_binary() |> Tx.decode_exact()
    tx
  end

  # --- undo / origin / filter queries ------------------------------------------

  @doc """
  The outputs a block's non-coinbase inputs spent (Core's undo data), in
  input order: `[%{value, script_pubkey, height, coinbase}]`.
  """
  def spent_outputs(%Archive{} = a, block_id) do
    rec = Archive.block_record!(a, block_id)
    spent_outputs_for_ids(a, rec.undo)
  end

  @doc """
  Slice of `rec.undo` starting at non-coinbase input `skip` for `count` inputs,
  batching segment reads and memoizing `:blocks` probes across inputs.
  """
  def spent_outputs_slice(%Archive{} = a, rec, skip, count) do
    spent_outputs_for_ids(a, Enum.slice(rec.undo, skip, count))
  end

  defp spent_outputs_for_ids(_a, []), do: []

  defp spent_outputs_for_ids(a, out_ids) do
    outs = Archive.read_outputs(a, out_ids)
    max_id = a.next.block - 1

    {list, _cache} =
      Enum.map_reduce(out_ids, %{}, fn out_id, cache ->
        {value, spk} = Map.fetch!(outs, out_id)
        {{height, coinbase}, cache} = output_origin_cached(a, out_id, max_id, cache)
        {%{value: value, script_pubkey: spk, height: height, coinbase: coinbase}, cache}
      end)

    list
  end

  defp output_origin_cached(a, out_id, max_id, cache) do
    {id, cache} = search_block_cached(a, out_id, 0, max_id, cache)
    {info, cache} = block_origin_info(a, id, cache)
    {{info.height, out_id < info.base_out + info.n0}, cache}
  end

  defp search_block_cached(_a, _out, lo, hi, cache) when lo >= hi, do: {lo, cache}

  defp search_block_cached(a, out, lo, hi, cache) do
    mid = div(lo + hi + 1, 2)
    {info, cache} = block_origin_info(a, mid, cache)

    if info.base_out <= out,
      do: search_block_cached(a, out, mid, hi, cache),
      else: search_block_cached(a, out, lo, mid - 1, cache)
  end

  defp block_origin_info(a, id, cache) do
    case cache do
      %{^id => info} ->
        {info, cache}

      _ ->
        rec = Archive.block_record!(a, id)
        {_, _, _, n0, _} = hd(rec.txs)
        info = %{base_out: rec.base_out, height: rec.height, n0: n0}
        {info, Map.put(cache, id, info)}
    end
  end

  @doc """
  The block's output scripts (all txs, in order) and the scripts its inputs
  spent, without reconstructing the block (so witness pruning does not matter).
  """
  def block_scripts(%Archive{} = a, id) do
    rec = Archive.block_record!(a, id)
    n_out = Enum.reduce(rec.txs, 0, fn {_, _, _, no, _}, acc -> acc + no end)

    outs =
      for {_v, spk} <-
            Archive.read_records(a, :outputs, rec.base_out, n_out, &Codec.decode_output/1),
          do: spk

    spent = for out_id <- rec.undo, do: elem(Archive.read_output(a, out_id), 1)
    {outs, spent}
  end

  @doc """
  The outputs a block spent, `{value, script_pubkey}` for each of its
  record's `undo` ids (`Archive.block_record!/2`), in that order: the exact
  archived outputs (spent, overwritten or disconnected since, all the
  same). Each distinct id is read once, grouped by sparse-index base in
  physical order (`Archive.read_outputs/2`); an id listed twice (storage
  fixtures) fills both positions.
  """
  def undo_outputs(%Archive{} = a, %{undo: undo}) do
    outs = Archive.read_outputs(a, undo)
    for id <- undo, do: Map.fetch!(outs, id)
  end

  @doc """
  The base (non-witness) transaction data of committed block `id`, for
  building indexes. Reads only the block record and its input and output
  records, never witness records, so pruned or cold witnesses make no
  difference. Returns `{:ok, %{hash, header, txs}}` with, per tx in block
  order, `{txid, prevouts, outputs}`: `prevouts` are `[{prev_hash,
  prev_index}]` and `outputs` `[{value, script_pubkey}]`, both in order.

  Failures are archive faults, never verdicts on a block:
  `{:error, {:archive_integrity, reason}}` for a mismatch, and a raise for
  a truncated segment, as in the strict readers. A pending (uncommitted)
  block raises.
  """
  def read_index_facts(%Archive{} = a, id) do
    committed!(a, id)
    read_index_facts(a, id, Archive.block_record!(a, id))
  end

  @doc "`read_index_facts/2` with block `id`'s record already read (`Archive.block_record!/2`); it must be `id`'s record."
  def read_index_facts(%Archive{} = a, id, rec) do
    committed!(a, id)
    t0 = System.monotonic_time(:microsecond)

    with {:ok, header} <- facts_header(a, id, rec),
         {:ok, n_in, n_out} <- facts_counts(rec) do
      ins = Archive.read_records(a, :inputs, rec.base_in, n_in, &Codec.decode_input_raw/1)
      outs = Archive.read_records(a, :outputs, rec.base_out, n_out, &Codec.decode_output_raw/1)
      t1 = System.monotonic_time(:microsecond)

      {txs, {ins_left, outs_left}} =
        Enum.map_reduce(rec.txs, {ins, outs}, fn {ver, lt, ni, no, _hw}, {ins, outs} ->
          {tin, ins} = Enum.split(ins, ni)
          {tout, outs} = Enum.split(outs, no)

          stripped = [
            <<ver::little-32>>,
            CompactSize.encode(ni),
            Enum.map(tin, &elem(&1, 2)),
            CompactSize.encode(no),
            Enum.map(tout, &elem(&1, 2)),
            <<lt::little-32>>
          ]

          {{Hash.hash256(stripped), for({ph, pi, _} <- tin, do: {ph, pi}),
            for({v, spk, _} <- tout, do: {v, spk})}, {ins, outs}}
        end)

      t2 = System.monotonic_time(:microsecond)
      {root, mutated} = Merkle.compute_root(for {txid, _, _} <- txs, do: txid)
      Archive.bump_stat(:facts_blocks, 1)
      Archive.bump_stat(:facts_read_us, t1 - t0)
      Archive.bump_stat(:facts_txid_us, t2 - t1)
      Archive.bump_stat(:facts_merkle_us, System.monotonic_time(:microsecond) - t2)

      cond do
        ins_left != [] or outs_left != [] -> {:error, {:archive_integrity, :leftover_records}}
        root != header.merkle_root -> {:error, {:archive_integrity, "bad-txnmrklroot"}}
        mutated -> {:error, {:archive_integrity, "bad-txns-duplicate"}}
        not coinbase_prevouts?(hd(txs)) -> {:error, {:archive_integrity, :first_tx_not_coinbase}}
        true -> {:ok, %{hash: header.hash, header: header, txs: txs}}
      end
    end
  end

  defp facts_header(a, id, rec) do
    {header, ""} = Header.decode(rec.header)

    cond do
      Map.get(rec, :hash, header.hash) != header.hash ->
        {:error, {:archive_integrity, :record_hash}}

      Archive.block_id(a, header.hash) != id ->
        {:error, {:archive_integrity, :record_not_block}}

      true ->
        {:ok, header}
    end
  end

  defp facts_counts(%{txs: [_ | _] = txs} = rec) do
    ok? =
      Map.get(rec, :n_tx, length(txs)) == length(txs) and
        Enum.all?(txs, fn
          {ver, lt, ni, no, _} ->
            is_integer(ver) and ver in -0x80000000..0xFFFFFFFF and is_integer(lt) and
              lt in 0..0xFFFFFFFF and
              is_integer(ni) and ni >= 1 and is_integer(no) and no >= 1

          _ ->
            false
        end)

    if ok?,
      do:
        {:ok, Enum.reduce(txs, 0, &(elem(&1, 2) + &2)), Enum.reduce(txs, 0, &(elem(&1, 3) + &2))},
      else: {:error, {:archive_integrity, :tx_metadata}}
  end

  defp facts_counts(_rec), do: {:error, {:archive_integrity, :tx_metadata}}

  defp coinbase_prevouts?({_txid, [{<<0::256>>, 0xFFFFFFFF}], _outs}), do: true
  defp coinbase_prevouts?(_), do: false

  @doc "`{height, coinbase?}` of the block that created output `out_id` (binary search on block base ids)."
  def output_origin(%Archive{} = a, out_id) do
    id = search_block(a, out_id, 0, a.next.block - 1)
    rec = Archive.block_record!(a, id)
    {_, _, _, n0, _} = hd(rec.txs)
    {rec.height, out_id < rec.base_out + n0}
  end

  defp search_block(_a, _out, lo, hi) when lo >= hi, do: lo

  defp search_block(a, out, lo, hi) do
    mid = div(lo + hi + 1, 2)

    if Archive.block_record!(a, mid).base_out <= out,
      do: search_block(a, out, mid, hi),
      else: search_block(a, out, lo, mid - 1)
  end

  # --- block reconstruction ----------------------------------------------------

  @doc """
  Reconstructs the block's exact serialized bytes from the archive, and checks
  them against the stored merkle root and witness commitment before returning.
  """
  def read_block(%Archive{} = a, id) do
    committed!(a, id)

    case read_checked(a, id, Archive.block_record!(a, id)) do
      {:ok, raw, _block} -> raw
      err -> err
    end
  end

  @doc """
  The block's transactions. With pruned witness data the witnesses are
  empty, so txids, inputs and outputs are exact but wtxids are not.
  `{:ok, %Block{}}`.
  """
  def read_block_txs(%Archive{} = a, id) do
    committed!(a, id)
    read_block_txs(a, id, Archive.block_record!(a, id))
  end

  @doc "`read_block_txs/2` with block `id`'s record already read (`Archive.block_record!/2`)."
  def read_block_txs(%Archive{} = a, id, rec) do
    case read_checked(a, id, rec) do
      {:ok, _raw, block} ->
        {:ok, block}

      {:error, :witness_pruned} ->
        {header, ""} = Header.decode(rec.header)
        n_in = Enum.reduce(rec.txs, 0, fn {_, _, ni, _, _}, acc -> acc + ni end)
        n_out = Enum.reduce(rec.txs, 0, fn {_, _, _, no, _}, acc -> acc + no end)
        ins = Archive.read_records(a, :inputs, rec.base_in, n_in, &Codec.decode_input/1)
        outs = Archive.read_records(a, :outputs, rec.base_out, n_out, &Codec.decode_output/1)

        {txs, _} =
          Enum.map_reduce(rec.txs, {ins, outs}, fn {ver, lt, ni, no, _}, {ins, outs} ->
            {tin, ins} = Enum.split(ins, ni)
            {tout, outs} = Enum.split(outs, no)

            inputs =
              for {ph, pi, ss, seq} <- tin,
                  do: %Tx.In{
                    prev_hash: ph,
                    prev_index: pi,
                    script_sig: ss,
                    sequence: seq,
                    witness: []
                  }

            {%Tx{
               version: ver,
               inputs: inputs,
               outputs: for({v, spk} <- tout, do: %Tx.Out{value: v, script_pubkey: spk}),
               locktime: lt
             }, {ins, outs}}
          end)

        %Block{header: header, txs: txs}
        |> Block.encode()
        |> IO.iodata_to_binary()
        |> Block.decode_exact()
    end
  end

  defp read_checked(%Archive{} = a, id, rec) do
    committed!(a, id)

    if Archive.rec_pruned?(a, rec),
      do: {:error, :witness_pruned},
      else: if_not_pruned(a, rec, fn -> reconstruct(a, rec) end, {:error, :witness_pruned})
  end

  defp committed!(%Archive{batch: %{blocks: pending}}, id),
    do:
      if(is_map_key(pending, id), do: raise("read_block of uncommitted block #{id}; flush first"))

  # Runs a witness read; if it fails because the segment was pruned
  # meanwhile (the prune point is raised before the files go), `pruned`
  # instead. Any other failure is raised: a missing file that was not
  # pruned is data loss, not a race.
  defp if_not_pruned(a, rec, read, pruned) do
    read.()
  rescue
    e -> if Archive.rec_pruned?(a, rec), do: pruned, else: reraise(e, __STACKTRACE__)
  end

  defp reconstruct(a, rec) do
    {header, ""} = Header.decode(rec.header)
    n_in = Enum.reduce(rec.txs, 0, fn {_, _, ni, _, _}, acc -> acc + ni end)
    n_out = Enum.reduce(rec.txs, 0, fn {_, _, _, no, _}, acc -> acc + no end)
    ins = Archive.read_records(a, :inputs, rec.base_in, n_in, &Codec.decode_input/1)

    wits =
      case rec do
        %{wloc: loc} ->
          Segments.read_run(a.readers.witness, loc, 0, n_in, &Codec.decode_witness/1)

        _ ->
          Archive.read_records(a, :witness, rec.base_in, n_in, &Codec.decode_witness/1)
      end

    outs = Archive.read_records(a, :outputs, rec.base_out, n_out, &Codec.decode_output/1)

    {txs, {[], [], []}} =
      Enum.map_reduce(rec.txs, {ins, wits, outs}, fn {ver, lt, ni, no, _hw}, {ins, wits, outs} ->
        {tin, ins} = Enum.split(ins, ni)
        {twit, wits} = Enum.split(wits, ni)
        {tout, outs} = Enum.split(outs, no)

        inputs =
          for {{ph, pi, ss, seq}, w} <- Enum.zip(tin, twit),
              do: %Tx.In{prev_hash: ph, prev_index: pi, script_sig: ss, sequence: seq, witness: w}

        outputs = for {v, spk} <- tout, do: %Tx.Out{value: v, script_pubkey: spk}
        {%Tx{version: ver, inputs: inputs, outputs: outputs, locktime: lt}, {ins, wits, outs}}
      end)

    raw = IO.iodata_to_binary(Block.encode(%Block{header: header, txs: txs}))
    {:ok, block} = Block.decode_exact(raw)
    :ok = BlockRules.check_merkle_root(block)

    # Core ContextualCheckBlock: a commitment is expected once segwit is
    # active, whatever the coinbase looks like. A pre-segwit block may carry
    # a commitment-shaped output without a coinbase witness.
    :ok = BlockRules.check_witness_malleation(block, rec.height >= a.segwit_height)

    {:ok, raw, block}
  end
end
