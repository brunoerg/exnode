defmodule Exnode.Properties.ReorgCoinModelTest do
  @moduledoc """
  Adversarial branch switching against an independent spendability model.

  Two branches from a common fork spend the SAME mature coins differently
  (double-spend pairs). The chain is switched back and forth repeatedly
  (each time the other branch is made longer), with a small commit batch so
  reorgs span committed and uncommitted blocks, with a mid-sequence kill -9
  (restart replay), and with prefetch on and off.

  After every transition, every outpoint ever created is resolved through
  the archive and compared with a simple independent model of the selected
  branch's spendable set (outpoint => {value, script, height, coinbase}).
  This catches: inactive-branch outputs becoming spendable, spent outputs
  resurrecting, wrong occurrence resolution, disconnect not undoing spends,
  and prefetch/batch/overlay divergence.
  """
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Exnode.Archive
  alias Exnode.Chain.{Headers, State}
  alias Exnode.ChainParams
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @moduletag timeout: 600_000
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  @op_true <<0x51>>
  @op_true2 <<0x51, 0x51>>

  # --- independent model -----------------------------------------------------
  # model: %{active: MapSet of {txid,vout}, info: %{op => {value, spk, height, coinbase}}}
  # Only spendable outputs are tracked (Archive.resolve never returns those).

  defp spendable?(spk), do: not (match?(<<0x6A, _::binary>>, spk) or byte_size(spk) > 10_000)

  # Per-tx, in order: a tx's inputs are spent before its outputs are created
  # (in-block chains).
  defp model_connect(model, block, height) do
    block.txs
    |> Enum.with_index()
    |> Enum.reduce(model, fn {tx, pos}, m ->
      m =
        if pos == 0 do
          m
        else
          Enum.reduce(tx.inputs, m, fn i, m ->
            %{m | active: MapSet.delete(m.active, {i.prev_hash, i.prev_index})}
          end)
        end

      tx.outputs
      |> Enum.with_index()
      |> Enum.reduce(m, fn {o, v}, m ->
        if spendable?(o.script_pubkey) do
          op = {tx.txid, v}

          %{
            m
            | active: MapSet.put(m.active, op),
              info: Map.put(m.info, op, {o.value, o.script_pubkey, height, pos == 0})
          }
        else
          m
        end
      end)
    end)
  end

  # Reverse of connect: txs in reverse order; per tx, remove its outputs,
  # then restore the outputs its inputs spent (in-block chains included).
  defp model_disconnect(model, block) do
    block.txs
    |> Enum.reverse()
    |> Enum.with_index()
    |> Enum.reduce(model, fn {tx, rpos}, m ->
      m =
        Enum.reduce(Enum.with_index(tx.outputs), m, fn {_, v}, m ->
          %{m | active: MapSet.delete(m.active, {tx.txid, v})}
        end)

      # rpos 0 is the coinbase (last in reverse order).
      if rpos == 0 do
        m
      else
        Enum.reduce(tx.inputs, m, fn i, m ->
          %{m | active: MapSet.put(m.active, {i.prev_hash, i.prev_index})}
        end)
      end
    end)
  end

  defp assert_model(cs, model, all_ops, label) do
    got = State.peek_archive(cs, &Archive.resolve_many(&1, all_ops))

    for op <- all_ops do
      want =
        if MapSet.member?(model.active, op) do
          {v, spk, h, cb} = model.info[op]
          {:ok, {v, spk, h, cb}}
        else
          :missing
        end

      g = got[op]

      assert compare(want, g),
             "#{label}: #{inspect(op)} model=#{inspect(want)} archive=#{inspect(g)}"
    end
  end

  defp compare(:missing, :missing), do: true

  defp compare({:ok, {v, spk, h, cb}}, {:ok, g}),
    do: {v, spk, h, cb} == {g.value, g.script_pubkey, g.height, g.coinbase}

  defp compare(_, _), do: false

  # --- chain building --------------------------------------------------------

  # A block spending `spends` = [{txid, vout, value}] into fresh OP_TRUE
  # outputs (splitting value), plus the coinbase. `tag` makes branches differ.
  # With >= 2 spends, the first spend's output is spent again in-block.
  defp spend_block(prev, height, spends, tag) do
    txs =
      for {{t, v, value}, k} <- Enum.with_index(spends) do
        half = div(value, 2)

        BB.tx([{t, v}], [
          {half, @op_true},
          {value - half - 1_000, @op_true2},
          {0, <<0x6A, tag, k>>}
        ])
      end

    txs =
      case txs do
        [t1 | _] when length(txs) >= 2 ->
          v0 = hd(t1.outputs).value
          [chained] = [BB.tx([{t1.txid, 0}], [{v0 - 1_000, @op_true}])]
          txs ++ [chained]

        _ ->
          txs
      end

    cb =
      BB.coinbase_with(height, 50 * @coin, outputs: [{50 * @coin, @op_true}, {0, <<0x6A, tag>>}])

    BB.build(prev, [cb | txs])
  end

  # Builds `n` blocks on `prev` from `height + 1`, spending out of `pool`
  # (a list of {txid, vout, value}, mature coins plus coins created earlier
  # in this same branch). Returns {blocks, pool'}.
  defp branch(prev, height, n, pool, tag, spend_frac) do
    Enum.map_reduce(1..n, {prev, pool}, fn i, {prev, pool} ->
      h = height + i
      # A bounded number of spends per block (block weight).
      {spend, pool} = Enum.split(pool, min(max(div(length(pool) * spend_frac, 100), 0), 8))

      b = spend_block(prev, h, spend, tag)

      spent_here =
        MapSet.new(for tx <- tl(b.txs), i <- tx.inputs, do: {i.prev_hash, i.prev_index})

      # Non-coinbase outputs not already spent in this block (coinbases are
      # immature within the branch).
      created =
        for tx <- tl(b.txs),
            {o, v} <- Enum.with_index(tx.outputs),
            spendable?(o.script_pubkey),
            o.value > 0,
            not MapSet.member?(spent_here, {tx.txid, v}) do
          {tx.txid, v, o.value}
        end

      {b, {b.header, pool ++ created}}
    end)
    |> then(fn {blocks, {_, pool}} -> {blocks, pool} end)
  end

  # --- the node --------------------------------------------------------------

  defp start(dir, name, opts) do
    {:ok, kv} = KV.open(Path.join(dir, "#{name}-kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)

    {:ok, cs} =
      State.start_link(
        [params: @p, headers: hs, kv: kv, hot: Path.join(dir, "#{name}-hot")] ++ opts
      )

    %{kv: kv, hs: hs, cs: cs}
  end

  defp stop(node) do
    GenServer.stop(node.cs)
    GenServer.stop(node.hs)
    KV.close(node.kv)
  end

  # Submits a whole branch's headers then bodies; asserts it becomes the tip.
  defp activate(node, blocks) do
    {:ok, _} = Headers.process_headers(node.hs, Enum.map(blocks, & &1.header))
    for b <- blocks, do: {:ok, _} = State.submit_block(node.cs, b, requested: true)
    tip = State.tip(node.cs)
    assert tip.hash == List.last(blocks).header.hash, "branch did not become active"
  end

  property "repeated branch switching with double spends matches the model", %{tmp_dir: dir} do
    check all(seed <- integer(1..10_000), max_runs: 12) do
      :rand.seed(:exsss, {seed, seed, seed})
      run = Path.join(dir, "run-#{seed}")
      # Small batch: reorgs span commit boundaries. Prefetch toggled by parity.
      prefetch = rem(seed, 2) * 4
      node = start(run, "n", batch_blocks: 5, prefetch_depth: prefetch, cache_bytes: 2_000)

      # Base chain: 130 empty-ish blocks (coinbases mature after 100).
      {base, _} =
        Enum.map_reduce(1..130, @p.genesis.header, fn h, prev ->
          b = BB.build(prev, [BB.coinbase(h, 50 * @coin)], time: prev.time + 1)
          {b, b.header}
        end)

      for b <- base, do: {:ok, _} = State.submit_block(node.cs, b)

      # The model tracks the selected branch's spendable set. The fork is at
      # height 120: the base chain's blocks 121..130 are disconnected as soon
      # as a branch activates, so the model starts at the fork (base 1..120).
      fork_header = Enum.at(base, 119).header
      fork_height = 120

      model =
        Enum.reduce(
          Enum.with_index(Enum.take(base, 120), 1),
          %{active: MapSet.new(), info: %{}},
          fn {b, h}, m ->
            model_connect(m, b, h)
          end
        )

      # Mature coins at the fork: coinbases 1..20.
      pool0 = for b <- Enum.take(base, 20), do: {hd(b.txs).txid, 0, 50 * @coin}

      all_ops =
        for b <- base, tx <- b.txs, v <- 0..(length(tx.outputs) - 1), do: {tx.txid, v}

      # Branch A: 15 blocks from the fork. Branch B: same fork, different
      # spends of (largely) the same pool.
      {a_blocks, a_pool} = branch(fork_header, fork_height, 15, pool0, 1, 60)
      {b_blocks, b_pool} = branch(fork_header, fork_height, 15, pool0, 2, 70)

      all_ops = all_ops ++ ops_of(a_blocks) ++ ops_of(b_blocks)

      # Activate A.
      activate(node, a_blocks)

      {model_a, _} =
        apply_branch(%{active: model.active, info: model.info}, a_blocks, fork_height + 1)

      assert_model(node.cs, model_a, all_ops, "seed #{seed}: A active")

      # Switch to B (longer): reorg 15 blocks, spanning commits.
      b_long =
        b_blocks ++
          elem(branch(List.last(b_blocks).header, fork_height + 15, 2, b_pool, 2, 50), 0)

      activate(node, b_long)
      model_b = switch_model(model_a, a_blocks, b_long, fork_height + 1)
      all_ops = all_ops ++ ops_of(Enum.drop(b_long, 15))
      assert_model(node.cs, model_b, all_ops, "seed #{seed}: B active")

      # Switch back to A extended (archived reconnect + new blocks).
      {a_ext, _a_pool2} = branch(List.last(a_blocks).header, fork_height + 15, 4, a_pool, 1, 50)
      a_long = a_blocks ++ a_ext
      activate(node, a_long)
      model_a2 = switch_model(model_b, b_long, a_long, fork_height + 1)
      all_ops = all_ops ++ ops_of(a_ext)
      assert_model(node.cs, model_a2, all_ops, "seed #{seed}: A' active")

      # Crash mid-life: kill -9, restart, replay from pending.
      Process.unlink(node.cs)
      Process.exit(node.cs, :kill)
      GenServer.stop(node.hs)
      KV.close(node.kv)
      node = start(run, "n", batch_blocks: 5, prefetch_depth: prefetch, cache_bytes: 2_000)
      assert State.tip(node.cs).hash == List.last(a_long).header.hash
      assert_model(node.cs, model_a2, all_ops, "seed #{seed}: A' after restart")

      # Switch to B extended past A' (archived + new).
      {b_ext, _} = branch(List.last(b_long).header, fork_height + 17, 4, [], 2, 0)
      b_long2 = b_long ++ b_ext
      activate(node, b_long2)
      model_b2 = switch_model(model_a2, a_long, b_long2, fork_height + 1)
      all_ops = all_ops ++ ops_of(b_ext)
      assert_model(node.cs, model_b2, all_ops, "seed #{seed}: B' active after crash")

      # And back to A once more (reconnect of twice-archived branch).
      {a_ext2, _} = branch(List.last(a_long).header, fork_height + 19, 3, [], 1, 0)
      a_long2 = a_long ++ a_ext2
      activate(node, a_long2)
      model_a3 = switch_model(model_b2, b_long2, a_long2, fork_height + 1)
      assert_model(node.cs, model_a3, all_ops ++ ops_of(a_ext2), "seed #{seed}: A'' active")

      # Every active block above the fork reconstructs byte-exactly, and the
      # abandoned branches' blocks are not on the chain.
      State.with_archive(node.cs, fn a ->
        active = Enum.take(base, 120) ++ a_long2

        for {b, h} <- Enum.with_index(active, 1) do
          assert Archive.read_block(a, Archive.id_at(a, h)) == b.raw,
                 "seed #{seed}: block #{h} bytes"
        end

        for b <- Enum.take(b_long2, 3) do
          id = Archive.block_id(a, b.header.hash)

          assert id == nil or not Archive.on_chain?(a, id),
                 "seed #{seed}: abandoned branch block on chain"
        end
      end)

      stop(node)
    end
  end

  defp ops_of(blocks),
    do: for(b <- blocks, tx <- b.txs, v <- 0..(length(tx.outputs) - 1), do: {tx.txid, v})

  # Connects a fresh branch onto the model at the fork (blocks start at `from_h`).
  defp apply_branch(model, blocks, from_h) do
    Enum.reduce(Enum.with_index(blocks, from_h), {model, from_h + length(blocks) - 1}, fn {b, h},
                                                                                          {m, _} ->
      {model_connect(m, b, h), h}
    end)
  end

  # Disconnects `old` (from its tip down to the fork), connects `new`.
  # `old` and `new` share a prefix below the fork already in the model.
  defp switch_model(model, old, new, fork_h) do
    model = Enum.reduce(Enum.reverse(old), model, fn b, m -> model_disconnect(m, b) end)
    {m, _} = apply_branch(model, new, fork_h)
    m
  end
end
