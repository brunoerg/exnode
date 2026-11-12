defmodule Exnode.Properties.ConsensusDifferentialTest do
  @moduledoc """
  Differential property: random regtest blocks, valid or carrying one
  rule-breaking mutation, on the tip or on a shallow fork, are submitted to
  exnode's `Chain.State` and to Core v32.1's own validation engine
  (`Exnode.Shadow`, libbitcoinkernel's chainstate manager in its own OS
  process). After every block the verdicts (valid / invalid / stored without
  validation / duplicate) and the active tips must be equal.

  Scripts are OP_TRUE (bare or P2WSH), so the property exercises the
  consensus rules exnode implements itself rather than the script engine
  the two share: amounts, double spends, missing and immature inputs,
  BIP34/30-style coinbase rules, merkle mutation (CVE-2012-2459), witness
  commitment, header version/bits/PoW/time, nLockTime, BIP68, and reorgs
  across forks.

  The generator builds blocks against an independent coin model. Blocks the
  model believes valid must be connected by Core when built on the tip, so
  a broken generator fails loudly instead of producing only invalid blocks.
  """
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Tx
  alias Exnode.Shadow
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB
  alias Exnode.Test.{Coins, ScriptAsm}
  alias Exnode.Validation.Connect

  @moduletag :tmp_dir
  @moduletag timeout: 900_000

  @p ChainParams.get(:regtest)
  @op_true <<0x51>>
  @base_blocks 110
  @max_money 21_000_000 * 100_000_000

  # Mutations that leave the block valid (boundary cases included).
  @valid [:none, :final_locktime, :bip68_ok, :mature_coinbase]
  @invalid [
    :overpay,
    :double_spend,
    :missing_input,
    :immature_coinbase,
    :dup_tx,
    :cve_2012_2459,
    :value_too_large,
    :outputs_exceed_inputs,
    :bad_cb_height,
    :cb_script_long,
    :bad_merkle,
    :time_too_old,
    :time_future,
    :nonfinal_locktime,
    :bip68_fail,
    :bad_version,
    :no_coinbase,
    :two_coinbases,
    :spend_later_in_block,
    :bad_commitment,
    :unexpected_witness,
    :bad_pow,
    :wrong_bits
  ]

  # --- generators -------------------------------------------------------------

  defp tx_spec do
    gen all(
          n_in <- integer(1..2),
          n_out <- integer(1..3),
          fee <- integer(0..2_000),
          picks <- list_of(integer(0..10_000), length: 2),
          witness_out <- list_of(boolean(), length: 3)
        ) do
      %{n_in: n_in, n_out: n_out, fee: fee, picks: picks, witness_out: witness_out}
    end
  end

  defp step do
    gen all(
          parent <-
            frequency([
              {6, constant(0)},
              {1, constant(1)},
              {1, constant(2)},
              {3, constant(:side)}
            ]),
          txs <- list_of(tx_spec(), max_length: 4),
          mutation <-
            frequency([
              {6, member_of(@valid)},
              {6, member_of(@invalid)}
            ]),
          seed <- integer(0..1_000_000)
        ) do
      %{parent: parent, txs: txs, mutation: mutation, seed: seed}
    end
  end

  # --- the base chain both nodes start from ------------------------------------

  setup_all do
    now = System.os_time(:second)
    genesis = @p.genesis

    {blocks, _} =
      Enum.map_reduce(1..@base_blocks, %{header: genesis.header, time: now - 7_200}, fn h, prev ->
        v = Connect.subsidy(h, @p)

        cb =
          BB.coinbase_with(h, v, outputs: [{div(v, 2), @op_true}, {v - div(v, 2), Coins.p2wsh()}])

        b = BB.build(prev.header, [cb], time: prev.time + 1)
        {b, %{header: b.header, time: b.header.time}}
      end)

    %{base: blocks}
  end

  # --- model ------------------------------------------------------------------
  # Block entry: %{header, height, utxos: %{{txid, vout} => coin}, times: [newest first]}
  # coin: %{value, spk, height, coinbase}

  defp genesis_entry do
    %{header: @p.genesis.header, height: 0, utxos: %{}, times: [@p.genesis.header.time]}
  end

  defp apply_block(parent, block) do
    h = parent.height + 1

    utxos =
      block.txs
      |> Enum.with_index()
      |> Enum.reduce(parent.utxos, fn {tx, pos}, u ->
        u =
          if pos == 0,
            do: u,
            else: Map.drop(u, Enum.map(tx.inputs, &{&1.prev_hash, &1.prev_index}))

        tx.outputs
        |> Enum.with_index()
        |> Enum.reduce(u, fn {o, v}, u ->
          if match?(<<0x6A, _::binary>>, o.script_pubkey),
            do: u,
            else:
              Map.put(u, {tx.txid, v}, %{
                value: o.value,
                spk: o.script_pubkey,
                height: h,
                coinbase: pos == 0
              })
        end)
      end)

    %{
      header: block.header,
      height: h,
      utxos: utxos,
      times: Enum.take([block.header.time | parent.times], 11)
    }
  end

  defp mtp(entry) do
    sorted = Enum.sort(entry.times)
    Enum.at(sorted, div(length(sorted), 2))
  end

  # --- block construction -------------------------------------------------------

  defp input(op, coin, opts \\ []) do
    %Tx.In{
      prev_hash: elem(op, 0),
      prev_index: elem(op, 1),
      script_sig: <<>>,
      sequence: Keyword.get(opts, :sequence, 0xFFFFFFFF),
      witness: if(coin.spk == @op_true, do: [], else: [@op_true])
    }
  end

  defp spendable(pool, h),
    do: pool |> Enum.filter(fn {_, c} -> not c.coinbase or h - c.height >= 100 end) |> Enum.sort()

  # Builds the block's non-coinbase txs from `specs`. Returns {txs, fees, pool}.
  defp build_txs(specs, pool, h) do
    Enum.reduce(specs, {[], 0, pool}, fn spec, {txs, fees, pool} ->
      avail = spendable(pool, h)

      if length(avail) < spec.n_in do
        {txs, fees, pool}
      else
        ins =
          spec.picks
          |> Enum.take(spec.n_in)
          |> Enum.reduce({[], avail}, fn pick, {acc, av} ->
            {op, c} = Enum.at(av, rem(pick, length(av)))
            {[{op, c} | acc], List.keydelete(av, op, 0)}
          end)
          |> elem(0)

        total = Enum.sum(Enum.map(ins, fn {_, c} -> c.value end))
        fee = min(spec.fee, total - spec.n_out * 1_000)

        if fee < 0 do
          {txs, fees, pool}
        else
          left = total - fee
          part = div(left, spec.n_out)
          values = List.duplicate(part, spec.n_out - 1) ++ [left - part * (spec.n_out - 1)]

          outs =
            for {v, w} <- Enum.zip(values, spec.witness_out),
                do: %Tx.Out{value: v, script_pubkey: if(w, do: Coins.p2wsh(), else: @op_true)}

          tx =
            BB.finalize(%Tx{
              version: 2,
              inputs: for({op, c} <- ins, do: input(op, c)),
              outputs: outs,
              locktime: 0
            })

          pool = Map.drop(pool, Enum.map(ins, &elem(&1, 0)))

          pool =
            outs
            |> Enum.with_index()
            |> Enum.reduce(pool, fn {o, v}, p ->
              Map.put(p, {tx.txid, v}, %{
                value: o.value,
                spk: o.script_pubkey,
                height: h,
                coinbase: false
              })
            end)

          {txs ++ [tx], fees + fee, pool}
        end
      end
    end)
  end

  # One tx spending `{op, coin}` into a single OP_TRUE output (fee 1,000).
  defp simple_spend({op, coin}, opts \\ []) do
    BB.finalize(%Tx{
      version: Keyword.get(opts, :version, 2),
      inputs: [input(op, coin, opts)],
      outputs: [%Tx.Out{value: coin.value - 1_000, script_pubkey: @op_true}],
      locktime: Keyword.get(opts, :locktime, 0)
    })
  end

  defp has_witness?(txs), do: Enum.any?(txs, fn t -> Enum.any?(t.inputs, &(&1.witness != [])) end)

  defp coinbase(h, value, opts), do: BB.coinbase_with(h, value, opts)

  # Assembles a block on `parent`: coinbase paying `cb_value`, the witness
  # commitment when needed (`:commit` overrides), header options.
  defp assemble(parent, h, txs, cb_value, opts) do
    cb_opts = Keyword.get(opts, :cb_opts, [])
    hdr = Keyword.get(opts, :header, [])
    hdr = Keyword.put_new(hdr, :time, parent.header.time + 1)

    case Keyword.get(opts, :commit, if(has_witness?(txs), do: :yes, else: :no)) do
      :no ->
        cb = Keyword.get_lazy(opts, :cb, fn -> coinbase(h, cb_value, cb_opts) end)
        txs = if Keyword.get(opts, :no_coinbase, false), do: txs, else: [cb | txs]

        BB.build(
          parent.header,
          txs ++ Keyword.get(opts, :extra, []),
          hdr ++ Keyword.get(opts, :build, [])
        )

      commit ->
        cb_fun = fn extra, wit ->
          outs = [{cb_value, @op_true} | extra]
          coinbase(h, cb_value, Keyword.merge([outputs: outs, witness: wit], cb_opts))
        end

        bopts = if commit == :bad, do: [commitment: <<1::256>>], else: []
        BB.build_segwit(parent.header, cb_fun, txs, bopts ++ hdr)
    end
  end

  # Returns [{block, mutation}] to submit, in order (the CVE-2012-2459 case
  # also submits the honest block with the same header).
  defp make_blocks(parent, s) do
    h = parent.height + 1
    subsidy = Connect.subsidy(h, @p)
    {txs, fees, _pool} = build_txs(s.txs, parent.utxos, h)
    value = subsidy + fees
    avail = spendable(parent.utxos, h)
    pick = fn list -> if list == [], do: nil, else: Enum.at(list, rem(s.seed, length(list))) end

    case s.mutation do
      :none ->
        [{assemble(parent, h, txs, value, []), :none}]

      :overpay ->
        [{assemble(parent, h, txs, value + 1, []), :overpay}]

      :double_spend ->
        case txs do
          [t | _] ->
            i = hd(t.inputs)
            coin = parent.utxos[{i.prev_hash, i.prev_index}]

            dup =
              if coin,
                do: simple_spend({{i.prev_hash, i.prev_index}, coin}, locktime: 1),
                else: nil

            if dup,
              do: [{assemble(parent, h, txs ++ [dup], value + 1_000, []), :double_spend}],
              else: fallback(parent, h, txs, value)

          [] ->
            fallback(parent, h, txs, value)
        end

      :missing_input ->
        ghost = {{:crypto.hash(:sha256, <<s.seed::64>>), 0}, %{value: 10_000, spk: @op_true}}
        [{assemble(parent, h, txs ++ [simple_spend(ghost)], value + 1_000, []), :missing_input}]

      m when m in [:immature_coinbase, :mature_coinbase] ->
        depth = if m == :immature_coinbase, do: 99, else: 100

        case Enum.find(Enum.sort(parent.utxos), fn {_, c} ->
               c.coinbase and h - c.height == depth
             end) do
          nil -> fallback(parent, h, txs, value)
          coin -> [{assemble(parent, h, [simple_spend(coin)], subsidy + 1_000, []), m}]
        end

      :dup_tx when txs != [] ->
        [{assemble(parent, h, txs ++ [List.last(txs)], value, []), :dup_tx}]

      :cve_2012_2459 ->
        # [cb, t1, t2] has 3 leaves: [cb, t1, t2, t2] has the same merkle root
        # (bare OP_TRUE spends, so no witness commitment changes either).
        case avail |> Enum.filter(fn {_, c} -> c.spk == @op_true end) |> Enum.take(2) do
          [c1, c2] ->
            t1 = simple_spend(c1)
            t2 = simple_spend(c2)
            honest = assemble(parent, h, [t1, t2], subsidy + 2_000, [])
            cb = hd(honest.txs)

            mutated =
              BB.build(parent.header, [cb, t1, t2, t2],
                merkle_txs: [cb, t1, t2],
                time: honest.header.time
              )

            true = mutated.header.hash == honest.header.hash
            [{mutated, :cve_2012_2459}, {honest, :none}]

          _ ->
            fallback(parent, h, txs, value)
        end

      :value_too_large ->
        case pick.(avail) do
          nil ->
            fallback(parent, h, txs, value)

          {op, c} ->
            t =
              BB.finalize(%Tx{
                version: 2,
                inputs: [input(op, c)],
                outputs: [%Tx.Out{value: @max_money + 1, script_pubkey: @op_true}],
                locktime: 0
              })

            [{assemble(parent, h, [t], subsidy, []), :value_too_large}]
        end

      :outputs_exceed_inputs ->
        case pick.(avail) do
          nil ->
            fallback(parent, h, txs, value)

          {op, c} ->
            t =
              BB.finalize(%Tx{
                version: 2,
                inputs: [input(op, c)],
                outputs: [%Tx.Out{value: c.value + 1, script_pubkey: @op_true}],
                locktime: 0
              })

            [{assemble(parent, h, [t], subsidy, []), :outputs_exceed_inputs}]
        end

      :bad_cb_height ->
        sig = ScriptAsm.parse("#{h + 1}") <> <<0>>
        [{assemble(parent, h, txs, value, cb_opts: [script_sig: sig]), :bad_cb_height}]

      :cb_script_long ->
        prefix = ScriptAsm.parse("#{h}")
        sig = prefix <> :binary.copy(<<0>>, 101 - byte_size(prefix))
        [{assemble(parent, h, txs, value, cb_opts: [script_sig: sig]), :cb_script_long}]

      :bad_merkle ->
        [
          {assemble(parent, h, txs, value,
             commit: :no,
             build: [merkle_root: <<s.seed::256>>],
             extra: []
           ), :bad_merkle}
        ]

      :time_too_old ->
        [{assemble(parent, h, txs, value, header: [time: mtp(parent)]), :time_too_old}]

      :time_future ->
        [
          {assemble(parent, h, txs, value, header: [time: System.os_time(:second) + 3 * 3_600]),
           :time_future}
        ]

      m when m in [:nonfinal_locktime, :final_locktime] ->
        case pick.(avail) do
          nil ->
            fallback(parent, h, txs, value)

          coin ->
            lt = if m == :nonfinal_locktime, do: h, else: h - 1
            t = simple_spend(coin, locktime: lt, sequence: 0xFFFFFFFE)
            [{assemble(parent, h, [t], subsidy + 1_000, []), m}]
        end

      m when m in [:bip68_fail, :bip68_ok] ->
        case pick.(avail) do
          nil ->
            fallback(parent, h, txs, value)

          {_, c} = coin ->
            n = h - c.height + if(m == :bip68_fail, do: 1, else: 0)

            if n > 0xFFFF do
              fallback(parent, h, txs, value)
            else
              t = simple_spend(coin, sequence: n)
              [{assemble(parent, h, [t], subsidy + 1_000, []), m}]
            end
        end

      :bad_version ->
        [{assemble(parent, h, txs, value, header: [version: 1]), :bad_version}]

      :no_coinbase when txs != [] ->
        [{assemble(parent, h, txs, value, commit: :no, no_coinbase: true), :no_coinbase}]

      :two_coinbases ->
        extra = coinbase(h, 1, script_sig: ScriptAsm.parse("#{h}") <> <<1>>)
        [{assemble(parent, h, txs, value, commit: :no, extra: [extra]), :two_coinbases}]

      :spend_later_in_block ->
        case pick.(avail) do
          nil ->
            fallback(parent, h, txs, value)

          coin ->
            a = simple_spend(coin)

            b =
              simple_spend(
                {{a.txid, 0}, %{value: a.outputs |> hd() |> Map.get(:value), spk: @op_true}}
              )

            [{assemble(parent, h, [b, a], subsidy + 2_000, []), :spend_later_in_block}]
        end

      m when m in [:bad_commitment, :unexpected_witness] ->
        case Enum.find(avail, fn {_, c} -> c.spk != @op_true end) do
          nil ->
            fallback(parent, h, txs, value)

          coin ->
            t = simple_spend(coin)
            commit = if m == :bad_commitment, do: :bad, else: :no
            [{assemble(parent, h, [t], subsidy + 1_000, commit: commit), m}]
        end

      :bad_pow ->
        [{assemble(parent, h, txs, value, commit: :no, build: [bad_pow: true]), :bad_pow}]
        |> only_without_witness(parent, h, txs, value)

      :wrong_bits ->
        [{assemble(parent, h, txs, value, header: [bits: 0x207FFFFE]), :wrong_bits}]

      _ ->
        fallback(parent, h, txs, value)
    end
  end

  defp only_without_witness([{b, m}], parent, h, txs, value),
    do: if(has_witness?(txs), do: fallback(parent, h, txs, value), else: [{b, m}])

  # A mutation that does not apply to this block's contents: submit it valid.
  defp fallback(parent, h, txs, value), do: [{assemble(parent, h, txs, value, []), :none}]

  # --- the two nodes ---------------------------------------------------------------

  defp start_nodes(dir) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    {:ok, cs} = State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "arch"))
    {:ok, sh} = Shadow.start_link(chain: :regtest, datadir: Path.join(dir, "shadow"))
    %{kv: kv, hs: hs, cs: cs, sh: sh}
  end

  defp stop_nodes(n) do
    for pid <- [n.sh, n.cs, n.hs], do: GenServer.stop(pid)
    KV.close(n.kv)
  end

  # `requested: true`: the kernel's process_block is Core's ProcessNewBlock
  # with force_processing, so unrequested-block storage gates do not apply.
  defp exnode_verdict(cs, b) do
    case State.submit_block(cs, b, requested: true) do
      {:ok, :connected} -> :valid
      {:ok, :stored} -> :stored
      {:ok, :duplicate} -> :duplicate
      {:error, r} -> {:invalid, r}
    end
  end

  defp core_verdict(sh, b) do
    {:ok, v} = Shadow.process_block(sh, b.raw)

    case Enum.find(v.events, fn {hash, _, _} -> hash == b.header.hash end) do
      {_, :valid, _} -> {:valid, v}
      {_, :invalid, r} -> {{:invalid, r}, v}
      nil -> {if(v.new_block, do: :stored, else: :duplicate), v}
    end
  end

  defp class({:invalid, _}), do: :invalid
  defp class(v), do: v

  defp tip_of(cs) do
    t = State.tip(cs)
    {t.height, t.hash}
  end

  # --- the property ---------------------------------------------------------------

  property "exnode's verdicts and tips equal Core's engine on random valid and mutated blocks",
           %{tmp_dir: dir, base: base} do
    runs = String.to_integer(System.get_env("CONSENSUS_RUNS", "20"))

    check all(
            steps <- list_of(step(), min_length: 10, max_length: 30),
            max_runs: runs,
            max_shrinking_steps: 50
          ) do
      run_dir = Path.join(dir, "run-#{System.unique_integer([:positive])}")
      n = start_nodes(run_dir)

      try do
        # Blocks the model can build on (hash => entry), and Core's tip.
        chain =
          Enum.reduce(base, %{blocks: %{}, tip: genesis_entry()}, fn b, chain ->
            assert {:ok, :connected} = State.submit_block(n.cs, b)
            assert {:valid, _} = core_verdict(n.sh, b)
            e = apply_block(chain.tip, b)
            %{blocks: Map.put(chain.blocks, b.header.hash, e), tip: e}
          end)

        Enum.reduce(Enum.with_index(steps), chain, fn {s, i}, chain ->
          parent =
            if s.parent == :side,
              do: chain[:side] || chain.tip,
              else: ancestor(chain, chain.tip, s.parent)

          Enum.reduce(make_blocks(parent, s), chain, fn {b, m}, chain ->
            core = core_verdict(n.sh, b)
            {cv, v} = core
            ev = exnode_verdict(n.cs, b)
            label = "step #{i} (#{m}, parent #{inspect(s.parent)}, height #{parent.height + 1})"

            # A validated block off the tip became the tip: a reorg.
            where =
              cond do
                parent.header.hash == chain.tip.header.hash -> :tip
                cv == :valid -> :reorg
                true -> :fork
              end

            tally({m, where, class(cv)})

            assert class(ev) == class(cv),
                   "#{label}: exnode #{inspect(ev)} vs Core #{inspect(cv)}"

            assert tip_of(n.cs) == v.tip,
                   "#{label}: exnode tip #{inspect(tip_of(n.cs))} vs Core #{inspect(v.tip)}"

            # The generator must build what it claims: a model-valid block on
            # the tip is connected by Core.
            if m in @valid and parent.header.hash == chain.tip.header.hash,
              do:
                assert(
                  cv == :valid,
                  "#{label}: model-valid block rejected by Core: #{inspect(cv)}"
                )

            if m in @valid and class(cv) != :invalid do
              e = apply_block(parent, b)
              {th, thash} = v.tip
              blocks = Map.put(chain.blocks, b.header.hash, e)

              tip =
                if th == e.height and thash == b.header.hash,
                  do: e,
                  else: blocks[thash] || chain.tip

              # The newest block off the active chain: extending it grows a
              # side branch until it overtakes the tip (a reorg).
              side = if tip.header.hash == b.header.hash, do: chain[:side], else: e
              side = if side && side.header.hash == tip.header.hash, do: nil, else: side
              %{blocks: blocks, tip: tip, side: side}
            else
              chain
            end
          end)
        end)
      after
        stop_nodes(n)
      end
    end

    print_tally()
  end

  defp tally(key),
    do: Process.put(:tally, Map.update(Process.get(:tally, %{}), key, 1, &(&1 + 1)))

  defp print_tally do
    t = Process.get(:tally, %{})

    IO.puts(
      "consensus differential: #{Enum.sum(Map.values(t))} blocks; " <>
        Enum.map_join(Enum.sort(t), ", ", fn {{m, where, v}, c} -> "#{m}/#{where}/#{v}=#{c}" end)
    )
  end

  defp ancestor(_chain, entry, 0), do: entry

  defp ancestor(chain, entry, k) do
    case chain.blocks[entry.header.prev_hash] do
      nil -> entry
      p -> ancestor(chain, p, k - 1)
    end
  end
end
