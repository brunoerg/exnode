defmodule Exnode.Interop.MempoolReplayTest do
  @moduledoc """
  Mempool acceptance matches bitcoind v32.1 on a replayed
  transaction stream.

  A seeded generator builds a few hundred txs: fee levels, chains past the
  cluster limit, RBF (paying, underpaying, diagram failures), dust, data
  carrier, non-standard outputs, tx-size-small, non-final and BIP68 locks,
  orphans, bad scripts, same-txid-different-witness, duplicates, TRUC
  parents/children/siblings, spends of conflicting txs, and 1p1c / TRUC /
  ephemeral-dust packages. Blocks and a reorg are mined mid-stream. Every tx
  goes to `testmempoolaccept` on both nodes. Verdict, reject reason, vsize
  and fee must match. Accepted txs are then submitted to both, and the
  mempools must have the same txids after every block.

  The test needs no signatures: outputs are P2WSH and P2SH of
  anyone-can-spend scripts, which are standard to create and spend.

  The only allowed difference is the documented one: scripts that are
  consensus-valid but violate Core's policy script flags (here OP_NOP4,
  discouraged upgradable NOPs). exnode accepts those, because the kernel
  exposes no policy flags. They are counted and asserted separately.
  """
  use Exnode.InteropCase
  import Exnode.Test.Coins, only: [hex: 1, raw: 1]

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Tx
  alias Exnode.Crypto.Hash
  alias Exnode.Mempool
  alias Exnode.Store.KV

  @moduletag :bitcoind
  @moduletag timeout: 1_800_000
  @p ChainParams.get(:regtest)
  @coin 100_000_000

  # Witness scripts.
  @ws_true <<0x51>>
  @ws_drop_true <<0x75, 0x51>>
  @ws_nop4_true <<0xB3, 0x51>>

  defp p2wsh(ws), do: <<0, 32>> <> :crypto.hash(:sha256, ws)
  defp p2sh_true, do: <<0xA9, 20>> <> Hash.hash160(<<0x51>>) <> <<0x87>>
  defp fin(tx), do: tx |> raw() |> Tx.decode_exact() |> elem(1)

  # A spendable output we know: {txid, vout, value, kind}.
  defp input({txid, vout, _v, kind}, opts \\ []) do
    {ss, wit} =
      case kind do
        true -> {<<>>, [@ws_true]}
        :drop -> {<<>>, [Keyword.get(opts, :drop_item, <<1>>), @ws_drop_true]}
        :nop4 -> {<<>>, [@ws_nop4_true]}
        :p2sh -> {<<1, 0x51>>, []}
        :bad -> {<<>>, [<<0x00>>]}
      end

    %Tx.In{
      prev_hash: txid,
      prev_index: vout,
      script_sig: ss,
      sequence: Keyword.get(opts, :sequence, 0xFFFFFFFD),
      witness: wit
    }
  end

  defp spk(true), do: p2wsh(@ws_true)
  defp spk(:drop), do: p2wsh(@ws_drop_true)
  defp spk(:nop4), do: p2wsh(@ws_nop4_true)
  defp spk(:p2sh), do: p2sh_true()

  # Builds a tx spending `coins` to outputs `outs` ([{value, spk}]), paying
  # `fee` sats or a target `rate` (sat/vB, from the built size).
  defp build(coins, outs_kinds, opts) do
    total = Enum.reduce(coins, 0, fn {_, _, v, _}, a -> a + v end)
    version = Keyword.get(opts, :version, 2)
    ins = for c <- coins, do: input(c, Keyword.get(opts, :input_opts, []))
    extra = Keyword.get(opts, :extra_outputs, [])

    make = fn fee ->
      n = length(outs_kinds)
      each = div(total - fee - Enum.reduce(extra, 0, &(&2 + elem(&1, 0))), max(n, 1))

      outs =
        for(k <- outs_kinds, do: %Tx.Out{value: each, script_pubkey: spk(k)}) ++
          for({v, s} <- extra, do: %Tx.Out{value: v, script_pubkey: s})

      fin(%Tx{
        version: version,
        inputs: ins,
        outputs: outs,
        locktime: Keyword.get(opts, :locktime, 0)
      })
    end

    case Keyword.fetch(opts, :fee) do
      {:ok, fee} ->
        make.(fee)

      :error ->
        rate = Keyword.get(opts, :rate, 2)
        t = make.(0)
        make.(ceil(rate * div(Tx.weight(t) + 3, 4)))
    end
  end

  defp outputs_of(tx, kinds),
    do: for({k, v} <- Enum.with_index(kinds), do: {tx.txid, v, Enum.at(tx.outputs, v).value, k})

  # --- the two nodes ----------------------------------------------------------------

  defp start_exnode(dir) do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    mp_name = :"mempool_#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(
        params: @p,
        headers: hs,
        kv: kv,
        hot: Path.join(dir, "hot"),
        mempool: mp_name
      )

    {:ok, mp} = Mempool.start_link(name: mp_name, chain_state: cs, headers: hs, params: @p)
    %{cs: cs, hs: hs, mp: mp}
  end

  # Feed bitcoind's active chain to exnode (from the fork point).
  defp sync_blocks(btc, ex) do
    height = Bitcoind.json(btc, ["getblockcount"])

    # Find the highest height where both agree.
    fork =
      Enum.find(min(height, State.tip(ex.cs).height)..0//-1, fn h ->
        Bitcoind.cli(btc, ["getblockhash", "#{h}"]) ==
          Hash.to_hex(
            State.with_archive(
              ex.cs,
              &Exnode.Archive.block_record!(&1, Exnode.Archive.id_at(&1, h)).hash
            )
          )
      end)

    for h <- (fork + 1)..height//1,
        do: {:ok, _} = State.submit_block(ex.cs, Bitcoind.block(btc, h))

    tip = State.tip(ex.cs)
    assert Hash.to_hex(tip.hash) == Bitcoind.cli(btc, ["getbestblockhash"])
    :ok = Mempool.sync_to(ex.mp, tip.hash)
  end

  defp core_test(btc, txs) do
    [res] = Bitcoind.rpc_batch(btc, [{"testmempoolaccept", [Enum.map(txs, &hex(raw(&1))), 0]}])
    res
  end

  defp core_submit(btc, tx),
    do: Bitcoind.rpc_batch(btc, [{"sendrawtransaction", [hex(raw(tx)), 0]}]) |> hd()

  defp ex_reason(%{result: :missing_inputs}), do: "missing-inputs"
  defp ex_reason(%{reason: r}), do: r

  # Compare one tx; on agreement-to-accept, submit to both. Returns :accepted |
  # :rejected | {:gap, tx} | {:diverged, info}.
  defp check(btc, ex, tx, label) do
    [core] = core_test(btc, [tx])
    [ex_res] = Mempool.test_accept(ex.mp, [tx])

    case {core["allowed"], ex_res} do
      {true, {:ok, _, res}} ->
        if core["vsize"] != res.vsize or round(core["fees"]["base"] * @coin) != res.fee do
          {:diverged, {label, :size_or_fee, core, res}}
        else
          {:ok, _} = Mempool.accept(ex.mp, tx)
          _ = core_submit(btc, tx)
          :accepted
        end

      {false, {:error, _, e}} ->
        cr = core["reject-reason"]
        er = ex_reason(e)

        if cr == er or
             (String.starts_with?(cr, "mempool-script-verify-flag-failed") and
                er == "mempool-script-verify-flag-failed"),
           do: {:rejected, cr},
           else: {:diverged, {label, cr, er}}

      {false, {:ok, _, _}} ->
        if String.starts_with?(core["reject-reason"], "mempool-script-verify-flag-failed") and
             label == :policy_script,
           do: {:gap, core["reject-reason"]},
           else: {:diverged, {label, core["reject-reason"], :accepted}}

      {true, {:error, _, e}} ->
        {:diverged, {label, :accepted, ex_reason(e)}}
    end
  end

  defp mempools_equal!(btc, ex, where) do
    core = btc |> Bitcoind.json(["getrawmempool"]) |> MapSet.new()
    ours = ex.mp |> Mempool.txids() |> MapSet.new(&Hash.to_hex/1)

    assert core == ours,
           "#{where}: core-only #{inspect(MapSet.difference(core, ours) |> Enum.take(5))}, exnode-only #{inspect(MapSet.difference(ours, core) |> Enum.take(5))}"

    MapSet.size(core)
  end

  test "replayed tx stream: same verdicts, reasons, sizes, fees and mempools", %{
    tmp_dir: dir,
    btc: btc
  } do
    # 140 coinbases to P2WSH(OP_TRUE), 10 to P2SH(OP_TRUE), then maturity.
    Bitcoind.mine(btc, 140, "raw(#{hex(p2wsh(@ws_true))})")
    Bitcoind.mine(btc, 9, "raw(#{hex(p2sh_true())})")
    Bitcoind.mine(btc, 101)
    ex = start_exnode(dir)
    sync_blocks(btc, ex)

    coinbase = fn h, kind ->
      b = Bitcoind.block(btc, h)
      {hd(b.txs).txid, 0, hd(hd(b.txs).outputs).value, kind}
    end

    fresh = Enum.map(1..140, &coinbase.(&1, true)) ++ Enum.map(141..149, &coinbase.(&1, :p2sh))
    :rand.seed(:exsss, {5, 5, 5})

    st = %{fresh: fresh, unconf: [], accepted: [], results: [], gaps: [], div: []}

    record = fn st, label, r, tx, out_kinds ->
      case r do
        :accepted ->
          %{
            st
            | unconf: st.unconf ++ outputs_of(tx, out_kinds),
              accepted: [tx | st.accepted],
              results: [{label, :ok} | st.results]
          }

        {:rejected, reason} ->
          %{st | results: [{label, reason} | st.results]}

        {:gap, reason} ->
          %{st | gaps: [{label, reason} | st.gaps]}

        {:diverged, info} ->
          %{st | div: [info | st.div]}
      end
    end

    take_fresh = fn st ->
      [c | rest] = st.fresh
      {c, %{st | fresh: rest}}
    end

    scenarios = [
      fanout: 8,
      chain: 10,
      rbf: 6,
      dust: 1,
      nonstd: 1,
      small: 1,
      nonfinal: 1,
      bip68: 1,
      orphan: 2,
      badscript: 1,
      policy_script: 1,
      witness_variant: 1,
      duplicate: 1,
      truc: 3,
      spends_conflict: 1,
      p2sh: 1
    ]

    pick = fn ->
      total = Enum.reduce(scenarios, 0, &(&2 + elem(&1, 1)))
      r = :rand.uniform(total)

      Enum.reduce_while(scenarios, r, fn {k, w}, acc ->
        if acc <= w, do: {:halt, k}, else: {:cont, acc - w}
      end)
    end

    rates = [0, 0.05, 0.1, 0.5, 1, 2, 5, 20]

    step = fn st, scenario ->
      case scenario do
        :fanout ->
          {c, st} = take_fresh.(st)
          kinds = Enum.take_random([true, true, :drop, :nop4, true, :p2sh], 2 + :rand.uniform(3))
          tx = build([c], kinds, rate: Enum.random(rates))
          r = check(btc, ex, tx, :fanout)
          st = record.(st, :fanout, r, tx, kinds)
          if r != :accepted, do: %{st | fresh: [c | st.fresh]}, else: st

        :chain ->
          case st.unconf |> Enum.filter(fn {_, _, _, k} -> k == true end) |> List.last() do
            nil ->
              st

            c ->
              tx = build([c], [true, true], rate: Enum.random([1, 2, 5]))
              r = check(btc, ex, tx, :chain)
              st = if r == :accepted, do: %{st | unconf: List.delete(st.unconf, c)}, else: st
              record.(st, :chain, r, tx, [true, true])
          end

        :rbf ->
          case Enum.filter(st.accepted, fn t ->
                 t.version == 2 and Enum.all?(t.inputs, &(&1.witness == [@ws_true])) and
                   Mempool.has?(ex.mp, t.txid)
               end) do
            [] ->
              st

            cands ->
              old = Enum.random(cands)
              in0 = hd(old.inputs)
              # The coin's value: fee of old + its outputs.
              case Mempool.entry(ex.mp, old.txid) do
                nil ->
                  st

                e ->
                  value = e.fee + Enum.reduce(old.outputs, 0, &(&2 + &1.value))
                  delta = Enum.random([-1000, 0, 50, 300, 5_000, 200_000])

                  # Sometimes bloat the replacement: more total fee, lower feerate (diagram check).
                  bloat =
                    if :rand.uniform(3) == 1,
                      do: [{0, <<0x6A>> <> push(:binary.copy(<<9>>, 3000))}],
                      else: []

                  delta = if bloat != [], do: 3_200, else: delta

                  tx =
                    build([{in0.prev_hash, in0.prev_index, value, true}], [true],
                      fee: max(e.fee + delta, 0),
                      extra_outputs: bloat
                    )

                  record.(st, :rbf, check(btc, ex, tx, :rbf), tx, [true])
              end
          end

        :dust ->
          {c, st} = take_fresh.(st)
          tx = build([c], [true], rate: 2, extra_outputs: [{100, p2wsh(@ws_true)}])
          st = record.(st, :dust, check(btc, ex, tx, :dust), tx, [true])
          %{st | fresh: [c | st.fresh]}

        :nonstd ->
          {c, st} = take_fresh.(st)
          tx = build([c], [true], rate: 2, extra_outputs: [{10_000, <<0x51>>}])
          st = record.(st, :nonstd, check(btc, ex, tx, :nonstd), tx, [])
          %{st | fresh: [c | st.fresh]}

        :small ->
          {c, st} = take_fresh.(st)

          t = %Tx{
            version: 2,
            locktime: 0,
            inputs: [input(c)],
            outputs: [%Tx.Out{value: elem(c, 2) - 10_000, script_pubkey: <<0x6A>>}]
          }

          tx = fin(t)
          st = record.(st, :small, check(btc, ex, tx, :small), tx, [])
          %{st | fresh: [c | st.fresh]}

        :nonfinal ->
          {c, st} = take_fresh.(st)
          h = State.tip(ex.cs).height
          tx = build([c], [true], rate: 2, locktime: h + 5)
          st = record.(st, :nonfinal, check(btc, ex, tx, :nonfinal), tx, [])
          %{st | fresh: [c | st.fresh]}

        :bip68 ->
          {c, st} = take_fresh.(st)
          tx = build([c], [true], rate: 2, input_opts: [sequence: 1000])
          st = record.(st, :bip68, check(btc, ex, tx, :bip68), tx, [])
          %{st | fresh: [c | st.fresh]}

        :orphan ->
          {c, st} = take_fresh.(st)
          parent = build([c], [true], rate: 2)
          child = build(outputs_of(parent, [true]), [true], rate: 2)

          st =
            record.(
              st,
              :orphan_child_first,
              check(btc, ex, child, :orphan_child_first),
              child,
              []
            )

          r = check(btc, ex, parent, :orphan_parent)
          st = record.(st, :orphan_parent, r, parent, [true])

          if r == :accepted do
            st = %{st | unconf: List.delete(st.unconf, hd(outputs_of(parent, [true])))}
            record.(st, :orphan_child, check(btc, ex, child, :orphan_child), child, [true])
          else
            %{st | fresh: [c | st.fresh]}
          end

        :badscript ->
          {c, st} = take_fresh.(st)
          {txid, vout, v, _} = c
          tx = build([{txid, vout, v, :bad}], [true], rate: 2)
          st = record.(st, :badscript, check(btc, ex, tx, :badscript), tx, [])
          %{st | fresh: [c | st.fresh]}

        :policy_script ->
          case Enum.find(st.unconf, fn {_, _, _, k} -> k == :nop4 end) do
            nil ->
              st

            c ->
              record.(
                st,
                :policy_script,
                check(btc, ex, build([c], [true], rate: 2), :policy_script),
                nil,
                []
              )
          end

        :witness_variant ->
          case take_unconf_kind(st, :drop) do
            nil ->
              st

            {c, st} ->
              tx1 = build([c], [true], rate: 2, input_opts: [drop_item: <<1>>])
              tx2 = build([c], [true], rate: 2, input_opts: [drop_item: <<2>>])
              r1 = check(btc, ex, tx1, :witness_variant_first)
              st = record.(st, :witness_variant_first, r1, tx1, [true])

              record.(
                st,
                :witness_variant_second,
                check(btc, ex, tx2, :witness_variant_second),
                tx2,
                [true]
              )
          end

        :duplicate ->
          case st.accepted do
            [] ->
              st

            l ->
              tx = Enum.random(l)
              record.(st, :duplicate, check(btc, ex, tx, :duplicate), tx, [])
          end

        :truc ->
          {c, st} = take_fresh.(st)
          parent = build([c], [true, true], version: 3, rate: 2)

          st =
            record.(st, :truc_parent, r = check(btc, ex, parent, :truc_parent), parent, [
              true,
              true
            ])

          if r == :accepted do
            [o1, o2] = outputs_of(parent, [true, true])
            st = %{st | unconf: st.unconf -- [o1, o2]}
            child1 = build([o1], [true], version: 3, rate: 2)
            st = record.(st, :truc_child, check(btc, ex, child1, :truc_child), child1, [true])
            # A second child: sibling eviction if it pays enough, else TRUC-violation.
            child2 = build([o2], [true], version: 3, rate: Enum.random([1, 50]))
            st = record.(st, :truc_sibling, check(btc, ex, child2, :truc_sibling), child2, [true])
            # A version-2 child of a version-3 parent, and an oversized v3 child.
            v2 = build([o2], [true], version: 2, rate: 3)
            st = record.(st, :truc_v2_child, check(btc, ex, v2, :truc_v2_child), v2, [true])

            big =
              build([o2], [true],
                version: 3,
                rate: 3,
                extra_outputs: [{0, <<0x6A>> <> push(:binary.copy(<<7>>, 1500))}]
              )

            record.(st, :truc_big_child, check(btc, ex, big, :truc_big_child), big, [true])
          else
            st
          end

        :spends_conflict ->
          case Enum.filter(
                 st.accepted,
                 &(&1.version == 2 and Enum.all?(&1.inputs, fn i -> i.witness == [@ws_true] end) and
                     Mempool.has?(ex.mp, &1.txid))
               ) do
            [] ->
              st

            cands ->
              old = Enum.random(cands)

              case Mempool.entry(ex.mp, old.txid) do
                nil ->
                  st

                e ->
                  in0 = hd(old.inputs)
                  value = e.fee + Enum.reduce(old.outputs, 0, &(&2 + &1.value))
                  # Spends old's input again AND old's first output.
                  coins = [
                    {in0.prev_hash, in0.prev_index, value, true},
                    {old.txid, 0, hd(old.outputs).value, true}
                  ]

                  tx = build(coins, [true], rate: 50)
                  record.(st, :spends_conflict, check(btc, ex, tx, :spends_conflict), tx, [true])
              end
          end

        :p2sh ->
          case Enum.find(st.fresh, fn {_, _, _, k} -> k == :p2sh end) do
            nil ->
              st

            c ->
              st = %{st | fresh: List.delete(st.fresh, c)}
              tx = build([c], [true, :p2sh], rate: 2)
              record.(st, :p2sh, check(btc, ex, tx, :p2sh), tx, [true, :p2sh])
          end
      end
    end

    # A chain of 70 txs: the cluster limit (64) is hit inside it.
    long_chain = fn st ->
      {c, st} = take_fresh.(st)

      {st, _} =
        Enum.reduce(1..70, {st, c}, fn i, {st, coin} ->
          tx = build([coin], [true], rate: 2)
          r = check(btc, ex, tx, :long_chain)
          st = record.(st, :long_chain, r, tx, [])

          {st, if(r == :accepted, do: hd(outputs_of(tx, [true])), else: coin)}
          |> tap(fn _ -> _ = i end)
        end)

      st
    end

    # Coins with a policy-only script (OP_NOP4), for the documented gap.
    seed_nop4 = fn st ->
      {c, st} = take_fresh.(st)
      tx = build([c], [:nop4, :nop4, true], rate: 2)
      record.(st, :seed_nop4, check(btc, ex, tx, :seed_nop4), tx, [:nop4, :nop4, true])
    end

    # Phase 1: stream of single txs, with blocks mined and a reorg between rounds.
    st =
      Enum.reduce(1..6, st, fn round, st ->
        st = st |> seed_nop4.() |> then(&if(round in [1, 4], do: long_chain.(&1), else: &1))
        st = Enum.reduce(1..60, st, fn _, st -> step.(st, pick.()) end)
        n = mempools_equal!(btc, ex, "round #{round} before block")

        cond do
          round == 3 ->
            # Reorg: invalidate the tip (its txs return to the mempool), then two empty blocks.
            Bitcoind.mine(btc, 1)
            sync_blocks(btc, ex)
            Bitcoind.cli(btc, ["invalidateblock", Bitcoind.cli(btc, ["getbestblockhash"])])
            for _ <- 1..2, do: Bitcoind.json(btc, ["generateblock", "raw(51)", "[]"])
            sync_blocks(btc, ex)
            mempools_equal!(btc, ex, "after reorg")

          true ->
            Bitcoind.mine(btc, 1)
            sync_blocks(btc, ex)
            mempools_equal!(btc, ex, "round #{round} after block (mempool had #{n})")
        end

        st
      end)

    # Phase 2: packages through submitpackage.
    st = Enum.reduce(1..12, st, fn i, st -> package_step(btc, ex, st, i) end)
    mempools_equal!(btc, ex, "after packages")

    reasons = st.results |> Enum.map(&elem(&1, 1)) |> Enum.frequencies()

    IO.puts(
      "\n  replayed #{length(st.results) + length(st.gaps) + length(st.div)} txs; outcomes: #{inspect(reasons)}"
    )

    IO.puts("  policy-script gaps (expected): #{length(st.gaps)}")
    assert st.div == [], "divergences: #{inspect(Enum.take(st.div, 10), limit: 50)}"
    # The stream must actually exercise the interesting cases.
    for r <- [
          "min relay fee not met",
          "insufficient fee",
          "too-large-cluster",
          "dust",
          "scriptpubkey",
          "tx-size-small",
          "non-final",
          "non-BIP68-final",
          "missing-inputs",
          "txn-already-in-mempool",
          "txn-same-nonwitness-data-in-mempool",
          "TRUC-violation",
          "bad-txns-spends-conflicting-tx",
          "replacement-failed"
        ] do
      assert Map.has_key?(reasons, r), "stream never produced #{r}"
    end

    assert Enum.any?(st.results, &match?({:rbf, :ok}, &1)), "no successful replacement"
  end

  defp take_unconf_kind(st, kind) do
    case Enum.find(st.unconf, fn {_, _, _, k} -> k == kind end) do
      nil -> nil
      c -> {c, %{st | unconf: List.delete(st.unconf, c)}}
    end
  end

  defp push(d) when byte_size(d) <= 75, do: <<byte_size(d)>> <> d
  defp push(d) when byte_size(d) <= 255, do: <<0x4C, byte_size(d)>> <> d
  defp push(d), do: <<0x4D, byte_size(d)::little-16>> <> d

  # Packages: compare package success and which txs end up in each mempool.
  defp package_step(btc, ex, st, i) do
    [c | rest] = st.fresh
    st = %{st | fresh: rest}

    {parent_opts, child_spends_dust, version} =
      case rem(i, 4) do
        # 1p1c, 0-fee parent
        0 -> {[fee: 0], true, 2}
        # ephemeral dust, spent
        1 -> {[fee: 0, extra_outputs: [{0, p2wsh(@ws_true)}]], true, 2}
        # ephemeral dust, not spent
        2 -> {[fee: 0, extra_outputs: [{0, p2wsh(@ws_true)}]], false, 2}
        # TRUC 1p1c
        3 -> {[fee: 0], true, 3}
      end

    parent = build([c], [true], [version: version] ++ parent_opts)

    spend =
      outputs_of(parent, [true]) ++
        if(child_spends_dust and length(parent.outputs) > 1,
          do: [{parent.txid, 1, 0, true}],
          else: []
        )

    child = build(spend, [true], version: version, rate: 20)

    [core] = Bitcoind.rpc_batch(btc, [{"submitpackage", [[hex(raw(parent)), hex(raw(child))]]}])
    ours = Mempool.submit_package(ex.mp, [parent, child])

    core_ok = core["package_msg"] == "success"
    ex_ok = ours.state == :ok

    in_core =
      for t <- [parent, child],
          do: Enum.member?(Bitcoind.json(btc, ["getrawmempool"]), Hash.to_hex(t.txid))

    in_ex = for t <- [parent, child], do: Enum.member?(Mempool.txids(ex.mp), t.txid)

    st = %{
      st
      | results: [
          {:"package_#{rem(i, 4)}", if(core_ok, do: :ok, else: core["package_msg"])} | st.results
        ]
    }

    if core_ok == ex_ok and in_core == in_ex,
      do: st,
      else: %{
        st
        | div: [{:package, rem(i, 4), core["package_msg"], ours.state, in_core, in_ex} | st.div]
      }
  end
end
