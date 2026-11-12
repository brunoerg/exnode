defmodule Exnode.Mempool.PackageTest do
  @moduledoc """
  Package acceptance (`Mempool.test_accept/2` with several txs,
  `Mempool.submit_package/2`), after Core v32.1's functional tests
  rpc_packages.py, mempool_package_rbf.py and mempool_truc.py:

  * well-formedness and child-with-parents;
  * txs already in the mempool, or there with another witness;
  * a parent below the minimum fee carried by its child (package
    feerate), and failures before, in and after package evaluation;
  * the mempool trimmed right after the package: "mempool full";
  * package RBF: 1-parent-1-child only, no mempool ancestors, anti-DoS
    fees, package feerate above the parent's, a better feerate diagram;
  * TRUC (version 3) rules between package and mempool txs.

  Real chain state and headers on a regtest chain built here, coinbases to
  P2WSH(OP_TRUE).
  """
  use ExUnit.Case, async: true

  alias Exnode.ChainParams
  alias Exnode.Chain.{Headers, State}
  alias Exnode.Codec.Tx
  alias Exnode.Mempool
  alias Exnode.Mempool.Package
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @moduletag :tmp_dir
  @p ChainParams.get(:regtest)
  @coin 100_000_000
  # P2WSH(OP_TRUE), spent with the witness [OP_TRUE].
  @spk <<0, 32>> <> :crypto.hash(:sha256, <<0x51>>)
  # P2WSH(OP_DROP OP_TRUE): any first witness item, so one tx can have
  # several witnesses.
  @drop <<0x75, 0x51>>
  @drop_spk <<0, 32>> <> :crypto.hash(:sha256, @drop)

  setup %{tmp_dir: dir} = ctx do
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    on_exit(fn -> KV.close(kv) end)
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    name = :"mp_#{System.unique_integer([:positive])}"

    {:ok, cs} =
      State.start_link(params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), mempool: name)

    {blocks, _} =
      Enum.map_reduce(1..120, @p.genesis.header, fn h, prev ->
        b = BB.build(prev, [BB.coinbase_with(h, 50 * @coin, outputs: [{50 * @coin, @spk}])])
        {b, b.header}
      end)

    for b <- blocks, do: {:ok, :connected} = State.submit_block(cs, b)

    {:ok, mp} =
      Mempool.start_link(
        name: name,
        chain_state: cs,
        headers: hs,
        params: @p,
        policy: Map.get(ctx, :policy, [])
      )

    # 20 mature coinbases.
    %{mp: mp, coins: for(b <- Enum.take(blocks, 20), do: {hd(b.txs).txid, 0, 50 * @coin})}
  end

  # A tx spending `ins` ({txid, vout} or {txid, vout, witness}; OP_TRUE by
  # default) to `outs` (values to P2WSH(OP_TRUE), or {value, spk}).
  defp tx(ins, outs, version \\ 2) do
    inputs =
      for i <- ins do
        {txid, vout, wit} =
          case i do
            {t, v} -> {t, v, [<<0x51>>]}
            {_, _, _} = full -> full
          end

        %Tx.In{
          prev_hash: txid,
          prev_index: vout,
          script_sig: <<>>,
          sequence: 0xFFFFFFFD,
          witness: wit
        }
      end

    outputs =
      for o <- outs do
        case o do
          {v, spk} -> %Tx.Out{value: v, script_pubkey: spk}
          v -> %Tx.Out{value: v, script_pubkey: @spk}
        end
      end

    BB.finalize(%Tx{version: version, inputs: inputs, outputs: outputs, locktime: 0})
  end

  # Spends coin `{txid, vout, value}` to one output, paying `fee`.
  defp spend({txid, vout, value}, fee, version \\ 2),
    do: tx([{txid, vout}], [value - fee], version)

  defp out(t, i \\ 0), do: {t.txid, i, Enum.at(t.outputs, i).value}

  defp state(res), do: res.state
  defp result(res, t), do: res.txs[t.wtxid]
  defp reason(res, t), do: elem(result(res, t), 1).reason
  defp in_pool?(mp, t), do: t.txid in Mempool.txids(mp)

  describe "context-free checks" do
    test "too many txs, and a single tx is not a child with parents", %{coins: [c | _]} do
      t = spend(c, 1_000)

      assert Package.well_formed(List.duplicate(t, 26)) ==
               {:error, "package-too-many-transactions"}

      refute Package.child_with_parents?([t])
    end

    test "a package that is not well formed is refused whole", %{mp: mp, coins: [c | _]} do
      p = spend(c, 1_000)
      ch = spend(out(p), 1_000)

      assert %{state: {:policy, "package-not-sorted", nil}, txs: txs} =
               Mempool.submit_package(mp, [ch, p])

      assert txs == %{}
      # testmempoolaccept evaluates it as one package too.
      assert {:policy, "package-not-sorted", nil} = state(Mempool.test_accept(mp, [ch, p]))
    end
  end

  describe "submitpackage" do
    test "a parent below the minimum fee goes in with its child (CPFP)", %{mp: mp, coins: [c | _]} do
      p = spend(c, 0)
      ch = spend(out(p), 10_000)
      res = Mempool.submit_package(mp, [p, ch])
      assert state(res) == :ok
      assert {:valid, %{fee: 0}} = result(res, p)
      assert {:valid, %{fee: 10_000}} = result(res, ch)
      assert in_pool?(mp, p) and in_pool?(mp, ch)
    end

    test "a package whose total feerate is too low: the child carries the error",
         %{mp: mp, coins: [c | _]} do
      p = spend(c, 0)
      ch = spend(out(p), 1)
      res = Mempool.submit_package(mp, [p, ch])
      assert state(res) == {:tx, "transaction failed", nil}
      assert reason(res, ch) == "min relay fee not met"
      refute in_pool?(mp, p)
    end

    test "parents already in the mempool, or there with another witness",
         %{mp: mp, coins: [c1, c2 | _]} do
      p1 = spend(c1, 1_000)
      # p2 spends an OP_DROP OP_TRUE output: any first witness item works,
      # so p2b has p2's txid with another wtxid.
      g = tx([{elem(c2, 0), 0}], [{50 * @coin - 1_000, @drop_spk}])
      p2 = tx([{g.txid, 0, [<<1>>, @drop]}], [50 * @coin - 2_000])
      p2b = tx([{g.txid, 0, [<<2>>, @drop]}], [50 * @coin - 2_000])
      assert p2b.txid == p2.txid and p2b.wtxid != p2.wtxid
      for t <- [p1, g, p2], do: assert({:ok, _} = Mempool.accept(mp, t))

      ch = tx([{p1.txid, 0}, {p2.txid, 0}], [100 * @coin - 3_000 - 10_000])
      res = Mempool.submit_package(mp, [p1, p2b, ch])
      assert state(res) == :ok
      assert {:mempool, %{fee: 1_000}} = result(res, p1)
      assert result(res, p2b) == {:different_witness, p2.wtxid}
      assert {:valid, %{fee: 10_000}} = result(res, ch)
      assert in_pool?(mp, ch)
    end

    test "a parent that fails for a reason no child can fix ends the package early",
         %{mp: mp, coins: [c | _]} do
      # A dust output: not standard, whatever the package pays.
      p = tx([{elem(c, 0), 0}], [50 * @coin - 10_000, 1])
      ch = spend(out(p), 10_000)
      res = Mempool.submit_package(mp, [p, ch])
      assert state(res) == {:tx, "transaction failed", nil}
      assert reason(res, p) == "dust"
      # The child failed alone (its input missing) and was never evaluated with p.
      assert {:invalid, %{result: :missing_inputs}} = result(res, ch)
    end

    test "a child whose script fails in package evaluation", %{mp: mp, coins: [c | _]} do
      p = spend(c, 0)
      # P2WSH(OP_TRUE) spent with OP_2 as the witness script: hash mismatch.
      ch = tx([{p.txid, 0, [<<0x52>>]}], [50 * @coin - 10_000])
      res = Mempool.submit_package(mp, [p, ch])
      assert state(res) == {:tx, "transaction failed", nil}
      assert {:invalid, %{}} = result(res, ch)
      refute in_pool?(mp, p)
    end

    test "a parent's ephemeral dust left unspent by its child: unspent-dust",
         %{mp: mp, coins: [c | _]} do
      # A 0-fee parent may carry one dust output if a package child spends it.
      p = tx([{elem(c, 0), 0}], [50 * @coin, 0])
      ch = spend(out(p), 10_000)
      res = Mempool.submit_package(mp, [p, ch])
      assert state(res) == {:tx, "unspent-dust", nil}
      assert reason(res, ch) == "missing-ephemeral-spends"

      ch = tx([{p.txid, 0}, {p.txid, 1}], [50 * @coin - 10_000])
      assert state(Mempool.submit_package(mp, [p, ch])) == :ok
    end

    # The mempool is trimmed once, after the whole package: a tx accepted
    # and then trimmed away is reported as "mempool full".
    @tag policy: [max_size: 1]
    test "trimmed after package evaluation: mempool full", %{mp: mp, coins: [c | _]} do
      p = spend(c, 0)
      ch = spend(out(p), 10_000)
      res = Mempool.submit_package(mp, [p, ch])
      assert state(res) == {:tx, "transaction failed", nil}
      for t <- [p, ch], do: assert(reason(res, t) == "mempool full")
      assert Mempool.txids(mp) == []
    end

    @tag policy: [max_size: 1]
    test "accepted alone, then trimmed: mempool full", %{mp: mp, coins: [c | _]} do
      p = spend(c, 1_000)
      ch = spend(out(p), 1_000)
      res = Mempool.submit_package(mp, [p, ch])
      assert state(res) == {:tx, "transaction failed", nil}
      for t <- [p, ch], do: assert(reason(res, t) == "mempool full")
      assert Mempool.txids(mp) == []
    end
  end

  describe "testmempoolaccept" do
    test "a tx with a missing input fails before any package rule", %{mp: mp, coins: [c | _]} do
      p = spend(c, 1_000)
      ch = tx([{p.txid, 0}, {<<9::256>>, 0}], [50 * @coin - 3_000])
      res = Mempool.test_accept(mp, [p, ch])
      assert state(res) == {:tx, "transaction failed", nil}
      assert {:invalid, %{result: :missing_inputs}} = result(res, ch)
      assert result(res, p) == nil
    end

    test "a valid package: results for each tx, nothing added", %{mp: mp, coins: [c | _]} do
      p = spend(c, 1_000)
      ch = spend(out(p), 1_000)
      res = Mempool.test_accept(mp, [p, ch])
      assert state(res) == :ok
      assert {:valid, _} = result(res, p)
      assert {:valid, _} = result(res, ch)
      assert Mempool.txids(mp) == []
    end
  end

  describe "package RBF" do
    # A mempool tx spending `c`, then a 0-fee parent replacing it (too poor
    # to replace it alone) and its child paying `child_fee`.
    defp rbf(mp, c, mempool_fee, child_fee, child_outs \\ 1) do
      m = spend(c, mempool_fee)
      assert {:ok, _} = Mempool.accept(mp, m)
      p = tx([{elem(c, 0), 0}], [50 * @coin - 1])
      v = 50 * @coin - 1 - child_fee

      outs = [
        v - div(v, child_outs) * (child_outs - 1)
        | List.duplicate(div(v, child_outs), child_outs - 1)
      ]

      ch = tx([{p.txid, 0}], outs)
      {m, p, ch}
    end

    defp rbf_error(res), do: elem(state(res), 1)

    test "a parent and child replace a mempool tx the parent could not replace alone",
         %{mp: mp, coins: [c | _]} do
      {m, p, ch} = rbf(mp, c, 1_000, 10_000)
      res = Mempool.submit_package(mp, [p, ch])
      assert state(res) == :ok
      assert {:valid, %{replaced: [mtxid]}} = result(res, p)
      assert mtxid == m.txid
      assert in_pool?(mp, p) and in_pool?(mp, ch)
      refute in_pool?(mp, m)
    end

    test "only a parent and one child may replace", %{mp: mp, coins: [c, c2 | _]} do
      {_m, p, _} = rbf(mp, c, 1_000, 10_000)
      p2 = spend(c2, 0)
      ch = tx([{p.txid, 0}, {p2.txid, 0}], [100 * @coin - 20_000])
      res = Mempool.submit_package(mp, [p, p2, ch])
      assert rbf_error(res) == "package RBF failed: package must be 1-parent-1-child"
    end

    test "the replacing txs may not have mempool ancestors", %{mp: mp, coins: [c, c2 | _]} do
      _ = rbf(mp, c, 1_000, 10_000)
      a = spend(c2, 1_000)
      assert {:ok, _} = Mempool.accept(mp, a)
      p = tx([{elem(c, 0), 0}, {a.txid, 0}], [100 * @coin - 1_000 - 1])
      ch = spend(out(p), 10_000)
      res = Mempool.submit_package(mp, [p, ch])
      assert rbf_error(res) == "package RBF failed: new transaction cannot have mempool ancestors"
    end

    test "the package must pay more than everything it replaces", %{mp: mp, coins: [c | _]} do
      {_m, p, ch} = rbf(mp, c, 50_000, 10_000)
      res = Mempool.submit_package(mp, [p, ch])
      assert rbf_error(res) == "package RBF failed: insufficient anti-DoS fees"
    end

    test "the package feerate must be above the parent's", %{mp: mp, coins: [c | _]} do
      # The replaced tx has a descendant: the parent pays more than the tx it
      # conflicts with, but not more than both, so it cannot replace alone.
      m = spend(c, 1_000)
      d = spend(out(m), 30_000)
      for t <- [m, d], do: assert({:ok, _} = Mempool.accept(mp, t))
      p = spend(c, 25_000)
      ch = spend(out(p), 7_000)
      res = Mempool.submit_package(mp, [p, ch])

      assert rbf_error(res) ==
               "package RBF failed: package feerate is less than or equal to parent feerate"
    end

    test "the replacement must improve the feerate diagram", %{mp: mp, coins: [c | _]} do
      # More fees in all, but in a large low-feerate child: worse at the top.
      {m, p, ch} = rbf(mp, c, 10_000, 15_000, 30)
      res = Mempool.submit_package(mp, [p, ch])

      assert rbf_error(res) ==
               "package RBF failed: insufficient feerate: does not improve feerate diagram"

      assert in_pool?(mp, m)
    end
  end

  describe "TRUC (version 3) in a package" do
    defp truc_error(res), do: elem(state(res), 2)
    defp v3(ins, outs), do: tx(ins, outs, 3)

    test "a version 3 parent and child pass", %{mp: mp, coins: [c | _]} do
      p = spend(c, 1_000, 3)
      ch = spend(out(p), 1_000, 3)
      assert state(Mempool.test_accept(mp, [p, ch])) == :ok
    end

    test "a version 3 child with two parents has too many ancestors", %{
      mp: mp,
      coins: [c1, c2 | _]
    } do
      p1 = spend(c1, 1_000, 3)
      p2 = spend(c2, 1_000, 3)
      ch = v3([{p1.txid, 0}, {p2.txid, 0}], [100 * @coin - 3_000])
      res = Mempool.test_accept(mp, [p1, p2, ch])
      assert {:policy, "TRUC-violation", msg} = state(res)
      assert msg =~ "would have too many ancestors"
    end

    test "a version 3 child of a package parent is at most 1,000 vbytes",
         %{mp: mp, coins: [c | _]} do
      p = spend(c, 1_000, 3)
      ch = v3([{p.txid, 0}], List.duplicate(div(50 * @coin - 2_000, 30), 30))
      assert truc_error(Mempool.test_accept(mp, [p, ch])) =~ "version=3 child tx"
    end

    test "version 3 and other txs do not spend each other in a package",
         %{mp: mp, coins: [c1, c2 | _]} do
      p = spend(c1, 1_000, 2)
      ch = spend(out(p), 1_000, 3)
      assert truc_error(Mempool.test_accept(mp, [p, ch])) =~ "cannot spend from non-version=3 tx"

      p = spend(c2, 1_000, 3)
      ch = spend(out(p), 1_000, 2)
      assert truc_error(Mempool.test_accept(mp, [p, ch])) =~ "non-version=3 tx"
    end

    test "a version 3 parent gets one child: not a second in the package, nor a grandchild",
         %{mp: mp, coins: [c1, c2 | _]} do
      # Two children of a mempool parent.
      p = tx([{elem(c1, 0), 0}], [25 * @coin, 25 * @coin - 1_000], 3)
      assert {:ok, _} = Mempool.accept(mp, p)
      a = spend(out(p, 0), 1_000, 3)
      b = spend(out(p, 1), 1_000, 3)
      assert truc_error(Mempool.test_accept(mp, [a, b])) =~ "would exceed descendant count limit"

      # A chain of three in the package.
      g = spend(c2, 1_000, 3)
      pa = spend(out(g), 1_000, 3)
      ch = spend(out(pa), 1_000, 3)
      assert truc_error(Mempool.test_accept(mp, [g, pa, ch])) =~ "would have too many ancestors"
    end
  end
end
