defmodule Exnode.Chain.QuarantineTest do
  @moduledoc """
  An exception while connecting a block is contained to that block
  and quarantines it, instead of crashing the chain state (and, through
  `pending`, every later start).
  1. A raise in validation, and a crash in the block's script task: the
     chain state survives, the block is quarantined (durable mark, crash
     report), its header is not invalidated, the source is told `:crash`.
  2. A restart skips it (no validation attempt, start-up log), no loop.
  3. Re-submitting it is refused at once, with no validation attempt.
  4. Clearing the quarantine lets it connect once the cause is gone.
  5. A consensus-invalid block still fails as before (header invalidated).
  Peers never punish a `:crash` or `:quarantined` result.
  """
  use Exnode.NodeCase, async: true
  import ExUnit.CaptureLog

  alias Exnode.ChainParams
  alias Exnode.Chain.{HeaderIndex, Headers, State}
  alias Exnode.Codec.Block
  alias Exnode.Store.KV
  alias Exnode.Test.BlockBuilder, as: BB

  @p ChainParams.get(:regtest)
  @chain Path.expand("../../fixtures/regtest/chain150.bin", __DIR__)
  @coin 100_000_000

  # The hook raises for `hash` while `armed` is set; every call for it is reported.
  defp hook(test, hash, armed) do
    fn block, _entry ->
      if block.header.hash == hash do
        send(test, :validated_target)
        if :atomics.get(armed, 1) == 1, do: raise("injected validation bug")
      end

      :ok
    end
  end

  defp start_cs(dir, kv, hs, opts) do
    {:ok, cs} =
      State.start_link(
        [params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), listeners: [self()]] ++ opts
      )

    cs
  end

  defp setup_chain(dir) do
    bs = for raw <- BB.read_chain(@chain), do: elem(Block.decode_exact(raw), 1)
    {:ok, kv} = KV.open(Path.join(dir, "kv"))
    {:ok, hs} = Headers.start_link(params: @p, kv: kv)
    # Block 151 spends block 1's coinbase (so it has script checks).
    b151 =
      BB.build(List.last(bs).header, [
        BB.coinbase(151, 25 * @coin),
        BB.spend_op_true(hd(hd(bs).txs).txid, 0, 50 * @coin)
      ])

    %{bs: bs, kv: kv, hs: hs, b151: b151}
  end

  defp status(hs, hash), do: HeaderIndex.lookup(Headers.index(hs), hash).status

  test "a raise in validation: quarantined, not invalidated, survives restart, refused on re-receipt, reconsidered",
       %{tmp_dir: dir} do
    %{bs: bs, kv: kv, hs: hs, b151: b} = setup_chain(dir)
    hash = b.header.hash
    armed = :atomics.new(1, [])
    :atomics.put(armed, 1, 1)
    cs = start_cs(dir, kv, hs, rule_override: hook(self(), hash, armed))
    for x <- bs, do: {:ok, :connected} = State.submit_block(cs, x)

    log =
      capture_log(fn ->
        assert {:ok, :stored} = State.submit_block(cs, b, defer: true, source: self())
        assert_receive {:block_checked, ^hash, {:error, {:crash, _}}}, 5_000
      end)

    # 1. Contained: alive, quarantined, header not failed, crash report written.
    assert Process.alive?(cs)
    assert State.poisoned(cs) == [hash]
    assert State.tip(cs).height == 150
    assert status(hs, hash) != :failed
    assert log =~ "validation crashed, block quarantined"
    assert_received {:block_quarantined, ^hash, _}
    report = File.read!(Path.join([dir, "crashes", Exnode.Crypto.Hash.to_hex(hash) <> ".log"]))
    assert report =~ "injected validation bug" and report =~ Base.encode16(b.raw, case: :lower)
    assert {:ok, _} = KV.get(kv, :poisoned, hash)
    assert_received :validated_target

    # 2. Restart: the quarantined block is not replayed.
    GenServer.stop(cs)

    log =
      capture_log(fn ->
        cs2 = start_cs(dir, kv, hs, rule_override: hook(self(), hash, armed))
        send(self(), {:cs2, cs2})
      end)

    assert_received {:cs2, cs2}
    assert log =~ "1 block(s) quarantined"
    assert State.tip(cs2).height == 150
    refute_received :validated_target
    # Skipped by load_pending: not held at all (its pending copy is kept).
    assert GenServer.call(cs2, :debug).held == []
    assert {:ok, _} = KV.get(kv, :pending, hash)

    # 3. Re-received: refused at once, never validated.
    assert {:error, {:quarantined, _}} = State.submit_block(cs2, b, defer: true, source: self())
    assert {:error, {:quarantined, _}} = State.submit_block(cs2, b)
    _ = State.tip(cs2)
    refute_received :validated_target
    refute_received {:block_checked, ^hash, _}
    assert status(hs, hash) != :failed

    # 4. Cause fixed: clearing the quarantine connects it from the kept pending copy.
    :atomics.put(armed, 1, 0)
    capture_log(fn -> assert State.reconsider_poisoned(cs2) == [hash] end)
    assert State.tip(cs2).hash == hash
    assert State.poisoned(cs2) == []
    assert KV.get(kv, :poisoned, hash) == :not_found
  end

  # Regression: a block quarantined while being reconnected
  # from the archive (after a reorg away from it) has no pending copy.
  # reconsider_poisoned re-held pending copies only, so it was no candidate
  # again until a restart rebuilt the candidates.
  test "reconsidering an archived block quarantined on reconnect makes it a candidate at once",
       %{tmp_dir: dir} do
    %{bs: bs, kv: kv, hs: hs, b151: a} = setup_chain(dir)
    hash = a.header.hash
    armed = :atomics.new(1, [])
    cs = start_cs(dir, kv, hs, rule_override: hook(self(), hash, armed))
    for x <- bs ++ [a], do: {:ok, :connected} = State.submit_block(cs, x)
    :atomics.put(armed, 1, 1)

    # A heavier fork from 150 whose first block is invalid: `a` is
    # disconnected (archived, off chain), f151 fails, and `a`, the best
    # candidate again on its own, crashes on reconnect: quarantined with no
    # pending copy and no held descendant.
    tip150 = List.last(bs).header
    f151 = BB.build(tip150, [BB.coinbase(151, 25 * @coin + 1, <<0x52>>)])
    f152 = BB.build(f151.header, [BB.coinbase(152, 25 * @coin, <<0x52>>)])

    capture_log(fn ->
      for x <- [f151, f152], do: State.submit_block(cs, x, requested: true)
      _ = State.tip(cs)
    end)

    assert State.poisoned(cs) == [hash]
    assert KV.get(kv, :pending, hash) == :not_found
    assert State.tip(cs).height == 150

    # Fixed: reconsidered, `a` reconnects without a restart.
    :atomics.put(armed, 1, 0)
    capture_log(fn -> assert State.reconsider_poisoned(cs) == [hash] end)
    assert State.tip(cs).hash == hash
  end

  # Regression: during startup replay, init waits in a
  # selective receive that ignored the private script executor's DOWN: if
  # the executor died there, init waited forever for its job results.
  test "the private script executor dying during startup replay fails the start instead of hanging",
       %{tmp_dir: dir} do
    %{bs: bs, kv: kv, hs: hs, b151: b} = setup_chain(dir)
    cs = start_cs(dir, kv, hs, batch_blocks: 1000, commit_at_tip: false)
    for x <- bs ++ [b], do: {:ok, :connected} = State.submit_block(cs, x)
    Process.unlink(cs)
    Process.exit(cs, :kill)

    # Its first script job (block 151's, replayed from pending) kills the executor.
    killer = fn _job ->
      {:links, links} = Process.info(self(), :links)
      Enum.each(links, &Process.exit(&1, :kill))
      # The worker then leaves on its executor's exit.
      {:invalid, "unused"}
    end

    opts = [params: @p, headers: hs, kv: kv, hot: Path.join(dir, "hot"), script_run: killer]
    task = Task.async(fn -> GenServer.start(State, opts) end)

    assert {:ok, {:error, {:script_exec_down, :killed}}} =
             Task.yield(task, 10_000) || Task.shutdown(task, :brutal_kill)
  end

  # Regression: BlockDownload selects blocks the chain
  # view does not "have". A quarantined block's body stays in `pending` and
  # resubmission is refused, so it must count as had: otherwise it is the
  # earliest missing block and every peer downloads it again, forever.
  test "a quarantined block counts as had for download selection, also after a restart",
       %{tmp_dir: dir} do
    %{bs: bs, kv: kv, hs: hs, b151: b} = setup_chain(dir)
    hash = b.header.hash
    armed = :atomics.new(1, [])
    :atomics.put(armed, 1, 1)
    name = :"quarantine_cs_#{System.unique_integer([:positive])}"
    opts = [rule_override: hook(self(), hash, armed), name: name]
    cs = start_cs(dir, kv, hs, opts)
    for x <- bs, do: {:ok, :connected} = State.submit_block(cs, x)
    refute MapSet.member?(State.view_have_many(State.view(name), [hash]), hash)

    capture_log(fn ->
      assert {:ok, :stored} = State.submit_block(cs, b, defer: true, source: self())
      assert_receive {:block_checked, ^hash, {:error, {:crash, _}}}, 5_000
    end)

    assert State.poisoned(cs) == [hash]
    assert MapSet.member?(State.view_have_many(State.view(name), [hash]), hash)
    assert MapSet.member?(State.have_many(cs, [hash]), hash)

    GenServer.stop(cs)
    capture_log(fn -> send(self(), {:cs2, start_cs(dir, kv, hs, opts)}) end)
    assert_received {:cs2, cs2}
    assert MapSet.member?(State.view_have_many(State.view(name), [hash]), hash)
    assert MapSet.member?(State.have_many(cs2, [hash]), hash)

    # Cleared and connected: had as an archived block.
    :atomics.put(armed, 1, 0)
    capture_log(fn -> assert State.reconsider_poisoned(cs2) == [hash] end)
    assert State.tip(cs2).hash == hash
    assert :ets.lookup(State.view(name), {:quarantined, hash}) == []
    assert MapSet.member?(State.view_have_many(State.view(name), [hash]), hash)
  end

  test "a crash inside the block's script task is contained the same way", %{tmp_dir: dir} do
    %{bs: bs, kv: kv, hs: hs, b151: b} = setup_chain(dir)
    hash = b.header.hash
    script_hook = fn blk -> if blk.header.hash == hash, do: raise("injected script task bug") end
    cs = start_cs(dir, kv, hs, test_script_hook: script_hook)
    Process.unlink(cs)
    ref = Process.monitor(cs)
    for x <- bs, do: {:ok, :connected} = State.submit_block(cs, x)

    capture_log(fn ->
      assert {:error, {:crash, _}} = State.submit_block(cs, b)
    end)

    # The task's link exit must not stop the chain state either.
    refute_receive {:DOWN, ^ref, _, _, _}, 500
    assert State.poisoned(cs) == [hash]
    assert status(hs, hash) != :failed
    assert State.tip(cs).height == 150
  end

  # An archive hook that reports every archiving of `hash` and, while
  # `armed`, then runs `fail` (after Archive.connect's side effects).
  defp archive_hook(test, hash, armed, fail) do
    fn block ->
      if block.header.hash == hash do
        send(test, :archived_target)
        if :atomics.get(armed, 1) == 1, do: fail.()
      end
    end
  end

  test "a crash while archiving: quarantined, the chain state restarts from its last commit, " <>
         "the uncommitted blocks are replayed, the block is not",
       %{tmp_dir: dir} do
    %{bs: bs, kv: kv, hs: hs, b151: b} = setup_chain(dir)
    hash = b.header.hash
    armed = :atomics.new(1, [])
    :atomics.put(armed, 1, 1)
    hook = archive_hook(self(), hash, armed, fn -> raise "injected archive bug" end)
    # Nothing committed before the crash: blocks 1..150 live only in the batch.
    opts = [test_archive_hook: hook, batch_blocks: 1_000, commit_at_tip: false]
    cs = start_cs(dir, kv, hs, opts)
    Process.unlink(cs)
    ref = Process.monitor(cs)
    for x <- bs, do: {:ok, :connected} = State.submit_block(cs, x)

    log =
      capture_log(fn ->
        assert {:ok, :stored} = State.submit_block(cs, b, defer: true, source: self())
        assert_receive {:block_checked, ^hash, {:error, {:crash, _}}}, 5_000
        assert_receive {:DOWN, ^ref, :process, ^cs, {:shutdown, {:archive_crashed, _}}}, 5_000
      end)

    assert log =~ "archiving crashed, block quarantined"
    assert_received :archived_target
    assert_received {:block_quarantined, ^hash, _}
    assert {:ok, _} = KV.get(kv, :poisoned, hash)
    assert status(hs, hash) != :failed
    report = File.read!(Path.join([dir, "crashes", Exnode.Crypto.Hash.to_hex(hash) <> ".log"]))
    assert report =~ "injected archive bug"

    # The restart (as the supervisor's): 1..150 come back from `pending`,
    # 151 is skipped, so no crash loop.
    log =
      capture_log(fn ->
        cs2 = start_cs(dir, kv, hs, opts)
        send(self(), {:cs2, cs2})
      end)

    assert_received {:cs2, cs2}
    assert log =~ "1 block(s) quarantined"
    wait_until(fn -> State.tip(cs2).height == 150 end)
    refute_received :archived_target
    assert State.poisoned(cs2) == [hash]

    # The archive is consistent past the crash: with the cause gone, the
    # block connects and commits, and survives another restart.
    :atomics.put(armed, 1, 0)
    capture_log(fn -> assert State.reconsider_poisoned(cs2) == [hash] end)
    assert State.tip(cs2).hash == hash
    State.commit_now(cs2)
    GenServer.stop(cs2)
    cs3 = start_cs(dir, kv, hs, opts)
    assert State.tip(cs3).hash == hash
  end

  # Regression: the crashing callback had already made a
  # durable commit; terminate/2 must not write its older pre-callback state
  # (meta tip/ends) over it.
  test "a crash after a commit in the same turn: terminate keeps the newer commit, the restart resumes past it",
       %{tmp_dir: dir} do
    %{bs: bs, kv: kv, hs: hs} = setup_chain(dir)
    {first, [b148, b149, b150]} = Enum.split(bs, 147)
    hash = b149.header.hash
    armed = :atomics.new(1, [])
    :atomics.put(armed, 1, 1)
    hook = archive_hook(self(), hash, armed, fn -> raise "injected archive bug" end)
    # Batches of 2: after 1..147 the batch holds 147 (uncommitted); 148
    # fills it (commit, tip 148 on disk), then 149 crashes in the same turn.
    opts = [test_archive_hook: hook, batch_blocks: 2, commit_at_tip: false]
    cs = start_cs(dir, kv, hs, opts)
    Process.unlink(cs)
    ref = Process.monitor(cs)
    for x <- first, do: {:ok, :connected} = State.submit_block(cs, x)

    capture_log(fn ->
      # 149 first (held: its parent's body is missing), then 148: one plan
      # retires both in one turn.
      _ = Headers.process_headers(hs, [b148.header, b149.header])
      assert {:ok, :stored} = State.submit_block(cs, b149, defer: true, source: self())
      assert {:ok, :stored} = State.submit_block(cs, b148, defer: true, source: self())
      assert_receive {:DOWN, ^ref, :process, ^cs, {:shutdown, {:archive_crashed, _}}}, 5_000
    end)

    assert_received :archived_target

    log =
      capture_log(fn ->
        cs2 = start_cs(dir, kv, hs, opts)
        send(self(), {:cs2, cs2})
      end)

    assert_received {:cs2, cs2}
    assert log =~ "1 block(s) quarantined"
    assert wait_until(fn -> State.tip(cs2).height == 148 end)
    assert State.tip(cs2).hash == b148.header.hash

    # The archive is whole: 149 connects once cleared, 150 on top, and both
    # survive a clean restart.
    :atomics.put(armed, 1, 0)
    capture_log(fn -> assert State.reconsider_poisoned(cs2) == [hash] end)
    assert {:ok, _} = State.submit_block(cs2, b150)
    assert State.tip(cs2).hash == b150.header.hash
    State.commit_now(cs2)
    GenServer.stop(cs2)
    cs3 = start_cs(dir, kv, hs, opts)
    assert State.tip(cs3).hash == b150.header.hash
  end

  test "a storage failure while archiving is not quarantined: fatal, and replayed once fixed",
       %{tmp_dir: dir} do
    %{bs: bs, kv: kv, hs: hs, b151: b} = setup_chain(dir)
    hash = b.header.hash
    armed = :atomics.new(1, [])
    :atomics.put(armed, 1, 1)

    # A segment write on a closed file fails inside the storage layer, as a
    # disk error would.
    path = Path.join(dir, "closed.seg")
    {:ok, fd} = :file.open(String.to_charlist(path), [:raw, :binary, :write])
    :ok = :file.close(fd)
    seg = %Exnode.Archive.Segments{dir: dir, kind: :outputs, seg: 0, offset: 0, fd: fd}

    hook =
      archive_hook(self(), hash, armed, fn -> Exnode.Archive.Segments.append_block(seg, ["x"]) end)

    opts = [test_archive_hook: hook]
    cs = start_cs(dir, kv, hs, opts)
    Process.unlink(cs)
    ref = Process.monitor(cs)
    for x <- bs, do: {:ok, :connected} = State.submit_block(cs, x)

    capture_log(fn ->
      assert {:ok, :stored} = State.submit_block(cs, b, defer: true, source: self())
      assert_receive {:DOWN, ^ref, :process, ^cs, reason}, 5_000
      refute match?({:shutdown, _}, reason)
    end)

    assert KV.get(kv, :poisoned, hash) == :not_found
    refute_received {:block_checked, ^hash, _}

    # Disk fixed: the restart replays the block from `pending`.
    :atomics.put(armed, 1, 0)
    cs2 = start_cs(dir, kv, hs, opts)
    wait_until(fn -> State.tip(cs2).hash == hash end)
    assert State.poisoned(cs2) == []
  end

  test "a consensus-invalid block still fails as before: header invalidated, not quarantined", %{
    tmp_dir: dir
  } do
    %{bs: bs, kv: kv, hs: hs, b151: b} = setup_chain(dir)
    hash = b.header.hash

    bad = fn block, _ ->
      if block.header.hash == hash, do: {:error, {:consensus, "injected-invalid"}}, else: :ok
    end

    cs = start_cs(dir, kv, hs, rule_override: bad)
    for x <- bs, do: {:ok, :connected} = State.submit_block(cs, x)

    capture_log(fn ->
      assert {:ok, :stored} = State.submit_block(cs, b, defer: true, source: self())
    end)

    assert_receive {:block_checked, ^hash, {:error, {:consensus, "injected-invalid"}}}, 5_000
    assert status(hs, hash) == :failed
    assert State.poisoned(cs) == []
    assert KV.get(kv, :poisoned, hash) == :not_found
  end

  test "peers do not punish :crash or :quarantined results", %{tmp_dir: dir} do
    %{n: n} = TestNode.start(dir)
    {pid, _sock} = FakePeer.connect_from(n, handshake: false)
    ref = Process.monitor(pid)
    send(pid, {:block_checked, <<1::256>>, {:error, {:crash, "validation crashed locally"}}})
    send(pid, {:block_checked, <<2::256>>, {:error, {:quarantined, "quarantined"}}})
    refute_receive {:DOWN, ^ref, _, _, _}, 500
    # A consensus failure is still punished (the existing path).
    send(pid, {:block_checked, <<3::256>>, {:error, {:consensus, "bad-txns"}}})
    assert_receive {:DOWN, ^ref, :process, ^pid, {:shutdown, {:misbehaving, _}}}, 2_000
  end
end
