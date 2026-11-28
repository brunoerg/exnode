defmodule Exnode.Store.GuardTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog

  alias Exnode.Store.Guard

  @moduletag :tmp_dir

  test "clean acquire, clean mark, and release removes flush.lock and allows reopen", %{
    tmp_dir: dir
  } do
    assert Guard.inspect_lock(dir) == :clean
    g = Guard.acquire!(dir, name: "canonical")
    assert File.exists?(Guard.lock_path(dir))
    assert {:dirty, %{status: :open, store: "canonical"}} = Guard.inspect_lock(dir)
    assert :ok == Guard.check!(g)
    refute Guard.faulted?(g)
    refute Guard.clean_close_ready?(g)

    :ok = Guard.mark_clean_close!(g)
    assert Guard.clean_close_ready?(g)
    assert :ok == Guard.release_clean!(g)
    refute File.exists?(Guard.lock_path(dir))
    assert Guard.inspect_lock(dir) == :clean

    # Reopen succeeds cleanly.
    g2 = Guard.acquire!(dir, name: "canonical", require_clean_mark: false)
    assert :ok == Guard.release_clean!(g2)
  end

  test "dirty flush.lock refuses acquire! before opening store", %{tmp_dir: dir} do
    g = Guard.acquire!(dir, name: "canonical")
    # Simulate crash: abandon without releasing flush.lock.
    Guard.abandon(g)
    assert File.exists?(Guard.lock_path(dir))

    assert_raise Exnode.StorageError, ~r/did not close cleanly/, fn ->
      Guard.acquire!(dir, name: "canonical")
    end

    # flush.lock stays intact until explicit restore removes it.
    assert File.exists?(Guard.lock_path(dir))
    :ok = Guard.remove_lock_for_restore!(dir)
    assert Guard.inspect_lock(dir) == :clean
  end

  test "release_clean! keeps flush.lock if primary writer did not mark clean close", %{
    tmp_dir: dir
  } do
    g = Guard.acquire!(dir, name: "canonical")

    log =
      capture_log(fn ->
        assert {:kept, :unclean} == Guard.release_clean!(g)
      end)

    assert log =~ "did not complete clean close"
    assert File.exists?(Guard.lock_path(dir))
    assert {:dirty, %{status: :open}} = Guard.inspect_lock(dir)
  end

  test "first storage fault latches permanently, fires callback once, persists into flush.lock, and blocks release",
       %{tmp_dir: dir} do
    me = self()
    g = Guard.acquire!(dir, name: "canonical", on_fault: &send(me, {:faulted, &1}))
    Guard.mark_clean_close!(g)

    log =
      capture_log(fn ->
        Guard.latch_fault(g, :segments, {:eio, 0}, "disk read error")
        # Second fault must not overwrite the first or re-trigger on_fault.
        Guard.latch_fault(g, :kv, :corruption, "secondary cascading error")
      end)

    assert log =~ "STORAGE FAULT LATCHED"
    assert_received {:faulted, %{source: :segments, message: "disk read error"}}
    refute_received {:faulted, _}

    assert Guard.faulted?(g)
    assert %{source: :segments, message: "disk read error"} = Guard.fault_info(g)
    refute Guard.clean_close_ready?(g)

    # Subsequent mark_clean_close! cannot clear a latched fault.
    Guard.mark_clean_close!(g)
    refute Guard.clean_close_ready?(g)

    # Every subsequent check! raises StorageError.
    assert_raise Exnode.StorageError, ~r/halted after latched storage fault/, fn ->
      Guard.check!(g)
    end

    # release_clean! refuses to delete flush.lock.
    capture_log(fn ->
      assert {:kept, :faulted} == Guard.release_clean!(g)
    end)

    assert {:faulted, %{source: :segments, message: "disk read error"}} = Guard.inspect_lock(dir)

    # Reopen fails loudly with faulted_store.
    assert_raise Exnode.StorageError, ~r/halted after a storage fault/, fn ->
      Guard.acquire!(dir, name: "canonical")
    end
  end

  test "corrupt flush.lock refuses acquire!", %{tmp_dir: dir} do
    File.write!(Guard.lock_path(dir), "garbage")
    assert {:corrupt_lock, :truncated} == Guard.inspect_lock(dir)

    assert_raise Exnode.StorageError, ~r/unreadable\/corrupt/, fn ->
      Guard.acquire!(dir, name: "canonical")
    end
  end

  test "StorageError.raise_and_latch! latches guard and raises", %{tmp_dir: dir} do
    g = Guard.acquire!(dir, name: "canonical")

    capture_log(fn ->
      assert_raise Exnode.StorageError, ~r/boom/, fn ->
        Exnode.StorageError.raise_and_latch!(g, :archive, :bad_checksum, "boom")
      end
    end)

    assert Guard.faulted?(g)
    assert %{source: :archive, reason: :bad_checksum} = Guard.fault_info(g)
    Guard.abandon(g)
  end
end
