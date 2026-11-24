defmodule Exnode.CLITest do
  use ExUnit.Case, async: true

  alias Exnode.Store.KV

  @moduletag :tmp_dir

  defp run_cli(fun_expr) do
    erl = System.find_executable("erl")
    pa = Enum.flat_map(:code.get_path(), &["-pa", List.to_string(&1)])

    eval =
      "#{fun_expr}, init:stop(0)."

    System.cmd(erl, ["-noshell" | pa] ++ ["-eval", eval], stderr_to_stdout: true)
  end

  test "reconsider rejects an unknown --chain and a missing store without creating directories",
       %{
         tmp_dir: dir
       } do
    {out, code} =
      run_cli(
        ~s|'Elixir.Exnode.CLI':reconsider([<<"--chain">>, <<"notachain">>, <<"--datadir">>, <<"#{dir}">>])|
      )

    assert code == 1
    assert out =~ "unknown chain notachain"
    refute File.exists?(Path.join(dir, "notachain"))

    {out2, code2} =
      run_cli(
        ~s|'Elixir.Exnode.CLI':reconsider([<<"--chain">>, <<"regtest">>, <<"--datadir">>, <<"#{dir}">>])|
      )

    assert code2 == 1
    assert out2 =~ "cannot open store"
    refute File.exists?(Path.join([dir, "regtest", "index"]))
  end

  test "reconsider rejects malformed hex arguments and closes the store cleanly", %{tmp_dir: dir} do
    idx_dir = Path.join([dir, "regtest", "index"])
    {:ok, kv} = KV.open(idx_dir)
    KV.close(kv)

    {out, code} =
      run_cli(
        ~s|'Elixir.Exnode.CLI':reconsider([<<"--chain">>, <<"regtest">>, <<"--datadir">>, <<"#{dir}">>, <<"not-hex">>])|
      )

    assert code == 1
    assert out =~ "invalid block hash"

    # In-process reconsider closes KV on return so the store can be reopened immediately.
    ExUnit.CaptureIO.capture_io(fn ->
      Exnode.CLI.reconsider(["--chain", "regtest", "--datadir", dir])
    end)

    {:ok, kv2} = KV.open(idx_dir, lock_wait_ms: 0)
    KV.close(kv2)
  end

  test "node rejects malformed --connect while accepting IPv4, bracketed IPv6, and default ports",
       %{tmp_dir: dir} do
    {out, code} =
      run_cli(
        ~s|'Elixir.Exnode.CLI':node([<<"--chain">>, <<"regtest">>, <<"--datadir">>, <<"#{dir}">>, <<"--connect">>, <<"2001:db8::1:8333">>])|
      )

    assert code == 1
    assert out =~ "invalid --connect address"

    # Valid IPv6 bracketed + host-without-port pass --connect parsing and reach the FD budget check.
    {out2, code2} =
      run_cli(
        ~s|'Elixir.Exnode.CLI':node([<<"--chain">>, <<"regtest">>, <<"--datadir">>, <<"#{dir}">>, <<"--connect">>, <<"[::1]:18444">>, <<"--connect">>, <<"127.0.0.1">>, <<"--max-connections">>, <<"999999">>])|
      )

    assert code2 == 1
    assert out2 =~ "not enough file descriptors"
  end
end
