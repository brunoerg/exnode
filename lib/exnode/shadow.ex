defmodule Exnode.Shadow do
  @moduledoc """
  Shadow validator: Core v32.1's own validation engine (libbitcoinkernel
  chainstate manager) in a separate OS process, driven through a Port.

  exnode feeds it every block it connects or rejects and compares verdicts.
  A crash of the shadow process cannot take the VM down. The GenServer exits,
  and its supervisor decides what to do.

  Wire protocol: see `native/shadow_validator/shadow_validator.c`.
  """
  use GenServer

  # bitcoinkernel.h btck_ValidationMode / btck_BlockValidationResult (v32.1)
  @modes %{0 => :valid, 1 => :invalid, 2 => :internal_error}
  @results %{
    0 => :unset,
    1 => :consensus,
    2 => :cached_invalid,
    3 => :invalid_header,
    4 => :mutated,
    5 => :missing_prev,
    6 => :invalid_prev,
    7 => :time_future,
    8 => :header_low_work
  }

  @chains ~w(mainnet testnet testnet4 signet regtest)a

  defmodule Verdict do
    @moduledoc """
    Result of one `process_block` call.

    * `events`: one `{block_hash, mode, result}` per `block_checked` callback
      fired during the call, in order. This may include blocks other than the
      submitted one, such as stored blocks connected during a reorg.
    * `tip`: `{height, hash}` of the active chain after the call.
    """
    defstruct [:rc, :new_block, :events, :tip]
  end

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "Submits a serialized block. Returns `{:ok, %Verdict{}}` or `{:error, reason}`."
  def process_block(server, raw_block, timeout \\ :timer.minutes(5)) when is_binary(raw_block),
    do: GenServer.call(server, {:req, <<1, raw_block::binary>>}, timeout)

  def tip(server), do: GenServer.call(server, {:req, <<2>>})

  def stop(server), do: GenServer.stop(server)

  @impl true
  def init(opts) do
    chain = Keyword.fetch!(opts, :chain)
    unless chain in @chains, do: raise(ArgumentError, "unknown chain #{inspect(chain)}")
    datadir = Keyword.fetch!(opts, :datadir)
    File.mkdir_p!(datadir)

    exe =
      Keyword.get_lazy(opts, :executable, fn ->
        Path.join(:code.priv_dir(:exnode), "native/shadow_validator")
      end)

    port =
      Port.open({:spawn_executable, exe}, [
        :binary,
        {:packet, 4},
        :exit_status,
        :use_stdio,
        args: [Atom.to_string(chain), datadir]
      ])

    {:os_pid, os_pid} = Port.info(port, :os_pid)
    Process.flag(:trap_exit, true)
    {:ok, %{port: port, os_pid: os_pid, pending: :queue.new()}}
  end

  # Closing the port gives the shadow EOF on stdin and it shuts down cleanly.
  # Wait for the OS process to exit, so its datadir lock is released before
  # anyone reopens it.
  @impl true
  def terminate(_reason, %{port: port, os_pid: os_pid}) do
    try do
      Port.close(port)
    rescue
      ArgumentError -> :ok
    end

    # Core flushes its caches on exit (up to the 450 MiB dbcache): allow 2 min.
    wait_exit(os_pid, 2400)
  end

  defp wait_exit(_pid, 0), do: :timeout

  defp wait_exit(pid, n) do
    case System.cmd("kill", ["-0", "#{pid}"], stderr_to_stdout: true) do
      {_, 0} -> Process.sleep(50) && wait_exit(pid, n - 1)
      _ -> :ok
    end
  end

  @impl true
  def handle_call({:req, payload}, from, %{port: port, pending: q} = st) do
    Port.command(port, payload)
    {:noreply, %{st | pending: :queue.in({from, payload}, q)}}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port, pending: q} = st) do
    {{:value, {from, <<op, _::binary>>}}, q} = :queue.out(q)
    GenServer.reply(from, decode(op, data))
    {:noreply, %{st | pending: q}}
  end

  def handle_info({:EXIT, port, _reason}, %{port: port} = st), do: {:noreply, st}
  # Owner exited: shut down (terminate/2 waits for the OS process).
  def handle_info({:EXIT, _owner, reason}, st), do: {:stop, reason, st}

  def handle_info({port, {:exit_status, status}}, %{port: port} = st) do
    {:stop, {:shadow_exited, status}, st}
  end

  defp decode(1, <<0, rc, new_block, n::32, rest::binary>>) do
    {events, <<tip::binary-size(36)>>} = take_events(n, rest, [])
    {:ok, %Verdict{rc: rc, new_block: new_block == 1, events: events, tip: decode_tip(tip)}}
  end

  defp decode(2, <<0, tip::binary-size(36)>>), do: {:ok, decode_tip(tip)}
  @port_errors ~w(bad_block_encoding unknown_op)
  defp decode(_, <<1, reason::binary>>) when reason in @port_errors,
    do: {:error, String.to_atom(reason)}

  defp decode(_, <<1, reason::binary>>), do: {:error, {:shadow, reason}}

  defp take_events(0, rest, acc), do: {Enum.reverse(acc), rest}

  defp take_events(n, <<hash::binary-size(32), mode, result::32, rest::binary>>, acc),
    do:
      take_events(n - 1, rest, [
        {hash, Map.get(@modes, mode, mode), Map.get(@results, result, result)} | acc
      ])

  defp decode_tip(<<height::signed-32, hash::binary-size(32)>>), do: {height, hash}
end
