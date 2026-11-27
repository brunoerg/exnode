defmodule Exnode.P2P.Listener do
  @moduledoc """
  Accepts inbound connections and starts one `Peer` per socket under the
  peer supervisor, subject to `Connman.accept_inbound?/3`.

  The listening socket is bound in `init/1`, so a bind failure fails the
  start and `port/1` answers as soon as the node is up; `port: 0` binds an
  ephemeral port (tests). A linked `:proc_lib` acceptor process runs the
  accept loop (any process may accept on a listening socket); either one
  exiting takes the other down, and the supervisor restarts the pair.

  Calls into `Connman` (`accept_inbound?/3` and `register_inbound/4`) are
  bounded by `@connman_timeout_ms` (default 5 s) so a stalled `Connman`
  cannot wedge the accept loop indefinitely; timed-out or unregistered
  connections are closed cleanly.

  An accept error does not end the loop (Core AcceptConnection logs "socket
  error accept failed" and goes on): under fd exhaustion (`:emfile`,
  `:enfile`, `:system_limit`) a crash per error would exhaust the restart
  intensity and take the P2P subtree, then the node, down.
  The loop backs off briefly instead; only `:closed` ends it.
  """
  use GenServer, restart: :permanent
  require Logger

  alias Exnode.P2P.{Connman, Peer}

  # Core Listen(SOMAXCONN); the kernel caps it at net.core.somaxconn.
  @backlog 4096
  # Pause after an accept error, so fd exhaustion is not a busy loop.
  @accept_backoff_ms 100
  # Bound Connman handoff calls so a slow Connman cannot wedge the acceptor.
  @connman_timeout_ms 5_000

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "The port actually bound (the configured one, or the ephemeral one for `port: 0`)."
  def port(server), do: GenServer.call(server, :port, 5_000)

  @impl true
  def init(opts) do
    port = Keyword.fetch!(opts, :port)
    ip = Keyword.get(opts, :ip, {0, 0, 0, 0})

    {:ok, lsock} =
      :gen_tcp.listen(port, [
        :binary,
        active: false,
        packet: :raw,
        reuseaddr: true,
        ip: ip,
        nodelay: true,
        backlog: @backlog
      ])

    {:ok, bound} = :inet.port(lsock)
    Logger.info("listening for peers on port #{bound}")
    {:ok, acceptor} = :proc_lib.start_link(__MODULE__, :init_acceptor, [self(), lsock, opts])
    {:ok, %{lsock: lsock, port: bound, acceptor: acceptor}}
  end

  @impl true
  def handle_call(:port, _from, st), do: {:reply, st.port, st}

  @doc false
  def init_acceptor(parent, lsock, opts) do
    :proc_lib.init_ack(parent, {:ok, self()})
    loop(lsock, opts)
  end

  defp loop(lsock, opts) do
    accept = Keyword.get(opts, :accept, &:gen_tcp.accept/1)

    case accept.(lsock) do
      {:ok, sock} ->
        handle_accepted(sock, opts)
        loop(lsock, opts)

      {:error, :closed} ->
        exit(:normal)

      {:error, reason} ->
        Logger.warning("socket error accept failed: #{inspect(reason)}")
        Process.sleep(@accept_backoff_ms)
        loop(lsock, opts)
    end
  end

  defp handle_accepted(sock, opts) do
    connman = Keyword.fetch!(opts, :connman)
    timeout = Keyword.get(opts, :connman_timeout_ms, @connman_timeout_ms)

    target =
      case :inet.peername(sock) do
        {:ok, {ip, port}} -> {to_string(:inet.ntoa(ip)), port}
        _ -> nil
      end

    if accept_inbound?(connman, target, timeout) do
      node = Map.put(Keyword.fetch!(opts, :node), :connman, connman)
      # Core CreateNodeFromAcceptedSocket: V2Transport whenever we signal
      # NODE_P2P_V2; it falls back to v1 when the peer speaks v1.
      spec =
        {Peer,
         %{
           node: node,
           conn_type: :inbound,
           target: target,
           v2: Exnode.P2P.Connman.local_v2?(node)
         }}

      case DynamicSupervisor.start_child(Keyword.fetch!(opts, :peer_sup), spec) do
        {:ok, pid} ->
          case :gen_tcp.controlling_process(sock, pid) do
            :ok ->
              if registered?(connman, pid, target, timeout) do
                send(pid, {:socket_ready, sock})
              else
                # Connman is restarting or timed out: an untracked peer would
                # escape the inbound limit and eviction. Refuse the connection.
                :gen_tcp.close(sock)
                Process.exit(pid, :kill)
              end

            # The peer already exited, or the socket closed meanwhile.
            {:error, _} ->
              :gen_tcp.close(sock)
              Process.exit(pid, :kill)
          end

        _ ->
          :gen_tcp.close(sock)
      end
    else
      :gen_tcp.close(sock)
    end
  end

  defp accept_inbound?(connman, target, timeout) do
    Connman.accept_inbound?(connman, target, timeout)
  catch
    :exit, {:timeout, _} ->
      Logger.warning("listener: Connman.accept_inbound? timed out after #{timeout} ms")
      false

    :exit, _ ->
      false
  end

  defp registered?(connman, pid, target, timeout) do
    Connman.register_inbound(connman, pid, target, timeout) == :ok
  catch
    :exit, {:timeout, _} ->
      Logger.warning("listener: Connman.register_inbound timed out after #{timeout} ms")
      false

    :exit, _ ->
      false
  end
end
