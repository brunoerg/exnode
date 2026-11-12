defmodule Exnode.P2P.Listener do
  @moduledoc """
  Accepts inbound connections and starts one `Peer` per socket under the
  peer supervisor, subject to `Connman.accept_inbound?/1`.

  The listening socket is bound in `init/1`, so a bind failure fails the
  start and `port/1` answers as soon as the node is up; `port: 0` binds an
  ephemeral port (tests). A linked acceptor process runs the accept loop
  (any process may accept on a listening socket); either one exiting takes
  the other down, and the supervisor restarts the pair.

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
    acceptor = spawn_link(fn -> loop(lsock, opts) end)
    {:ok, %{lsock: lsock, port: bound, acceptor: acceptor}}
  end

  @impl true
  def handle_call(:port, _from, st), do: {:reply, st.port, st}

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

    target =
      case :inet.peername(sock) do
        {:ok, {ip, port}} -> {to_string(:inet.ntoa(ip)), port}
        _ -> nil
      end

    if Connman.accept_inbound?(connman, target) do
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
              if registered?(connman, pid, target) do
                send(pid, {:socket_ready, sock})
              else
                # Connman is restarting: an untracked peer would escape the
                # inbound limit and eviction (P2P-4). Refuse the connection.
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

  defp registered?(connman, pid, target) do
    Connman.register_inbound(connman, pid, target) == :ok
  catch
    :exit, _ -> false
  end
end
