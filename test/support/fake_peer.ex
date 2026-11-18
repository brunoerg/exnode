defmodule Exnode.Test.FakePeer do
  @moduledoc """
  Test helper: a v1 P2P peer driven by the test over a plain TCP socket.

  * `connect_from/2`: the node dials us. A manual `Peer` is started under the
    node's peer supervisor towards a socket the test listens on.
  * `dial/2`: we dial the node's listener (an inbound peer for the node).
  * `version/1`, `send_msgs/3`, `recv/4`: the messages themselves.

  Sockets are passive (`active: false`) and owned by the calling process.
  """
  import Bitwise

  alias Exnode.P2P.{Frame, Message, Peer}

  @regtest_magic Exnode.ChainParams.get(:regtest).magic

  @doc """
  A `version` message from the fake peer; `overrides` replaces any field.
  Defaults: protocol 70017, services 9 (NETWORK | WITNESS), relay false, a
  random nonce.
  """
  def version(overrides \\ %{}) do
    Map.merge(
      %{
        version: 70017,
        services: 9,
        time: System.os_time(:second),
        addr_recv: %{services: 0, net: :ipv4, addr: <<127, 0, 0, 1>>, port: 0},
        nonce: :rand.uniform(1 <<< 60),
        user_agent: "/fake/",
        start_height: 0,
        relay: false
      },
      Map.new(overrides)
    )
  end

  @doc """
  The node dials a socket the test listens on: a manual `Peer` under
  `n.peer_sup` (`n` from `Exnode.Node.names/1`). Returns `{peer_pid, socket}`.

  Options:
  * `:node`: fields merged into the peer's node map. The defaults are
    params, headers, sync and chain_state from `n`, no address book, nonce
    1, services 9, user agent "/t/". Anything else (tx_relay, mempool,
    a clock...) is added here.
  * `:params`: chain params (default regtest).
  * `:conn_type`: the peer's connection type (default
    `:outbound_full_relay`), e.g. `:block_relay` or `:manual` (never
    disconnected for misbehaving, as in Core).
  * `:handshake`: `false` sends nothing; by default version and verack are
    sent, built by `version/1` from `:version`.
  * `:after_handshake`: extra messages sent with the handshake (one write).
  * `:monitor`: `true` monitors the peer as soon as it is started, before
    the connection is accepted, and returns `{pid, socket, monitor_ref}`:
    an exit at any point then arrives with its reason (a monitor taken
    after this returns sees an early exit only as `:noproc`).
  """
  def connect_from(n, opts \\ []) do
    params = Keyword.get(opts, :params, Exnode.ChainParams.get(:regtest))
    {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(lsock)

    node =
      Map.merge(
        %{
          params: params,
          headers: n.headers,
          addrman: nil,
          sync: n.sync,
          chain_state: n.chain_state,
          block_serving: n[:block_serving],
          decode_budget: n[:decode_budget],
          nonce: 1,
          services: 9,
          user_agent: "/t/"
        },
        Map.new(Keyword.get(opts, :node, %{}))
      )

    {:ok, pid} =
      DynamicSupervisor.start_child(
        n.peer_sup,
        {Peer,
         %{
           node: node,
           conn_type: Keyword.get(opts, :conn_type, :outbound_full_relay),
           connect: {"127.0.0.1", port}
         }}
      )

    ref = if Keyword.get(opts, :monitor, false), do: Process.monitor(pid)
    {:ok, sock} = :gen_tcp.accept(lsock, 5_000)
    :gen_tcp.close(lsock)

    if Keyword.get(opts, :handshake, true) do
      msgs = [{:version, version(Keyword.get(opts, :version, %{}))}, :verack]
      :ok = send_msgs(sock, msgs ++ Keyword.get(opts, :after_handshake, []), params.magic)
    end

    if ref, do: {pid, sock, ref}, else: {pid, sock}
  end

  @doc """
  Dials the node's listener on `port`. By default sends version (from
  `:version`) and verack; a send failing because the node closed the
  connection is not an error (see `recv/4`). Returns the socket.
  """
  def dial(port, opts \\ []) do
    magic = Keyword.get(opts, :magic, @regtest_magic)
    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)

    if Keyword.get(opts, :handshake, true) do
      _ = send_msgs(sock, [{:version, version(Keyword.get(opts, :version, %{}))}], magic)
      _ = send_msgs(sock, [:verack], magic)
    end

    sock
  end

  @doc "Encodes `msgs` (one message or a list) and sends them in one write. Returns the send result."
  def send_msgs(sock, msgs, magic \\ @regtest_magic) do
    bin =
      for m <- List.wrap(msgs), into: <<>> do
        {c, pl} = Message.encode(m)
        IO.iodata_to_binary(Frame.encode(magic, c, pl))
      end

    :gen_tcp.send(sock, bin)
  end

  @doc """
  Reads until `count` messages whose command is in `wanted` have arrived;
  returns them in order as `{command, payload}` (other commands are
  skipped). Fails on a closed socket or after `:timeout` ms without data
  (default 10 s). `:magic` defaults to regtest's.
  """
  def recv(sock, wanted, count, opts \\ []) do
    magic = Keyword.get(opts, :magic, @regtest_magic)
    timeout = Keyword.get(opts, :timeout, 10_000)
    read(sock, List.wrap(wanted), count, magic, timeout, <<>>, [])
  end

  defp read(_sock, _wanted, count, _magic, _timeout, _buf, acc) when length(acc) >= count,
    do: Enum.reverse(acc)

  defp read(sock, wanted, count, magic, timeout, buf, acc) do
    case Frame.decode(magic, buf) do
      {:ok, cmd, payload, rest} ->
        acc = if cmd in wanted, do: [{cmd, payload} | acc], else: acc
        read(sock, wanted, count, magic, timeout, rest, acc)

      _ ->
        case :gen_tcp.recv(sock, 0, timeout) do
          {:ok, data} ->
            read(sock, wanted, count, magic, timeout, buf <> data, acc)

          {:error, reason} ->
            ExUnit.Assertions.flunk(
              "recv #{inspect(wanted)}: #{inspect(reason)} after #{length(acc)} of #{count}"
            )
        end
    end
  end
end
