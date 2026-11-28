defmodule Exnode.P2P.Peer.Conn do
  @moduledoc """
  TCP transport, v1 `FrameBuffer` framing, BIP324 `V2.Transport` handshake &
  v1 fallback, `Peer.Writer` lifecycle, and `-maxsendbuffer` send-buffer
  accounting for a single `Exnode.P2P.Peer`.

  Isolating transport concerns in this module keeps `Exnode.P2P.Peer` focused
  on Bitcoin protocol state transitions while preserving synchronous
  backpressure checks (`paused?/1`) during `getdata` serving.
  """

  alias Exnode.P2P.{Frame, FrameBuffer}
  alias Exnode.P2P.Peer.Writer
  alias Exnode.P2P.V2.Transport

  # A send blocked this long (peer not reading) fails and closes the socket,
  # so the writer cannot hang; Core's send-side TIMEOUT_INTERVAL.
  @default_send_timeout_ms 20 * 60 * 1000
  # net.h DEFAULT_MAXSENDBUFFER (1000) * 1000 bytes, Core -maxsendbuffer.
  @default_max_send_buffer 1_000 * 1_000

  defstruct [
    :magic,
    :inbound,
    :v2,
    :socket,
    :writer,
    :send_fun,
    :send_timeout_ms,
    :max_send_buffer,
    transport: :v1,
    buf: FrameBuffer.new(),
    pending_msgs: [],
    send_queued: 0,
    paused_since: nil,
    bytes_sent: 0,
    bytes_recv: 0,
    last_send: nil,
    last_recv: nil
  ]

  @type t :: %__MODULE__{}

  @doc "Constructs a disconnected transport struct from peer options."
  def new(opts) do
    %__MODULE__{
      magic: Keyword.fetch!(opts, :magic),
      inbound: Keyword.fetch!(opts, :inbound),
      v2: Keyword.get(opts, :v2, false),
      send_fun: Keyword.get(opts, :send_fun, &:gen_tcp.send/2),
      send_timeout_ms: Keyword.get(opts, :send_timeout_ms, @default_send_timeout_ms),
      max_send_buffer: Keyword.get(opts, :max_send_buffer, @default_max_send_buffer)
    }
  end

  @doc "Dials `{host, port}` (outbound), starts the writer and BIP324 session if enabled."
  def connect(%__MODULE__{} = conn, {host, port}, now) do
    # IP literals are parsed to tuples. IPv6 needs the :inet6 option, otherwise
    # gen_tcp treats the literal as a hostname (nxdomain).
    {addr, family} =
      case :inet.parse_address(to_charlist(host)) do
        {:ok, ip} when tuple_size(ip) == 8 -> {ip, [:inet6]}
        {:ok, ip} -> {ip, []}
        {:error, _} -> {to_charlist(host), []}
      end

    opts = family ++ [:binary, active: :once, packet: :raw, nodelay: true] ++ send_opts(conn)

    case dial(addr, port, opts) do
      {:ok, sock} -> {:ok, start_session(%{conn | socket: sock}, now)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Attaches an accepted inbound socket, sets options, starts writer and v2 detection."
  def attach(%__MODULE__{} = conn, sock, now) do
    :ok = :inet.setopts(sock, [active: :once] ++ send_opts(conn))
    start_session(%{conn | socket: sock}, now)
  end

  @doc "Encodes `{cmd, payload}` for v1 or v2 and queues the bytes on the writer."
  def send_msg(%__MODULE__{transport: %Transport{} = t} = conn, cmd, payload, now) do
    {t, out} = Transport.send_message(t, cmd, payload)
    send_bytes(%{conn | transport: t}, out, now)
  end

  def send_msg(%__MODULE__{transport: :v1} = conn, cmd, payload, now) do
    send_bytes(conn, Frame.encode(conn.magic, cmd, payload), now)
  end

  @doc "Queues raw iodata on the writer and updates send-buffer accounting."
  def send_bytes(%__MODULE__{} = conn, bytes, now) do
    case IO.iodata_length(bytes) do
      0 ->
        conn

      n ->
        Writer.write(conn.writer, bytes)
        queued = conn.send_queued + n

        if queued > conn.max_send_buffer and conn.paused_since == nil,
          do: %{conn | send_queued: queued, paused_since: now},
          else: %{conn | send_queued: queued}
    end
  end

  @doc """
  Applies `{:sent, n}` from the writer. Returns `{resumed?, conn}` where
  `resumed?` is true when `send_queued` just dropped back to or below
  `max_send_buffer`.
  """
  def on_sent(%__MODULE__{} = conn, n, now) do
    queued = conn.send_queued - n

    conn = %{
      conn
      | bytes_sent: conn.bytes_sent + n,
        last_send: now,
        send_queued: queued
    }

    if conn.paused_since != nil and queued <= conn.max_send_buffer do
      {true, %{conn | paused_since: nil}}
    else
      {false, conn}
    end
  end

  @doc """
  Processes incoming TCP bytes. Returns:
  * `{:v1, conn}` — v1 stream ready to pull frames via `next_v1_frame/1`;
  * `{:v2, conn, msgs}` — v2 decoded messages (`{:msg, cmd, payload}` or `:reject`);
  * `{:error, {:v2_error, reason}}` — v2 transport failure.
  """
  def on_tcp(%__MODULE__{} = conn, data, now) do
    conn = %{conn | bytes_recv: conn.bytes_recv + byte_size(data), last_recv: now}

    case conn.transport do
      :v1 ->
        {:v1, %{conn | buf: FrameBuffer.append(conn.buf, data)}}

      %Transport{} = t ->
        case Transport.received(t, data) do
          {:ok, t, out, msgs} ->
            conn = %{conn | transport: t} |> send_bytes(out, now)
            {:v2, conn, msgs}

          {:v1, bytes} ->
            conn = %{conn | transport: :v1, buf: FrameBuffer.from_binary(bytes)}

            conn =
              Enum.reduce(Transport.queued(t), conn, fn {cmd, p}, acc ->
                send_bytes(acc, Frame.encode(acc.magic, cmd, p), now)
              end)

            {:v1, conn}

          {:error, reason} ->
            {:error, {:v2_error, reason}}
        end
    end
  end

  @doc "Extracts the next v1 frame from the receive buffer."
  def next_v1_frame(%__MODULE__{buf: buf, magic: magic} = conn) do
    case FrameBuffer.next(buf, magic) do
      {:more, buf} -> {:more, %{conn | buf: buf}}
      {:error, reason} -> {:error, reason}
      {:reject, cmd, buf} -> {:reject, cmd, %{conn | buf: buf}}
      {:ok, cmd, payload, buf} -> {:ok, cmd, payload, %{conn | buf: buf}}
    end
  end

  @doc "Appends deferred v2 messages while blocked."
  def append_pending(%__MODULE__{} = conn, msgs),
    do: %{conn | pending_msgs: conn.pending_msgs ++ msgs}

  @doc "Takes all deferred v2 messages, returning `{msgs, conn}`."
  def take_pending(%__MODULE__{pending_msgs: msgs} = conn),
    do: {msgs, %{conn | pending_msgs: []}}

  @doc "Rearms `active: :once` on the socket when connected."
  def rearm(%__MODULE__{socket: nil}), do: :ok
  def rearm(%__MODULE__{socket: sock}), do: :inet.setopts(sock, active: :once)

  @doc "Whether outbound send buffer is currently over `max_send_buffer`."
  def paused?(%__MODULE__{paused_since: p}), do: p != nil

  @doc "Whether a socket is attached."
  def connected?(%__MODULE__{socket: s}), do: s != nil

  @doc "Whether the transport is currently in v1 mode."
  def v1?(%__MODULE__{transport: t}), do: t == :v1

  @doc "Transport type string for `Peer.info/1` (`\"v1\"`, `\"v2\"`, or `\"detecting\"`)."
  def transport_type(%__MODULE__{transport: :v1}), do: "v1"

  def transport_type(%__MODULE__{transport: %Transport{} = t}),
    do: if(Transport.established?(t), do: "v2", else: "detecting")

  @doc "BIP324 session id once established, or `nil`."
  def session_id(%__MODULE__{transport: %Transport{} = t}), do: Transport.session_id(t)
  def session_id(_), do: nil

  @doc "Core `ShouldReconnectV1` check on close."
  def should_reconnect_v1?(%__MODULE__{transport: %Transport{} = t}),
    do: Transport.should_reconnect_v1?(t)

  def should_reconnect_v1?(_), do: false

  @doc "Core send/receive/send-buffer inactivity checks."
  def inactivity_reason(
        %__MODULE__{} = conn,
        connected_at,
        now,
        handshake_timeout_s,
        timeout_interval_s
      ) do
    cond do
      connected_at == nil or now - connected_at <= handshake_timeout_s ->
        nil

      conn.last_send == nil or conn.last_recv == nil ->
        :no_message_in_connect_timeout

      now > conn.last_send + timeout_interval_s ->
        :send_timeout

      now > conn.last_recv + timeout_interval_s ->
        :receive_timeout

      conn.paused_since != nil and now > conn.paused_since + timeout_interval_s ->
        :send_buffer_full

      true ->
        nil
    end
  end

  @doc """
  Flushes queued outbound writes when terminating cleanly with a live writer
  and socket. Skips flushing immediately if the socket or writer already failed.
  """
  def flush_on_terminate(%__MODULE__{writer: nil}, _reason, _timeout_ms), do: :ok
  def flush_on_terminate(%__MODULE__{send_queued: q}, _reason, _timeout_ms) when q <= 0, do: :ok

  def flush_on_terminate(%__MODULE__{writer: writer}, reason, timeout_ms) do
    if skip_flush?(reason) do
      :ok
    else
      Writer.flush(writer, timeout_ms)
    end
  end

  def flush_on_terminate(conn, reason), do: flush_on_terminate(conn, reason, 500)

  # --- internal helpers -------------------------------------------------------

  defp skip_flush?({:shutdown, {:send_failed, _}}), do: true
  defp skip_flush?({:shutdown, {:tcp_error, _}}), do: true
  defp skip_flush?({:shutdown, {:closed, _}}), do: true
  defp skip_flush?({:shutdown, {:reconnect_v1, _}}), do: true
  defp skip_flush?({:shutdown, :send_buffer_full}), do: true
  defp skip_flush?({:shutdown, :send_timeout}), do: true
  defp skip_flush?(_), do: false

  defp dial(host, port, opts) do
    :gen_tcp.connect(host, port, opts, 5_000)
  catch
    :exit, :badarg -> {:error, :einval}
  end

  defp send_opts(%__MODULE__{send_timeout_ms: ms}),
    do: [send_timeout: ms, send_timeout_close: true]

  defp start_session(%__MODULE__{} = conn, now) do
    {:ok, writer} = Writer.start_link(conn.socket, conn.send_fun)
    conn = %{conn | writer: writer}

    if conn.v2 do
      {t, out} = Transport.new(not conn.inbound, conn.magic)
      send_bytes(%{conn | transport: t}, out, now)
    else
      conn
    end
  end
end
