defmodule Exnode.P2P.Peer.Writer do
  @moduledoc """
  Per-peer socket writer process, started via `:proc_lib.start_link/3`.

  Owns blocking `:gen_tcp.send/2` calls so a slow peer never blocks the
  `Peer` process from reading, answering `Peer.info/1`, or running timeouts.
  Coalesces queued writes up to `@writer_batch` bytes per socket send and
  notifies the peer with `{:sent, n}` or `{:send_failed, reason}`.
  """

  # Bytes the writer coalesces into one socket send.
  @writer_batch 256 * 1024

  @doc "Starts a linked `:proc_lib` writer for `sock`."
  def start_link(sock, send_fun \\ &:gen_tcp.send/2) do
    :proc_lib.start_link(__MODULE__, :init_writer, [self(), sock, send_fun])
  end

  @doc "Queues `iodata` for writing on `writer`."
  def write(writer, iodata) when is_pid(writer) do
    send(writer, {:write, iodata})
    :ok
  end

  @doc """
  Waits for `writer` to finish all writes queued ahead of this call, up to
  `timeout_ms`. Returns immediately if `writer` is already dead or exits
  while flushing (avoids hanging `Peer.terminate/2` on a dead writer).
  """
  def flush(writer, timeout_ms \\ 500)
  def flush(nil, _timeout_ms), do: :ok

  def flush(writer, timeout_ms) when is_pid(writer) do
    if Process.alive?(writer) do
      mref = Process.monitor(writer)
      send(writer, {:flush, self(), mref})

      receive do
        {:flushed, ^mref} ->
          Process.demonitor(mref, [:flush])
          :ok

        {:DOWN, ^mref, :process, ^writer, _reason} ->
          :ok
      after
        timeout_ms ->
          Process.demonitor(mref, [:flush])
          :ok
      end
    else
      :ok
    end
  end

  @doc false
  def init_writer(peer, sock, send_fun) do
    :proc_lib.init_ack(peer, {:ok, self()})
    ref = Process.monitor(peer)
    loop(sock, send_fun, peer, ref)
  end

  defp loop(sock, send_fun, peer, ref) do
    receive do
      {:write, data} ->
        {data, n} = collect([data], IO.iodata_length(data))

        case send_fun.(sock, data) do
          :ok ->
            send(peer, {:sent, n})
            loop(sock, send_fun, peer, ref)

          {:error, reason} ->
            send(peer, {:send_failed, reason})
        end

      {:flush, from, flush_ref} ->
        send(from, {:flushed, flush_ref})
        loop(sock, send_fun, peer, ref)

      {:flush, from} ->
        send(from, :flushed)
        loop(sock, send_fun, peer, ref)

      {:DOWN, ^ref, :process, _, _} ->
        :ok
    end
  end

  defp collect(acc, n) when n >= @writer_batch, do: {Enum.reverse(acc), n}

  defp collect(acc, n) do
    receive do
      {:write, data} -> collect([data | acc], n + IO.iodata_length(data))
    after
      0 -> {Enum.reverse(acc), n}
    end
  end
end
