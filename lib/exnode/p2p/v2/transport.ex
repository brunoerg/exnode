defmodule Exnode.P2P.V2.Transport do
  @moduledoc """
  BIP324 v2 transport. Port of Core v32.1 `net.cpp` `V2Transport`.

  Receive states (Core `RecvState`): `:key_maybe_v1` (responder only: the
  first 16 bytes decide between a v1 `version` header and a v2 key), `:key`,
  `:garb_garbterm`, `:version`, `:app`. Core's `APP_READY` is not needed:
  complete messages are returned as they are decoded.
  Send states (Core `SendState`): `:maybe_v1` (responder before it knows),
  `:awaiting_key`, `:ready`.

  * The initiator sends its ElligatorSwift key and 0–4095 random garbage
    bytes at once; the responder sends its own once the first bytes are not
    a v1 prefix (`ProcessReceivedMaybeV1Bytes` / `StartSendingHandshake`).
  * Once the peer's key is in, both send the garbage terminator and the
    version packet (empty contents, our garbage as AAD) and become `:ready`
    (`ProcessReceivedKeyBytes`).
  * Garbage is searched for the terminator up to 4095 + 16 bytes
    (`ProcessReceivedGarbageBytes`); the first packet after it is
    authenticated with the garbage as AAD; decoys (ignore bit) are skipped.
  * Contents: 1-byte short id (`V2_MESSAGE_IDS`) + payload, or 0x00 + the
    12-byte v1 command + payload (`GetMessageType`, `SetMessageToSend`).
  * Messages given before `:ready` are queued and sent in order once ready
    (Core keeps them in the node's send queue until the transport accepts).

  A value is used linearly: it holds OpenSSL stream states (see `Cipher`).
  """

  alias Exnode.Crypto.Secp
  alias Exnode.P2P.V2.Cipher

  @max_garbage_len 4095
  @v1_prefix_len 16
  @ellswift_len 64
  @message_type_size 12
  # 1 (long-type marker) + 12 (message type) + min(MAX_SIZE, MAX_PROTOCOL_MESSAGE_LENGTH)
  @max_contents_len 1 + 12 + 4_000_000
  @v1_header_size 24

  # BIP324 short message ids, in order (Core V2_MESSAGE_IDS; 29..36 unused).
  @short_ids ~w(addr block blocktxn cmpctblock feefilter filteradd filterclear filterload getblocks getblocktxn
                getdata getheaders headers inv mempool merkleblock notfound ping pong sendcmpct tx getcfilters
                cfilter getcfheaders cfheaders getcfcheckpt cfcheckpt addrv2)
  @id_to_type @short_ids
              |> Enum.with_index(1)
              |> Map.new(fn {t, i} -> {i, t} end)
              |> Map.put(37, "feature")
  @type_to_id Map.new(@id_to_type, fn {i, t} -> {t, i} end)

  def max_garbage_len, do: @max_garbage_len

  defstruct [
    :initiating,
    :magic,
    :sk,
    :ours,
    :garbage,
    :cipher,
    :recv_state,
    :send_state,
    :recv_len,
    buf: <<>>,
    tail: <<>>,
    tail_bytes: 0,
    aad: <<>>,
    queue: [],
    sent: 0
  ]

  @doc """
  A new transport: `{transport, bytes_to_send}`. Options (tests):
  `key: {sk, ellswift}`, `garbage: binary`.
  """
  def new(initiating, magic, opts \\ []) do
    {sk, ours} = Keyword.get_lazy(opts, :key, &Secp.new_ellswift_key/0)

    garbage =
      Keyword.get_lazy(opts, :garbage, fn ->
        :crypto.strong_rand_bytes(:rand.uniform(@max_garbage_len + 1) - 1)
      end)

    true = byte_size(garbage) <= @max_garbage_len

    t = %__MODULE__{
      initiating: initiating,
      magic: magic,
      sk: sk,
      ours: ours,
      garbage: garbage,
      recv_state: if(initiating, do: :key, else: :key_maybe_v1),
      send_state: if(initiating, do: :awaiting_key, else: :maybe_v1)
    }

    if initiating, do: sent(t, ours <> garbage), else: {t, <<>>}
  end

  @doc """
  Feeds received bytes. Returns `{:ok, t, out, msgs}` (`out`: bytes to send;
  `msgs`: `{:msg, command, payload}` or `:reject` for an undecodable message
  type, in order), `{:v1, bytes}` when a responder sees a v1 `version`
  header (hand all `bytes` to the v1 framing), or `{:error, reason}`
  (disconnect).
  """
  def received(%__MODULE__{} = t, data) do
    # Linear buffering: new bytes are appended to the binary `tail`
    # (amortised in-place append, ~1-2 bytes held per byte; an iodata list
    # cost ~48 B per byte for 1-byte segments, AUD-F3) and joined to `buf`
    # only when the current state can make progress (need/1), so a packet
    # costs O(its size) however the stream is split. All checks (v1 prefix,
    # wrong network, garbage limit, packet length) stay in step/3.
    data = IO.iodata_to_binary(data)
    tail = t.tail
    t = %{t | tail: <<tail::binary, data::binary>>, tail_bytes: t.tail_bytes + byte_size(data)}

    if byte_size(t.buf) + t.tail_bytes >= need(t) do
      step(%{t | buf: t.buf <> t.tail, tail: <<>>, tail_bytes: 0}, <<>>, [])
    else
      {:ok, t, <<>>, []}
    end
  end

  # Bytes needed before step/3 can do anything: one in the key, v1-detection
  # and garbage states (bounded by 16, 64 and 4095 + 16 bytes), the length,
  # then the whole packet.
  defp need(%{recv_state: s, recv_len: nil}) when s in [:version, :app], do: 3
  defp need(%{recv_state: s, recv_len: len}) when s in [:version, :app], do: len + 17
  defp need(_), do: 1

  @doc """
  Encodes a message, `{t, out}`. Before the handshake completes it is
  queued and `out` is empty; queued messages go out with the handshake.
  """
  def send_message(%__MODULE__{send_state: :ready} = t, cmd, payload) do
    {t, packet} = encode(t, cmd, payload)
    sent(t, packet)
  end

  def send_message(%__MODULE__{} = t, cmd, payload),
    do: {%{t | queue: [{cmd, payload} | t.queue]}, <<>>}

  @doc "Messages queued before the handshake finished, in order (for a fallback to v1)."
  def queued(%__MODULE__{queue: q}), do: Enum.reverse(q)

  @doc "v2 established: the peer's version packet was authenticated (Core `GetInfo` reports v2 from here)."
  def established?(%__MODULE__{recv_state: s}), do: s == :app

  def session_id(%__MODULE__{cipher: %Cipher{session_id: id}} = t),
    do: if(established?(t), do: id)

  def session_id(_), do: nil

  @doc """
  Core `ShouldReconnectV1`: an outbound v2 attempt that received nothing
  after sending at least a v1 header's worth (24 bytes), so a v1-only peer
  would have dropped it.
  """
  def should_reconnect_v1?(%__MODULE__{} = t),
    do:
      t.initiating and t.recv_state == :key and t.buf == <<>> and t.tail_bytes == 0 and
        t.sent >= @v1_header_size

  # --- receive -------------------------------------------------------------

  defp step(%{recv_state: :key_maybe_v1, buf: buf} = t, out, msgs) do
    prefix = t.magic <> "version" <> <<0, 0, 0, 0, 0>>
    n = min(byte_size(buf), @v1_prefix_len)

    cond do
      binary_part(buf, 0, n) != binary_part(prefix, 0, n) ->
        # Not v1: answer with our key and garbage, keep the bytes as key bytes.
        {t, o} = sent(%{t | recv_state: :key, send_state: :awaiting_key}, t.ours <> t.garbage)
        step(t, out <> o, msgs)

      n == @v1_prefix_len ->
        {:v1, buf}

      true ->
        done(t, out, msgs)
    end
  end

  defp step(%{recv_state: :key, buf: buf} = t, out, msgs) do
    # Core: on a responder, bytes 4..16 matching a v1 version header (with
    # another network's magic, else it would be v1) mean a peer from another network.
    if not t.initiating and byte_size(buf) >= @v1_prefix_len and
         binary_part(buf, 4, 12) == "version" <> <<0, 0, 0, 0, 0>> do
      {:error, :v1_peer_wrong_network}
    else
      case buf do
        <<theirs::binary-size(@ellswift_len), rest::binary>> ->
          c = Cipher.init(t.sk, t.ours, theirs, t.initiating, t.magic)
          {c, version} = Cipher.encrypt(c, <<>>, t.garbage, false)
          t = %{t | cipher: c, sk: nil, recv_state: :garb_garbterm, send_state: :ready, buf: rest}
          {t, o} = sent(t, c.send_garbage_terminator <> version)
          {t, o2} = flush_queue(%{t | garbage: nil})
          step(t, out <> o <> o2, msgs)

        _ ->
          done(t, out, msgs)
      end
    end
  end

  defp step(%{recv_state: :garb_garbterm, buf: buf} = t, out, msgs) do
    term = t.cipher.recv_garbage_terminator
    tl = byte_size(term)
    window = min(byte_size(buf), @max_garbage_len + tl)

    case :binary.match(buf, term, scope: {0, window}) do
      {pos, ^tl} ->
        <<garbage::binary-size(pos), _::binary-size(tl), rest::binary>> = buf
        step(%{t | recv_state: :version, aad: garbage, buf: rest}, out, msgs)

      :nomatch when window == @max_garbage_len + tl ->
        {:error, :missing_garbage_terminator}

      :nomatch ->
        done(t, out, msgs)
    end
  end

  defp step(%{recv_state: s, buf: buf} = t, out, msgs) when s in [:version, :app] do
    ll = Cipher.length_len()

    case {t.recv_len, buf} do
      {nil, <<len3::binary-size(ll), rest::binary>>} ->
        {c, len} = Cipher.decrypt_length(t.cipher, len3)

        if len > @max_contents_len,
          do: {:error, {:packet_too_large, len}},
          else: step(%{t | cipher: c, recv_len: len, buf: rest}, out, msgs)

      {len, _} when is_integer(len) and byte_size(buf) >= len + 17 ->
        <<packet::binary-size(len + 17), rest::binary>> = buf

        case Cipher.decrypt(t.cipher, packet, t.aad) do
          {_c, :error} ->
            {:error, :decryption_failure}

          {c, {:ok, ignore, contents}} ->
            t = %{t | cipher: c, aad: <<>>, recv_len: nil, buf: rest}

            cond do
              ignore -> step(t, out, msgs)
              s == :version -> step(%{t | recv_state: :app}, out, msgs)
              true -> step(t, out, [message(contents) | msgs])
            end
        end

      _ ->
        done(t, out, msgs)
    end
  end

  # A small remainder is copied so it does not keep a large packet's binary alive.
  defp done(t, out, msgs) do
    t = if byte_size(t.buf) < 4096, do: %{t | buf: :binary.copy(t.buf)}, else: t
    {:ok, t, out, Enum.reverse(msgs)}
  end

  # Core GetMessageType.
  defp message(<<0, type::binary-size(@message_type_size), payload::binary>>) do
    [name | pad] = :binary.split(type, <<0>>)
    pad = Enum.join(pad, <<0>>)

    if printable?(name) and pad == :binary.copy(<<0>>, byte_size(pad)),
      do: {:msg, name, payload},
      else: :reject
  end

  defp message(<<id, payload::binary>>) when id != 0 do
    case Map.fetch(@id_to_type, id) do
      {:ok, name} -> {:msg, name, payload}
      :error -> :reject
    end
  end

  defp message(_), do: :reject

  defp printable?(s), do: s |> :binary.bin_to_list() |> Enum.all?(&(&1 >= 0x20 and &1 <= 0x7E))

  # --- send ----------------------------------------------------------------

  # Core SetMessageToSend: short id if there is one, else 0x00 + 12-byte type.
  defp encode(t, cmd, payload) do
    contents =
      case Map.fetch(@type_to_id, cmd) do
        {:ok, id} -> [<<id>>, payload]
        :error -> [<<0>>, cmd, :binary.copy(<<0>>, @message_type_size - byte_size(cmd)), payload]
      end

    {c, packet} = Cipher.encrypt(t.cipher, IO.iodata_to_binary(contents), <<>>, false)
    {%{t | cipher: c}, packet}
  end

  defp flush_queue(t) do
    {t, out} =
      Enum.reduce(Enum.reverse(t.queue), {%{t | queue: []}, []}, fn {cmd, p}, {t, acc} ->
        {t, packet} = encode(t, cmd, p)
        {t, [acc, packet]}
      end)

    sent(t, IO.iodata_to_binary(out))
  end

  defp sent(t, bytes), do: {%{t | sent: t.sent + byte_size(bytes)}, bytes}
end
