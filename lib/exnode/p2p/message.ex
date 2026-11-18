defmodule Exnode.P2P.Message do
  @moduledoc """
  P2P message payload codecs, mirroring Core v32.1 `net_processing.cpp`
  `ProcessMessage` deserialization and `protocol.h`/`netaddress.h` types.

  `decode(command, payload)` returns `{:ok, message}`, `{:error, reason}`
  (Core's deserialization would throw), or `{:unknown, command}`. It never
  raises.

  Messages are tagged tuples, e.g. `{:version, %{...}}` or `{:headers, [Header]}`.
  """
  import Bitwise

  alias Exnode.Codec.{CompactSize, Header}

  # node/protocol_version.h
  @protocol_version 70017
  @min_peer_proto_version 31800
  # net_processing.cpp / net_processing.h
  @max_headers_results 2000
  @max_locator_sz 101
  @max_inv_sz 50000
  @max_addr_to_send 1000
  # net.h MAX_SUBVERSION_LENGTH
  @max_subversion_length 256
  # netaddress.h CNetAddr::MAX_ADDRV2_SIZE
  @max_addrv2_size 512

  def protocol_version, do: @protocol_version
  def min_peer_proto_version, do: @min_peer_proto_version
  def max_headers_results, do: @max_headers_results
  def max_locator_sz, do: @max_locator_sz
  def max_inv_sz, do: @max_inv_sz
  def max_addr_to_send, do: @max_addr_to_send

  # protocol.h ServiceFlags
  @services %{
    network: 1,
    bloom: 4,
    witness: 8,
    compact_filters: 64,
    network_limited: 1024,
    p2p_v2: 2048
  }
  def service(name), do: Map.fetch!(@services, name)

  # protocol.h GetDataMsg
  @msg_witness_flag 1 <<< 30
  @inv_types %{1 => :tx, 2 => :block, 3 => :filtered_block, 4 => :cmpct_block, 5 => :wtx}
  @inv_codes Map.new(@inv_types, fn {k, v} -> {v, k} end)

  # netaddress.h BIP155Network and address sizes
  @bip155 %{
    1 => {:ipv4, 4},
    2 => {:ipv6, 16},
    3 => {:torv2, 10},
    4 => {:torv3, 32},
    5 => {:i2p, 32},
    6 => {:cjdns, 16}
  }

  @empty ~w(verack sendheaders wtxidrelay sendaddrv2 getaddr mempool)

  # --- decode ---------------------------------------------------------------

  def decode(command, payload) do
    do_decode(command, payload)
  catch
    {:codec_error, reason} -> {:error, reason}
  end

  defp do_decode(
         "version",
         <<version::little-signed-32, services::little-64, time::little-signed-64, rest::binary>>
       ) do
    {addr_recv, rest} = take_netaddr_v1(rest)
    # Core reads the remaining fields only if bytes remain (if (!vRecv.empty())).
    {_addr_from, rest} = if rest == <<>>, do: {nil, rest}, else: take_netaddr_v1(rest)
    {nonce, rest} = optional(rest, fn <<n::little-64, r::binary>> -> {n, r} end, 0)
    {ua, rest} = optional(rest, &limited_string(&1, @max_subversion_length), "")
    # Kept for the connection's lifetime (Peer `version`): a slice of 64 bytes
    # or more would keep the whole payload, up to 4 MB, alive (AUD-A1-2).
    ua = :binary.copy(ua)
    {height, rest} = optional(rest, fn <<h::little-signed-32, r::binary>> -> {h, r} end, -1)
    {relay, _rest} = optional(rest, fn <<b, r::binary>> -> {b != 0, r} end, true)

    {:ok,
     {:version,
      %{
        version: version,
        services: services,
        time: time,
        addr_recv: addr_recv,
        nonce: nonce,
        user_agent: ua,
        start_height: height,
        relay: relay
      }}}
  end

  defp do_decode(cmd, _) when cmd in @empty, do: {:ok, String.to_atom(cmd)}

  defp do_decode("ping", <<nonce::little-64, _::binary>>), do: {:ok, {:ping, nonce}}
  # Pre-BIP31 pings carry no nonce; Core ignores those.
  defp do_decode("ping", <<>>), do: {:ok, {:ping, nil}}
  defp do_decode("pong", <<nonce::little-64, _::binary>>), do: {:ok, {:pong, nonce}}

  defp do_decode("sendcmpct", <<announce, version::little-64, _::binary>>),
    do: {:ok, {:sendcmpct, %{announce: announce != 0, version: version}}}

  defp do_decode("feefilter", <<rate::little-signed-64, _::binary>>),
    do: {:ok, {:feefilter, rate}}

  defp do_decode(cmd, <<version::little-32, rest::binary>>)
       when cmd in ["getheaders", "getblocks"] do
    {locator, rest} = vector(rest, fn <<h::binary-size(32), r::binary>> -> {h, r} end)

    case rest do
      <<stop::binary-size(32), _::binary>> ->
        {:ok, {String.to_atom(cmd), %{version: version, locator: locator, hash_stop: stop}}}

      _ ->
        throw({:codec_error, :truncated})
    end
  end

  defp do_decode("headers", payload) do
    {n, rest} = CompactSize.decode(payload)
    # Core rejects this count (misbehaving). The decoder reports it
    # without parsing 33M headers.
    if n > @max_headers_results, do: throw({:codec_error, {:too_many_headers, n}})
    {headers, _} = take_n(n, rest, &take_header_with_txcount/1)
    {:ok, {:headers, headers}}
  end

  # Over-size vectors (AUD-A1-5): Core deserializes the whole vector before
  # checking its size, so only a complete one is misbehaving; a truncated
  # one throws in deserialization and is dropped. `notfound` has no size
  # check that punishes: Core ignores a large one.
  defp do_decode(cmd, payload) when cmd in ["inv", "getdata", "notfound"] do
    {n, rest} = CompactSize.decode(payload)

    cond do
      n <= @max_inv_sz -> :ok
      byte_size(rest) < n * 36 -> throw({:codec_error, :truncated})
      cmd == "notfound" -> throw({:codec_error, {:notfound_too_large, n}})
      true -> throw({:codec_error, {:inv_too_large, n}})
    end

    {items, _} = take_n(n, rest, &take_inv/1)
    {:ok, {String.to_atom(cmd), items}}
  end

  defp do_decode("addr", payload) do
    {n, rest} = CompactSize.decode(payload)

    if n > @max_addr_to_send do
      if byte_size(rest) < n * 30, do: throw({:codec_error, :truncated})
      throw({:codec_error, {:addr_too_large, n}})
    end

    {addrs, _} =
      take_n(n, rest, fn
        <<time::little-32, services::little-64, rest::binary>> ->
          {{net, ip, port}, r} = take_service_v1(rest)
          {%{time: time, services: services, net: net, addr: ip, port: port}, r}

        _ ->
          throw({:codec_error, :truncated})
      end)

    {:ok, {:addr, addrs}}
  end

  defp do_decode("addrv2", payload) do
    {n, rest} = CompactSize.decode(payload)

    if n > @max_addr_to_send do
      # Entries vary in size: read them all (none kept), as Core does
      # before its check; a malformed one throws first.
      skip_n(n, rest, &take_addrv2/1)
      throw({:codec_error, {:addr_too_large, n}})
    end

    {addrs, _} = take_n(n, rest, &take_addrv2/1)
    {:ok, {:addrv2, Enum.reject(addrs, &is_nil/1)}}
  end

  defp do_decode(cmd, payload)
       when cmd in ["block", "tx", "cmpctblock", "getblocktxn", "blocktxn"],
       do: {:ok, {String.to_atom(cmd), payload}}

  # BIP157 requests: <<filter_type, start_height::32-le, stop_hash::32-bytes>> (getcfcheckpt has no height).
  defp do_decode(cmd, <<type, start::little-32, stop::binary-size(32), _::binary>>)
       when cmd in ["getcfilters", "getcfheaders"],
       do:
         {:ok, {String.to_atom(cmd), %{filter_type: type, start_height: start, stop_hash: stop}}}

  defp do_decode("getcfcheckpt", <<type, stop::binary-size(32), _::binary>>),
    do: {:ok, {:getcfcheckpt, %{filter_type: type, stop_hash: stop}}}

  @known ~w(version verack ping pong sendheaders sendcmpct wtxidrelay sendaddrv2 getaddr mempool feefilter
            getheaders getblocks headers inv getdata notfound addr addrv2 getcfilters getcfheaders getcfcheckpt)
  defp do_decode(cmd, _) when cmd in @known, do: {:error, :truncated}
  defp do_decode(cmd, _), do: {:unknown, cmd}

  defp optional(<<>>, _f, default), do: {default, <<>>}

  defp optional(bin, f, _default) do
    f.(bin)
  rescue
    FunctionClauseError -> throw({:codec_error, :truncated})
  end

  defp limited_string(bin, max) do
    {len, rest} = CompactSize.decode(bin)
    if len > max, do: throw({:codec_error, :string_too_long})

    case rest do
      <<s::binary-size(len), r::binary>> -> {s, r}
      _ -> throw({:codec_error, :truncated})
    end
  end

  defp vector(bin, f) do
    {n, rest} = CompactSize.decode(bin)
    take_n(n, rest, f)
  end

  defp take_n(n, bin, f), do: take_n(n, bin, f, [])

  # Reads n items, keeping none.
  defp skip_n(0, _bin, _f), do: :ok

  defp skip_n(n, bin, f) do
    {_item, rest} =
      try do
        f.(bin)
      rescue
        FunctionClauseError -> throw({:codec_error, :truncated})
      end

    skip_n(n - 1, rest, f)
  end

  defp take_n(0, bin, _f, acc), do: {Enum.reverse(acc), bin}

  defp take_n(n, bin, f, acc) do
    {item, rest} =
      try do
        f.(bin)
      rescue
        FunctionClauseError -> throw({:codec_error, :truncated})
      end

    take_n(n - 1, rest, f, [item | acc])
  end

  defp take_header_with_txcount(bin) do
    {h, rest} = Header.decode(bin)
    # Core: ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
    {_txcount, rest} = CompactSize.decode(rest)
    {h, rest}
  end

  defp take_inv(<<type::little-32, hash::binary-size(32), rest::binary>>) do
    base = type &&& bnot(@msg_witness_flag)
    witness = (type &&& @msg_witness_flag) != 0
    {%{type: Map.get(@inv_types, base, {:unknown, type}), witness: witness, hash: hash}, rest}
  end

  # CNetAddr::V1 + port: 16-byte IPv6 (IPv4-mapped for v4), then the port big-endian.
  defp take_netaddr_v1(<<services::little-64, rest::binary>>) do
    {{net, ip, port}, r} = take_service_v1(rest)
    {%{services: services, net: net, addr: ip, port: port}, r}
  end

  defp take_netaddr_v1(_), do: throw({:codec_error, :truncated})

  defp take_service_v1(<<ip::binary-size(16), port::big-16, rest::binary>>) do
    case ip do
      <<0::80, 0xFFFF::16, v4::binary-size(4)>> -> {{:ipv4, v4, port}, rest}
      _ -> {{:ipv6, ip, port}, rest}
    end
  end

  defp take_service_v1(_), do: throw({:codec_error, :truncated})

  # Core: CAddress (V2) + CNetAddr::UnserializeV2Stream (netaddress.h)
  defp take_addrv2(<<time::little-32, rest::binary>>) do
    {services, rest} = CompactSize.decode(rest, false)

    case rest do
      <<net_id, rest::binary>> ->
        {len, rest} = CompactSize.decode(rest)
        if len > @max_addrv2_size, do: throw({:codec_error, :addrv2_too_long})

        case rest do
          <<addr::binary-size(len), port::big-16, rest::binary>> ->
            entry =
              case Map.fetch(@bip155, net_id) do
                # Known network with the wrong size: Core throws.
                {:ok, {_net, size}} when size != len ->
                  throw({:codec_error, :addrv2_bad_length})

                # TORv2 is no longer supported; Core leaves the address invalid.
                {:ok, {:torv2, _}} ->
                  nil

                {:ok, {net, _}} ->
                  %{time: time, services: services, net: net, addr: addr, port: port}

                # Unknown network ids are skipped (forward compatibility).
                :error ->
                  nil
              end

            {entry, rest}

          _ ->
            throw({:codec_error, :truncated})
        end

      _ ->
        throw({:codec_error, :truncated})
    end
  end

  defp take_addrv2(_), do: throw({:codec_error, :truncated})

  # --- encode ---------------------------------------------------------------

  @doc "Encodes a message to `{command, payload_iodata}`."
  def encode({:version, v}) do
    {"version",
     [
       <<v.version::little-signed-32, v.services::little-64, v.time::little-signed-64>>,
       netaddr_v1(v.addr_recv),
       netaddr_v1(%{services: v.services, net: :ipv6, addr: <<0::128>>, port: 0}),
       <<v.nonce::little-64>>,
       CompactSize.encode_bytes(v.user_agent),
       <<v.start_height::little-signed-32, if(v.relay, do: 1, else: 0)>>
     ]}
  end

  def encode(cmd) when is_atom(cmd), do: {Atom.to_string(cmd), []}
  def encode({:ping, nonce}), do: {"ping", <<nonce::little-64>>}
  def encode({:pong, nonce}), do: {"pong", <<nonce::little-64>>}

  def encode({:sendcmpct, %{announce: a, version: v}}),
    do: {"sendcmpct", <<if(a, do: 1, else: 0), v::little-64>>}

  def encode({:feefilter, rate}), do: {"feefilter", <<rate::little-signed-64>>}

  def encode({cmd, %{locator: loc, hash_stop: stop} = m}) when cmd in [:getheaders, :getblocks] do
    {Atom.to_string(cmd),
     [
       <<Map.get(m, :version, @protocol_version)::little-32>>,
       CompactSize.encode(length(loc)),
       loc,
       stop
     ]}
  end

  def encode({:headers, headers}),
    do:
      {"headers",
       [CompactSize.encode(length(headers)), Enum.map(headers, &[Header.encode(&1), 0])]}

  def encode({cmd, items}) when cmd in [:inv, :getdata, :notfound] do
    {Atom.to_string(cmd),
     [
       CompactSize.encode(length(items)),
       Enum.map(items, fn %{type: t, hash: h} = i ->
         code =
           Map.fetch!(@inv_codes, t) |||
             if(Map.get(i, :witness, false), do: @msg_witness_flag, else: 0)

         [<<code::little-32>>, h]
       end)
     ]}
  end

  def encode({:addrv2, addrs}) do
    ids = Map.new(@bip155, fn {id, {net, _}} -> {net, id} end)

    {"addrv2",
     [
       CompactSize.encode(length(addrs)),
       Enum.map(addrs, fn a ->
         [
           <<a.time::little-32>>,
           CompactSize.encode(a.services),
           <<Map.fetch!(ids, a.net)>>,
           CompactSize.encode_bytes(a.addr),
           <<a.port::big-16>>
         ]
       end)
     ]}
  end

  def encode({:addr, addrs}) do
    {"addr",
     [
       CompactSize.encode(length(addrs)),
       Enum.map(addrs, fn a -> [<<a.time::little-32>>, netaddr_v1(a)] end)
     ]}
  end

  def encode({cmd, payload}) when cmd in [:block, :tx, :cmpctblock, :getblocktxn, :blocktxn],
    do: {Atom.to_string(cmd), payload}

  # BIP157 replies.
  def encode({:cfilter, %{filter_type: t, block_hash: h, filter: f}}),
    do: {"cfilter", [<<t>>, h, CompactSize.encode_bytes(f)]}

  def encode({:cfheaders, %{filter_type: t, stop_hash: h, prev_header: p, filter_hashes: hs}}),
    do: {"cfheaders", [<<t>>, h, p, CompactSize.encode(length(hs)), hs]}

  def encode({:cfcheckpt, %{filter_type: t, stop_hash: h, headers: hs}}),
    do: {"cfcheckpt", [<<t>>, h, CompactSize.encode(length(hs)), hs]}

  def encode({cmd, %{filter_type: t, start_height: s, stop_hash: h}})
      when cmd in [:getcfilters, :getcfheaders],
      do: {Atom.to_string(cmd), <<t, s::little-32>> <> h}

  def encode({:getcfcheckpt, %{filter_type: t, stop_hash: h}}), do: {"getcfcheckpt", <<t>> <> h}

  defp netaddr_v1(%{services: s, net: net, addr: ip, port: port}) do
    ip16 =
      case net do
        :ipv4 -> <<0::80, 0xFFFF::16, ip::binary-size(4)>>
        :ipv6 -> ip
      end

    <<s::little-64, ip16::binary-size(16), port::big-16>>
  end
end
