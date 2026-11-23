defmodule Exnode.P2P.NetAddr do
  @moduledoc """
  Network address classification. Port of the parts of Core v32.1
  `netaddress.cpp` (`CNetAddr`, `CService`) and `netgroup.cpp`
  (`NetGroupManager::GetGroup`, without ASMap) that the address manager and
  connection manager rely on.

  An address is `%{net: net, addr: bytes}` (a service adds `port`), with
  `net` one of `:ipv4 | :ipv6 | :torv3 | :i2p | :cjdns` (BIP155; TorV2 is
  dropped, as Core does).
  """

  import Bitwise

  # netaddress.h enum Network (GetNetClass values, the first byte of a group).
  @net_unroutable 0
  @net_ipv4 1
  @net_ipv6 2
  @net_onion 3
  @net_i2p 4
  @net_cjdns 5

  @net_internal 6

  @ipv4_in_ipv6 <<0::80, 0xFF, 0xFF>>
  @internal_in_ipv6 <<0xFD, 0x6B, 0x88, 0xC0, 0x87, 0x24>>
  @torv2_in_ipv6 <<0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43>>

  @doc """
  Core `CNetAddr::SetInternal(name)`: a placeholder address standing for a
  name (a DNS seed host, "fixedseeds"), used as the source of addresses
  learned that way: the first 10 bytes of sha256(name).
  """
  def internal(name) when is_binary(name) and name != "",
    do: %{net: :internal, addr: binary_part(:crypto.hash(:sha256, name), 0, 10)}

  def ipv4?(%{net: n}), do: n == :ipv4
  def ipv6?(%{net: n}), do: n == :ipv6

  # --- the RFC ranges (CNetAddr::IsRFC*) --------------------------------------

  defp rfc1918?(%{net: :ipv4, addr: <<a, b, _, _>>}),
    do: a == 10 or (a == 192 and b == 168) or (a == 172 and b in 16..31)

  defp rfc1918?(_), do: false
  defp rfc2544?(%{net: :ipv4, addr: <<198, b, _, _>>}), do: b in [18, 19]
  defp rfc2544?(_), do: false
  defp rfc3927?(%{net: :ipv4, addr: <<169, 254, _, _>>}), do: true
  defp rfc3927?(_), do: false
  defp rfc6598?(%{net: :ipv4, addr: <<100, b, _, _>>}), do: b in 64..127
  defp rfc6598?(_), do: false
  defp rfc5737?(%{net: :ipv4, addr: <<192, 0, 2, _>>}), do: true
  defp rfc5737?(%{net: :ipv4, addr: <<198, 51, 100, _>>}), do: true
  defp rfc5737?(%{net: :ipv4, addr: <<203, 0, 113, _>>}), do: true
  defp rfc5737?(_), do: false
  defp rfc3849?(%{net: :ipv6, addr: <<0x20, 0x01, 0x0D, 0xB8, _::binary>>}), do: true
  defp rfc3849?(_), do: false
  defp rfc9637?(%{net: :ipv6, addr: <<0x3F, 0xFF, c, _::binary>>}), do: (c &&& 0xF0) == 0
  defp rfc9637?(_), do: false
  defp rfc3964?(%{net: :ipv6, addr: <<0x20, 0x02, _::binary>>}), do: true
  defp rfc3964?(_), do: false
  defp rfc6052?(%{net: :ipv6, addr: <<0x00, 0x64, 0xFF, 0x9B, 0::64, _::binary>>}), do: true
  defp rfc6052?(_), do: false
  defp rfc4380?(%{net: :ipv6, addr: <<0x20, 0x01, 0x00, 0x00, _::binary>>}), do: true
  defp rfc4380?(_), do: false
  defp rfc4862?(%{net: :ipv6, addr: <<0xFE, 0x80, 0::48, _::binary>>}), do: true
  defp rfc4862?(_), do: false
  defp rfc4193?(%{net: :ipv6, addr: <<a, _::binary>>}), do: (a &&& 0xFE) == 0xFC
  defp rfc4193?(_), do: false
  defp rfc6145?(%{net: :ipv6, addr: <<0::64, 0xFF, 0xFF, 0, 0, _::binary>>}), do: true
  defp rfc6145?(_), do: false
  defp rfc4843?(%{net: :ipv6, addr: <<0x20, 0x01, 0x00, d, _::binary>>}), do: (d &&& 0xF0) == 0x10
  defp rfc4843?(_), do: false
  defp rfc7343?(%{net: :ipv6, addr: <<0x20, 0x01, 0x00, d, _::binary>>}), do: (d &&& 0xF0) == 0x20
  defp rfc7343?(_), do: false
  defp he_net?(%{net: :ipv6, addr: <<0x20, 0x01, 0x04, 0x70, _::binary>>}), do: true
  defp he_net?(_), do: false

  @doc "Core `CNetAddr::IsLocal`: 127/8, 0/8, ::1."
  def local?(%{net: :ipv4, addr: <<a, _, _, _>>}), do: a in [127, 0]
  def local?(%{net: :ipv6, addr: <<1::128>>}), do: true
  def local?(_), do: false

  @doc "Core `CNetAddr::IsValid`."
  def valid?(%{net: :internal}), do: false
  def valid?(%{net: :ipv6, addr: <<0::128>>}), do: false
  def valid?(%{net: :cjdns, addr: <<p, _::binary>>}) when p != 0xFC, do: false
  def valid?(%{net: :ipv4, addr: a}) when a in [<<0, 0, 0, 0>>, <<255, 255, 255, 255>>], do: false

  def valid?(%{net: net, addr: a} = x)
      when net in [:ipv4, :ipv6, :torv3, :i2p, :cjdns] and is_binary(a) do
    size_ok?(net, a) and not (rfc3849?(x) or rfc9637?(x) or embedded_in_ipv6?(x))
  end

  def valid?(_), do: false

  # Core never holds these prefixes as IPv6: SetLegacyIPv6 maps IPv4-mapped
  # to IPv4 and internal to NET_INTERNAL; UnserializeV2Stream (BIP155) reads
  # IPv4-mapped and TORv2 as invalid. Here one comes from a peer's addrv2
  # (decoded as is, so it still uses a rate-limit token, as Core's does) or a
  # peers.dat written before this check.
  defp embedded_in_ipv6?(%{net: :ipv6, addr: <<0::80, 0xFF, 0xFF, _::binary-size(4)>>}),
    do: true

  defp embedded_in_ipv6?(%{net: :ipv6, addr: <<p::binary-size(6), _::binary-size(10)>>}),
    do: p in [@torv2_in_ipv6, @internal_in_ipv6]

  defp embedded_in_ipv6?(_), do: false

  defp size_ok?(:ipv4, a), do: byte_size(a) == 4
  defp size_ok?(:ipv6, a), do: byte_size(a) == 16
  defp size_ok?(:cjdns, a), do: byte_size(a) == 16
  defp size_ok?(n, a) when n in [:torv3, :i2p], do: byte_size(a) == 32

  @doc "Core `CNetAddr::IsRoutable`."
  def routable?(x) do
    valid?(x) and
      not (rfc1918?(x) or rfc2544?(x) or rfc3927?(x) or rfc4862?(x) or rfc6598?(x) or rfc5737?(x) or
             rfc4193?(x) or
             rfc4843?(x) or rfc7343?(x) or local?(x))
  end

  @doc "Core `HasLinkedIPv4`: IPv4, or IPv6 carrying an IPv4 address (6145, 6052, 6to4, Teredo)."
  def linked_ipv4?(x),
    do: routable?(x) and (ipv4?(x) or rfc6145?(x) or rfc6052?(x) or rfc3964?(x) or rfc4380?(x))

  defp linked_ipv4(%{net: :ipv4, addr: a}), do: a

  defp linked_ipv4(%{addr: a} = x) do
    cond do
      rfc6052?(x) or rfc6145?(x) ->
        binary_part(a, 12, 4)

      rfc3964?(x) ->
        binary_part(a, 2, 4)

      rfc4380?(x) ->
        <<n::32>> = binary_part(a, 12, 4)
        <<bnot(n) &&& 0xFFFFFFFF::32>>
    end
  end

  @doc "Core `GetNetClass` (as its enum value)."
  def net_class(%{net: :internal}), do: @net_internal

  def net_class(x) do
    cond do
      not routable?(x) -> @net_unroutable
      linked_ipv4?(x) -> @net_ipv4
      true -> net_id(x.net)
    end
  end

  defp net_id(:ipv4), do: @net_ipv4
  defp net_id(:ipv6), do: @net_ipv6
  defp net_id(:torv3), do: @net_onion
  defp net_id(:i2p), do: @net_i2p
  defp net_id(:cjdns), do: @net_cjdns

  @doc "Core `GetAddrBytes`: the 16-byte v1 form for IPv4/IPv6, raw bytes otherwise."
  def addr_bytes(%{net: :ipv4, addr: a}), do: @ipv4_in_ipv6 <> a
  def addr_bytes(%{net: :internal, addr: a}), do: @internal_in_ipv6 <> a
  def addr_bytes(%{addr: a}), do: a

  @doc "Core `CService::GetKey`: address bytes and the big-endian port."
  def service_key(%{port: p} = s), do: addr_bytes(s) <> <<p::16>>

  @doc "Core `NetGroupManager::GetGroup` (no ASMap), as bytes."
  # Internal addresses: their own group, the 10 name-hash bytes.
  def group(%{net: :internal, addr: a}), do: <<@net_internal>> <> a

  def group(x) do
    class = net_class(x)

    cond do
      local?(x) or not routable?(x) ->
        <<class>>

      linked_ipv4?(x) ->
        <<a, b, _, _>> = linked_ipv4(x)
        <<class, a, b>>

      true ->
        bits =
          cond do
            x.net in [:torv3, :i2p] -> 4
            x.net == :cjdns -> 12
            he_net?(x) -> 36
            true -> 32
          end

        bytes = addr_bytes(x)
        whole = div(bits, 8)
        rest = rem(bits, 8)

        tail =
          if rest > 0, do: <<:binary.at(bytes, whole) ||| (1 <<< (8 - rest)) - 1>>, else: <<>>

        <<class>> <> binary_part(bytes, 0, whole) <> tail
    end
  end

  # netbase.cpp IsBadPort: ports of well-known services, not dialled automatically.
  @bad_ports [
    1,
    7,
    9,
    11,
    13,
    15,
    17,
    19,
    20,
    21,
    22,
    23,
    25,
    37,
    42,
    43,
    53,
    69,
    77,
    79,
    87,
    95,
    101,
    102,
    103,
    104,
    109,
    110,
    111,
    113,
    115,
    117,
    119,
    123,
    135,
    137,
    139,
    143,
    161,
    179,
    389,
    427,
    465,
    512,
    513,
    514,
    515,
    526,
    530,
    531,
    532,
    540,
    548,
    554,
    556,
    563,
    587,
    601,
    636,
    989,
    990,
    993,
    995,
    1719,
    1720,
    1723,
    2049,
    3306,
    3389,
    3659,
    4045,
    5060,
    5061,
    5432,
    5900,
    6000,
    6566,
    6665,
    6666,
    6667,
    6668,
    6669,
    6697,
    10080,
    27017
  ]

  @doc "Core `IsBadPort`."
  def bad_port?(port), do: port in @bad_ports
end
