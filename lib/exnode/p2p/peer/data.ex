defmodule Exnode.P2P.Peer.Data do
  @moduledoc """
  Structured state held by the `Exnode.P2P.Peer` `:gen_statem`.

  Splits connection-lifetime configuration (`Data`), transport (`Peer.Conn`),
  handshake fields (`Handshake`), and post-verack protocol state (`Proto`,
  `nil` until entering `{:ready, _}`).
  """

  alias Exnode.P2P.Peer.Conn

  defmodule Handshake do
    @moduledoc "Per-connection handshake state populated across `:awaiting_version` / `:awaiting_verack`."
    defstruct [
      :local_nonce,
      :connected_at,
      :version,
      sent_version: false,
      wtxid_relay: false,
      addrv2: false,
      pending_hb_selected: false
    ]

    @type t :: %__MODULE__{}
  end

  defmodule Proto do
    @moduledoc "Post-handshake protocol state (present only in `{:ready, _}`)."
    defstruct [
      # Core m_getdata_requests: getdata items not served yet.
      getdata_queue: :queue.new(),
      # Peer's last feefilter (sat/kvB), resent to TxRelay after it restarts.
      feefilter: 0,
      prefers_headers: false,
      # ping
      ping_nonce: nil,
      ping_sent_at: nil,
      ping_sent_mono: nil,
      next_ping_at: nil,
      last_pong_rtt_ms: nil,
      min_ping_us: nil,
      # headers & block sync
      sync_started: false,
      headers_sync_timeout: nil,
      headers_sync: nil,
      last_getheaders_at: nil,
      best_known: nil,
      best_known_block: -1,
      # Core ChainSyncTimeoutState (m_timeout, m_work_header,
      # m_sent_getheaders, m_protect); timeout nil is Core's 0s.
      chain_sync: %{timeout: nil, work_header: nil, sent_getheaders: false, protect: false},
      getaddr_answered: false,
      # Core m_addr_token_bucket.
      addr_rate: nil,
      # BIP152: the peer sent sendcmpct version 2; blocks being rebuilt from cmpctblock.
      provides_cmpct: false,
      partials: %{},
      # Compact blocks this peer already sent us that we tried to rebuild.
      cmpct_seen: [],
      # Core m_tx_inventory_known_filter, the part this peer announced to us:
      # a RollingBloom written here, read by TxRelay.
      known_in: nil,
      # Blocks rebuilt from this peer's compact blocks stored for a deferred verdict.
      rebuilt_deferred: [],
      # BIP152: the peer asked us to announce new blocks as cmpctblock.
      hb_requested: false,
      # BIP152: we asked the peer to announce new blocks to us as cmpctblock.
      hb_selected: false,
      # Last tip announced to this peer (block announcements).
      announced: nil,
      # Plan 02 hook: bounded in-flight tx submissions to TxRelay.
      tx_in_flight: 0,
      max_tx_in_flight: :infinity
    ]

    @type t :: %__MODULE__{}
  end

  defstruct [
    :node,
    :p,
    :conn_type,
    :inbound,
    :target,
    :conn,
    :handshake,
    proto: nil,
    trace: []
  ]

  @type t :: %__MODULE__{
          conn: Conn.t(),
          handshake: Handshake.t(),
          proto: Proto.t() | nil
        }

  @doc "Whether the peer is in `{:ready, _}` (proto initialized)."
  def ready?(%__MODULE__{proto: proto}), do: proto != nil

  @doc "Updates `proto` via `fun`."
  def update_proto(%__MODULE__{proto: %Proto{} = proto} = data, fun) do
    %{data | proto: fun.(proto)}
  end

  @doc "Updates `handshake` via `fun`."
  def update_handshake(%__MODULE__{handshake: %Handshake{} = hs} = data, fun) do
    %{data | handshake: fun.(hs)}
  end

  @doc "Records a recent wire event for disconnect diagnostics."
  def trace(%__MODULE__{trace: tr} = data, ev) do
    %{data | trace: Enum.take([ev | tr], 12)}
  end
end
