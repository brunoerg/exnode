defmodule Exnode.RPC.Methods do
  @moduledoc """
  Core-compatible JSON-RPC methods (a subset), with Core v32.1's result
  shapes, field order and error codes/messages: rpc/blockchain.cpp,
  rpc/rawtransaction.cpp, rpc/mempool.cpp, rpc/net.cpp, core_io.cpp.

  `ctx` holds the node's process names and chain params. Each method returns
  `{:ok, json}` or `{:error, code, message}`.
  """
  import Bitwise

  alias Exnode.Archive
  alias Exnode.Chain.{HeaderIndex, Headers}
  alias Exnode.Chain.State, as: ChainState
  alias Exnode.Codec.Tx
  alias Exnode.RPC.{Blockchain, MempoolRPC, Net, RawTx}

  # rpc/protocol.h
  @rpc_misc_error -1
  @rpc_type_error -3
  @rpc_invalid_address_or_key -5
  @rpc_invalid_parameter -8

  @max_money 21_000_000 * 100_000_000

  @dispatch %{
    # Blockchain
    "getblockchaininfo" => {Blockchain, :getblockchaininfo},
    "getbestblockhash" => {Blockchain, :getbestblockhash},
    "getblockcount" => {Blockchain, :getblockcount},
    "getblockhash" => {Blockchain, :getblockhash},
    "getblockheader" => {Blockchain, :getblockheader},
    "getblock" => {Blockchain, :getblock},
    "gettxout" => {Blockchain, :gettxout},
    "getdifficulty" => {Blockchain, :getdifficulty},
    "getblockfilter" => {Blockchain, :getblockfilter},
    # Raw transactions
    "getrawtransaction" => {RawTx, :getrawtransaction},
    "decoderawtransaction" => {RawTx, :decoderawtransaction},
    "decodescript" => {RawTx, :decodescript},
    "sendrawtransaction" => {RawTx, :sendrawtransaction},
    # Mempool
    "getrawmempool" => {MempoolRPC, :getrawmempool},
    "getmempoolentry" => {MempoolRPC, :getmempoolentry},
    "getmempoolinfo" => {MempoolRPC, :getmempoolinfo},
    "testmempoolaccept" => {MempoolRPC, :testmempoolaccept},
    "submitpackage" => {MempoolRPC, :submitpackage},
    # Network & node control
    "setmocktime" => {Net, :setmocktime},
    "uptime" => {Net, :uptime},
    "getconnectioncount" => {Net, :getconnectioncount},
    "getnetworkinfo" => {Net, :getnetworkinfo},
    "getpeerinfo" => {Net, :getpeerinfo}
  }

  def known?(m), do: Map.has_key?(@dispatch, m)

  def call(method, params, ctx) do
    case Map.get(@dispatch, method) do
      {mod, fun} -> apply(mod, fun, [params, ctx])
      nil -> {:error, -32601, "Method not found"}
    end
  rescue
    e in [Exnode.StorageError, Exnode.Store.KV.Error] ->
      require Logger
      Logger.critical("RPC #{method}: fatal storage fault: " <> Exception.message(e))
      {:error, -32603, "fatal storage fault: " <> Exception.message(e)}

    e in [ArgumentError, FunctionClauseError] ->
      {:error, @rpc_type_error, Exception.message(e)}

    e ->
      # Core: RPC_INTERNAL_ERROR (-32603) for unexpected failures.
      require Logger
      Logger.error("RPC #{method} failed: " <> Exception.format(:error, e, __STACKTRACE__))
      {:error, -32603, Exception.message(e)}
  catch
    # A node component restarting (its name unregistered, or it died during
    # the call): an error for this request only, not a dropped connection
    # and lost batch.
    :exit, reason ->
      require Logger
      Logger.warning("RPC #{method}: node component unavailable: #{inspect(reason, limit: 5)}")
      {:error, -32603, "node component unavailable, retry"}
  end

  @doc "Core `TxToUniv(tx, block_hash = null, entry, include_hex, txundo, verbosity)`."
  defdelegate tx_to_univ(tx, network, undo, verbosity, include_hex), to: RawTx

  # Core GetDifficulty
  def difficulty(bits) do
    shift = bits >>> 24 &&& 0xFF
    d = 0x0000FFFF / (bits &&& 0x00FFFFFF)
    d = Enum.reduce(1..max(29 - shift, 0)//1, d, fn _, d -> d * 256.0 end)
    Enum.reduce(1..max(shift - 29, 0)//1, d, fn _, d -> d / 256.0 end)
  end

  # --- shared RPC helpers --------------------------------------------------------

  @doc false
  def idx(ctx), do: Headers.index(ctx.headers)

  # The committed tip, from the lock-free reader: block data up to it is readable.
  @doc false
  def tip(ctx), do: Archive.tip(reader(ctx))

  @doc false
  def reader(ctx), do: ChainState.reader(ctx.chain_state)

  @doc false
  def tip_entry(ctx), do: HeaderIndex.lookup(idx(ctx), tip(ctx).hash)

  @doc false
  def network(ctx), do: ctx.params.network

  # The node's clock (Exnode.Clock; Core GetTime / NodeClock): mockable.
  @doc false
  def now(ctx), do: Exnode.Clock.now(ctx[:clock])

  @doc false
  def arg(params, i, default \\ nil) do
    case Enum.at(params, i) do
      nil -> default
      v -> v
    end
  end

  # Core ParseHashV.
  @doc false
  def parse_hash(v, name) when is_binary(v) do
    cond do
      byte_size(v) != 64 ->
        {:error, @rpc_invalid_parameter,
         "#{name} must be of length 64 (not #{byte_size(v)}, for '#{v}')"}

      not String.match?(v, ~r/^[0-9a-fA-F]+$/) ->
        {:error, @rpc_invalid_parameter, "#{name} must be hexadecimal string (not '#{v}')"}

      true ->
        {:ok, Exnode.Crypto.Hash.from_hex(String.downcase(v))}
    end
  end

  def parse_hash(v, name),
    do: {:error, @rpc_type_error, "#{name} must be a string, got #{inspect(v)}"}

  @doc false
  def parse_optional_hash(nil, _name), do: {:ok, nil}
  def parse_optional_hash(v, name), do: parse_hash(v, name)

  # Verbosity args may be numbers or (legacy) booleans.
  @doc false
  def verbosity(nil, default), do: default
  def verbosity(true, _), do: 1
  def verbosity(false, _), do: 0
  def verbosity(n, _) when is_integer(n), do: n

  @doc false
  def on_active?(idx, tip_e, e),
    do: e.height <= tip_e.height and HeaderIndex.ancestor(idx, tip_e, e.height).hash == e.hash

  @doc false
  def lookup_header(ctx, hash) do
    case HeaderIndex.lookup(idx(ctx), hash) do
      nil -> {:error, @rpc_invalid_address_or_key, "Block not found"}
      e -> {:ok, e}
    end
  end

  @doc false
  def check_type(v, expected, ok?) do
    if ok?.(v),
      do: :ok,
      else:
        {:error, @rpc_type_error,
         "JSON value of type #{json_type(v)} is not of expected type #{expected}"}
  end

  @doc false
  def check_uint32(n) when is_integer(n) and n in 0..0xFFFFFFFF, do: :ok
  def check_uint32(_), do: {:error, @rpc_misc_error, "JSON integer out of range"}

  @doc false
  def json_type(nil), do: "null"
  def json_type(v) when is_binary(v), do: "string"
  def json_type(v) when is_boolean(v), do: "bool"
  def json_type(v) when is_list(v), do: "array"
  def json_type(v) when is_map(v), do: "object"
  def json_type(_), do: "number"

  @doc false
  def decode_tx(h) when is_binary(h) do
    with {:ok, raw} <- Base.decode16(h, case: :mixed), {:ok, tx} <- Tx.decode_exact(raw) do
      {:ok, tx}
    else
      _ -> :error
    end
  end

  def decode_tx(_), do: :error

  # Core DecodeHexTx: rejects 0-input transactions too.
  @doc false
  def decode_hex_tx(h) when is_binary(h) do
    case decode_tx(h) do
      {:ok, %Tx{inputs: [_ | _]} = tx} -> {:ok, tx}
      _ -> :error
    end
  end

  def decode_hex_tx(_), do: :error

  # Core CScript::HasValidOps: every op parses, is <= MAX_OPCODE (0xb9), pushes <= 520 bytes.
  @doc false
  def valid_ops?(<<>>), do: true

  def valid_ops?(s) do
    case Exnode.Script.get_op(s) do
      {:ok, op, d, rest} -> op <= 0xB9 and byte_size(d) <= 520 and valid_ops?(rest)
      :error -> false
    end
  end

  # Core AmountFromValue (rpc/util.cpp).
  @doc false
  def parse_amount(v) when is_integer(v) do
    sat = v * 100_000_000

    if sat >= 0 and sat <= @max_money,
      do: {:ok, sat},
      else: {:error, @rpc_type_error, "Amount out of range"}
  end

  def parse_amount(v) when is_float(v) do
    scaled = v * 100_000_000
    sat = round(scaled)

    cond do
      abs(scaled - sat) > 1.0e-4 -> {:error, @rpc_type_error, "Invalid amount"}
      sat < 0 or sat > @max_money -> {:error, @rpc_type_error, "Amount out of range"}
      true -> {:ok, sat}
    end
  end

  def parse_amount(v) when is_binary(v) do
    case Regex.run(~r/^(-?)(\d*)(?:\.(\d*))?$/, v) do
      [_, sign, whole, frac] when (whole != "" or frac != "") and byte_size(frac) <= 8 ->
        w = if whole == "", do: 0, else: String.to_integer(whole)
        f = frac |> String.pad_trailing(8, "0") |> String.to_integer()
        sat = w * 100_000_000 + f
        sat = if sign == "-", do: -sat, else: sat

        if sat >= 0 and sat <= @max_money,
          do: {:ok, sat},
          else: {:error, @rpc_type_error, "Amount out of range"}

      [_, sign, whole] when whole != "" ->
        sat = String.to_integer(whole) * 100_000_000
        sat = if sign == "-", do: -sat, else: sat

        if sat >= 0 and sat <= @max_money,
          do: {:ok, sat},
          else: {:error, @rpc_type_error, "Amount out of range"}

      _ ->
        {:error, @rpc_type_error, "Invalid amount"}
    end
  end

  def parse_amount(_), do: {:error, @rpc_type_error, "Amount is not a number or string"}

  @doc false
  def parse_optional_amount(nil, default), do: {:ok, default}
  def parse_optional_amount(v, _default), do: parse_amount(v)

  # Core ParseFeeRate (rpc/util.cpp).
  @doc false
  def parse_feerate(nil, default), do: {:ok, default}

  def parse_feerate(v, _default) do
    with {:ok, sat} <- parse_amount(v) do
      if sat >= 100_000_000,
        do:
          {:error, @rpc_invalid_parameter,
           "Fee rates larger than or equal to 1BTC/kvB are not accepted"},
        else: {:ok, sat}
    end
  end
end
