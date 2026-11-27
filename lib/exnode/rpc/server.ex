defmodule Exnode.RPC.Server do
  @moduledoc """
  JSON-RPC over HTTP, as Core v32.1 `httprpc.cpp` / `rpc/request.cpp`:

  * Basic auth with the cookie (`<datadir>/<chain>/.cookie`, user
    `__cookie__`, written at startup) or `rpcuser` / `rpcpassword`.
  * Single requests and batches. JSON-RPC 2.0 requests (`"jsonrpc": "2.0"`)
    get 2.0 replies; legacy ones get `{"result", "error", "id"}`.
  * Legacy errors use Core's HTTP statuses: 404 for unknown methods, 400 for
    invalid requests, 500 for other errors. 2.0 replies are always 200.
  * Named parameters map to positional ones by Core's argument names.
  * Batches are limited to 1,000 requests (local resource limit); an
    oversize batch is rejected in full before any method executes.
  """
  use Plug.Builder
  require Logger

  alias Exnode.RPC.Methods

  # Local resource limit (Core has a body limit but no batch-count limit).
  # Reject the whole batch before executing anything; never truncate it.
  @max_batch_size 1_000
  def max_batch_size, do: @max_batch_size

  @arg_names %{
    "getblockhash" => ~w(height),
    "getblockheader" => ~w(blockhash verbose),
    "getblock" => ~w(blockhash verbosity),
    "gettxout" => ~w(txid n include_mempool),
    "getrawtransaction" => ~w(txid verbosity blockhash),
    "decoderawtransaction" => ~w(hexstring iswitness),
    "decodescript" => ~w(hexstring),
    "getrawmempool" => ~w(verbose mempool_sequence),
    "getmempoolentry" => ~w(txid),
    "testmempoolaccept" => ~w(rawtxs maxfeerate),
    "sendrawtransaction" => ~w(hexstring maxfeerate maxburnamount),
    "submitpackage" => ~w(package maxfeerate maxburnamount),
    "getblockfilter" => ~w(blockhash filtertype)
  }

  def child_spec(opts) do
    port = Keyword.fetch!(opts, :port)
    ctx = Keyword.fetch!(opts, :ctx)
    auth = Keyword.fetch!(opts, :auth)
    plug_opts = %{ctx: ctx, auth: auth}

    Supervisor.child_spec(
      {Bandit,
       plug: {__MODULE__, plug_opts},
       port: port,
       ip: Keyword.get(opts, :ip, {127, 0, 0, 1}),
       startup_log: false,
       thousand_island_options: Exnode.FdBudget.api_server_options()},
      id: Keyword.get(opts, :id, __MODULE__)
    )
  end

  @doc "Writes the RPC cookie (Core GenerateAuthCookie) and returns `{user, password}`."
  def write_cookie(dir) do
    pass = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
    File.mkdir_p!(dir)
    path = Path.join(dir, ".cookie")
    File.write!(path, "__cookie__:" <> pass)
    File.chmod(path, 0o600)
    {"__cookie__", pass}
  end

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, opts) do
    # Each connection process is an archive reader the fd budget counts.
    Exnode.Archive.Segments.limit_read_handles(Exnode.FdBudget.api_read_handles())
    conn = Plug.Conn.put_resp_content_type(conn, "application/json")

    try do
      cond do
        not authorized?(conn, opts.auth) ->
          conn
          |> Plug.Conn.put_resp_header("www-authenticate", ~s(Basic realm="jsonrpc"))
          |> Plug.Conn.send_resp(401, "")

        conn.method != "POST" ->
          Plug.Conn.send_resp(conn, 405, "JSONRPC server handles only POST requests")

        true ->
          case Plug.Conn.read_body(conn, length: 32_000_000) do
            {:ok, body, conn} -> handle_body(conn, body, opts.ctx)
            {:more, _, conn} -> Plug.Conn.send_resp(conn, 413, "Request body too large")
          end
      end
    after
      Exnode.Archive.take_stats()
      Exnode.Archive.Segments.close_all_readers()
    end
  end

  defp authorized?(conn, credentials) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      ["Basic " <> b64] ->
        case Base.decode64(b64) do
          {:ok, userpass} ->
            Enum.any?(credentials, fn {u, p} ->
              Plug.Crypto.secure_compare(userpass, u <> ":" <> p)
            end)

          :error ->
            false
        end

      _ ->
        false
    end
  end

  defp handle_body(conn, body, ctx) do
    case Jason.decode(body) do
      {:ok, reqs} when is_list(reqs) ->
        cond do
          length(reqs) > @max_batch_size ->
            invalid_batch(conn, "Batch exceeds #{@max_batch_size} requests")

          # Accepted batches return 200 (Core JSONRPCExecBatch).
          true ->
            send_json(conn, 200, Enum.map(reqs, &elem(execute(&1, ctx), 1)))
        end

      {:ok, req} when is_map(req) ->
        {status, reply} = execute(req, ctx)
        send_json(conn, status, reply)

      _ ->
        send_json(conn, 500, %{
          "result" => nil,
          "error" => %{"code" => -32700, "message" => "Parse error"},
          "id" => nil
        })
    end
  end

  defp invalid_batch(conn, message),
    do:
      send_json(conn, 400, %{
        "jsonrpc" => "2.0",
        "error" => %{"code" => -32600, "message" => message},
        "id" => nil
      })

  defp execute(req, ctx) when is_map(req) do
    id = Map.get(req, "id")
    v2 = Map.get(req, "jsonrpc") == "2.0"
    method = Map.get(req, "method")

    result =
      cond do
        not is_binary(method) -> {:error, -32600, "Method must be a string"}
        true -> Methods.call(method, positional(method, Map.get(req, "params", [])), ctx)
      end

    case result do
      {:ok, value} ->
        {200,
         if(v2,
           do: %{"jsonrpc" => "2.0", "result" => value, "id" => id},
           else: obj(result: value, error: nil, id: id)
         )}

      {:error, code, message} ->
        err = %{"code" => code, "message" => message}

        status =
          cond do
            v2 -> 200
            code == -32601 -> 404
            code == -32600 -> 400
            true -> 500
          end

        {status,
         if(v2,
           do: %{"jsonrpc" => "2.0", "error" => err, "id" => id},
           else: obj(result: nil, error: err, id: id)
         )}
    end
  end

  defp execute(_req, _ctx),
    do:
      {400,
       %{
         "result" => nil,
         "error" => %{"code" => -32600, "message" => "Invalid Request object"},
         "id" => nil
       }}

  defp obj(kv), do: Jason.OrderedObject.new(Enum.map(kv, fn {k, v} -> {Atom.to_string(k), v} end))

  defp positional(_method, params) when is_list(params), do: params

  defp positional(method, params) when is_map(params) do
    names = Map.get(@arg_names, method, [])
    args = Enum.map(names, &Map.get(params, &1))
    # Trailing unset arguments are dropped, so defaults apply.
    args |> Enum.reverse() |> Enum.drop_while(&is_nil/1) |> Enum.reverse()
  end

  defp positional(_method, _), do: []

  defp send_json(conn, status, data), do: Plug.Conn.send_resp(conn, status, Jason.encode!(data))
end
