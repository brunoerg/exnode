defmodule Exnode.Chain.Headers do
  @moduledoc """
  Owns the header tree. It is the single writer of the `HeaderIndex` ETS
  tables and persists every accepted header to the RocksDB `headers` column
  family, so a restart does not resync.

  Readers get the index with `index/1` and then read the ETS tables
  directly. For a registered server, `index/1` and `best_header/1` do not
  call this process: the index handle is published in `:persistent_term`
  at init (as `Chain.State.view/1`), because this process can be blocked
  for seconds (its KV writes queue behind a chain-state commit) and a 5 s
  call timeout there used to crash callers such as `P2P.BlockDownload`.
  The handle never changes while this process lives; a restart publishes
  a new one before its dependents restart (`Exnode.Node` is `rest_for_one`).

  Persisted value: `<<height::32, status::8, raw_header::80-bytes>>`, keyed by hash.
  """
  use GenServer

  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex, as: Index
  alias Exnode.Codec.Header
  alias Exnode.Store.KV
  alias Exnode.Validation.Header, as: HeaderRules

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  The index (ETS handles; `HeaderIndex.best/1` reads the best header). Safe
  to read from any process. Without a call when `server` is a registered
  name; a pid (tests) falls back to a call.
  """
  def index(server) when is_atom(server) do
    case :persistent_term.get({__MODULE__, server}, nil) do
      nil -> GenServer.call(server, :index)
      idx -> idx
    end
  end

  def index(server), do: GenServer.call(server, :index)

  @doc "The best header entry (Core `m_best_header`), without a call for a registered server."
  def best_header(server), do: Index.best(index(server))

  def params(server), do: GenServer.call(server, :params)

  @doc """
  Core `ProcessNewBlockHeaders`. Returns `{:ok, last_entry}` or
  `{:error, {result, reason}, last_accepted_or_nil}`.

  Options: `:min_pow_checked` (default true) and `:now`, the clock override
  used by tests.
  """
  def process_headers(server, headers, opts \\ []),
    do: GenServer.call(server, {:process, headers, opts}, :infinity)

  @doc """
  Marks a block and its descendants invalid (persisted), recalculating the
  best header (at least `fallback_hash`, the active tip) if it descended
  from the block. Waits with no timeout: the chain state holds `cs_main` in
  Core across this, and the descendant scan is O(index).
  """
  def invalidate(server, hash, fallback_hash),
    do: GenServer.call(server, {:invalidate, hash, fallback_hash}, :infinity)

  @impl true
  def init(opts) do
    %ChainParams{} = p = Keyword.fetch!(opts, :params)
    kv = Keyword.get(opts, :kv)

    idx = Index.insert(Index.new(), Index.make_entry(p.genesis.header, nil))
    idx = if kv, do: load(idx, kv), else: idx
    # Published only once loaded, so readers never see a half-loaded tree.
    if name = opts[:name], do: :persistent_term.put({__MODULE__, name}, idx)
    {:ok, %{params: p, idx: idx, kv: kv, now: Keyword.get(opts, :now)}}
  end

  @impl true
  def handle_call(:index, _from, st), do: {:reply, st.idx, st}
  def handle_call(:params, _from, st), do: {:reply, st.params, st}

  def handle_call({:invalidate, hash, fallback_hash}, _from, st) do
    {idx, failed} = Index.invalidate(st.idx, hash, Index.lookup(st.idx, fallback_hash))
    if st.kv && failed != [], do: persist(st.kv, failed)
    {:reply, :ok, %{st | idx: idx}}
  end

  def handle_call({:process, headers, opts}, _from, st) do
    now = Keyword.get_lazy(opts, :now, fn -> clock(st) end)
    min_pow = Keyword.get(opts, :min_pow_checked, true)
    before = Index.size(st.idx)

    {reply, idx, new_entries} =
      case HeaderRules.process_new_block_headers(st.idx, headers, st.params, min_pow, now) do
        {:ok, last, idx} -> {{:ok, last}, idx, new_since(idx, headers)}
        {:error, reason, last, idx} -> {{:error, reason, last}, idx, new_since(idx, headers)}
      end

    if st.kv && Index.size(idx) > before, do: persist(st.kv, new_entries)
    {:reply, reply, %{st | idx: idx}}
  end

  defp clock(%{now: f}) when is_function(f, 0), do: f.()
  defp clock(_), do: System.os_time(:second)

  defp new_since(idx, headers) do
    headers |> Enum.map(&Index.lookup(idx, &1.hash)) |> Enum.reject(&is_nil/1)
  end

  defp persist(kv, entries) do
    ops = for e <- entries, do: {:put, :headers, e.hash, encode(e)}
    :ok = KV.write(kv, ops, sync: false)
  end

  defp encode(e), do: <<e.height::32, status_byte(e.status), e.raw::binary>>
  defp status_byte(:valid_header), do: 0
  defp status_byte(:failed), do: 1

  defp load(idx, kv) do
    kv
    |> KV.fold_prefix(:headers, <<>>, [], fn {_k, <<h::32, s, raw::binary-size(80)>>}, acc ->
      [{h, s, raw} | acc]
    end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.reduce(idx, fn {_h, s, raw}, idx ->
      {hdr, ""} = Header.decode(raw)

      if Index.lookup(idx, hdr.hash) do
        idx
      else
        prev = Index.lookup(idx, hdr.prev_hash)
        e = Index.make_entry(hdr, prev)
        # Core LoadBlockIndex (blockstorage.cpp): a child of a failed block
        # is failed; failed entries never become the best header (insert/2).
        failed = s == 1 or (prev != nil and prev.status == :failed)
        Index.insert(idx, %{e | status: if(failed, do: :failed, else: :valid_header)})
      end
    end)
  end
end
