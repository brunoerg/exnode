defmodule Exnode.Chain.Headers do
  @moduledoc """
  Owns the header tree. It is the single writer of the `HeaderIndex` ETS
  tables and persists accepted headers so restarts do not resync.

  In split-store node mode (`staging_kv` provided):
  * Authoritative headers (committed blocks and `:failed` invalidations) live
    in canonical `kv` (`:headers` CF), written exclusively by `Chain.State`
    inside synced canonical commits and verified by `"headers_count"` on load.
  * Newly received ahead-of-tip P2P headers are written asynchronously by
    `Headers.Writer` to ephemeral `staging_kv` (`:headers_cache` CF,
    `sync: false`), with zero contention against canonical commits.

  In standalone mode (`staging_kv` omitted, unit tests):
  * `Headers.Writer` persists accepted headers directly to `kv` (`:headers` CF).

  Readers get the index with `index/1` and then read the ETS tables
  directly. For a registered server, `index/1` and `best_header/1` do not
  call this process: the index handle is published in `Exnode.Node.Runtime`
  at init (as `Chain.State.view/1`), because this process can be blocked
  for seconds (e.g. on a long `invalidate/3`) and a 5 s call timeout
  there used to crash callers such as `P2P.BlockDownload`.
  The handle never changes while this process lives; a restart publishes
  a new one before its dependents restart (`Exnode.Node` is `rest_for_one`).

  Persisted value: `<<height::32, status::8, raw_header::80-bytes>>`, keyed by hash.
  """
  use GenServer

  alias Exnode.ChainParams
  alias Exnode.Chain.HeaderIndex, as: Index
  alias Exnode.Chain.Headers.Writer
  alias Exnode.Codec.Header
  alias Exnode.Node.Runtime
  alias Exnode.StorageError
  alias Exnode.Store.KV
  alias Exnode.Validation.Header, as: HeaderRules

  @headers_count_key "headers_count"

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "Metadata key storing the canonical `:headers` row count."
  def headers_count_key, do: @headers_count_key

  @doc "Encodes header entries as canonical `:headers` KV put ops."
  def canonical_ops(entries), do: for(e <- entries, do: {:put, :headers, e.hash, encode(e)})

  @doc """
  The index (ETS handles; `HeaderIndex.best/1` reads the best header). Safe
  to read from any process. Without a call when `server` is a registered
  name; a pid (tests) falls back to a call.
  """
  def index(server) when is_atom(server) do
    case Runtime.get_handle({__MODULE__, server}, nil) do
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
  Marks a block and its descendants invalid, recalculating the best header
  (at least `fallback_hash`, the active tip) if it descended from the block.
  """
  def invalidate(server, hash, fallback_hash) do
    _ = invalidate_entries(server, hash, fallback_hash)
    :ok
  end

  @doc """
  Same as `invalidate/3`, returning the newly failed header entries so the
  canonical writer (`Chain.State`) can persist them synchronously in split mode.
  """
  def invalidate_entries(server, hash, fallback_hash),
    do: GenServer.call(server, {:invalidate, hash, fallback_hash}, :infinity)

  @doc """
  Waits until every header accepted so far is written to the writer's KV
  (a no-op without a writer).
  """
  def flush(server), do: GenServer.call(server, :flush, :infinity)

  @impl true
  def init(opts) do
    %ChainParams{} = p = Keyword.fetch!(opts, :params)

    kv =
      case Keyword.fetch(opts, :kv) do
        {:ok, kv} -> kv
        :error -> if node_name = opts[:node_name], do: Runtime.kv(node_name), else: nil
      end

    staging_kv =
      case Keyword.fetch(opts, :staging_kv) do
        {:ok, skv} -> skv
        :error -> if node_name = opts[:node_name], do: Runtime.staging_kv(node_name), else: nil
      end

    split? = staging_kv != nil

    idx = Index.insert(Index.new(), Index.make_entry(p.genesis.header, nil))
    idx = if kv, do: load_canonical(idx, kv), else: idx
    idx = if split?, do: load_staging(idx, staging_kv), else: idx

    # Trapping exits so terminate/2 runs on a supervisor shutdown and drains
    # the writer before the store closes (Node.Runtime stops after this process).
    writer_kv = if split?, do: staging_kv, else: kv
    writer_cf = if split?, do: :headers_cache, else: :headers

    writer =
      if writer_kv do
        Process.flag(:trap_exit, true)
        {:ok, w} = Writer.start_link(writer_kv)
        w
      end

    # Published only once loaded, so readers never see a half-loaded tree.
    if name = opts[:name], do: Runtime.put_handle({__MODULE__, name}, idx)

    {:ok,
     %{
       params: p,
       idx: idx,
       writer: writer,
       writer_cf: writer_cf,
       split?: split?,
       now: Keyword.get(opts, :now)
     }}
  end

  @impl true
  def handle_call(:index, _from, st), do: {:reply, st.idx, st}
  def handle_call(:params, _from, st), do: {:reply, st.params, st}

  def handle_call(:flush, _from, st) do
    if st.writer, do: Writer.sync(st.writer)
    {:reply, :ok, st}
  end

  def handle_call({:invalidate, hash, fallback_hash}, _from, st) do
    {idx, failed} = Index.invalidate(st.idx, hash, Index.lookup(st.idx, fallback_hash))

    if st.writer && failed != [] do
      Writer.write_sync(st.writer, ops(st.writer_cf, failed))
    end

    {:reply, failed, %{st | idx: idx}}
  end

  def handle_call({:process, headers, opts}, _from, st) do
    now = Keyword.get_lazy(opts, :now, fn -> clock(st) end)
    min_pow = Keyword.get(opts, :min_pow_checked, true)
    before = Index.size(st.idx)

    existing =
      if st.writer,
        do:
          for(h <- headers, Index.lookup(st.idx, h.hash) != nil, into: MapSet.new(), do: h.hash),
        else: MapSet.new()

    {reply, idx} =
      case HeaderRules.process_new_block_headers(st.idx, headers, st.params, min_pow, now) do
        {:ok, last, idx} -> {{:ok, last}, idx}
        {:error, reason, last, idx} -> {{:error, reason, last}, idx}
      end

    if st.writer && Index.size(idx) > before do
      new_entries =
        for h <- headers,
            not MapSet.member?(existing, h.hash),
            e = Index.lookup(idx, h.hash),
            e != nil,
            do: e

      if new_entries != [], do: Writer.write(st.writer, ops(st.writer_cf, new_entries))
    end

    {:reply, reply, %{st | idx: idx}}
  end

  # The writer failed (a KV error): stop as a failed write here used to.
  @impl true
  def handle_info({:EXIT, w, reason}, %{writer: w} = st), do: {:stop, reason, st}
  def handle_info({:EXIT, _pid, _reason}, st), do: {:noreply, st}

  @impl true
  def terminate(_reason, %{writer: w}) when is_pid(w) do
    # Everything queued is written before the store can close.
    Writer.stop(w)
  catch
    :exit, _ -> :ok
  end

  def terminate(_reason, _st), do: :ok

  defp clock(%{now: f}) when is_function(f, 0), do: f.()
  defp clock(_), do: System.os_time(:second)

  defp ops(cf, entries), do: for(e <- entries, do: {:put, cf, e.hash, encode(e)})

  defp encode(e), do: <<e.height::32, status_byte(e.status), e.raw::binary>>
  defp status_byte(:valid_header), do: 0
  defp status_byte(:failed), do: 1

  defp load_canonical(idx, kv) do
    rows =
      KV.fold_prefix(kv, :headers, <<>>, [], fn
        {k, <<h::32, s, raw::binary-size(80)>>}, acc ->
          [{h, s, k, raw} | acc]

        {k, bad}, _acc ->
          StorageError.raise_and_latch!(
            kv.guard,
            :headers,
            {:corrupt_header_row, k, byte_size(bad)},
            "header store corrupt: invalid header row length #{byte_size(bad)}"
          )
      end)

    case KV.get(kv, :meta, @headers_count_key) do
      {:ok, <<expected::32>>} when expected != length(rows) ->
        StorageError.raise_and_latch!(
          kv.guard,
          :headers,
          {:headers_count_mismatch, length(rows), expected},
          "header store scan returned #{length(rows)} row(s), expected #{expected}"
        )

      {:ok, bad} when byte_size(bad) != 4 ->
        StorageError.raise_and_latch!(
          kv.guard,
          :headers,
          {:corrupt_headers_count, byte_size(bad)},
          "corrupt headers_count metadata"
        )

      _ ->
        :ok
    end

    rows
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.reduce(idx, fn {h, s, k, raw}, idx ->
      if Index.lookup(idx, k) do
        idx
      else
        hdr = Header.decode_with_hash(raw, k)
        prev = Index.lookup(idx, hdr.prev_hash)

        if prev == nil do
          StorageError.raise_and_latch!(
            kv.guard,
            :headers,
            {:missing_parent, k, hdr.prev_hash},
            "header store corrupt: missing parent for header at height #{h}"
          )
        end

        e = Index.make_entry(hdr, prev)
        # Core LoadBlockIndex (blockstorage.cpp): a child of a failed block
        # is failed; failed entries never become the best header (insert/2).
        failed = s == 1 or prev.status == :failed
        Index.insert(idx, %{e | status: if(failed, do: :failed, else: :valid_header)})
      end
    end)
  end

  # Ephemeral ahead-of-tip headers cached in staging/: non-authoritative,
  # skipped if already present in canonical or if parent is absent.
  defp load_staging(idx, staging_kv) do
    staging_kv
    |> KV.fold_prefix(:headers_cache, <<>>, [], fn
      {k, <<h::32, s, raw::binary-size(80)>>}, acc -> [{h, s, k, raw} | acc]
      _, acc -> acc
    end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.reduce(idx, fn {_h, s, k, raw}, idx ->
      if Index.lookup(idx, k) do
        idx
      else
        hdr = Header.decode_with_hash(raw, k)

        case Index.lookup(idx, hdr.prev_hash) do
          nil ->
            idx

          prev ->
            e = Index.make_entry(hdr, prev)
            failed = s == 1 or prev.status == :failed
            Index.insert(idx, %{e | status: if(failed, do: :failed, else: :valid_header)})
        end
      end
    end)
  end
end
