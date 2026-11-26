defmodule Exnode.Index.BlockFilter do
  @moduledoc """
  BIP157/158 basic filter index (Core v32.1 `index/blockfilterindex.cpp`).
  For each block on the active chain, the filter and its filter header are
  stored by block hash (`<<"f", hash>>` -> `<<header::32-bytes, filter>>`),
  so blocks that a reorg disconnects keep theirs, as Core's index does. The
  `Exnode.Index.Follower` keeps it in step with the committed chain.

  Next to each filter, `<<"s", hash>>` -> `<<filter_hash::32-bytes,
  header::32-bytes>>` (Core's DBVal keeps hash and header apart from the
  filter): getcfheaders / getcfcheckpt read only these 64 bytes, never whole
  filters. An index built before this record existed is
  backfilled in the background (cursor `"sfill"`); until then a missing
  record falls back to the filter.

  Reads run in the caller's process (RocksDB is safe for concurrent
  readers), not in this server, which only builds the index.
  """
  use GenServer
  require Logger

  alias Exnode.Chain.State, as: ChainState

  alias Exnode.{Archive, BlockFilter}
  alias Exnode.Index.Follower
  alias Exnode.Node.Runtime
  alias Exnode.Store.KV

  @cf :filters
  @tick_ms 200
  # Blocks backfilled per tick (see moduledoc).
  @backfill_batch 2_000

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc "`{:ok, filter, header}`, or `:not_found`."
  def get(server, hash), do: lookup(kv(server), hash)

  @doc "One ordered multi_get for a BIP157 request, including missing entries: `{:ok, filter, header} | :not_found`."
  def get_many(_server, []), do: []

  def get_many(server, hashes),
    do: KV.multi_get(kv(server), @cf, Enum.map(hashes, &("f" <> &1))) |> Enum.map(&decode/1)

  @doc """
  `{:ok, filter_hash, header} | :not_found` per hash, in order, without
  reading the filters (except for blocks not yet backfilled).
  """
  def get_headers(_server, []), do: []

  def get_headers(server, hashes) do
    kv = kv(server)
    found = KV.multi_get(kv, @cf, Enum.map(hashes, &("s" <> &1)))

    case for({h, :not_found} <- Enum.zip(hashes, found), do: h) do
      [] ->
        Enum.map(found, &decode_summary/1)

      missing ->
        fallback = Map.new(Enum.zip(missing, get_many(server, missing)))

        for {h, r} <- Enum.zip(hashes, found) do
          case {r, fallback[h]} do
            {{:ok, _} = ok, _} -> decode_summary(ok)
            {:not_found, {:ok, f, header}} -> {:ok, Exnode.BlockFilter.filter_hash(f), header}
            {:not_found, _} -> :not_found
          end
        end
    end
  end

  # The KV handle, published by init/1 under the registered name (stable
  # across restarts) or, unnamed, the pid.
  defp kv(server) when is_atom(server) do
    case Runtime.get_handle({__MODULE__, server}, nil) do
      nil -> GenServer.call(server, :kv)
      kv -> kv
    end
  end

  defp kv(server), do: GenServer.call(server, :kv)

  @doc "Indexed tip `{height, hash}`."
  def tip(server), do: GenServer.call(server, :tip)

  @doc "Waits until the index reaches `hash` (tests, RPC)."
  def sync_to(server, hash, timeout \\ 30_000),
    do: GenServer.call(server, {:sync_to, hash}, timeout)

  @impl true
  def init(opts) do
    kv =
      case Keyword.fetch(opts, :kv) do
        {:ok, kv} -> kv
        :error -> Runtime.derived_kv(Keyword.fetch!(opts, :node_name))
      end

    if name = opts[:name], do: Runtime.put_handle({__MODULE__, name}, kv)

    send(self(), :tick)
    {:ok, %{kv: kv, chain_state: Keyword.fetch!(opts, :chain_state), waiters: []}}
  end

  @impl true
  def handle_call(:kv, _from, st), do: {:reply, st.kv, st}
  def handle_call(:tip, _from, st), do: {:reply, Follower.tip(st.kv, @cf), st}

  def handle_call({:sync_to, hash}, from, st) do
    if lookup(st.kv, hash) != :not_found,
      do: {:reply, :ok, st},
      else: {:noreply, %{st | waiters: [{hash, from} | st.waiters]}}
  end

  @impl true
  def handle_info(:tick, st) do
    result =
      try do
        Follower.sync(st.kv, @cf, st.chain_state, &connect(st.kv, &1, &2, &3), fn _, _, _ ->
          []
        end)
      catch
        kind, reason ->
          # The chain view may not exist yet at startup; anything else is logged.
          if ChainState.view(st.chain_state) != nil,
            do: Logger.warning("filter index: #{inspect(kind)} #{inspect(reason, limit: 5)}")

          :done
      end

    for {{:filter_header, _} = k, _} <- Process.get(), do: Process.delete(k)
    backfill(st.kv)

    waiters =
      Enum.reject(st.waiters, fn {h, from} ->
        lookup(st.kv, h) != :not_found and GenServer.reply(from, :ok) == :ok
      end)

    Process.send_after(self(), :tick, if(result == :more, do: 0, else: @tick_ms))
    {:noreply, %{st | waiters: waiters}}
  end

  defp lookup(kv, hash) do
    decode(KV.get(kv, @cf, "f" <> hash))
  end

  defp decode({:ok, <<header::binary-size(32), filter::binary>>}), do: {:ok, filter, header}
  defp decode(:not_found), do: :not_found

  defp decode_summary({:ok, <<fh::binary-size(32), header::binary-size(32)>>}),
    do: {:ok, fh, header}

  # Writes the missing summary records of an index built before they existed,
  # @backfill_batch heights per tick, from the cursor up to the indexed tip.
  defp backfill(kv) do
    case KV.get(kv, @cf, "sfill") do
      {:ok, "done"} ->
        :ok

      cursor ->
        from = with {:ok, <<h::32>>} <- cursor, do: h, else: (_ -> 0)
        {tip, _} = Follower.tip(kv, @cf)
        to = min(tip, from + @backfill_batch - 1)

        hashes = for h <- from..to//1, hash = Follower.hash_at(kv, @cf, h), hash != nil, do: hash
        have = KV.multi_get(kv, @cf, Enum.map(hashes, &("s" <> &1)))

        ops =
          for {hash, :not_found} <- Enum.zip(hashes, have),
              {:ok, f, header} <- [lookup(kv, hash)],
              do: {:put, @cf, "s" <> hash, Exnode.BlockFilter.filter_hash(f) <> header}

        next = if to >= tip, do: "done", else: <<to + 1::32>>
        :ok = KV.write(kv, ops ++ [{:put, @cf, "sfill", next}], sync: false)
    end
  end

  # Builds the block's filter; its header chains on the parent's.
  defp connect(kv, height, id, reader) do
    rec = Archive.block_record!(reader, id)
    {outs, spent} = Archive.block_scripts(reader, id)
    filter = BlockFilter.build(rec.hash, outs, spent)

    prev_header =
      if height == 0 do
        <<0::256>>
      else
        prev_hash = Archive.block_record!(reader, rec.prev_id).hash

        case lookup(kv, prev_hash) do
          {:ok, _, h} ->
            h

          :not_found ->
            Process.get({:filter_header, prev_hash}) || raise("filter of the parent not indexed")
        end
      end

    header = BlockFilter.header(filter, prev_header)
    # Within one batch the parent's header is not in the KV yet.
    Process.put({:filter_header, rec.hash}, header)

    [
      {:put, @cf, "f" <> rec.hash, header <> filter},
      {:put, @cf, "s" <> rec.hash, BlockFilter.filter_hash(filter) <> header}
    ]
  end
end
