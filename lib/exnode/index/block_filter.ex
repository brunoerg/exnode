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
  @fallback_tick_ms 5_000
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
        :error -> Runtime.kv(Keyword.fetch!(opts, :node_name))
      end

    if name = opts[:name], do: Runtime.put_handle({__MODULE__, name}, kv)
    chain_state = Keyword.fetch!(opts, :chain_state)

    st = %{
      kv: kv,
      chain_state: chain_state,
      waiters: [],
      writer_mon: nil,
      sync_queued: false,
      fallback_timer: nil
    }

    st = st |> maybe_subscribe() |> schedule_sync(0)
    {:ok, st}
  end

  @impl true
  def handle_call(:kv, _from, st), do: {:reply, st.kv, st}
  def handle_call(:tip, _from, st), do: {:reply, Follower.tip(st.kv, @cf), st}

  def handle_call({:sync_to, hash}, from, st) do
    if lookup(st.kv, hash) != :not_found,
      do: {:reply, :ok, st},
      else: {:noreply, %{st | waiters: [{hash, from} | st.waiters]} |> schedule_sync(0)}
  end

  @impl true
  def handle_info({:archive_committed, _tip}, st), do: {:noreply, schedule_sync(st, 0)}
  def handle_info({:archive_disconnected, _tip}, st), do: {:noreply, schedule_sync(st, 0)}

  def handle_info(:fallback_tick, st) do
    st = %{st | fallback_timer: nil} |> maybe_subscribe()
    {:noreply, schedule_sync(st, 0)}
  end

  def handle_info(:tick, st) do
    st = %{st | sync_queued: false} |> maybe_subscribe()

    result =
      try do
        Follower.sync(
          st.kv,
          @cf,
          st.chain_state,
          &connect(st.kv, &1, &2, &3, &4),
          fn _, _, _ -> [] end,
          %{}
        )
      catch
        kind, reason ->
          # The chain view may not exist yet at startup; anything else is logged.
          if ChainState.view(st.chain_state) != nil,
            do: Logger.warning("filter index: #{inspect(kind)} #{inspect(reason, limit: 5)}")

          :done
      end

    backfill(st.kv)

    waiters =
      Enum.reject(st.waiters, fn {h, from} ->
        lookup(st.kv, h) != :not_found and GenServer.reply(from, :ok) == :ok
      end)

    st = %{st | waiters: waiters}

    st =
      if result == :more do
        schedule_sync(st, 0)
      else
        ensure_fallback_timer(st)
      end

    {:noreply, st}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{writer_mon: ref} = st) do
    # Archive.Writer restarted; clear subscription so next tick/fallback re-subscribes.
    {:noreply, %{st | writer_mon: nil} |> ensure_fallback_timer()}
  end

  def handle_info(_msg, st), do: {:noreply, st}

  defp maybe_subscribe(%{writer_mon: ref} = st) when is_reference(ref), do: st

  defp maybe_subscribe(st) do
    try do
      case ChainState.subscribe_commits(st.chain_state) do
        {:ok, writer_pid} -> %{st | writer_mon: Process.monitor(writer_pid)}
        _ -> st
      end
    catch
      :exit, _ -> st
    end
  end

  defp schedule_sync(%{sync_queued: true} = st, _ms), do: st

  defp schedule_sync(st, 0) do
    send(self(), :tick)
    %{st | sync_queued: true}
  end

  defp ensure_fallback_timer(%{fallback_timer: ref} = st) when is_reference(ref), do: st

  defp ensure_fallback_timer(st) do
    ref = Process.send_after(self(), :fallback_tick, @fallback_tick_ms)
    %{st | fallback_timer: ref}
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
  defp connect(kv, height, id, reader, batch_headers) do
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
            Map.get(batch_headers, prev_hash) || raise("filter of the parent not indexed")
        end
      end

    header = BlockFilter.header(filter, prev_header)

    ops = [
      {:put, @cf, "f" <> rec.hash, header <> filter},
      {:put, @cf, "s" <> rec.hash, BlockFilter.filter_hash(filter) <> header}
    ]

    {ops, Map.put(batch_headers, rec.hash, header)}
  end
end
