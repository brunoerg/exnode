defmodule Exnode.P2P.BlockServing do
  @moduledoc """
  Node-wide, byte-bounded LRU of serialized block responses. Core's
  `ProcessGetBlockData` also shares its most recent block/compact block.
  Repeated getdata requests must not reconstruct and SipHash a block again
  in every peer. Concurrent requests for one key build it once (the later
  callers wait for that build); callers wait with TCP backpressure,
  independently of chain validation.

  Builds run in worker processes, never in this server: a
  cache hit is answered at once whatever is being built. At most
  `max_builders` ordinary builds run at a time, further misses queue;
  `priority` builds (near-tip blocks: compact announcements, getblocktxn,
  fresh getdata) skip the queue, so peers requesting old blocks cannot
  delay block propagation. Near-tip keys are few, so this bounds them too.

  Only serialized binaries are retained, never decoded transactions or
  archive views. Peers check active-chain membership, pruning and serving
  depth on every request, including cache hits. The five recent compact
  responses have reserved slots: cheap historical requests cannot evict
  them and force repeated SipHash passes over near-tip blocks.
  """
  use GenServer

  alias Exnode.Archive
  alias Exnode.Archive.Segments
  alias Exnode.Codec.Block
  alias Exnode.P2P.CompactBlock

  @max_entries 16
  @max_bytes 32 * 1024 * 1024

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  def get(server, reader, id, hash, format, decode \\ &Block.decode_exact/1, priority \\ false) do
    if server,
      do: GenServer.call(server, {:get, {hash, format}, reader, id, decode, priority}, :infinity),
      else: build(reader, id, format, decode)
  end

  @impl true
  def init(opts) do
    {task_sup, private_sup} =
      case Keyword.get(opts, :task_sup) do
        nil ->
          {:ok, sup} = Task.Supervisor.start_link()
          {sup, sup}

        sup ->
          {sup, nil}
      end

    {:ok,
     %{
       entries: %{},
       order: [],
       bytes: 0,
       max_entries: Keyword.get(opts, :max_entries, @max_entries),
       max_compact_entries: min(5, Keyword.get(opts, :max_entries, @max_entries)),
       max_bytes: Keyword.get(opts, :max_bytes, @max_bytes),
       # key => callers waiting for its build
       pending: %{},
       # monitor ref => {key, pid, priority, tag}
       builders: %{},
       # tag => monitor ref
       tags: %{},
       queue: :queue.new(),
       max_builders: Keyword.get(opts, :max_builders, max(2, System.schedulers_online())),
       task_sup: task_sup,
       private_sup: private_sup
     }}
  end

  @impl true
  def handle_call({:get, key, reader, id, decode, priority}, from, st) do
    case st.entries do
      %{^key => msg} ->
        {:reply, {:ok, msg}, %{st | order: [key | List.delete(st.order, key)]}}

      _ ->
        case st.pending do
          %{^key => waiters} ->
            {:noreply, %{st | pending: Map.put(st.pending, key, [from | waiters])}}

          _ ->
            st = %{st | pending: Map.put(st.pending, key, [from])}
            job = {key, reader, id, decode}

            st =
              if priority or ordinary_builders(st) < st.max_builders,
                do: start_build(st, job, priority),
                else: %{st | queue: :queue.in(job, st.queue)}

            {:noreply, st}
        end
    end
  end

  @impl true
  def handle_info({:build_done, tag, result}, st) do
    case Map.pop(st.tags, tag) do
      {nil, _} ->
        {:noreply, st}

      {mref, tags} ->
        Process.demonitor(mref, [:flush])
        {{key, _pid, _priority, _tag}, builders} = Map.pop!(st.builders, mref)
        finish_build(%{st | builders: builders, tags: tags}, key, result)
    end
  end

  def handle_info({:DOWN, mref, :process, _pid, _reason}, st) do
    case Map.pop(st.builders, mref) do
      {nil, _} ->
        {:noreply, st}

      {{key, _pid, _priority, tag}, builders} ->
        finish_build(%{st | builders: builders, tags: Map.delete(st.tags, tag)}, key, :notfound)
    end
  end

  def handle_info(_msg, st), do: {:noreply, st}

  @impl true
  def terminate(_reason, st) do
    for {mref, {_key, pid, _priority, _tag}} <- st.builders do
      try do
        Task.Supervisor.terminate_child(st.task_sup, pid)
      catch
        :exit, _ -> :ok
      end

      Process.demonitor(mref, [:flush])
    end

    if is_pid(st.private_sup) and Process.alive?(st.private_sup) do
      try do
        Supervisor.stop(st.private_sup, :shutdown, 5_000)
      catch
        :exit, _ -> :ok
      end
    end

    :ok
  end

  defp finish_build(st, key, reply) do
    {waiters, pending} = Map.pop(st.pending, key, [])
    for w <- waiters, do: GenServer.reply(w, reply)
    {:noreply, %{st | pending: pending} |> cache(key, reply) |> start_queued()}
  end

  defp start_build(st, {key, reader, id, decode}, priority) do
    {_, format} = key
    owner = self()
    tag = make_ref()

    {:ok, pid} =
      Task.Supervisor.start_child(st.task_sup, fn ->
        result =
          try do
            build(reader, id, format, decode)
          after
            Segments.close_all_readers()
          end

        send(owner, {:build_done, tag, result})
      end)

    mref = Process.monitor(pid)

    %{
      st
      | builders: Map.put(st.builders, mref, {key, pid, priority, tag}),
        tags: Map.put(st.tags, tag, mref)
    }
  end

  defp ordinary_builders(st), do: Enum.count(st.builders, fn {_, {_, _, p, _}} -> not p end)

  defp start_queued(st) do
    if ordinary_builders(st) < st.max_builders do
      case :queue.out(st.queue) do
        {{:value, job}, q} -> start_queued(start_build(%{st | queue: q}, job, false))
        {:empty, _} -> st
      end
    else
      st
    end
  end

  defp cache(st, key, {:ok, {_, payload} = msg}) do
    if byte_size(payload) <= st.max_bytes and st.max_entries > 0 and
         not Map.has_key?(st.entries, key) do
      evict(%{
        st
        | entries: Map.put(st.entries, key, msg),
          order: [key | st.order],
          bytes: st.bytes + byte_size(payload)
      })
    else
      st
    end
  end

  defp cache(st, _key, _), do: st

  defp evict(st) do
    {compact, other} = Enum.split_with(st.order, fn {_, format} -> format == :compact end)

    key =
      cond do
        length(compact) > st.max_compact_entries -> List.last(compact)
        st.bytes <= st.max_bytes and map_size(st.entries) <= st.max_entries -> nil
        true -> List.last(other) || List.last(compact)
      end

    if key do
      {{_, payload}, entries} = Map.pop(st.entries, key)

      evict(%{
        st
        | entries: entries,
          order: List.delete(st.order, key),
          bytes: st.bytes - byte_size(payload)
      })
    else
      st
    end
  end

  # Core: ProcessGetBlockData / CBlockHeaderAndShortTxIDs (net_processing.cpp).
  # A corrupt/unavailable archive read is not allowed to kill the shared cache.
  defp build(reader, id, format, decode) do
    with raw when is_binary(raw) <- Archive.read_block(reader, id) do
      msg =
        case format do
          :witness ->
            {:block, raw}

          :stripped ->
            {:ok, b} = decode.(raw)
            {:block, IO.iodata_to_binary(Block.encode(b, witness: false))}

          :compact ->
            {:ok, b} = decode.(raw)

            {:cmpctblock,
             CompactBlock.encode(CompactBlock.from_block(b, :rand.uniform(0xFFFFFFFFFFFFFFFF)))}
        end

      {:ok, msg}
    else
      _ -> :notfound
    end
  rescue
    _ -> :notfound
  end
end
