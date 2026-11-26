defmodule Exnode.Chain.Quarantine do
  @moduledoc """
  Block quarantine (`:poisoned` column family and crash-report writer),
  durable halt marks (`:meta` `"halt"`), and host-fault vs. local-bug
  classification for `Exnode.Chain.State`.

  Storage errors (`Exnode.StorageError`, `Exnode.Store.KV.Error`, or raw
  `:file` match failures inside `Segments`/`KV`) and native out-of-memory
  errors (`:enomem`, `:kernel_alloc`, `:kernel_txdata`) are fatal host
  faults (`AbortNode` in Core) and are never quarantined.
  """

  require Logger

  alias Exnode.Chain.View
  alias Exnode.Codec.Block
  alias Exnode.Crypto.Hash
  alias Exnode.StorageError
  alias Exnode.Store.KV

  @halt_key "halt"
  @poisoned_count_key "poisoned_count"
  @out_of_memory [:enomem, :kernel_alloc, :kernel_txdata]

  # --- durable halt mark -------------------------------------------------------

  @doc "The durable halt mark in `kv`: `%{reason, time, height, hash}` or `nil`."
  def halt_mark(kv) do
    case KV.get(kv, :meta, @halt_key) do
      {:ok, bin} ->
        try do
          :erlang.binary_to_term(bin)
        rescue
          e in ArgumentError ->
            StorageError.raise_and_latch!(
              kv.guard,
              :quarantine,
              {:corrupt_halt_mark, e},
              "corrupt halt mark in store metadata"
            )
        end

      :not_found ->
        nil
    end
  end

  @doc false
  def load_halt(kv, view) do
    case halt_mark(kv) do
      nil ->
        false

      m ->
        Logger.error(
          "block connection HALTED since #{m.time} at height #{m.height} " <>
            "(#{Hash.to_hex(m.hash)}): #{inspect(m.reason)}; not connecting blocks. " <>
            "See the shadow's divergences/ records; clear with ChainState.clear_halt/1 or " <>
            "mix exnode.reconsider --clear-halt once resolved"
        )

        View.put_halted(view, m.reason)
        m.reason
    end
  end

  @doc false
  def put_halt_mark(kv, view, reason, tip) do
    mark = %{reason: reason, time: System.os_time(:second), height: tip.height, hash: tip.hash}
    :ok = KV.write(kv, [{:put, :meta, @halt_key, :erlang.term_to_binary(mark)}], sync: true)
    View.put_halted(view, reason)
    mark
  end

  @doc false
  def clear_halt_mark(kv, view) do
    :ok = KV.write(kv, [{:delete, :meta, @halt_key}], sync: true)
    View.put_halted(view, false)
    :ok
  end

  # --- :poisoned marks & crash reports -----------------------------------------

  @doc false
  def load_poisoned(kv, view) do
    hashes = KV.fold_prefix(kv, :poisoned, <<>>, [], fn {k, _v}, acc -> [k | acc] end)

    case KV.get(kv, :meta, @poisoned_count_key) do
      {:ok, <<expected::32>>} when expected != length(hashes) ->
        StorageError.raise_and_latch!(
          kv.guard,
          :quarantine,
          {:poisoned_count_mismatch, length(hashes), expected},
          "poisoned scan returned #{length(hashes)} row(s), expected #{expected}"
        )

      _ ->
        :ok
    end

    if hashes != [] do
      Logger.warning(
        "#{length(hashes)} block(s) quarantined after a validation crash; not connecting them: " <>
          Enum.map_join(hashes, ", ", &Hash.to_hex/1) <>
          " (clear with ChainState.reconsider_poisoned/2 or mix exnode.reconsider once fixed)"
      )
    end

    View.quarantine_many(view, hashes)
    MapSet.new(hashes)
  end

  @doc false
  def mark_poisoned(kv, crash_dir, view, entry, block, error, msg, new_count \\ nil) do
    hash = entry.hash

    mark =
      :erlang.term_to_binary(%{
        height: entry.height,
        time: System.os_time(:second),
        error: inspect(error, limit: 50)
      })

    ops =
      [{:put, :poisoned, hash, mark}] ++
        if(is_integer(new_count), do: [{:put, :meta, @poisoned_count_key, <<new_count::32>>}], else: [])

    :ok = KV.write(kv, ops, sync: true)
    write_crash_report(kv, crash_dir, entry, block, msg)
    View.quarantine(view, hash)
    :ok
  end

  @doc false
  def clear_poisoned(kv, view, poisoned, which) do
    hashes =
      if which == :all,
        do: MapSet.to_list(poisoned),
        else: Enum.filter([which], &MapSet.member?(poisoned, &1))

    remaining = MapSet.difference(poisoned, MapSet.new(hashes))

    ops =
      for(h <- hashes, do: {:delete, :poisoned, h}) ++
        [{:put, :meta, @poisoned_count_key, <<MapSet.size(remaining)::32>>}]

    :ok = KV.write(kv, ops, sync: true)
    View.unquarantine_many(view, hashes)
    for h <- hashes, do: Logger.warning("quarantine cleared for block #{Hash.to_hex(h)}")
    {hashes, remaining}
  end

  @doc false
  def crash_message({kind, reason}, stack) when kind in [:exit, :throw, :error],
    do: Exception.format(kind, reason, stack)

  def crash_message(e, stack), do: Exception.format(:error, e, stack)

  @doc false
  def write_crash_report(kv, crash_dir, entry, block, msg) do
    raw =
      case block do
        %Block{raw: raw} when is_binary(raw) ->
          raw

        _ ->
          case KV.get(kv, :pending, entry.hash) do
            {:ok, raw} -> raw
            _ -> <<>>
          end
      end

    File.mkdir_p!(crash_dir)
    hex = Hash.to_hex(entry.hash)

    File.write!(Path.join(crash_dir, hex <> ".log"), """
    block: #{hex}
    height: #{entry.height}
    time: #{DateTime.utc_now() |> DateTime.to_iso8601()}

    #{msg}

    block hex:
    #{Base.encode16(raw, case: :lower)}
    """)
  rescue
    e -> Logger.error("could not write crash report: #{Exception.message(e)}")
  end

  # --- host-fault classification -----------------------------------------------

  @doc false
  def raise_if_host_fault({:crash, error, stack}) do
    {kind, reason} =
      case error do
        {kind, reason} when kind in [:error, :exit, :throw] -> {kind, reason}
        exception -> {:error, exception}
      end

    if host_fault?(kind, reason, stack), do: :erlang.raise(kind, reason, stack)
    :ok
  end

  @doc """
  True when `{kind, reason, stack}` is a host fault (storage or out-of-memory)
  rather than a bug triggered by the block being validated.
  """
  def host_fault?(kind, reason, stack),
    do: storage_failure?(reason, stack) or out_of_memory?(kind, reason)

  @doc """
  True when `reason` / `stack` comes from a storage failure (`Exnode.StorageError`,
  `Exnode.Store.KV.Error`, or a failure inside `Segments` / `KV`).
  """
  def storage_failure?(%Exnode.StorageError{}, _stack), do: true
  def storage_failure?(%KV.Error{}, _stack), do: true

  def storage_failure?(_reason, stack) do
    case Enum.find(stack, fn {m, _, _, _} ->
           String.starts_with?(Atom.to_string(m), "Elixir.Exnode.")
         end) do
      {m, _, _, _} -> m in [Exnode.Archive.Segments, KV]
      nil -> false
    end
  end

  defp out_of_memory?(:error, %ErlangError{original: r}), do: r in @out_of_memory
  defp out_of_memory?(:error, r), do: r in @out_of_memory
  defp out_of_memory?(_kind, _reason), do: false
end
