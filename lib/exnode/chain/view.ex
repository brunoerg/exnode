defmodule Exnode.Chain.View do
  @moduledoc """
  Lock-free public ETS view (`:chain_view`) of a `Chain.State`'s tip,
  committed height, read-only `Archive.reader/1`, held/quarantined block
  hashes, halt state and latched IBD status.

  Published in `:persistent_term` under `{Exnode.Chain.State, name}` when the
  chain state is registered by name so RPC, REST, index followers and peers
  read it without calling into the chain-state process.
  """

  alias Exnode.Archive
  alias Exnode.Chain.HeaderIndex

  @pt_ns Exnode.Chain.State

  @doc "Creates the `:chain_view` ETS table and publishes it if `name` is given."
  def new(kv, name \\ nil) do
    t = :ets.new(:chain_view, [:set, :public, read_concurrency: true])
    :ets.insert(t, [{:kv, kv}, {:halted, false}])
    if name, do: :persistent_term.put({@pt_ns, name}, t)
    t
  end

  @doc """
  The chain view ETS handle for `server` (must be a registered atom name),
  or `nil` if none is published.
  """
  def view(server) when is_atom(server), do: :persistent_term.get({@pt_ns, server}, nil)

  @doc "A read-only archive (committed blocks only) for serving, from the view."
  def view_reader(nil), do: exit({:noproc, {Exnode.Chain.State, :view_reader, [nil]}})

  def view_reader(view) do
    :ets.lookup_element(view, :reader, 2)
  rescue
    ArgumentError -> exit({:noproc, {Exnode.Chain.State, :view_reader, [view]}})
  end

  @doc """
  The read-only archive of `server`'s committed chain, without a call into
  the chain-state process. Its `Archive.tip/1` is the committed tip.
  """
  def reader(server), do: view_reader(view(server))

  @doc "Height of the last committed (durable) tip, from the view."
  def view_committed(view), do: :ets.lookup_element(view, :committed, 2)

  @doc "Halt reason (`false` if none), from the view."
  def view_halted(view), do: :ets.lookup_element(view, :halted, 2)

  @doc "Active tip from the view (no call into the chain-state process)."
  def view_tip(view), do: :ets.lookup_element(view, :tip, 2)

  @doc """
  Core `IsInitialBlockDownload`, the one answer for peers and RPC: the
  tip's work is below the chain's minimum, or the tip is older than 24 h
  at `now` (seconds). Once false it stays false for this chain state's
  life (Core `m_cached_finished_ibd`), latched in the view.
  """
  def view_ibd?(view, idx, now, params) do
    if :ets.member(view, :ibd_done) do
      false
    else
      ibd =
        case HeaderIndex.lookup(idx, view_tip(view).hash) do
          nil -> true
          e -> e.chain_work < params.minimum_chain_work or e.time < now - 24 * 3600
        end

      if not ibd, do: :ets.insert(view, {:ibd_done, true})
      ibd
    end
  end

  @doc """
  Whether `hash`'s block data is held in memory, archived (see
  `Archive.have_block_data?/2`), or quarantined (no call).
  """
  def view_have?(view, hash) do
    :ets.member(view, {:held, hash}) or :ets.member(view, {:quarantined, hash}) or
      Archive.have_block_data?(view_reader(view), hash)
  end

  @doc """
  Subset of `hashes` whose block data is held in memory, archived (see
  `Archive.have_block_data?/2`), or quarantined (no call).
  """
  def view_have_many(view, hashes) do
    reader = view_reader(view)

    MapSet.new(
      Enum.filter(hashes, fn h ->
        :ets.member(view, {:held, h}) or :ets.member(view, {:quarantined, h}) or
          Archive.have_block_data?(reader, h)
      end)
    )
  end

  # --- writer updates (owned by Chain.State) -----------------------------------

  @doc false
  def publish(view, %Archive{} = a) do
    :ets.insert(view, [
      {:tip, Archive.tip(a)},
      {:committed, Archive.committed_tip(a).height},
      {:reader, Archive.reader(a)}
    ])

    :ok
  end

  @doc false
  def put_tip(view, tip) do
    :ets.insert(view, {:tip, tip})
    :ok
  end

  @doc false
  def put_committed(view, %Archive{} = a) do
    :ets.insert(view, [
      {:committed, Archive.committed_tip(a).height},
      {:reader, Archive.reader(a)}
    ])

    :ok
  end

  @doc false
  def put_halted(view, halted) do
    :ets.insert(view, {:halted, halted})
    :ok
  end

  @doc false
  def hold(view, hash) do
    :ets.insert(view, {{:held, hash}})
    :ok
  end

  @doc false
  def hold_many(view, hashes) do
    for h <- hashes, do: :ets.insert(view, {{:held, h}})
    :ok
  end

  @doc false
  def unhold(view, hash) do
    :ets.delete(view, {:held, hash})
    :ok
  end

  @doc false
  def unhold_many(view, hashes) do
    for h <- hashes, do: :ets.delete(view, {:held, h})
    :ok
  end

  @doc false
  def quarantine(view, hash) do
    :ets.delete(view, {:held, hash})
    :ets.insert(view, {{:quarantined, hash}})
    :ok
  end

  @doc false
  def quarantine_many(view, hashes) do
    for h <- hashes, do: :ets.insert(view, {{:quarantined, h}})
    :ok
  end

  @doc false
  def unquarantine_many(view, hashes) do
    for h <- hashes, do: :ets.delete(view, {:quarantined, h})
    :ok
  end
end
