defmodule Exnode.Node.Handles do
  @moduledoc """
  Permanent owner of the VM-wide `Exnode.Handles` ETS table under
  `Exnode.Supervisor`.

  Creating `Exnode.Handles` inside a long-lived child process guarantees the
  table is not tied to the short-lived `application_master` starter process or
  to any transient caller process. If a caller created `Exnode.Handles` before
  `:exnode` started, this process monitors the existing owner and recreates the
  table as soon as that owner exits.
  """
  use GenServer

  @table Exnode.Handles

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(_opts) do
    {:ok, ensure_owned()}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{owner_ref: ref}) do
    {:noreply, ensure_owned()}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp ensure_owned do
    case :ets.whereis(@table) do
      :undefined ->
        create_or_watch()

      _tid ->
        watch_existing_owner()
    end
  end

  defp create_or_watch do
    try do
      :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
      %{owner_ref: nil}
    rescue
      ArgumentError -> watch_existing_owner()
    end
  end

  defp watch_existing_owner do
    case :ets.info(@table, :owner) do
      pid when pid == self() ->
        %{owner_ref: nil}

      pid when is_pid(pid) ->
        %{owner_ref: Process.monitor(pid)}

      :undefined ->
        create_or_watch()
    end
  end
end
