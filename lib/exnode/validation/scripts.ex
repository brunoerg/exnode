defmodule Exnode.Validation.Scripts do
  @moduledoc """
  Block script verification. Core v32.1 `CheckInputScripts` / `CScriptCheck`,
  executed by the kernel (`Exnode.Kernel.verify_tx`).

  Every non-coinbase tx of a block is checked with the block's flags, one
  kernel NIF call per tx (the kernel shares its precomputed tx data across
  the tx's inputs). The chain state sends a block's txs in chunks of
  `chunk_size/0` to the node's shared executor (`Exnode.Validation.ScriptExec`);
  `verify_all/2` is the standalone form (callers outside a node).

  Outcomes are classified (`classify/1`), because only one of them proves
  anything about the block:
  * `:ok`, every input verified;
  * `{:invalid, reason}`: the kernel ran the script and it failed. This is
    Core's `block-script-verify-flag-failed` (the kernel does not expose the
    ScriptError, so Core's ` (<ScriptErrorString>)` suffix cannot be
    reproduced);
  * `{:local, reason}`: the kernel could not run the check (a status error,
    an argument it rejected, a tx it could not parse that exnode decoded).
    That is our bug or bad local data, never proof that a peer sent an
    invalid block: the chain state quarantines the block (as for a crash)
    instead of marking its header failed or punishing its source.
  """
  alias Exnode.Kernel

  @chunk 32

  @doc "Txs per executor job (fixed-size chunks; cost-aware chunking is a later measured change)."
  def chunk_size, do: @chunk

  @doc """
  Classifies one `Exnode.Kernel.verify_tx_all/3` result. `{:error, {i,
  :invalid}}` is the only script failure; every other error is local.
  """
  def classify(:ok), do: :ok
  def classify({:error, {_i, :invalid}}), do: {:invalid, "block-script-verify-flag-failed"}
  def classify({:error, {i, {:error, status}}}), do: {:local, {:kernel_status, i, status}}
  def classify({:error, reason}), do: {:local, {:kernel_api, reason}}

  @doc """
  Verifies a chunk of `{raw_tx, [{script_pubkey, value}]}` jobs with `flags`.
  The first proven failure stops the chunk; a local error is remembered
  but the chunk continues, since a later tx may still prove the block
  invalid (proof outranks a local error). Returns `:ok`, `{:invalid, r}` or
  `{:local, r}`.
  """
  def check_chunk(checks, flags) do
    Enum.reduce_while(checks, :ok, fn {raw, spent}, acc ->
      case classify(Kernel.verify_tx_all(raw, spent, flags)) do
        :ok -> {:cont, acc}
        {:invalid, _} = inv -> {:halt, inv}
        {:local, _} = l -> {:cont, if(acc == :ok, do: l, else: acc)}
      end
    end)
  end

  @doc """
  Combines chunk outcomes of one block: any proven failure wins, then any
  local error (or crash), else `:ok`.
  """
  def combine(outcomes) do
    cond do
      inv = Enum.find(outcomes, &match?({:invalid, _}, &1)) -> inv
      loc = Enum.find(outcomes, &(&1 != :ok)) -> loc
      true -> :ok
    end
  end

  defmodule LocalError do
    @moduledoc "A kernel API/status error: the check could not run (not a consensus failure)."
    defexception [:reason]
    @impl true
    def message(%{reason: r}), do: "script check could not run: #{inspect(r)}"
  end

  @doc """
  Standalone verification (no executor): `:ok` or
  `{:error, {:consensus, "block-script-verify-flag-failed"}}`. A local
  error raises `LocalError`, so a caller's crash containment (quarantine)
  applies instead of a consensus verdict. Runs chunks with
  `Task.async_stream` on the calling node's schedulers; inside a node the
  chain state uses the shared executor instead.
  """
  def verify_all(checks, flags) do
    checks
    |> Enum.chunk_every(@chunk)
    |> Task.async_stream(&check_chunk(&1, flags),
      max_concurrency: System.schedulers_online(),
      ordered: false,
      timeout: :infinity
    )
    |> Enum.map(fn {:ok, r} -> r end)
    |> combine()
    |> case do
      :ok -> :ok
      {:invalid, r} -> {:error, {:consensus, r}}
      {:local, r} -> raise LocalError, reason: r
    end
  end
end
