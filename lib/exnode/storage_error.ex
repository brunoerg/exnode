defmodule Exnode.StorageError do
  @moduledoc """
  Raised when local storage (archive segments, index records or header rows)
  cannot be read, written, synced or decoded cleanly.

  Treated as a fatal host/storage fault (`AbortNode` / `FatalError` in Core)
  rather than a verdict on the block being validated: `Chain.State` never
  quarantines a block for `Exnode.StorageError`.
  """

  defexception [:message, :reason, :source, latched: false]

  @doc """
  Latches the fault on `guard` (if provided) and immediately raises
  `Exnode.StorageError`.
  """
  @spec raise_and_latch!(Exnode.Store.Guard.t() | nil, atom(), term(), String.t()) :: no_return()
  def raise_and_latch!(guard, source, reason, message) do
    Exnode.Store.Guard.latch_fault(guard, source, reason, message)

    raise __MODULE__,
      source: source,
      reason: reason,
      message: message,
      latched: guard != nil
  end
end
