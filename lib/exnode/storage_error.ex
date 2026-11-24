defmodule Exnode.StorageError do
  @moduledoc """
  Raised when local storage (archive segments, index records or header rows)
  cannot be read, written, synced or decoded cleanly.

  Treated as a fatal host/storage fault (`AbortNode` / `FatalError` in Core)
  rather than a verdict on the block being validated: `Chain.State` never
  quarantines a block for `Exnode.StorageError`.
  """

  defexception [:message, :reason, :source]
end
