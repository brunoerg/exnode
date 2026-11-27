defmodule Mix.Tasks.Exnode.Restore do
  @shortdoc "Restore a dirty or faulted store from its latest quiescent snapshot"
  @moduledoc """
  Restores a store that did not close cleanly (left `flush.lock` on disk after
  a crash or power loss) back to an exact prior quiescent state from its latest
  complete snapshot (`snapshots/primary`, falling back to `snapshots/secondary`):

      mix exnode.restore --chain testnet4 --datadir ~/exnode-testnet4
      mix exnode.restore --chain mainnet --datadir ~/exnode --datadir-cold /mnt/hdd/exnode

  If the store halted after a latched storage fault (disk I/O error, checksum
  mismatch, archive corruption), investigate hardware and storage health first.
  Local snapshots hard-link immutable SST files on the same volume and share
  the append-only segment files, so `--force-from-snapshot` cannot recover from
  damaged storage media or corrupted SST/segment data (relinking the same files
  will hit the same fault). Use `--force-from-snapshot` only after confirming a
  non-media fault; for media faults, replace failing hardware and resync from
  the network or restore an independent off-volume backup:

      mix exnode.restore --chain testnet4 --datadir ~/exnode-testnet4 --force-from-snapshot

  Run only with the node stopped.
  """
  use Mix.Task

  @impl true
  def run(argv), do: Exnode.CLI.restore(argv)
end
