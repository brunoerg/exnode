defmodule Mix.Tasks.Exnode.Restore do
  @shortdoc "Restore a dirty or faulted store from its latest quiescent snapshot"
  @moduledoc """
  Restores a store that did not close cleanly (left `flush.lock` on disk after
  a crash or power loss) back to an exact prior quiescent state from its latest
  complete snapshot (`snapshots/primary`, falling back to `snapshots/secondary`):

      mix exnode.restore --chain testnet4 --datadir ~/exnode-testnet4
      mix exnode.restore --chain mainnet --datadir ~/exnode --datadir-cold /mnt/hdd/exnode

  If the store halted after a latched storage fault (disk I/O error, checksum
  mismatch, archive corruption), investigate hardware/software first, then pass
  `--force-from-snapshot` to restore from the last known-good snapshot (or wipe
  and resync from the network):

      mix exnode.restore --chain testnet4 --datadir ~/exnode-testnet4 --force-from-snapshot

  Run only with the node stopped.
  """
  use Mix.Task

  @impl true
  def run(argv), do: Exnode.CLI.restore(argv)
end
