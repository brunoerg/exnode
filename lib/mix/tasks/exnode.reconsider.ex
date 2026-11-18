defmodule Mix.Tasks.Exnode.Reconsider do
  @shortdoc "List or clear quarantined blocks and a shadow-divergence halt"
  @moduledoc """
  Lists, or clears, the blocks the chain state quarantined because
  connecting them raised an exception (see `Exnode.Chain.State`). Run it
  with the node stopped:

      mix exnode.reconsider --chain testnet4 --datadir ~/exnode-testnet4          # list
      mix exnode.reconsider --chain testnet4 --datadir ~/exnode-testnet4 --all    # clear all
      mix exnode.reconsider --chain testnet4 --datadir ~/exnode-testnet4 <hash>   # clear one

  A shadow divergence halts block connection durably (it survives restarts,
  with or without `--shadow`). The listing shows it; clear it only once you
  have decided which engine was wrong (records in the shadow's
  `divergences/`):

      mix exnode.reconsider --chain testnet4 --datadir ~/exnode-testnet4 --clear-halt

  On a running node, `Exnode.Chain.State.clear_halt/1` does the same.

  Crash reports are in `<datadir>/<chain>/crashes/<hash>.log`. Clear a mark
  only once the cause is fixed: at the next start the block is connected
  again from its kept `pending` copy (or downloaded again). On a running
  node, `Exnode.Chain.State.reconsider_poisoned/2` does the same.
  """
  use Mix.Task

  @impl true
  def run(argv), do: Exnode.CLI.reconsider(argv)
end
