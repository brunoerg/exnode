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

  alias Exnode.Crypto.Hash
  alias Exnode.Store.KV

  @impl true
  def run(argv) do
    {opts, args} =
      OptionParser.parse!(argv,
        strict: [chain: :string, datadir: :string, all: :boolean, clear_halt: :boolean]
      )

    chain = Keyword.get(opts, :chain, "mainnet")
    datadir = opts |> Keyword.get(:datadir, "~/.exnode") |> Path.expand()
    {:ok, kv} = KV.open(Path.join([datadir, chain, "index"]))

    clear_halt? = Keyword.get(opts, :clear_halt, false)

    case Exnode.Chain.State.halt_mark(kv) do
      nil ->
        Mix.shell().info("block connection not halted")

      m when clear_halt? ->
        :ok = KV.write(kv, [{:delete, :meta, "halt"}], sync: true)
        Mix.shell().info("cleared halt: #{inspect(m.reason)} (height #{m.height})")

      m ->
        Mix.shell().info(
          "HALTED since #{m.time} at height #{m.height} (#{Hash.to_hex(m.hash)}): #{inspect(m.reason)} " <>
            "(clear with --clear-halt)"
        )
    end

    marks =
      KV.fold_prefix(kv, :poisoned, <<>>, [], fn {k, v}, acc ->
        [{k, :erlang.binary_to_term(v)} | acc]
      end)

    targets =
      cond do
        opts[:all] -> Enum.map(marks, &elem(&1, 0))
        args != [] -> Enum.map(args, &Hash.from_hex/1)
        true -> []
      end

    if targets == [] do
      if marks == [] and not clear_halt?, do: Mix.shell().info("no quarantined blocks")

      for {h, m} <- marks,
          do: Mix.shell().info("#{Hash.to_hex(h)} height #{m.height} at #{m.time}: #{m.error}")
    else
      :ok = KV.write(kv, for(h <- targets, do: {:delete, :poisoned, h}), sync: true)
      for h <- targets, do: Mix.shell().info("cleared #{Hash.to_hex(h)}")
    end
  end
end
