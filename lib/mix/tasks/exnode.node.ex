defmodule Mix.Tasks.Exnode.Node do
  @shortdoc "Runs an exnode node"
  @moduledoc """
  Runs a node until interrupted, printing a status line every 10 seconds.

      mix exnode.node --chain mainnet --datadir ~/.exnode [--connect host:port]... [--listen 8333]
                      [--status-file path]

  Validation options: `--assumevalid <hash>|0`, `--shadow` (cross-check every
  verdict with Core's engine), `--no-halt-on-divergence`.

  Service options: `--rpcport <port>` (default: Core's port for the chain),
  `--rpcuser` / `--rpcpassword` (besides the `.cookie` file), `--norpc`,
  `--blockfilterindex`, `--peerblockfilters` (BIP157/158), `--indexscripthash`,
  `--restport <port>` (Esplora REST API).

  P2P options: `--no-v2transport` (BIP324 off; on by default, as Core's
  `-v2transport=1`).

  Storage options: `--datadir-cold <dir>` (inputs and witness segments, which
  are rarely read), `--prune-witness` (keep witness data for the last 288
  blocks only), `--dbcache <MiB>` (coin cache budget, default 450 as Core's
  `DEFAULT_KERNEL_CACHE`), `--kv-cache-mib <MiB>` (RocksDB block cache budget,
  default 256), `--batch-blocks <n>` / `--batch-mib <MiB>` (commit
  batch limits, default 128 blocks / 64 MiB; larger values cut sync overhead
  during IBD at the cost of memory and crash replay), `--snapshot-every <n>`
  (take a canonical snapshot every `n` commits during IBD, default 1; near tip
  and on clean shutdown a snapshot is always taken), `--chain-state-heap-mib
  <MiB>` (the chain state's minimum heap, default 384; during IBD its live
  data is hundreds of MiB, and a larger floor means fewer collections).

  `--decode-budget-mib <MiB>`: payload bytes of large peer messages (64 KiB
  or more) decoded and handled at once across all peers (default 32). A
  decoded block is several times its wire size; this bounds that memory.

  `--status-file` also writes the latest status as JSON (best header height
  and hash, peer count), for scripts that compare against bitcoind.
  """
  use Mix.Task

  @impl true
  def run(argv) do
    Mix.Task.run("app.start")
    Exnode.CLI.node(argv)
  end
end
