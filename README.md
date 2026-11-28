# exnode

A Bitcoin full node written in Elixir/OTP.

> **Status: experimental. Do not use it as production ready.**

## How it works

### Processes

The node is an OTP supervision tree. Each part is its own BEAM process (or
group of processes) with its own restart policy:

```
Node (rest_for_one)
├─ Shadow.Monitor         optional: Core's engine in a separate OS process, cross-checks every block
├─ Headers                header tree, proof of work, headers presync (anti-DoS)
├─ ScriptExec             shared native script workers for blocks and the mempool
├─ ChainState             the only writer of the archive; picks the best chain, connects and disconnects blocks
├─ Relay                  MempoolVerify, Mempool (cluster mempool), TxRelay
├─ P2P                    AddrMan, SyncState, BlockDownload, BlockServing,
│                         HighBandwidth, Connman + one process per peer, optional Listener
└─ Services               BIP158 filter index, scripthash index, JSON-RPC, Esplora REST
```

Restart boundaries follow ownership and dependencies. A mempool failure restarts
the relay subtree while peers can stay connected; a chain-state restart also
restarts downstream consumers of its views. Repeated failures can exhaust a
subtree's restart budget and propagate to the node supervisor. These are BEAM
process boundaries; native code loaded into the VM shares its address space.

The supervision layout is defined in [`Exnode.Node`](lib/exnode/node.ex).

### A block from the network to disk

1. A **peer** process decodes the message (plain v1 or BIP324 encrypted v2)
   and checks for a mutated body before changing download ownership.
2. **Headers** checks the header (PoW, difficulty, timestamps, version) and
   adds it to the header tree. Low-work header chains go through Core's
   presync/redownload state machine first.
3. **BlockDownload** fetches blocks along the best header chain from several
   peers (16 in flight per peer, a 1024-block window, byte estimates and stall
   timeouts). A received block remains reserved while it is checked, preventing
   another peer from selecting it again before it is stored.
4. The peer runs context-free `CheckBlock` work in parallel with other peers.
   **ChainState** applies the acceptance checks and stores the body in `pending`.
   During IBD it replies before activation finishes, so downloads can continue.
5. A persistent activation plan performs contextual/non-script checks in order,
   using earlier provisional blocks' coin-view deltas. Prevout prefetch overlaps
   this work. Script jobs go to **ScriptExec**, which calls libbitcoinkernel on
   dirty CPU schedulers; scripts from several blocks can overlap.
6. Only the successful prefix validated under the configured mode is retired
   into the archive. A failing ancestor discards dependent speculative results.
   Connected blocks accumulate in a batch, with the active tip potentially ahead
   of the durable tip.
7. A commit syncs segment files, then writes one synced atomic RocksDB batch
   containing indexes, archive metadata/tip and pending-body deletions. Recovery
   truncates uncommitted segment tails and replays available pending bodies.
8. Optional indexes follow the committed chain in their own processes. With
   `--shadow`, committed blocks and rejected-block verdicts are cross-checked
   against Core's engine; divergence halts connection by default.

### Storage: an archive instead of a UTXO set

Bitcoin Core stores raw blocks (`blk*.dat`), undo data (`rev*.dat`) and a UTXO
database. exnode stores the chain once, split into parts:

- **Segments**: append-only files of outputs, inputs and witnesses. Blocks,
  outputs and inputs get increasing ids.
- **RocksDB index**: the tx index, block metadata, and spend records
  (`output id + spending block → input id`).

The archive keeps historical outputs and transaction occurrences, including
disconnected branches. Spendability is a selected-chain query: creation and
spending-block membership, plus BIP30 duplicate-txid/overwrite rules, determine
which coin exists. A reorg removes the disconnected blocks' spend records;
block records retain spent-output IDs and overwrite metadata for disconnects.
There are no separate `rev*.dat` undo files, but undo information is still needed.

This gives serving, validation and indexes one historical store. The tradeoff
is permanent history/index growth, lookup work to establish spendability, and
reconstruction work when exact raw blocks are requested. The tx index is always
present because the archive needs it; it is not an optional query-only index.
An in-memory coin overlay/cache (`--dbcache`, 450 MiB by default) accelerates the
selected-chain view and masks uncommitted spends. Like Core's `-dbcache`, the
budget is the cache's own memory (coin entries and the eviction queue); the
node's total memory is higher.

Outputs, which prevout lookup reads, stay in the hot directory. `--datadir-cold`
places input and witness segments elsewhere. `--prune-witness` removes eligible
old witness segments while retaining base transaction history; recent blocks
remain fully servable and older full-witness reads report that data was pruned.
The hot/cold split saves fast-disk space while making reconstruction and index
backfill sensitive to the cold device's read performance.

## Architecture decisions

### Elixir owns the node; Core's kernel executes scripts

Networking, header validation, chain selection, non-script block checks, archive
state and mempool policy are implemented in Elixir. Script execution is delegated
to the pinned Bitcoin Core v32.1 **libbitcoinkernel** through
[`Exnode.Kernel`](lib/exnode/kernel.ex) and a small C NIF adapter. It receives
the transaction, spent outputs and the applicable consensus flags. Native
transaction/precomputed data is reused across that transaction's inputs.

This keeps the native integration narrow while reusing Core's script engine.
It also leaves responsibility for prevout selection, flags and surrounding
consensus checks with exnode. Dirty scheduling protects ordinary BEAM schedulers
from long CPU calls; it does not isolate native memory corruption or assertions
from the VM. libbitcoinkernel is distinct from the libbitcoin project.

### Parallel work, one owner of canonical chain changes

[`Chain.State`](lib/exnode/chain/state.ex) alone mutates the archive and publishes
the active tip. Its activation plan is persistent state driven by bounded turns
and completion messages. The default path keeps non-script preparation ordered
and overlaps scripts across up to eight provisional blocks. Later blocks can
use earlier deltas, but cannot become active before their ancestors succeed.

Jobs carry plan/body identities so obsolete results cannot publish into a new
branch or body retry. This makes dependencies and rollback explicit without
putting archive writes in every worker. The tradeoff is a serial preparation,
append and commit path: more workers cannot eliminate those costs. The separate
preparation engine/worker remains experimental; `:reference` is the default.

### Resource limits follow real work lifetimes

Blocks and mempool verification share a per-node
[`ScriptExec`](lib/exnode/validation/script_exec.ex) pool. Oldest-block priority
keeps the retirement head progressing, and mempool work has a reserved share.
Pipeline depth, estimated retained bytes, request bytes and peer slots limit
admission rather than spawning work for every input at once. These are separate
budgets, not a single hard limit on total process memory.

Cancelling a block does not stop an executing dirty NIF. Queued work can be
dropped, but running work retains its slot until native execution returns.
Restart/shutdown handling follows that lifetime. Startup also uses a
[file-descriptor budget](lib/exnode/fd_budget.ex) for peers, archive readers and
RocksDB table files, fitting the store's open-file allowance to the OS limit.

Large batches are an allocation concern as well as an I/O concern. Spend and
txindex operations are packed into binaries in memory and expanded at the KV
boundary, preserving the on-disk rows. Process-local heap/binary-virtual-heap
settings address BEAM collection behavior; a virtual-heap floor is an accounting
threshold, not preallocated RAM or a physical-memory cap.

### Acceptance, activation and durability are different milestones

| Milestone | Meaning |
|---|---|
| Stored | The body is in `pending` and eligible for later activation; validation may still fail. |
| Active (`tip`) | Ordered validation completed under the configured mode and the block joined the selected chain. |
| Committed (`committed`) | Segment sync and the synced atomic KV publication completed. |
| Index-ready | A particular optional index has caught up to the committed target. |

The commit order makes the canonical KV metadata the authority for segment ends
and the durable tip. New segment directory entries are synced before committed
metadata can reference them. Canonical consensus state (`index/`, single-writer,
`sync: true` only with `use_fsync`, `atomic_flush`, `paranoid_checks`, and
`absolute_consistency` WAL recovery) is separated from ephemeral download/header
staging (`staging/`, whose WAL and directory are fsynced before clean-close
unlock and whose cached headers verify their recomputed hash on reload) and
per-index single-writer query stores (`derived/filters/` and
`derived/scripthash/`, each with its own `flush.lock` and quiescent snapshots
taken between batches and on clean shutdown).

`flush.lock` enforces a strict clean-close gate on each store: the lock is
created and fsynced before opening the store and removed only after a clean,
fault-free shutdown. After every canonical commit (or every `--snapshot-every`
commits during IBD, always near tip and on clean shutdown), `exnode` takes a
quiescent RocksDB checkpoint (flushing memtables and hard-linking immutable
SSTs) and rotates `snapshots/primary` and `snapshots/secondary` via atomic
directory renames. After a crash or power loss, the node refuses to open any
dirty store directly; `mix exnode.restore` (or `bin/exnode-restore`) replaces a
dirty `index/` whole from the latest complete snapshot, truncates hot/cold
append-only segments to the snapshot's exact `ends`, wipes ephemeral `staging/`,
restores (or wipes) any dirty derived index store, and clears `flush.lock`. Any
storage I/O error, checksum mismatch, missing/short segment, or archive
integrity failure permanently latches a store fault, halts the node immediately,
and retains `flush.lock` with the fault record. Because local snapshots
hard-link immutable SST files on the same volume and share the append-only
segment files, `--force-from-snapshot` cannot recover from damaged storage media
or corrupted SST/segment data; media faults require replacing failing hardware
and resyncing from the network or restoring an independent off-volume backup.

Pending admission uses unsynced writes into `staging/`, so a `:stored` reply is
not a promise that every accepted body survives power loss. Missing bodies are
downloaded again after restore. Batching amortizes sync costs while allowing the
active tip to lead the committed tip.

### Prefetch is advisory, with an explicit validity window

[`Chain.Prefetch`](lib/exnode/chain/prefetch.ex) prepares bodies and committed
prevout answers ahead of the owner. A result's archive epoch must still match
when consumed; commits and disconnects advance the epoch. Speculative deltas,
the live overlay and the batch retain precedence over committed answers.
Cache hints may omit redundant reads, but an omitted key is unresolved and
falls back normally if the cache no longer answers it.

This preserves correctness across commits/reorgs and worker failure. The cost
is wasted work when results become stale: prefetch depth is a storage/workload
tuning parameter, not a guaranteed speedup. `--prefetch 0` disables it. The
`perf` log separates used/stale results, worker work and owner resolution.

### Serving and indexes use explicit read contracts

Serving/index workers read through published committed archive readers, avoiding
a round trip through the archive owner for each historical output. Optional
indexes follow the committed chain independently, remember their own tip and
rewind on reorg. They can be rebuilt from the archive without having observed
live validation events. This avoids a separate indexer process/service, but
their CPU, reads and native database work still compete with sync.

`read_block` reconstructs exact raw blocks and checks their base merkle root
and witness commitment; a pruned full-witness block is reported as unavailable.
`read_block_txs` can also reconstruct base transactions from witness-pruned
history. The narrower
[`Archive.read_index_facts`](lib/exnode/archive.ex) API reads base records,
derives stripped txids and checks their merkle root/record identity for indexing.
It does not read or authenticate witness data and is not a block-admission path.

The [index follower](lib/exnode/index/follower.ex) publishes each batch of rows
and its index tip atomically with `sync: false`. Index-ready is therefore a query
availability milestone with a different durability policy from the canonical
archive. A node can be chain-synced while its address history is still catching up.

### Local failure is different from consensus invalidity

A proven invalid block can invalidate descendants and affect its source peer.
A kernel API error, worker exception or local processing bug is not that proof:
the block is quarantined, its crash report and mark are persisted, and its
header is not marked consensus-invalid. `mix exnode.reconsider` clears quarantine
while the node is stopped once the cause has been addressed.

Storage errors keep the fatal/recovery path. A partially failed archive append
can already have changed files and ETS state, so restarting from the last commit
is preferable to continuing with an old struct. Supervision provides scoped
recovery where possible, not a guarantee that the entire node always stays up.

With `--shadow`, a separate OS process runs Core's full chainstate engine and
cross-checks connected/rejected verdicts and tips. Its queue applies backpressure
and divergences halt connection by default. This checks exnode's surrounding
consensus implementation, but it shares Core's script engine and adds its own
storage/validation cost; it is not an independent cryptographic implementation.

### Consensus rules and mempool policy have separate boundaries

The cluster mempool implements replacement, fee/size limits, relay and eviction
policy separately from block validity. Its optimal cluster linearizer can differ
from Core's budget-limited linearization in edge cases. Memory limits use exnode's
own estimates rather than Core's C++ allocation accounting.

The kernel C API exposes consensus script flags, not all of Core's policy-only
flags. Consequently some transactions rejected by Core's standardness policy
are accepted by exnode's mempool. These are documented compatibility differences,
not additional block-validity rules. The gaps are listed in the moduledocs of
`Exnode.Mempool.Policy`, `Exnode.Mempool.Pool` and `Exnode.P2P.TxRelay`.

## Building

Requirements: Erlang/OTP 28 and Elixir 1.19 (pinned in `.tool-versions`;
mise or asdf), CMake and a C compiler, and optionally `liblz4-dev`
(RocksDB compression).

Bitcoin Core v32.1 is not part of this repository. The build, several tests
(ported vectors read from Core's sources) and the interop tests expect it in
`vendor/bitcoin` (ignored by git):

```sh
git clone --depth 1 --branch v32.1 https://github.com/bitcoin/bitcoin vendor/bitcoin
git -C vendor/bitcoin rev-parse HEAD   # f0de87f040621468b956f01f526a43a010310501
```

The NIFs can be built against another checkout with `CORE_DIR=<path> mix
compile`, but the tests look for Core in `vendor/bitcoin`.

```sh
# Core v32.1 kernel library (the NIFs link against it)
cd vendor/bitcoin
cmake -B build-kernel -DBUILD_KERNEL_LIB=ON -DBUILD_SHARED_LIBS=ON \
      -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF -DBUILD_TESTS=OFF -DENABLE_WALLET=OFF -DENABLE_IPC=OFF
cmake --build build-kernel -j"$(nproc)"

# optional: bitcoind and bitcoin-cli for the interop tests
cmake -B build -DBUILD_KERNEL_LIB=ON -DBUILD_TESTS=OFF -DENABLE_WALLET=OFF -DENABLE_IPC=OFF
cmake --build build -j"$(nproc)"
cd ../..

mix deps.get
mix compile        # also builds the NIFs (Makefile, via elixir_make)
```

## Reproducible release

`contrib/release/build.sh` builds a self-contained release (Erlang runtime,
NIFs and Core's kernel library included) for Linux in Docker, and anyone
building the same commit gets the same bytes:

```sh
contrib/release/build.sh                            # this machine's architecture
PLATFORM=linux/amd64 contrib/release/build.sh       # or a given one
cat dist/SHA256SUMS                                 # compare with other builders
```

Every input is pinned (`contrib/release/Dockerfile`): the Debian bookworm
image by digest, its packages by snapshot.debian.org date, and the Erlang/OTP,
Elixir, Hex, rebar3 and Bitcoin Core v32.1 sources by hash; Hex packages by
`mix.lock`. The build uses fixed paths and takes its time stamps from the
commit (`SOURCE_DATE_EPOCH`). The `Reproducible release` workflow builds each
change twice on separate runners and fails if the outputs differ.

The tarball needs glibc 2.36 or later (Debian 12, Ubuntu 23.04) and
libstdc++ and liblz4 (present on any Debian or Ubuntu); OpenSSL is linked
in. Unpack it anywhere and run:

```sh
exnode-<version>-<arch>-linux-gnu/bin/exnoded --chain testnet4 --datadir ~/exnode-testnet4
exnode-<version>-<arch>-linux-gnu/bin/exnode-reconsider --chain testnet4 --datadir ~/exnode-testnet4
exnode-<version>-<arch>-linux-gnu/bin/exnode-restore --chain testnet4 --datadir ~/exnode-testnet4
```

They take the options of `mix exnode.node`, `mix exnode.reconsider`, and
`mix exnode.restore`. The node runs without Erlang distribution, and no cookie
ships with the release.

## Running

```sh
mix exnode.node --chain testnet4 --datadir ~/exnode-testnet4 --listen 48333
```

For mainnet:

```sh
mix exnode.node --chain mainnet --datadir ~/exnode --listen 8333
```

`--datadir` is the parent of the network directory: the second command opens
`~/exnode/mainnet/index` and `~/exnode/mainnet/archive`. Starting with the same
datadir resumes the existing chain. Add `--indexscripthash` when address history
is needed; it catches up from committed archive data.

Common options:

| Option | Meaning |
|---|---|
| `--chain` | `mainnet`, `testnet`, `testnet4`, `signet`, `regtest` |
| `--connect host:port` | connect only to these peers (repeatable) |
| `--assumevalid <hash>\|0` | as Core's `-assumevalid`; `0` checks every script |
| `--shadow` | cross-check every block with Core's engine |
| `--dbcache <MiB>` | coin cache size |
| `--prefetch <blocks>` | prevout preparation depth; `0` disables it (default 8) |
| `--datadir-cold <dir>` | inputs and witnesses on a second disk |
| `--prune-witness` | keep witness data for the last 288 blocks only |
| `--rpcport`, `--rpcuser`, `--rpcpassword` | JSON-RPC (cookie auth by default) |
| `--blockfilterindex`, `--peerblockfilters` | BIP158 index, BIP157 serving |
| `--indexscripthash`, `--restport <port>` | address index, Esplora REST API (no auth; keep it local) |
| `--no-v2transport` | disable BIP324 |

`mix help exnode.node` lists all options. `scripts/soak.sh` runs and
monitors a long testnet4 node.

Assumevalid skips eligible historical script checks while retaining non-script
checks. `--assumevalid 0` checks every script as blocks are validated; it does
not retroactively revalidate history already stored in the datadir.

## Tests

```sh
mix test                      # everything, including the bitcoind interop tests
mix test --exclude interop    # without bitcoind
```

The interop tests (tagged `:interop`) run exnode against bitcoind v32.1 on
regtest. They need `vendor/bitcoin/build/bin/bitcoind` and are skipped
without it. Core's own test data is ported where it exists (script vectors
through the kernel, BIP324 packets, eviction cases, block filters, an
invalid-block corpus). Many tests were mutation-checked: a rule was broken on
purpose to confirm that a test fails.

Tests can run several nodes in one VM. Each node owns a mockable
[`Exnode.Clock`](lib/exnode/clock.ex) value, keeping wall time and monotonic
timeouts distinct. Tests advance that clock and explicitly tick periodic work
to exercise expiry, trickle and timeouts without changing another node's clock.
Message barriers control worker/reorg interleavings. Archive/model properties,
Core differential tests and replay/store/index digests complement ordinary
example tests; they check state transitions and recovery as well as happy paths.

## License

MIT; see [`LICENSE`](LICENSE). Test vectors, generated seed data and ported
logic from Bitcoin Core are covered by Core's MIT license, reproduced there.
