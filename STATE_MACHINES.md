# exnode state machines

This file lists every state machine in the node, explicit or implicit. For each one it gives the states, the invariants that must hold, and the transitions. It also keeps a register of the invalid states and transitions the code could actually reach, with the evidence and what was done about each one.

References point to functions, not line numbers, because line numbers drift.

Last audit: 2026-11-12. The fixes listed in section 11 (items 14-18) close every item the audit left open. The previous audit (2026-11-11) covered the code before the asynchronous mempool accept, the scripthash totals, the KV owner and the 300 s commit cadence; this one re-read those and re-checked every open item.

Bug IDs used below (`CS-1`, `MP-1`, ...) are cited in the regression tests.

## Contents

1. [Supervision and process lifecycle](#1-supervision-and-process-lifecycle)
2. [Chain state: blocks, plan, commit, recovery](#2-chain-state)
3. [Index follower](#3-index-follower)
4. [Mempool](#4-mempool)
5. [Transaction relay](#5-transaction-relay)
6. [Peer connection](#6-peer-connection)
7. [Connman, address book, discouragement](#7-connman-address-book-discouragement)
8. [Header sync and block download](#8-header-sync-and-block-download)
9. [Services: clock, KV, RPC/REST, fd budget](#9-services)
10. [Bug register](#10-bug-register)
11. [Fix issues (grouped)](#11-fix-issues)

---

## 1. Supervision and process lifecycle

The supervision tree is defined in `Exnode.Node`. The root uses `rest_for_one` and is `:temporary`. Its children start in this order:

`KVOwner` → `Shadow?` → `Headers` → `ScriptExec` → `ChainState` → `Relay` (rest_for_one: MempoolVerify, Mempool, TxRelay) → `P2P` (rest_for_one: AddrMan, SyncState, BlockDownload, HighBandwidth, BlockServing, Conns (one_for_all: PeerSup, Connman), Listener?) → `Services` (one_for_one: BlockFilter, Scripthash, RPC, REST)

| From | Event | To | Effects |
|---|---|---|---|
| — | `Node.init` | starting | `fd_budget!` (may raise), `KV.open`, cookie written |
| starting | `ChainState.init` replays `pending` and publishes the view | chain ready | view ETS and `persistent_term` set |
| chain ready | Services start | serving | indexes publish their KV handle in `persistent_term` |
| serving | Headers, ScriptExec or ChainState crashes | restarting downstream | every later subtree is stopped and restarted |
| serving | a leaf in Services crashes | leaf restart | — |
| serving | Mempool or TxRelay crashes | Relay restarting | Peers stay connected: their TxRelay/Mempool calls answer neutrally while it is down (MP-3) and they register again on `:tx_relay_resync` |
| any | root restart intensity exceeded | stopped | the mix task halts with status 1 |

Invariants:

- **I1.** A consumer never holds state that belongs to a dead producer. rest_for_one restarts everything downstream, so no stale in-flight map survives a ChainState or BlockDownload restart.
- **I2.** Readiness is implicit: RPC and REST start only after `ChainState.init` has returned. There is no separate ready flag.
- **I3 (fixed by MP-3, SVC-4).** A process outside a restarting subtree does not die because it was calling into it: peers' TxRelay and `match_short_ids` calls and RPC methods catch the exit and answer neutrally.
- **I4.** A cast to a registered name that is momentarily unregistered (a restart) is silently dropped. Anything that must arrive (the shadow halt, CS-6) is re-sent until acknowledged.

---

## 2. Chain state

### 2.1 Block lifecycle (`Exnode.Chain.State`)

Block states:

- **header-only**
- **held**: the body is stored in `pending`, `{:held, h}` is in the view, and `h` is in `st.blocks`.
- **provisional**: a plan item.
- **active-uncommitted**: in the archive batch and in `st.uncommitted`.
- **committed**
- **disconnected-archived**: in `st.disconnected`.
- **failed**: the header index marks it `:failed`.
- **quarantined**: a durable `poisoned` mark, the body kept in `pending`, and `{:quarantined, h}` in the view.

| From | Event | Guard | To | Effects |
|---|---|---|---|---|
| header-only | `do_submit` | checks pass | held | `pending` put, `{:held,h}` |
| header-only | `do_submit` | contextual check fails | failed | `Headers.invalidate` |
| header-only | `do_submit` | quarantined | refused | `{:error,{:quarantined,_}}`; never validated |
| held / disconnected | `new_plan` / `extend_plan` | path available, not failed, not quarantined | provisional | `add_item` |
| provisional | head ready, `retire` | its archive preparation is not running | active-uncommitted | `Archive.connect` (with the prepared records if their ids still match), view tip, mempool and listener events |
| provisional | head `{:error}` / `{:invalid}` | — | failed | `cancel_plan`, `commit`, invalidate (descendants too), unhold |
| provisional | head `{:crash}` / `{:local}` | — | quarantined | `commit`, `poison` (fsynced mark, crash report, view marker) |
| active-uncommitted | `commit` (batch full, age, at tip, halt, fail, quarantine, disconnect, `with_archive`, `terminate`) | — | committed | `Archive.flush`, `pending` deletes in the same KV batch, `:held` removed |
| committed | `disconnect_to(fork)` | tip above the fork | disconnected-archived | commit first; `disconnect_tip` writes durably; epoch +1 |
| quarantined | `reconsider_poisoned` | body still in `pending` | held | mark deleted (fsynced), view marker removed |

Invariants:

- **CS-I1.** Only the head of the plan's FIFO retires. A failure makes the plan final.
- **CS-I2.** A reorg (`disconnect_to`) happens only in `new_plan`, so only while there is no plan. Speculative results never survive a base change.
- **CS-I3.** Script results carry `{:blk, gen, ref, i}`, preparation results carry `{:prep, gen, ref}` and archive preparation results carry `{:apre, gen, ref}`. All are matched against the live plan generation and item; stale results are dropped.
- **CS-I4.** For download selection, a block counts as "had" if it is held, archived **or quarantined**. See BD-1.
- **CS-I5 (fixed by CS-1).** `terminate/2` commits only an archive struct whose epoch equals the epoch of this process's last durable write (`note_durable/1`, `durable_current?/1`).
- **CS-I6b (fixed by CS-8).** `find_target` ranks candidates and the tip with one key, Core's `CBlockIndexWorkComparator`: more work, then the earlier activatable body (sequence id), then the hash. A candidate ranked above the tip qualifies even at equal work.

### 2.2 Plan and turn

- **Plan states:** none → growing (`todo` not empty) → final → drained (`:done`, then `retarget`).
- **Turn results:**
  - `:more`: the budget is used up (`activation_step` retirements, plus `pipeline_depth` preparations, or `turn_ms`). Re-queues `:drive`.
  - `:waiting`: a completion message is due.
  - `:idle`: the waiters are answered.
- **Item states:** `:preparing` → `:scripts` → `:ready` / `:failed`.
- **Archive preparation (per item, alongside its state):** `nil` → `{:pending, tag, mref}` (started once the item has its result and the ids before it are known) → `{:done, prepared}`, or `:none` if it failed or its process died. A `:ready` head retires only once this is not pending; `:none` and a stale id guess both mean the block is archived in place, with the same result.
- **Halt:** while `halted != false`, every turn cancels the plan and returns `:idle`.

### 2.2.1 Halt (durable, CS-2)

States: **running** (`halted: false`, no mark) and **halted** (`halted: reason`, `{:meta, "halt"}` mark with `%{reason, time, height, hash}`, view `{:halted, reason}`).

| From | Event | To | Effects |
|---|---|---|---|
| running | `{:halt, reason}` cast (shadow divergence) | halted | the mark is written **first** (synced), then the view is updated and the plan cancelled; `Monitor.halt_ack` |
| halted | `{:halt, other}` | halted | ignored; the first reason stands; `Monitor.halt_ack` |
| halted | restart (with or without `--shadow`) | halted | `load_halt` runs before `load_pending` / `drive_until_idle`; pending blocks are held, not connected |
| halted | blocks submitted | halted | stored and held, never connected |
| halted | `clear_halt/1` or `mix exnode.reconsider --clear-halt` (offline) | running | mark deleted (synced), view reset, `retarget`, drive |
| running | `clear_halt/1` | running | `:not_halted` |

Invariant **CS-I6.** If a halt mark exists, no block is connected, in any process lifetime, until an operator clears it. Blocks connected between the divergent block and the halt (shadow lag ≤ 512) stay committed; a clear does not roll them back.

Invariant **CS-I7 (fixed by CS-6).** A divergence the monitor recorded with `halt: true` always ends in a halt mark. The monitor's side:

| From | Event | To | Effects |
|---|---|---|---|
| clean | round with a divergence | halt pending | record written; `{:halt}` cast to the chain state's name (dropped if the name is unregistered) |
| halt pending | `round` / `shadow_tip` / `set_ahead` call | halt pending | `{:halt}` cast to the caller's pid (the live chain state). A restarted chain state calls `shadow_tip` first, so it halts before its first round |
| halt pending | `halt_ack` cast (the chain state wrote, or already had, a mark) | clean | — |

The monitor still never calls the chain state, so they cannot deadlock. A stale re-sent halt that arrives after an operator's `clear_halt` halts again: the safe direction.

### 2.3 Commit and durability (`Archive.flush`, `Archive.disconnect_tip`)

A commit runs in this order:

1. `Segments.sync` for each kind.
2. One synced KV batch: ops, then the pending deletes, then the meta (next ids, segment ends, tip).
3. Reset the in-memory batch, set `committed`, and bump the epoch.

Durable writes inside one callback: a mid-turn batch commit (`archive_block`), `disconnect_to` (commit plus `disconnect_tip`), `fail_block`, and `quarantine_block`.

| Event | Precondition | Effect |
|---|---|---|
| callback returns | — | the gen_server state matches the disk epoch |
| callback crashes, **no** durable write in it | `durable_current?` | `terminate` flushes the pre-callback batch (consistent: recovery truncates segment tails to the committed ends) |
| callback crashes **after** a durable write | not `durable_current?` | `terminate` skips the commit and logs a warning; the restart resumes from the disk and `pending` (CS-1) |
| kill -9 | — | `terminate` does not run; recovery truncates and replays `pending` |

### 2.4 Recovery (`Archive.open`, `ChainState.init`)

1. Read the meta.
2. `check_committed!`.
3. `truncate_to` the committed ends.
4. Re-remove pruned witness files.
5. `rebuild_chain`.
6. `load_poisoned` (also sets the view markers).
7. `load_candidates`.
8. `load_pending`.
9. `drive_until_idle` (a no-op while halted; `load_halt` runs before step 6).
10. `publish`.

### 2.5 Workers

- **Prefetch:** task running → ready / `:none` → taken. The epoch is checked when a result is used.
- **Prep worker:** `prep_job` is nil or outstanding. Worker death turns the item into a crash, which quarantines it.
- **Private ScriptExec** (no shared executor given): its DOWN stops the chain state with `{:script_exec_down, reason}`, after init and during init's startup replay alike (CS-5).
- **ScriptExec job:** queued → running → done (`{:script_exec,…}`). A cancelled queued job is dropped; a cancelled running job has its result discarded. A worker death gives the outcome `:crash`. When the owner goes DOWN, its groups are cancelled.
- **Shadow monitor:** rounds are queued, then checked asynchronously. On a divergence it writes the record and keeps the halt pending until ChainState acknowledges it (section 2.2.1, CS-2, CS-6). A rejected block is in the round of the turn that failed it: `fail_block` commits first, the turn ends, and its epilogue (`maybe_commit` with an empty batch, `publish`, `publish_pipeline`, then `flush_round`) does no I/O that could exit in between (CS-7, not reachable).

### 2.6 Commit cadence (`maybe_commit`)

| From | Event | To |
|---|---|---|
| uncommitted | n ≥ 128, or bytes ≥ 64 MB, or caught up, or halted, or age ≥ (best − tip ≥ 128 ? 300 s : 5 s) | committed (`flush` + `note_durable`) |

Readers (RPC, REST, indexes) lag the in-memory tip by up to 300 s only while ≥ 128 blocks behind (IBD). `:commit_tick` fires every 5 s whatever the `:batch_ms` option (tests only).

### 2.7 KV store owner (`Store.KVOwner`)

| From | Event | To | Effects |
|---|---|---|---|
| — | `Node.init` → `KV.open` (retries ≤ 5 s while this VM holds the lock) | open | handle given to KVOwner (first child) and its users |
| open | node stops (`:shutdown`, children stop in reverse order) | closed | `KVOwner.terminate` → `KV.close` after every user has stopped |
| open | root killed / abnormal stop | closed | the trapping owner gets `:killed` and closes too (KV-1); erlang-rocksdb closes once NIF calls in progress release the handle |
| open | `Node.init` raises after the open | freed | released by GC |

---

## 3. Index follower

`Exnode.Index.Follower` is used by `Index.Scripthash` and `Index.BlockFilter`.

Persisted state, per column family:

- `"tip"` → `<<h, hash>>`
- `"h"<>h` → hash

Every step is a single KV batch.

| From | Event | Guard | To | Effects |
|---|---|---|---|---|
| tick | view not ready / raise | — | idle (retry in 200 ms) | warning |
| any | `rewind` | `id_at(tip.h)` hash ≠ indexed tip hash | rewinding | disconnect ops, delete `"h"`, tip ← h-1; repeats |
| at tip | `h >= committed` | — | following (`:done`) | — |
| behind | `sync` | each block's header prev = previous indexed hash | catching up | rows for `h+1..last_linked` (≤ 200); tip ← last linked block itself |
| behind | `sync` | the first block does not link (a reorg is in progress) | idle (`:done`, retry next tick) | nothing written |

Invariants:

- **IDX-I1.** The index tip is at or below the committed tip.
- **IDX-I2 (fixed by IDX-1).** The indexed heights form one parent-linked chain, and the tip is that chain's last block.
- **IDX-I3.** The tip and its rows change atomically (one KV batch).

Rewind therefore only needs to compare the tip hash.

### 3.1 Scripthash totals

| From | Event | To | Writes (one batch) |
|---|---|---|---|
| fresh (tip −1) | tick | complete | `"totals"` mark |
| legacy (rows, no mark) | tick: `backfill_totals` | complete, or legacy again on a raise (retried) | totals every 10k ops; the mark in the last batch |
| complete | `sync`, linked block | complete | rows + merges (+n) + `"h"` + tip |
| complete | rewind | complete | rows deleted + merges (−n) + `"h"` deleted + tip − 1 |

Readers: `totals` is nil while legacy (REST then scans the history). `history`, `history_page` and `rows_at` run in the caller, each on one iterator snapshot. Between a disconnect and the rewind (≤ 200 ms) the index can hold rows above the view's tip, or rows of a block no longer active. REST `/utxo` keeps only rows whose indexed block (`Scripthash.hash_at/2`, the follower's `"h"` entry) is the active one at that height (SVC-3). `Scripthash.sync_to/3` returns once the block is on the indexed chain, at or below its tip (SVC-5).

---

## 4. Mempool

### 4.1 Transaction lifecycle (`Exnode.Mempool`, `Mempool.Accept`, `Mempool.Pool`)

Transaction states:

- **unknown**
- **deferred**: in `st.deferred`.
- **verifying**: in `st.jobs`, `pending_spends` and `pending_txids`.
- **in_pool**
- **removed**: mined, conflicted, replaced, expired, trimmed or dropped after a reorg.

| From | Event | To | Notes |
|---|---|---|---|
| unknown | context-free precheck fails | replied error | — |
| unknown | jobs + deferred ≥ 128 | replied `:reconsiderable` "mempool busy" | transient: TxRelay does not cache it (MP-5) |
| unknown / deferred | txid or an input in `pending_txids` / `pending_spends` | deferred | — |
| unknown / deferred | `prepare` error | replied error | — |
| unknown / deferred | `prepare` ok | verifying | task started; inputs → `pending_spends`, txid → `pending_txids`; `job.tip_hash`, `job.state` saved |
| verifying | task result or DOWN | finishing | `sync`; pending entries cleared |
| finishing | task crashed | replied `:reconsiderable` "script-check-crashed" | transient (MP-5) |
| finishing | tip moved and the chain is still ahead | replied `:reconsiderable` "tip-changed" | transient (MP-5) |
| finishing | same tip and same state term | `complete` (workspace reused) | — |
| finishing | otherwise | re-`prepare` on the current pool (inline verify if spent coins or flags differ), `complete` | never inserts from a stale pool |
| finishing | another submitter added the tx meanwhile | replied `:conflict` "txn-already-in-mempool" | TxRelay treats it as had, not rejected (MP-7) |
| complete | ok, still present after `limit_size` | in_pool | notify, reply, `unbroadcast` if asked |
| complete | trimmed | replied "mempool full" | the new state is kept |
| deferred | any job ends | `start_accept` again, FIFO | — |
| in_pool | block connected | removed | confirmed txs non-recursively; conflicts with their descendants |
| in_pool | RBF | removed | `all_conflicts` = conflicts plus descendants |
| in_pool | expiry / trim | removed | with descendants / whole chunk |
| block tx | disconnected | re-added (`bypass_limits`) | **linked to the in-pool children that already spend it** (MP-1) |
| re-added clusters | a merged cluster over 64 txs or 404,000 WU | trimmed | **`Pool.trim_oversized`: topological, highest feerate first, kept while it fits and its parents are kept; the rest (descendant-closed) removed, before anything linearizes** (MP-1b) |
| block tx | re-add fails, `txn-already-known` | — | the view has it confirmed again; **its children are kept** (MP-2) |
| block tx | re-add fails, other reason | — | in-pool spenders removed with their descendants (removeRecursive) |
| in_pool | after reorg, not final / immature | removed | with descendants |

Invariants:

- **MP-I1.** `entries`, `by_wtxid`, `spenders`, `by_time`, `lin` and `total_*` change only in `Pool.add` and `Pool.remove`.
- **MP-I2 (fixed by MP-1).** For every `spenders[{t,v}] = c` with `t` in the pool: `c ∈ entries[t].children` and `t ∈ entries[c].parents`, and `t` and `c` are in the same cluster.
- **MP-I3.** `pending_spends` holds disjoint outpoints per job.
- **MP-I4.** The pool corresponds to `tip_hash`. The chain view the mempool reads can be ahead of it while later updates are still in the mailbox, which is why MP-2 exists.
- **MP-I5 (fixed by MP-1b).** After every `update_for_reorg`, every cluster is within the count and weight limits, so no linearization (`lin_refresh`, `extract_best`, `trim`) runs on an unbounded cluster. `Accept.cluster_limits` does not see a re-added tx's children (`Pool.stage` seeds parents only); the trim is what enforces it, as Core's `TxGraph::Trim` in `UpdateTransactionsFromBlock`.
- **MP-I6.** Every `start_accept` / `finish_accept` path replies exactly once.

### 4.1.1 Package (`submit_package`, synchronous)

It ignores `pending_txids` / `pending_spends`, so a pending single accept of one of its txs ends in "txn-already-in-mempool" (MP-7).

| Step | Outcome |
|---|---|
| not well formed / not child-with-parents | error reply |
| per tx: same wtxid in pool | `:mempool` |
| per tx: same txid in pool | `:different_witness` |
| per tx: single accept ok | in pool, `{:valid, _}` (stays even if the package then fails) |
| per tx: reconsiderable or missing inputs (n > 1) | to `multi` |
| per tx: other error | quit early; the txs accepted before it stay |
| `multi(to_eval)` | prechecks → TRUC → package feerate → package RBF (1p1c) → cluster → unspent dust → scripts → finalize |
| end | `limit_size`; a `:valid` tx no longer present → "mempool full"; the `:valid` ones are notified with the caller as origin |

### 4.2 Block-update sync

ChainState accumulates `mempool_event`s each turn and sends `{:mempool_update, tip, events}`. A reorg can span several turns, so it can arrive as several messages. The Mempool applies everything in its mailbox (`sync/1`) before any accept, test, package or job end.

---

## 5. Transaction relay

`Exnode.P2P.TxRelay`.

### 5.1 Announcement / request tracker

This mirrors Core's TxRequestTracker. Per `(peer, hash)` the states are: candidate → (parked in `waiting[h]`) → requested → completed → deleted. A completed entry stays so that the peer's re-announcement of `h` is a no-op (Core `ReceivedInv`); it counts towards the per-peer cap. Until AUD-A4-1 there was no completed state: a response deleted the entry, and a peer could re-announce at once.

| From | Event | To |
|---|---|---|
| none | inv, not already had, under the per-peer cap | candidate (`ready_at` = now + delays) |
| candidate | tick, ready, `h` requested elsewhere | parked in `waiting[h]` |
| candidate | tick, best ready (preferred, then oldest) | requested; `in_flight[p]++`; expiry; getdata |
| candidate / requested | tx / notfound / 60 s expiry (`ann_complete`, Core MakeCompleted) | **completed**; a request is released (`release` re-queues `waiting[h]`) (AUD-A4-1) |
| completed | inv of `h` from the same peer | **unchanged** (AUD-A4-1) |
| any | the last uncompleted entry of `h` completes | **every entry of `h` deleted** (Core IsOnlyNonCompleted) (AUD-A4-1) |
| any | peer DOWN | completed, then deleted (Core DisconnectedPeer) |
| any | tx accepted / orphaned / confirmed | `ann_delete_hashes` for every peer |

Invariants:

- At most one `requested` entry per hash.
- **(AUD-A4-1)** `ann_peers[h]` is exactly the peers with an entry of `h`; no hash is kept with every entry completed.
- `in_flight[p]` equals the number of `p`'s requested entries.
- Stale tree entries are skipped by sequence number.

### 5.2 Orphanage

| From | Event | To |
|---|---|---|
| none | `:missing_inputs` from a registered peer, no rejected parent | orphan; parents requested |
| orphan | wtxid announced by a new peer | announcer added |
| orphan | parent accepted / confirmed (`add_children_to_work_set`) | **queued in one random announcer's work set, unless already queued** (AUD-A4-2) |
| orphan (queued) | its `:orphan_work` step (round-robin over peers; a peer's work until one decisive answer) | dropped, then accepted / re-put / rejected |
| orphan (queued) | its assigned peer DOWN | **unqueued** (Core EraseForPeer) |
| orphan | 1p1c package accepted (`try_1p1c`) | **dropped before the parent's reconsideration** (MP-4) |
| orphan | 1p1c package failed, child `{:invalid, e}` (not missing inputs) | **dropped; `rejects` or `reconsiderable` by `e`** (TXR-1) |
| orphan | reconsideration answered transiently (busy, tip-changed, script-check-crashed) | **kept** (MP-5) |
| orphan | confirmed or conflicted by a block; last announcer DOWN; limits | dropped |
| orphan | count cap (oldest), peer over its weight budget, or total score over 3,000 (highest-score peer) | **that announcement dropped; the orphan too if it has none left** (AUD-H1) |

Invariants:

- `orphan_by_parent` matches `orphans`.
- **(AUD-A4-2)** `orphan_work_set` is exactly the wtxids in the `orphan_work` queues; `orphan_work_peers` holds each peer with a queue once; an `:orphan_work` message is pending (`orphan_work_scheduled`) whenever `orphan_work` is not empty. No handler reconsiders orphans inline.
- **(AUD-H1)** `orphan_order`, `orphan_peers` (weight, latency score and announcements of each peer) and `orphan_score` match `orphans`. Only `orphan_put/3`, `orphans_drop/2`, `orphan_announcer_add/3` and `orphan_announcer_del/3` change them. `limit_orphans/1` reads them and does work proportional to the evictions.
- **(AUD-H1)** After every `limit_orphans/1`, `orphan_score` ≤ 3,000 (Core `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE`: one per announcement plus one per 10 inputs of each unique orphan).

### 5.3 Filters

- `rejects` and `reconsiderable` reset on a tip change. `confirmed` resets on a disconnect.
- An accepted or in-mempool tx is never inserted into `rejects` (MP-4, MP-7).
- Only verdicts on the tx are cached. "mempool busy", "tip-changed" and "script-check-crashed" leave no trace and do not start a 1p1c evaluation, which would bypass the 128-accept cap (MP-5).

### 5.4 1p1c (`try_1p1c`, Core `Find1P1CPackage` + `ProcessPackageResult`)

| Trigger | Outcome |
|---|---|
| reconsiderable (non-transient) parent + an orphan child from the same peer, package hash not filtered | `submit_package([parent, child])` |
| result `:ok` | child dropped from the orphanage, `accepted(parent)`, `accepted(child)` |
| result not `:ok` | package hash → `reconsiderable`; then per tx (**TXR-1**): child `:valid` → accepted; child invalid (not missing inputs) → `rejected`; parent `:valid` → `accepted` (announced, its other orphans reconsidered) |

The mempool's `:mempool_accepted` notification names TxRelay as origin for these, and TxRelay ignores its own, so `accepted/3` is the only path that announces them.

---

## 6. Peer connection

`Exnode.P2P.Peer`, `P2P.V2.Transport`.

### 6.1 Phase (implicit)

The phase is derived from `socket`, `connected_at`, `version` and `verack_received`.

| Phase | Encoding |
|---|---|
| INIT_IN | `socket=nil, connected_at=nil` (waiting for `:socket_ready`) |
| CONNECTING | in `handle_continue(:connect)` |
| AWAIT_VERSION | `connected_at!=nil, version=nil` |
| AWAIT_VERACK | `version!=nil, verack_received=false` |
| READY | `handshake_done?` |
| STOPPING | `terminate` flushes the writer (≤ 1 s) |

| From | Event | Guard | To |
|---|---|---|---|
| CONNECTING | connect ok / error | — | AWAIT_VERSION / exit |
| INIT_IN | `:socket_ready` | — | AWAIT_VERSION |
| AWAIT_VERSION | version | bad services, obsolete version, self-connect | exit |
| AWAIT_VERSION | version | feeler | exit `:feeler_done` |
| AWAIT_VERSION | version | otherwise | AWAIT_VERACK |
| AWAIT_VERACK | wtxidrelay / sendaddrv2 | — | same, flags set |
| AWAIT_VERACK | verack | — | READY (sendheaders, sendcmpct, getaddr, `peer_ready`, TxRelay connected) |
| not READY | **any other message, including an oversized inv/headers/addr** | — | same, ignored (P2P-1) |
| READY | version / verack | — | ignored |
| READY | wtxidrelay / sendaddrv2 | — | exit |
| any connected | tick | not READY after 60 s | exit `:handshake_timeout` / `:reconnect_v1` |
| any | tcp_closed / error / disconnect / send_failed | — | exit |

Invariants:

- **P-I1.** `verack_received` implies `version != nil`.
- **P-I2.** Nothing other than version, verack, wtxidrelay and sendaddrv2 changes state or punishes the peer before READY.
- **P-I3.** The tick timer is a single chain; timeouts are re-evaluated from fields, not from per-request timers.
- **P-I4 (fixed by MP-3).** A peer's `:infinity` calls into TxRelay (`inv`, `received_tx`, `notfound`, `feefilter`, `lookup`) and the Mempool (`match_short_ids`) answer neutrally (`:ok`, all items notfound, an empty match) when the Relay subtree is restarting, instead of exiting the peer.

### 6.2 v2 transport

- **recv:** `:key_maybe_v1 → :key → :garb_garbterm → :version → :app`
- **send:** `:maybe_v1 → :awaiting_key → :ready`

Nothing is sent before send reaches `:ready` (it is queued). The responder falls back to v1 only from `:key_maybe_v1`. The initiator retries v1 only through `closing/2`, and only if it received nothing while in `:key`.

---

## 7. Connman, address book, discouragement

### 7.1 Connman peer record

| From | Event | To |
|---|---|---|
| — | `start_outbound` ok / `register_inbound` (a call: the Listener hands the socket over only once it returns; with Connman down the connection is refused, P2P-4) | tracked (ready=false), monitored |
| tracked | `peer_ready` | ready; `AddrMan.good` for non-inbound peers |
| tracked inbound | evicted | evicting; deadline timer |
| evicting | deadline, still tracked | killed |
| tracked | DOWN | removed. `AddrMan.connected`; discouraged on misbehaving (not manual / local); v1 retry |
| absent | late DOWN / stats / ready / deadline | no-op |

The slot counts are derived from `peers` each time, so there are no stored counters to drift. "Already connected" (outbound, feeler collision, anchor) matches the IP alone as well as IP and port, as Core's `AlreadyConnectedToAddress` (P2P-2).

Anchors (`anchors.dat`):

- read once at start, then deleted;
- written in `terminate` **only when the node stops** (P2P-3, P2P-3b): `Exnode.Node.stop/2` and the application's `prep_stop` mark the node as stopping (`Node.stopping?/1`, reset by `Node.init`); a direct `:normal` stop of Connman also writes. A restart cascade's `:shutdown`, or a crash, does not.

### 7.2 AddrMan entry (`addr_man/table.ex`)

`absent → NEW (1..8 refs) → TRIED`. Collisions are resolved by `resolve_collisions`. A displaced TRIED entry goes back to NEW.

Invariants:

- `n_new + n_tried = |info|`
- `net_counts` match the table.
- Every NEW position points at an entry whose `refs` contains it.
- A TRIED entry has no refs.

### 7.3 Discouraged / AddrRate

- **Discouraged:** key → `inserted_at`, with a 24 h TTL. Pruned at flush and when the cap is reached.
- **AddrRate:** a token bucket.
- **(AUD-A2-1)** An address a peer sends reaches `AddrMan.add` only after the token bucket and `Peer.sanitize_addrs/2` (Core `ProcessAddrs`): NODE_NETWORK or NODE_NETWORK_LIMITED, a reachable network (IPv4, IPv6), not discouraged, and a time no later than now + 10 min and after 1973 (otherwise now − 5 days).

---

## 8. Header sync and block download

### 8.1 HeadersSync (per peer)

None → presync → redownload → final (nil). This matches Core's HeadersSyncState. It dies with the peer.

### 8.2 Per-peer header sync

`not_started → started` when `try_start` is true (SyncState monitors the peer). Then, each tick:

- best header within 24 h: the deadline is cleared and never checked again;
- past the deadline, `count == 1` and another preferred peer exists (`BlockDownload.other_preferred?`): exit `:headers_sync_timeout`, inbound or outbound;
- otherwise: kept, checked next tick.

A peer stops being counted only on DOWN.

### 8.3 Block request ownership (`BlockDownload`)

| From | Event | Guard | To |
|---|---|---|---|
| absent | `request` walk | not had (held, archived **or quarantined**), not failed, not in flight, free slot, byte gate (the walk's earliest missing block is exempt only while nothing below it is in flight, BD-3) | requested(P) |
| absent | `mark` (P starts a compact-block reconstruction or its full fallback) | known header | requested(P) (BD-4) |
| requested(P) | `cancel` from P (its partial ended: the block arrived another way) | — | absent |
| requested(Q) / absent | `rebuilt` by P | — | checking(P) (Core `RemoveBlockRequest(hash, nullopt)`, BD-4) |
| requested(P) | `received` from P | — | checking(P) |
| checking(P) | `checked` | — | absent (released) |
| requested / checking(P) | P DOWN, staller (marked by a peer with nothing in flight that found the window exhausted, mark older than the stall timeout), timeout | — | absent; P disconnected |

Stall timeout (`stall_ms`, Core `m_block_stalling_timeout`):

| Event | Effect |
|---|---|
| a staller is disconnected | ×2, at most 64 s |
| `{:block_connected}` | ×0.85, at least 2 s (Core `BlockConnected`) |
| a requested block is delivered | none (BD-7: it used to decay here, so five deliveries undid a doubling while the window's first block was still missing) |

Invariants:

- `per_peer[P] ∪ checking[P] = {h : in_flight[h].peer = P}`
- `bytes = Σ r.bytes`
- `|per_peer[P]| ≤ 16` from walks; marked reconstructions add at most 16 more (Core counts them in transit too)
- **(BD-3)** at most one in-flight block was let past the byte budget, and only while nothing below it was in flight
- **(BD-5)** a cursor never lies above a block that is not held: `{:block_invalid, h, _}` drops the cursors at or above `h`'s height (a `:mutated` failure un-holds without invalidating)

### 8.4 Compact block partial (per peer)

None → partial (getblocktxn; `BlockDownload.mark`) → none: rebuilt (`BlockDownload.rebuilt`), full block, failed (full getdata, still marked), 60 s expiry (full getdata) or the block held another way (`BlockDownload.cancel`). A cmpctblock for a block another peer is already checking is ignored, as Core ignores one it has data for (BD-4).

### 8.5 HighBandwidth

List of at most 3 `{peer, inbound?}`, oldest first; a reselected peer moves to the end. Adding a fourth demotes the oldest, except that an inbound peer never displaces the only outbound one (it is swapped into the second slot first, as Core). A select for a peer already gone is ignored; DOWN removes a peer (BD-6).

### 8.6 BlockServing

Per `{hash, format}`: absent → building (worker plus waiters) or queued → cached. Eviction is LRU.

---

## 9. Services

- **Clock:** atomics slots hold mock wall time, frozen monotonic time and the frozen flag. Moves between system, mock and frozen.
- **KV handle:** open → closed (only tests close it). Iterators and batches are released in `after`.
- **RPC / REST:** one Bandit handler per connection, at most `FdBudget.api_connections/0` (16) per server; more wait up to 5 s, then are closed (IDX-2). Each handler process keeps at most 2 segment read handles (`Segments.limit_read_handles/1`). They read through `ChainState.reader/1` and the `persistent_term` index handles, by name. A disabled index is **nil** in the context, and the consumers also treat `false` as disabled (SVC-1, SVC-2). An RPC method that hits a restarting process answers -32603 for that request only (SVC-4).
- **IBD flag:** `ChainState.view_ibd?/4` for peers and RPC alike: tip work below the minimum, or tip older than 24 h; latched false in the view once false (Core `m_cached_finished_ibd`, SVC-6).
- **Archive readers and witness pruning:** the prune point is shared (`:atomics`) and raised before the files are deleted; a witness read that fails anyway is reported as pruned only if the live prune point says so (SVC-7).
- **Fd budget:** a static plan made at startup: reserve + peers + 16 long-lived readers × 16 handles + the API servers at their caps (2 × 16 × (1 socket + 2 handles)) + RocksDB table files. There are no runtime reservations.

---

## 10. Bug register

Status:

- **fixed**: fixed, with a regression test that fails on the old code (each one checked).
- **open**: confirmed but not fixed; see the reason.
- **not reachable**: reported, then shown by re-checking the code not to be reachable; see the evidence.

Severity reflects impact if the bug is reached.

| ID | Sev | Status | Summary | Evidence / trace | Regression test |
|---|---|---|---|---|---|
| CS-1 | Critical | fixed | `terminate/2` committed the pre-callback archive over a newer commit made earlier in the crashing callback | A turn retires Bm (the batch fills, so a commit writes tip=Bm and deletes Bm's `pending`), then Bm+1 crashes in `Archive.connect` → `archive_crashed` exits → `terminate` flushes the old batch: meta tip=Bk, ends=E_k. The rows of Bk+1..Bm survive while their segments are truncated and their `pending` copies are gone, so the chain is stuck and needs a resync. A reorg variant restores disconnected rows without their spends, which resurrects coins. | `quarantine_test.exs` "a crash after a commit in the same turn…" (failed 3/3 before the fix) |
| IDX-1 | High | fixed | Follower batch could mix branches: X's rows and `"h"` entry under X′'s tip hash | `sync` read `id_at(C)=X`, then a reorg replaced C with X′, then `last = id_at(stop)` read X′. The next rewind sees an active tip and never removes X. Scripthash shows phantom history and misses X′; the filter index is stuck on the missing parent. | `index/follower_reorg_race_test.exs` |
| MP-1 | High | fixed | Reorg re-add did not link re-added txs to their in-pool children | `Pool.add` derived parents only. After P was re-added, the child C had `parents={}`. A later conflict or RBF of P removed P alone, leaving C spending an output that exists nowhere (relayed for 14 days, RBF fee rule bypassed, clusters undercounted). | `mempool/maintenance_test.exs` "a reorg links re-added txs…" |
| AUD-F1 | High | fixed | One peer withholding one block stalled IBD for 600 s per window: a staller that was itself window-blocked was exempt from stall detection | `check_stalling` skipped a staller in `window_blocked`; `walk` put every peer there once its own request found nothing, including the staller with free slots (1 s ticks). Only the 600 s download timeout (not misbehaviour) ended it, and the attacker could reconnect. Now Core's `m_stalling_since`: a peer with nothing in flight that finds the window exhausted marks the holder of the window's first in-flight block (another peer); marks older than the stall timeout disconnect; a delivered request clears the mark. In IBD inbound peers download only with no outbound peer or nothing in flight (Core `sync_blocks_and_headers_from_peer`). Found in a P2P security review, 2026-11-11. | `dos/block_stalling_test.exs`, `p2p/block_download_timeout_test.exs` "F1: …" (both failed before the fix) |
| AUD-F2 | High | fixed | Invalid-witness RBF attempts made the mempool process linearize every touched main and staging cluster from scratch, ~2-3 s per attempt (100 × 64-tx clusters), stalling every full-relay peer through `:infinity` calls | `replacement_checks` → `Pool.diagrams` ran 2K optimal linearizations with no cache use and no work bound, before scripts; `prepare` ran twice per attempt and `Pool.stage` three times. Now: main diagrams from the linearization cache (refreshed when the mempool is idle, `Pool.refresh_stale/2`); staging linearized within a work budget, then in the main order (valid, never better, so never a wrong accept); `stage` reused and built from entry links; the post-script `prepare` skipped when the state is the same term. Repro: ~45 ms per attempt. `extract_best` also reads the cache. Found in a P2P security review, 2026-11-11. | `dos/rbf_linearize_test.exs` (measures the pre-fix computation: ~3 s vs ~15 ms), `mempool/linearize_test.exs` bounded-chunks property |
| AUD-H1 | High | fixed | Orphanage fan-out: every new orphan and every `inv` adding an announcer cost the shared TxRelay O(orphans × announcers) | `limit_orphans` rebuilt the per-peer weight budgets by walking every (orphan, announcer) pair on each call, and nothing bounded the number of announcers: only the orphan count (1,000) and each peer's weight (404,000 WU). 1,000 orphans spending non-existent outpoints, each announced by 200 peers, made one ~94-byte orphan `tx` cost ~127 ms; a few connections streaming fresh orphans delayed every peer's tx relay (and blocks queued behind it in those peers' mailboxes): 755 ms vs 20 ms control at 400 × 100 × 24, 4.6 s at 1000 × 120 × 40. Now Core's global latency score cap (3,000, trimmed from the highest-score peer) and incremental per-peer accounting (Core `m_peer_orphanage_info`); the DOWN handler walks only the peer's announcements. After the fix, 1000 × 200 × 40: 3,000 announcer entries, 41 ms vs 20 ms control. Found in a security review, 2026-11-13. | `dos/orphan_fanout_test.exs` (asserted the stall before the fix), `dos/orphanage_test.exs` "AUD-H1: …" (the score test fails with the cap removed) |
| AUD-F3 | High | fixed | ~48 bytes of memory per received byte when a frame arrives in 1-byte TCP segments: ~200 MB per connection for one 4 MB frame, remote OOM with tens of connections | `FrameBuffer.append` and the v2 `tail` consed each segment onto an iodata list until the frame was complete. Both are now one binary grown by appending (VM in-place append): ~1.3 bytes per byte. Found in a P2P security review, 2026-11-11. | `dos/recv_buffer_memory_test.exs` (v1 41 B/B and v2 50 B/B before the fix) |
| AUD-A1-1 | High | fixed | Decoding a large `block`/`tx` built ~45 B of heap per wire byte, in every peer in parallel: a remote OOM with a few hundred MB per peer | One input with ~4M empty witness items (consensus-serialization-valid, 4,000,000 B) held 181 MB decoded (`decode_bytes` made a fresh empty binary per item) and peaked at ~200 MB per peer; even a realistic block is ~6.5 B/B. Peers decode in their own processes (Core: one message-handler thread), and the attacker needs no PoW: the peer is disconnected only after the decode. Measured: 6 peers released together peaked at 1,067 MB (5.3× one decode). Now the empty vector is the shared literal (18.8 B/B held), and `P2P.DecodeBudget` (node-wide, default 32 MiB, `--decode-budget-mib`) is held for the payload size while a message of 64 KiB or more is decoded and handled (FIFO, released on death, after a GC). Found in a static security review and confirmed by test, 2026-11-17. | `dos/decode_amplification_test.exs` (the shared-literal and concurrent-peers tests failed before the fix: 45.4 B/B; 5.3×) |
| AUD-B9-1 | Medium | fixed | An invalid block relayed by compact block got the relaying peer disconnected and discouraged; Core exempts it (BIP152) | `maybe_punish_for_block` had no `via_compact_block`: a rebuilt block failing `:consensus`/`:mutated` (synchronously or in a deferred `{:block_checked}`) and a cmpctblock header failing `:cached_invalid` punished the peer. Core announces to high-bandwidth peers from `NewPoWValidBlock`, before `ConnectBlock`, so honest Core peers relay PoW-valid invalid blocks: one such block (cheap on testnet4) disconnected and discouraged exnode's honest high-bandwidth outbound peers for 24 h, which helps an eclipse. Now Core's rule (`net_processing.cpp` `MaybePunishNodeForBlock`): via compact, `:consensus`, `:mutated` and `:cached_invalid` are not punished; invalid headers still are. Found in a static security review, 2026-11-17. | `p2p/compact_block_peer_test.exs` "an invalid block rebuilt from a compact block…", "a deferred verdict on a rebuilt block…", "a cached-invalid header via cmpctblock punishes neither…" (all three failed before the fix; the last one had asserted the divergence) |
| AUD-A4-2 | Medium | fixed | Orphan reconsideration ran inline in TxRelay: relaying one parent stalled every peer's TxRelay calls for the sum of its orphan children's script checks | `reconsider_children` made one synchronous `Mempool.accept` per child of an accepted tx (and of a block's txs), recursively, inside the handler that accepted it. Attackers fill the orphanage within its caps with children built to fail late, then relay the parent: every peer blocks in its `:infinity` TxRelay call (inv, tx, notfound, getdata), and the blocks queued behind those calls wait. Measured: 200 children × 25 ms stalled another peer's `inv` 5.2 s. Now Core's work sets (`AddChildrenToWorkSet` to a random announcer, `ProcessOrphanTx` until one decisive orphan): drained by `:orphan_work` steps, round-robin over peers, behind the calls already queued (6 ms). A disconnecting peer's work goes with it. Found in a static security review, 2026-11-17. | `dos/orphan_reconsider_stall_test.exs` (the stall and disconnect tests failed before the fix) |
| AUD-A2-1 | Medium | fixed | Peer-sent address times were stored unclamped: re-announcing known addresses with a future time made them terrible and evictable | Core `ProcessAddrs` clamps a time ≤ 100,000,000 or > now + 10 min to now − 5 days, drops addresses without NODE_NETWORK / NODE_NETWORK_LIMITED, discouraged ones, and unreachable networks; exnode passed them straight to `AddrMan.add`. `add_single`'s update branch then set a known entry's time (tried ones too) to 2³² − 2 h, so `terrible?` held: honest entries were overwritable by any new address in `place_new`, left out of `getaddr` answers, and never refreshed by honest sources, which helps an eclipse. Now `Peer.sanitize_addrs/2` applies Core's rules after the token bucket (`Connman.reject_discouraged/2` in one call). TorV3 from addrv2 is no longer stored (no onion proxy: not reachable). Found in a static security review, 2026-11-17. | `p2p/peer_addr_test.exs` "AUD-A2-1: …" (three tests) and the TorV3 test (all four failed before the fix) |
| AUD-A4-1 | Medium | fixed | `notfound` (and a tx response or an expiry) deleted the peer's announcement, so re-announcing at once piled parked entries behind another peer's request | Core marks the announcement COMPLETED (`ReceivedResponse` → `MakeCompleted`), `ReceivedInv` from that peer is then a no-op, and a hash is forgotten once all its announcements are completed. exnode had no completed state: peer X holds requests unanswered; peer B announces the same hashes, gets parked behind X in `waiting`, sends notfound, re-announces; every round parked new entries while the old ones stayed until X's request ended (≤ 60 s), then all were re-inserted in one turn. Measured: 20 rounds × 100 hashes parked 2,000 entries (now 100). Now `ann_complete/3` with a by-hash peer index (`ann_peers`) for Core's IsOnlyNonCompleted; DOWN completes then erases. Found in a static security review, 2026-11-17. | `dos/notfound_churn_test.exs` (failed before the fix); `p2p/tx_relay_test.exs` property, its oracle moved to Core's rule, with the index and no-all-completed invariants (both fail with forgetting removed) |
| MP-2 | Medium | fixed | A re-add judged against a chain view that is already ahead dropped valid children | A reorg spanning turns sends `[disconnected B]` while the view has B′ (containing P) connected. Re-adding P gives `txn-already-known`, and the error branch removed P's mempool children. | `mempool/maintenance_test.exs` "a re-add judged against a view…" |
| BD-1 | Medium | fixed | A quarantined block was re-downloaded forever | `poison` deleted `{:held,h}` without invalidating the header, so `view_have_many` said "missing" and it was the earliest missing block (exempt from the byte budget). Every peer fetched 1–4 MB, got `:quarantined`, released it, and repeated. | `quarantine_test.exs` "a quarantined block counts as had…" |
| SVC-1 | Medium | fixed | `GET /tx/:txid/outspends` answered 500 whenever address indexing was disabled | `node.ex` passed `scripthash_index: false`; `chain_spender` matched `idx != nil` and called `Scripthash.history(false, …)` → ArgumentError | `rest/disabled_index_test.exs` |
| SVC-2 | Low | fixed | `getblockfilter` with the filter index disabled gave -32603 CaseClauseError instead of Core's "Index is not enabled" | `filter_index: false`; the case matched `nil` only | `rpc/disabled_index_test.exs` |
| P2P-3 | Low | fixed | anchors.dat was rewritten on a Connman crash, so a crash loop redialled the same anchors | `terminate` → `write_anchors` ignored the reason | `p2p/outbound_selection_test.exs` "anchors are not written when Connman stops abnormally" |
| P2P-1 | Low | fixed | Oversized inv/headers/addr before the handshake → misbehaving → disconnect plus 24 h discouragement | Size errors were handled before the handshake gate; Core ignores pre-verack messages | `p2p/outbound_selection_test.exs` "an oversized message before the handshake…" |
| MP-4 | Low | fixed | A 1p1c-accepted child was resubmitted and put in `rejects` | `try_1p1c` accepted the parent while the child was still an orphan → `reconsider_children` → `txn-already-in-mempool` → `rejects` | `dos/orphanage_test.exs` "a 1p1c package…" |
| CS-2 | Medium | fixed | The shadow halt was not persisted; a ChainState restart replayed `pending` past the divergence before the shadow could halt again, and a restart without `--shadow` never halted | `halted:false` at init; the monitor keeps no halted flag and casts once. Now a synced KV mark is loaded before replay and cleared only by an operator; it is kept without `--shadow` too, by design. | `chain/halt_test.exs` |
| BD-2 | Medium | fixed (soak pending) | Stall detection was more aggressive than Core | Age was measured from the request time, not `m_stalling_since`, and "blocked" did not require an empty in-flight set. Fixed with AUD-F1, which adopted Core's rule; download behaviour on a soak has not been measured yet. | `p2p/block_download_timeout_test.exs` |
| MP-1b | Medium | fixed | A reorg re-add merged any number of in-pool clusters into one, and its linearization blocked the mempool, TxRelay and every peer for seconds to hours | `Pool.stage` seeds the re-added tx and its in-pool parents only, so `cluster_limits` saw a 1-tx cluster; `Pool.add` then linked every child cluster (MP-1). P with k outputs, each spent by a 63-tx chain: one cluster of 1 + 63k. `Linearize.chunks` measured 1.4–2.1 s at 505 txs and 17.5 s at 1,009; `limit_size` → `trim` → `cluster_chunks` ran it synchronously inside the update, and `extract_best` (TxRelay, every tick, `:infinity`) again. Later accepts into it fail "too-large-cluster". Now `Pool.trim_oversized` (Core `TxGraph::Trim`) runs right after the re-adds. | `mempool/maintenance_test.exs` "a reorg re-add that merges child clusters past the limit is trimmed back" (91-tx cluster before the fix) |
| MP-3 | Medium | fixed | A Relay subtree restart killed every peer blocked in, or making, a TxRelay call | Peers call TxRelay with `:infinity` and no catch, contradicting node.ex's "peers stay connected". A new Mempool crash path exists since the async accept (`finish_accept`'s inline verify). Now the peer-facing TxRelay API and `Mempool.match_short_ids` catch the exit and answer neutrally. | `dos/orphanage_test.exs` "a peer blocked in a TxRelay call survives the relay's death…" |
| MP-5 | Medium | fixed | Transient mempool answers were cached as fee failures until the next block; with REST enabled this was a tx-relay blackout | `rejected` put every `:reconsiderable` into `reconsiderable`, and `add_announcement` skips those. "mempool busy" shares its 128 slots with unauthenticated REST `POST /tx`: ~128 concurrent bad-signature submissions spending real UTXOs made every P2P tx "busy", and each wtxid stayed suppressed until a block. Each busy parent also started a synchronous 1p1c that skips the cap. Now transient answers leave no trace and an orphan that gets one stays. | `dos/orphanage_test.exs` "a transient mempool answer is not cached…", "an orphan whose reconsideration gets a transient answer stays an orphan" |
| CS-6 | Medium | fixed | A shadow divergence could be recorded without the node ever halting | The halt was one cast to ChainState's registered name. If ChainState was restarting (e.g. a storage exit; rest_for_one stops Services, P2P and Relay first, so the name is gone for hundreds of ms) when the monitor finished that round, the cast was dropped. The restarted ChainState had no mark, found the shadow ahead, called `set_ahead`, and the tolerance hid the mismatch from then on. Now the halt stays pending in the monitor and is re-sent to the caller of every `round` / `shadow_tip` / `set_ahead` until `halt_ack`. | `shadow/monitor_test.exs` "a halt lost while the chain state restarts reaches the restarted one" |
| IDX-2 | Medium-Low | fixed | The fd budget assumed 16 archive readers; every REST/RPC keep-alive connection was another, with up to 16 fds, and connections were unbounded | `segments.ex` caches read handles per process; Bandit's default is 100 acceptors × 16,384 connections. Enough clients exhausted the descriptors and the chain state's next segment open failed (a storage error: the node stops). Now each server takes 16 connections (one acceptor), each handler keeps 2 handles, and `FdBudget.plan` counts them. | `fd_budget_test.exs` "the API servers are capped…", `archive/segments_test.exs` "limit_read_handles/1…" |
| BD-7 | Low-Medium | fixed | The stall timeout fell back to 2 s on every delivered block, so its doubling never held while the window's first block was missing | `received` applied ×0.85 per delivery; Core decays only in `BlockConnected`. Five deliveries took 4 s back to 2 s, and each new holder of the window's first block was dropped after ~2 s on a slow link, losing up to 16 requests each time. Now the decay is on `{:block_connected}`. | `p2p/block_download_timeout_test.exs` "the doubled stall timeout holds…" |
| TXR-1 | Low-Medium | fixed | After a failed 1p1c package, an accepted parent was never announced and the invalid child stayed an orphan | `try_1p1c` looked only at `res.state`. A parent that passes its single sub-accept stays in the pool when the child then fails; the mempool notifies with TxRelay as origin, which TxRelay ignores. The parent's other orphans were not reconsidered either. Now per-tx results are handled as Core's `ProcessPackageResult`. | `dos/orphanage_test.exs` "a failed 1p1c package: the parent accepted alone is announced…" |
| BD-3 | Low-Medium | fixed | The byte budget could be bypassed by one block per woken peer | The exemption applied to each walk's first missing block, not the global one: with the earliest blocks in flight, every peer's walk took one more past the budget. Now it is exempt only while nothing below it is in flight. | `p2p/refill_test.exs` "the byte budget gates requests…" (the old test encoded the bypass) |
| BD-4 | Low-Medium | fixed | Compact-block reconstructions were not marked in flight, so the block was also downloaded whole | `rebuild` / `request_full_block` never told BlockDownload (Core `BlockRequested(…, partialBlock)`); a rebuilt block left another peer's request standing (Core `RemoveBlockRequest(hash, nullopt)`); a cmpctblock for a block being checked started a mempool pass and a getblocktxn. Now `mark`, `rebuilt`, `cancel` and `in_flight_state`. | `p2p/compact_block_peer_test.exs` "a reconstruction is in flight from its peer…", "…gives its request back" |
| P2P-2 | Low | fixed | "Already connected" was checked by (IP, port), not IP | `connected_targets` keyed on `addr_key({ip, port})` and inbound peers carry ephemeral ports, so the node dialled out to peers already connected to it. Now the IP alone matches too (Core `AlreadyConnectedToAddress`), anchors included. | `p2p/outbound_selection_test.exs` "an address whose IP is already connected inbound is not dialled" |
| P2P-4 | Low | fixed | An inbound peer could run untracked if Connman restarted while the Listener ran | `register_inbound` was a cast to a name unregistered while PeerSup was already back: the peer escaped the inbound limit and eviction. Now a call; with no Connman the connection is refused. | `dos/listener_accept_test.exs` "an inbound peer that cannot be registered is refused…" |
| MP-7 | Low | fixed | An accept that found its tx added meanwhile by `submitpackage` put the in-mempool tx in `rejects` | `submit_package` ignores the pending sets; `end_job` re-prepares and answers "txn-already-in-mempool", which `rejected` filed as a rejection (breaks the MP-4 invariant: if evicted and re-announced it was filtered until the next block). Now it counts as had. | `dos/orphanage_test.exs` "txn-already-in-mempool is not a rejection" |
| CS-3 | Low | fixed | A reorg deeper than the witness-pruning horizon crashed `disconnect_to` when a mempool is configured, on every restart | `{:ok,b} = Block.decode_exact(read_block)` got `{:error, :witness_pruned}`. Now `Archive.read_block_txs` rebuilds the block without witnesses; its segwit spends fail the re-add and leave the mempool with their descendants. | `archive/prune_cold_test.exs` "a reorg below the witness-pruning horizon works with a mempool" |
| SVC-4 | Low | fixed | RPC rescued exceptions, not exits: a `:noproc` during a subtree restart exited the handler and dropped the whole (batch) response | `Methods.call` had only `rescue`. Now an exit is -32603 "node component unavailable, retry" for that request. | `rpc/component_restart_test.exs` |
| MP-6 | Low | fixed | The `unbroadcast` set was pruned only by `lookup`; a txid evicted and later re-accepted from P2P still read as unbroadcast | Core erases it in `removeUnchecked`. Now pruned to pool members after every handler that changes the pool. | `mempool/maintenance_test.exs` "a tx that leaves the pool leaves the unbroadcast set" |
| CS-4 | Low | fixed | A quarantined disconnected-archived block was not a candidate again after `reconsider` until a restart | `reconsider_poisoned` re-held only `pending` bodies; an archived block off the active chain (quarantined while being reconnected) went back to `disconnected` only through `load_candidates` at start. Now reconsider puts it back. | `chain/quarantine_test.exs` "reconsidering an archived block quarantined on reconnect…" |
| CS-5 | Low | fixed | `init` hung if a private ScriptExec died during startup replay (tests / embedded only) | the selective receive passed its DOWN to `handle_down`, which ignored it, and waited for job results forever. Now it exits `{:script_exec_down, reason}` as after init. | `chain/quarantine_test.exs` "the private script executor dying during startup replay…" |
| SVC-3 | Low | fixed | REST `/utxo` could answer 500, or another block's hash, in the ≤ 200 ms between a disconnect and the index rewind | `HeaderIndex.ancestor` returned nil for a row above the tip, and a row of a replaced block got the new block's hash. Now rows whose indexed block is not the active one are skipped. | `rest/esplora_test.exs` "/utxo skips rows of blocks a reorg replaced…" |
| SVC-5 | Low | fixed | `Scripthash.sync_to` waited for an exact tip match and missed a tip that moved past | Now it returns once the block is on the indexed chain at or below the tip. | `rest/esplora_test.exs` "Scripthash.sync_to returns at once for a block below the indexed tip" |
| BD-5 | Low | fixed | The download cursor skipped a block that was unheld without being invalidated (`:mutated` at connect) | The cursor kept passing while the best chain only grew, so peers with one never selected the block again. Now `{:block_invalid}` drops cursors at or above it. | `p2p/refill_test.exs` "a held block failed as mutated is selected again…" |
| BD-6 | Low | fixed | HighBandwidth had no outbound protection; a `select` for a dead peer demoted a live one | Now Core's rule (an inbound peer never displaces the only outbound HB peer) and dead peers are ignored. | `p2p/high_bandwidth_test.exs` |
| SVC-6 | Low | fixed | The IBD flag was not latched and differed between RPC and P2P | RPC used tip age only, on the committed tip; peers added the minimum-work check; neither latched, so an old tip flipped a synced node back into IBD. Now one latched `ChainState.view_ibd?/4`. | `rpc/ibd_test.exs` |
| P2P-3b | Low | fixed | anchors.dat was still written when a supervisor restart cascade stopped Connman | The cascade's reason is `:shutdown`, as a node stop's, so a crash loop of ChainState, Headers or a P2P sibling redialled the same anchors. Now written only when the node is marked stopping (`Node.stop/2`, application `prep_stop`) or on a direct `:normal` stop. | `p2p/outbound_selection_test.exs` "anchors are not written when Connman stops abnormally" |
| KV-1 | Low | fixed | After an abnormal node stop, a new node in the same VM could not open the datadir | `KVOwner.terminate` closed only on `:normal`/`:shutdown`, and the `persistent_term` index handles pinned the DB and its LOCK. Now the owner closes on every stop. | `node_supervision_test.exs` "a killed node has closed its store too…" |
| SVC-7 | Low | fixed | REST could answer 500 when witness pruning raced a read | readers checked their stale `wpruned`, while `prune_witness` deleted the files before `commit` published the new reader; the read crashed on `enoent`. Now a shared live prune point, raised before the deletion, and a failed witness read re-checked against it. | `archive/prune_cold_test.exs` "a reader taken before a prune reads the newly pruned blocks as pruned…" |
| CS-8 | Low | fixed | After a failed reorg to an equal-work branch, the node stayed on that branch; Core returns to the first-seen one | A and B are equal-work siblings, A received first and active. C, an invalid child of B, makes both nodes reorg to B and fail C. Core keeps A in `setBlockIndexCandidates` (ranked above the tip B by `nSequenceId`) and reorgs back to A; exnode required a candidate to have strictly more work than the tip and stayed on B. No validity difference (both branches valid, equal work), but the active tip, what is built and relayed on, differed from Core's until the next block. Found by the consensus differential property, 2026-11-13. | `chain/equal_work_fallback_test.exs` (failed before the fix), `properties/consensus_differential_test.exs` |
| CS-9 | Medium | fixed | `--dbcache` did not bound the coin cache's memory: a mainnet node with `--dbcache 8000` reached 22 GB and was killed by the kernel OOM killer | `Overlay` counted 200 bytes per entry and kept up to 2 queued outpoints per entry on the process heap. Measured: an ETS entry is ~301 bytes, a queued outpoint 88 bytes, and the heap's growth margin and GC copies about doubled the queue, so real use was ~2.5x the budget. Now the budget is charged 320 bytes per entry plus the exact size of the generation queue, whose outpoints each block packs into one off-heap binary (37 bytes per outpoint). Found in a mainnet IBD, 2026-11-15. | `archive/overlay_test.exs` "CS-9: the budget bounds real memory…", overlay model property |
| CS-7 | — | not reachable | A rejected block still in `round_rejected` when ChainState crashes would never be checked by the shadow | Re-checked: between `fail_block` (which commits first) and the turn's `flush_round` only an empty `maybe_commit`, `publish` and `publish_pipeline` run, with no I/O that can exit. | — |

Candidates that were checked and ruled out:

- stale script, prep or prefetch results;
- waiter reply leaks;
- request tracker leaks;
- double insert from concurrent accepts;
- DOWN racing `checked`;
- duplicate version/verack;
- handshake timeouts after READY;
- AddrMan count drift;
- an index crash between the tip and its rows;
- iterator and batch leaks;
- (2026-11-12) scripthash totals double counting, interrupted backfill, merges on missing keys, key-family collisions, totals mixing two snapshots;
- (2026-11-12) mempool: lost or double replies, stranded `deferred`, `pending_*` leaks, task result racing DOWN, stale inserts, concurrent RBF / parent-child jobs, package partial state;
- (2026-11-12) TxRelay tracker counts and parked entries, orphan index consistency, a double `:connected` after a resync race;
- (2026-11-12) BlockDownload invariants across `received` / `release` / `drop_peer` / DOWN, duplicate delivery during checking, SyncState counts after a restart, deadlocks through the new `:infinity` calls, v2 transport fallback, Connman slot accounting, HeadersSync phases, BlockServing waiters.

---

## 11. Fix issues

The fixed bugs are grouped by root cause, in priority order.

1. **Durability across crashes (CS-1).** `Chain.State`: `note_durable/1` after every durable archive write; `terminate/2` commits only when `durable_current?/1`.
2. **Readers racing a reorg (IDX-1).** `Index.Follower.sync`: parent-linkage check per block, and the tip taken from the linked records; a broken link ends the batch.
3. **Mempool consistency across reorgs (MP-1, MP-2).**
   - `Pool.add` links existing children: parents/children both ways, and the clusters merge.
   - `update_for_reorg` keeps the children of a tx that the view already reconfirmed.
4. **Quarantine visible to download selection (BD-1).** A `{:quarantined, h}` view marker is set in `poison` and `load_poisoned` and removed in `reconsider_poisoned`. `view_have_many` and the `have_many` call path count it as had.
5. **Disabled services are nil, not false (SVC-1, SVC-2).** `Node` builds `nil`, and the Esplora and RPC consumers accept both.
6. **Durable halt (CS-2).** `Chain.State`: synced `{:meta, "halt"}` mark written before the halt takes effect, `load_halt/1` before startup replay, `clear_halt/1`, `halt_mark/1`; `mix exnode.reconsider` lists it and clears it with `--clear-halt`.
7. **Lifecycle hygiene at the edges (P2P-1, P2P-3, MP-4).**
   - Pre-handshake size errors are ignored.
   - Anchors are written only on a clean stop.
   - The 1p1c child is dropped from the orphanage before the parent is reconsidered.
8. **Peer-driven work is bounded (AUD-F1, AUD-F2, AUD-F3, AUD-H1, BD-2).**
   - `BlockDownload`: Core's `m_stalling_since` staller rule (no exemption for a window-blocked staller), and the IBD preferred-download gate.
   - `Mempool`: RBF diagrams from the linearization cache plus a bounded staging linearization (`Linearize.chunks_bounded/3`); idle refresh of stale clusters.
   - `FrameBuffer`, `V2.Transport`: receive buffers are single binaries.
   - `TxRelay`: the orphanage's total latency score is capped (Core's 3,000) and its per-peer accounting is incremental, so `limit_orphans` costs O(evictions).

9. **Bounded mempool work after a reorg (MP-1b).** `Pool.trim_oversized/2` after the re-adds in `update_for_reorg`, before `limit_size` or any linearization.
10. **Signals that must arrive are re-sent until acknowledged (CS-6).** `Shadow.Monitor`: `halt_pending`, re-sent to the caller of `round` / `shadow_tip` / `set_ahead`; `Monitor.halt_ack/1` from ChainState's halt handlers.
11. **TxRelay keeps only verdicts on the tx (MP-5, MP-7, TXR-1).**
    - Transient mempool answers are not cached and start no 1p1c; an orphan that gets one stays.
    - "txn-already-in-mempool" is had, not rejected.
    - A failed 1p1c package's per-tx results are processed (Core `ProcessPackageResult`).
12. **Callers survive subtree restarts (MP-3, SVC-4).** The peer-facing TxRelay API and `Mempool.match_short_ids` catch exits and answer neutrally; `RPC.Methods.call` turns an exit into -32603.
13. **Edges that crashed or drifted (BD-7, CS-3, IDX-2).**
    - BlockDownload decays the stall timeout on `{:block_connected}`, not on delivery.
    - `disconnect_to` reads the block with `Archive.read_block_txs` (works below the pruning horizon).
    - RPC and REST: 16 connections each, 2 segment handles per handler, counted in `FdBudget`.

14. **Download scheduling parity with Core (BD-3, BD-4, BD-5, BD-6).**
    - The byte-budget exemption holds only while nothing below the block is in flight.
    - Compact-block reconstructions are in flight (`BlockDownload.mark`), a rebuilt block takes over any request (`rebuilt`), an ended partial gives its request back (`cancel`), and a block being checked is not rebuilt again.
    - `{:block_invalid}` resets the cursors at or above the block.
    - HighBandwidth keeps the last outbound peer and ignores dead ones.
    - Their effect on IBD speed has not been measured on a soak (as for BD-2 and BD-7).
15. **An explicit node-stop path (P2P-3b, KV-1).** `Exnode.Node.stop/2`, `mark_stopping/1`, `stopping?/1`, and the application's `prep_stop`; Connman writes anchors only then; KVOwner closes the store on every stop.
16. **Connman tracks every peer it should (P2P-2, P2P-4).** IP-only "already connected"; inbound registration as a call, refused when Connman is down.
17. **Readers racing a reorg or a prune (SVC-3, SVC-5, SVC-7).** `/utxo` checks each row's indexed block against the active chain; `sync_to` accepts any indexed block; a live witness prune point shared with readers.
18. **Smaller lifecycle gaps (CS-4, CS-5, MP-6, SVC-6).** Reconsider restores archived candidates; init exits on the private executor's DOWN; the unbroadcast set follows the pool; one latched IBD flag.
19. **Chain selection at equal work (CS-8).** `Chain.State.find_target` compares candidates with the tip by Core's comparator key (`work_key/2`), so an equal-work candidate with an earlier body ranks above the tip.
20. **The coin cache's budget is real memory (CS-9).** `Overlay.memory/1` charges each entry its measured ETS size and the generation queue its packed bytes; eviction runs while the charge is over `--dbcache`.

21. **Peer decoding is bounded node-wide (AUD-A1-1).** `CompactSize.decode_bytes` returns the shared `<<>>` for an empty vector; `Peer.process_message` decodes and handles a message of 64 KiB or more inside `DecodeBudget.with_budget/3`, sized by the payload.

22. **Compact-block relays are not punished for the block (AUD-B9-1).** `Peer.maybe_punish_for_block/4` takes `via_compact` (cmpctblock headers, rebuilt blocks, and their deferred verdicts via `rebuilt_deferred`), as Core's `MaybePunishNodeForBlock`.

23. **Orphans are reconsidered in steps (AUD-A4-2).** `TxRelay.add_children_to_work_set/2` queues children per announcer; `handle_info(:orphan_work)` runs `orphan_work_step/1`, one peer's work until a decisive answer, and reschedules itself behind the mailbox; `drop_orphan_work/2` on DOWN.

24. **Peer addresses are sanitised before the address book (AUD-A2-1).** `Peer.sanitize_addrs/2`: services, reachable networks (`Connman.reachable_nets/0`), the time clamp, and `Connman.reject_discouraged/2`.

25. **Request responses complete announcements (AUD-A4-1).** `TxRelay.ann_complete/3` (notfound, a received tx, expiry) and `drop_peer/2` follow Core's MakeCompleted / DisconnectedPeer, with `ann_peers` as the by-hash index.

CS-7 was re-checked and is not reachable (see the register). No item of the register is open.
