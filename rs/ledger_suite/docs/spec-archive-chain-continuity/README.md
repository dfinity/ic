---
id: DEFI-2967-followup
title: Archive chain continuity and bounded archiving retries
tags: [ledger, archive, icrc, icp]
---

# Archive Chain Continuity And Bounded Archiving Retries

This specification is split into an overview and three parts, each with the
**behavioural contract** first and the **solution** second, following the convention
in dfinity/oisy-trade#256:

| part | requirements | design | implemented by |
|---|---|---|---|
| **A** — the archive append protocol: placement by declared index, chain continuity, capacity reporting, the index-less compatibility path, counters | [`archive-protocol/requirements.md`](archive-protocol/requirements.md) | [`archive-protocol/design.md`](archive-protocol/design.md) | PR 1 (`ic-icrc1-archive`) |
| **L** — ledger reconciliation and retries: range tiling, the archived prefix, backoff and halts, the capability probe, round shape, bounded waits | [`ledger-reconciliation/requirements.md`](ledger-reconciliation/requirements.md) | [`ledger-reconciliation/design.md`](ledger-reconciliation/design.md) | PR 3, PR 4 |
| **C** — archive creation and handover: the creation journal, adoption, the staged controller handover | [`archive-creation/requirements.md`](archive-creation/requirements.md) | [`archive-creation/design.md`](archive-creation/design.md) | PR 4 |

This file holds what all three share: the problem, the glossary, the non-goals, the
constraints of the surrounding system, the delivery sequence, and the alternatives
that were considered. Read it first; the parts assume it.

*Criteria are cited by document prefix: `A` for the archive append protocol, `L` for
ledger reconciliation and retries, `C` for archive creation and handover — so `A2.4`
is criterion 4 of requirement 2 in
[`archive-protocol/requirements.md`](archive-protocol/requirements.md). Design
decisions are numbered once across the whole specification (D1–D10); each design
document says which it holds.*

> **Read the criteria as a set.** They interlock across the three parts, and several
> are deliberately permissive on their own because a sibling constrains the case they
> leave open — `A1.4` allows what `A2.1` forbids once an index is present, and `L3.1`
> looks absolute until `L3.6` excepts the ICP ledger. A criterion read in isolation will
> therefore look either too weak or too strong more often than not. Where that is
> load-bearing the criterion says "per X.N.M"; where it is not stated, assume a sibling
> is carrying it and check before concluding a gap. The parts interlock the same way —
> A1's chain check needs A2's placement to know which block it applies to, and L3's
> prefix needs A3's report to have something to trust — which is why the build order in
> Delivery is by PR rather than by part.

## Introduction

**Archiving is switched off today.** On the ckBTC and ckDOGE ledgers
`trigger_threshold` is set beyond any reachable block count, so blocks accumulate in
the ledgers instead. This document is the contract archiving must satisfy before it
is switched back on. Four things carry most of it: an archive must be able to tell
where an incoming batch belongs and refuse one that does not fit; it must report its
own extent, so a ledger never has to infer it; a ledger must not stop serving a block
until an archive has confirmed holding it; and a ledger must space its attempts while
archiving is failing. The requirements below state those four precisely and add what
they need in order to be safe in practice — how capacity is reported, what an
un-upgraded archive means, how a lost archive creation is detected, and what a round
may do. The rest of this section is why the four are needed.

A ledger keeps only its most recent blocks and moves older ones to archive
canisters. Because an archive is a separate canister, moving blocks means an
inter-canister call, and the two halves of that call commit independently: the
archive commits the blocks it stored when its message ends, while the ledger
records *that* it stored them in a later message of its own. If the ledger's later
message fails, the blocks are in the archive and the ledger does not know it.

The ledger's response is to send those blocks again on its next attempt, and
`append_blocks` gives an archive no way to tell that second send from a genuine
continuation — the call carries blocks but no indication of where they belong. So
the archive appends them a second time. Every index above that point then shifts
by the length of the duplicate, and because an archive maps a global block index
to its own storage by a fixed offset chosen when it was created, the shift is
permanent and silent. `icrc3_get_blocks` returns a block that is internally valid
and belongs at a different index.

Two clients read those blocks and are harmed differently. Rosetta checks that each block's
parent hash matches the block before it — the check that catches a misplaced archive
block, since archives return blocks without indices and Rosetta numbers them from the
ledger's callback — so it stops synchronising and goes stale. The index
canister performs no such check, so it attributes transactions to whichever
accounts a wrongly-placed block names, and serves plausible but incorrect account
histories. Neither can repair the archive.

A second failure compounds the first, and in one direction: a ledger whose archiving
keeps failing retries on every transaction with no spacing, so a single persistent
cause becomes continuous wasted work — and the storage pressure that prompted this
work sat on the subnet for about four and a half hours — while the blocks it could
not archive accumulate, so there is more to send once archiving
resumes. Switching archiving back on re-exposes both, which is why the contract
comes first.

## Glossary

- **Archive**: the ICRC archive canister, `ic-icrc1-archive`. "THE Archive" never
  means the ICP archive, which is a separate canister and is not changed here — see
  the corresponding non-goal.
- **Tail_Archive**: the archive a ledger currently appends to — the most recently
  created one. Earlier archives are full and are never contacted again.
- **Archive_Range**: the contiguous span of global block indices an archive holds,
  from its `block_index_offset` up to but excluding its Archive_Position, **as the
  archive itself reports it** (A3). It is observed, not inferred.
- **Published_Range**: the span a ledger publishes for an archive through
  `archives()`. It is the ledger's own record — derived from what archives have
  reported for every archive created since this change, and inferred for those that
  predate it — so it is not evidence about an archive on its own; L1.2 constrains
  what it may say, and L3.3 what contradicts it.
- **Archive_Position**: the next global block index an archive expects, i.e. the
  index one past the last block it holds. Reported as `next_index`.
- **Declared_Index**: the global index an append states its first block belongs
  at, carried as the optional second argument to `append_blocks`.
- **Indexed_Append**: a call to `append_blocks` that carries a Declared_Index.
- **Index_Less_Append**: a call to `append_blocks` that carries no
  Declared_Index — the only shape a ledger built before this change can send.
- **Archiving_Round**: one attempt by a ledger to move blocks to archives,
  triggered by a transaction.
- **Archived_Prefix**: the blocks a ledger has stopped serving itself because an
  archive confirmed holding them. Its *end* means the lowest index the ledger still
  serves, one past the last it has given up — exclusive, like an Archive_Position and
  unlike a Published_Range, so that the two compose without an off-by-one. L3.3 is
  the criterion where the inclusive form meets the exclusive one, and says so.
- **ARCHIVE_CALL_TIMEOUT**, **BACKOFF_INITIAL**, **BACKOFF_CAP**: respectively the
  longest a ledger waits for a response to a call it is willing to stop waiting for,
  the minimum spacing between archiving attempts after the first failure, and the
  ceiling that spacing grows to under repeated failure. L7 and L4 fix the
  behaviour; `design.md` settles the numbers.
- **`block_index_offset`**: the archive's published second `init` argument, the
  global index of the first block it will ever hold. It is fixed for the life of
  the canister.
- **Expected_Parent**: the hash an archive is told at `init` to expect as the parent
  of the first block it stores, i.e. the hash of the block at
  `block_index_offset - 1`. Absent for an archive whose offset is zero, and absent
  for one created by a ledger that does not supply it.
- **`at_capacity`**: a reported flag distinguishing an archive that has reached its
  own configured storage limit from one that merely could not grow.

## Non-goals

- **Repairing a suite that has already diverged.** These requirements prevent
  further divergence; they do not correct an archive that already serves a block at
  the wrong index. Detecting whether that has happened is possible today with
  existing tooling and is a prerequisite to this work rather than part of it, and
  correcting it needs deliberate, operator-computed intervention that is safe only
  once it is known to be needed.
- **The ICP archive's side of the indexed protocol.** The ICP archive is a separate
  canister from the ICRC archive and is not changed here, so the ICP ledger gains
  the ledger-side obligations but not the addressed-append ones. This leaves the ICP
  suite exposed to the divergence described above until that port lands, which is
  accepted deliberately and tracked separately. L1.5, L3.6, L5.5 and
  L7.6 pin the behaviour that makes the exemption safe rather than silent — each
  says what the ICP ledger does *instead*, so none of it is left to inference.
- **Building the change that stops an archiving failure contradicting a transaction's
  reply.** On a ledger that waits for archiving before replying, a failure after the
  transaction has committed turns a successful transfer into a rejection, which a client
  that retries can turn into a double credit. L4.5 states the property that has to
  hold, because a contract for archiving failures that said nothing about the reply
  would be incomplete — but the code that delivers it is a separate change, reviewed
  separately, and `design.md` orders it as a dependency rather than as one of this
  specification's PRs. So the requirement is in scope and its implementation is not.
- **Recovering the cycles in an abandoned archive canister.** A creation that is
  interrupted after the canister exists but before the ledger has recorded its
  identity leaves a canister nobody can address. C1 requires that this is
  detected and that archiving stops, because continuing past it is what turns one
  abandoned canister into many; reclaiming its cycles needs an administrative path
  that does not exist and is accepted as a loss.
- **Surviving a storage refusal that terminates the archive's execution.** Not all
  refusals return control: two of them end the call outright, so the archive cannot
  keep a partial result or report a cause, and every block it stored earlier in that
  call is discarded with it. Those are the cycle-reservation refusals, and they are
  the class that refused the ledger's upgrade on 2026-09-01 — so A4's reporting
  covers the refusals that *do* return control, and this class is out of reach of any
  protocol change (A4.5).

  The answer to it is configuration, not protocol — a higher `reserved_cycles_limit`,
  or better a reserved `memory_allocation`, inside which growth needs no further
  reservation and so cannot be refused on these grounds at all. That is why the
  drafted proposals are a dependency of this work rather than an adjacent nicety;
  `design.md` has the mechanism.
- **Bounding a ledger's memory growth.** Switching archiving back on bounds only the
  blocks a ledger retains — `trigger_threshold` of them, about 1.2 MiB at 2000 — which
  is the smaller part of what a transaction costs it: of the ~1040 B a maximal
  `icrc2_approve` takes, only the ~624 B block is archived, and the ~416 B of allowance
  and expiration entries stay for as long as the approval does. So archiving slows
  spam-driven growth by roughly 2.5x rather than bounding it, and no `memory_allocation`
  covers the remainder, because stable memory never shrinks and usage once reached is a
  permanent floor on what the canister is billed. The heap is the bounded half and
  resets on upgrade. Rate limiting, the transfer fee and allowance pruning are the
  levers for the rest, and each is separate work.
- **Restoring a ledger from a canister snapshot as a recovery path.** A ledger
  restored alone resumes issuing block indices its archives already hold with
  different content, so its chain forks from the archived prefix and balances
  rewind. L3.7 requires that such a fork is detected — the archives are then ahead
  of a chain tip that has moved backwards — and L3.8 and A1 require that it is
  not extended into the archives; none of them makes the restore safe. The only
  coherent rollback is the whole suite to a common point, accepting the loss after
  it.
- **Verifying the first append to a freshly created archive from a ledger that
  sends no index.** Such an append is unverifiable in principle: the archive has no
  last block to chain against and the call carries nothing saying where its blocks
  belong, so it is taken on trust (`A1.4`). This is the one window the
  archive-only release does not close, and it is the exact shape of the original
  failure — a node created for one index, then handed blocks from a lower one.
  Refusing instead is not available, because a ledger that sends no index does the
  same thing on the ordinary path at every node roll-over, so refusing would halt
  archiving rather than only the bad case. `A1.6` makes the window countable so
  it is visible while it lasts and demonstrably shut once ledgers send an index.

- **Defending against an archive being downgraded beneath its ledger.** Once a ledger
  has learned that its Tail_Archive reports its range (L5.4), it sends blocks
  without asking again, and an archive rolled back to a build that ignores the
  Declared_Index would store them as new before replying with nothing. The ledger
  cannot tell in advance; `design.md` states the release-order rule that prevents it
  and bounds the exposure to a single append.
- **Validating the archive controller configuration.** The platform allows a canister
  ten controllers; `ArchiveOptions` puts no bound on how many a ledger names for its
  archives. Part C's handover takes at most ten distinct controllers as a precondition
  and cannot complete otherwise, so the ledger's `init` and `post_upgrade` should reject
  a larger set, counted after de-duplication — and the handover sends the de-duplicated
  list, since the platform bounds the encoded vector before it collapses duplicates. That is a minimal, self-contained change and is tracked as its own
  ticket and PR rather than folded into this one.
- **Making the archive's canister logs readable.** Some obligations here are
  satisfiable only through a metric because a canister's log is not readable by
  default. Changing that is a governance proposal, not a code change, and is out
  of scope.

## Design overview

Archiving moves blocks from a ledger to an archive canister, and the two halves of
that move commit independently. `send_blocks_to_archive` ends its message at the
`.await` on `append_blocks`, so the archive's write commits while the ledger's
record of it belongs to a later message. A failure in that later message leaves the
blocks in the archive and the ledger unaware, and the ledger's next attempt sends
them again. The archive cannot tell that second send from a continuation, because
`append_blocks` carries no index.

The design closes that by **addressing appends**: the call gains an optional
expected start index and returns an optional result carrying the archive's own
extent. The archive can then place an incoming batch exactly — continuation, already
held, straddling, below its range, or a gap — and the ledger stops inferring what an
archive holds and starts being told (`A2`, `A3`). Idempotency follows rather
than being bolted on: a re-send is recognised and discarded, so a lost
acknowledgement costs a round trip. That is ICP's own callee-side ID-deduplication
pattern, with an identifier that never expires, because an archive's position only
moves forward.

Three smaller pieces complete it. Capacity stops being a failure and becomes a
reported position plus a flag distinguishing "I am full" from "the platform refused
me memory" (`A4`), which is what lets an attempt under storage pressure keep the
blocks that fit. A backoff bounds the per-transaction retries a failing archive
currently provokes (`L4`). And a round is reduced to a single append to a single
archive (`L6`), which removes both loops from `send_blocks_to_archive` and, with
one append, puts the range reconciliation and the block removal in the same message.

Two things outside this design gate its value, and Delivery orders both: **DEFI-2967**,
because a post-commit archiving failure turns a committed transfer into a rejection
the ckBTC minter retries without deduplication, and a **Rosetta sync from genesis**,
because nothing here repairs a suite that has already diverged.

## Constraints

Facts about the surrounding system that the implementation must not violate.

**An archive's offset is immutable and the mapping is a subtraction.**
`block_index_offset` is written to a stable cell at `init`
(`icrc1/archive/src/main.rs:84, 173`) and `post_upgrade()` takes no arguments
(`:212`). Reads map global to local as `start - opts.block_index_offset` (`:280`).
A node that stores the right blocks under the wrong offset is therefore wrong at
every index, permanently — which is why `A2.6` has to be checked on the archive
and cannot be inferred by the ledger. Note the read path already enforces this
boundary, rejecting a `start` below the offset (`:274-277`); only the write path
lacks it.

**What happened on 2026-09-01, so nothing here has to reconstruct it.** An
unrelated canister's transient ~894 GiB allocation took subnet `pzp6e` from 68.7 GiB
to 962.5 GiB between 05:28 and 07:28 UTC and released it around 10:00-10:28 — so for
roughly four and a half hours the subnet sat 212.5 GiB above the 750 GiB
storage-reservation threshold. Two ck canisters were refused a memory growth in that
window:

* **08:45 — the ckBTC index stopped syncing permanently**, its one-shot timer chain
  never re-arming (DEFI-2983).
* **09:13:17 — the ckBTC ledger's upgrade failed**: `Canister cannot grow memory by
  59179008 bytes due to its reserved cycles limit. The current limit
  (5_000_000_000_000) would be exceeded by 2_139_715_996_442.` That is `post_upgrade`
  asking for 56.4 MB and being refused. The same upgrade succeeded at 11:00:37 once
  the subnet had dropped back, with nothing on the ledger changed.

**Archiving was not observed to fail, and whether it did cannot be determined.** The
ledger's transaction path kept working throughout; the deployed ledger has no
archiving-failure metric, callback traps are not logged by the replica, the canister
log is controller-gated, and the ledger's own buffer was cleared by the 11:00:37
upgrade. So the mitigation that disabled archiving was **precautionary** — applied
after the subnet had already recovered, because the refusal class is reachable and
its effect on archiving is undetectable. Every claim below about reservation refusals
is about the *mechanism*, verified from the replica source, not about an observed
archiving failure.

**Two storage refusals never reach the archive's code.**
`try_grow_stable_memory` maps most failures to `-1`, which
`ic-stable-structures` surfaces as an `Err` the archive can handle — including the
subnet being out of memory. But `InsufficientCyclesInMemoryGrow` and
`ReservedCyclesLimitExceededInMemoryGrow` are returned as `HypervisorError` and
therefore **trap**, deliberately, so that an operator can tell a cycles problem from
an out-of-memory one (`embedders/src/wasmtime_embedder/system_api.rs:3605-3617`,
which carries the comment saying so; the trap reaches the wasm boundary at
`linker.rs:1089-1101`).

This bounds `A4` sharply, and in the direction that matters. The refusals
actually seen on 2026-09-01 were `IC0534`, and they hit the ledger's `post_upgrade`
and the index rather than an append — but the class is on the trapping side wherever
it lands, so an append refused that way keeps nothing and reports nothing, and blocks
it appended earlier in the same call are discarded with the trap. `A4.6`'s partial progress is
therefore real for an out-of-memory subnet and unavailable for a reservation
refusal — which is what `A4.5` says and why the non-goal points at
`memory_allocation` rather than at anything in this design. `A4.1` is untouched
by all of this, because reaching a configured limit asks for nothing. Growth inside a reserved
allocation computes zero newly-allocated bytes (`system_api.rs:1051-1070`), so it
charges no reservation and cannot be refused on those grounds.

The ledger needs nothing new either way: the trap arrives as a reject, `Rt::call`
returns `Err`, and the round takes the graceful path under `L4`.

**A trap discards its message's state changes, counters included.** This is what
makes `A6.2` necessary rather than stylistic: a cause that traps cannot appear in
`/metrics`, and the archive's canister log is a bounded ring buffer that is
unreadable by default, since `log_visibility` defaults to `Controllers` and the
controller is NNS Root.

**The ledger's view of archives is derived, not observed.** `nodes_block_ranges` and
`num_archived_blocks` are maintained by inference from acknowledgements, and the
ledger never records the offset it installed — on a successful append it re-derives
the node's range entry from `(last_height + 1, ...)` (`archive.rs:300-301`), the
same expression that produced the offset. So a mis-indexed node looks self-consistent
in the ledger's own state.

**`send_blocks_to_archive` has no ledger access.** It is generic over
`Rt: Runtime, Wasm: ArchiveCanisterWasm` and receives only
`Arc<RwLock<Option<Archive>>>`, so it cannot call `remove_archived_blocks`, which
lives on `Blockchain` behind `LA::with_ledger_mut`. Only `archive_blocks<LA:
LedgerAccess>` can, and it runs once per round. This shapes how `L3.2` is
implemented — see D6, in the ledger design.

**Selection happens before any await.** `Blockchain::get_blocks_for_archiving`
(`blockchain.rs:125`) materialises blocks from `ledger::blocks_to_archive`
(`ledger.rs:460`), and only then does `node_and_capacity` ask an archive anything.
So `L6.3`'s cap can only use values known locally.

**Every await in the archiving chain must be an inter-canister call.**
`ic_cdk::futures::spawn` is the *protected* variant; cancellation is refcounted, and
`enter_current_method` (`ic-cdk-executor/src/machinery.rs`) cancels attached tasks
only when the method's `MethodHandle` count reaches zero. A handle is taken before
every inter-canister call and threaded through its callback, so a task blocked on a
call keeps its context alive. Awaiting anything a call does not wake — a timer, a
channel — drops the count to zero, cancels the task, and trips `ProtectedTask`'s
`PinnedDrop` panic. A second, independent reason not to make archiving
timer-driven, the first being DEFI-2983.

**Cleanup callbacks keep their state changes.** Every "guard released, failure
counted" runs during task cancellation and survives the trap, which is why it is
limited to flipping a bool and incrementing a `u64`.

**The reply buffer is an irreducible allocation.** ic-cdk materialises response bytes
into its own `Vec` with no API to hand it a pre-allocated one, so every call is a
place the ledger can trap with earlier messages already committed. What remains after
this design:

| allocation | already committed | consequence |
|---|---|---|
| `create_canister` reply | canister exists, cycles gone | orphan; `C1` detects it and halts |
| `install_code` reply, or a graceful `Err` from it | + wasm **possibly** installed — a reject may precede or follow the install | **not** an orphan: `Created(id)` was committed before the call, so the round that finds it asks `canister_status` for `module_hash` and finishes the creation (`C1.6`, `C1.8`) |
| `update_settings` reply, or a graceful `Err` from it | + controllers **possibly** changed | **not** an orphan and not a halt: the archive is already adopted, the handover is tracked in `pending_handovers` and retried after reading the controller list (`C1.9`, `C1.10`) |
| `remaining_capacity` reply, existing node | the transaction | round skipped, spaced by `L4` |
| `remaining_capacity` reply, new node | + node recorded | round skipped; next round finds it |
| `append_blocks` reply | the archive holds the blocks | `A2.4` makes the re-send a no-op |

Only the first row is an orphan, and only because no id was ever learned: that is the
`Started` state `C1.1` halts on. The other two windows used to be write-offs and are not
any more — the creation journal records the id before anything else is done with it, so
a canister the ledger can name is one it can still finish or hand over. Part C is where
that is specified.

**The suite is upgraded in the order index, ledger, archives.** A new ledger
therefore talks to old archives during a rollout window unless the releases are
split — see Delivery.

**The ICP archive is a separate crate and decodes appends by hand.**
`Decode!(&msg_arg_data(), Vec<EncodedBlock>)` (`icp/archive/src/main.rs:291`), and
candid's `done()` (`candid-0.10.35`, `de.rs:122-125`) absorbs an extra trailing value as
`Reserved`, so it tolerates the new argument and its empty reply decodes as absent.
Its `post_upgrade` already takes `Option<ArchiveUpgradeArgument>` (`:383`).

**The same rule makes the new archive's reply readable by an old ledger, and it is the
premise the archive-only release rests on.** The archive is a typed entry point
returning `Option<append_result>`, so an index-less call gets `None` — which on the wire
is one *present* value, an absent `opt`, not a zero-length tuple. The old ledger decodes
the reply as `()` (`candid_tuple::<()>()` in `runtime.rs`, on `Rt::call(.., (chunk,))`
at `archive.rs:280`). That succeeds for the same reason as above: `done()` loops
`while !is_done()` consuming each remaining *declared* value as `Reserved`, and `is_done`
is `types.is_empty()` (`de.rs:118-120`) — the declared-type list, not the byte
position — so the one surplus `opt` is consumed before the trailing-bytes check runs. No
raw-reply entry point is needed, and the shape `A5.1` calls "empty" is exactly this
`None`. It is asserted as a pure Candid unit test — row 10b, already written — rather than
trusted, since everything about releasing the archive first depends on it.

**Every SNS ledger suite runs this archive, with archiving on.** `ic-icrc1-archive`
is not ckBTC and ckDOGE's alone: `sns/init/src/lib.rs:604-616` installs it for every
SNS with `trigger_threshold: 2000` and `num_blocks_to_archive: 1000`, so archiving is
active there today. PR 1's cost — archiving *can* halt until PR 3, retrying every
transaction — therefore reaches all of them, each upgrading on its own schedule, so
the window is as long as the slowest SNS takes.

**"Can", because the trigger is a trap and only a trap.** A *graceful* `Err` from a
chunk still records what landed — `remove_archived_blocks(num_sent_blocks)` runs on
the error branch too (`ledger.rs:485-488`) — so no re-send follows and nothing
refuses. The halt needs a round that dies *after* a successful append, which means a
trap in the continuation, and the test plan's own note records that DEFI-2967 could
not induce that deliberately. So the exposure is real but not routine; what makes it
worth acting on is the number of suites it reaches, not its likelihood on any one.

**Chunking today.** The chunk size is
`min(archive.max_message_size_bytes, max_ledger_msg_size_bytes)`
(`archive.rs:233-236`), so the smaller governs:

| | archive option | effective chunk | 1000 blocks |
|---|---|---|---|
| **ICP** | 128 kB (`icp/src/lib.rs:628`; the ledger ceiling `:634` is written only in `init`) | 128 kB | two chunks *(unconfirmed — see below)* |
| **ckBTC, ckDOGE** | `null`, so the 2 MiB default, clamped by a hard-coded 1 MiB `MAX_MESSAGE_SIZE` | 1 MiB | one chunk |
| **every SNS** | 128 kB (same `ArchiveOptions`) | 128 kB | **multi-chunk** |

The ICP row is `LedgerCanisterInitPayloadBuilder`'s default, not observed
configuration, and it cannot currently be confirmed from metrics: DEFI-1565's
`ledger_archive_*` settings metrics are not deployed on mainnet, where only
`ledger_archived_blocks` and `ledger_archived_transactions` exist. Confirm it against
the deployed ledger before relying on the row — and note that needing to is itself
the argument DEFI-1565 was making.

"ICRC is single-chunk" is therefore true only of the two ck suites. The chunking
window is open on ICP *and* on every SNS. Node roll-over makes a round multi-message
on all of them regardless, independently of chunk size, roughly once per configured
archive fill — 3 GiB on the ck suites, 1 GiB on SNS and ICP.

## Design decision held here

*Decisions are numbered across the whole specification; D10 is the one that concerns
every part equally, so it lives with the constraints it follows from.*

### D10 — No repair path is built now

A mis-indexed archive is repairable in principle, and it is worth recording why we are
not building it. Because the mapping is a single subtraction, a node holding the right
blocks under the wrong label is off by one constant everywhere: rewriting node 1's
offset from `N+1000` to `N` resolves every index in it, at the cost of overlapping the
previous node's tail by a thousand blocks — wasted space, not incorrectness, provided
the ledger's ranges are corrected too.

That is two coordinated changes, neither of which exists: an optional
`block_index_offset` in the archive's `post_upgrade` (cheaper on ICP, which already
takes an upgrade argument), and a ledger-side path that rewrites its ranges. It is
break-glass — writing an offset on a healthy archive corrupts it, and the archive
cannot validate the value, having no access to the previous node's tip. Build it only
if the Rosetta verification finds a divergence, and gate it behind a proposal carrying
the computed value.

## Testing, across the parts

The behavioural baseline for tests that need a trap is the **DEFI-2967 branch**: on
`master` archiving is awaited, so a trap in a continuation rejects the transaction and
the observable behaviour differs, and the harness those tests reuse
(`archiving_recovers_after_a_trapped_attempt`,
`routine_archiving_does_not_grow_the_ledger`) exists only there. Every archive-level
test is baseline-independent.

**Seams the design owes.** `L4` is observable only through the attempt spacing, so
the failure counter and last-attempt timestamp must be exposed as metrics; `L6.1`
needs a per-round append count; `L7` needs an unknown-outcome counter. All three
are metrics rather than test-only hooks, so they are also what an operator reads.

**At risk.** Row 26 needs a growth refusal that is neither the archive's own limit
nor a reservation refusal, since the latter traps. The wasm's declared stable maximum
is the most controllable route; a subnet memory cap works if the harness exposes one.
Note that `reserved_cycles_limit` is **not** usable for row 26 — it produces the
trapping case, which is row 26b's subject. If no returning route is controllable,
`A4.4` moves to Not attempted and the distinction rests on review of the branch
that sets the flag.

**Not attempted.** Inducing a trap in the append continuation end-to-end: routine
rounds grow ledger memory by zero bytes, which is why DEFI-2967 records "I could not
make that trap". A multi-chunk configuration with large batches would make the
per-batch encode big enough for the reserved-cycles trick to bite, so it is probably
reachable, but it depends on allocator behaviour and would be flaky. Test 14 covers
the same arithmetic deterministically. The comment correction and the
allocation-pressure half of the error work cannot be provoked reliably for the same
reason.

**Verification.**

    cargo check --all-targets --all-features -p ic-icrc1-archive -p ic-icp-archive \
      -p ic-ledger-canister-core -p ic-icrc1-ledger -p ledger-canister
    ./ci/scripts/rust-lint.sh
    bazel test --test_output=errors \
      //rs/ledger_suite/icrc1/archive:archive_integration_tests \
      //rs/ledger_suite/icrc1/archive:archive_integration_tests_u256 \
      //rs/ledger_suite/icp/archive:ledger_archive_node_canister_integration \
      //rs/ledger_suite/common/ledger_canister_core:... \
      //rs/ledger_suite/icrc1/ledger:... //rs/ledger_suite/icp/ledger:...

## Delivery / PR sequence

The suite upgrade order (Constraints) means a new ledger meets old archives unless the
releases are split. Do not reorder the suite; split instead, so each release is safe in
the normal index-ledger-archives sequence.

**And never roll an archive back below PR 1 while its ledger is at PR 3 or later.** D8
explains why the ledger cannot defend against it: its cached capability answer sends the
next batch without a probe, and an old archive stores it blindly. If an archive release
has to be reverted, revert the ledger first, or revert to a build that still carries
PR 1's `append_blocks`.

**Step 0 — verification of the live suites.** Not a PR. Two checks on ckBTC, ckDOGE and
ICP, because nothing here repairs an already-diverged suite and the answer reorders
everything after it.

First, a Rosetta sync from genesis. Rosetta checks that parent hashes chain across
every block it fetches (`rosetta-api/icrc1/src/ledger_blocks_synchronization/blocks_synchronizer.rs`),
and that is the check that matters for archive content: archives return blocks without
indices and Rosetta numbers them from the ledger's callback start (`:645-647`), so its
separate index check (`indices_are_valid`, `:432`) verifies the ledger's routing, not an
archive's internal placement. A clean sync therefore shows every block *the ledger
publishes* chains correctly — one check on archive content, not two.

Second — and a sync cannot stand in for it — each archive's own extent against the
ledger's published range for it. Rosetta reads archives only through the
`archived_blocks` callbacks the ledger hands it (`blocks_synchronizer.rs:591-629`), so it
never sees an archive *suffix* beyond `nodes_block_ranges`. A legacy lost reconciliation
leaves exactly that: the duplicate re-send sits in the archive above the published end,
unread by anyone, and it is what an indexed append would collide with the moment
archiving resumes. So for every archive, the number of blocks it holds must equal the length of the range
the ledger publishes for it — the archive's count is *local*, so `offset + count` is what
has to equal one past the published end. On an ICRC archive the count is the
`log_length` that `icrc3_get_blocks` returns (`icrc1/archive/src/main.rs:385-387`); on an
ICP archive it is `archive_node_blocks` (`icp/archive/src/main.rs:414`), that archive
having no `icrc3_get_blocks`. An archive holding more than its published range is the
latent divergence, and D10 is the repair. Only the two checks together gate Step 5.

**PR 1 — archive.** `append_blocks`'s new argument and result, placement, the clamp,
the chain check on the first stored block, capacity reporting, the counters, and the
`.did`. The ledger is unchanged, so it sends no index and reads no result — which is
why `A5` is in this PR and not a later one. It also **deletes** the test in row 10 and
lands row 11's in its place: row 10 installs the archive wasm from source and decodes the
indexed reply as `Option<u64>`, which stops being true the moment this PR returns `opt
append_result`, so it cannot survive the change it guards the run-up to.
*Acceptance:* `A1`, `A2`, `A3`, `A4` (A4.1-A4.4, A4.5-A4.7), `A5`,
`A6`.

*Who this lands on.* Every ICRC suite, not only the two ck ones, on each suite's own
upgrade schedule — see the SNS Constraint above for the window that opens. That is
the strongest argument for keeping PR 1 and PR 3 close together, and for not treating
PR 1 as a change that can sit in `master` for a while.

*What this release costs.* Three things, and the last is a limit rather than a
price.

**The archive starts decoding blocks, which it has never done.** `A1.7` needs
every stored block's `parent_hash`, so PR 1 parses block bytes that were written by
many ledger versions across years of SNS history. A block that fails to decode is
refused, and for an index-less append — the only shape PR 1 sees — a refusal *traps*
(`A5.2`), so a single decode regression halts archiving on that suite and stays
halted. This is the largest new risk in PR 1 and it is not in the protocol at all.

Two things follow. **Pre-flight it**: decode every block in a real mainnet archive
log offline, for each token variant, before PR 1 ships — the wasms and the block
bytes are both available, so this costs nothing but time and it is the only way to
find a historical encoding the current decoder rejects. And **budget the
instructions**: per-block decode plus hash on a 1 MiB append is not costed anywhere
in this document, and if it approaches the **per-message instruction** limit the
append traps, which is the same halt by another route. Note that is a different
ceiling from the payload limit `L6.3` caps: sizing a round to fit one message
says nothing about the instructions needed to decode and hash it.

An old ledger cannot tell a refusal's cause, so a round that dies after a successful
append leaves the next round re-sending blocks the archive holds; the archive
refuses, and the old ledger has no way past it. Archiving halts until PR 3, retrying
every transaction because the backoff is not in yet. Blocks accumulate locally, so it
is survivable, and a stall beats silent corruption — but keep the window short.

And it does not close the window on a **freshly created** archive — the limit of the
three, and the subject of the corresponding non-goal, which says why refusing instead
is not available. So the archive-only release closes the re-send case and leaves the
roll-over case open until PR 3 makes the ledger send an index, with `A1.6` counting
the window while it lasts.

**PR 2 — DEFI-2967.** Reviewed separately; not part of this spec. Ordered after PR 1
because spawning makes an archiving trap silent, so landing it first would leave the
corruption path open while removing the symptom that reveals it.

**PR 3 — ledger, bookkeeping.** Reconciliation from the reported extent, the coverage
and backwards checks, offset derivation, the capability probe and the seam.
*Acceptance:* `L2`, `L1`, `L3`, `L4` (L4.7, L4.8),
`L5`. On the ICP ledger the
acceptance is `L1.5`, `L3.6` and `L5.5` — the exemptions — rather than the
criteria they except, since its archives report nothing to reconcile against.

**PR 4 — ledger, round shape and retries.** Byte-based selection, one append per
round, the backoff, the creation journal, the bounded calls, the allocation work and
the comment.
*Acceptance:* `L4` (L4.1-L4.6, L4.9-L4.11), `C1`, `L6`, `L7`. `L4.5`'s
reply clause is the exception: PR 2 delivers that half, and PR 4 delivers the rest of
the criterion — the failure count and the blocks staying served.

`L4.7` and `L4.8` are deliberately in PR 3 rather than here: PR 3 is what gives
the ledger a `ChainMismatch` or `Gap` to read, and a release that can receive an
unresolvable refusal without knowing to stop would retry it on every transaction. The
rest of `L4` — the backoff itself — is independent and can follow.

**Step 5 — lower `trigger_threshold`**, by NNS proposal. Not a PR, and it must not
precede PR 3.

PR 1 and PR 2 are not enough, which an earlier version of this section got wrong. PR 1
closes the re-send case and PR 2 removes the double-mint, but the **fresh-archive
window stays open** until the ledger sends an index and an Expected_Parent — see the
`init` subsection: a node created for one index and then handed blocks from a
different chain state is exactly the original corruption, and only PR 3 gives the
archive what it needs to refuse it. So safety is reached after **PR 3**; PR 4 adds
recovery, turning a stall that waits for an operator into one that heals itself.

Nothing forces re-enablement to a date, so there is no reason to take it before PR 4
either.

Expect the backlog to drain at **one message per transaction**, not at
`num_blocks_to_archive` per transaction — `L6.1` makes a round one append, so that
setting no longer governs the rate. The ck backlogs have been growing since the
mitigation, so the drain is long even though each round is cheap; plan the proposal
knowing that rather than expecting it to catch up quickly.

The union of PRs 1, 3 and 4 covers `A1` through `L7` with one exception, and it
is the one PR 2 is ordered for: `L4.5`'s requirement that a failed round leaves the
triggering transaction's reply alone. That is the reply-path change, in scope as a
criterion and out of scope as code, per the corresponding non-goal. So the honest claim
is that PRs 1-4 cover the specification and PRs 1, 3 and 4 cover all of it that this
spec also designs.

## Discussed Alternatives

**A typed error return with no index.** `append_blocks : (vec blob) -> (opt
append_error)`, letting the ledger branch on the cause without addressing the append.
Subsumed: `opt append_result` *is* that return value and `Gap` is a typed cause. It
would not have delivered `A2` or `A3`, which need the index.

**String-matching the reject message.** Works today, depends on replica message
formatting and CDK version, cannot be tested against future changes.

**Idempotency without a reported position.** Make `append_blocks` skip duplicates but
change nothing else. Leaves the ledger counting what it *sent* rather than what was
stored, so it over-advances: with one batch's range recorded and the next lost, a
re-send walks the range to (0,2999) for an archive holding 0..1999, and reads for
2000..2999 route to an archive with nothing. `A3` is what makes idempotency
sufficient rather than a dead end.

**Reconciling from `log_length`.** `icrc3_get_blocks` already returns it
(`icrc1/archive/src/main.rs:387`), so the ledger could poll and repair its ranges.
Superseded by `A3`, which reports on every append — no extra round trip, nothing to
forget — and which needs no new block-count endpoint on the ICP archive. Polling
remains the only way to fix a ledger that has *already* diverged, which is judged not
to apply — not because the divergence is impossible, since both exposure windows are
open, but because none has been observed and DEFI-2967 could not induce the trap even
deliberately. See D10 for what repairing one would take.

**Advancing on a refusal.** Treat a refusal as "already archived" and advance by the
batch just attempted, making a trapped round resumable with no interface change. Its
soundness rests entirely on gaps being impossible, and if that premise were violated
the ledger would silently skip blocks — trading a loud stall for quiet data loss.
`A2` removes the choice by making a covered index a success rather than a refusal.

**Rolling over to a fresh node when the tail cannot answer.** Spawn a new archive,
which speaks the protocol by construction — no waiting and no incremental path.
Rejected because the costs are not one-off: spawning charges canister creation and
needs cycles provisioned, every extra archive is another canister to top up and upgrade
forever, and it abandons up to a whole archive's configured capacity of already-paid-for
space.

**Making response handling infallible.** The irreducible reply buffer (Constraints)
means this cannot be completed at the ledger level; it would need a CDK change. With
addressed appends it does not need to be — a trap in response handling stops being
harmful because the retry is idempotent. Rather than making the post-commit region
infallible, make it irrelevant, and keep the cheap parts as hygiene.

**Letting the archive pull.** The archive owns its position, the ledger serves blocks
and drops those below the reported point, and the transaction path has no archiving
commit point at all — every root cause dissolves. But it trades the ledger's
commit-point problem for the index's timer-fragility problem, and DEFI-2983 is exactly
that failure: a one-shot timer chain that stopped re-arming and went unnoticed for
hours. Not worth taking without a much better story for timer liveness.

**A separate range endpoint.** `archive_range() -> (start, end)` would answer the same
question as `A3`, but `A3` answers it on every append, and an empty append
answers it when there is no round to run (`A3.5`) — which is what the capability
probe uses. One method serves both.
