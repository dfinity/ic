---
id: DEFI-2967-followup
title: Archive chain continuity and bounded archiving retries
tags: [ledger, archive, icrc, icp]
---

# Archive Chain Continuity And Bounded Archiving Retries — Design

*Companion to [`requirements.md`](requirements.md), and the document an implementer
is handed. Every decision here serves numbered criteria, and every requirement is
served by something here. Criteria are cited as `Req 5` / `Req 5.1`, never
restated.*

*Line references are against `master`, paired with the symbol they point at so they
stay findable once the numbers drift.*

## Overview

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
archive holds and starts being told (`Req 2`, `Req 3`). Idempotency follows rather
than being bolted on: a re-send is recognised and discarded, so a lost
acknowledgement costs a round trip. That is ICP's own callee-side ID-deduplication
pattern, with an identifier that never expires, because an archive's position only
moves forward.

Three smaller pieces complete it. Capacity stops being a failure and becomes a
reported position plus a flag distinguishing "I am full" from "the platform refused
me memory" (`Req 4`), which is what lets an attempt under storage pressure keep the
blocks that fit. A backoff bounds the per-transaction retries a failing archive
currently provokes (`Req 9`). And a round is reduced to a single append to a single
archive (`Req 12`), which removes both loops from `send_blocks_to_archive` and, with
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
every index, permanently — which is why `Req 2.6` has to be checked on the archive
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

This bounds `Req 4` sharply, and in the direction that matters. The refusals
actually seen on 2026-09-01 were `IC0534`, and they hit the ledger's `post_upgrade`
and the index rather than an append — but the class is on the trapping side wherever
it lands, so an append refused that way keeps nothing and reports nothing, and blocks
it appended earlier in the same call are discarded with the trap. `Req 4.8`'s partial progress is
therefore real for an out-of-memory subnet and unavailable for a reservation
refusal — which is what `Req 4.7` says and why the non-goal points at
`memory_allocation` rather than at anything in this design. `Req 4.1` is untouched
by all of this, because reaching a configured limit asks for nothing. Growth inside a reserved
allocation computes zero newly-allocated bytes (`system_api.rs:1051-1070`), so it
charges no reservation and cannot be refused on those grounds.

The ledger needs nothing new either way: the trap arrives as a reject, `Rt::call`
returns `Err`, and the round takes the graceful path under `Req 9`.

**A trap discards its message's state changes, counters included.** This is what
makes `Req 6.2` necessary rather than stylistic: a cause that traps cannot appear in
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
LedgerAccess>` can, and it runs once per round. This shapes how `Req 8.2` is
implemented — see D6.

**Selection happens before any await.** `Blockchain::get_blocks_for_archiving`
(`blockchain.rs:125`) materialises blocks from `ledger::blocks_to_archive`
(`ledger.rs:460`), and only then does `node_and_capacity` ask an archive anything.
So `Req 12.3`'s cap can only use values known locally.

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
| `create_canister` reply | canister exists, cycles gone | orphan; `Req 11` detects it and halts |
| `install_code` reply, or a graceful `Err` from it | + wasm installed | same — and note this arrives as an ordinary `Err`, not only as a trap |
| `update_settings` reply, or a graceful `Err` from it | + controllers replaced | same |
| `remaining_capacity` reply, existing node | the transaction | round skipped, spaced by `Req 9` |
| `remaining_capacity` reply, new node | + node recorded | round skipped; next round finds it |
| `append_blocks` reply | the archive holds the blocks | `Req 2.4` makes the re-send a no-op |

All three orphan windows sit between `create_canister` committing and `nodes.push`
committing, so one non-zero check covers all of them — which is why resumable
creation is not needed. In the first two the orphan's only controller is the ledger,
which does not know its id, so its cycles are written off.

**The suite is upgraded in the order index, ledger, archives.** A new ledger
therefore talks to old archives during a rollout window unless the releases are
split — see Delivery.

**The ICP archive is a separate crate and decodes appends by hand.**
`Decode!(&msg_arg_data(), Vec<EncodedBlock>)` (`icp/archive/src/main.rs:291`), and
candid's `done()` (`candid-0.10.35`, `de.rs`) absorbs an extra trailing value as
`Reserved`, so it tolerates the new argument and its empty reply decodes as absent.
Its `post_upgrade` already takes `Option<ArchiveUpgradeArgument>` (`:383`).

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
on all of them regardless, independently of chunk size, roughly once per 3 GiB.

## Design Decisions

### D1 — Backoff is spaced geometrically, not latched

Serves `Req 9.1`, `Req 9.2`. `BACKOFF_INITIAL` = 30 s, doubling per consecutive
failure, `BACKOFF_CAP` = 1 h. A transient cause recovers within a minute; a permanent
one costs one probe per hour. What recovered on its own on 2026-09-01 was the
*subnet*, not archiving — the pressure appeared and vanished inside four and a half
hours, driven by a canister that was nothing to do with us. Latching on failure would
have outlasted a cause that cleared itself, which is why `Req 9.4` exists.

Transaction-triggered plus a timestamp check rather than a timer: no re-arm hazard,
and it satisfies the every-await-is-a-call constraint above.

### D2 — Backoff and probe state are `#[serde(skip)]`

Serves `Req 9.3`, `Req 9.9`, `Req 10.4`. Matches `archiving_in_progress`, and makes
an upgrade the operator's "resume now" lever, which is the right shape when the
upgrade is usually the fix.

That lever is a *deviation* from `Req 9.1`, not a consequence of it: after a failed
round, `Req 9.1` alone would forbid an immediate attempt, and resetting the state
permits one. `Req 9.9` is therefore the criterion that makes this legal rather than a
contract violation — the behaviour was always intended, but only the design said so.

### D3 — One seam, `Wasm::INDEXED_APPENDS`, and no others

Serves `Req 10.5`, `Req 13.6`. The shared code always sends the index, including to
`ic-icp-archive`, which the tolerance recorded in Constraints makes safe. What the
shared code cannot infer is whether a silent absence of a reply is a
misconfiguration or the expected state, so `ArchiveCanisterWasm` gains
`const INDEXED_APPENDS: bool` — `true` for `ic-icrc1-archive`, `false` for
`ic-icp-archive`. It is a property of the Wasm the ledger embeds, which is what that
trait already abstracts.

Every other component stays in shared code with no seam: the per-transaction retry,
the lost-creation window and the inferred bookkeeping exist on both ledgers, so
fixing them fixes both.

### D4 — Placement is decided before the chain is checked, and the prefix length is clamped

Serves `Req 1.3`, `Req 2.3`, `Req 2.5`. The order is load-bearing in two directions.
On a re-send the batch's first block does not continue the archive's tip — it
continues one of the archive's own earlier blocks — so checking the chain first would
trap on precisely the re-send `Req 2.4` makes harmless. And the prefix length is
unsigned:

    // reached only where offset <= i <= offset + log_length
    k = min(offset + log_length - i, blocks.len())   // leading blocks to skip
    append blocks.iter().skip(k)                     // saturating
    report offset + log_length                       // re-read AFTER the append (Req 3.2)

The upper clamp is reachable through a varying batch size alone — 1000 blocks stored,
the reconciliation lost, then a smaller message — and without it the slice panics.
The lower bound underflows if `i` is above the archive's position, which is the
`Req 2.2` branch, so computing `k` only inside the middle branch is what keeps it in
range; inverting the order would turn a gap into a wrapped `k` and an append at the
wrong offset, which is silent rather than loud. `skip` rather than `blocks[k..]`
makes the clamp structural.

### D5 — An indexed append never refuses by trapping

Serves `Req 6.1`, `Req 6.2`. Forced by the Constraint that a trap discards its
counter: the chain mismatch is the condition an operator most needs to see, being an
invariant violation rather than an expected outcome, so it is exactly the wrong thing
to make invisible. The cost is that atomicity becomes ordering-plus-test rather than
platform-enforced — the check runs before any append and `Req 1.2` pins it. An
index-less append still traps, per `Req 5.2`.

This is why `append_result` has a `ChainMismatch` arm: the decision not to trap is
only realisable if there is something to return. `Req 2.9`'s refusal shares it.

### D6 — Accept the re-send; do not redraw the module boundary

Serves `Req 8.1`, `Req 8.2`, `Req 8.6`. Giving `send_blocks_to_archive` ledger access
would let it advance the archived prefix directly, but the divergence it avoids is
benign: while `num_archived_blocks` lags, `block_locations` still routes those indices
to the ledger, which still holds them (`Req 8.5`), and any completed round corrects
the count. So the round *reports* instead — it returns a count that includes blocks an
archive already held, and `archive_blocks` performs the removal, which is a wider
return value rather than wider access.

`Req 12` shrinks this further: with one append there is no await after it, so the
range reconciliation and the removal land in the same message. The accepted re-send is
then at most one batch.

### D7 — The ICP archive is not changed here

The consequence of the corresponding non-goal. `Req 2` and `Req 3` are implemented in
`ic-icrc1-archive` only, so the ICP ledger gains D1, D2, the allocation work and
`Req 12` but not addressed appends, and stays on the incremental path under
`Req 10.5`.

**D6 does not reach ICP either**, which is easy to miss because it is ledger-side
code. D6 serves `Req 8.1`, `8.2` and `8.6`, and all three require an archive to have
reported an extent. An ICP archive reports none, so the ICP ledger is exempt from
`Req 7.1`-`7.4` and from `Req 8.1`-`8.4` and `8.6` (`Req 7.5`, `Req 8.7`) and keeps
deriving both the offset and the archived prefix from its own record. `Req 7.2` is in
that list for a second, independent reason: ICP's `archives()` returns canister ids
with no ranges (`icp/ledger.did:246-248`) and it has no `icrc3_get_archives` at all,
so publishing matching ranges through both would be an interface change this design
does not make. Without
those exemptions the requirements would forbid it from creating an archive or
discarding a block at all, contradicting `Req 10.5`.

There is no cheap partial: porting the chain check alone catches the
variant where a new node already has a tip, but the silent variant is the *empty*
node, which has none — closing that needs the offset check, hence the index, hence the
interface change.

### D8 — Only a positive capability answer is cached

Serves `Req 10.2`, `Req 10.4`. Caching "the tail cannot answer" would strand the
ledger, because the cache lives in the ledger and upgrading only the archive — the
scenario `Req 10` exists for — would not clear it. So an absent answer is re-probed,
spaced by D1's backoff, and a positive answer is cached in `#[serde(skip)]` state.

### D9 — `ARCHIVE_CALL_TIMEOUT` is the CDK default, 300 s

Serves `Req 13.1`, `Req 13.8`. `ic_cdk::call::Call::bounded_wait` defaults to 300 s,
aligned with the replica's `MAX_CALL_TIMEOUT`.

**Our own archives do not stall, so that is not the justification.** Neither archive
has an `async fn` or a single `.await`: every endpoint is synchronous, so a call
either completes and replies or traps, and a trap arrives as a reject. The platform
closes the remaining gap — it synthesises a reject when a callee becomes unreachable
— so there is no state in which one of our archives silently never answers. A stopped,
stopping, frozen, deleted or out-of-cycles archive all reject. What is genuinely
unbounded is how *long* a guaranteed-response call may take on a loaded subnet, not
whether it returns.

**The justification is the reservation, and the numbers make it.** A
guaranteed-response call must be answerable whatever happens next, so the system sets
aside subnet message memory for the reply when the *request* is sent and holds it
until the call completes. The amount is flat: every outstanding call counts
`MAX_RESPONSE_COUNT_BYTES` — `size_of::<RequestOrResponse>() + size_of::<Response>()`
plus a 2 MiB payload ceiling (`types/types/src/messages.rs:86`, `:66`) — against
`guaranteed_response_memory_usage`
(`replicated_state/src/canister_state/queues.rs:1862`), regardless of how small the
reply turns out to be. Best-effort responses are not in that accounting at all; the
field's own comment distinguishes them.

Our reply is two `nat64`s, a `bool` and a small variant — under 100 bytes. So each
in-flight append reserves about 2 MiB to use about 50, and that reservation is taken
from the same subnet memory whose exhaustion on 2026-09-01 refused the ledger's
upgrade and killed the index. A bounded call reserves none of it, so it is likelier to
be accepted under exactly the conditions that matter. The argument needs no archive to misbehave, which is why it
and not the stall is what carries `Req 13`.

**Upgradeability is a real secondary, but weaker here than in the guidance.** An
outstanding callback prevents the caller being stopped and therefore cleanly
upgraded, which matters because D2 makes an upgrade the operator's "resume now" lever
and `Req 11.4`'s halt has no other remedy. The guidance raises it for *untrusted*
callees that never respond; against our own synchronous archives the window is only
as long as a response is slow. Worth having, not worth leading with. A shorter value buys a faster stall detection at the
cost of spurious unknown outcomes, each of which re-sends a batch; 300 s is
conservative and can be lowered once the unknown-outcome counter shows how often it
fires. The value is settled here rather than in `requirements.md` because `Req 13.1`
fixes only the behaviour.

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

## Implementation

### `ic-icrc1-archive` — `append_blocks`

    type append_outcome = variant {
      Stored;                                      // all of them: Req 2.1, 2.3
      StoredPartial;                               // a prefix; at_capacity says why: Req 4.1, 4.8
      AlreadyHeld;                                 // Req 2.4
      BelowRange;                                  // Req 2.6
      Gap;                                         // Req 2.2
      ChainMismatch : record { at_index : nat64 };  // every chain ground of Req 1, and 2.9
      Undecodable   : record { at_index : nat64 };  // Req 6.4
    };

    type append_result = record {
      block_index_offset : nat64;
      next_index         : nat64;
      at_capacity        : bool;
      outcome            : append_outcome;
    };

    append_blocks : (vec blob, opt nat64) -> (opt append_result);

Both arguments and the result are optional, which is what makes the archive
releasable alone. The reply's first field is named `block_index_offset`, matching
the published `init` argument it reports, rather than `start_index` — the request's
second argument is the index the *batch* starts at, and one word cannot mean both.

`StoredPartial` exists because `at_capacity` cannot carry that distinction on its
own (`Req 3.7`): a growth the platform refused reports `at_capacity = false`
(`Req 4.4`) and so does a complete append (`Req 4.9`), so `Stored` plus a false flag
would have described both and left the ledger comparing `next_index` against what it
sent — exactly what `Req 3.6` promises it never has to do. With the outcome split,
`at_capacity` answers only "why did it stop", never "did it stop".

**A record, not a variant, because the range is unconditional.** `Req 3.1` requires
the offset and position on *any* answer and `Req 3.3` requires one meaning in every
outcome of `Req 2` — a variant whose refusing arms carried only their own fields
satisfied neither, and left `Req 2.6` distinguishable from an ordinary success only by
the ledger re-deriving it from what it sent. Hoisting the range out and demoting the
outcome to a field makes `Req 3.3` literally true and `Req 3.6` free.

`ChainMismatch` carries the index at which the divergence was found and serves
*every* chain ground of `Req 1` — `1.1` at the tip, `1.5` for a parentless block
offered anywhere but index zero, `1.7` inside the batch, `1.8` against a fresh
archive's Expected_Parent — plus `Req 2.9` inside a range already held. Deliberately
"every ground of Req 1" rather than a list, so that adding a ground does not silently
leave it without an arm. One arm for all of them because the ledger's response is the
same — halt per `Req 9.7` — while `Req 6.1`'s separate counters give the operator the
distinction that matters to them. That is D5's division of labour: type what the ledger acts on, count
what an operator diagnoses. `Undecodable` exists because decoding on append is new —
the current implementation stores opaque bytes and never parses them — so a block the
archive cannot parse is a failure mode this design introduces and must answer for.

Order of work, per D4 and D5:

1. Caller check, unchanged.
2. If the batch is empty **and carries an index**: reply per `Req 3.1`-`3.4` and
   stop. No placement, no chain check, no counter (`Req 3.5`, `Req 6.5`). This is the
   capability probe of `Req 10.3`, and short-circuiting is what keeps a probe sent at
   an index above the archive's position from being counted as a gap.
3. If the index is absent, skip **steps 4 and 5 only** — there is no index to place,
   so the batch is treated as continuing the tip, `k = 0`. Steps 6 onward still
   apply, and any refusal fails the call instead of returning a description of it
   (`Req 5.1`, `5.2`). An index-less batch that is *also* empty therefore falls
   through to here rather than to step 2: it stores nothing and replies empty, and
   steps 6 and 7 are no-ops because there is no block to check or store.
4. Place the index against `block_index_offset` and `block_index_offset +
   log_length` (`Req 2.1`, `2.2`, `2.6`), returning without appending in the
   refusing cases.
5. Compute `k` and the suffix per D4. If the batch is wholly covered, compare its
   last block against the stored block at that index and return `ChainMismatch` on a
   difference (`Req 2.9`). One comparison suffices rather than sampling: blocks are
   hash-chained, so a divergence at or below that index propagates forward to it and
   cannot heal — if the last covered block matches, every block below it does.
6. Determine which blocks will actually be stored — the suffix from `k`, trimmed to
   what fits the archive's own configured limit — and then chain-check **only those**:
   `blocks[k]` against the tip, or against the Expected_Parent when the archive holds
   nothing and was given one (`Req 1.1`, `1.3`, `1.4`, `1.5`, `1.8`), then each
   subsequent stored block against its predecessor (`Req 1.7`). Capacity is decided
   before validation, not after, because `Req 1.7` binds the blocks it *stores*: a
   block beyond the limit is never stored, so refusing the whole append because that
   block is malformed or does not chain would contradict `Req 4.1`, which requires the
   prefix to be stored and the stop reported. The second half
   is one hash per stored block, which is what makes `Req 2.8` a property the archive
   enforces rather than one it inherits from the sender — worth the cost precisely
   because the rest of this design exists to stop trusting what the ledger asserts.
7. Append the suffix. **For an indexed append**, stop short where it must
   (`Req 4.1`, `4.2`, `4.8`) and report `at_capacity` false whenever nothing stopped
   short (`Req 4.9`). **For an index-less one it is all-or-nothing** (`Req 5.5`): if
   the whole batch does not fit, store none of it and fail the call, which is what the
   archive does today. Partial progress is only safe for a caller that can be *told*
   it was partial — an index-less caller gets an empty reply, reads success as the
   whole batch, and removes all of it, so a stored prefix would leave the suffix in no
   archive and no longer served by the ledger. That is the one case where rolling back
   what was stored is the safe act rather than the wasteful one, which is why
   `Req 4.2` is scoped to indexed appends. Note the one
   wasted round this leaves: an archive that stores its last block exactly fills, still
   answers false, and is found full on the next round — which then spawns. Two
   different stops, and only one of them depends on the platform. `Req 4.1` is the
   archive comparing the next block's size against its own configured limit and its
   own usage, so it stops *before* asking for memory and cannot be refused — this is
   the routine case, reached once per archive fill — and on *every* fill once the
   `remaining_capacity` pre-call is replaced by the reported `at_capacity`, per
   `Req 4.5` and `4.6` and the `node_and_capacity` subsection below.
   `Req 4.8` is a grow the archive did ask for and was refused; `StableLog::append`
   returns a `Result`, so the current `unwrap_or_else(|_| trap("no space left"))` is
   the archive's own choice and can be handled — but only for the refusals that
   reach it, which is what `Req 4.7` bounds; see the Constraint below.
8. Re-read `log_length` and reply (`Req 3.1`-`3.4`), or fail the call if step 3
   applied.

**Three ordering traps in this list, every one of which has been fallen into.**

*Step 3 says "steps 4 and 5 only" for a reason.* An index-less append is the only
shape PR 1 sees in production, so skipping the chain check along with placement would
make PR 1 a no-op against the corruption it exists to stop.

*Capacity is decided before validation for a reason.* Validating a block the archive
was never going to store, and refusing the append because of it, denies `Req 4.1` the
prefix it requires — see step 6. `Req 1.9` states it as an obligation.

*Step 2 is scoped to an indexed batch for a reason.* Written to catch the empty batch
first, it also catches an **index-less** empty one and answers it with a result —
which `Req 5.1` forbids, and which the already-written
`test_empty_append_blocks_is_accepted_and_stores_nothing` would fail, since it sends
the one-argument shape and asserts the reply reads as absent. The index test has to
come first for an index-less caller, and the empty test first only within the indexed
path.

**Step 7 is a restructuring, not a reuse.** The current check is whole-batch and
traps: it sums every block's size and compares against `max_memory_size_bytes`
(`icrc1/archive/src/main.rs:242`), then traps inside the append loop if a grow
fails. `Req 4.1` needs a fitting *prefix* instead — append while the next block
still fits — and `Req 4.2` forbids unwinding what fitted. The distinction
`at_capacity` reports (`Req 4.3` versus `Req 4.4`) is then whichever stopped the
loop: the archive's own limit, computed per block, or a failed grow. Keeping the
all-or-nothing form would satisfy neither criterion.

A block that fails to decode is counted distinctly (`Req 6.4`). Both
`trap("no space left")` sites are replaced.

### `ic-icrc1-archive` — `init`, and the Expected_Parent

    service : (principal, nat64, opt nat64, opt nat64, opt blob) -> { ... }
    //                                                  ^^^^^^^^ new: Expected_Parent

A fifth optional `init` argument, the hash the archive should expect as the parent of
the first block it stores (`Req 1.8`). It closes the last place where a stored block
goes unchecked.

**Why nothing else can close it.** The declared index verifies *position* and the
chain check verifies *content*, and for a non-empty archive that covers both. An
**empty** archive has no tip, so content is unverifiable — `Req 2.1` will accept a
first append whose index is right whatever the blocks actually are. That is the hole
`Req 1.4` documents, and it is the seat of the original corruption: a node created
for one index, then handed blocks from a different chain state. Supplying the parent
at creation gives the archive a tip before it has one, and makes the invariant
plain — **the only block ever stored without a parent-hash check is genesis**.

**What it does and does not catch.** It catches the case where creation and first
append see *different* ledger states: the roll-over corruption, and a ledger restored
from a snapshot between the two. It does not catch a ledger that had already forked
before it created the node, since such a ledger would declare the forked parent and
then send the matching forked block — consistently wrong. That is the residual the
Rosetta precondition exists for.

**It is not redundant with the index, but it does arrive with the same release.** A
ledger that cannot send an index cannot supply the hash either, since both come from
the same ledger version — so this buys nothing during the archive-only release, and
`Req 1.4`'s window stays open for the ICP ledger and for third-party suites that
upgrade only the archive. `Req 1.6` counts exactly those.

**Plumbing, and it is not where it first appears to be.** The value is the first
block's parent hash, but it cannot be read where the batch is sent: by then the blocks
are `EncodedBlock`, which exposes only `from_vec`, `into_vec`, `as_slice` and
`size_bytes` (`ledger_core/src/block.rs:23-39`). `parent_hash()` is a `BlockType`
method on the *decoded* block (`:114`), so it is available only while the concrete
block type still is — in `archive_blocks<LA: LedgerAccess>`, where
`<LA::Ledger as LedgerData>::Block` is known.

So it must be extracted there and threaded down, not computed in
`send_blocks_to_archive`: that helper is generic over `Rt` and `Wasm` and sees a
type-erased `VecDeque<EncodedBlock>`, and `node_and_capacity` below it receives only
`blocks[0].size_bytes()` today. The hash travels as a value alongside that size to
reach the `Encode!` at `archive.rs:463-468`. Same boundary as D6's, and for the same
reason.

**Compatibility, in two separate places.** The Candid argument and the stored field
are different problems and only the first is solved by `opt`. An old ledger encodes
four arguments; the fifth being `opt` means candid decodes it as absent, so a new
archive installed by an old ledger behaves exactly as it does today.

The **stored** field needs `#[serde(default)]` returning `None`. `ArchiveConfig` is
CBOR-decoded from stable memory on every archive upgrade, and it already does this for
its later-added field (`icrc1/archive/src/main.rs:91`), so without it PR 1 would make
every existing archive fail its *first* upgrade — the release that adds the protection
would be the release that breaks the fleet. An upgrade regression test decoding a
pre-change `ArchiveConfig` is the cheap guard. That is what keeps the archive-only release safe, and it is
the same tolerance `Req 5` rests on. `archive.did` gains the second argument and the
result type, both `opt` and so compatible in either direction; verify the whole of it
with `didc` and the CI Candid check rather than by inspection.

### `ic-icrc1-archive` — `encode_metrics`

One counter per ground enumerated in `Req 6.1`, which is the whole list — the four
chain grounds of `Req 1` separately, `2.2`, `2.6`, `2.9`, `4.3`, `4.4`, `6.4` and
`1.6`. The archive exposes none of these today, so all of them are new.

**Separately, because the grounds localise a divergence differently.** `Req 1.1`
means the blocks offered do not continue the archive's last block; `Req 2.9` means a
range it already holds was re-sent with different content, which points at a ledger
that has been rolled back; `Req 1.8` means a fresh archive was handed blocks from a
different chain state than the one it was created for. One mismatch counter would
collapse three different investigations into one number.

Three of them are not faults and should not read as such. `Req 1.6` counts a
*success* — the append the archive could not verify — and should read zero once every
ledger supplies an Expected_Parent. `Req 2.6` is the ordinary "the ledger is behind"
signal and is diagnostic by `Req 6.6`. `Req 4.3` is normal operation: archives fill
up. Only the chain grounds, the gap and `6.4` are conditions an operator should act
on. An empty append is counted by none of them (`Req 6.5`), and all of them commit,
because D5 removed the traps.

### `ledger_canister_core::archive` — `send_blocks_to_archive`

Both loops go (`Req 12.1`, `12.2`): pick a node, send what the round selected, one
call, reconcile, return. Reconcile `nodes_block_ranges` from the reported
`block_index_offset` and `next_index` rather than incrementing (`Req 7.3`, `Req 8.6`).

The coverage check (`Req 8.2`, `8.3`) and the backwards check (`Req 8.4`) live here,
since this is where the ranges are; per D6 they report upward rather than acting. The
return type widens to carry the count `archive_blocks` should remove, which may
include blocks an archive already held.

A `BelowRange` outcome is **not** a halt. It is the ordinary signal that the ledger
is behind — the coverage guard's input — so it routes to `Req 8.2` rather than
halting (`Req 9.8`), and its counter is a diagnostic rather than a fault
(`Req 6.6`). It is the one refusing outcome that does
not stop archiving, which is why it is worth naming here rather than leaving to the
halt table below.

An absent reply routes by `Wasm::INDEXED_APPENDS` (D3): halt and count for an ICRC
ledger (`Req 10.1`), incremental path and count for ICP (`Req 10.5`). The
determination itself is the empty append of `Req 10.3`, issued here and bounded by
`Req 12.1`'s one-empty-append limit.

Reconciliation also maintains what `archives()` publishes, so a Published_Range only
ever widens to what an archive has reported (`Req 7.2`), and an archive that holds
nothing yet appears in no published range at all (`Req 7.6`) — which is what the code
already does, since the range entry is pushed on the first successful append rather
than at creation. A published range is inclusive of both ends, so an empty archive
has no pair of indices that could describe it — the ledger's published view
and its internal record are the same data, which is why `Req 8.6` has to be about the
*source* of that data rather than about which field it is read from.

### `ledger_canister_core::archive` — `Archive` state

`#[serde(skip)]` fields per D2: last-attempt timestamp and consecutive-failure count
(`Req 9`) and cached capability answer (`Req 10.4`). Creation state is the one
exception, a single persisted field:

    #[serde(default)]                                      // Idle is Default
    creating: Creating,
    #[serde(default)]                                      // None is Default
    pending_handover: Option<CanisterId>,

    enum Creating { Idle, Started, Created(CanisterId) }   // Default = Idle

`Started` before `create_canister`, `Created(id)` as soon as it returns, `Idle` when
`nodes.push` succeeds. Both non-`Idle` states are exposed (`Req 11.2`), with the id
when there is one (`Req 11.7`), but **they do not have the same effect and must not
be collapsed into one halt**:

| state | effect |
|---|---|
| `Started` | no blocks move, and nothing resumes on its own (`Req 11.1`, `11.4`) — a canister may exist that cannot be named, so an operator has to look |
| `Created(id)` | the round *finishes the creation first* and then proceeds (`Req 11.8`) — it is a "do this before archiving" state, not a halt |

Treating every non-`Idle` state as a halt would make `Req 11.8` unreachable, because
the halt is implemented as a skip in `blocks_to_archive` *before* the guard is taken:
a `Created(id)` round would be skipped and would never reach the reconciliation it
exists to perform.

This is ICP's journaling pattern — record intent before the work and the result
after — which its guidance recommends over trying to avoid traps after an await. It
is persisted rather than `#[serde(skip)]` like the rest of D2's state, because an
orphan must outlive an upgrade or the upgrade becomes a way to forget it.

Being persisted, it needs `#[serde(default)]` with `Idle` as `Default`. `Archive` is
CBOR-decoded on every ledger upgrade, so a required new field would fail to decode
every pre-change state — the journal would break the first upgrade it shipped in,
before it could help with anything. `Archive` already does this for its later-added
fields (`archive.rs:33, 36, 39, 148`), so the pattern is established rather than
novel.

`pending_handover` is a second field for the same reason, and it is needed because
`Req 11.9` moved the handover *after* adoption: `Creating` returns to `Idle` when
`nodes.push` succeeds, so without it nothing records which adopted archive still owes
a handover, and `Req 11.10`'s retry and metric would have nothing to work from — least
of all across an upgrade. It is set when the archive is adopted, and cleared
when the handover's second step is confirmed or refused as unauthorized
(`Req 11.12`) — the two ways the ledger can know it is done.

**Two of the three orphan windows stop being write-offs, and only `Idle` may be
restored.** `create_and_initialize_node_canister` runs `create_canister` →
`install_code` → `update_settings` → `nodes.push`, each with `?` (`archive.rs:455`,
`:461`, `:489`, `:508`), so a graceful `Err` from either middle step returns with
**the canister already created** and its id dropped on the stack. Recording the id as
soon as `create_canister` returns (`Req 11.6`) makes those two windows *recoverable*:
an operator can finish or delete a canister the ledger can name. Only a trap in
`create_canister`'s own reply is irreducible, and `Started` covers it — a halt with no
id, precisely the "a canister may exist and I cannot name it" case.

So `Req 11.3` is the pre-creation case and `Req 11.5` the post-creation one, and the
implementation is that distinction: return to `Idle` only where `create_canister`
itself returned `Err`. Doing it anywhere later would hand those two windows back to
`Req 9`'s backoff and defeat `Req 11.1`'s halt entirely. Making `update_settings` a
bounded call (below) makes this sharper rather than looser — an unknown outcome there
arrives as an `Err` on a call that may well have succeeded, and must halt for the same
reason.

### Halt conditions, and how each one clears

Five conditions stop archiving, with three different recovery stories, and they are
easy to conflate because they present identically — archiving stops and blocks
accumulate. An operator's first question is which one it is, so the metrics must be
distinct (they are, by `Req 8.3`, `8.4`, `9.7`, `10.1` and `11.2`) and the answer to
"what now" must be written down:

| condition | criterion | clears |
|---|---|---|
| the span below an archive's reported range is covered by no archive | `Req 8.3` | not on its own. No endpoint sets the archived prefix, so it needs an upgrade carrying a migration. Unreachable except from self-inconsistent ledger state |
| an archive reports a position below the archived prefix | `Req 8.4` | never — blocks the ledger already stopped serving are held nowhere. Recovery is whatever backup exists, not this system |
| an archive refused an append on chain or position grounds | `Req 9.7` | not on its own, and deliberately: the archive's counters say which of `1.1`, `2.2` or `2.9` fired, and they call for different investigations |
| the tail archive reports no range | `Req 10.1` | **itself**, on the next probe once the archive is upgraded (`Req 10.2`). The only self-clearing halt |
| an archive creation was begun and never accounted for | `Req 11.1` | operator only, explicitly not itself (`Req 11.4`), because a canister may exist that nothing will address |

Two things follow for the implementation. The four non-clearing halts must be
distinguishable from the backoff of `Req 9.1` — a ledger that is *waiting* and one
that has *stopped* look the same from block accumulation alone. And `Req 10.1` is the
only one whose state may be derived from a cache, since it is the only one expected
to change without an upgrade.

### `ledger_canister_core::archive` — `node_and_capacity`

The roll-over test (`remaining_capacity < needed`, `archive.rs:552`) is restated in
terms of the last append's `at_capacity` (`Req 4.5`, `4.6`), with the
`remaining_capacity` pre-call kept only for a cold start or a freshly spawned node.
This is what makes `Req 12` cheaper than today rather than dearer: a 1000-block ICP
round is one pre-call plus two appends today, and one append per round with no
pre-call afterwards.

Creating a node sets `block_index_offset` from the reported extent of the previously
created node (`Req 7.1`), and refuses to use a node whose reported range does not
begin where the previous one ends (`Req 7.4`).

For a suite that predates this work there is no previously *created* node to have
reported anything — but there is a tail, and `Req 10.3`'s probe reports its range
before the first roll-over, which is where `Req 7.1` gets its value. Worth a comment
at the call site, since the probe doubling as the bootstrap is not obvious.

That first probe is also a free divergence check: a tail whose reported range
disagrees with what the ledger had inferred trips `Req 8.2` or `Req 8.4` immediately.
It covers only the tail, so it does not replace Step 0's Rosetta sync — but it fires
on every existing suite the moment PR 3 deploys, with no operator action, which the
sync cannot claim.

### `ledger_canister_core::ledger` and `::blockchain` — round selection

Cap the selection at `min(num_blocks_to_archive, one message)` in bytes, in
`Blockchain::get_blocks_for_archiving` (`blockchain.rs:125`) called from
`blocks_to_archive` (`ledger.rs:460`) — both terms local, per the Constraint that
selection precedes any await (`Req 12.3`). `take_prefix(remaining_capacity)` still
trims on the cold-start path. Expose the effective per-round count (`Req 12.4`).

A failed round counts the failure in `ledger_archiving_failures`, the metric the
ledger already exposes, keeps serving the blocks it did not archive, and leaves the
triggering transaction's reply untouched (`Req 9.5`, `Req 9.6`) — all of
which the cleanup callback must achieve if the round trapped rather than returned,
which is why the Constraints limit it to a bool and a `u64`.

Splitting large stable-memory work across messages is the platform's own answer to
memory-exhaustion errors, and `Req 12` does it for the append side; block removal
stays one message per round, so if that proves too much for one message, splitting it
too is the prescription rather than an invention.

**Whether it is too much is unmeasured, and worth measuring before assuming either
way.** `remove_archived_blocks` loops `pop_first()` once per block, so the cost scales
with `min(num_blocks_to_archive, MAX_BLOCKS_TO_ARCHIVE)` — 18,000 at the cap — and it
is listed as a trap source on that reasoning rather than on a number. `Req 12` shrinks
each round's removal, which probably settles it, but canbench already measures this
class of thing and the figure is cheap to get.

`blocks_to_archive` also carries the skip conditions: the backoff (`Req 9.1`), the
creation halt (`Req 11.1`), the capability halt (`Req 10.1`) and the coverage halts
(`Req 8.3`, `8.4`) — all before the guard is taken, so a skipped round costs nothing.

**Only a state that clears without the ledger doing anything belongs in that list.**
Skipping happens before the guard is taken, so a skipped round performs no work at
all — right for a wait, wrong for anything needing an action to clear. Two entries
above are therefore wrong as listed:

| state | in the skip list? |
|---|---|
| backing off (`Req 9.1`) | **yes** — a wait; time clears it |
| `Started`, no identity (`Req 11.1`) | **yes** — only an operator clears it |
| coverage halts (`Req 8.3`, `8.4`) | **yes** — only an operator clears it |
| `Created(id)` (`Req 11.8`) | **no** — the round must finish the creation |
| capability halt (`Req 10.1`) | **no** — the round must issue the probe |

`Req 10.1` is the same mistake in a second place, and worth naming because fixing the
first did not catch it. An old tail returns no range, so every later transaction exits
at the skip and never issues the probe that `Req 10.2` and D8 depend on — meaning
upgrading only the archive would never resume archiving, which is the entire scenario
`Req 10` exists for. Once the backoff permits, that state must enter a **probe-only
round**: no blocks, one empty append, a decision.

The general rule, since this class has now appeared twice: **a state that needs the
ledger to *do* something cannot be expressed as a skip.**

### `ledger_canister_core::runtime` — `Runtime::call`

One call site today, `Call::unbounded_wait` (`runtime.rs:68`), used for every
archiving call including the management-canister ones from `spawn.rs:25, 40`. It gains
a bounded variant so the choice is per call site (`Req 13.1`, `Req 13.5`):

| call | wait | why |
|---|---|---|
| `append_blocks` | bounded, ICRC only | idempotent under `Req 2.4`; ICP exempt per `Req 13.6` |
| `remaining_capacity` | bounded | read-only, so an unknown outcome is resolved by asking again |
| `update_settings`, adding the controllers | bounded | the ledger is still a controller, so `canister_status` resolves it (`Req 13.7`) |
| `update_settings`, removing the ledger | **unbounded** | not queryable once it has succeeded, so `Req 13.5` forbids bounding it — see below |
| `install_code` | bounded | resolvable, see below |
| `create_canister` | **unbounded** | the only genuinely unresolvable one: an unknown outcome leaves a canister nothing can address |

**The handover's last step is not queryable, and "setting the same controllers twice
is a no-op" was wrong.** The call as written today replaces the ledger with the
configured controllers in one shot (`archive.rs:366-372`, `:489-497`), and the
management canister validates the caller before applying settings
(`canister_manager.rs:690`). So once it has succeeded the ledger is no longer a
controller: it can neither retry nor call `canister_status` to find out. An unknown
outcome would be indistinguishable from a real failure, and `Req 11.8`'s adoption path
would stall on it.

**So it stays unbounded, and `Req 13.5` already says so** — this is the second call
it forbids bounding, after `create_canister`. Bounding it
would leave a timeout the ledger could never resolve: the settings may have committed
before the response was lost, after which it can neither retry nor query. Unbounded,
it always learns the outcome, so a retry only ever follows an *observed* failure.
Putting it in the bounded column was a violation of a criterion this document already
contains.

**But unbounded is not sufficient, so the handover is staged.** An
unbounded call guarantees a *response*, not that the ledger *processes* it: the
callback can still trap on the irreducible reply buffer, and if it does after the
settings committed, the ledger is no longer a controller while `pending_handover` is
still set — every retry unauthorized, the metric never clearing.

So it goes in two steps (`Req 11.11`). First add the configured controllers while
keeping the ledger: idempotent, and verifiable at any time by reading the archive's
controller list, which the ledger is still a controller and so still entitled to do.
Then remove the ledger — and that step cannot fail in a way that matters, because its
only two outcomes are "still a controller, retry" and "not a controller", which is
precisely the state the handover exists to reach. `Req 11.12` therefore treats an
unauthorized retry as completion. The archive is governable by its intended
controllers after step one, so nothing is at risk while step two settles. Only the
first step is bounded, per the table above: it is the one the ledger can still ask
about.

The ambiguity is therefore *dissolved* rather than interpreted. `Req 11.12` does read
an unauthorized rejection as completion, which this design otherwise avoids — but it
is not the load-bearing part: both readings of that rejection lead to the same end
state, so the criterion only spares the ledger a retry it would lose anyway.

Ordering is the other half of the fix, and it addresses a different problem —
**adopt the archive before handing over control** (`Req 11.9`) — so that an observed
handover failure does not block archiving while it is retried. Adoption ends the creation's critical path, and the handover
becomes a separate step the ledger retries on later rounds while it is still a
controller (`Req 11.10`). A lost handover then leaves a fully adopted, working archive
that is merely still ledger-controlled — recoverable, and visible on a metric — rather
than an ambiguous state that blocks archiving.

**`install_code` is resolvable, which the earlier reasoning missed.** "`install` mode
fails if already installed, so it cannot be retried" is true of a *blind* retry and
false of a reconciled one. At that point the ledger is still the new canister's only
controller — `update_settings` has not run — so it can call `canister_status` and read
`module_hash`: absent means the install did not happen and may be retried, present and
matching means it did. `canister_status` is itself read-only and so resolvable by
asking again, which terminates the regress.

Leaving it unbounded would contradict `Req 13.7`, since the outcome *is* resolvable,
and would keep a callback that can block stopping the ledger in the one path where
that is least welcome.

This shrinks the halt population rather than the safety. `Req 11.8` lets the ledger
finish a creation whose identity it recorded, so the only case that still needs an
operator is a lost `create_canister` reply — a canister that exists and cannot be
named, which is what `Req 11.4` is now scoped to.

An unknown outcome is handled as a failure, which is safe only because the retry is
idempotent (`Req 13.3`, `13.4`), and is counted distinctly so D9's timeout can be
revisited. The first three rows are `Req 13.7`'s "resolvable by asking again"; the
last two are `Req 13.5`'s exception, and the table is the exhaustive reading of both.

### `ledger_canister_core::spawn`

`install_code` takes `Vec<u8>`, forcing `archive_wasm().into_owned()`, and `Rt::call`
then serialises it again — two multi-MB copies in the continuation after
`create_canister` committed. Take `Cow<'static, [u8]>`, pre-reserve the encode buffer
before the first await, and `nodes.reserve(1)`. This lowers the probability of the
trap that produces an orphan; it does not remove it, which is why `Req 11` exists.

Correct the comment above `create_canister` (`archive.rs:452-454`): it claims a panic
there rolls the triggering transaction back, which holds only for the first node a
ledger ever creates. On a roll-over `node_and_capacity` awaits `remaining_capacity`
first (`archive.rs:547-549`), committing the transaction, so a panic rejects the reply
instead. The comment should state that condition rather than the conclusion.

### Error construction

`FailedToArchiveBlocks(pub String)` allocates on every error, so an allocation failure
turns a graceful `Err` into a trap. Replace it with an enum carrying `Copy` payloads,
rendered to text only where logged. `Rt::print` takes `impl AsRef<str>`, so
non-interpolating messages become `&'static str` for free.

**Keep** the canister id in the `create_canister` callback log — canister logs survive
traps, verified by `test_appending_logs_in_trapped_update_call`
(`rs/execution_environment/tests/canister_logging.rs`), so it is the only record of an
orphan's identity — but drop the `{result:?}` debug format.

Expect little from this beyond keeping graceful failures graceful: these are tens to
hundreds of bytes, and a small allocation only fails once the irreducible reply buffer
allocated moments earlier would very likely have failed too.

## Test plan

The behavioural baseline for tests that need a trap is the **DEFI-2967 branch**: on
`master` archiving is awaited, so a trap in a continuation rejects the transaction and
the observable behaviour differs, and the harness those tests reuse
(`archiving_recovers_after_a_trapped_attempt`,
`routine_archiving_does_not_grow_the_ledger`) exists only there. Every archive-level
test is baseline-independent.

| # | level | case | pins |
|---|---|---|---|
| 1 | archive | append a valid range, re-append it, assert nothing stored and every index still resolves to its own block | `Req 2.4`, `2.7`, `2.8` |
| 2 | archive | append a batch whose first block does not continue the tip; assert refusal and unchanged extent | `Req 1.1`, `1.2` |
| 3 | archive | install with `block_index_offset = N+1000`, append at `N`; assert nothing stored and `block_index_offset = N+1000` reported. Then append `N+1000..N+1999` so the node is non-empty, re-send at `N`, and assert the reply still reports offset `N+1000` but `next_index = N+2000` — the two fields are indistinguishable on an empty node and must not be conflated | `Req 2.6`, `Req 3.1`, `3.3` |
| 4 | archive | append `N..N+499`, then `N..N+999`; assert the extent becomes 1000 not 1500, every index resolves, and the chain check did not refuse on the covered prefix | `Req 2.3`, `Req 1.3` |
| 5 | archive | append 1000 blocks, then re-append the first 600; assert success, nothing stored, extent unchanged — the case a plausible implementation panics on | `Req 2.5` |
| 6 | archive | append at an index above the position; assert a gap and nothing stored | `Req 2.2` |
| 7 | archive | size `max_memory_size_bytes` so a batch only partly fits; append it **with an index** and assert a short `next_index`, `at_capacity = true`, and that the blocks that fit are readable | `Req 4.1`, `4.2`, `4.3` |
| 7b | archive | the same over-large batch **without** an index; assert the call fails and the archive holds exactly what it held before — the partial store that would make the suffix unretrievable | `Req 5.5` |
| 7c | archive | assert a complete append and a partial one are distinguishable from the reply alone: the first reports the whole-batch outcome, the second the partial one, and neither is told apart by `at_capacity` — which reads false for a complete append and for a platform-refused stop alike | `Req 3.6`, `3.7` |
| 8 | archive | **partly written**: `test_empty_append_blocks_is_accepted_and_stores_nothing` already asserts an empty append stores nothing and consumes no capacity, on both the one-argument and null-index shapes. Extend it against the new implementation to assert an *indexed* empty append reports an extent, that an indexed empty append above the archive's position is neither refused nor counted, and that both index-less empty shapes still reply **empty** — the last of these is what fails if the empty check is ordered before the index check | `Req 3.5`, `Req 5.1`, `Req 6.5` |
| 9 | archive | genesis into an empty archive with offset 0; then assert a block with no parent hash is refused by an archive whose offset is non-zero, and by one that already holds blocks | `Req 1.5` |
| 9b | archive | install with no Expected_Parent, append into it, and assert it is stored and the unverifiable-first-append counter rises | `Req 1.4`, `Req 1.6` |
| 9c | archive | install with an Expected_Parent, then append a first batch whose first block carries a different parent; assert refusal and that nothing is stored. Then append one that matches and assert it is stored and the counter in 1.6 does *not* rise | `Req 1.8`, `Req 1.6` |
| 10 | archive | **written, and retired by PR 1**: `test_append_blocks_ignores_an_extra_optional_start_index` — the current one-argument archive stores the blocks, ignores the extra argument, and its empty reply reads as absent; a wrong-typed payload is rejected as a negative control. Its `Decode!(.., Option<u64>)` stops describing the archive the moment the new implementation returns `opt append_result` (`Req 3.1`), so row 11 replaces it rather than extending it. The ICP twin in row 12 stays valid indefinitely, which is why only that one is a release gate | the rollout premise, pre-PR-1 only |
| 11 | archive | against the new implementation: one argument only; assert blocks stored, empty reply, and that a chain mismatch traps rather than returning a refusal | `Req 5.1`, `5.2`, `5.3`, `5.4` |
| 12 | archive | **written**: `should_ignore_an_extra_optional_start_index` (`icp/archive/tests/tests.rs`) — the ICP archive's hand-rolled decode tolerates the extra argument, capacity drops by the block size, and the empty reply reads as absent | D3's tolerance; a **release gate** |
| 13 | archive | assert each counter in `Req 6.1` moves for its own cause and is readable afterwards | `Req 6.1`, `6.2`, `6.3`, `6.4` |
| 14 | unit, `ledger_canister_core` | drive a round whose reconciliation is dropped; with the span covered assert the archived prefix advances to the reported extent, with it uncovered assert the halt and the metric | `Req 8.2`, `8.3` |
| 15 | unit, `ledger_canister_core` | report an extent below the archived prefix; assert the halt, that no further block stops being served, and the metric | `Req 8.4` |
| 16 | integration | stop the archive so `remaining_capacity` is rejected; count attempts over a window, then restart and assert archiving resumes with no intervention | `Req 9.1`–`9.6` |
| 17 | integration | reuse the creation-trap harness so the `create_canister` reply is lost; assert `Creating` is `Started`, that it is exposed, and that it does not self-clear — no identity was recorded, so there is nothing to finish | `Req 11.1`, `11.2`, `11.4` |
| 17b | integration | lose the `install_code` outcome *after* the identity was recorded; assert the ledger resolves it by asking the created canister, finishes the creation without an operator, and adopts that same canister rather than creating a second | `Req 11.6`, `11.8` |
| 17c | integration | fail a round, then upgrade the ledger; assert the next transaction triggers an Archiving_Round immediately rather than waiting out the spacing | `Req 9.9` |
| 7d | archive | offer a batch whose second block exceeds the configured limit and, in turn, either does not chain or does not decode; assert in both cases that the first block is stored, the stop is reported, and the append is neither refused nor counted — the block was never going to be stored | `Req 1.9`, `Req 4.1`, `Req 6.4` |
| 17d | integration | lose the `update_settings` outcome; assert the archive is already adopted and serving, that archiving continues, that the handover metric is non-zero, and that a later round retries the handover and clears it | `Req 11.9`, `11.10` |
| 17e | upgrade | decode a pre-change `Archive` state; assert it decodes and that both new fields read their defaults — `Idle` and `None` — so the journal's own release cannot be the upgrade that fails | the two `#[serde(default)]`s above |
| 17f | upgrade | adopt an archive whose handover has not completed, then upgrade the ledger; assert `pending_handover` survives and the handover is still retried afterwards | `Req 11.10` |
| 17g | integration | complete step one of the handover, then lose step two's outcome; assert a retry refused as unauthorized clears the state and the metric rather than retrying forever | `Req 11.11`, `11.12` |
| 17h | upgrade | decode a pre-change `ArchiveConfig`; assert it decodes and the Expected_Parent reads absent, so PR 1 is not the release that breaks every archive's first upgrade | the `#[serde(default)]` above |
| 18b | integration | after the tail returns no range, assert a later round issues the probe once the backoff permits — no blocks moved, one empty append — rather than skipping every round and never resuming | `Req 10.1`, `10.2` |
| 18 | integration | install an old archive wasm as the tail; assert nothing is archived and the metric rises, then upgrade the archive and assert archiving resumes without a ledger upgrade. Repeat against a ledger whose archives do not implement the protocol and assert it archives normally | `Req 10.1`, `10.2`, `10.5` |
| 19 | integration | make the tail archive not answer; assert the round ends within `ARCHIVE_CALL_TIMEOUT` and is retried, and that a subsequent round does not store any block twice. Then, with a call still in flight to that archive, assert the ledger can be stopped and upgraded — the property an unbounded call removes | `Req 13.1`, `13.2`, `13.4`, `13.8` |
| 20 | integration | count `append_blocks` per round against a configuration that is multi-chunk today; assert one, and that the effective per-round metric matches | `Req 12.1`, `12.3`, `12.4` |
| 21 | measurement | ledger memory across an archive-creation round, as `routine_archiving_does_not_grow_the_ledger` does for a routine one; assert growth below a bound | D2's allocation work |
| 22 | archive | append `0..999`; then re-send `500..999` from a chain that diverges at 701, and assert `ChainMismatch` is returned, nothing is stored, and the covered-range counter rises while the tip-mismatch counter does not. Then re-send a range that does *not* diverge and assert success — so the check is not simply refusing every re-send | `Req 2.9`, `Req 6.1` |
| 22b | integration | drive the ledger into a refusal per 1.1, 2.2, 2.9 and 6.4 in turn; assert it stops attempting rather than backing off, and exposes the distinct metric. Then drive a `BelowRange` report and assert it does *not* halt but reconciles | `Req 9.7`, `Req 9.8` |
| 22c | archive | append a batch whose first block continues the tip but whose fifth does not continue the fourth; assert `ChainMismatch` at that index and that nothing was stored — the case a first-block-only check accepts | `Req 1.7` |
| 22d | archive | append a batch containing bytes that do not decode as a block; assert `Undecodable` is returned with its index, nothing is stored, and its counter rises separately from the mismatch counters | `Req 6.4` |
| 22e | archive | assert every outcome of Req 2 carries the same `block_index_offset` and `next_index` fields, and that `at_capacity` is false on a full store and on a wholly-covered re-send | `Req 3.1`, `3.3`, `3.6`, `Req 4.9` |
| 23 | unit, `ledger_canister_core` | create an archive after a round in which the previous one reported `next_index = N`; assert the new `block_index_offset` is exactly `N`, not `N+1` — `next_index` is *already* one past the last held index, and the off-by-one here is the whole of `Req 7.1`. Assert `archives()` tiles with no gap or overlap. Then present a node whose reported range starts elsewhere and assert no blocks are stored in it and the metric rises | `Req 7.1`, `7.2`, `7.3`, `7.4` |
| 24 | integration | on a ledger whose archives report no extent, assert an archive is still created and blocks are still discarded — the exemptions, which a literal reading of Req 7 and Req 8 would forbid | `Req 7.5`, `Req 8.7` |
| 25 | integration | fail `install_code` gracefully after `create_canister` succeeded; assert archiving halts, that the metric exposes the created canister's id and the id survives a ledger upgrade, and that a failure of `create_canister` itself does not halt | `Req 11.1`, `11.3`, `11.5`, `11.6`, `11.7` |
| 26 | archive | constrain growth so an append stops short for a reason other than the archive's own limit, using a route that **returns** control — the wasm's declared stable maximum, or a subnet memory cap — and assert `at_capacity` is reported false and the blocks that fit are readable | `Req 4.4` |
| 26b | archive | induce a reservation refusal with a low `reserved_cycles_limit`; assert the call is rejected, that nothing was stored, and that the ledger takes the graceful path — the negative case that fixes what `Req 4.7` gives up | `Req 4.7` |
| 28 | integration | fill the tail so an append comes back `at_capacity = true`; assert the *next* round creates an archive rather than re-offering to the same one, and that a short stop with `at_capacity = false` instead retries the same archive. This is why the flag exists and nothing else tests it | `Req 4.5`, `4.6` |
| 29 | integration | after each round, assert every index the ledger served before it is still retrievable, and that the ledger stopped serving only indices some archive reports covering — the headline safety property, which rows 14 and 15 approach only from their failure sides | `Req 8.1`, `Req 8.5` |
| 30 | integration | drive a round that must roll over; assert exactly one archive is created, and that a round which both fills the tail and has blocks left over does not create two | `Req 12.2` |
| 31 | integration | assert the capability probe stores nothing and consumes no capacity against a live archive, that a second round against an archive that already answered issues no further probe, and that a round which does probe sends at most one empty append | `Req 10.3`, `10.4`, `Req 12.1` |
| 27 | matrix | both token variants for every archive-level row: 1-9, 9b, 9c, 10, 11, 13, 22, 22c, 22d, 22e, 26 and 26b — (12) is ICP-only by nature, and 22b, 25 and 28-31 are integration rows | yes |

**Seams the design owes.** `Req 9` is observable only through the attempt spacing, so
the failure counter and last-attempt timestamp must be exposed as metrics; `Req 12.1`
needs a per-round append count; `Req 13` needs an unknown-outcome counter. All three
are metrics rather than test-only hooks, so they are also what an operator reads.

**At risk.** Row 26 needs a growth refusal that is neither the archive's own limit
nor a reservation refusal, since the latter traps. The wasm's declared stable maximum
is the most controllable route; a subnet memory cap works if the harness exposes one.
Note that `reserved_cycles_limit` is **not** usable for row 26 — it produces the
trapping case, which is row 26b's subject. If no returning route is controllable,
`Req 4.4` moves to Not attempted and the distinction rests on review of the branch
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

**Step 0 — Rosetta verification.** Not a PR. A sync from genesis on ckBTC, ckDOGE and
ICP, because nothing here repairs an already-diverged suite and the answer reorders
everything after it. Rosetta verifies both that returned indices match those requested
and that parent hashes chain
(`rosetta-api/icrc1/src/ledger_blocks_synchronization/blocks_synchronizer.rs`), so a
clean sync *is* the verification.

**PR 1 — archive.** `append_blocks`'s new argument and result, placement, the clamp,
the chain check on the first stored block, capacity reporting, the counters, and the
`.did`. The ledger is unchanged, so it sends no index and reads no result — which is
why `Req 5` is in this PR and not a later one.
*Acceptance:* `Req 1`, `Req 2`, `Req 3`, `Req 4` (4.1-4.4, 4.7, 4.8), `Req 5`,
`Req 6`.

*Who this lands on.* Every ICRC suite, not only the two ck ones, on each suite's own
upgrade schedule — see the SNS Constraint above for the window that opens. That is
the strongest argument for keeping PR 1 and PR 3 close together, and for not treating
PR 1 as a change that can sit in `master` for a while.

*What this release costs.* Three things, and the last is a limit rather than a
price.

**The archive starts decoding blocks, which it has never done.** `Req 1.7` needs
every stored block's `parent_hash`, so PR 1 parses block bytes that were written by
many ledger versions across years of SNS history. A block that fails to decode is
refused, and for an index-less append — the only shape PR 1 sees — a refusal *traps*
(`Req 5.2`), so a single decode regression halts archiving on that suite and stays
halted. This is the largest new risk in PR 1 and it is not in the protocol at all.

Two things follow. **Pre-flight it**: decode every block in a real mainnet archive
log offline, for each token variant, before PR 1 ships — the wasms and the block
bytes are both available, so this costs nothing but time and it is the only way to
find a historical encoding the current decoder rejects. And **budget the
instructions**: per-block decode plus hash on a 1 MiB append is not costed anywhere
in this document, and if it approaches the **per-message instruction** limit the
append traps, which is the same halt by another route. Note that is a different
ceiling from the payload limit `Req 12.3` caps: sizing a round to fit one message
says nothing about the instructions needed to decode and hash it.

An old ledger cannot tell a refusal's cause, so a round that dies after a successful
append leaves the next round re-sending blocks the archive holds; the archive
refuses, and the old ledger has no way past it. Archiving halts until PR 3, retrying
every transaction because the backoff is not in yet. Blocks accumulate locally, so it
is survivable, and a stall beats silent corruption — but keep the window short.

And it does not close the window on a **freshly created** archive — the limit of the
three, and the subject of the corresponding non-goal, which says why refusing instead
is not available. So the archive-only release closes the re-send case and leaves the
roll-over case open until PR 3 makes the ledger send an index, with `Req 1.6` counting
the window while it lasts.

**PR 2 — DEFI-2967.** Reviewed separately; not part of this spec. Ordered after PR 1
because spawning makes an archiving trap silent, so landing it first would leave the
corruption path open while removing the symptom that reveals it.

**PR 3 — ledger, bookkeeping.** Reconciliation from the reported extent, the coverage
and backwards checks, offset derivation, the capability probe and the seam.
*Acceptance:* `Req 4` (4.5, 4.6), `Req 7`, `Req 8`, `Req 9` (9.7, 9.8), `Req 10`. On the ICP ledger the
acceptance is `Req 7.5`, `Req 8.7` and `Req 10.5` — the exemptions — rather than the
criteria they except, since its archives report nothing to reconcile against.

**PR 4 — ledger, round shape and retries.** Byte-based selection, one append per
round, the backoff, the creation journal, the bounded calls, the allocation work and
the comment.
*Acceptance:* `Req 9` (9.1-9.6), `Req 11`, `Req 12`, `Req 13`.

`Req 9.7` and `Req 9.8` are deliberately in PR 3 rather than here: PR 3 is what gives
the ledger a `ChainMismatch` or `Gap` to read, and a release that can receive an
unresolvable refusal without knowing to stop would retry it on every transaction. The
rest of `Req 9` — the backoff itself — is independent and can follow.

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
`num_blocks_to_archive` per transaction — `Req 12.1` makes a round one append, so that
setting no longer governs the rate. The ck backlogs have been growing since the
mitigation, so the drain is long even though each round is cheap; plan the proposal
knowing that rather than expecting it to catch up quickly.

The union of PRs 1, 3 and 4 covers `Req 1` through `Req 13`.

## Discussed Alternatives

**A typed error return with no index.** `append_blocks : (vec blob) -> (opt
append_error)`, letting the ledger branch on the cause without addressing the append.
Subsumed: `opt append_result` *is* that return value and `Gap` is a typed cause. It
would not have delivered `Req 2` or `Req 3`, which need the index.

**String-matching the reject message.** Works today, depends on replica message
formatting and CDK version, cannot be tested against future changes.

**Idempotency without a reported position.** Make `append_blocks` skip duplicates but
change nothing else. Leaves the ledger counting what it *sent* rather than what was
stored, so it over-advances: with one batch's range recorded and the next lost, a
re-send walks the range to (0,2999) for an archive holding 0..1999, and reads for
2000..2999 route to an archive with nothing. `Req 3` is what makes idempotency
sufficient rather than a dead end.

**Reconciling from `log_length`.** `icrc3_get_blocks` already returns it
(`icrc1/archive/src/main.rs:387`), so the ledger could poll and repair its ranges.
Superseded by `Req 3`, which reports on every append — no extra round trip, nothing to
forget — and which needs no new block-count endpoint on the ICP archive. Polling
remains the only way to fix a ledger that has *already* diverged, which is judged not
to apply — not because the divergence is impossible, since both exposure windows are
open, but because none has been observed and DEFI-2967 could not induce the trap even
deliberately. See D10 for what repairing one would take.

**Advancing on a refusal.** Treat a refusal as "already archived" and advance by the
batch just attempted, making a trapped round resumable with no interface change. Its
soundness rests entirely on gaps being impossible, and if that premise were violated
the ledger would silently skip blocks — trading a loud stall for quiet data loss.
`Req 2` removes the choice by making a covered index a success rather than a refusal.

**Rolling over to a fresh node when the tail cannot answer.** Spawn a new archive,
which speaks the protocol by construction — no waiting and no incremental path.
Rejected because the costs are not one-off: spawning charges canister creation and
needs cycles provisioned, every extra archive is another canister to top up and upgrade
forever, and it abandons up to 3 GiB of already-paid-for space.

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
question as `Req 3`, but `Req 3` answers it on every append, and an empty append
answers it when there is no round to run (`Req 3.5`) — which is what the capability
probe uses. One method serves both.
