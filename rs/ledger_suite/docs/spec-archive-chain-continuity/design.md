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
acknowledgement costs a round trip.

Three smaller pieces complete it. Capacity stops being a failure and becomes a
reported position plus a flag distinguishing "I am full" from "the platform refused
me memory" (`Req 4`), which is what lets an attempt under storage pressure keep the
blocks that fit. A backoff bounds the per-transaction retries a failing archive
currently provokes (`Req 9`). And a round is reduced to a single append to a single
archive (`Req 12`), which removes both loops from `send_blocks_to_archive` and, with
one append, puts the range reconciliation and the block removal in the same message.

Two things outside this design gate its value. **DEFI-2967** must land before
archiving is switched back on: while archiving is awaited, a post-commit failure
turns a committed transfer into a rejection, and the ckBTC minter retries on
rejection with no deduplication window. And a **Rosetta sync from genesis** on
ckBTC, ckDOGE and ICP should run first, because nothing here repairs a suite that
has already diverged — Rosetta verifies both that returned indices match those
requested and that parent hashes chain
(`rosetta-api/icrc1/src/ledger_blocks_synchronization/blocks_synchronizer.rs`), so a
clean sync *is* the verification.

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

**Chunking today.** The chunk size is
`min(archive.max_message_size_bytes, max_ledger_msg_size_bytes)`
(`archive.rs:233-236`): 128 kB on ICP (`icp/src/lib.rs:628, :634`, and the ledger
ceiling is written only in `init`), and 1 MiB on ICRC via a hard-coded
`MAX_MESSAGE_SIZE`. So ICP rounds are two-chunk at `num_blocks_to_archive: 1000`
(`icp/src/lib.rs:623-624`) and ICRC rounds are single-chunk. Node roll-over makes a
round multi-message on *both*, independently of chunk size, roughly once per 3 GiB.

## Design Decisions

### D1 — Backoff is spaced geometrically, not latched

Serves `Req 9.1`, `Req 9.2`. `BACKOFF_INITIAL` = 30 s, doubling per consecutive
failure, `BACKOFF_CAP` = 1 h. A transient cause recovers within a minute; a permanent
one costs one probe per hour. Latching on any failure would have converted the
2026-09-01 self-recovery into a manual intervention, which is why `Req 9.4` exists.

Transaction-triggered plus a timestamp check rather than a timer: no re-arm hazard,
and it satisfies the every-await-is-a-call constraint above.

### D2 — Backoff and probe state are `#[serde(skip)]`

Serves `Req 9.3`, `Req 10.4`. Matches `archiving_in_progress`, and makes an upgrade
the operator's "resume now" lever, which is the right shape when the upgrade is
usually the fix.

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
`Req 7.1`, `7.3`, `7.4` and from `Req 8.1`-`8.4` and `8.6` (`Req 7.5`, `Req 8.7`) and
keeps deriving both the offset and the archived prefix from its own record. Without
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

Serves `Req 13.1`. `ic_cdk::call::Call::bounded_wait` defaults to 300 s, aligned with
the replica's `MAX_CALL_TIMEOUT`. A shorter value buys a faster stall detection at the
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

    type append_result = variant {
      Ok  : record { block_index_offset : nat64; next_index : nat64; at_capacity : bool };
      Gap : record { expected : nat64; got : nat64 };
    };

    append_blocks : (vec blob, opt nat64) -> (opt append_result);

Both arguments and the result are optional, which is what makes the archive
releasable alone. The reply's first field is named `block_index_offset`, matching
the published `init` argument it reports, rather than `start_index` — the request's
second argument is the index the *batch* starts at, and one word cannot mean both.

Order of work, per D4 and D5:

1. Caller check, unchanged.
2. If the batch is empty: reply per `Req 3.1`-`3.4` and stop. No placement, no
   chain check, no counter (`Req 3.5`, `Req 6.5`). This is the capability probe of
   `Req 10.3`, and short-circuiting is what keeps a probe sent at an index above
   the archive's position from being counted as a gap.
3. If the index is absent, skip **steps 4 and 5 only** — there is no index to place,
   so the batch is treated as continuing the tip, `k = 0`. Steps 6 onward still
   apply, and any refusal fails the call instead of returning a description of it
   (`Req 5.1`, `5.2`).
4. Place the index against `block_index_offset` and `block_index_offset +
   log_length` (`Req 2.1`, `2.2`, `2.6`), returning without appending in the
   refusing cases.
5. Compute `k` and the suffix per D4. If the batch is wholly covered, compare its
   last block against the stored block at that index and refuse on a mismatch
   (`Req 2.9`).
6. Chain-check `blocks[k]` against the tip (`Req 1.1`, `1.3`, `1.4`, `1.5`).
7. Append the suffix, stopping short where it must (`Req 4.1`, `4.2`).
8. Re-read `log_length` and reply (`Req 3.1`-`3.4`), or fail the call if step 3
   applied.

**Step 3 is the whole of what PR 1 delivers, so read it carefully.** PR 1 ships the
archive alone, which means an index-less append is the *only* shape it sees in
production. If the chain check were skipped along with placement, PR 1 would be a
no-op against the corruption it exists to stop: an un-upgraded ledger re-sending a
batch would have it stored a second time. The chain check must run for an index-less
append, and its refusal must fail the call, which is what `Req 5.2` and `Req 1`
together require.

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

### `ic-icrc1-archive` — `archive.did`

Add the second argument and the result type. Both `opt`, so the change is
backward-compatible in either direction; verify with `didc` and the CI Candid check
rather than by inspection.

### `ic-icrc1-archive` — `encode_metrics`

One counter per cause in `Req 6.1`, plus the decode-failure counter (`Req 6.4`).
All commit, because D5 removed the traps.

### `ledger_canister_core::archive` — `send_blocks_to_archive`

Both loops go (`Req 12.1`, `12.2`): pick a node, send what the round selected, one
call, reconcile, return. Reconcile `nodes_block_ranges` from the reported
`block_index_offset` and `next_index` rather than incrementing (`Req 7.3`, `Req 8.6`).

The coverage check (`Req 8.2`, `8.3`) and the backwards check (`Req 8.4`) live here,
since this is where the ranges are; per D6 they report upward rather than acting. The
return type widens to carry the count `archive_blocks` should remove, which may
include blocks an archive already held.

An absent reply routes by `Wasm::INDEXED_APPENDS` (D3): halt and count for an ICRC
ledger (`Req 10.1`), incremental path and count for ICP (`Req 10.5`). The
determination itself is the empty append of `Req 10.3`, issued here and exempt from
the round's append budget (`Req 12.5`).

Reconciliation also maintains what `archives()` publishes, so a Published_Range only
ever widens to what an archive has reported (`Req 7.2`) — the ledger's published view
and its internal record are the same data, which is why `Req 8.6` has to be about the
*source* of that data rather than about which field it is read from.

### `ledger_canister_core::archive` — `Archive` state

`#[serde(skip)]` fields per D2: last-attempt timestamp and consecutive-failure count
(`Req 9`), in-flight creation counter (`Req 11`), cached capability answer (`Req 10.4`).

The creation counter is `+1` before `create_canister` and `-1` when `nodes.push`
succeeds. It is per-epoch, so it needs no baseline, and it does not self-clear
(`Req 11.4`).

**The decrement is scoped to failures observed before the canister exists**, which
is narrower than "any creation step" and the distinction matters.
`create_and_initialize_node_canister` runs `create_canister` → `install_code` →
`update_settings` → `nodes.push`, each with `?`
(`archive.rs:129, 135-153, 163-179, 182`). A graceful `Err` from `install_code` or
`update_settings` therefore returns with **the canister already created** and its id
dropped on the stack — an orphan by any definition, and two of the three windows the
Constraints table lists. Decrementing there would hand those windows back to
`Req 9`'s backoff and defeat `Req 11.1`'s halt entirely.

So `Req 11.3`'s "a failure THE Ledger observes" is a failure of `create_canister`
itself; anything after it leaves the counter non-zero and halts. Making
`update_settings` a bounded call (below) makes this sharper rather than looser: an
unknown outcome there arrives as an `Err` on a call that may well have succeeded, and
it must halt for exactly the same reason.

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

### `ledger_canister_core::ledger` and `::blockchain` — round selection

Cap the selection at `min(num_blocks_to_archive, one message)` in bytes, in
`Blockchain::get_blocks_for_archiving` (`blockchain.rs:125`) called from
`blocks_to_archive` (`ledger.rs:460`) — both terms local, per the Constraint that
selection precedes any await (`Req 12.3`). `take_prefix(remaining_capacity)` still
trims on the cold-start path. Expose the effective per-round count (`Req 12.4`).

`blocks_to_archive` also carries the skip conditions: the backoff (`Req 9.1`), the
creation halt (`Req 11.1`), the capability halt (`Req 10.1`) and the coverage halts
(`Req 8.3`, `8.4`) — all before the guard is taken, so a skipped round costs nothing.

### `ledger_canister_core::runtime` — `Runtime::call`

One call site today, `Call::unbounded_wait` (`runtime.rs:68`), used for every
archiving call including the management-canister ones from `spawn.rs:25, 40`. It gains
a bounded variant so the choice is per call site (`Req 13.1`, `Req 13.5`):

| call | wait | why |
|---|---|---|
| `append_blocks` | bounded, ICRC only | idempotent under `Req 2.4`; ICP exempt per `Req 13.6` |
| `remaining_capacity` | bounded | read-only, so an unknown outcome is resolved by asking again |
| `update_settings` | bounded | setting the same controllers twice is a no-op |
| `create_canister` | **unbounded** | an unknown outcome leaves a canister nothing can address |
| `install_code` | **unbounded** | `install` mode fails if already installed, so it cannot be retried |

An unknown outcome is handled as a failure, which is safe only because the retry is
idempotent (`Req 13.3`, `13.4`), and is counted distinctly so D9's timeout can be
revisited.

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
| 7 | archive | size `max_memory_size_bytes` so a batch only partly fits; assert a short `next_index`, `at_capacity = true`, and that the blocks that fit are readable | `Req 4.1`, `4.2`, `4.3` |
| 8 | archive | **partly written**: `test_empty_append_blocks_is_accepted_and_stores_nothing` already asserts an empty append stores nothing and consumes no capacity, on both the one-argument and null-index shapes. Extend it against the new implementation to assert a reported extent, and that an empty append at an index above the archive's position is neither refused nor counted | `Req 3.5`, `Req 6.5` |
| 9 | archive | genesis into an empty archive with offset 0 | `Req 1.5` |
| 10 | archive | **written**: `test_append_blocks_ignores_an_extra_optional_start_index` — the current one-argument archive stores the blocks, ignores the extra argument, and its empty reply reads as absent; a wrong-typed payload is rejected as a negative control | the rollout premise |
| 11 | archive | against the new implementation: one argument only; assert blocks stored, empty reply, and that a chain mismatch traps rather than returning a refusal | `Req 5.1`, `5.2`, `5.3`, `5.4` |
| 12 | archive | **written**: `should_ignore_an_extra_optional_start_index` (`icp/archive/tests/tests.rs`) — the ICP archive's hand-rolled decode tolerates the extra argument, capacity drops by the block size, and the empty reply reads as absent | D3's tolerance; a **release gate** |
| 13 | archive | assert each counter in `Req 6.1` moves for its own cause and is readable afterwards | `Req 6.1`, `6.2`, `6.3`, `6.4` |
| 14 | unit, `ledger_canister_core` | drive a round whose reconciliation is dropped; with the span covered assert the archived prefix advances to the reported extent, with it uncovered assert the halt and the metric | `Req 8.2`, `8.3` |
| 15 | unit, `ledger_canister_core` | report an extent below the archived prefix; assert the halt, that no further block stops being served, and the metric | `Req 8.4` |
| 16 | integration | stop the archive so `remaining_capacity` is rejected; count attempts over a window, then restart and assert archiving resumes with no intervention | `Req 9.1`–`9.6` |
| 17 | integration | reuse the creation-trap harness; assert the counter is non-zero, archiving is halted, and that it does not self-clear | `Req 11.1`, `11.2`, `11.4` |
| 18 | integration | install an old archive wasm as the tail; assert nothing is archived and the metric rises, then upgrade the archive and assert archiving resumes without a ledger upgrade. Repeat against a ledger whose archives do not implement the protocol and assert it archives normally | `Req 10.1`, `10.2`, `10.5` |
| 19 | integration | make the tail archive not answer; assert the round ends within `ARCHIVE_CALL_TIMEOUT` and is retried, and that a subsequent round does not store any block twice | `Req 13.1`, `13.2`, `13.4` |
| 20 | integration | count `append_blocks` per round against a configuration that is multi-chunk today; assert one, and that the effective per-round metric matches | `Req 12.1`, `12.3`, `12.4` |
| 21 | measurement | ledger memory across an archive-creation round, as `routine_archiving_does_not_grow_the_ledger` does for a routine one; assert growth below a bound | D2's allocation work |
| 22 | archive | append a range, then re-send it whole with one block replaced by a different block at the same index; assert the append is refused and nothing stored — a fork detected without waiting for the boundary | `Req 2.9` |
| 23 | unit, `ledger_canister_core` | create an archive after a round whose reported extent ends at `N`; assert its `block_index_offset` is `N+1` and that `archives()` tiles with no gap or overlap. Then present a node whose reported range starts elsewhere and assert no blocks are stored in it and the metric rises | `Req 7.1`, `7.2`, `7.3`, `7.4` |
| 24 | integration | on a ledger whose archives report no extent, assert an archive is still created and blocks are still discarded — the exemptions, which a literal reading of Req 7 and Req 8 would forbid | `Req 7.5`, `Req 8.7` |
| 25 | integration | fail `install_code` gracefully after `create_canister` succeeded; assert the creation counter stays non-zero and archiving halts, and that a failure of `create_canister` itself does not halt | `Req 11.1`, `11.3` |
| 26 | archive | constrain growth so an append stops short for a reason other than the archive's own limit — a low `reserved_cycles_limit` on the archive, or a subnet memory cap if the harness allows it — and assert `at_capacity` is reported false and the blocks that fit are readable | `Req 4.4` |
| 27 | matrix | both token variants for 1-9, 10, 11, 13, 22 | — |

**Seams the design owes.** `Req 9` is observable only through the attempt spacing, so
the failure counter and last-attempt timestamp must be exposed as metrics; `Req 12.1`
needs a per-round append count; `Req 13` needs an unknown-outcome counter. All three
are metrics rather than test-only hooks, so they are also what an operator reads.

**At risk.** Row 26 depends on the harness being able to induce a growth refusal
that is not the archive's own limit — a `reserved_cycles_limit` low enough to trip
`IC0534`, or a constrained subnet memory. If neither is controllable, `Req 4.4` moves
to Not attempted below and the distinction rests on review of the branch that sets
the flag. That would be unsatisfying, because getting `Req 4.4` backwards is what
makes a ledger spawn archives during storage exhaustion — the original incident — so
try the reserved-cycles route before giving up on it.

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
      -p ledger-canister-core -p ic-icrc1-ledger -p ledger-canister
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
everything after it.

**PR 1 — archive.** `append_blocks`'s new argument and result, placement, the clamp,
the chain check on the first stored block, capacity reporting, the counters, and the
`.did`. The ledger is unchanged, so it sends no index and reads no result — which is
why `Req 5` is in this PR and not a later one.
*Acceptance:* `Req 1`, `Req 2`, `Req 3`, `Req 4` (4.1-4.4), `Req 5`, `Req 6`.

*What this release costs.* An old ledger cannot tell a refusal's cause, so a round
that dies after a successful append leaves the next round re-sending blocks the archive
holds; the archive refuses, and the old ledger has no way past it. Archiving halts
until PR 2, retrying every transaction because the backoff is not in yet. Blocks
accumulate locally, so it is survivable, and a stall beats silent corruption — but keep
the window to PR 2 short.

**PR 2 — DEFI-2967.** Reviewed separately; not part of this spec. Ordered after PR 1
because spawning makes an archiving trap silent, so landing it first would leave the
corruption path open while removing the symptom that reveals it.

**PR 3 — ledger, bookkeeping.** Reconciliation from the reported extent, the coverage
and backwards checks, offset derivation, the capability probe and the seam.
*Acceptance:* `Req 4` (4.5, 4.6), `Req 7`, `Req 8`, `Req 10`. On the ICP ledger the
acceptance is `Req 7.5`, `Req 8.7` and `Req 10.5` — the exemptions — rather than the
criteria they except, since its archives report nothing to reconcile against.

**PR 4 — ledger, round shape and retries.** Byte-based selection, one append per
round, the backoff, the creation counter, the bounded calls, the allocation work and
the comment.
*Acceptance:* `Req 9`, `Req 11`, `Req 12`, `Req 13`.

**Step 5 — lower `trigger_threshold`**, by NNS proposal. Not a PR. Last, because
nothing forces re-enablement to a date: after PR 1 and PR 2 archiving is *safe*, and
after PR 3 and PR 4 a stall heals itself rather than waiting for an operator.

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
remains the only way to fix a ledger that has *already* diverged; see D10.

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
