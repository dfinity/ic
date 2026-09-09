# Spec: chain-continuity check in the ICRC archive, and bounded archiving retries

Follow-up to DEFI-2967. Every component here works whether archiving is awaited or
spawned, so this is separately shippable — but the two changes address *different*
failures and re-enabling archiving needs both.

**Line references are against `master`**, paired with the symbol they point at so
they stay findable once the numbers drift. The one branch-specific thing is the
behavioural baseline for the trap tests; see Testing strategy.

## The goal: re-enabling archiving

Archiving is **disabled by configuration** on two ck ledgers today —
`trigger_threshold` raised beyond any reachable block count — as an incident
mitigation. Everything here serves turning it back on, which makes the sequence,
not any single change, the deliverable.

It cannot be re-enabled on `master` as it stands: doing so re-exposes the trap
that caused the incident, and awaited archiving turns that trap into a reject for
a transaction that committed (see *What awaiting costs*). DEFI-2967 is therefore a
prerequisite for re-enablement even though it is not a prerequisite for any
component here.

| # | step | why it sits there |
|---|---|---|
| 0 | **Rosetta verification** | whether the chains have already diverged reorders everything after it, and nothing here repairs a divergence |
| 1 | **Release 1** — archive only: A1, C1, archive half of E1 | closes the corruption. Safe on `master` as-is: an A1 refusal arrives as a graceful `Err` on the ledger's existing path and never rejects a transaction |
| 2 | **DEFI-2967** — spawn instead of await | removes the committed-but-rejected reply, and with it the double-mint hazard |
| 3 | **Release 2** — ledger: B, D, E2-E4, F | bounded retries, creation detection, reconciliation, the tail-archive probe, single-message rounds |
| 4 | **Lower `trigger_threshold` back**, by NNS proposal | archiving resumes, on a suite where a bad append is refused, a failure cannot contradict a reply, and a stall heals itself |

Two things about that order are deliberate:

* **1 before 2.** DEFI-2967 makes an archiving trap silent. Landing it first would
  leave the corruption path open *and* remove the symptom that would reveal it.
  The two are independent, so closing the hole before removing the alarm is free.
* **Re-enabling comes last.** Release 2 is not needed for *safety* — after steps 1
  and 2 a bad append is refused and a failure cannot misinform a caller, so the
  worst case is a stall. It is needed for *operability*: without it a stall waits
  for an operator instead of healing itself, and a failing archive is retried on
  every transaction. Nothing forces re-enablement to a date, so there is no reason
  to turn archiving back on and then have to watch it by hand.

D2-D4 are hygiene and can land whenever. **DEFI-2967 is reviewed as a PR, not
specced here**: it is already implemented, and its rationale lives as the doc
comment on `spawn_archiving`, next to the code. The dependency between the two is
this table.

**E is the substantive component.** It makes retries idempotent, so the whole
family of lost-acknowledgement problems stops mattering rather than each being
guarded separately. It is also the only part that changes a Candid interface,
which is what the two-release split exists for. **F is the one that removes code**
— both loops in `send_blocks_to_archive` — shrinking the state space E's checks
have to cover.

## Problem

Two canisters commit their own state independently, and the bug lives in the gap.

### Where each side commits

    // in the LEDGER, inside send_blocks_to_archive
    match Rt::call(node, "append_blocks", 0, (chunk,)).await {
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the ledger's message ENDS here
        Ok(()) => num_sent_blocks += chunk_len as usize,
        Err(..) => return Err((num_sent_blocks, ...)),
    };
    // ---- everything below runs in a NEW ledger message (the callback) ----
    let heights = inspect_archive(&archive, |a| { ... a.nodes_block_ranges ... });
    // ... loop for the next chunk, and eventually:
    //     remove_archived_blocks(num_sent_blocks)

The archive runs `append_blocks` as a message in its own canister; if it does not
trap, its stable-log write commits when that message ends, which is why a reply
comes back at all. **A reply is proof the archive committed.** The ledger, by
contrast, ends a message at the `.await`, so `num_sent_blocks`, the
`nodes_block_ranges` update and `remove_archived_blocks` all belong to a *new*
message and are not durable until it ends successfully.

So while the ledger executes that callback: **the archive has committed the
blocks, and the ledger has committed nothing about them.** A trap there drops the
future, `num_sent_blocks` is gone, the ranges are not advanced,
`remove_archived_blocks` never runs — and the ledger re-sends on the next round.

Can it tell afterwards? In the moment, yes: the callback *received* `Ok(())`, and
loses it because recording it is part of the message that traps. From its own
state, no: the result is indistinguishable from "the call was never made". By
asking the archive, yes — which is why E is the fix. Note the contrast that makes
this specific: a *failed* call yields `Err`, takes the graceful path, and is
handled. Only the **success-then-trap** interleaving destroys information.

### Why the two halves commit at different times

A module boundary, not a decision. `send_blocks_to_archive` is generic over
`Rt: Runtime, Wasm: ArchiveCanisterWasm` and receives only
`Arc<RwLock<Option<Archive>>>`, so it cannot call `remove_archived_blocks`, which
lives on `Blockchain` behind `LA::with_ledger_mut`. Only `archive_blocks<LA:
LedgerAccess>` can, and it runs once per round.

| | who can reach it | so it happens |
|---|---|---|
| `nodes_block_ranges` | archive state, which `send_blocks_to_archive` holds | **per chunk** |
| block removal | ledger state, which only `archive_blocks` holds | **once, at the end** |

**The line does not need redrawing.** The dangerous half is already reachable: the ranges are archive state, so they can be reconciled from the
archive's report per chunk — and they are what a new node's offset derives from.
Only `num_archived_blocks` lags, benignly: `block_locations` derives the local
range from it, so the ledger still claims blocks it has not removed and reads go
to the ledger, which still holds them; and any completed round calls
`remove_archived_blocks(num_sent_blocks)`, with a re-sent chunk still counting as
sent. The cost is re-sending chunks the archive discards.

### Why the re-send is harmful

`block_index_offset` is fixed at the archive's `init` and maps global to local by
a constant shift, so appending the same blocks twice shifts every later index:
append 0..999 twice and then 1000..1999, and a read for global 1500 resolves to
local 1500 — the second copy's block 500. Bad data from `icrc3_get_blocks`, and
the two clients that read it react differently — neither of them well:

* **Rosetta detects it and stops.** Its synchroniser checks that returned indices
  match those requested and that the parent hash of the lowest block fetched
  matches the highest already stored
  (`rosetta-api/icrc1/src/ledger_blocks_synchronization/blocks_synchronizer.rs`),
  so it bails rather than storing the bad range. That makes Rosetta the *detector*
  — the basis of the Rosetta precondition below — but it also means it stops
  syncing and goes stale, serving nothing new until someone intervenes.
* **The index accepts it silently.** `index-ng` has no parent-hash check at all: it
  fetches blocks and indexes them, trapping only if one fails to decode. A validly
  decoded block served at the wrong index is indexed against whichever accounts it
  names, so the corruption propagates into account histories as plausible-looking
  wrong answers. This is the worse of the two outcomes.

Neither can *repair* anything — one stalls, the other spreads it. So the
archive-side check does not make the fact knowable; it makes *not knowing* safe,
by refusing the re-send.

### What awaiting costs, and why this spec does not fix it

Moving archiving off the reply path does not address the divergence above — the
bookkeeping rots identically either way. But the two models differ in something
this spec cannot reach, and it is not a matter of how loud the failure is.

**On `master`, archiving is awaited.** The block committed at the chain's first
`.await`, so a trap in a later continuation cannot roll it back — but it turns the
reply into a **reject**. The caller is told the transfer failed when it succeeded
and cannot distinguish that from one that never happened; for clients that retry
on reject that risks minting a deposit twice. The ckBTC minter is such a client,
and nothing shields it: it mints with `created_at_time: None`
(`ckbtc/minter/src/updates/update_balance.rs:470`), so there is no ICRC-1
deduplication window to absorb a retry, and a reject is mapped to
`TemporarilyUnavailable` (`:475`) — an error whose name invites exactly the retry
that double-mints. **Spawned**, the
reply is produced in the message that commits the transaction, so a later
archiving failure cannot contradict it.

The two changes therefore do different jobs, and neither substitutes for the
other. A trap in an archiving continuation has four separable consequences:

| consequence | fixed by |
|---|---|
| the caller is told a committed transfer failed | **DEFI-2967** — the reply is produced before archiving starts, so nothing can contradict it |
| the archive's and the ledger's views diverge | **this spec** — E1 refuses a bad append, E2 reconciles from what the archive reports |
| the trap happens at all | **D2** — removes the largest post-commit allocation, lowering the probability |
| nobody notices the now-silent failure | **this spec** — C1's counters, `ledger_archiving_failures`, D1's counter, and the `log_visibility` proposal below |

So DEFI-2967 removes the trap's *consequence for the caller*, D2 lowers its
*probability*, and this spec removes its *damage* and makes what remains
*visible*. The last row is the one to notice: spawning is what makes the failure
silent, so the observability work here is not incidental to DEFI-2967 — it is what
keeps spawning from being a downgrade.

### Root causes

* **R-1. The ledger's knowledge of the archive is derived, not observed.**
  `nodes_block_ranges` and `num_archived_blocks` mirror archive state by inference
  from acknowledgements, so a lost acknowledgement rots the mirror silently. The
  duplicate append, the poisoned offset and the gap question are one bug in three
  hats.
* **R-2. The append protocol is positional, not addressed.** `append_blocks`
  carries no index, so neither side can verify that a message means what the other
  thinks. This is why A1 has to *infer* intent from hashes, why gap-versus-
  duplicate is undecidable at the archive, and why idempotency is impossible.
* **R-3. Work happens after commit points, in a language where allocation failure
  is fatal.**

### How exposed are we today?

Two windows, easily conflated. A round is multi-*message* either because a chunk
boundary splits it (**chunking**, governed by message size) or because it outgrows
the tail node and must create another (**node roll-over**, governed by archive
fill rate). Either is enough for the divergence.

The chunk size is `min(archive.max_message_size_bytes, max_ledger_msg_size_bytes)`
(`send_blocks_to_archive`, `archive.rs:233-236`), so the smaller governs:

| | archive option | ledger ceiling | effective chunk | 1000 blocks |
|---|---|---|---|---|
| **ICP** | 128 kB (`icp/src/lib.rs:628`), configurable | 128 kB (`:634`), set only in `init` | **128 kB** | **two chunks** |
| **ICRC** (ckBTC, ckDOGE) | `null`, so the 2 MiB default | `const MAX_MESSAGE_SIZE` = 1 MiB, **hard-coded** | **1 MiB** | one chunk |

So the **chunking** window is open today on ICP and closed on ICRC, while the
**node roll-over** window depends on nothing configurable — it opens once per
archive filling, roughly per 3 GiB — and is **open on both**. A single-chunk
configuration is not safety.

Neither window *closes* under this Approach; a round can still die after a
roll-over, and F only narrows it. What changes is the consequence, from silent
permanent corruption to a refusal the ledger recovers from or halts on. That is
why E belongs in this change rather than a later one — and note ICP is precisely
the ledger a *repair*-based fix could not have reached, since its archive exposes
no block count.

Two notes for other tickets:

* **On an ICRC ledger the configurable option cannot exceed 1 MiB**, because the
  hard-coded const caps it silently — so the 2 MiB default is already being
  clamped everywhere. A second instance of the DEFI-1565 finding that a metric
  must be labelled as the option rather than the enforced limit.
* **DEFI-1666's "2 MB messages" is not a configuration change.** ICRC needs
  `MAX_MESSAGE_SIZE` raised (code, Wasm release); ICP's ceiling is written only in
  `init` (`icp/ledger/src/main.rs:116`), and `ChangeArchiveOptions` updates
  `archive.max_message_size_bytes` but not the ledger's own ceiling
  (`icp/src/lib.rs:501-502`). It would *narrow* the chunking window, not widen it.

### How a round dies, and what it leaves behind

Both damaging variants need a **multi-node** round — node 0 filling mid-round —
plus a trap in a specific window.

Say a round starts at `num_archived_blocks = N` and selects N..N+1999. Chunk 1
fills node 0; node 1 is then created with offset `N+1000`, taken from
`nodes_block_ranges.last().map(|(_, to)| to + 1)` — the ranges chunk 1 just
advanced, never a count of what this round sent. `nodes.push` commits at that
point; the ranges and `num_archived_blocks` do not.

* **Node 1 received chunk 2, then the round died.** The next round restarts at N
  and sends to `nodes.last()` = node 1, whose tip is N+1999. Block N's parent hash
  does not match, so A1 refuses and archiving **stalls**. No corruption.
* **Node 1 received nothing before the round died.** The next round sends N..N+999
  to node 1, which is **empty** — no tip, so the chain check cannot fire, and
  without an offset check it accepts. Node 1 then holds N..N+999 while its
  `block_index_offset` says N+1000, so a read for global N+1000 returns block N.
  **Silent corruption, and nothing deployed can correct it**: the offset lives in
  a stable cell written at `init` (`icrc1/archive/src/main.rs:84, 173`) and
  `post_upgrade()` takes no arguments (`:212`). That is a property of the current
  code, not a law — see *Repairing a mis-indexed archive*.

**Under E both variants present identically**, as an append whose index is *below*
the node's offset — N against N+1000. They differ only in whether the node has a
tip, which is exactly the distinction A1 cannot make; comparing against the offset
works either way, because the offset is known from `init` and does not depend on
anything being stored. What separates them is remedy, not detection, and the
ledger decides that from its ranges (see *the coverage guard*).

**The ledger cannot catch this locally.** It never records the offset it
installed, and on a successful append it re-derives the node's range entry from
`(last_height + 1, ...)` (`archive.rs:300-301`) — the same expression that
produced the offset. So it writes a range that is self-consistent on paper while
the node serves the wrong block for that index. The offset is the one piece of
state only the archive holds, which is why the check must live there.

**A trapped round is not resumable with A1 alone**, which is the sharpest argument
for E. With only the chain check the ledger cannot tell a refusal meaning "you
already sent me these" from one meaning "you skipped some", so its only safe
response is to stop. The tempting shortcut — treat a refusal as "already archived"
and advance — rests entirely on gaps being impossible, and if that premise were
ever violated it would silently skip blocks, trading a loud stall for quiet data
loss. E removes the choice: a covered index is not a refusal at all, so the ledger
is *told* where it stands.

The realistic trap sources in a round, once D2 has removed the wasm copies:

1. **The per-chunk `Encode!`** — up to one message-size of Candid serialisation in
   the continuation after the previous append committed. The largest post-commit
   allocation, and the window F's single-message round removes rather than shrinks.
2. **Block removal's instruction cost.** `remove_archived_blocks` loops
   `pop_first()` once per block, so a large `num_blocks_to_archive` means
   thousands of stable-structure removals in one message. E leaves this alone (the
   range reconciliation stays per chunk) and F shrinks each round's removal. Worth
   *measuring* rather than assuming.
3. **Reply buffers** — tiny, and only fail once the heap is at the wall.

Not trap sources: an archive trap arrives as a *reject*, so A1 refusals and "no
space left" take the graceful path; and an upgrade cannot abandon a round
mid-flight, because stopping drains outstanding calls first.

## Approach

Six parts. A and C are confined to the ICRC archive; B, D, E's ledger half and F
are shared and so apply to both ledgers. Only **E** changes a Candid interface. A
is shippable alone and closes the corruption; F is worth doing only alongside E.

**A. The archive refuses appends that do not continue its chain.** `append_blocks`
hashes its own tip and compares it to the `parent_hash` of the first incoming
block, trapping on mismatch. The data is already in the message:
`BlockType::block_hash(&EncodedBlock)` (`ledger_core/src/block.rs:109`) hashes
stored bytes and `parent_hash()` (`:114`, impl at `icrc1/src/lib.rs:737`) reads
the incoming one. The archive already decodes blocks, so this is not a new
capability.

**B. The ledger stops spinning on a failing archive.** Archiving is triggered per
transaction (`archive_blocks::<Access>` at `icrc1/ledger/src/main.rs:566, 901,
994, 1092`), so a permanently failing archive is retried on every transaction —
each attempt materialising `min(num_blocks_to_archive, MAX_BLOCKS_TO_ARCHIVE)`
blocks on the heap (`ledger.rs:462`), making a `remaining_capacity` call and
encoding up to one message-size of Candid. Add a backoff: skip the attempt unless
enough time has passed since the last failure, with the interval growing on
consecutive failures up to a cap.

Backoff rather than latching, because most causes are transient:

| cause | transient? | under E |
|---|---|---|
| `append_blocks` refused a memory growth (OutOfStorage / reserved cycles) | yes — cleared itself in ~4.5 h on 2026-09-01 | short position with `at_capacity = false`; retry the same node, blocks that fit are kept |
| `remaining_capacity` rejected (archive stopped, frozen, upgrading) | yes | unchanged |
| archive creation short of cycles | yes, after a top-up | unchanged |
| `create_canister` / `install_code` / `update_settings` rejected | usually | unchanged |
| `append_blocks` trapped "no space left" on the logical cap | semi — ledger should have created a node | not a failure: `at_capacity = true`, ledger spawns the next node |
| "empty chunk" (a block exceeds the chunk size) | no | F's byte-based cap removes the case |
| **chain mismatch (new)** | **no** | stays a trap (Decision 5) |

Latching on any failure would have converted the 2026-09-01 self-recovery into a
manual intervention. Backoff bounds the waste without needing the cause, and
degenerates to a cheap hourly probe for permanent ones. Deliberately **not** a
timer: transaction-triggered plus a timestamp check has no re-arm hazard, and a
one-shot timer chain that failed to re-arm is exactly DEFI-2983.

**C. The archive records why it refused, in its own metrics.** The archive knows
the cause and already serves `/metrics`, so a counter there puts it where an
operator can read it without travelling over the wire.

Where the line falls between wire and metrics is settled by E. **Position and
capacity go in the reply**, because the ledger's response genuinely differs: a
covered index is success, a `Gap` halts, `at_capacity` means spawn, and a short
position without it means retry the same node. **A chain mismatch stays a trap**,
diagnosed through C1 — there is no progress to preserve, the ledger's action is
the same as for a `Gap`, and given E's index check it is an invariant violation
rather than an expected outcome (Decision 5). Neither needs reject-string
matching.

**D. Allocation and observability work on the ledger side.** Four independent
items, detailed in Components: an in-flight counter that detects an archive
creation whose outcome was never recorded, and halts (D1); removing the two
multi-megabyte copies of the archive Wasm that happen *after* `create_canister`
committed (D2); correcting a comment that claims a panic there rolls the
triggering transaction back, which holds only for the first archive a ledger ever
creates (D3); and making error construction allocation-free, so a graceful failure
cannot decay into a trap under memory pressure (D4).

**E. Give appends an index, and have them report their position back.**

    type append_result = variant {
      Ok  : record { start_index : nat64; next_index : nat64; at_capacity : bool };
      Gap : record { expected : nat64; got : nat64 };
    };

    append_blocks : (vec blob, opt nat64) -> (opt append_result);

The archive knows both its `block_index_offset` and its `log_length`, so it can
place the incoming index exactly:

| incoming index | meaning | action |
|---|---|---|
| `< offset` | not this node's range at all — the blocks belong to an earlier node | append nothing; the ledger is behind and runs the *coverage guard* (defined below) |
| `offset <= i <= offset + log_length` | starts at or inside what it holds | **drop the covered prefix, append the rest** |
| `> offset + log_length` | a gap | refuse, having appended nothing |

The first row matters more than it looks. Collapsing it into "less, so I already
have those" is exactly how a fresh node gets mis-indexed: a node with offset
`N+1000` and nothing stored, handed index `N`, would answer "I have those" when it
has nothing. It is also the **only** check available on an empty node, and what
lets the ledger learn its `num_archived_blocks` is behind.

Both fields are **global** indices rather than the local `log_length`, because a
local count would still need the node's offset to be useful — and that offset is
exactly the state we are trying not to depend on.

`next_index` means one thing in every row: **the next global index this node
expects, after whatever this call appended.** `start_index` is the node's
`block_index_offset`, and it is what the first row is really answering — the ledger
compares its own index against it to know it is behind. The two coincide on an
empty node, which is the case that row exists for, but not on a non-empty one, and
that case is reachable: node 1 receives chunk 2 (holding N+1000..N+1999), the round
dies, and the next round sends `N`. Carrying both means the ledger learns in *one*
round that node 0 covers up to N+999 and node 1 covers N+1000..N+1999, so it can
advance to N+2000 directly instead of advancing to N+1000 and rediscovering the
rest on the next round.

#### One rule for covered, straddling and fresh chunks

The middle row is one rule, not the two it looks like, because a batch can
*straddle* the boundary: the archive holds `N..N+499` and the ledger re-sends
`N..N+999`. That is reachable after a partial append followed by a trap.

**F does not remove this case**, which is worth saying since F removes so much
else. A straddle needs the archive to hold only *part* of what is being re-sent,
so it needs a partial append — and partial appends come from capacity or a
platform growth refusal, not from chunking. One message per round changes nothing
about that, and under F2 partial appends become *routine*, one per node fill. What
F removes is the multi-*chunk* round: the batch that gets re-sent is then the
round's single message rather than one chunk of several, and the arithmetic below
is the same either way.

**It is nonetheless safe, and the reason is the arithmetic.** `blocks[k]`'s true
global index is `incoming_index + k`, which by construction equals
`offset + log_length` — so the appended suffix lands at exactly the indices those
blocks belong at, and A1 confirms it, since `blocks[k]`'s parent is the block at
`offset + log_length - 1`, which is the archive's tip. E2 then reconciles the
node's range *from the report* rather than by incrementing, so the range is
correct whatever it was before. The round self-heals and the only cost is
re-sending the covered prefix. Nor can a straddle produce a double-mint: that
hazard is on the reply path, which DEFI-2967 removes, whereas a straddle happens
inside archiving, after the caller was answered.

    // reached only in the middle branch, where offset <= i <= offset + log_length
    k = min(offset + log_length - i, blocks.len())   // leading blocks to skip
    append blocks.iter().skip(k)                     // saturating, so never out of range
    report offset + log_length                       // re-read AFTER the append

`k` is unsigned and both of its bounds matter, in opposite directions:

* **Upper.** `offset + log_length - i` can exceed `blocks.len()`, so slicing on it
  panics. Reachable whenever the batch size varies between rounds: round 1 sends
  1000 blocks and the archive stores them all, the reconciliation is lost, then
  block sizes grow (or `num_blocks_to_archive` changes) so round 2's message fits
  only 600 — `k` is 1000 against a 600-block batch. The `min` handles it, and
  `skip` rather than `blocks[k..]` makes the clamp structural instead of a separate
  line a later edit can drop.
* **Lower.** The subtraction underflows if `i > offset + log_length`. That is the
  `Gap` row, so it must be **impossible to reach this line** with such an `i` —
  which is why `k` is computed *inside* the middle branch rather than before the
  placement check. Ordering the checks the other way round would turn a gap into a
  wrapped `k` and an append at the wrong place: silent corruption, not a panic.

Both are worth stating because the failure modes differ so much. The upper bound
fails loudly — the panic reaches the ledger as a reject, so archiving stalls with
an opaque cause on a path that should have been a clean no-op, but nothing is
corrupted. The lower bound, if the branch order were ever inverted, fails
silently. Placement first is therefore not only about A1 (above); it is also what
keeps this arithmetic in range.

A wholly covered chunk is the degenerate case `k == chunk.len()` — the idempotent
no-op, which falls out rather than needing its own branch. A chunk starting at the
tip is `k == 0`.

The reported value must be read **after** the append, not before. Reporting the
pre-append tip would have the ledger reconcile backwards and re-send the same
chunk every round.

**Placement is checked before the chain, and A1 applies only to the blocks
actually appended.** Getting this order wrong destroys the idempotency: on a
covered re-send the chunk's first block does not continue the archive's tip, it
continues one of the archive's own earlier blocks — so an A1 check on `blocks[0]`
would trap on precisely the re-send E exists to make harmless. The chain check
runs on `blocks[k]`.

#### With no index, the archive behaves exactly as it does today

A `null` index must be indistinguishable from the current implementation: A1 only,
trap on refusal, **empty reply**, never a refusal as a value.

This is what makes the archive half safe to release on its own. An index-less
append can only come from a ledger with no code to read a result, and candid will
not protect it: `done()` absorbs an unexpected trailing value as `Reserved`
(`candid-0.10.34`, `de.rs`), so an old ledger decoding the reply as `()` reads
`opt append_result { Gap = ... }` as `Ok(())`. It would then advance
`heights.1 += chunk_len` and call `remove_archived_blocks` for blocks the archive
refused to store. A trap, which the old ledger already handles on its `Err` path,
is the only safe answer to a caller that cannot listen.

So: **a value is only ever returned to a caller that asked with an index.**
Verified in both directions by
`test_append_blocks_ignores_an_extra_optional_start_index` (ICRC) and
`should_ignore_an_extra_optional_start_index` (ICP).

#### `next_index` may fall short, and `at_capacity` says why

`Ok` does not mean "I stored all of them". Two things stop an append part-way, and
they demand opposite responses:

| situation | `at_capacity` | ledger's action |
|---|---|---|
| the archive is at its own `max_memory_size_bytes` | `true` | spawn the next node |
| the platform refused a memory growth — subnet storage exhausted, `reserved_cycles_limit`, too few cycles for the reservation | `false` | **same node**, back off under B |

Today both trap, and the second is where a trap costs most: `StableLog::append` is
called per block, so a refusal mid-chunk leaves earlier blocks already in the log
and trapping discards real progress. `log_length` is accurate after a failed grow,
so the archive can report the position it reached instead. Under a persistent
cause, re-sending the whole chunk fails at the same place every round and makes
**no** progress, whereas banking the short position lets each attempt keep what it
managed.

The bit is load-bearing. Reading a short position as "full" would be actively
harmful under storage pressure: creating a canister needs the very subnet capacity
and reserved cycles that just failed, so the spawn likely fails too, and any that
succeed leave a trail of barely-filled nodes. The archive can tell the two apart —
its up-front check against its own limit is that test — so the answer belongs in
the reply. It also removes a trap from a path that is *normal operation*: archives
filling up is the steady state, not an error.

#### The coverage guard: when the ledger may skip forward

Learning that the tail node starts above the index it was about to send tells the
ledger its `num_archived_blocks` is behind, not that skipping is safe. It may
advance only if an **earlier node's range already covers the span it would skip**.
In the worked example the ranges are `[(0,1999)]` and the node reports
`start_index = 2000`, so `1000..1999` is covered and the count advances — to the
node's `next_index`, since everything from `start_index` up to it is held by this
node.

**Detection and remedy sit on opposite sides of the module boundary.** The check
belongs to `send_blocks_to_archive`, which holds the ranges; advancing the count is
`remove_archived_blocks`, which Decision 6 left out of reach there. So the guard
*reports* rather than acts: the round returns "sent nothing, but N blocks are
already archived" and `archive_blocks` performs the removal — the same shape as
today's `Ok(num_sent_blocks)`, needing a wider return value rather than wider
access.

**The halt branch is a safety net, not a live path.** If nothing covers the span,
advancing would skip blocks no archive holds, so it must halt with its own metric.
But it cannot arise normally: a new node's offset is *derived from*
`nodes_block_ranges.last()`, so the span below it is covered by construction.
Reaching it needs ranges inconsistent with themselves — a ledger restored from a
snapshot while its archives kept their state, or a rolled-back upgrade. Worth
stating, because the branch has no operator remedy: no endpoint sets
`num_archived_blocks`, so escaping it would need an upgrade carrying a migration.
Acceptable for a state reachable only by losing ledger state; unacceptable if a
trap could reach it — which is why the derivation matters.

The blocks are never *lost* in either branch. A lagging `num_archived_blocks` means
the ledger removed nothing, so it still holds them; a hole in the archive address
space costs the ability to archive them, not the data.

#### The mirror case: an archive that has gone backwards

The guard above handles the archive being *ahead* of the ledger. The opposite is
also worth one comparison, because it is the only shape of this bug that loses
data: **`next_index < num_archived_blocks`** means the ledger has already removed
blocks the archive no longer holds.

Normally unreachable, since `num_archived_blocks` only ever advances to a position
the archive reported. It becomes reachable if the archive itself goes backwards —
an operator restoring it with `load_canister_snapshot`, or reinstalling it — which
walks `log_length` back below what the ledger has already trusted.

The response is to **halt with its own metric and never remove another block**, and
to say so loudly: unlike every other case here, waiting does not help and retrying
does not either. The blocks between the archive's position and the ledger's are
gone from the system, and recovering them needs whatever backup the operator took.
Detection is a single comparison against a value the reply already carries, so
there is no reason not to make it.

#### What E buys, and what it retires

* **Retries become idempotent**, so a lost acknowledgement is harmless instead of
  corrupting, and a rotten mirror heals by retrying. Resumability comes free — no
  advance-on-refusal rule, no persisted intent.
* **The ledger's ranges become observed, not derived**, dissolving R-1 rather than
  working around it. It costs nothing in the failure model: the ledger already has
  to materialise a reply buffer, empty or not.
* **Gap versus duplicate is decided at the archive**, with a typed answer, and
  `Gap` as a *value* rather than a trap means the archive's message commits having
  done nothing — atomicity by construction, a precise reason instead of an opaque
  reject string, and no wasted work.
* **A full archive stops being an error**, distinguished from a platform growth
  refusal, so the ledger spawns in one case and waits in the other.
* **A1 is demoted** to belt-and-braces. Indexes verify *position*; the hash chain
  still verifies *content*, catching a ledger that sends right indexes with wrong
  blocks. Cheap, so worth keeping.
* **No separate range endpoint is needed.** A dedicated `archive_range() ->
  (start, end)` would answer the same question, but E already answers it on every
  append — and an **empty** `append_blocks` answers it when there is no round to
  run, which is how the tail archive is probed in Rollout.

**F. One message per round, sized by bytes.**

`send_blocks_to_archive` nests two loops: an outer one per **node**
(`archive.rs:240`), each iteration able to create one, and an inner one per
**message** within that node's capacity (`archive.rs:269`). Cap the round's
*selection* at `min(num_blocks_to_archive, one message)` and **both** loops go:
pick a node, take what fits, one call, reconcile, done.

Note what this is not. "Remove chunking" deletes only the inner loop, and the outer
one supplies multi-message rounds by itself — a round outgrowing the tail node must
create another and send again, reproducing the whole problem. Only capping the
selection collapses both. Blocks are variable-size, so the cap must be byte-based.

Both terms are known locally, which is what keeps selection before the first await:
`Blockchain::get_blocks_for_archiving` (`blockchain.rs:125`) materialises blocks
from `blocks_to_archive` (`ledger.rs:460`), and only then does `node_and_capacity`
ask. Folding tail capacity into the cap would move selection after a call.

| | how capacity is known | what a full node looks like |
|---|---|---|
| F1 alone | `remaining_capacity` pre-call, as today | `take_prefix(remaining_capacity)` trims, so the round is short and the *next* round rolls over |
| F1 + F2 | the previous append's `at_capacity` | no trim, so the round sends a full message, the archive stores what fits and answers `at_capacity = true`, and the *next* round rolls over |

Under F2 the ledger stops predicting capacity and reacts to what the archive
reports — the same move E makes for position — so `node_and_capacity`'s roll-over
test (`remaining_capacity < needed`, `archive.rs:552`) is restated as "the last
append to this node reported `at_capacity`", with the pre-call kept only for a cold
start or a freshly spawned node. Two consequences: "a roll-over round is short"
holds only under F1 alone, and partial appends become routine — one per node fill —
which is why the straddling rule above is load-bearing rather than defensive.

What it buys: one "did it land?" question per round instead of N; no node creation
mid-round; and less state to reason about, which is worth more than any single fix,
since most of the case analysis here exists because a round has interior states.

It also does more for Decision 6 than bounding the waste. With one append there is
**no await after it**, so the range reconciliation and `remove_archived_blocks`
land in the same message and commit together — the divergence Decision 6 accepts
exists only for multi-chunk rounds. Under F a round either records both values or
neither, and the re-send it accepts is at most one batch.

It does **not** make `index < offset` unreachable, and should not be sold that way.
A round whose append landed but whose removal did not leaves `num_archived_blocks`
one message behind, and if the next round rolls over, that node's offset is again
ahead of the index being sent. E1's offset check and E2's coverage guard remain
what make this safe; F narrows the window and bounds the waste.

**Throughput is not a concern.** ICP mainnet is `trigger_threshold: 2000,
num_blocks_to_archive: 1000` (`icp/src/lib.rs:623-624`), and 1000 blocks is two
chunks at 128 kB, so a single-message round archives roughly 500. Rounds fire per
transaction while accumulation is one block per transaction, so net drain goes from
~999 to ~499 per transaction — a factor of two on a ~500x margin. Backlog drain is
equally unaffected, being only 2x better today and equally slow.

**The real cost is one extra call per message, and `at_capacity` removes it.** A
1000-block ICP round is one `remaining_capacity` plus two appends today; split into
two rounds it is 2 x (1 + 1) = four calls. But an append reporting
`at_capacity = false` has already told the ledger the node has room, so the
pre-call is needed only on a cold start or right after a spawn — putting the
steady-state count *below* today's. This is why F follows E.

It also converges with DEFI-1666: 2 MB messages fit ~5000 blocks, exactly its
proposed `num_blocks_to_archive = 5000`, making single-message rounds the natural
configuration rather than a constraint. Cap the selection rather than selecting
`num_blocks_to_archive` and sending a prefix — capping keeps the configured value
honest and makes the effective per-round count exposable as a metric, the same
"report the enforced value" point as DEFI-1565.

### Not worth chasing: up-front allocation

Making response handling infallible cannot be completed at the ledger level: the
irreducible allocation in a callback is the **reply buffer**, which ic-cdk
materialises into its own `Vec` with no API to hand it a pre-allocated one. With
addressed appends it does not need to be — a trap in response handling stops being
harmful because the retry is idempotent. Rather than making the post-commit region
infallible, make it irrelevant, and keep the cheap parts as hygiene.

## Why not the alternatives

* **A typed error return on its own**, `append_blocks : (vec blob) -> (opt
  append_error)`, letting the ledger branch on the cause without an index.
  Subsumed by E: `opt append_result` *is* that return value and `Gap` is a typed
  cause. E deliberately does not type every cause — see Decision 5.
* **String-matching the reject message.** Works today, depends on replica message
  formatting and CDK version, and cannot be tested against future changes.
* **Making `append_blocks` idempotent (skip duplicates).** Leaves
  `heights.1 += chunk_len` counting what the ledger *sent*, not what was stored, so
  it over-advances: with chunk 1's range recorded and chunk 2's lost, a re-send
  walks the range to (0,2999) for an archive holding 0..1999, and reads for
  2000..2999 route to an archive that has nothing. It also needs the ledger to
  learn the archive's true position — which is what E adds, and why idempotency
  becomes the mechanism rather than a dead end.
* **Reconciling from `log_length`.** `icrc3_get_blocks` already returns it
  (`icrc1/archive/src/main.rs:387`), so the ledger could poll and repair its
  ranges. Superseded by E, which reports on every append — no extra round trip,
  nothing to forget — and which needs no new block-count endpoint on the ICP
  archive. Repair remains the only way to fix a ledger that has *already* diverged;
  see *Repairing a mis-indexed archive*.

### The road not taken: let the archive pull

The most fundamental option inverts the direction: the archive owns its position,
the ledger serves blocks and drops those below the reported point, and the
transaction path has no archiving commit point at all — R-1, R-2 and R-3 all
dissolve. But it trades the ledger's commit-point problem for the index's
timer-fragility problem, and DEFI-2983 is exactly that failure: a one-shot timer
chain that stopped re-arming and went unnoticed for hours. Not worth taking without
a much better story for timer liveness.

## Acceptance criteria

1. An ICRC archive rejects an `append_blocks` whose first appended block does not
   continue its stored chain, and its stored log is unchanged afterwards.
2. An empty ICRC archive **sent an index** accepts its first append only if it
   starts at the index the archive was created for. An index-less first append
   cannot be checked and keeps today's behaviour, which is why this is scoped to
   indexed appends.
3. A re-send after a lost ledger continuation is not stored again, so no archive
   holds the same block twice and no index resolves to the wrong block.
4. Refusal causes that remain traps are visible on the archive's `/metrics`, chain
   mismatch counted separately from a platform growth refusal.
5. The ledger treats a refusal as an ordinary archiving failure: counts it in
   `ledger_archiving_failures`, removes no blocks, releases the lock, and replies
   to the triggering transaction normally.
6. A ledger whose archiving keeps failing does not attempt it on every
   transaction; attempts are spaced by a growing interval up to a cap.
7. Archiving resumes without operator action once a transient cause clears.
8. Re-sending covered blocks stores nothing again and reports the archive's
   position, and the ledger reconciles from it rather than incrementing. A chunk
   starting inside the stored range and ending past it appends only its uncovered
   suffix. An index beyond the archive's position is refused as a gap.
9. A new node's `block_index_offset` is always derived from ranges reconciled
   against the archive. If `num_archived_blocks` lags after a round dies, reads
   remain correct and the next completed round corrects it.
10. An append storing only part of a chunk reports the position it reached. With
   `at_capacity` the ledger spawns the next node; without it, it retries the same
   node under B. Neither traps, and no stored block is discarded.
11. An append whose index is below the tail node's `start_index` appends nothing
   and reports both `start_index` and `next_index`. The ledger advances only if an
   earlier node's range covers the span below `start_index` — otherwise it halts
   with a distinct metric. The advance is applied by `archive_blocks`, from a count
   the round returns, and reaches `next_index` in one round rather than two.
12. A round issues exactly one *block-carrying* `append_blocks` and creates at most
   one node, at its start. Empty position probes do not count.
13. A ledger whose `Wasm::INDEXED_APPENDS` is true and whose tail archive does not
   answer an empty indexed `append_blocks` archives nothing, increments a distinct
   metric, and resumes without operator action once the archive is upgraded. The
   probe stores no blocks and consumes no capacity.
14. An archive whose reported position is *below* the ledger's
   `num_archived_blocks` causes the ledger to halt permanently with a distinct
   metric and remove no further blocks, since blocks it already removed are gone.
15. A batch whose covered prefix is longer than the batch itself is a no-op, not a
   panic: the archive clamps the prefix to the batch length.
16. A ledger whose `Wasm::INDEXED_APPENDS` is false uses the incremental path
   instead of halting, so the ICP ledger keeps archiving; E3's counter
   distinguishes the two cases.
17. The ICP archive is unchanged; the ICP *ledger* gains B1-B3, D1-D4, E2, E3, E4
   and F, but not the indexed protocol (Decisions 3 and 7).

## Components

| # | Component | Where | Notes |
|---|---|---|---|
| A1 | tip hash + parent comparison, trap on mismatch | `icrc1/archive/src/main.rs` `append_blocks` | separate crate from `ic-icp-archive`; no shared code |
| B1 | last-attempt timestamp + consecutive-failure count | `ledger_canister_core::archive::Archive` | `#[serde(skip)]` so an upgrade resets it |
| B2 | skip the round while backing off | `ledger_canister_core::ledger::blocks_to_archive` | before the guard is taken, so it costs nothing |
| B3 | backoff schedule constants | `ledger_canister_core::archive` | |
| C1 | counters for the causes that stay traps — chain mismatch, and a platform-refused growth, separately | `icrc1/archive/src/main.rs` `encode_metrics` | a capacity *stop* is no longer a refusal under E1; it is reported in the reply |
| D1 | in-flight archive-creation counter; halt archiving while non-zero | `ledger_canister_core::archive`, checked in `blocks_to_archive`, per-ledger metric | `+1` before `create_canister`, `-1` on a graceful `Err` from any creation step, `-1` when `nodes.push` succeeds. A trap skips the decrement, so non-zero means a creation was begun and never accounted for. `#[serde(skip)]`, so per-epoch and needing no baseline |
| D2 | stop copying the archive wasm after a commit point | `ledger_canister_core::spawn::install_code` signature, `archive.rs` | `install_code` takes `Vec<u8>`, forcing `archive_wasm().into_owned()`, and `Rt::call` serialises it again — two multi-MB copies in the continuation after `create_canister` committed. Take `Cow<'static, [u8]>`, pre-reserve the encode buffer before the first await, and `nodes.reserve(1)` |
| D3 | correct the comment above `create_canister` (`archive.rs:452-454`) | `ledger_canister_core::archive` | it says a panic there rolls the triggering transaction back. That holds only when no await preceded it, i.e. the **first** node a ledger creates: on a roll-over, `node_and_capacity` awaits `remaining_capacity` first (`archive.rs:547-549`), committing the transaction, so a panic rejects the reply instead. The comment should state the condition, not the conclusion |
| D4 | make error construction allocation-free, trim interpolating log lines | `ledger_canister_core::archive`, `::spawn` | `FailedToArchiveBlocks(pub String)` allocates on every error, so an allocation failure turns a graceful `Err` into a trap: use an enum with `Copy` payloads, rendered only where logged. `Rt::print` takes `impl AsRef<str>`, so static messages are free. **Keep** the canister id in the `create_canister` callback log — canister logs survive traps (`test_appending_logs_in_trapped_update_call`, `rs/execution_environment/tests/canister_logging.rs`), so it is the only record of an orphan's identity — but drop the `{result:?}` debug format |
| E1 | `append_blocks` takes an optional expected start index and returns an optional result carrying the node's `start_index`, its `next_index` after the append, and `at_capacity`, or a gap. Placement checked before the chain; covered prefix dropped; capacity reported rather than trapped; mismatch still traps; `null` index keeps today's behaviour exactly | `icrc1/archive/src/main.rs`, `archive.did`, `ledger_canister_core::archive::send_blocks_to_archive` | the only interface change; both `opt`, so tolerant in either direction. Verify with `didc` and the CI Candid check |
| E2 | the ledger reconciles `nodes_block_ranges` from the reported index instead of incrementing, and treats a covered index as success. The coverage guard detects here and reports upward — the round returns a count including blocks an archive already held, and `archive_blocks` performs the removal (Decision 6) | `send_blocks_to_archive`, return type consumed by `ledger::archive_blocks` | shared, so it applies to both ledgers once their archives answer |
| E3 | count every use of the incremental path | `ledger_canister_core::archive` + per-ledger metric | should read zero forever on an ICRC ledger, since E4 halts instead; reads every round on ICP, and is the signal for when Decision 7's port lets the path be deleted |
| E4 | probe the tail archive with an empty indexed `append_blocks`, cache the answer in `#[serde(skip)]` state, and halt archiving with a distinct metric if it does not answer — unless `Wasm::INDEXED_APPENDS` is false | `ArchiveCanisterWasm` gains `const INDEXED_APPENDS: bool`; probe and cache in `ledger_canister_core::archive` | the flag is a property of the wasm the ledger embeds, which is what the trait already abstracts. `true` for `ic-icrc1-archive`, `false` for `ic-icp-archive` |
| F1 | cap the round's selection at `min(num_blocks_to_archive, one message)` in bytes; delete both loops in `send_blocks_to_archive` | `Blockchain::get_blocks_for_archiving` (`blockchain.rs:125`) from `ledger::blocks_to_archive` (`ledger.rs:460`); `archive::send_blocks_to_archive` | removes code; byte-based so it is correct for variable-size blocks, and both terms are local so selection stays before the first await. Expose the effective per-round count as a metric |
| F2 | replace the `remaining_capacity` pre-call with the last append's `at_capacity`, keeping the call for a cold start or a freshly spawned node | `archive::node_and_capacity` (roll-over test at `archive.rs:552`) | depends on E1; makes F cheaper than today rather than dearer, and makes partial appends routine |

A1, C1 and E1 are in `ic-icrc1-archive`. B1-B3, D1-D4, E2-E4, F1 and F2 are
shared and therefore affect both ledgers; see Decision 3.

## Edge cases

* **Empty archive.** No tip, so the chain check cannot fire, and a node created
  for index X but handed blocks starting at Y < X stays wrong for as long as the
  offset does. So it must check the offset — which under E it can.
* **Genesis.** Block 0's `parent_hash` is `None`; an empty archive accepting it is
  the normal path.
* **Multi-chunk round.** Chunk 2's first block must continue chunk 1's last, so
  the check holds within a round as well as across rounds. F removes the case from
  our ledgers but not from a third-party one, so the check must still hold.
* **A round that rolls over.** Under F this is one creation plus one append, with
  the offset derived from ranges reconciled in the previous round. If that round's
  removal was lost, the offset is ahead of `num_archived_blocks` and E1's offset
  check fires — see the coverage guard.
* **Partial append.** The ledger must reconcile to the reported position, not to
  what it sent, and consult `at_capacity` before deciding whether to spawn.
* **Deployed archives.** The checks only apply to archives running the new wasm;
  see Rollout.
* **Undecodable first block.** The archive must not trap on a decode failure in a
  way indistinguishable from a mismatch; treat separately.
* **u64 vs u256 archives.** Both variants need the checks and the tests.

## Residual failure modes after this spec

Every inter-canister call allocates a reply buffer in the callback message. That
allocation cannot be removed, so each call is a place where the ledger can trap
with everything from earlier messages already committed. With A through F applied:

| allocation | already committed | consequence | severity |
|---|---|---|---|
| `create_canister` reply | canister exists, cycles gone | orphan; the id was never learned, and a canister cannot enumerate what it controls. D1 detects and halts | leak, irreducible; detected |
| `install_code` reply | + wasm installed | same, via D1 | leak; detected |
| `update_settings` reply | + controllers replaced | same, via D1 | leak; detected |
| `remaining_capacity` reply, existing node | the transaction (whose reply has gone out, if spawned) | round skipped, next attempt spaced by B | benign |
| `remaining_capacity` reply, new node | + node recorded in `archive.nodes` | round skipped; next round finds the node | benign, self-heals |
| `append_blocks` reply | the archive holds the blocks | under E the re-send is idempotent: the archive recognises the covered index, reports its position, and the ledger reconciles | none |

The "already committed" column assumes archiving is **spawned**. Awaited, every row
additionally commits the transaction and then rejects its reply — the correctness
hazard under *What awaiting costs*, a residual mode of the awaited model rather
than of this spec.

All three orphan windows sit between `create_canister` committing and `nodes.push`
committing, so D1's single non-zero check covers all of them; that is why
resumable creation is not needed. In the first two windows the orphan's only
controller is the *ledger*, because `update_settings` has not run, and the ledger
does not know the id — so the ~10 T is realistically written off and the cleanup is
bookkeeping.

D1 also gives the structural/transient split without an interface change: a
structural failure halts and waits for an operator, transient ones keep backing off
under B, and the ledger distinguishes them from its own state.

Two calibration notes. **D4 and its kin are tens to hundreds of bytes**, and a
small allocation only fails once the heap is already at the wall — where the
irreducible reply buffer allocated moments earlier would very likely have failed
too. D2 is different in kind (megabytes, reliably forcing a `memory.grow`), and so
is D4's error-enum half: it is not about probability but about keeping graceful
failures graceful. **And all of it depends on the cleanup callback surviving** —
every "guard released, failure counted" runs during task cancellation, which is
why it is limited to flipping a bool and incrementing a `u64`.

## Rollout

The suite is upgraded together, in the order index, ledger, archives. A through D
change no wire format, and neither does F; **E does**.

* **A** is confined to the archive. A new archive facing an *old* ledger sees
  ordinary contiguous appends and passes; on a re-send it refuses, and the old
  ledger already handles a rejected `append_blocks` on its `Err` path.
* **C** is additive to the archive's `/metrics`.
* **B**, **D** and **F** are ledger-internal. An old archive neither knows nor
  cares — F1 stands alone, F2 is inert until the archive answers.
* **E** adds an optional argument and result. Both are `opt`, so an old archive
  ignores the argument and returns nothing, which a new ledger reads as `null` —
  and then either halts or falls back, per *The tail archive must answer* below.
  Not taken on trust:
  `test_append_blocks_ignores_an_extra_optional_start_index` proves an unmodified
  ICRC archive stores the blocks and ignores the argument, and that its empty reply
  decodes as `null`; `should_ignore_an_extra_optional_start_index` proves the same
  for the ICP archive's hand-rolled decode. Both carry a negative control. Verify
  the declared Candid with `didc` and the CI check as well.

### Two releases, both in the standard order

Do not reorder the suite; split instead, so each release is safe in the normal
index-ledger-archives sequence.

**Release 1 — archive only.** A, C and the archive half of E. The ledger is
unchanged, so it neither sends the index nor reads the result — which is exactly
why the archive must keep today's behaviour for an index-less append. After this,
every archive in our suites speaks the protocol and the corruption is closed.

*What Release 1 costs.* It converts a corruption risk into an availability risk,
deliberately, but not for free. An old ledger cannot tell a refusal's cause, so a
round that dies after a successful append leaves the next round re-sending blocks
the archive holds; A1 refuses, and the ledger cannot advance past it — no endpoint
sets `num_archived_blocks`. Archiving halts indefinitely, with no remedy short of
Release 2, and because B is not in Release 1 the ledger keeps retrying every
transaction while halted. Blocks accumulate locally, so it is survivable, and a
stall beats silent corruption — but it is a reason to keep the window between the
releases short rather than to treat Release 1 as unconditionally safe.

**Release 2 — ledger.** B, D, F and the ledger half of E (E2-E4). Because Release 1 went
first, every ICRC archive in our suites already answers, so the probe below never
halts us. The `opt` tolerance matters for third parties, who may upgrade only the
ledger — and for the ICP ledger, whose archive does not answer at all.

### The tail archive must answer: probe it, and halt if it cannot

**Detect it with an empty `append_blocks`.** Nothing else discriminates:
`remaining_capacity` and `icrc3_get_blocks` exist on old archives too, and
`canister_status` would give the module hash but needs controller rights the ledger
does not have, since `update_settings` hands the archive to NNS Root. An empty
indexed append does discriminate — a new archive answers with its position, an old
one returns nothing — and it is side-effect-free: it stores nothing and consumes no
capacity, verified by
`test_empty_append_blocks_is_accepted_and_stores_nothing`.

Detecting from a *real* append instead would be post-hoc: an old archive has
already stored the blocks by the time it answers `null`, which is the very risk the
check exists to avoid.

Only the **last** archive matters, since `node_and_capacity` appends only to
`nodes.last()` and a newly spawned node runs the Wasm the ledger embeds. So the
requirement is "the current tail archive answers", satisfied permanently by one
rollover.

**Cache the answer in `#[serde(skip)]` state.** It then clears on every ledger
upgrade — precisely the moment the archives were upgraded too — so the ledger
re-probes exactly when the answer could have changed, and resumes on its own with
no operator flag to flip.

**What to do with a `null` answer depends on whether this ledger's own archives
should have answered**, and that is a property the ledger knows: it embeds the
archive Wasm it installs. Give `ArchiveCanisterWasm` an associated
`const INDEXED_APPENDS: bool` — true for `ic-icrc1-archive`, false for
`ic-icp-archive` — and the two cases separate cleanly:

| `INDEXED_APPENDS` | tail answered `null` means | behaviour |
|---|---|---|
| `true` (ICRC) | the operator upgraded the ledger but not the archives | **halt archiving**, increment a distinct metric, and resume on the next probe |
| `false` (ICP) | expected; its archive has no indexed protocol yet | incremental path, counted by E3 |

**Halting is the recommendation for ICRC**, because the incremental path preserves
exactly the bug this spec exists to close: with no reported position the ledger is
back to inferring, so a duplicate can still be stored and a new node's offset can
still be poisoned. A third-party operator who upgrades only the ledger is better
told than silently left unfixed, and the cost of telling them is stable-memory
growth while they finish the upgrade — the same degraded mode two ck ledgers run
deliberately today. It needs its own metric rather than hiding in the generic
failure counter, since it depends on an operator acting.

Note that this **revises Decision 3's "no trait seam"** rather than contradicting
it. Decision 3 rejected a seam introduced *only* to keep the ICP ledger on the old
behaviour, on the grounds that it would have no beneficiary. This seam has one:
the two ledgers genuinely differ in whether a silent `null` is a misconfiguration
or the expected state, and without the distinction a halt rule would stop ICP
archiving permanently.

### The incremental path, and why it survives only for ICP

Mechanically it is today's code: no position was reported, so the ledger advances
`heights.1 += chunk_len` and calls `remove_archived_blocks(num_sent_blocks)` as it
does now. It offers none of the new guarantees, which is exactly why ICRC ledgers
halt rather than use it. It stays reachable for one reason: the ICP archive never
answers, so ICP would otherwise stop archiving permanently (Decision 7).

Hence E3 counts its every use. On an ICRC ledger the counter should read zero
forever — a non-zero value means the `INDEXED_APPENDS` flag is wrong. On ICP it
reads every round, and it is the signal that says when Decision 7's port has landed
and the path can be deleted outright.

**Not recommended: rolling over to a fresh node.** A `null`-answering tail could be
treated as unusable and a new node spawned, which speaks the protocol by
construction — no waiting and no incremental path. Rejected because the costs are
not one-off: spawning charges canister creation and needs cycles provisioned, every
extra archive is another canister to top up and upgrade forever, and it abandons up
to 3 GiB of already-paid-for space.

## Testing strategy

A failing test per issue on the current baseline, passing after the fix.

Two things are branch-dependent, and conflating them is what makes references
drift. **Line numbers** here are against `master`. The **behavioural baseline** for
tests needing a trap is the *DEFI-2967 branch*: on `master` archiving is awaited,
so a trap in a continuation rejects the transaction and the observable behaviour
differs, and the harness those tests reuse
(`archiving_recovers_after_a_trapped_attempt`,
`routine_archiving_does_not_grow_the_ledger`) exists only there. Every
archive-level test is baseline-independent.

| # | issue | test | deterministic? |
|---|---|---|---|
| 1 | A1 — archive accepts a duplicate append, then serves the wrong block for an index | archive-level: append a valid range, re-append the same blocks, assert refusal and unchanged `log_length`, then assert `icrc3_get_blocks` resolves every index correctly | **yes** — pure archive behaviour |
| 2 | D1 — a trapped creation leaves an orphan and archiving keeps going | reuse the atomicity harness, which already induces a creation-round trap, and additionally assert the in-flight counter is non-zero and archiving is halted | **yes** — the trigger is reproducible |
| 3 | B — archiving is retried on every transaction | stop the archive so `remaining_capacity` is rejected, generate transactions, count attempts over a window, restart and assert archiving resumes | **yes** — a stopped canister gives repeatable graceful failures |
| 4 | E1/E2 — a node whose offset is ahead of the index being sent | archive-level: install with `block_index_offset = N+1000`, append starting at `N`, assert nothing is stored and that the reply carries `start_index = N+1000`. Repeat on a **non-empty** node (append N+1000..N+1999 first) and assert `next_index = N+2000` alongside the same `start_index`, so the two fields are distinguishable. Then a unit test in `ledger_canister_core` for the coverage guard: with the span covered, assert the ledger advances to `next_index`; with it uncovered, assert it halts and increments the distinct metric | **yes** — the offset is an install argument |
| 5 | D2 — the creation round's post-commit allocation | measure ledger memory across an archive-creation round, as `routine_archiving_does_not_grow_the_ledger` does for a routine one; assert growth is below a bound | yes, as a measurement |
| 6 | E1 — a partial append reports its true position rather than trapping | archive-level: set `max_memory_size_bytes` so a chunk only partly fits, append it, assert `Ok` with a short `next_index`, `at_capacity = true`, and that the blocks that fit are readable | **yes** — the limit is configurable at `init` |
| 7 | F1 — a round issues one append and creates at most one node | count `append_blocks` calls per round against a configuration that is multi-chunk today; assert one, and that the effective per-round metric matches | **yes** |
| 8 | E1 — an index-less append keeps today's behaviour and returns no value an old caller could misread | **already written**: `test_append_blocks_ignores_an_extra_optional_start_index` asserts the blocks are stored, the argument ignored, and the empty reply decodes as `null`; a wrong-typed payload is rejected as a negative control | **yes** — passing today, so it locks the premise |
| 9 | Decision 3 — the ICP archive's hand-rolled `Decode!` tolerates the extra argument | **already written**: `should_ignore_an_extra_optional_start_index` (`icp/archive/tests/tests.rs`) appends with a trailing `opt nat64`, asserts capacity dropped by the block size so it really stored it, and that the empty reply decodes as `None` | **yes** — a release gate |
| 10 | E1 — a straddling chunk appends only its uncovered suffix | archive-level: append `N..N+499`, then `N..N+999`, and assert `log_length` becomes 1000 rather than 1500, that every index resolves correctly, and that the chain check did not trap on the covered prefix | **yes** |
| 11 | E4 — a ledger halts against an un-upgraded tail, and resumes on upgrade | install an old archive wasm as the tail, generate transactions, assert nothing is archived and the halt metric rises; upgrade the archive, assert archiving resumes with no other intervention. Then assert an `INDEXED_APPENDS = false` ledger archives normally against the same archive | **yes** — both wasms are build artefacts |
| 12 | E1 — an over-long covered prefix is a no-op rather than a panic | archive-level: append 1000 blocks, then append the first 600 of them again, and assert the call succeeds, stores nothing, and reports `next_index` unchanged at 1000 | **yes** |
| 13 | E2 — an archive that has gone backwards halts the ledger | reduce the archive's position (reinstall it, or restore a snapshot taken before the appends), then run a round and assert the ledger halts, increments the distinct metric, and removes no blocks | **yes** — a reinstall is deterministic |
| 14 | both token variants for (1), (4), (6), (8), (10) and (12) | (9) is ICP-only by nature, so it has no u256 variant | yes |

Deliberately not attempted: **the duplicate-append and offset-divergence paths
end-to-end**, by inducing a trap in the append continuation. Routine rounds grow
ledger memory by zero bytes, which is why DEFI-2967 records "I could not make that
trap"; a multi-chunk configuration with large chunks would make the per-chunk
encode big enough for the reserved-cycles trick to bite, so it is probably
reachable, but it depends on allocator behaviour and would be flaky. Test 4 covers
the same arithmetic deterministically, which is where the bug lives. **D3** is a
comment, and the part of **D4** that matters cannot be provoked reliably for the
same reason.

## Decisions

1. **Backoff schedule:** start at 30 s, double on each consecutive failure, cap at
   1 h. A transient cause recovers within a minute; a permanent one costs one probe
   per hour.
2. **Backoff state:** `#[serde(skip)]` on `Archive`, so an upgrade resets it. This
   matches `archiving_in_progress` and makes an upgrade the operator's "resume now"
   lever, which is the right shape when the upgrade is usually the fix.
3. **The shared components apply to both ledgers, with no trait seam.** B1-B3,
   D1-D4, E2-E4 and F stay shared: the per-transaction retry, the lost-creation
   window and the inferred bookkeeping exist on both ledgers, so fixing them fixes
   both, and a seam added only to keep ICP on the old behaviour would have no
   beneficiary.

   Concretely, **the shared code always sends the index**, including to
   `ic-icp-archive`, which is what lets there be no seam — `send_blocks_to_archive`
   does not know which ledger it serves. That is safe because the ICP archive
   decodes by hand, `Decode!(&msg_arg_data(), Vec<EncodedBlock>)`
   (`icp/archive/src/main.rs:291`), and candid's `done()` absorbs the extra trailing
   value as `Reserved`; its empty reply then decodes as `None`, putting ICP on the
   incremental path. That tolerance is on a different code path from the ICRC
   archive's macro decode, so it has its own test and is a **release gate**: if it
   failed, shipping E2 would break ICP archiving outright rather than degrade it.

   **One seam is warranted after all**: `Wasm::INDEXED_APPENDS` (E4). It is not a
   layer added to keep ICP on the old behaviour — it records whether the archive
   Wasm *this ledger embeds* answers indexed appends, which is a fact the trait
   already exists to abstract. Without it, E4's halt rule would stop ICP archiving
   permanently. The general principle stands: a seam needs a beneficiary, and this
   one has two, since it is also what lets an ICRC ledger halt loudly.
4. **The typed result is part of E, not deferred.** It is what lets the ledger
   distinguish a duplicate from a gap without inspecting reject strings, and how the
   archive reports its position. An un-upgraded archive returns none of it, which is
   the whole of what the incremental path gives up — and the reason E4 refuses to
   use that path on a ledger whose archives should have answered.
5. **Capacity is reported; a chain mismatch still traps.** Not symmetric. A capacity
   stop has real progress to preserve and two causes needing opposite responses, so
   it belongs in the reply as a short `next_index` plus `at_capacity`. A mismatch has
   nothing to preserve, no distinct ledger action, and — given E's index check —
   cannot happen on a correctly addressed append; a trap is the right response to an
   invariant violation, platform-enforced rather than review-enforced. Capacity could
   later gain its own variant without changing what `Ok` means; a typed mismatch
   would leave us maintaining a handler for an impossible state.
6. **Accept the re-send; do not redraw the module boundary.** A trapped round
   re-sends chunks the archive discards. That is cheaper than giving
   `send_blocks_to_archive` ledger access, the divergence it leaves is benign, and F
   bounds the waste to a single message.
7. **The ICP archive is deferred, and this is the plan's main gap — not a limitation
   of it.** E1 lives in `ic-icrc1-archive`, so the ICP ledger never receives a
   reported position, E2's reconciliation never engages, and it stays permanently on
   the incremental path. R-1 and R-2 remain open on the ledger that has *both*
   windows open today.

   There is no cheap partial: porting A1 alone catches the variant where the new node
   has a tip, but the silent-corruption variant is the **empty** node, which has
   none — closing that needs the offset check, hence the index, hence the interface
   change. So ICP needs the whole of E1 against `ic-icp-archive`, plus its Candid and
   a second archive release. Deferring is defensible, since ICRC carries the two ck
   suites that prompted this, but it must be a tracked follow-up with its own ticket.
   **Whoever approves this spec is approving that ICP stays exposed until that
   lands.**

8. **An ICRC ledger halts rather than falling back.** The incremental path
   preserves exactly the bug this spec closes: with no reported position the ledger
   infers again, so a duplicate can still be stored and a new node's offset
   poisoned. Silently leaving a third-party operator in that state because they
   upgraded the ledger and not the archives is worse than stopping and telling
   them, and the cost of stopping is stable-memory growth they can end by
   finishing the upgrade. The probe makes the check cheap and side-effect-free, and
   the `#[serde(skip)]` cache makes recovery automatic. ICP is exempt by
   `INDEXED_APPENDS`, not by accident.

## Precondition: verify the live suites with Rosetta

**Do this first.** Nothing here repairs a suite that has *already* diverged, and a
mis-indexed node cannot be corrected by anything deployed today. So whether it has
already happened is not a question to carry alongside the work — the answer reorders
the work — and it is cheap.

The ICRC Rosetta synchroniser performs exactly this audit while syncing from
genesis, checking both halves independently
(`rosetta-api/icrc1/src/ledger_blocks_synchronization/blocks_synchronizer.rs`):

* `blocks_verifier::indices_are_valid` asserts the returned indices match those
  requested — with the comment "Block Indices are not part of the block hash",
  precisely the mis-indexing this spec is about.
* the parent hash of the lowest block fetched must equal the hash of the highest
  block already stored, or it bails with "Hash of block N in database does not match
  parent hash of fetched block N+1".

`derive_synchronization_gaps` additionally refuses a store with more than one gap.
Because the ledger routes reads through to its archives, a full sync walks the whole
chain across every node and would surface a duplicated or mis-indexed range as a
hash or index mismatch. So a clean Rosetta sync from genesis on ckBTC, ckDOGE and
ICP *is* the verification.

## Repairing a mis-indexed archive

Worth recording, because the plan's value changes if a divergence is found and
"unrecoverable" would be the wrong conclusion.

**The property that makes the corruption total also makes it repairable.** The
offset maps global to local by a single subtraction — `start -
opts.block_index_offset` (`icrc1/archive/src/main.rs:280`) — so a node storing the
right blocks under the wrong label is off by one constant everywhere.

In the worked case node 1 has offset `N+1000` but its local 0 holds block `N`, so
local `k` holds block `N+k`. Rewrite the offset to `N` and every index in the node
resolves correctly, not just the first thousand. The cost is that node 0's tail also
holds `N..N+999`, so the nodes overlap by a thousand blocks — wasted space, but
reads resolve as long as the ledger's ranges are corrected to hand `N..` to node 1.

So a repair is **two coordinated changes**, neither of which exists:

| | change | why it is needed |
|---|---|---|
| archive | `post_upgrade` takes an optional `block_index_offset` and writes the stable cell | the offset is the corrupted value |
| ledger | a migration or admin path that rewrites `nodes_block_ranges` | otherwise reads still route by the stale ranges |

The archive half is cheaper on ICP: `ic-icp-archive` already takes
`post_upgrade(upgrade_arg: Option<ArchiveUpgradeArgument>)`
(`icp/archive/src/main.rs:383`) and already mutates stable state through it, so this
is one more optional field on an existing record. The ICRC archive's
`post_upgrade()` takes nothing, so there it is a signature and `.did` change.

**Treat it as break-glass, not a feature.** Writing an offset on a healthy archive
corrupts it in exactly the way this spec exists to prevent, and the archive cannot
validate the value — it has no access to the previous node's tip. Safety rests on
the operator's arithmetic, which argues for building it only if the precondition
finds a divergence, and gating it behind a proposal carrying the computed value.

Note the asymmetry it exposes: the **read** path already enforces this boundary,
rejecting a `start` below the offset (`icrc1/archive/src/main.rs:274-277`). Only the
**write** path lacks the check, so E1 restores a symmetry rather than introducing a
concept.

## Remaining open items

1. **Block removal's instruction cost is unmeasured.** `remove_archived_blocks`
   loops `pop_first()` once per block, and it is listed as a trap source on
   assumption. F shrinks each round's removal, but the number is still worth having,
   and canbench already measures this class of thing.
2. **Genuine subnet exhaustion is not recoverable by anything here.** The archive
   cannot grow, and the ledger cannot grow to hold the backlog either. E makes the
   failure a clean, loud stall on the same node instead of a corrupting one, and
   lets each attempt bank the blocks that fit — it does not make archiving proceed.
   Since this is what caused the 2026-09-01 incident, note where the answer lives:
   capacity and reservation headroom, i.e. the drafted `memory_allocation` proposals
   for the ck suites, not this spec.

## Adjacent: make the ledger suite's logs readable

Trapped archiving leaves the ledger's `debug_print` output, a `[TRAP]` record and a
backtrace in the canister log — exactly the evidence DEFI-2967 records as
unobtainable for 2026-09-01. It is unreadable only because `log_visibility` defaults
to `Controllers` and the controller is NNS Root.

The NNS `UpdateCanisterSettings` action already supports the field
(`nns/governance/api/src/types.rs:2748`, validated in
`proposals/update_canister_settings.rs:47-52`), so one proposal would open it. Two
caveats: the action maps only `Controllers` and `Public`, so `AllowedViewers` is not
reachable that way; and the store is a bounded ring buffer, so it is a recent window
rather than an archive. Read what the ledgers actually emit before proposing
`Public`, since the output includes account principals and amounts. Pairs naturally
with the drafted memory-allocation proposals, which are the same NNS action.

## Design notes

* **`spawn` is the correct CDK primitive, and better than `spawn_migratory`.**
  `ic_cdk::futures::spawn` is the *protected* variant, documented as "canceled if
  the method returns before they complete", which looks wrong for a task meant to
  outlive its method. It is not: cancellation is refcounted, not tied to the future
  resolving. `enter_current_method` (`ic-cdk-executor/src/machinery.rs`) cancels
  attached tasks only when the method's `MethodHandle` count reaches zero, and a
  handle is taken before every inter-canister call and threaded through its
  callback — so a task blocked on a call keeps its context alive, and the chain of
  calls keeps the count above zero until archiving finishes. "Returns" means "the
  body finished *and* every outstanding call completed".

  Protected is also preferable: if the context ever did die with the task pending,
  `ProtectedTask`'s `PinnedDrop` panics, so it surfaces. `spawn_weak` drops
  silently, and `spawn_migratory` removes both the attachment and the alarm while
  the archiving chain has no need to migrate.

  **Invariant this creates:** every await in the archiving chain must be an
  inter-canister call. Awaiting anything a call does not wake — a timer, a channel —
  drops the refcount to zero, cancels the task and trips the panic. A second,
  independent reason not to make archiving timer-driven, and worth a comment at the
  archiving trigger.

* **Gap versus duplicate needs no distinguishing.** A refusal could mean a
  *duplicate*, where the ledger's bookkeeping has fallen behind and nothing is lost,
  or a *gap*, where blocks between the archive's tip and the ledger's next send are
  stored nowhere. Telling them apart at the archive is impossible today, because
  `append_blocks` carries no index. E answers the question at the archive instead:
  the index says which side of the tip the sender believes it is on, so the archive
  replies `Gap` or a covered-index success rather than the ledger guessing. What
  remains for C1 is the chain mismatch, which under E is an invariant violation.
