# Spec: chain-continuity check in the ICRC archive, and bounded archiving retries

Follow-up to DEFI-2967. Separately shippable from the archive-off-reply-path
change itself.

## What this proposes

A sequence, not a single choice. Only the last step is an open decision, and
deferring it costs nothing because the first two are needed either way.

| step | what | why it can go first |
|---|---|---|
| **1** | **A1 + C1** — the archive refuses appends that do not continue its chain, and counts why | confined to `ic-icrc1-archive`: no shared code, no ledger change, no interface change. Closes the corruption on its own, and its regression test fails today |
| **2** | **B + D1** — bounded retries, and detection of an archive creation whose outcome was lost | independent of the append protocol, so they survive either answer to step 3, and both apply to both ledgers |
| **3** | **E** — give appends an index and have them report their position back | the one part that changes a deployed interface |
| **4** | **F** — one message per round, sized by bytes | pure simplification of the ledger; needs E's `at_capacity` to pay for itself, so it follows |

D2-D4 are hygiene and can land whenever.

**E is the substantive one.** It makes retries idempotent, so the whole family of
lost-acknowledgement problems stops mattering rather than each being guarded
separately. It is the only part that touches the ledger-to-archive interface,
which the two-release split makes safe. Note that it needs no restructuring of the
ledger: the ranges it has to reconcile are already reachable where the chunks are
sent, and block removal can stay exactly where it is.

**Before any of it, run the precondition**: a Rosetta sync from genesis on ckBTC,
ckDOGE and ICP, which verifies the live chains and answers whether a divergence
has already happened. Nothing here repairs one, so that answer reorders the work.
See *Precondition: verify the live suites with Rosetta*.

**F is the one that removes code rather than adding it.** It deletes both loops in
`send_blocks_to_archive`, so a round is one node and one append, and the "did it
land?" question is asked once per round instead of once per chunk. It does not
replace E's checks — it shrinks the state space they have to cover.

## Problem

Two canisters are involved, each committing its own state independently, and the
bug lives in the gap between them.

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

* **The archive** runs `append_blocks` as a message in *its own* canister. If it
  does not trap, its stable-log write commits when that message ends — which is
  exactly why a reply comes back at all. A reply is proof the archive committed.
* **The ledger** ends a message at the `.await` and resumes in a *new* one. So
  `num_sent_blocks` (a local in the future's state), the `nodes_block_ranges`
  update, and `remove_archived_blocks` all belong to that new message and are not
  durable until it ends successfully.

At the instant the ledger is executing the callback, then: **the archive has
committed the blocks, and the ledger has committed nothing about them.**

### Why the two halves commit at different times

Not a decision — a module boundary. `send_blocks_to_archive` is generic over
`Rt: Runtime, Wasm: ArchiveCanisterWasm` and receives only
`Arc<RwLock<Option<Archive>>>`, so it has no ledger access at all and physically
cannot call `remove_archived_blocks`, which lives on `Blockchain` behind
`LA::with_ledger_mut`. Only the caller, `archive_blocks<LA: LedgerAccess>`, can —
and it runs once per round.

| | who can reach it | so it happens |
|---|---|---|
| `nodes_block_ranges` | archive state, which `send_blocks_to_archive` holds | **per chunk** |
| block removal | ledger state, which only `archive_blocks` holds | **once, at the end** |

There is no comment justifying the timing, and nothing in the history suggests it
was deliberate. So the divergence is a direct consequence of where the line was
drawn.

**It does not need to be redrawn.** The dangerous half is already on the reachable
side: `nodes_block_ranges` is archive state, so `send_blocks_to_archive` can
reconcile it from the archive's report per chunk, which is what keeps a new node's
offset correct — the part that caused permanent damage. Only
`num_archived_blocks` lags, and while it lags the divergence is benign:

* **Reads stay correct.** `block_locations` derives the local range from
  `num_archived_blocks`, so the ledger still claims blocks it has not removed; the
  archive's overlapping suffix is stripped by the existing resolution and reads go
  to the ledger, which genuinely still holds them.
* **It self-corrects.** Any round that completes calls
  `remove_archived_blocks(num_sent_blocks)`, and a re-sent chunk still counts as
  sent, so the total comes out right.

The cost is re-sending chunks in proportion to how far a trapped round had got,
for the archive to discard them. On a path we do not expect to take, that is a
better trade than widening `send_blocks_to_archive`'s access in shared code used
by both ledgers.

### What a trap in that callback destroys

The future is dropped, so `num_sent_blocks` is gone; `nodes_block_ranges` is not
advanced; `remove_archived_blocks` never runs. The ledger therefore still holds
blocks the archive already has, and re-sends them on the next round.

### Can the ledger tell whether the archive stored them?

Three answers, and the middle one is the problem:

* **In the moment — yes.** The callback *received* `Ok(())`. The ledger has the
  answer and loses it, because recording it is part of the message that traps.
* **Afterwards, from its own state — no.** The persisted state is
  indistinguishable from "the call was never made". Nothing separates *I asked, it
  worked, and I forgot* from *I never asked*.
* **Afterwards, by asking the archive — yes.** Which is why E is the fix: the
  acknowledgement itself carries the archive's position, so there is nothing to
  forget in the first place.

Note the contrast that makes this specific. If the call had **failed**, the
callback receives `Err` and takes the graceful path — count the failure,
`remove_archived_blocks(num_sent_blocks)` with the count so far, release the
guard. A graceful failure is distinguishable and handled. It is the
**success-then-trap** interleaving, and only that, which destroys information.

### Why the re-send is harmful

`block_index_offset` is fixed at the archive's `init` and it maps global to local
by a constant shift. So appending the same blocks twice shifts every later index:
append 0..999 twice and then 1000..1999, and a read for global 1500 resolves to
local 1500, which is the second copy's block 500. Silent bad data from
`icrc3_get_blocks`, which the index, Rosetta and any chain-verifying client would
accept.

Spawning archiving off the reply path (DEFI-2967) does not address this. It
arguably makes it quieter, because no caller sees the reject.

Note what the archive-side check does and does not do: it does not make the fact
knowable, it makes *not knowing* safe, by refusing the re-send.

### Root causes

Three structural facts generate the whole family of failures above, and naming
them explains why the approach is shaped as it is:

* **R-1. The ledger's knowledge of the archive is derived, not observed.**
  `nodes_block_ranges` and `num_archived_blocks` are a *mirror* of archive state,
  maintained by inference from acknowledgements. A lost acknowledgement rots the
  mirror silently. The duplicate append, the poisoned offset of a newly created
  node, and the gap question are all the same bug wearing different hats.
* **R-2. The append protocol is positional, not addressed.** `append_blocks`
  carries no index; position is implied by arrival order, so neither side can
  verify that a message means what the other thinks it means. This is why A1 has
  to *infer* intent from hashes, why gap-versus-duplicate is undecidable at the
  archive, and why idempotency is impossible.
* **R-3. Work happens after commit points, in a language where allocation failure
  is fatal.**

### How exposed are we today?

Two different windows, and it is easy to conflate them. A round is multi-*message*
either because a chunk boundary splits it (**chunking**, governed by message size)
or because it outgrows the tail node and must create another (**node roll-over**,
governed by archive fill rate). Both make the round multi-message, which is all the
divergence needs.

* The **chunking** window depends on configuration, and the two ledgers differ
  sharply — see the table below.
* The **node roll-over** window depends on nothing configurable: it opens once per
  archive filling, roughly per 3 GiB, and it is **open on both ledgers**, ICRC
  included, whose rounds are single-chunk.

So a single-chunk configuration is not safety. The chunk size is `min(archive.max_message_size_bytes, max_ledger_msg_size_bytes)`
(`archive.rs:252-256`), so whichever is smaller governs:

| | archive option | ledger ceiling | effective chunk | 1000 blocks |
|---|---|---|---|---|
| **ICP** | 128 kB (`icp/src/lib.rs:628`), configurable | 128 kB (`:634`), set only in `init` | **128 kB** | **two chunks** |
| **ICRC** (ckBTC, ckDOGE) | `null`, so the 2 MiB default, configurable | `const MAX_MESSAGE_SIZE` = 1 MiB, **hard-coded** | **1 MiB** | one chunk |

Two things follow that are easy to miss:

* **On an ICRC ledger the configurable option cannot exceed 1 MiB.** The
  hard-coded const caps it silently, so the 2 MiB default is *already* being
  clamped on every ICRC ledger. A second instance of the DEFI-1565 finding that
  the metric has to be labelled as the option rather than the enforced limit.
* **DEFI-1666's "2 MB messages" is not a configuration change.** On ICRC it needs
  `MAX_MESSAGE_SIZE` raised, which is a code change and a Wasm release. On ICP the
  ledger's ceiling is written only in `init` (`icp/ledger/src/main.rs:116`), so an
  upgrade cannot change it — note the asymmetry at `icp/src/lib.rs:501-502`, where
  `ChangeArchiveOptions` updates `archive.max_message_size_bytes` but nothing
  updates the ledger's own ceiling. So raising the archive option post-deployment
  is a no-op on both ledgers. Worth flagging on DEFI-1666.

`new_with_mainnet_settings()` sets both ICP values to 128 kB, and ckDOGE's
install record confirms `max_message_size_bytes = null` on the ICRC side.

So the **chunking** window is open today on the ICP ledger, whose rounds are
already two-chunk, and closed on ICRC. The **node roll-over** window is open on
both. Neither is a future risk.

To be clear about what the Approach does to them: **neither window closes** — a
round can still die after a roll-over, and F only narrows it. What changes is the
consequence, from silent permanent corruption to a refusal the ledger either
recovers from or halts on. See E1's offset check and E2's coverage guard. That is the main reason E belongs in this change
rather than a later one — and note the ICP ledger is precisely the one a
*repair*-based fix could not have reached, since the ICP archive exposes no block
count.

**DEFI-1666 would narrow the chunking window, not widen it** — and leaves the
roll-over window untouched. Its proposed
`num_blocks_to_archive = 5000` with 2 MB messages puts 5000 blocks at ~150 bytes
at about 750 kB — comfortably a single message — so it would take the ICP ledger
from two chunks to one. Note that it cannot be delivered as a configuration
change: the ICRC ceiling is a hard-coded const and the ICP ceiling is written only
in `init`, so both need code changes for a 2 MB message to take effect.

### How a round dies, and what it leaves behind

A round that dies mid-flight leaves work half done, and in one variant that is
worse than a stall. Both variants need a **multi-node** round,
i.e. node 0 filling mid-round — roughly once per 3 GiB of archive — plus a trap
in a specific window.

Say a round starts at `num_archived_blocks = N` and selects N..N+1999. Chunk 1
fills node 0; node 1 is then created with offset `N+1000`, correct because
`sent_so_far` is 1000. Note `nodes.push` commits at that point, while the ranges
and `num_archived_blocks` do not.

* **Node 1 received chunk 2, then the round died.** The next round restarts at N
  and sends to `nodes.last()` = node 1, whose tip is N+1999. Block N's parent
  hash does not match, so A1 refuses and archiving **stalls** until an operator
  intervenes. No corruption.
* **Node 1 received nothing before the round died.** The next round restarts at N
  and sends N..N+999 to node 1, which is **empty** — so it has no tip, the chain
  check cannot fire, and without an offset check it accepts. Node 1 then holds
  N..N+999 while its baked-in `block_index_offset` says N+1000, so a read for
  global N+1000 returns block N. **Silent corruption, and nothing deployed can
  correct it**: the offset lives in a stable cell written at `init`
  (`icrc1/archive/src/main.rs:84, 173`) and `post_upgrade()` takes no arguments
  (`:212`). That is a property of the current code rather than a law — see
  *Repairing a mis-indexed archive*, which is possible but needs new code on both
  sides and a hand-computed value.

Keeping the ledger's own bookkeeping consistent is not enough to close the second
case: it says nothing about a node whose offset was chosen for blocks it never
received. Closing it that way needs the offset recorded when the node is created,
so a later round can compare `nodes.last()`'s offset against its next index and
refuse a node that does not match. E covers this more directly: the archive
reports the index it expects, so the ledger sees the mismatch before appending.

Giving appends an index closes it directly, because the first append carries its
start index and the archive either adopts it or rejects the mismatch. That is E.

**Under E both variants present identically**, as an append whose index is *below*
the node's offset — N against an offset of N+1000. The variants differ only in
whether the node has a tip, which is exactly the distinction A1 cannot make.
Comparing against the offset works either way, because the offset is known from
`init` and does not depend on anything being stored. What separates the two is not
detection but remedy, and the ledger decides that from its own ranges: see the
coverage guard under E2.

Note also that the ledger **cannot** catch this locally. It never records the
offset it installed; when an append succeeds it re-derives the node's range entry
from `(last_height + 1, ...)` (`archive.rs:296-301`), the same expression that
produced the offset. So it writes a range that is self-consistent on paper while
the node physically serves the wrong block for that index. The offset is the one
piece of state only the archive holds, which is why the check has to live there.

The realistic trap sources in a round, once D2 has removed the wasm copies:

1. **The per-chunk `Encode!`** — up to one message-size of Candid serialisation,
   in the continuation after the previous append committed. The largest
   post-commit allocation in a multi-chunk round.
2. **Block removal's instruction cost.** `remove_archived_blocks` loops
   `pop_first()` once per block, so a large `num_blocks_to_archive` means
   thousands of stable-structure removals in one message — and E makes that
   message larger by adding the range application. A non-allocation trap source,
   and one worth *measuring* rather than assuming.
3. **Reply buffers** — tiny, and only fail once the heap is at the wall.

Not trap sources: the archive trapping arrives as a *reject*, so A1 refusals and
"no space left" take the graceful path; and an upgrade cannot abandon a round
mid-flight, because stopping drains outstanding calls first.

If resumability is wanted later, the cheapest route needs no new state, no
endpoint and no interface change: **treat an A1 refusal as "already archived" and
advance.** Given E, a gap is impossible, so the only cause of a refusal is that
the archive already holds those blocks; and an append is atomic per chunk, so it
is all-or-nothing — if the archive had none of them the tip would match and A1
would not refuse. The ledger can therefore advance by exactly the chunk it tried
to send, and a trapped multi-chunk round converges in one subsequent round, one
wasted call per already-landed chunk.

The caveat is real, though: it converts a loud stall into silent self-healing, and
its soundness rests entirely on "gaps are impossible", which is true *given* E but
is a premise a future change could break. If it ever were violated, advancing on
refusal would silently skip blocks. So it should be metric-visible and probably
bounded per round, and written down as depending on that invariant.

**Recommendation: not now.** The stall is loudly detectable — C1's counter,
`ledger_archiving_failures` and block accumulation all fire — and the remedy is a
proposal the team makes routinely. F removes most of the motive anyway: with one
message per round there is at most one already-landed chunk to re-send, so the
waste this would recover is a single call.

## Approach

Six parts. A and C are confined to the ICRC archive; B, D, E's ledger half and F
are in shared ledger code and so apply to both ledgers. Only **E** changes a
Candid interface, which is what the two-release split in Rollout exists for. A is
shippable on its own and closes the corruption; the rest are largely independent,
except that F is worth doing only alongside E.

**A. The archive refuses appends that do not continue its chain.**
`append_blocks` computes the hash of its own tip and compares it to the
`parent_hash` of the first incoming block. On mismatch it traps. The data is
already in the message: `BlockType::block_hash(&EncodedBlock)`
(`ledger_core/src/block.rs:109`) hashes stored bytes, and `parent_hash()`
(`:114`, impl at `icrc1/src/lib.rs:737`) reads the incoming one. The archive
already decodes blocks, so this is not a new capability.

**B. The ledger stops spinning on a failing archive.**
Archiving is triggered per transaction (`spawn_archiving()` at
`icrc1/ledger/src/main.rs:585, 918, 1011, 1109`), so a permanently failing
archive is retried on every transaction, each attempt materialising
`min(num_blocks_to_archive, MAX_BLOCKS_TO_ARCHIVE)` blocks on the heap
(`ledger.rs:462`), making a `remaining_capacity` call and encoding up to a
one message-size of Candid serialisation — 1 MiB on ICRC, 128 kB on ICP; see
below. Add a backoff: skip the attempt unless enough time has passed
since the last failure, with the interval growing on consecutive failures up
to a cap.

Backoff rather than latching, because most failure causes are transient and
self-healing:

| cause | transient? | under E |
|---|---|---|
| `append_blocks` refused a memory growth (OutOfStorage / reserved cycles) | yes — cleared itself in ~4.5 h on 2026-09-01 | reported as a short position with `at_capacity = false`; retry the same node, and any blocks that fit are kept |
| `remaining_capacity` rejected (archive stopped, frozen, upgrading) | yes | unchanged |
| archive creation short of cycles | yes, after a top-up | unchanged |
| `create_canister` / `install_code` / `update_settings` rejected | usually | unchanged |
| `append_blocks` trapped "no space left" on the logical cap | semi — ledger should have created a new node | no longer a failure: reported as `at_capacity = true`, and the ledger spawns the next node |
| "empty chunk" (a block exceeds the chunk size) | no | F's byte-based cap removes the case |
| **chain mismatch (new)** | **no** | stays a trap, by Decision 5 |

Latching on any failure would have converted the 2026-09-01 self-recovery into
a manual intervention. Backoff bounds the waste without needing to know the
cause, and degenerates to a cheap probe at the cap interval for the permanent
causes.

Deliberately **not** a timer. Transaction-triggered plus a timestamp check has
no re-arm hazard; a one-shot timer chain that failed to re-arm is exactly
DEFI-2983.

**C. The archive records why it refused, in its own metrics.**
The archive knows the cause and already serves `/metrics`, so a counter there —
a chain mismatch counted separately from a capacity refusal — puts the cause where
an operator can read it without it having to travel over the wire.

**What travels over the wire and what stays in metrics** is settled by E, and the
line falls in a specific place:

* **Position and capacity are in the reply**, because the ledger's response
  genuinely differs: a covered index is success, a `Gap` halts, `at_capacity`
  means spawn the next node, and a short position without `at_capacity` means
  retry the same node. These are control flow, so they must be typed.
* **A chain mismatch stays a trap**, and C1 is how it is diagnosed. There is no
  progress to preserve, since the check runs before any append; the ledger's
  action is the same as for a `Gap`; and given E's index check a mismatch on a
  correctly addressed append is an invariant violation rather than an expected
  outcome. A trap is the right answer to "this cannot happen" — it is
  platform-enforced rather than review-enforced, so a future edit cannot silently
  mutate state before the check. Typing it would buy the ledger a distinction it
  has no different action for.

So C carries the causes that remain traps, and E's typed result carries the ones
the ledger acts on. Neither needs reject-string matching. See Decision 5.

**D. Allocation and observability work on the ledger side.** Four items that are
independent of each other and of the above, detailed in Components: an in-flight
counter that detects an archive creation whose outcome was never recorded and
halts archiving until an operator looks (D1); removing the two multi-megabyte
copies of the archive Wasm that happen *after* `create_canister` has committed
(D2); correcting a comment that still claims a panic there rolls the triggering
transaction back, which stopped being true when archiving was spawned (D3); and
making error construction allocation-free, so a graceful failure cannot decay
into a trap under memory pressure (D4).

**E. Give appends an index, and have them report their position back.**

    type append_result = variant {
      Ok  : record { next_index : nat64; at_capacity : bool };
      Gap : record { expected : nat64; got : nat64 };
    };

    append_blocks : (vec blob, opt nat64) -> (opt append_result);

The second argument is the expected start index. The archive knows both its
`block_index_offset` and its `log_length`, so it can place that index exactly:

| incoming index | meaning | action |
|---|---|---|
| `< offset` | not this node's range at all — the blocks belong to an earlier node | report this node's start; the ledger is behind |
| `offset <= i < offset + log_length` | already holds them | **no-op success** — this is the idempotency, not an error |
| `== offset + log_length` | correct continuation | append, and report the new next index |
| `> offset + log_length` | a gap | refuse, having appended nothing |

The first case matters more than it looks. Collapsing it into "less, so I already
have those" is exactly how a freshly created node gets mis-indexed: a node with
offset `N+1000` and nothing stored, handed index `N`, would otherwise answer "I
have those" when it has nothing at all. It is also the **only** check available
on an empty node, since there is no tip for A1 to compare against, and it is what
lets the ledger learn that its `num_archived_blocks` is behind.

#### `next_index` may fall short, and `at_capacity` says why

`Ok` does not mean "I stored all of them". Two quite different things stop an
append part-way, and they demand opposite responses:

| situation | `at_capacity` | ledger's action |
|---|---|---|
| the archive is at its own `max_memory_size_bytes` | `true` | spawn the next node |
| the platform refused a memory growth — subnet storage exhausted, `reserved_cycles_limit`, too few cycles to fund the reservation | `false` | **same node**, back off under B |

Today both trap, and the second is where a trap is most costly:
`StableLog::append` is called per block (`icrc1/archive/src/main.rs`), so a
refusal mid-chunk means earlier blocks are already in the log, and trapping
discards real progress. `log_length` is accurate after a failed grow, so the
archive can instead report the position it actually reached and the ledger
reconciles to exactly what was stored. Under a persistent cause, re-sending the
whole chunk fails at the same place every round and makes **no** progress, whereas
banking the short position lets each attempt keep what it managed.

The bit is load-bearing, not cosmetic. Reading a short position as "full" would be
actively harmful under storage pressure: creating a canister needs the very subnet
capacity and reserved cycles that just failed, so the spawn likely fails too, and
any that succeed leave a trail of barely-filled nodes. The archive can tell the
two apart — its up-front check against its own limit is exactly that test — so the
answer belongs in the reply.

It also removes a trap from a path that is *normal operation*: archives filling up
is the steady state, not an error.

Note it reports a **global** index rather than its local `log_length`. The local
count would still need the node's offset to be useful, and that offset is exactly
the state we are trying not to depend on; the archive knows both, so it should do
the arithmetic.

Both `opt`s keep this compatible in either direction: an old archive ignores the
extra argument and returns nothing, which decodes as `null` and tells a new
ledger to fall back to today's incremental behaviour. That matters, because the
suite upgrade order puts archives **last**, so a new ledger will talk to old
archives during the rollout window.

Returning `Gap` as a *value* rather than trapping is better than the current
design on three counts: the archive's message commits having done nothing, so
atomicity holds by construction; the reason is precise instead of an opaque
reject string; and no work is wasted.

Reporting the next index back is what makes this more than an idempotency fix. The
ledger then **observes** its position on every round instead of inferring it, so
`nodes_block_ranges` stops being a mirror that can rot and becomes a value the
archive just told it. That dissolves R-1 rather than working around it. It costs
nothing in the failure model, because the ledger already has to materialise a
reply buffer — that allocation is irreducible whether the reply is empty or not.

What the change does, in total:

* **Retries become idempotent**, so a lost acknowledgement is harmless instead of
  corrupting. A rotten mirror heals by simply retrying.
* **The ledger's ranges become observed, not derived**, so they cannot silently
  diverge in the first place.
* **Gap versus duplicate is decided at the archive**, with a typed answer the
  ledger can act on: a duplicate is success, a gap halts.
* **A new node's offset can no longer be poisoned**, because the ranges it derives
  from are reconciled against the archive rather than inferred.
* **A full archive stops being an error.** Capacity is reported rather than
  trapped, and distinguished from a platform growth refusal, so the ledger spawns
  a node in one case and waits in the other.
* **Resumability is free.** No advance-on-refusal rule, no persisted intent.
* **A1 is demoted** to a belt-and-braces check. Indexes verify *position*; the
  hash chain still verifies *content*, which catches a ledger that sends the
  right indexes with the wrong blocks. Cheap, so worth keeping.

#### The coverage guard: when the ledger may skip forward

Learning that the tail node starts above the index it was about to send tells the
ledger its `num_archived_blocks` is behind, but not that skipping is safe. It may
advance only if an **earlier node's range already covers the span it would skip**.
In the worked example the ranges are `[(0,1999)]` and the node reports it starts at
2000, so `1000..1999` is covered and the count advances to 2000.

**Detection and remedy sit on opposite sides of the module boundary.** The check is
in `send_blocks_to_archive`, which holds the ranges; advancing the count is
`remove_archived_blocks`, which Decision 6 deliberately left out of reach there. So
the guard does not act — it *reports*: the round returns "sent nothing, but N
blocks are already archived", and `archive_blocks` performs the removal. That is
the same shape as today's `Ok(num_sent_blocks)`, with a count that includes blocks
an archive already held, so it needs a wider return value rather than wider access.

**The halt branch is a safety net, not a live path.** If nothing covers the span,
advancing would skip blocks that no archive holds — so it must halt, with its own
metric. But it cannot arise in normal operation: a new node's offset is *derived
from* `nodes_block_ranges.last()`, so the span below it is covered by construction.
Reaching it requires ranges that are inconsistent with themselves — a ledger
restored from a snapshot while its archives kept their own state, or a rolled-back
upgrade. Worth stating, because the branch has no operator remedy: no endpoint
sets `num_archived_blocks`, so escaping it would need an upgrade carrying a
migration. That is an acceptable cost for a state we can only reach by losing
ledger state, and an unacceptable one if it were reachable by a trap — which is
why the derivation above matters.

Note also that the blocks are never *lost* in either branch. `num_archived_blocks`
lagging means the ledger has removed nothing, so it still holds them; what a hole
in the archive address space costs is the ability to archive them, not the data.

#### No separate range endpoint is needed

An earlier version of this design added `archive_range() -> (start, end)` so the
ledger could *observe* its position rather than *derive* it. E already does that
on every append, and an **empty** `append_blocks` gives the same answer for free
when the ledger has no round to run — a cold start, or after a round that died
before any append landed. So one method serves as both the append and the position
query, and no extra endpoint is required.

**F. One message per round, sized by bytes.**

`send_blocks_to_archive` nests two loops: an outer one per **node**
(`archive.rs:240`), each iteration able to create one, and an inner one per
**message** within that node's remaining capacity (`archive.rs:269`). Cap the
round's *selection* at `min(num_blocks_to_archive, one message)` and **both**
loops go: pick a node, take what fits, one call, reconcile, done.

Both terms of that cap are known locally, which is what makes it cheap. Tail
capacity deliberately is **not** in it: selection happens before any await —
`get_blocks_for_archiving` materialises blocks (`ledger.rs:462`) and only then does
`node_and_capacity` ask — so folding capacity in would move selection after a call.
Today's `take_prefix(remaining_capacity)` trims the selection instead. A round is
therefore always *at most* one message, and a roll-over round is simply a short
one.

Note what this is not. "Remove chunking" deletes only the inner loop, and the
outer one supplies multi-message rounds by itself — a round that outgrows the tail
node must create another and send again, which reproduces the whole problem. Only
capping the selection collapses both. Blocks are variable-size, so the cap has to
be byte-based; a block count cannot guarantee a fit.

What it buys:

* **One "did it land?" question per round** instead of N, so the bookkeeping lag
  that Approach E accepts is bounded to a single message rather than growing with
  round progress.
* **No node creation mid-round.** A round creates at most one node, at its start,
  and appends to it immediately.
* **Less state to reason about**, which is worth more here than any single fix:
  most of the case analysis in this document exists because a round has interior
  states.

It does **not** make `index < offset` unreachable, and it should not be sold that
way. A round whose append landed but whose removal did not leaves
`num_archived_blocks` one message behind; if the next round then rolls over to a
new node, that node's offset is again ahead of the index being sent. E1's offset
check and E2's coverage guard remain the things that make this safe. F narrows the
window and bounds the waste.

**Throughput is not a concern.** ICP mainnet is `trigger_threshold: 2000,
num_blocks_to_archive: 1000` (`icp/src/lib.rs:623-624`), and 1000 blocks is two
chunks at 128 kB — so a single-message round archives roughly 500 blocks. Rounds
fire per transaction while accumulation is one block per transaction, so net drain
goes from ~999 to ~499 blocks per transaction: a factor of two on a ~500× margin.
Backlog drain is equally unaffected, being only 2× better today and equally slow.

**The real cost is one extra call per message, and `at_capacity` removes it.**
Today a 1000-block ICP round is one `remaining_capacity` plus two appends. Split
into two rounds it becomes 2 x (1 + 1) = four calls. But an append that reports
`at_capacity = false` has already told the ledger the node has room, so the
pre-call is only needed on a cold start or right after a spawn — which puts the
steady-state count *below* today's. This is why F follows E rather than standing
alone.

**It converges with DEFI-1666.** 2 MB messages fit ~5000 blocks, which is exactly
DEFI-1666's proposed `num_blocks_to_archive = 5000`, so that change makes
single-message rounds the natural configuration rather than a constraint.

Cap the selection rather than selecting `num_blocks_to_archive` and sending a
prefix: capping keeps the configured value honest, and makes the effective
per-round count something to expose as a metric — the same "report the enforced
value, not the configured one" point as DEFI-1565.

### Not worth chasing: up-front allocation

Making response handling infallible cannot be completed at the ledger level. The
irreducible allocation in a callback is the **reply buffer** — ic-cdk materialises
the response bytes into its own `Vec`, and there is no API to hand it a
pre-allocated one, so this would need a CDK change rather than a ledger change.

With addressed appends it does not need to be: a trap in response handling stops
being harmful, because the retry is idempotent. Rather than making the post-commit
region infallible, make it irrelevant. Keep the cheap parts — pre-reserving what
the ledger itself allocates, no `format!` in callbacks — as hygiene rather than as
a safety mechanism.

## Why not the alternatives

Options considered and set aside. Several were rejected only because they assumed
the interface could not change; E lifts that constraint and makes the idempotency
option in this list the mechanism rather than a dead end.


* **A typed error return on its own**, `append_blocks : (vec blob) -> (opt
  append_error)`, so the ledger could branch on the failure cause without adding
  an index argument. Subsumed by E rather than rejected: E's `opt append_result`
  is that return value, and its `Gap` variant is a typed cause. E deliberately
  does not type *every* cause: capacity is reported as a short position plus
  `at_capacity` because the ledger's action differs, while a chain mismatch keeps
  trapping and is diagnosed through C1. Decision 5 gives the reasoning.
* **String-matching the reject message.** Works today, depends on replica
  message formatting and CDK version, and cannot be tested against future
  changes. Rejected.
* **Making `append_blocks` idempotent (skip duplicates).** Leaves the ledger's
  `heights.1 += chunk_len` counting what it *sent*, not what was stored, so it
  over-advances: with chunk 1's range recorded and chunk 2's lost, a re-send
  walks the range to (0,2999) for an archive holding 0..1999, and reads for
  2000..2999 route to an archive that has nothing. Would additionally need the
  ledger to learn the archive's true position rather than infer it. E does exactly
  that, which is why idempotency stops being a dead end and becomes the
  mechanism.
* **Reconciling from `log_length`.** `icrc3_get_blocks` already returns it
  (`icrc1/archive/src/main.rs:387`), so the ledger could read the archive's true
  block count and repair its ranges. Superseded by E, which has the archive report
  its position on every append rather than the ledger polling for it — no extra
  round trip, and nothing to forget. Repair would also have needed a new
  block-count endpoint on the ICP archive, which E does not. Repair remains the only
  way to fix a ledger that has *already* diverged — see *Repairing a mis-indexed
  archive* for what that would take. Judged not to apply — not
  because the divergence is impossible (ICP rounds are multi-chunk today, and node
  roll-over opens the window on both ledgers), but because it has never been observed and DEFI-2967 could not
  induce the trap even deliberately.

## The road not taken: let the archive pull

The most fundamental option inverts the direction. The archive would own its
position, the ledger would serve blocks and drop those below the archive's
reported point, and the transaction path would have no archiving commit point at
all — R-1, R-2 and R-3 all dissolve.

But it trades the ledger's commit-point problem for the index's timer-fragility
problem, and DEFI-2983 is exactly that failure: a one-shot timer chain that
stopped re-arming and went unnoticed for hours. Not worth taking without a much
better story for timer liveness.

## Acceptance criteria

1. An ICRC archive rejects an `append_blocks` whose first block does not
   continue its stored chain, and its stored log is unchanged afterwards.
2. An empty ICRC archive accepts its first append when that append starts at the
   index the archive was created for, and refuses it otherwise. It has no tip to
   compare against, so the chain check cannot help; the offset is the only thing
   that can be checked, and it must be, because an empty node that accepts the
   wrong blocks is mis-indexed for the life of that node, absent the repair path.
3. A re-send after a lost ledger continuation is refused rather than stored, so
   no archive ever holds the same block twice and no index resolves to the
   wrong block.
4. The refusal is visible on the archive's `/metrics`, distinguishable from a
   capacity refusal.
5. The ledger treats the refusal as an ordinary archiving failure: it counts it
   in `ledger_archiving_failures`, removes no blocks, releases the archiving
   lock, and replies to the triggering transaction normally.
6. A ledger whose archiving keeps failing does not attempt it on every
   transaction; attempts are spaced by a growing interval up to a cap.
7. Archiving resumes without operator action once a transient cause clears.
8. Re-sending blocks an archive already holds is a no-op that reports the
   archive's position, and the ledger reconciles from it rather than incrementing
   — so a lost acknowledgement costs a round trip and nothing else. An append
   whose start index is beyond the archive's position is refused as a gap.
9. A new node's `block_index_offset` is always derived from ranges that were
   reconciled against the archive, so it is never taken from stale state. If
   `num_archived_blocks` lags after a round dies, reads remain correct and the
   next completed round corrects it; the only cost is re-sending chunks the
   archive then discards.
10. An append that stores only part of a chunk reports the position it reached.
   With `at_capacity` set the ledger spawns the next node; without it the ledger
   retries the same node under B. Neither traps, and no stored block is discarded.
11. An append whose index is below the tail node's offset is refused, and the
   ledger advances only if an earlier node's range covers the skipped span —
   otherwise it halts with a distinct metric rather than dropping the blocks. The
   advance is applied by `archive_blocks`, from a count the round returns.
12. A round issues exactly one `append_blocks`, and creates at most one node,
   at its start.
13. The ICP archive is unchanged. The ICP *ledger* does change: B1-B3, D1-D4, E2,
   E3 and F apply to both ledgers, so the backoff, the creation counter, the
   allocation work, the reconciliation and the single-message round are shared;
   the indexed protocol itself is ICRC-only until the ICP archive grows one
   (Decision 3).

## Components

| # | Component | Where | Notes |
|---|---|---|---|
| A1 | tip hash + parent comparison, trap on mismatch | `icrc1/archive/src/main.rs` `append_blocks` | separate crate from `ic-icp-archive`; no shared code |
| B1 | last-attempt timestamp + consecutive-failure count | `ledger_canister_core::archive::Archive` | `#[serde(skip)]` so an upgrade resets it |
| B2 | skip the round while backing off | `ledger_canister_core::ledger::blocks_to_archive` | before the guard is taken, so it costs nothing |
| B3 | backoff schedule constants | `ledger_canister_core::archive` | |
| C1 | counters for the causes that stay traps — chain mismatch, and a platform-refused memory growth counted separately | `icrc1/archive/src/main.rs` `encode_metrics` | a capacity *stop* is no longer a refusal under E1; it is reported in the reply, so what remains here is the mismatch plus the growth refusal as a diagnostic |
| D1 | in-flight archive-creation counter; halt archiving while it is non-zero | `ledger_canister_core::archive`, checked in `blocks_to_archive`, exposed as a per-ledger metric | `+1` before `create_canister`, `-1` on a graceful `Err` from any creation step, `-1` when `nodes.push` succeeds. A trap skips the decrement, so a non-zero value means a creation was begun and never accounted for. `#[serde(skip)]`, so it is per-epoch and needs no baseline |
| D2 | stop copying the archive wasm after a commit point | `ledger_canister_core::spawn::install_code` signature, `archive.rs` | `install_code` takes `Vec<u8>`, forcing `archive_wasm().into_owned()`, and `Rt::call` then serialises it again — two multi-MB copies in the continuation after `create_canister` committed. Take `Cow<'static, [u8]>`, pre-reserve the encode buffer before the first await, and `nodes.reserve(1)` |
| D3 | correct the stale comment at `archive.rs:468-474` | `ledger_canister_core::archive` | it says a panic there "leads to the rolling back of the transaction that triggered the archiving", which stopped being true when archiving was spawned |
| D4 | make error construction allocation-free, and trim the interpolating log lines | `ledger_canister_core::archive`, `::spawn` | `FailedToArchiveBlocks(pub String)` allocates on every error construction, so an allocation failure there turns a graceful `Err` into a trap: replace it with an enum carrying `Copy` payloads, rendered to text only where it is logged. `Rt::print` takes `impl AsRef<str>`, so non-interpolating messages become `&'static str` for free. **Keep** the canister id in the `create_canister` callback log — canister logs survive traps — verified, `test_appending_logs_in_trapped_update_call` in `rs/execution_environment/tests/canister_logging.rs` asserts the pre-trap `debug_print` persists *and* that the trap gets its own record — so it is the only possible record of an orphan's identity (D1 says one happened, this says which) — but drop the `{result:?}` debug format, which also stringifies the reject message. `reject_message()` borrows a `String` ic-cdk has already allocated, so only our second copy is avoidable |
| E1 | `append_blocks` takes an optional expected start index and returns an optional result carrying the archive's next expected global index plus `at_capacity`, or a gap. Four-way placement of the index against `offset`/`offset + log_length`; capacity reported rather than trapped; chain mismatch still traps | `icrc1/archive/src/main.rs`, `archive.did`, `ledger_canister_core::archive::send_blocks_to_archive` | the only interface change; both `opt`, so tolerant in either direction. Verify with `didc` and the CI Candid check |
| E2 | the ledger reconciles `nodes_block_ranges` from the reported index instead of incrementing, and treats a covered index as success. The coverage guard *detects* here and reports upward — the round returns a count that includes blocks an archive already held, and `archive_blocks` performs the removal, so the module boundary is not redrawn (Decision 6) | `ledger_canister_core::archive::send_blocks_to_archive`, return type consumed by `ledger::archive_blocks` | shared code, so it applies to both ledgers once their archives are upgraded; the incremental path stays as the fallback for archives that return nothing |
| E3 | count every use of the incremental fallback | `ledger_canister_core::archive` + per-ledger metric | the path's problem is an unknowable lifetime; a counter makes it deletable once it reads zero everywhere |
| F1 | cap the round's selection at `min(num_blocks_to_archive, one message)` in bytes, and delete both loops in `send_blocks_to_archive` | `ledger_canister_core::ledger::get_blocks_for_archiving`, `::archive::send_blocks_to_archive` | removes code; the byte-based cap is what makes it correct for variable-size blocks. Both terms are known locally, so selection stays before the first await; `take_prefix(remaining_capacity)` still trims, so a roll-over round is short. Expose the effective per-round count as a metric |
| F2 | skip the `remaining_capacity` pre-call when the last append reported `at_capacity = false` | `ledger_canister_core::archive::node_and_capacity` | depends on E1; this is what makes F cheaper than today rather than dearer |

A1, C1 and E1 are in `ic-icrc1-archive`. B1-B3, D1-D4, E2, E3, F1 and F2 are in
shared ledger code and therefore affect both ledgers; see Decision 3.

## Edge cases

* **Empty archive.** No tip, so the chain check cannot fire. It has nothing to
  duplicate, but it *can* be mis-indexed: a node created for index X that is later
  handed blocks starting at Y < X stays wrong for as long as the offset does, and
  nothing deployed can change it. So an empty archive must check the offset even though it cannot check
  the chain — which under E it can, since the append carries the index it is
  expected to start at. See the multi-node case under *How a round dies*.
* **Genesis.** Block 0's `parent_hash` is `None`; an empty archive accepting it
  is the normal path.
* **New node mid-round.** After the first append the node has a tip, so a
  re-send to it is caught.
* **Multi-chunk round.** Chunk 2's first block must continue chunk 1's last, so
  the check holds within a round as well as across rounds. F removes the case
  from our own ledgers, but not from a third-party ledger that has not adopted it,
  so the check must still hold.
* **A round that rolls over to a new node.** Under F this is one node creation
  plus one append, and the node's offset is derived from ranges reconciled in the
  previous round. If that previous round's removal was lost, the offset is ahead
  of `num_archived_blocks` and E1's offset check fires — see the coverage guard.
* **Partial append.** The archive stored some blocks and reports a short position.
  The ledger must reconcile to the reported position, not to what it sent, and
  must consult `at_capacity` before deciding whether to spawn.
* **Deployed archives.** The check only applies to archives running the new
  wasm; see Rollout.
* **Undecodable first block.** The archive must not trap on a decode failure in
  a way that is indistinguishable from a mismatch; treat separately.
* **u64 vs u256 archives.** Both variants need the check and the test.

## Residual failure modes after this spec

Every inter-canister call allocates a buffer for its reply, in the callback
message. That allocation cannot be removed, so each call is a place where the
ledger can trap with everything from earlier messages already committed. With
A through F applied:

| allocation | already committed | consequence | severity |
|---|---|---|---|
| `create_canister` reply | canister exists, cycles gone | orphan; the id was never learned, and a canister cannot enumerate what it controls. D1 detects it and halts archiving | leak, irreducible; detected |
| `install_code` reply | + wasm installed | orphan, installed. Same detection and halt via D1 | leak; detected |
| `update_settings` reply | + controllers replaced | orphan, installed, controllers replaced. Same detection and halt via D1 | leak; detected |
| `remaining_capacity` reply, existing node | the transaction, which already replied | round skipped, next attempt spaced by B | benign |
| `remaining_capacity` reply, new node | + node recorded in `archive.nodes` | round skipped; next round finds the node and proceeds | benign, self-heals |
| `append_blocks` reply | the archive holds the blocks | under E the re-send is idempotent: the archive recognises the index it already covers, replies with its position, and the ledger reconciles. Self-healing | none |

All three orphan windows sit between `create_canister` committing and
`nodes.push` committing, so D1's single non-zero check covers all of them. That
is why resumable creation is not needed: it would recover rows two and three,
but detection plus a halt is the proportionate response given how rare archive
creation is.

Note what the orphan's cycles cost. In the `create_canister` and `install_code`
windows the orphan's only controller is the *ledger*, because `update_settings`
has not run, and the ledger does not know the id. Reclaiming those cycles would
need a ledger-side admin path that does not exist, so the ~10 T is realistically
written off and the cleanup is bookkeeping.

D1 also gives the split we wanted without any interface change: a **structural**
failure halts and waits for an operator, while **transient** failures keep
backing off under B. The ledger distinguishes them from its own state rather
than from the failure, so no reject-string matching and no typed return value.

A calibration note on D4 and its kin: these are tens to hundreds of bytes, and
a small allocation only fails once the heap is already at the wall — where the
irreducible reply buffer allocated moments earlier in the same callback would
very likely have failed too. So trimming them barely moves the failure
probability. D2 is different in kind (megabytes, reliably forces a `memory.grow`),
and the error-enum half of D4 is different in kind too: it is not about
probability but about keeping graceful failures graceful. The static log lines are
free, so worth doing, but expect nothing from them.

Continuation B's post-commit allocations are an interpolating `log!` and the
`nodes_block_ranges` update, which E keeps where it is — reconciled from the
reported position rather than incremented. A neutralises the duplicate
consequence and E the offset one, so shrinking that window is hygiene rather than
a fix.

Two notes that apply throughout:

* **Error strings are not allocation-free.** `FailedToArchiveBlocks(format!(...))`
  allocates on the failure branch, so under memory pressure a call that failed
  cleanly and would have returned `Err` traps instead. The outcome is nearly the
  same — the guard is released and the failure counted through the cleanup
  callback rather than the graceful increment — but the graceful paths degrade
  into the trap paths exactly when it matters most.
* **All of it depends on the cleanup callback surviving.** Every "guard released,
  failure counted" above runs during task cancellation. If that traps, neither
  happens. It is deliberately limited to flipping a bool and incrementing a
  `u64` for that reason.

## Rollout

The whole ledger suite is upgraded together, in the order index, ledger,
archives. Two releases rolled out one after another are available if a change
ever makes a (new ledger, old archive) pair unacceptable.

A through D change no wire format, and neither does F; **E does**, and is the
reason the split matters here:

* **A** is confined to the archive. A new archive facing an *old* ledger sees
  ordinary contiguous appends and passes; on a re-send it refuses, and the old
  ledger already handles a rejected `append_blocks` on its existing `Err` path.
  A new ledger facing an *old* archive is unaffected, because A changes nothing
  in the ledger.
* **C** is additive to the archive's `/metrics`.
* **B**, **D** and **F** are ledger-internal: state, allocation behaviour and
  round sizing. An old archive neither knows nor cares — F1 stands alone, while F2
  is inert until the archive answers.
* **E** adds an optional argument and an optional result to `append_blocks`. Both
  are `opt`, so an old archive ignores the argument and returns nothing, which a
  new ledger reads as `null` and falls back to its current incremental behaviour.
  That tolerance is what makes the order irrelevant — but it also means the
  fallback path has to stay for as long as un-upgraded archives exist, which for
  third-party ICRC ledgers is indefinitely. Verify the Candid compatibility with
  `didc` and the CI check rather than relying on this paragraph.

### Two releases, both in the standard order

Do not reorder the suite. Split instead, so that each release is safe in the
normal index-ledger-archives sequence:

* **Release 1 — archive only.** A, C and the archive half of E: the chain check,
  the refusal metric, and `append_blocks` accepting the optional index and
  returning the optional result. The ledger is unchanged, so it neither sends the
  index nor reads the result. After this release every archive in our suites
  speaks the protocol, and the corruption is closed.
* **Release 2 — ledger.** B, D, F and the ledger half of E: sending the index,
  reconciling from the reported position, the single-message round, the backoff
  and the creation counter. By now the archives it talks to already answer, so the
  fallback path is never exercised in our deployments.

The `opt` tolerance is still worth having, but for third parties rather than for
us: an operator who upgrades only the ledger gets the incremental fallback rather
than a failure.

**Detecting an old archive.** The ledger can tell, from the reply: an archive that
returns nothing decodes as `null`. That is after the append rather than before,
which is harmless, since an old archive still stores the blocks — it just cannot
say where it is. Detecting it beforehand is not practical: `remaining_capacity`
and `icrc3_get_blocks` both exist on old archives so neither discriminates, and
`canister_status` would give the module hash but needs controller rights the
ledger does not have, since `update_settings` hands the archive to NNS Root.

Only the **last** archive matters. `node_and_capacity` appends only to
`nodes.last()`, so a full archive is never written to again and its version is
irrelevant; and a newly spawned node runs the Wasm the ledger embeds, so it
necessarily speaks the protocol. The requirement is therefore "the current tail
archive is upgraded", which one node rollover satisfies permanently.

### What the fallback actually is

Worth being precise, because "falls back to the incremental behaviour" is easy to
read as a lesser mode when it is really the present one.

**Mechanically** it is today's code, unchanged: no position was reported, so the
ledger cannot reconcile, and it advances `heights.1 += chunk_len` and calls
`remove_archived_blocks(num_sent_blocks)` exactly as it does now.

**In terms of guarantees it offers none of the new ones.** A pre-release-1 archive
has neither the index check nor the chain check, so against it a duplicate append
can still be stored and a new node's offset can still be poisoned.

**But it is not a regression.** A ledger talking to an un-upgraded archive is left
exactly where it is today — no worse, simply not yet better. The improvement
arrives when the archive is upgraded, and until then nothing has been taken away.

Two consequences:

* **Count every use of it.** The objection to keeping the path is not that it
  exists but that its lifetime is unknowable; a counter makes it observable, so
  the path can be deleted once it reads zero everywhere. This is worth doing
  regardless of anything else here.
* **The fallback keeps the old exposure.** Writing both values together needs a
  reported position, and an un-upgraded archive supplies none, so on that path the
  ledger is back to inferring, with the divergence and the duplicate storage that
  implies. Nothing available to the ledger alone fixes that, which is the argument
  for not carrying the path at all.

### If the fallback's lifetime is judged too long to carry

**Halt and wait.** Probe the tail archive with an **empty** `append_blocks` before
committing to a round. One that answers reports its next expected index; one that
returns nothing is un-upgraded, and the ledger then archives nothing and
accumulates locally until it is upgraded. This is what lets the incremental path be
deleted outright.

The probe is what makes this coherent. Detection from a *real* append is post-hoc
— an old archive has already stored the blocks by the time it answers `null` — so
without a cheap probe the retry would itself be a full archiving round, taking the
very risk the halt exists to avoid. An empty append is accepted, stores nothing and
consumes no capacity: verified by
`test_empty_append_blocks_is_accepted_and_stores_nothing`.

Cache the answer in `#[serde(skip)]` state so the probe is not repeated every
round. That also removes any need for a manually flipped flag: the cache clears on
every ledger upgrade, which is precisely when the archives were upgraded too, so
the ledger re-probes at the only moment the answer could have changed, and resumes
on its own.

The cost is stable-memory growth while waiting — the same degraded mode two ck
ledgers are running deliberately today, and cheaper than it looks, since resident
blocks do not drive upgrade instruction cost — plus a dependency on operators
upgrading their archives, so the halt needs its own metric rather than hiding in
the generic failure counter.

**Not recommended: rolling over to a fresh node.** A `null`-answering tail could
be treated as unusable and a new node spawned, which speaks the protocol by
construction — no waiting and no fallback path. Rejected because the costs are
not one-off: spawning charges canister creation and needs cycles provisioned for
it, and every extra archive is then another canister to keep topped up and to
upgrade forever. It also abandons the old tail's unused capacity, up to 3 GiB of
already-paid-for space. Doing this automatically, in response to a version
mismatch, is a poor trade for what it buys.

## Testing strategy

The goal is a failing test per issue on the current baseline, passing after the
fix. Note the baseline is the **DEFI-2967 branch**, not `master`: on `master`
archiving is awaited, so a trap in a continuation rejects the transaction and the
observable behaviour differs. For A1 the archive behaves identically on both, so
that one test is baseline-independent.

| # | issue | test | deterministic? |
|---|---|---|---|
| 1 | A1 — archive accepts a duplicate append, then serves the wrong block for an index | archive-level: append a valid range, re-append the same blocks, assert refusal and unchanged `log_length`, then assert `icrc3_get_blocks` resolves every index correctly | **yes** — no trap needed, pure archive behaviour |
| 2 | D1 — a trapped creation leaves an orphan and archiving keeps going | reuse the existing atomicity harness, which already induces a creation-round trap (`archiving_recovers_after_a_trapped_attempt` asserts no archive appeared), and additionally assert the in-flight counter is non-zero and that archiving is halted | **yes** — the trigger is already reproducible |
| 3 | B — archiving is retried on every transaction | stop the archive canister so `remaining_capacity` is rejected, generate transactions, count attempts over a window, then restart and assert archiving resumes | **yes** — a stopped canister gives repeatable graceful failures |
| 4 | E1/E2 — a node whose offset is ahead of the index being sent | **archive-level**: install a node with `block_index_offset = N+1000`, append starting at `N`, assert refusal and unchanged `log_length`. Then a **unit test in `ledger_canister_core`** for the coverage guard: with ranges covering the skipped span, assert the ledger advances and continues; with the span uncovered, assert it halts and increments the distinct metric | **yes** — no trap needed; the offset is an install argument |
| 5 | D2 — the creation round's post-commit allocation | measure ledger memory across an archive-creation round, as `routine_archiving_does_not_grow_the_ledger` already does for a routine round; assert the growth is below a bound after D2 | yes, as a measurement |
| 6 | E1 — a partial append reports its true position rather than trapping | archive-level: configure `max_memory_size_bytes` so a chunk only partly fits, append it, assert `Ok` with a short `next_index`, `at_capacity = true`, and that the blocks that fit are readable | **yes** — the archive's own limit is configurable at `init` |
| 7 | F1 — a round issues one append and creates at most one node | count `append_blocks` calls per round against a configuration that is multi-chunk today; assert one, and assert the effective per-round count metric matches | **yes** |
| 8 | both token variants for (1), (4) and (6) | | yes |

Two things deliberately not attempted:

* **The duplicate-append and offset-divergence paths end-to-end**, by inducing a
  trap in the append continuation.
  Routine rounds grow ledger memory by zero bytes, which is why DEFI-2967 records
  "I could not make that trap". A multi-chunk configuration with large chunks
  would make the per-chunk Candid encode big enough for the reserved-cycles
  trick to bite, so it is probably reachable — but it depends on allocator
  behaviour and would likely be flaky. Test 4 covers the same arithmetic
  deterministically at the unit level, which is where the bug actually lives.
* **D3** is a comment, and the part of **D4** that matters (graceful failures
  staying graceful under allocation pressure) cannot be provoked reliably for the
  same reason.

## Decisions

1. **Backoff schedule:** start at 30 s, double on each consecutive failure, cap
   at 1 h. A transient cause recovers within a minute; a permanent one costs one
   probe per hour.
2. **Backoff state:** `#[serde(skip)]` on `Archive`, so an upgrade resets it.
   This matches `archiving_in_progress`, and makes an upgrade the operator's
   "resume now" lever, which is the right shape when the upgrade is usually the
   fix.
3. **The shared components apply to both ledgers, with no trait seam.** B1-B3,
   D1-D4, E2 and E3 stay in shared code: the wasteful per-transaction retry, the
   lost-creation window and the inferred bookkeeping all exist on both ledgers
   today, so fixing them fixes both. A seam introduced only to keep the ICP ledger
   on the old behaviour would be a layer with no beneficiary. A1, C1 and E1 are
   ICRC-only regardless, since `ic-icrc1-archive` and `ic-icp-archive` are
   separate crates — so the ICP ledger gains the ledger-side fixes but not the
   indexed protocol until its own archive grows one.
4. **The typed result is part of E, not deferred.** It is what lets the ledger
   distinguish a duplicate (success) from a gap (halt) without inspecting reject
   strings, and it is how the archive reports its position. An un-upgraded archive
   returns none of this, which is the whole of what the fallback path gives up.
5. **Capacity is reported; a chain mismatch still traps.** The two are not
   symmetric. A capacity stop has real progress to preserve and two causes needing
   opposite responses, so it belongs in the reply as a short `next_index` plus
   `at_capacity`. A mismatch has nothing to preserve, no distinct ledger action,
   and — given E's index check — cannot happen on a correctly addressed append; a
   trap is the right response to an invariant violation, and it is enforced by the
   platform rather than by review. If capacity later needs its own variant it can
   be added without changing what `Ok` means; a typed mismatch would leave us
   maintaining a handler for an impossible state.
6. **Accept the re-send; do not redraw the module boundary.** A trapped round
   re-sends chunks the archive then discards. That is cheaper than giving
   `send_blocks_to_archive` ledger access, the divergence it leaves is benign (see
   *Why the two halves commit at different times*), and F bounds the waste to a
   single message.
7. **The ICP archive is deferred, and this is the plan's main gap — not a
   limitation of it.** E1 lives in `ic-icrc1-archive`, so the ICP ledger never
   receives a reported position, E2's reconciliation never engages, and it stays
   permanently on the incremental path. R-1 and R-2 therefore remain open on the
   ledger that has *both* windows open today.

   There is no cheap partial. Porting A1 alone catches the variant where the new
   node already has a tip, but the silent-corruption variant is the **empty** node,
   which has no tip to compare against — closing that needs the offset check, which
   needs the index, which is the interface change. So ICP needs the whole of E1
   against `ic-icp-archive`, plus its Candid and a second archive release.

   Deferring is defensible — ICRC carries the two ck suites that prompted this, and
   the work is mechanically the same in a second crate — but it must be a tracked
   follow-up with its own ticket, not a line in an open-items list. Whoever
   approves this spec is approving that ICP stays exposed until that lands.

## Precondition: verify the live suites with Rosetta

**Do this first, before building anything here.** Nothing in this spec repairs a
suite that has *already* diverged — E prevents further damage, but a mis-indexed
node cannot be corrected by anything deployed today, and the repair path below
needs new code on both sides plus a hand-computed value. So whether it has already happened is not an open question to
carry alongside the work: the answer reorders the work. It is also cheap.

Whether a divergence has already happened is answerable today, with no new tooling.
The ICRC Rosetta synchroniser performs exactly this audit while syncing from
genesis, and checks both halves independently
(`rosetta-api/icrc1/src/ledger_blocks_synchronization/blocks_synchronizer.rs`):

* `blocks_verifier::indices_are_valid` asserts the indices returned match those
  requested — with the comment "Block Indices are not part of the block hash",
  which is precisely the mis-indexing this spec is about.
* the parent hash of the lowest block fetched must equal the hash of the highest
  block already stored, or it bails with "Hash of block N in database does not
  match parent hash of fetched block N+1".

`derive_synchronization_gaps` additionally refuses a store with more than one gap.
Because the ledger routes reads through to its archives, a full sync walks the
whole chain across every node and would surface a duplicated or mis-indexed range
as a hash or index mismatch. So a clean Rosetta sync from genesis on ckBTC, ckDOGE
and ICP *is* the verification.

## Repairing a mis-indexed archive

Worth writing down, because the plan's value changes if a divergence is found and
"unrecoverable" would be the wrong conclusion.

**The property that makes the corruption total also makes it repairable.** The
offset maps global to local by a single subtraction — `start -
opts.block_index_offset` (`icrc1/archive/src/main.rs:280`) — so a node storing the
right blocks under the wrong label is off by one constant everywhere. Setting that
constant correctly fixes the whole node at once.

Work through the worked case. Node 1 has offset `N+1000` but its local 0 holds
block `N`, so local `k` holds block `N+k`. Rewrite the offset to `N` and every
index in the node resolves correctly — not just the first thousand. The cost is
that node 0's tail also holds `N..N+999`, so the two nodes overlap by a thousand
blocks; that space is wasted, but reads resolve as long as the ledger's ranges are
corrected to hand `N..` to node 1.

So a repair is **two coordinated changes**, and neither exists:

| | change | why it is needed |
|---|---|---|
| archive | `post_upgrade` takes an optional `block_index_offset` and writes the stable cell | the offset is the corrupted value |
| ledger | a migration or admin path that rewrites `nodes_block_ranges` | otherwise reads still route by the stale ranges |

**Treat it as a break-glass tool, not a feature.** Writing an offset on a healthy
archive corrupts it in exactly the way this spec exists to prevent, and the archive
cannot validate the new value — it has no access to the previous node's tip, so
there is nothing to check it against. The safety rests entirely on the operator
computing it correctly, which argues for building it only if the precondition
actually finds a divergence, and for gating it behind an NNS proposal with the
computed value in the summary.

Note the asymmetry it exposes in the current code: the **read** path already
enforces this boundary, rejecting a `start` below the offset
(`icrc1/archive/src/main.rs:274-277`). Only the **write** path lacks the check, so
E1 is restoring a symmetry rather than introducing a concept.

## Remaining open items

Two, both narrow. The ICP archive is Decision 7 rather than an open item, and the
already-diverged question is the precondition above.

1. **Block removal's instruction cost is unmeasured.** `remove_archived_blocks`
   loops `pop_first()` once per block, and it is listed as a trap source on
   assumption rather than measurement. F makes each round's removal smaller, which
   helps, but the number is still worth having, and canbench already measures this
   class of thing.
2. **Genuine subnet exhaustion is not recoverable by anything here.** The archive
   cannot grow, and the ledger cannot grow to hold the backlog either. What E
   delivers is that the failure becomes a clean, loud stall on the same node
   instead of a corrupting one, and that each attempt banks the blocks that did
   fit. It does not make archiving proceed — and since this is what actually
   caused the 2026-09-01 incident, note where the answer does live: capacity and
   reservation headroom, i.e. the drafted `memory_allocation` proposals for the ck
   suites, not this spec.

## Adjacent: make the ledger suite's logs readable

Trapped archiving leaves the ledger's own `debug_print` output, a `[TRAP]`
record and a backtrace in the canister log — exactly the evidence DEFI-2967
records as unobtainable for 2026-09-01. It is unreadable today only because
`log_visibility` defaults to `Controllers` and the controller is NNS Root.

The NNS `UpdateCanisterSettings` action already supports the field
(`nns/governance/api/src/types.rs:2743`, validated in
`proposals/update_canister_settings.rs:47-52`), so one proposal would open it.
Two caveats: the action maps only `Controllers` and `Public`, so
`AllowedViewers` is not reachable that way; and the store is a bounded ring
buffer, so it is a recent window rather than an archive. Worth reading what the
ledgers actually emit before proposing `Public`, since the output includes
account principals and amounts.

Pairs naturally with the drafted memory-allocation proposals, which are the same
NNS action.

## Design notes

Reasoning worth keeping, on points that are settled but easy to re-litigate.

* **`spawn` is the correct CDK primitive here, and better than `spawn_migratory`.**
  `ic_cdk::futures::spawn` is the *protected* variant, documented as "canceled if
  the method returns before they complete", which looks wrong for a task designed
  to outlive its method. It is not: cancellation is refcounted, not tied to the
  Rust future resolving. `enter_current_method`
  (`ic-cdk-executor/src/machinery.rs`) cancels attached tasks only when the
  method's `MethodHandle` count reaches zero, and a handle is taken before every
  inter-canister call and threaded through its callback. A task blocked on a call
  therefore keeps its method context alive, and the chain of calls keeps the count
  above zero until archiving finishes. "Returns" means "the body finished *and*
  every outstanding call completed".

  Protected is also preferable: if the context ever did die with the task pending,
  `ProtectedTask`'s `PinnedDrop` panics, so it surfaces. `spawn_weak` drops
  silently, and `spawn_migratory` is unattached — which sounds more robust but
  removes both the attachment and the alarm, and the archiving chain has no need
  to migrate because every await is its own call.

  **Invariant this creates:** every await in the archiving chain must be an
  inter-canister call. Awaiting anything a call does not wake — a timer, a channel
  — drops the refcount to zero, cancels the task and trips the panic. A second,
  independent reason not to make archiving timer-driven, and worth a comment at
  `spawn_archiving` so nobody later adds a delay inside the task.

* **Gap versus duplicate needs no distinguishing.** A refusal could in principle
  mean either of two things with opposite severity: a *duplicate*, where the
  ledger's bookkeeping has fallen behind what the archive holds and nothing is
  lost; or a *gap*, where blocks between the archive's tip and the ledger's next
  send are stored nowhere. Telling them apart at the archive is impossible,
  because `append_blocks` carries no index and the archive cannot know which side
  of its tip the sender believes it is on.

  E makes the question moot at the archive, by answering it there. The index says
  which side of the tip the sender believes it is on, so the archive replies
  `Gap` or a covered-index success instead of the ledger having to guess. What
  remains for C1 is the chain mismatch, which under E is an invariant violation
  rather than an ambiguous refusal — so its single counter still says all there
  is to say.
