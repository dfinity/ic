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
| **4** | **F** — commit the round's bookkeeping atomically | ledger-only, and the one thing that also protects the fallback path against an un-upgraded archive |

D2-D4 are hygiene and can land whenever.

**E is the substantive one.** It makes retries idempotent, so the whole family of
lost-acknowledgement problems stops mattering rather than each being guarded
separately. It is the only part that touches the ledger-to-archive interface,
which the two-release split makes safe. **F** is not an alternative to it: E fixes
the protocol and so only helps against an upgraded archive, while F fixes the
ledger's own consistency and therefore also covers the fallback path. Taking both
is the recommendation; if only one, take E.

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
* **Afterwards, by asking the archive — yes.** Which is why `log_length` matters,
  and why the addressed-appends alternative below is the clean fix: the
  acknowledgement carries the state, so there is nothing to forget.

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

The divergence needs a **multi-chunk round**, and the two ledgers are configured
very differently:

The chunk size is `min(archive.max_message_size_bytes, max_ledger_msg_size_bytes)`
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

So **the window is open today, on the ICP ledger**, whose rounds are already
two-chunk. It is not a future risk. That is the main reason E belongs in this
change rather than a later one — and note the ICP ledger is precisely the one a
*repair*-based fix could not have reached, since the ICP archive exposes no block
count.

**DEFI-1666 would narrow this window, not widen it.** Its proposed
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
  global N+1000 returns block N. **Silent corruption, permanently**: the offset
  is written to a stable cell at `init` and the ICRC archive's `post_upgrade()`
  takes no arguments, so it can never be corrected.

Keeping the ledger's own bookkeeping consistent is not enough to close the second
case: it says nothing about a node whose offset was chosen for blocks it never
received. Closing it that way needs the offset recorded when the node is created,
so a later round can compare `nodes.last()`'s offset against its next index and
refuse a node that does not match — see F.

Giving appends an index closes it directly, because the first append carries its
start index and the archive either adopts it or rejects the mismatch. That is E.

The realistic trap sources in a round, once D2 has removed the wasm copies:

1. **The per-chunk `Encode!`** — up to one message-size of Candid serialisation,
   in the continuation after the previous append committed. The largest
   post-commit allocation in a multi-chunk round.
2. **The final message's instruction cost.** `remove_archived_blocks` loops
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
proposal the team makes routinely. Revisit if rounds stay multi-chunk — noting
that DEFI-1666 would reduce chunking, so landing it makes this *less* pressing
rather than more.

## Approach

Five parts, none of which changes a Candid interface. A and C are confined to the
ICRC archive; B, D and E are in shared ledger code and so apply to both ledgers.
A is shippable on its own and closes the corruption; the rest are independent of
each other.

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

| cause | transient? |
|---|---|
| `append_blocks` refused a memory growth (OutOfStorage / reserved cycles) | yes — cleared itself in ~4.5 h on 2026-09-01 |
| `remaining_capacity` rejected (archive stopped, frozen, upgrading) | yes |
| archive creation short of cycles | yes, after a top-up |
| `create_canister` / `install_code` / `update_settings` rejected | usually |
| `append_blocks` trapped "no space left" on the logical cap | semi — ledger should have created a new node |
| "empty chunk" (a block exceeds the chunk size) | no |
| **chain mismatch (new)** | **no** |

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

Why the ledger does not need it: **its correct response is the same for every
cause it can actually encounter** — keep the blocks it has no acknowledgement
for, count the failure, release the lock, back off. The two cases that would
warrant a different response are both detected without knowing the cause:

* a **lost archive creation** needs a halt rather than a backoff, and D1 detects
  that from the ledger's own in-flight counter;
* a **full archive** needs a new node, and `node_and_capacity` discovers that
  *before* appending, from the `remaining_capacity` pre-check, so in normal
  operation it never reaches the refusal path. The ledger asks for the remaining
  capacity and `take_prefix` takes only as many blocks as fit it, which is the
  same arithmetic the archive applies (`max_memory_size_bytes < log_size_bytes +
  bytes`). A capacity *refusal* therefore means the two disagreed, which should
  not happen — so distinguishing it has diagnostic value, not behavioural value.

So the cause is wanted for diagnosis, not control flow, and that is why neither
reject-string matching nor a typed return value is needed here.

**The claim above is a property of this design, not a general one.** "The ledger
does not need the cause" is true given A-E, because every cause it can encounter
calls for the same response. Under E
it is false: the archive there returns a typed result and the ledger acts on it —
a `Gap` halts, a duplicate counts as success. The two are not in conflict;
addressed appends create a distinction that A-E has no use for.

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
      Ok  : record { next_index : nat64 };
      Gap : record { expected : nat64; got : nat64 };
    };

    append_blocks : (vec blob, opt nat64) -> (opt append_result);

The second argument is the expected start index. The archive compares it against
the next global index it expects — `block_index_offset + log_length`, both of
which it knows — and decides with certainty:

| | meaning | action |
|---|---|---|
| equal | correct continuation | append, and report the new next index |
| less | already holds them | **no-op success** — this is the idempotency, not an error |
| greater | a gap | return `Gap`, having appended nothing |

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
* **F becomes redundant against an upgraded archive**, though not on the fallback
  path — see F below.
* **Resumability is free.** No advance-on-refusal rule, no persisted intent.
* **A1 is demoted** to a belt-and-braces check. Indexes verify *position*; the
  hash chain still verifies *content*, which catches a ledger that sends the
  right indexes with the wrong blocks. Cheap, so worth keeping.

### Companion: let the archive report its range

With appends reporting `log_length`, this is no longer needed in the steady
state — it remains useful for a cold start, or after a round that was lost
entirely before any append landed. An explicit `archive_range() -> (start, end)` the ledger *observes* instead of *deriving*, so
`nodes_block_ranges` becomes a refreshable cache rather than a mirror that can rot
unnoticed. It also gives the ICP ledger something it currently lacks; recall that
a repair-based fix was ICRC-only purely because the ICP archive exposes no count.

### Companion: one message per round, sized by bytes

The useful form of "remove chunking" is not a smaller block count but a different
sizing rule: **take as many blocks as fit one message**. Then a round is always
exactly one append, so there is one "did it land?" question instead of N, and E's
divergence cannot arise by construction. Blocks are variable-size, so this has to
be byte-based — a block count cannot guarantee a fit.

The enabler is DEFI-1666: today's 128 kB ICP cap is exactly why ICP rounds are
two-chunk, and raising it to 2 MB makes 1000-5000 blocks fit one message.

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

**F. The ledger's round bookkeeping commits atomically.** E fixes the
ledger-to-archive *protocol*, so it only helps against an archive that
understands it. F fixes the ledger's *internal* consistency, so it helps
regardless of what the archive supports — which is what makes it worth having
alongside E rather than instead of it. The divergence that
poisons a new node's offset exists only because two pieces of bookkeeping commit
in *different* messages: `nodes_block_ranges` per chunk, and
`remove_archived_blocks` once at the end. A trap between them leaves
`last_range_end + 1` disagreeing with `num_archived_blocks`, and a node created
afterwards takes its offset from the former:

    let node_block_height_offset: u64 = archive
        .nodes_block_ranges
        .last()
        .map(|(_, height_to)| *height_to + 1)
        .unwrap_or(0);

That offset is baked in at `init` and unchangeable, and A1 cannot catch the
result because a fresh node is empty and accepts its first append
unconditionally (acceptance criterion 2). So a diverged ledger permanently
mis-indexes a brand new archive.

Rather than detect and repair it, make it impossible:

* during the round, accumulate per-node counts in a **local** — it dies with the
  future on a trap, which is exactly what we want;
* derive a new node's offset from `num_archived_blocks + blocks sent so far this
  round`, which is the global index of the next block to be archived and is
  already available at the call site, instead of from the range bookkeeping;
* in the final message, apply the accumulated counts to `nodes_block_ranges`
  **and** call `remove_archived_blocks` together.

Then either both commit or neither, and they can never disagree. Two useful
consequences:

* **A gap becomes impossible.** `num_archived_blocks` advances only by
  acknowledged chunk counts, and the ranges advance by the same amounts, so
  neither can ever exceed what the archives actually hold. The gap-versus-
  duplicate classification that would have needed an extra probe is therefore
  moot.
* **No archive cooperation is required**, so this fixes the ICP ledger too. The
  bug is in shared code and the ICP archive has the identical baked-in
  `block_height_offset` (`icp/archive/src/main.rs`, `get_blocks` resolving via
  `from_offset..from_offset + blocks_len()`), so the ICP ledger was exposed as
  well; only the absence of a block-count endpoint there made a repair-based fix
  ICRC-only.

The surface is small: `nodes_block_ranges` has exactly two writers (the
per-chunk update in `send_blocks_to_archive`, the offset derivation in
`create_and_initialize_node_canister`) and one reader (`Archive::index()`, used
by `block_locations`). Mid-round the ledger simply claims every block locally,
which is correct because it has not removed any, and `index()` already tolerates
`nodes.len() > nodes_block_ranges.len()` because `nodes.push` and the first range
push are already in different messages today.

**Open: should the other refusal causes be returned rather than trapped?**
`append_result` currently types only the index comparison. A capacity refusal and
A1's chain mismatch still trap. Folding them in would be a modest improvement on
the same grounds as `Gap`: the archive decides before appending either way, so
atomicity is preserved, the reason becomes precise, and no work is wasted on a
message that traps. It would change A1 from trapping to returning, so acceptance
criterion 1 would need rewording — "refuses" rather than "traps". The ledger still
would not branch on them, so the gain is diagnostics and instructions rather than
control flow. Not decided.

**Scope, and why both.** Against an upgraded archive E already makes the ledger's
bookkeeping self-correcting, so F adds nothing there. F earns its keep on the
**fallback path** — an un-upgraded archive returns `null`, the ledger increments
as it does today, and the divergence is live again. F closes that without needing
anything from the archive.

So F's value is proportional to how long the fallback path lives: for our own
suites that is one release, so near-zero; for third-party ledgers on un-upgraded
archives, indefinitely. It is cheap and ledger-only, so the case for taking it is
that it costs little and covers the one path E cannot reach.

## Why not the alternatives

Options considered and set aside. Several were rejected only because they assumed
the interface could not change; E lifts that constraint and makes the idempotency
option in this list the mechanism rather than a dead end. Note that F, the
ledger-side atomicity, is *not* in this list — it is a component, not a rejected
alternative.


* **A typed error return on its own**, `append_blocks : (vec blob) -> (opt
  append_error)`, so the ledger could branch on the failure cause without adding
  an index argument. Subsumed by E rather than rejected: E's `opt append_result`
  is that return value, and its `Gap` variant is a typed cause. What E does *not*
  do is type every cause — a capacity refusal and a chain mismatch still trap, so
  they remain diagnosed through C's counter, and the ledger still does not branch
  on them. See the open question below about folding those into `append_result`
  too.
* **String-matching the reject message.** Works today, depends on replica
  message formatting and CDK version, and cannot be tested against future
  changes. Rejected.
* **Making `append_blocks` idempotent (skip duplicates).** Leaves the ledger's
  `heights.1 += chunk_len` counting what it *sent*, not what was stored, so it
  over-advances: with chunk 1's range recorded and chunk 2's lost, a re-send
  walks the range to (0,2999) for an archive holding 0..1999, and reads for
  2000..2999 route to an archive that has nothing. Would additionally need the
  ledger to derive the range from the archive's `log_length`. Note E removes the
  over-advance, so with E in place this option becomes viable — and under
  addressed appends it is the mechanism.
* **Reconciling from `log_length`.** `icrc3_get_blocks` already returns it
  (`icrc1/archive/src/main.rs:387`), so the ledger could read the archive's true
  block count and repair its ranges. Superseded by E, which has the archive report
  its position on every append rather than the ledger polling for it — no extra
  round trip, and nothing to forget. Repair would also have needed a new
  block-count endpoint on the ICP archive, which E does not. Repair remains the only
  way to fix a ledger that has *already* diverged. Judged not to apply — not
  because the divergence is impossible (ICP rounds are multi-chunk today, so the
  window is open), but because it has never been observed and DEFI-2967 could not
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
   wrong blocks is mis-indexed permanently.
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
9. The ledger's range bookkeeping and `num_archived_blocks` can never disagree —
   a round that dies leaves both untouched — and a node whose recorded offset does
   not match the ledger's next index is not appended to. This holds whether or not
   the archive understands the indexed protocol.
10. The ICP archive is unchanged. The ICP *ledger* does change: B1-B3, D1-D4 and
   E1 are in shared code, so the backoff, the creation counter, the allocation
   work and the atomic bookkeeping apply to both ledgers (Decision 3).

## Components

| # | Component | Where | Notes |
|---|---|---|---|
| A1 | tip hash + parent comparison, trap on mismatch | `icrc1/archive/src/main.rs` `append_blocks` | separate crate from `ic-icp-archive`; no shared code |
| B1 | last-attempt timestamp + consecutive-failure count | `ledger_canister_core::archive::Archive` | `#[serde(skip)]` so an upgrade resets it |
| B2 | skip the round while backing off | `ledger_canister_core::ledger::blocks_to_archive` | before the guard is taken, so it costs nothing |
| B3 | backoff schedule constants | `ledger_canister_core::archive` | |
| C1 | counter for the refusal cause, chain mismatch counted separately from a capacity refusal | `icrc1/archive/src/main.rs` `encode_metrics` | |
| D1 | in-flight archive-creation counter; halt archiving while it is non-zero | `ledger_canister_core::archive`, checked in `blocks_to_archive`, exposed as a per-ledger metric | `+1` before `create_canister`, `-1` on a graceful `Err` from any creation step, `-1` when `nodes.push` succeeds. A trap skips the decrement, so a non-zero value means a creation was begun and never accounted for. `#[serde(skip)]`, so it is per-epoch and needs no baseline |
| D2 | stop copying the archive wasm after a commit point | `ledger_canister_core::spawn::install_code` signature, `archive.rs` | `install_code` takes `Vec<u8>`, forcing `archive_wasm().into_owned()`, and `Rt::call` then serialises it again — two multi-MB copies in the continuation after `create_canister` committed. Take `Cow<'static, [u8]>`, pre-reserve the encode buffer before the first await, and `nodes.reserve(1)` |
| D3 | correct the stale comment at `archive.rs:468-474` | `ledger_canister_core::archive` | it says a panic there "leads to the rolling back of the transaction that triggered the archiving", which stopped being true when archiving was spawned |
| D4 | make error construction allocation-free, and trim the interpolating log lines | `ledger_canister_core::archive`, `::spawn` | `FailedToArchiveBlocks(pub String)` allocates on every error construction, so an allocation failure there turns a graceful `Err` into a trap: replace it with an enum carrying `Copy` payloads, rendered to text only where it is logged. `Rt::print` takes `impl AsRef<str>`, so non-interpolating messages become `&'static str` for free. **Keep** the canister id in the `create_canister` callback log — canister logs survive traps — verified, `test_appending_logs_in_trapped_update_call` in `rs/execution_environment/tests/canister_logging.rs` asserts the pre-trap `debug_print` persists *and* that the trap gets its own record — so it is the only possible record of an orphan's identity (D1 says one happened, this says which) — but drop the `{result:?}` debug format, which also stringifies the reject message. `reject_message()` borrows a `String` ic-cdk has already allocated, so only our second copy is avoidable |
| E1 | `append_blocks` takes an optional expected start index and returns an optional result carrying the archive's next expected global index, or a gap | `icrc1/archive/src/main.rs`, `archive.did`, `ledger_canister_core::archive::send_blocks_to_archive` | the only interface change; both `opt`, so tolerant in either direction. Verify with `didc` and the CI Candid check |
| E2 | the ledger reconciles its ranges from the reported index instead of incrementing, and treats a covered index as success | `ledger_canister_core::archive`, `ledger::archive_blocks` | shared code, so it applies to both ledgers once their archives are upgraded; the incremental path stays as the fallback for archives that return nothing |
| E3 | count every use of the incremental fallback | `ledger_canister_core::archive` + per-ledger metric | the path's problem is an unknowable lifetime; a counter makes it deletable once it reads zero everywhere |
| F1 | accumulate per-node counts locally; derive a new node's offset from `num_archived_blocks + sent_so_far`; record that offset when the node is created, so a later round can refuse a node whose offset does not match its next index; apply ranges and `remove_archived_blocks` in one message | `ledger_canister_core::archive::send_blocks_to_archive`, `::create_and_initialize_node_canister`, `ledger::archive_blocks` | ledger-only, so it covers the fallback path that E cannot reach |

A1, C1 and E1 are in `ic-icrc1-archive`. B1-B3, D1-D4, E2, E3 and F1 are in
shared ledger code and therefore affect both ledgers; see Decisions 3.

## Edge cases

* **Empty archive.** No tip, so the chain check cannot fire. It has nothing to
  duplicate, but it *can* be mis-indexed: a node created for index X that is later
  handed blocks starting at Y < X is wrong forever, because the offset is
  immutable. So an empty archive must check the offset even though it cannot check
  the chain — see the multi-node case under E.
* **Genesis.** Block 0's `parent_hash` is `None`; an empty archive accepting it
  is the normal path.
* **New node mid-round.** After the first append the node has a tip, so a
  re-send to it is caught.
* **Multi-chunk round.** Chunk 2's first block must continue chunk 1's last, so
  the check holds within a round as well as across rounds.
* **Deployed archives.** The check only applies to archives running the new
  wasm; see Rollout.
* **Undecodable first block.** The archive must not trap on a decode failure in
  a way that is indistinguishable from a mismatch; treat separately.
* **u64 vs u256 archives.** Both variants need the check and the test.

## Residual failure modes after this spec

Every inter-canister call allocates a buffer for its reply, in the callback
message. That allocation cannot be removed, so each call is a place where the
ledger can trap with everything from earlier messages already committed. With
A through E applied:

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

Continuation B's post-commit allocations are an interpolating `log!` and, before
E, the `nodes_block_ranges` update — E moves that into the final message, so
afterwards only the log line and a push onto the local accumulator remain. A
neutralises the duplicate consequence and E the offset one, so shrinking that
window is hygiene rather than a fix.

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

A through D and F change no wire format; **E does**, and is the reason the split
matters here:

* **A** is confined to the archive. A new archive facing an *old* ledger sees
  ordinary contiguous appends and passes; on a re-send it refuses, and the old
  ledger already handles a rejected `append_blocks` on its existing `Err` path.
  A new ledger facing an *old* archive is unaffected, because A changes nothing
  in the ledger.
* **C** is additive to the archive's `/metrics`.
* **B**, **D** and **F** are ledger-internal: state, allocation behaviour, and the
  order in which the ledger commits its own bookkeeping. An old archive neither
  knows nor cares.
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
  reconciling from the reported position, the backoff, the creation counter and
  the atomic round bookkeeping.
  By now the archives it talks to already answer, so the fallback path is never
  exercised in our deployments.

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
* **F is what makes the fallback path less bad.** It is cheap and ledger-only, and
  it closes the *offset-poisoning* half of the fallback's exposure. The
  duplicate-storage half is irreducible there, since an un-upgraded archive cannot
  refuse anything.

### If the fallback's lifetime is judged too long to carry

**Halt and wait.** Refuse to archive against a tail archive that answers `null`,
back off, and accumulate blocks locally until it is upgraded. This is what lets
the incremental path be deleted outright. The cost is stable-memory growth while
waiting — the same degraded mode two ck ledgers are running deliberately today,
and cheaper than it looks, since resident blocks do not drive upgrade instruction
cost — plus a hard dependency on operators upgrading their archives, so the halt
needs its own metric rather than hiding in the generic failure counter.

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
| 4 | F1 — the ledger's range bookkeeping and `num_archived_blocks` can diverge, and a new node's offset is taken from the former | **unit test in `ledger_canister_core`**: drive a two-chunk round where the second chunk's bookkeeping is dropped, assert today that `last_range_end + 1 != num_archived_blocks` and that the derived offset follows the stale value; after F, assert a dropped round leaves both untouched and the offset is `num_archived_blocks + sent_so_far` | **yes** — constructible in Rust, no canister and no trap needed |
| 5 | D2 — the creation round's post-commit allocation | measure ledger memory across an archive-creation round, as `routine_archiving_does_not_grow_the_ledger` already does for a routine round; assert the growth is below a bound after D2 | yes, as a measurement |
| 6 | both token variants for (1) | | yes |

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
3. **Backoff applies to both ledgers.** B1-B3 stay in shared code with no trait
   seam. The wasteful per-transaction retry exists on both ledgers today, so
   this fixes both; a seam introduced only to keep the ICP ledger on the old
   behaviour would be a layer with no beneficiary. The archive-side check (A)
   remains ICRC-only regardless, since `ic-icrc1-archive` and `ic-icp-archive`
   are separate crates.
4. **The typed result is part of E, not deferred.** It is what lets the ledger
   distinguish a duplicate (success) from a gap (halt) without inspecting reject
   strings. On the fallback path there is no such distinction to be had, which is
   one of the things F cannot make up for.

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

  E makes the question moot. With `num_archived_blocks` and the ranges advancing
  together and only by acknowledged chunk counts, neither can exceed what the
  archives hold, so a gap cannot arise. Every refusal is therefore a duplicate,
  and C1's single mismatch counter says all there is to say.
