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
| **3** | **E _or_ addressed appends** | the only real decision — see below |

D2-D4 are hygiene and can land whenever.

**Step 3 is the choice.** E stops the ledger's bookkeeping from diverging;
addressed appends (see *Alternative architecture*) instead make a divergence
*harmless*, and retire E. The recommendation is **addressed appends**: making
retries idempotent means the whole family of lost-acknowledgement problems stops
mattering, rather than each being guarded separately, and two sequential releases
remove the compatibility risk. E is the fallback if there is no appetite for
touching a deployed protocol — it is small, just narrower in what it buys.

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

**This holds for the component set below, not universally.** The
addressed-appends alternative deliberately gives the ledger a cause worth acting
on — a `Gap` halts while a duplicate is success — so there the ledger *does*
branch on it. Not a contradiction: addressed appends create a distinction that
this design has no use for.

**D. Allocation and observability work on the ledger side.** Four items that are
independent of each other and of the above, detailed in Components: an in-flight
counter that detects an archive creation whose outcome was never recorded and
halts archiving until an operator looks (D1); removing the two multi-megabyte
copies of the archive Wasm that happen *after* `create_canister` has committed
(D2); correcting a comment that still claims a panic there rolls the triggering
transaction back, which stopped being true when archiving was spawned (D3); and
making error construction allocation-free, so a graceful failure cannot decay
into a trap under memory pressure (D4).

**E. The ledger's round bookkeeping commits atomically.** The divergence that
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

**Correction to an earlier version of this analysis, and to the DEFI-2967
description.** Both claimed that DEFI-1666's proposed `num_blocks_to_archive =
5000` with 2 MB messages "would make rounds multi-chunk, putting those
allocations back". That is backwards. Raising the ICP cap from 128 kB to 2 MB
makes 5000 blocks at ~150 bytes about 750 kB — comfortably a single message. So
DEFI-1666 would take ICP from two chunks to one and *close* this window rather
than open it. The ticket description still carries the wrong claim and should be
corrected.

### How a round traps, and whether to make it resumable

**What prevention does not do** is make a trapped round resumable. If a round
dies after appending to a second node, the next round re-sends from
`num_archived_blocks`, which is now behind that node's offset, so A1 refuses and
archiving stalls until an operator intervenes. No corruption, but no self-healing.

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
proposal the team makes routinely. Revisit if rounds stay multi-chunk; note the
trigger is the *opposite* of what an earlier version of this spec said, since
DEFI-1666 would reduce chunking rather than increase it.

## Why not the alternatives

These are alternatives *within* the no-interface-change constraint. Dropping that
constraint gives a better answer than any of them — see **Alternative
architecture: addressed appends** below, which retires E entirely and makes the
idempotency option in this list work properly.


* **Typed `opt` error return.** `append_blocks : (vec blob) -> (opt append_error)`
  should be compatible both ways (old ledger ignores the extra value; new ledger
  reading an old archive's empty reply gets `null`), and `archive.did` plus CI's
  Candid compatibility job make that checkable. But it is only needed if the
  ledger must branch on the cause, and with (B) cause-agnostic and (C) recording
  the cause, it does not. Defer.
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
  block count and repair its ranges. Superseded by E: prevention makes the
  divergence impossible instead of repairing it, needs no archive cooperation and
  therefore fixes the ICP ledger too, whereas repair would have needed a new
  block-count endpoint on the ICP archive to get there. Repair remains the only
  way to fix a ledger that has *already* diverged. Judged not to apply — not
  because the divergence is impossible (ICP rounds are multi-chunk today, so the
  window is open), but because it has never been observed and DEFI-2967 could not
  induce the trap even deliberately.

## Acceptance criteria

1. An ICRC archive rejects an `append_blocks` whose first block does not
   continue its stored chain, and its stored log is unchanged afterwards.
2. An empty ICRC archive accepts its first append unconditionally (it has no
   tip to compare against, and nothing to duplicate).
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
8. A newly created archive node's `block_index_offset` is the global index of the
   next block to be archived, and the ledger's range bookkeeping and
   `num_archived_blocks` can never disagree — a round that dies leaves both
   untouched.
9. The ICP archive is unchanged. The ICP *ledger* does change: B1-B3, D1-D4 and
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
| E1 | accumulate per-node counts locally; derive a new node's offset from `num_archived_blocks + sent_so_far`; apply ranges and `remove_archived_blocks` in one message | `ledger_canister_core::archive::send_blocks_to_archive`, `::create_and_initialize_node_canister`, `ledger::archive_blocks` | shared code, so it fixes both ledgers; no archive endpoint and no trait seam |

A1 and C1 are confined to `ic-icrc1-archive`. B1-B3, D1-D4 and E1 are in shared
ledger code and therefore affect both ledgers; see Decisions 3.

## Edge cases

* **Empty archive.** No tip; must accept. It therefore cannot detect a gap at a
  node boundary — but E makes a gap impossible in the first place, and an empty
  archive has nothing to duplicate, so nothing is lost by accepting.
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
| `append_blocks` reply | the archive holds the blocks | E leaves the ledger's bookkeeping untouched, so no offset is poisoned; the re-send is refused by A, so the archive never holds a duplicate. The ledger cannot archive those blocks and probes at the backoff cap | stall, not corruption |

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

Nothing here needs that. None of A through E changes a wire format:

* **A** is confined to the archive. A new archive facing an *old* ledger sees
  ordinary contiguous appends and passes; on a re-send it refuses, and the old
  ledger already handles a rejected `append_blocks` on its existing `Err` path.
  A new ledger facing an *old* archive is unaffected, because A changes nothing
  in the ledger.
* **C** is additive to the archive's `/metrics`.
* **B**, **D** and **E** are ledger-internal: state, allocation behaviour and the
  order in which the ledger commits its own bookkeeping. An old archive neither
  knows nor cares.

So this ships as one release in the standard order. Note the consequence of that
order: archives are upgraded last, so the corruption is only closed at the end
of the sequence. Since A needs no cooperation from the ledger, the archives
could be upgraded first for this change if closing it earlier is worth
reordering for.

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
| 4 | E1 — the ledger's range bookkeeping and `num_archived_blocks` can diverge, and a new node's offset is taken from the former | **unit test in `ledger_canister_core`**: drive a two-chunk round where the second chunk's bookkeeping is dropped, assert today that `last_range_end + 1 != num_archived_blocks` and that the derived offset follows the stale value; after E, assert a dropped round leaves both untouched and the offset is `num_archived_blocks + sent_so_far` | **yes** — constructible in Rust, no canister and no trap needed |
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
4. **The typed error is deferred.** Record the reasoning as a comment next to
   the backoff constants, since that is where the consequence lives: the ledger
   probes at the cap interval forever because it cannot tell a permanent cause
   from a transient one. An `opt` return on `append_blocks` would let it latch
   instead, and with two releases (archives return the value first, the ledger
   reads it second) that carries no compatibility risk. Not needed while C puts
   the cause on the archive's `/metrics`, where an operator can see it.

## Alternative architecture: addressed appends

Everything above treats the symptoms of a protocol that cannot express what it
means. Worth stating the root causes plainly, because most of the components
exist to work around one of them:

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

### The fix: give appends an index, and have them report state back

    type append_result = variant {
      Ok  : record { log_length : nat64 };
      Gap : record { expected : nat64; got : nat64 };
    };

    append_blocks : (vec blob, opt nat64) -> (opt append_result);

The second argument is the expected start index. The archive compares it against
its own `offset + log_length` and decides with certainty:

| | meaning | action |
|---|---|---|
| equal | correct continuation | append, report the new `log_length` |
| less | already holds them | **no-op success** — this is the idempotency, not an error |
| greater | a gap | return `Gap`, having appended nothing |

Both `opt`s keep this compatible in either direction: an old archive ignores the
extra argument and returns nothing, which decodes as `null` and tells a new
ledger to fall back to today's incremental behaviour. That matters, because the
suite upgrade order puts archives **last**, so a new ledger will talk to old
archives during the rollout window.

Returning `Gap` as a *value* rather than trapping is better than the current
design on three counts: the archive's message commits having done nothing, so
atomicity holds by construction; the reason is precise instead of an opaque
reject string; and no work is wasted.

Reporting `log_length` back is what makes this more than an idempotency fix. The
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
* **E is no longer needed.** Atomic bookkeeping was protecting against a
  divergence that idempotent, self-reporting appends make impossible.
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

### What survives from the current spec

| component | under addressed appends |
|---|---|
| A1 hash check | keep, demoted to an integrity check |
| C1 refusal metric | keep, now able to distinguish gap from duplicate |
| B backoff | **keep** — orthogonal, it is about not spinning |
| D1 orphan counter | **keep** — a creation problem, unrelated to appends |
| D2, D3, D4 | keep as hygiene |
| E atomic bookkeeping | no longer needed |
| resumability | free |

So B and D1 stand on their own merits; the rest of the complexity is
compensating for R-2.

### The road not taken: let the archive pull

The most fundamental option inverts the direction. The archive would own its
position, the ledger would serve blocks and drop those below the archive's
reported point, and the transaction path would have no archiving commit point at
all — R-1, R-2 and R-3 all dissolve.

But it trades the ledger's commit-point problem for the index's timer-fragility
problem, and DEFI-2983 is exactly that failure: a one-shot timer chain that
stopped re-arming and went unnoticed for hours. Not worth taking without a much
better story for timer liveness.

### Choosing

The two are not exclusive, and the choice is narrower than it looks: A1, C1, B
and D1 are wanted either way, so what is actually being decided is **E versus
addressed appends** — one component against one protocol change.

* **E**: no interface change, ships in one release, and is genuinely small. But
  it prevents one specific divergence rather than removing the reason
  divergences matter, and it leaves a trapped round needing an operator.
* **Addressed appends**: touches a deployed protocol and needs two sequential
  releases, larger to review, but *smaller in concept*. Retries become
  idempotent, so a lost acknowledgement stops being a problem to guard against;
  gap-versus-duplicate is decided at the archive; resumability comes free; and E
  is no longer needed.

**Recommended: addressed appends**, on the grounds that it eliminates the class
rather than the instances. E is the fallback if the appetite for changing a
deployed protocol is low — it is a good answer to a smaller question.

Either way, ship A1 and C1 first. They close the corruption, need nothing from
the ledger, and neither answer to this question invalidates them.

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

## Resolved questions

Kept for the reasoning, not because anything is outstanding.

* **Corrected: DEFI-1666 reduces chunking, it does not increase it.** Earlier
  versions of this spec, and the DEFI-2967 description, argued that
  `num_blocks_to_archive = 5000` with 2 MB messages "would make rounds
  multi-chunk". Backwards: raising the ICP cap from 128 kB to 2 MB makes 5000
  blocks at ~150 bytes about 750 kB, a single message. So DEFI-1666 would take ICP
  from two chunks to one. Two consequences — the multi-chunk window is open
  **today** on the ICP ledger rather than being a future risk, and the trigger for
  revisiting resumability is the opposite of what was written. The ticket
  description still carries the wrong claim.


* **Resolved: `spawn` is correct, and better than `spawn_migratory` here.** The
  concern was that `ic_cdk::futures::spawn` is the *protected* variant, documented
  as "canceled if the method returns before they complete", while archiving is
  meant to outlive the method. Cancellation is refcounted, not tied to the Rust
  future resolving: `enter_current_method` cancels attached tasks only when the
  method's `MethodHandle` count reaches zero, and a handle is taken before every
  inter-canister call and threaded through its callback. A task blocked on a call
  therefore keeps its method context alive, and the chain of calls keeps the count
  above zero until archiving finishes. "Returns" means "the body finished *and*
  every outstanding call completed".

  Protected is also the better choice: if the context ever did die with the task
  pending, `ProtectedTask`'s `PinnedDrop` panics, so it surfaces. `spawn_weak`
  drops silently and `spawn_migratory` is unattached, which sounds more robust but
  removes both the attachment and the alarm — and the archiving chain has no need
  to migrate, because every await is its own call.

  **Invariant this creates:** every await in the archiving chain must be an
  inter-canister call. Awaiting anything a call does not wake — a timer, a channel
  — drops the refcount to zero, cancels the task and trips the panic. This is a
  second, independent reason for the decision not to make archiving timer-driven,
  and worth a comment at `spawn_archiving` so nobody later adds a delay inside the
  task.

* **Moot: gap versus duplicate.** The two cases had opposite severity — a
  *duplicate* meant the ledger's bookkeeping had fallen behind what the archive
  holds, a *gap* meant blocks between the archive's tip and the ledger's next send
  were stored nowhere. Distinguishing them would have needed the archive's
  `log_length`, because `append_blocks` carries no index and the archive cannot
  tell which side of its tip the sender believes it is on.

  E removes the question. With `num_archived_blocks` and the ranges advancing
  together, and only by acknowledged chunk counts, neither can ever exceed what
  the archives hold, so a gap cannot arise. Every refusal A1 reports is a
  duplicate, and C1's single mismatch counter says all there is to say.
