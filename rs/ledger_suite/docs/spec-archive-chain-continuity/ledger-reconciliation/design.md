---
id: DEFI-2967-followup/ledger-reconciliation
title: Ledger Reconciliation And Retries
tags: [ledger, archive, icrc, icp]
---

# Ledger Reconciliation And Retries — Design

*Companion to [`requirements.md`](requirements.md), and part **L** of the specification;
the overview, constraints, delivery sequence and alternatives are in
[`../README.md`](../README.md). Every decision here serves numbered criteria, and every
criterion of this part is served by something here. Criteria are cited, never restated.*

*Line references are against `master`, paired with the symbol they point at so they
stay findable once the numbers drift.*

*Criteria are cited by document prefix: `A` for the archive append protocol, `L` for
ledger reconciliation and retries, `C` for archive creation and handover — so `A2.4`
is criterion 4 of requirement 2 in
[`archive-protocol/requirements.md`](../archive-protocol/requirements.md). Design
decisions are numbered once across the whole specification (D1–D10); each design
document says which it holds.*

## Design Decisions

*Decisions are numbered across the whole specification. This part holds D1–D3 and
D6–D9; D4 and D5 are in the archive design, D10 in the README.*

### D1 — Backoff is spaced geometrically, not latched

Serves `L4.1`, `L4.2`. `BACKOFF_INITIAL` = 30 s, doubling per consecutive
failure, `BACKOFF_CAP` = 1 h. A transient cause recovers within a minute; a permanent
one costs one probe per hour. What recovered on its own on 2026-09-01 was the
*subnet*, not archiving — the pressure appeared and vanished inside four and a half
hours, driven by a canister that was nothing to do with us. Latching on failure would
have outlasted a cause that cleared itself, which is why `L4.4` exists.

Transaction-triggered plus a timestamp check rather than a timer: no re-arm hazard,
and it satisfies the every-await-is-a-call constraint above.

### D2 — Backoff, probe and halt state are `#[serde(skip)]`

Serves `L4.3`, `L4.9`, `L4.11`, `L5.4`. Matches `archiving_in_progress`, and makes an upgrade the
operator's "resume now" lever, which is the right shape when the upgrade is usually the
fix.

That lever is a *deviation* from `L4.1`, not a consequence of it: after a failed
round, `L4.1` alone would forbid an immediate attempt, and resetting the state
permits one. `L4.9` is therefore the criterion that makes this legal rather than a
contract violation — the behaviour was always intended, but only the design said so.

**The line is whether forgetting it costs anything.** Backoff state forgotten is a
round attempted sooner, which is the point, and a capability answer forgotten is one
empty append that stores nothing — so `L5.4` permits that one re-determination
explicitly rather than the design engineering around it. What an upgrade must *not*
forget is an archive that may exist and cannot be named, which is why the creation
journal is the exception and persists.

### D3 — One seam, `Wasm::INDEXED_APPENDS`, and no others

Serves `L5.5`, `L7.6`. The shared code always sends the index, including to
`ic-icp-archive`, which the tolerance recorded in Constraints makes safe. What the
shared code cannot infer is whether a silent absence of a reply is a
misconfiguration or the expected state, so `ArchiveCanisterWasm` gains
`const INDEXED_APPENDS: bool` — `true` for `ic-icrc1-archive`, `false` for
`ic-icp-archive`. It is a property of the Wasm the ledger embeds, which is what that
trait already abstracts.

Every other component stays in shared code with no seam: the per-transaction retry,
the lost-creation window and the inferred bookkeeping exist on both ledgers, so
fixing them fixes both.

### D6 — Accept the re-send; do not redraw the module boundary

Serves `L3.1`, `L3.5`. Giving `send_blocks_to_archive` ledger access
would let it advance the archived prefix directly, but the divergence it avoids is
benign: while `num_archived_blocks` lags, `block_locations` still routes those indices
to the ledger, which still holds them (`L3.4`), and any completed round corrects
the count. So the round *reports* instead — it returns a count that includes blocks an
archive already held, and `archive_blocks` performs the removal, which is a wider
return value rather than wider access.

`L6` shrinks this further: with one append there is no await after it, so the
range reconciliation and the removal land in the same message. The accepted re-send is
then at most one batch.

### D7 — The ICP archive is not changed here

The consequence of the corresponding non-goal. `A2` and `A3` are implemented in
`ic-icrc1-archive` only, so the ICP ledger gains D1, D2, the allocation work and
`L6` but not addressed appends, and stays on the incremental path under
`L5.5`.

**D6 does not reach ICP either**, which is easy to miss because it is ledger-side
code. D6 serves `L3.1` and `L3.5`, and both require an archive to have reported an
extent. An ICP archive reports none, so the ICP ledger is exempt from
`L1.1`-`L1.4` and from `L3.1`-`L3.3`, `L3.5`, `L3.7`, `L3.8` and `L3.9` (`L1.5`,
`L3.6`) and keeps deriving both the offset and the archived prefix from its own
record. `L1.2` is in
that list for a second, independent reason: ICP's `archives()` returns canister ids
with no ranges (`icp/ledger.did:246-248`) and it has no `icrc3_get_archives` at all,
so publishing matching ranges through both would be an interface change this design
does not make. Without
those exemptions the requirements would forbid it from creating an archive or
discarding a block at all, contradicting `L5.5`.

There is no cheap partial: porting the chain check alone catches the
variant where a new node already has a tip, but the silent variant is the *empty*
node, which has none — closing that needs the offset check, hence the index, hence the
interface change.

### D8 — Only a positive capability answer is cached

Serves `L5.2`, `L5.4`. **It also assumes archives are never downgraded below
PR 1 while a ledger is at PR 3 or later**, and that is an operational rule, not something
the ledger can enforce: a cached positive answer means the next append carries blocks
without a probe, and an archive rolled back to the old wasm would store them blindly
before returning the empty reply that makes the ledger notice. The exposure is one append
and is harmful only if that append was a re-send — but it is exactly the original
corruption, so Delivery states the prohibition rather than the design pretending to a
defence it does not have. Re-probing before every append would close it at the cost of
doubling every round's calls, which is not worth it against an operator action the
release order already forbids.

Caching "the tail cannot answer" would strand the
ledger, because the cache lives in the ledger and upgrading only the archive — the
scenario `L5` exists for — would not clear it. So an absent answer is re-probed,
spaced by D1's backoff, and a positive answer is cached in `#[serde(skip)]` state.

**Losing it on upgrade is the intended behaviour, not a defect to design around.** The
tail reports its range on the first round after an upgrade and on every round
afterwards, so one empty append re-establishes the answer at a cost of nothing — it
stores no block and consumes no capacity (`A3.5`). `L5.4` therefore permits that
single re-determination rather than the ledger persisting state to avoid it.

### D9 — `ARCHIVE_CALL_TIMEOUT` is the CDK default, 300 s

Serves `L7.1`, `L7.8`. `ic_cdk::call::Call::bounded_wait` defaults to 300 s,
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
and not the stall is what carries `L7`.

**Upgradeability is a real secondary, but weaker here than in the guidance.** An
outstanding callback prevents the caller being stopped and therefore cleanly
upgraded, which matters because D2 makes an upgrade the operator's "resume now" lever
and `C1.4`'s halt has no other remedy. The guidance raises it for *untrusted*
callees that never respond; against our own synchronous archives the window is only
as long as a response is slow. Worth having, not worth leading with. A shorter value buys a faster stall detection at the
cost of spurious unknown outcomes, each of which re-sends a batch; 300 s is
conservative and can be lowered once the unknown-outcome counter shows how often it
fires. The value is settled here rather than in `requirements.md` because `L7.1`
fixes only the behaviour.

## Implementation

### `ledger_canister_core::archive` — `send_blocks_to_archive`

Both loops go (`L6.1`, `L6.2`): pick a node, send what the round selected, one
call, reconcile, return. Reconcile `nodes_block_ranges` from the reported
`block_index_offset` and `next_index` rather than incrementing (`L1.3`, `L3.5`) —
**for the tail only, and only its end**. The reported start must equal the recorded
one for every archive, the tail included (`L3.9`): an offset is immutable, so a
difference means the record was wrong or this is not the canister the ledger thinks,
and rewriting the start would leave every index between the two held nowhere. The
first archive a suite ever has is the case `L1.4` cannot reach, having no previous
range to check against, and its start is zero by definition.

The start check (`L3.2`), the backwards check (`L3.3`) and the **forwards**
check (`L3.7`) live here, since this is where the ranges are; per D6
they report upward rather than acting.

**The forwards check is the third direction and the one L3 was missing.** `L3.2`
catches a reported range starting too high and `L3.3` one ending too low, but an
archive whose `next_index` is above the ledger's *own* chain tip trips neither: its
range starts at or below the archived prefix and ends above it, which reads as ordinary
progress. That state is what a ledger-only snapshot restore produces — the archive holds
indices from a timeline the restored ledger never issued — and reconciling it would
publish and discard against the fork. So the ledger compares the reported position
against the next index it would itself issue and halts if the archive is ahead
(`L3.7`).

**And only an append that verified a block may advance the prefix** (`L3.8`). A
probe reports a range but puts no block in front of the archive, so `A2.9`'s fork
check cannot run: the range alone is consistent with an archive continuing a fork of
this ledger's chain. A probe may therefore *halt* on what it reports — `L3.3` and
`L3.7` are both decidable from numbers alone — but it may not move the
Archived_Prefix forward.

**Carrying blocks is not the test; verifying one is.** `Gap` and `BelowRange` both
arrive from appends that carried blocks and yet stored and compared none (`A2.2`,
`A2.6`), so their reported ranges are no better evidence than a probe's; both halt.

**And the outcome arm is not the test either**, which is worth stating because listing
the permitted arms is the obvious next mistake. `Stored` covers the empty probe, where
nothing was verified; `StoredPartial` covers an append whose very first block did not
fit (`L2.3`), where nothing was stored. Both would pass an arm-based gate and
neither verified anything.

So the gate is the reply's `verified` flag (`A3.10`, `L3.8`): true when a stored
block was chained against the archive's tip or its Expected_Parent, or when a wholly
held re-send had its last block compared per `A2.9`; false otherwise.

**It has to be a field, and this is the one piece of evidence the ledger genuinely
cannot reconstruct.** `blocks_stored > 0` is *almost* right, and was the previous
draft's gate, but `A1.4` allows exactly one store that checks nothing: the first
append into an empty archive that was given no Expected_Parent (the unverifiable append
`A1.6` counts). That archive may be the tail a new ledger inherits from the old one —
created before the upgrade, so never given a hash — and nothing in the ledger's own
state says whether it was. The archive knows, because it knows whether it had anything
to check against; so it says so, and the ledger reads it rather than guessing.

**Why a flag rather than an `AlreadyHeld` arm, when the arm was rejected as
redundant.** The arm was redundant because everything it encoded — did the archive
already hold these blocks — the ledger could reconstruct from `blocks_stored` and the
batch it had just sent in the same message. The flag is not redundant, because whether
a *parent check happened* depends on state only the archive has. Same test applied both
times: the ledger derives what it can, and the reply carries what it cannot. That is
also why `blocks_stored` stays — it separates the zero-stored cases for `A3.7`, `A3.8`
and `L2.3`, which `verified` does not.

**The gate has a ceiling as well as a trigger, and `next_index` is not it.** Having
verified *a* block does not license advancing to wherever the archive happens to reach.
An archive holding 1000 blocks, offered only the first 100 on a retry, compares index 99
per `A2.9` and reports `next_index = 1000` — and advancing there would discard
100..999 having compared none of them, which after a fork below the tip is silent loss.
The hash-chain argument that makes one comparison sufficient runs *downward*: a
divergence propagates forward and cannot heal, so a match at index N is evidence about
every index at and below N and about none above it.

So the prefix advances to one past the highest-indexed block of that append the archive
stored or compared, never to the reported `L3.8` position. In the ordinary cases the
two coincide — a full store, a straddling append, a complete re-send all end at the
offered batch's top — and they diverge in exactly the partial-re-send case that is
unsafe. D6's removal count is capped the same way, being the same quantity. This is the
one place where detection and advancement have different evidence requirements, and
conflating them is how a fork gets archived. The
return type widens to carry the count `archive_blocks` should remove, which may
include blocks an archive already held.

**A `BelowRange` outcome is a halt** (`L4.8`), with its own metric because it points
somewhere different from a chain mismatch. It is worth recording why it is a halt and
not a recovery, because an earlier draft built a whole redirect path to recover from it
— the blocks offered again to whichever older archive covered them, that archive probed
first in case it still ran the old wasm, the batch cut at its range end — and every
piece of that path generated failure modes of its own.

**The one benign way to reach it was a defect in the archive, and `A2.9` now closes
it.** Tail `A` is nearly full. The ledger offers `[i, i+n)` at `i`; `A` stores `k`
blocks, fills, and replies `StoredPartial`, `at_capacity`, `next_index = i+k`. The
ledger's callback — advance the prefix, remove `k` blocks, note the tail is full — is
lost: a reply-buffer trap, or under `L7.1` a bounded wait that expired before a slow
reply. Next round the ledger offers the same batch; it is now a *straddling* append, and
under the earlier rule the archive skipped the held prefix, found the first new block did
not fit, and stored and compared nothing — `verified = false`, so `L3.8` forbade
advancing, while `at_capacity` sent the ledger to `L2.1` to create `B` at `i+k`. The
round after, `[i, i+n)` went to `B`, and `i` is below `B`'s offset. With `A2.9`
comparing the last held block of *any* overlapping append, that second round verifies
through `i+k-1`, `L3.8` advances the prefix to `i+k`, and the next batch goes to `B`
at `B`'s own offset. Nothing below range is ever offered.

**Everything that remains is a wrong record.** A ledger restored alone from a snapshot,
or a legacy suite whose inferred ranges were never right, offers blocks its archives
already hold at indices below the tail's start. Nothing the ledger can do alone is safe
there — advancing discards blocks that may be held nowhere, re-sending changes nothing —
so it stops and says which condition it is in. Step 0's Rosetta sync is how that record
gets checked and D10 is how it gets repaired, both deliberately and by a person.

An absent reply routes by `Wasm::INDEXED_APPENDS` (D3): halt and count for an ICRC
ledger (`L5.1`), incremental path and count for ICP (`L5.5`). The
determination itself is the empty append of `L5.3`, issued here and bounded by
`L6.1`'s one-empty-append limit.

Reconciliation also maintains what `archives()` publishes, so a Published_Range only
ever widens to what an archive has reported (`L1.2`), and an archive that holds
nothing yet appears in no published range at all (`L1.6`). **The current code does
not give that for free, and an earlier draft said it did.** Today the first range entry
is derived from the batch — `push((0, chunk_len - 1))` for the first node,
`last_height + chunk_len` for the rest (`archive.rs:285-301`) — which was safe only
while no append was ever empty. A successful indexed probe to a fresh archive has
`chunk_len = 0`, so that arithmetic underflows or publishes a range for a block that does
not exist. The rule is therefore stated rather than inherited: a node's range is set **only from
the reply's `block_index_offset` and `next_index`**, and a reply with the two equal
describes an archive holding nothing. The batch length plays no part, and the `chunk_len`
arithmetic goes with the loops it belonged to.

**And "absent" cannot mean a missing element, because of how the ranges are stored.**
`Archive::index()` zips `nodes_block_ranges` with `nodes` (`archive.rs:191-196`), so the
two vectors are aligned only by the implicit rule that at most the *last* node may lack
an entry. That holds today by accident of the loops, and an empty archive that is not
the last node — or any future path that creates one — would pair a later node's range
with the empty node's canister id and corrupt both `archives()` and block routing. So the
state gains `node_ranges`, one `NodeRange { offset, next_index }` per node, aligned with
`nodes` by construction: an empty archive is `next_index == offset`, published ranges
are derived by skipping those (`L1.6`) and taking `next_index - 1` for the inclusive
end, and the per-node `offset` is the recorded start `L3.9` compares against — which
the ledger otherwise never records (README, Constraints). It is `#[serde(default)]` so that pre-change state *decodes* — but a derived default can
only supply an empty vector, not read `nodes_block_ranges`, so the conversion is an
explicit step in `post_upgrade`, run once when `node_ranges` is empty and `nodes` is not:
each legacy inclusive pair `(start, end)` becomes `(start, end + 1)` — **and padded**, because a valid legacy state can have one more node
than pair: the current creation path pushes the node before the `remaining_capacity`
call (`archive.rs:507-514`) while a pair appears only after the first successful append
(`archive.rs:285-310`), so an upgrade can land between the two. **Every** trailing node
without a pair — there can be several, since an oversized first block makes
`take_prefix` return nothing and the next attempt then finds that empty node too small
and creates another (`archive.rs:255-258`, `:507-514`, `:547-565`) — gets an empty record
at the preceding record's `next_index` (zero if it is the first node), which is exactly
the state a freshly created archive is in, so `node_ranges` always has one record per
node.
`nodes_block_ranges` keeps being *written* for one release after this lands, so that a
rollback to the previous ledger still finds its ranges, and is dropped in the release
after; until then `archives()` is served from `node_ranges` and the legacy field is
write-only.

A published range is inclusive of both ends, so an empty archive has no pair of indices
that could describe it — the ledger's published view and its internal record are the
same data, which is why `L3.5` has to be about the *source* of that data rather than
about which field it is read from.

### `ledger_canister_core::archive` — `Archive` state, the ledger's half

`#[serde(skip)]` fields per D2: last-attempt timestamp and consecutive-failure count
(`L4`), the halt reason below (`L4.11`), and the tail's last reported
`at_capacity` (`L2.1`, `L2.2`) — without which
`node_and_capacity` has nothing to decide a roll-over from once the routine
`remaining_capacity` pre-call is gone. That one is skipped rather than persisted because
losing it is not a hazard: a cold start falls back to the pre-call, which is the same
value computed the expensive way.

The one persisted field on this side is the per-node range record that
`send_blocks_to_archive` above reconciles into, aligned with `nodes` by construction and
populated from the legacy pairs by an explicit `post_upgrade` step, not by the default
(see that section for the conversion and its padding):

    #[serde(default)]                                      // filled from the legacy pairs on first upgrade
    node_ranges: Vec<NodeRange>,                           // one per node, aligned with `nodes`
    struct NodeRange { offset: u64, next_index: u64 }      // empty archive: next_index == offset

The other persisted fields — the creation journal and the pending handovers — belong to
the creation protocol and are specified in
[`../archive-creation/design.md`](../archive-creation/design.md).

### Halt conditions, and how each one clears

Nine conditions stop archiving, with three different recovery stories, and they are
easy to conflate because they present identically — archiving stops and blocks
accumulate. An operator's first question is which one it is, so the metrics must be
distinct (they are, by `L2.3`, `L3.2`, `L3.3`, `L3.7`, `L3.9`, `L4.7`, `L4.8`, `L5.1` and `C1.2`) and the answer to
"what now" must be written down:

| condition | criterion | clears |
|---|---|---|
| the tail reports a start above the archived prefix's end | `L3.2` | not on its own. No endpoint sets the archived prefix, so it needs an upgrade carrying a migration. Unreachable except from a wrong record |
| an archive reports the blocks offered fall below its range | `L4.8` | operator only — once `A2.9` compares straddling appends, only a wrong record reaches this: a restore, or a suite that had already diverged. Step 0 to check it, D10 to repair it |
| an archive reports a position below the archived prefix | `L3.3` | never — blocks the ledger already stopped serving are held nowhere. Recovery is whatever backup exists, not this system |
| an archive reports a position above the ledger's own chain tip | `L3.7` | operator only. The ledger is on a chain the archive was not built from, which is the snapshot-restore non-goal; the coherent fix is restoring the whole suite to a common point, not resuming |
| an empty archive reports `at_capacity` | `L2.3` | operator only, and cheaply: raise `node_max_memory_size_bytes` above the block that did not fit. Halting is what stops it creating a canister per transaction meanwhile |
| an archive refused an append on chain or position grounds | `L4.7` | not on its own, and deliberately: the archive's counters say which of `A1.1`, `A2.2` or `A2.9` fired, and they call for different investigations |
| the tail archive reports no range | `L5.1` | **itself**, on the next probe once the archive is upgraded (`L5.2`). The only self-clearing halt |
| any archive reports an offset other than its recorded start | `L3.9` | operator only — an offset is immutable, so the record or the canister identity is wrong, and either needs a person |
| an archive creation was begun and never accounted for | `C1.1` | operator only, explicitly not itself (`C1.4`), because a canister may exist that nothing will address |

Two things follow for the implementation. The eight non-clearing halts must be
distinguishable from the backoff of `L4.1` — a ledger that is *waiting* and one
that has *stopped* look the same from block accumulation alone. And `L5.1` is the
only one whose state may be derived from a cache, since it is the only one expected to
change without a *ledger* upgrade.

**Where the halt lives, and what clears it** (`L4.11`). Seven of the eight are
learned from one archive reply and are invisible to the next round unless something
records them — the ranges are unchanged after a `ChainMismatch`, so `blocks_to_archive`
could not re-derive the refusal and would send again. So the round that learns one sets

    #[serde(skip)]
    halted: Option<Halt>,

    enum Halt { OversizedBlock, StartAhead, PositionShort, PositionAhead,
                StartMoved, Refused(RefusedGround), BelowRange }
    // L2.3, L3.2, L3.3, L3.7, L3.9, L4.7, L4.8 respectively

which `blocks_to_archive` reads before the guard, and which is the source for each halt's
metric. It is **skipped, not persisted**, and that is a decision rather than an
omission: every one of these seven is re-derivable from the next reply — the archive will
refuse again, report the same position again — so forgetting it on upgrade costs one
attempt that re-establishes it, and that one attempt is precisely the "resume now" lever
D2 gives an operator. Nothing else clears it: no timer, no successful unrelated call, no
metric read. The eighth, `C1.1`, is the exception in both directions — it is
`Creating::Started`, it is persisted, and an upgrade does *not* clear it (`C1.4`) —
because an orphaned canister cannot be re-derived from anything. That is D2's line
drawn through the halts: persist what only the past knows, skip what the next reply
will say again.

### `ledger_canister_core::archive` — `node_and_capacity`

The roll-over test (`remaining_capacity < needed`, `archive.rs:552`) is restated in
terms of the last append's `at_capacity`, held in the skipped field above (`L2.1`,
`L2.2`), with the `remaining_capacity` pre-call kept for a cold start or a freshly
spawned node — which is what makes that field safe to lose on an upgrade.

**And it is gated on the prefix having caught up** (`L2.1`). `at_capacity` alone is
not licence to create the next archive: the first append into a tail inherited from an
old ledger — empty, given no Expected_Parent — can store a prefix, fill, and report both
`at_capacity = true` and `verified = false` (`A1.6`, `A3.10`). The ledger may not
advance its Archived_Prefix on that (`L3.8`), and an archive created at the reported
position would then sit above blocks the ledger still serves, so every later offer of
them would come back `BelowRange` and halt. So a roll-over waits until the Archived_Prefix
equals the tail's reported position. Getting there needs no special path: the next round
offers from the prefix as always, the full tail already holds those blocks, `A2.9`
compares the last of them, `verified` comes back true, and the prefix advances — after
which `at_capacity` is acted on.
This is what makes `L6` cheaper than today rather than dearer: a 1000-block ICP
round is one pre-call plus two appends today, and one append per round with no
pre-call afterwards.

Creating a node sets `block_index_offset` from the reported extent of the previously
created node (`L1.1`), and refuses to use a node whose reported range does not
begin where the previous one ends (`L1.4`).

**One roll-over per cause, not one per round** (`L2.3`). `at_capacity` true with
nothing stored is the *ordinary* roll-over signal from a full tail, so it cannot halt in
general. But from an archive that holds **no** blocks it means something else entirely:
the first block offered exceeds the whole of `node_max_memory_size_bytes`. Rolling over
then creates an archive with the same limit, which cannot take it either — one canister
created per transaction, indefinitely, each one abandoned. The option has no lower bound
and can be set at runtime, so this is a misconfiguration away rather than impossible.
An empty archive reporting `at_capacity` therefore halts, and the reply already carries
what is needed to tell the two apart: the archive holds no blocks exactly when
`next_index` equals `block_index_offset`.

**The reply is not the only path to a roll-over, and the other one must halt too.** On a
cold start the current code asks the tail for `remaining_capacity` and rolls over when
it is below the first block's size (`archive.rs:547-558`) — before any append is sent,
so before any reply could carry `at_capacity`. An empty tail whose first block exceeds
`node_max_memory_size_bytes` would therefore create a same-sized archive on that path
and never reach the halt. So the check is made where the information already is: a block
larger on its own than the configured archive size halts *before any call*, and a
capacity pre-check that finds an *empty* tail too small halts rather than creates. Both
are the same condition seen from different places, and `L2.3` names both.

For a suite that predates this work there is no previously *created* node to have
reported anything — but there is a tail, and `L5.3`'s probe reports its range
before the first roll-over, which is where `L1.1` gets its value. Worth a comment
at the call site, since the probe doubling as the bootstrap is not obvious.

**Legacy non-tail nodes are deliberately not swept**, which is worth stating because
the opposite looks prudent. Their ranges were inferred rather than reported, and they
stay that way: a full archive never receives another block, so no decision the ledger
makes afterwards reads its range — `L1.1` derives an offset from the tail, `L3.1`
gives up blocks on the tail's report, and `L3.2` halts on a tail whose start lies
above the prefix rather than asking anyone to cover the gap. Asking them would find a historical mis-indexing, but
the only response available is a halt, and halting archiving repairs nothing that is
already written; Step 0's Rosetta sync is the deliberate, operator-owned path for that,
and D10 the repair. So the ledger asks the tail, on the round after each upgrade and on
every round after that, and no other archive is ever contacted again.

**Comparing per archive, not against the prefix.** `L3.3` still had to be restated:
a non-tail archive legitimately ends below the Archived_Prefix, because later archives
hold the blocks above it, so comparing any archive's reported position against the
aggregate prefix would read a correct answer as irrecoverable loss. Only the tail ever
reports, for which the two comparisons coincide — but the criterion is stated per
archive so that it stays right if that ever changes.

**And it is the one comparison that crosses the two conventions**, so it is worth
writing out. A Published_Range is inclusive at both ends (`L1.6`, because an empty
archive otherwise has no pair of indices); an Archive_Position is exclusive, being the
next index expected. An archive published as `[0, 99]` and holding all of it therefore
reports `100`, and a report of `99` means it holds through `98` — one block short, and
numerically *equal* to the range end rather than below it. The test is
`next_index > inclusive_end`, not `>=`, and the glossary now fixes the Archived_Prefix's
end as exclusive so this is the only place the two conventions meet.

That first probe is also a free divergence check: a tail whose reported range
disagrees with what the ledger had inferred trips `L3.2`, `L3.3` or `L3.7`
immediately. It covers only the tail, so it does not replace Step 0's Rosetta sync —
but it fires on every existing suite the moment PR 3 deploys, with no operator action,
which the sync cannot claim.

What it cannot do is *clear* anything: per `L3.8` a probe's range never advances the
Archived_Prefix, only halts on it. The probe is a smoke detector, not a
reconciliation.

### `ledger_canister_core::ledger` and `::blockchain` — round selection

Cap the selection at `min(num_blocks_to_archive, one message)` in bytes, in
`Blockchain::get_blocks_for_archiving` (`blockchain.rs:125`) called from
`blocks_to_archive` (`ledger.rs:460`) — both terms local, per the README's constraint that
selection precedes any await (`L6.3`). `take_prefix(remaining_capacity)` still
trims on the cold-start path. Expose the effective per-round count (`L6.4`).

A failed round counts the failure in `ledger_archiving_failures`, the metric the
ledger already exposes, keeps serving the blocks it did not archive, and leaves the
triggering transaction's reply untouched (`L4.5`, `L4.6`).

**A short stop with `at_capacity` false counts as a failed round** (`L4.10`), which
is not obvious because the call *succeeded*. The archive was refused a growth, kept
what fitted and reported so; the round returns `StoredPartial` and no error. Left
outside `L4`, the ledger would then provoke the same refused growth on every
following transaction — precisely the per-transaction retry storm `L4` exists to
stop, reached by a path where nothing ever failed. So the round is marked failed for
spacing and for the failure metric while the reported progress is kept: `L2.2`'s
retry against the same archive still happens, just spaced. A stop at the archive's own
limit is the opposite case and must *not* count — `at_capacity` true is a full archive,
answered by creating the next one (`L2.1`), not by waiting — all of
which the cleanup callback must achieve if the round trapped rather than returned,
which is why the Constraints limit it to a bool and a `u64`.

Splitting large stable-memory work across messages is the platform's own answer to
memory-exhaustion errors, and `L6` does it for the append side; block removal
stays one message per round, so if that proves too much for one message, splitting it
too is the prescription rather than an invention.

**Whether it is too much is unmeasured, and worth measuring before assuming either
way.** `remove_archived_blocks` loops `pop_first()` once per block, so the cost scales
with `min(num_blocks_to_archive, MAX_BLOCKS_TO_ARCHIVE)` — 18,000 at the cap — and it
is listed as a trap source on that reasoning rather than on a number. `L6` shrinks
each round's removal, which probably settles it, but canbench already measures this
class of thing and the figure is cheap to get.

`blocks_to_archive` also carries the skip conditions: the backoff (`L4.1`), the
creation halt (`C1.1`), the capability halt (`L5.1`), the coverage halts
(`L3.2`, `L3.3`, `L3.7`, `L3.9`), the oversized-block halt (`L2.3`) and the
below-range halt (`L4.8`) — all before the guard is taken, so a skipped round costs nothing.

**Only a state that clears without the ledger doing anything belongs in that list.**
Skipping happens before the guard is taken, so a skipped round performs no work at
all — right for a wait, wrong for anything needing an action to clear. Two entries
above are therefore wrong as listed:

| state | in the skip list? |
|---|---|
| backing off (`L4.1`) | **yes** — a wait; time clears it |
| `Started`, no identity (`C1.1`) | **yes** — only an operator clears it |
| coverage halts (`L3.2`, `L3.3`, `L3.7`, `L3.9`) and the below-range halt (`L4.8`) | **yes** — only an operator clears them |
| `L2.3` | **yes** — only an operator clears it |
| `Created(id)` (`C1.8`) | **no** — the round must finish the creation |
| capability halt (`L5.1`) | **no** — the round must issue the probe |

`L5.1` is the same mistake in a second place, and worth naming because fixing the
first did not catch it. An old tail returns no range, so every later transaction exits
at the skip and never issues the probe that `L5.2` and D8 depend on — meaning
upgrading only the archive would never resume archiving, which is the entire scenario
`L5` exists for. Once the backoff permits, that state must enter a **probe-only
round**: no blocks, one empty append, a decision.

The general rule, since this class has now appeared twice: **a state that needs the
ledger to *do* something cannot be expressed as a skip.**

### `ledger_canister_core::runtime` — `Runtime::call`

One call site today, `Call::unbounded_wait` (`runtime.rs:68`), used for every
archiving call including the management-canister ones from `spawn.rs:25, 40`. It gains
a bounded variant so the choice is per call site (`L7.1`, `L7.5`):

| call | wait | why |
|---|---|---|
| `append_blocks` | bounded, ICRC only | idempotent under `A2.4`; ICP exempt per `L7.6` |
| `remaining_capacity` | bounded | read-only, so an unknown outcome is resolved by asking again |
| `update_settings`, adding the controllers | bounded | the ledger is still a controller, so `canister_status` resolves it (`L7.7`) |
| `update_settings`, removing the ledger | bounded | not queryable, but resolvable by *retrying* once the handover is staged — see below |
| `install_code` | bounded | resolvable, see below |
| `create_canister` | **unbounded** | the only genuinely unresolvable one: an unknown outcome leaves a canister nothing can address |

`create_canister` is therefore `L7.5`'s **only** member, which it was not when this
table was first written.

The reasoning behind the three management-canister rows — why the handover is staged,
why both of its steps are bounded, and why `install_code` is resolvable — is the
creation protocol's and lives in
[`../archive-creation/design.md`](../archive-creation/design.md); the table is the
exhaustive reading of it.

An unknown outcome is handled as a failure, which is safe only because the retry is
idempotent (`L7.3`, `L7.4`), and is counted distinctly so D9's timeout can be
revisited. Every row but the last is `L7.7`'s "resolvable by asking again" — reading "again"
as the retry it is, not narrowly as a query — and the last is `L7.5`'s only
exception. The table is the exhaustive reading of both.

## Test plan

*The baseline note, the seams the design owes, what is at risk and what is not
attempted are in the README's **Testing** section; they span the parts.*

| # | level | case | pins |
|---|---|---|---|
| 14 | unit, `ledger_canister_core` | report a tail whose start is above the archived prefix's end; assert the halt and its metric whether or not published ranges happen to cover the gap — there is no recovery left to distinguish | `L3.2` |
| 14c | integration | drive a `BelowRange` report and assert the ledger halts on its own metric, distinct from L4.7's, and sends no further append | `L4.8` |
| 15 | unit, `ledger_canister_core` | report, for an archive, a position that does not reach past the last index of its own Published_Range; assert the halt, that no further block stops being served, and the metric | `L3.3` |
| 15b | unit, `ledger_canister_core` | report an extent *above* the next index the ledger would issue — the ledger-only snapshot restore — and assert the halt and its own metric, distinct from L3.2's and L3.3's. Assert too that a reported extent within the tip does not halt, so the check is not simply refusing progress | `L3.7` |
| 15c | unit, `ledger_canister_core` | answer a probe with a range extending past the archived prefix and assert the prefix does **not** advance; then make the same range the reply to an append that stored or compared blocks and assert it advances only to one past the highest of them — a probe may halt but never advance, and a verifying append advances only as far as it verified | `L3.8` |
| 23g | integration | create a non-genesis archive and assert its first append is accepted, then — with the ledger patched under test to omit the hash — create another and assert the first append into *that* one raises the unverifiable-append counter instead; then patch it to send a wrong hash and assert the first append is refused as a mismatch. The installed value is init-only and has no readback, so the three appends are the observation | `L1.7`, `A1.6`, `A1.8` |
| 15d | integration | make a grow refusal recur so every round comes back `StoredPartial` with `at_capacity = false`; assert attempts are spaced per the backoff and counted as failures rather than repeating per transaction, and that the stored prefix is kept. Assert an `at_capacity = true` stop does *not* space, but creates | `L4.10` |
| 16 | integration | stop the archive so `remaining_capacity` is rejected; count attempts over a window, then restart and assert archiving resumes with no intervention | `L4.1`–`L4.6` |
| 17c | integration | fail a round, then upgrade the ledger; assert the next transaction triggers an Archiving_Round immediately rather than waiting out the spacing | `L4.9` |
| 17l | integration | drive a `ChainMismatch` halt, then run several further transactions and assert no append is sent; upgrade the ledger with the archive unchanged and assert exactly one append is sent and the halt is re-established with its metric; then fix the archive, upgrade again, and assert archiving resumes — the three clearing semantics of one field | `L4.11`, `L4.7`, `L4.9` |
| 18b | integration | after the tail returns no range, assert a later round issues the probe once the backoff permits — no blocks moved, one empty append — rather than skipping every round and never resuming | `L5.1`, `L5.2` |
| 18 | integration | install an old archive wasm as the tail; assert nothing is archived and the metric rises, then upgrade the archive and assert archiving resumes without a ledger upgrade. Repeat against a ledger whose archives do not implement the protocol and assert it archives normally | `L5.1`, `L5.2`, `L5.5` |
| 19 | integration | make the tail archive not answer; assert the round ends within `ARCHIVE_CALL_TIMEOUT` and is retried, and that a subsequent round does not store any block twice. Then, with a call still in flight to that archive, assert the ledger can be stopped and upgraded — the property an unbounded call removes | `L7.1`, `L7.2`, `L7.4`, `L7.8` |
| 20 | integration | count `append_blocks` per round against a configuration that is multi-chunk today; assert one, and that the effective per-round metric matches | `L6.1`, `L6.3`, `L6.4` |
| 22b | integration | drive the ledger into a refusal per A1.1, A2.2, A2.9 and A6.4 in turn; assert it stops attempting rather than backing off, and exposes the distinct metric | `L4.7` |
| 15h | integration | answer with an empty probe and separately with a first-block-too-large `StoredPartial`, both reporting a range beyond the archived prefix; assert the prefix does not advance on either, although both would pass a gate written on outcome arms alone | `L3.8`, `A3.9` |
| 15j | integration | with an archive holding 1000 blocks, re-send only the first 100 and take the wholly-held reply; assert the Archived_Prefix advances to 100 and **not** to the reported 1000, and that the removal count matches — the blocks the comparison at index 99 said nothing about | `L3.8`, `A2.5` |
| 7e | archive | configure `max_memory_size_bytes` below a single block's size and append it with an index; assert nothing is stored, `at_capacity` is true, and `next_index` equals `block_index_offset` — the reply the ledger must halt on | `L2.3` |
| 15e | integration | drive the oversized-block case end to end, on both paths: through an indexed append's `at_capacity` reply, and on a cold start where the `remaining_capacity` pre-check meets an empty tail; assert the ledger halts with its own metric and creates **no** archive on either, and that an ordinary full tail still rolls over — the cases that look identical in the flag alone | `L2.3`, `L2.1` |
| 15f | integration | report, from a non-tail archive, a position below the aggregate Archived_Prefix but matching its own published range; assert no halt. Then report one short of its own range and assert the halt — the false positive that the aggregate comparison produced for every legacy archive | `L3.3` |
| 15l | unit, `ledger_canister_core` | have the tail report an offset one above its published start, and separately have a suite's first archive report a non-zero offset; assert both halt on the distinct metric and the record is unchanged — the start `L1.4` never checks | `L3.9` |
| 15i | unit, `ledger_canister_core` | for an archive published as `[0, 99]`, assert a reported position of `100` does not halt and `99` does — the boundary where the inclusive published range meets the exclusive position, and the one value an off-by-one would miss | `L3.3`, `L1.6` |
| 15g | integration | answer with `BelowRange`, and separately with `Gap`, from appends that carried blocks; assert the Archived_Prefix does not advance on either, then assert it does advance on a wholly-held re-send, and *not* on an empty probe reporting the same range — carrying blocks is not verifying one, and the two zero-stored cases part on `verified` | `L3.8`, `A3.10` |
| 23c | integration | force a mid-round roll-over while PR 3's loops are still in place and assert the created node's first append is **accepted**; then, with the ledger patched under test to capture the round's first block's parent instead, assert the same append is refused as a mismatch — the two behaviours that distinguish a per-creation hash from a per-round one, without reading the field back | `L1.7`, `A1.8`, the per-creation hash above |
| 23 | unit, `ledger_canister_core` | create an archive after a round in which the previous one reported `next_index = N`; assert the new `block_index_offset` is exactly `N`, not `N+1` — `next_index` is *already* one past the last held index, and the off-by-one here is the whole of `L1.1`. Assert `archives()` tiles with no gap or overlap. Then present a node whose reported range starts elsewhere and assert no blocks are stored in it and the metric rises | `L1.1`, `L1.2`, `L1.3`, `L1.4` |
| 24 | integration | on a ledger whose archives report no extent, assert an archive is still created and blocks are still discarded — the exemptions, which a literal reading of L1 and L3 would forbid | `L1.5`, `L3.6` |
| 28 | integration | fill the tail so an append comes back `at_capacity = true`; assert the *next* round creates an archive rather than re-offering to the same one, and that a short stop with `at_capacity = false` instead retries the same archive. This is why the flag exists and nothing else tests it | `L2.1`, `L2.2` |
| 28b | integration | install the tail with no Expected_Parent, as an old ledger would, and make the new ledger's first append into it capacity-shortened; assert the reply carries `at_capacity = true` and `verified = false`, that **no** archive is created on the next round, that the re-send is compared and advances the prefix to the reported position, and only then that the next archive is created — the sequence that otherwise ends in a permanent `BelowRange` halt | `L2.1`, `L3.8`, `A2.9`, `A1.6` |
| 29 | integration | after each round, assert every index the ledger served before it is still retrievable, and that the ledger stopped serving only indices some archive reports covering — the headline safety property, which rows 14 and 15 approach only from their failure sides | `L3.1`, `L3.4` |
| 30 | integration | drive a round that must roll over; assert exactly one archive is created, and that a round which both fills the tail and has blocks left over does not create two | `L6.2` |
| 31 | integration | assert the capability probe stores nothing and consumes no capacity against a live archive, that a second round against an archive that already answered issues no further probe, and that a round which does probe sends at most one empty append | `L5.3`, `L5.4`, `L6.1` |
| 31b | unit, `ledger_canister_core` | send the capability probe to a freshly created archive and take its reply with `next_index == block_index_offset`; assert its `NodeRange` reads empty, `archives()` omits it, and nothing underflows — the `chunk_len - 1` arithmetic the probe would have hit | `L1.6`, `A3.5` |
| 31c | upgrade | decode a pre-change `Archive` with three inclusive legacy ranges and run `post_upgrade`; assert `node_ranges` is filled one per node as `(start, end + 1)`, `archives()` is unchanged, and — with one node's range then set empty — every other node still pairs with its own canister id, which the zipped representation could not guarantee. Repeat with a fourth and a fifth node that have no legacy pair — created, never appended to, as an oversized first block produces — and assert each is padded with an empty record at the third's `next_index` and omitted from `archives()`, so that `node_ranges` has exactly one record per node | `L1.2`, `L1.6`, `L3.9` |
