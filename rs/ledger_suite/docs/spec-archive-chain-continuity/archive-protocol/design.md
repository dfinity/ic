---
id: DEFI-2967-followup/archive-protocol
title: Archive Append Protocol
tags: [ledger, archive, icrc, icp]
---

# Archive Append Protocol — Design

*Companion to [`requirements.md`](requirements.md), and part **A** of the specification;
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

*Decisions are numbered across the whole specification. This part holds D4 and D5;
D1–D3 and D6–D9 are in the ledger design, D10 in the README.*

### D4 — Placement is decided before the chain is checked, and the prefix length is clamped

Serves `A1.3`, `A2.3`, `A2.5`. The order is load-bearing in two directions.
On a re-send the batch's first block does not continue the archive's tip — it
continues one of the archive's own earlier blocks — so checking the chain first would
trap on precisely the re-send `A2.4` makes harmless. And the prefix length is
unsigned:

    // reached only where offset <= i <= offset + log_length
    k = min(offset + log_length - i, blocks.len())   // leading blocks to skip
    append blocks.iter().skip(k)                     // saturating
    report offset + log_length                       // re-read AFTER the append (A3.2)

The upper clamp is reachable through a varying batch size alone — 1000 blocks stored,
the reconciliation lost, then a smaller message — and without it the slice panics.
The lower bound underflows if `i` is above the archive's position, which is the
`A2.2` branch, so computing `k` only inside the middle branch is what keeps it in
range; inverting the order would turn a gap into a wrapped `k` and an append at the
wrong offset, which is silent rather than loud. `skip` rather than `blocks[k..]`
makes the clamp structural.

### D5 — An indexed append never refuses *on protocol grounds* by trapping

Serves `A6.1`, `A6.2`. This is about the refusals the archive *decides* — chain,
placement, decoding, its own capacity limit — not about the storage refusals that
terminate its execution before it can decide anything, which `A4.5` excludes and the
README's constraints describe. Forced by the constraint that a trap discards its
counter: the chain mismatch is the condition an operator most needs to see, being an
invariant violation rather than an expected outcome, so it is exactly the wrong thing
to make invisible. The cost is that atomicity becomes ordering-plus-test rather than
platform-enforced — the check runs before any append and `A1.2` pins it. An
index-less append still traps, per `A5.2`.

This is why `append_result` has a `ChainMismatch` arm: the decision not to trap is
only realisable if there is something to return. `A2.9`'s refusal shares it.

## Implementation

### `ic-icrc1-archive` — `append_blocks`

    type append_outcome = variant {
      Stored;                                      // all it did not already hold: A2.1, A2.3, A2.4, A3.5, A3.8
      StoredPartial;                               // a prefix; at_capacity says why: A4.1, A4.6
      BelowRange;                                  // A2.6
      Gap;                                         // A2.2
      ChainMismatch : record { at_index : nat64 };  // every chain ground of A1, and A2.9
      Undecodable   : record { at_index : nat64 };  // A6.4
    };

    type append_result = record {
      block_index_offset : nat64;
      next_index         : nat64;
      verified           : bool;    // A3.9 — what L3.8's gate reads
      at_capacity        : bool;
      outcome            : append_outcome;
    };

    append_blocks : (vec blob, opt nat64) -> (opt append_result);

The new argument and the result are optional — the `vec blob` is required, as it is
today — which is what makes the archive releasable alone. The reply's first field is named `block_index_offset`, matching
the published `init` argument it reports, rather than `start_index` — the request's
second argument is the index the *batch* starts at, and one word cannot mean both.

**`Stored` is a post-condition, not a count** (`A3.8`): *every block you offered
that I did not already hold, I now hold*. Three cases satisfy it — a clean
continuation (`A2.1`), a straddling append where the leading blocks were already
held and only the suffix was stored (`A2.3`), and the empty probe, where there were
none (`A3.5`). They share an arm because the ledger's response to all three is
identical: reconcile against `next_index`. How much the archive already held is
not something the ledger acts on — it is visible from `next_index` for anyone who wants
it — which is the division `A3.6` asks for, the outcome naming the *action* rather
than the effort.

**A wholly held re-send is `Stored` too** (`A2.4`), for the same reason: the archive
holds every block offered, and the ledger's response is again to reconcile against the
reported position. It compared the last of them per `A2.9`, which matters to
`L3.8`'s gate — but that does not need an arm of its own, as the ledger design's
`send_blocks_to_archive` section shows.

`StoredPartial` is the one that breaks the post-condition, and that is exactly why it
is separate: blocks were offered, not already held, and still not stored. `A3.7`
counts *fewer than all* rather than *some*, so the zero-stored case of `L2.3` lands
here and not in `Stored` — which matters, because `L3.8`'s gate relies on it.

`StoredPartial` exists because `at_capacity` cannot carry that distinction on its
own (`A3.7`): a growth the platform refused reports `at_capacity = false`
(`A4.4`) and so does a complete append (`A4.7`), so `Stored` plus a false flag
would have described both and left the ledger comparing `next_index` against what it
sent — exactly what `A3.6` promises it never has to do. With the outcome split,
`at_capacity` answers only "why did it stop", never "did it stop".

**A record, not a variant, because the range is unconditional.** `A3.1` requires
the offset and position on *any* answer and `A3.3` requires one meaning in every
outcome of `A2` — a variant whose refusing arms carried only their own fields
satisfied neither, and left `A2.6` distinguishable from an ordinary success only by
the ledger re-deriving it from what it sent. Hoisting the range out and demoting the
outcome to a field makes `A3.3` literally true and `A3.6` free.

`ChainMismatch` carries the index at which the divergence was found and serves
*every* chain ground of `A1` — `A1.1` at the tip, `A1.5` for a parentless block
offered anywhere but index zero, `A1.7` inside the batch, `A1.8` against a fresh
archive's Expected_Parent — plus `A2.9` inside a range already held. Deliberately
"every ground of A1" rather than a list, so that adding a ground does not silently
leave it without an arm. One arm for all of them because the ledger's response is the
same — halt per `L4.7` — while `A6.1`'s separate counters give the operator the
distinction that matters to them. That is D5's division of labour: type what the ledger acts on, count
what an operator diagnoses. `Undecodable` exists because decoding on append is new —
the current implementation stores opaque bytes and never parses them — so a block the
archive cannot parse is a failure mode this design introduces and must answer for.

Order of work, per D4 and D5:

1. Caller check, unchanged.
2. If the batch is empty **and carries an index**: reply per `A3.1`-`A3.4` and
   stop. No placement, no chain check, no counter (`A3.5`, `A6.5`). This is the
   capability probe of `L5.3`, and short-circuiting is what keeps a probe sent at
   an index above the archive's position from being counted as a gap.
3. If the index is absent, skip **steps 4 and 5 only** — there is no index to place,
   so the batch is treated as continuing the tip, `k = 0`. Steps 6 onward still
   apply, and any refusal fails the call instead of returning a description of it
   (`A5.1`, `A5.2`). An index-less batch that is *also* empty therefore falls
   through to here rather than to step 2: it stores nothing and replies empty, and
   steps 6 and 7 are no-ops because there is no block to check or store.
4. Place the index against `block_index_offset` and `block_index_offset +
   log_length` (`A2.1`, `A2.2`, `A2.6`), returning without appending in the
   refusing cases.
5. Compute `k` and the suffix per D4. If `k > 0` — the batch overlaps blocks already
   held, whether wholly or as a leading prefix — compare `blocks[k-1]` against the
   stored block at that index and return `ChainMismatch` on a difference (`A2.9`).
   One comparison suffices rather than sampling: blocks are hash-chained, so a
   divergence at or below that index propagates forward to it and cannot heal — if the
   last covered block matches, every block below it does. Doing this for a *straddling*
   append and not only a wholly held one is what makes a re-send into a full archive
   verify something (`A3.9`), which is the case that otherwise strands the ledger —
   see `BelowRange` in the ledger design's `send_blocks_to_archive` section.
6. Determine which blocks will actually be stored — the suffix from `k`, trimmed to
   what fits the archive's own configured limit — and then chain-check **only those**:
   `blocks[k]` against the tip, or against the Expected_Parent when the archive holds
   nothing and was given one (`A1.1`, `A1.3`, `A1.4`, `A1.5`, `A1.8`), then each
   subsequent stored block against its predecessor (`A1.7`). A first stored block that carries *no* parent hash is
   refused unless it lands at global index zero (`A1.5`) — the genesis block belongs at
   zero or nowhere, and an empty archive with a non-zero offset and no Expected_Parent
   has no other way to tell. Conversely, a block landing at global index zero must carry
   *no* parent (`A1.10`) — the converse of
   `A1.5`, and not implied by it: `A1.5` says where a parentless block may go,
   while without `A1.10` an append declared at zero into an empty archive given no
   Expected_Parent would put a parented block at the genesis position and never be able
   to tell. Capacity is decided
   before validation, not after, because `A1.7` binds the blocks it *stores*: a
   block beyond the limit is never stored, so refusing the whole append because that
   block is malformed or does not chain would contradict `A4.1`, which requires the
   prefix to be stored and the stop reported. The second half
   is one hash per stored block, which is what makes `A2.8` a property the archive
   enforces rather than one it inherits from the sender — worth the cost precisely
   because the rest of this design exists to stop trusting what the ledger asserts.
7. Append the suffix. **For an indexed append**, stop short where it must
   (`A4.1`, `A4.2`, `A4.6`) and report `at_capacity` false whenever nothing stopped
   short (`A4.7`). **For an index-less one it is all-or-nothing** (`A5.5`): if
   the whole batch does not fit, store none of it and fail the call, which is what the
   archive does today. Partial progress is only safe for a caller that can be *told*
   it was partial — an index-less caller gets an empty reply, reads success as the
   whole batch, and removes all of it, so a stored prefix would leave the suffix in no
   archive and no longer served by the ledger. That is the one case where rolling back
   what was stored is the safe act rather than the wasteful one, which is why
   `A4.2` is scoped to indexed appends. Note the one
   wasted round this leaves: an archive that stores its last block exactly fills, still
   answers false, and is found full on the next round — which then spawns. Two
   different stops, and only one of them depends on the platform. `A4.1` is the
   archive comparing the next block's size against its own configured limit and its
   own usage, so it stops *before* asking for memory and cannot be refused — this is
   the routine case, reached once per archive fill — and on *every* fill once the
   `remaining_capacity` pre-call is replaced by the reported `at_capacity`, per
   `L2.1` and `L2.2` and the ledger design's `node_and_capacity` section.
   `A4.6` is a grow the archive did ask for and was refused; `StableLog::append`
   returns a `Result`, so the current `unwrap_or_else(|_| trap("no space left"))` is
   the archive's own choice and can be handled — but only for the refusals that
   reach it, which is what `A4.5` bounds; see the README's Constraints.
8. Re-read `log_length` and reply (`A3.1`-`A3.4`) — or, if step 3 applied, reply
   `None` (`A5.1`), having already failed the call at whichever of steps 6 and 7 met
   a refusal (`A5.2`, `A5.5`). Step 3 is the whole index-less path, valid appends
   included, so "fail if step 3 applied" would fail every old ledger's every append; the
   failure belongs to the refusal, not to the path.

**Three ordering traps in this list, every one of which has been fallen into.**

*Step 3 says "steps 4 and 5 only" for a reason.* An index-less append is the only
shape PR 1 sees in production, so skipping the chain check along with placement would
make PR 1 a no-op against the corruption it exists to stop.

*Capacity is decided before validation for a reason.* Validating a block the archive
was never going to store, and refusing the append because of it, denies `A4.1` the
prefix it requires — see step 6. `A1.9` states it as an obligation.

*Step 2 is scoped to an indexed batch for a reason.* Written to catch the empty batch
first, it also catches an **index-less** empty one and answers it with a result —
which `A5.1` forbids, and which the already-written
`test_empty_append_blocks_is_accepted_and_stores_nothing` would fail, since it sends
the one-argument shape and asserts the reply reads as absent. The index test has to
come first for an index-less caller, and the empty test first only within the indexed
path.

**Step 7 is a restructuring, not a reuse.** The current check is whole-batch and
traps: it sums every block's size and compares against `max_memory_size_bytes`
(`icrc1/archive/src/main.rs:242`), then traps inside the append loop if a grow
fails. `A4.1` needs a fitting *prefix* instead — append while the next block
still fits — and `A4.2` forbids unwinding what fitted. The distinction
`at_capacity` reports (`A4.3` versus `A4.4`) is then whichever stopped the
loop: the archive's own limit, computed per block, or a failed grow. Keeping the
all-or-nothing form would satisfy neither criterion.

A block that fails to decode is counted distinctly (`A6.4`). Both
`trap("no space left")` sites are replaced.

### `ic-icrc1-archive` — `init`, and the Expected_Parent

    service : (principal, nat64, opt nat64, opt nat64, opt blob) -> { ... }
    //                                                  ^^^^^^^^ new: Expected_Parent

A fifth optional `init` argument, the hash the archive should expect as the parent of
the first block it stores (`A1.8`). It closes the last place where a stored block
goes unchecked.

**Why nothing else can close it.** The declared index verifies *position* and the
chain check verifies *content*, and for a non-empty archive that covers both. An
**empty** archive has no tip, so content is unverifiable — `A2.1` will accept a
first append whose index is right whatever the blocks actually are. That is the hole
`A1.4` documents, and it is the seat of the original corruption: a node created
for one index, then handed blocks from a different chain state. Supplying the parent
at creation gives the archive a tip before it has one, and makes the invariant
plain — **once every ledger supplies the hash, the only block ever stored without a
parent-hash check is genesis**. Until then there is one other, and it is deliberate: the
first index-less append into an empty archive given no Expected_Parent is accepted
whatever its first block's parent (`A1.4`), because there is nothing to compare it
against and refusing would halt every old ledger at every roll-over; `A1.6` counts it so
the window is visible while it lasts.

**What it does and does not catch.** It catches the case where creation and first
append see *different* ledger states: the roll-over corruption, and a ledger restored
from a snapshot between the two. It does not catch a ledger that had already forked
before it created the node, since such a ledger would declare the forked parent and
then send the matching forked block — consistently wrong. That is the residual the
Rosetta precondition exists for.

**It is not redundant with the index, but it does arrive with the same release.** A
ledger that cannot send an index cannot supply the hash either, since both come from
the same ledger version — so this buys nothing during the archive-only release, and
`A1.4`'s window stays open for the ICP ledger and for third-party suites that
upgrade only the archive. `A1.6` counts exactly those.

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
reach the `Encode!` at `archive.rs:463-468`. Same boundary as D6's (ledger design), and for the same
reason.

**It is one hash per creation point, not one per round** (`L1.7`). Capturing the parent of the
round's *first* block once would be wrong wherever a round creates a node after already
sending earlier chunks — the new node's first block is then the deque front, not
`blocks[0]`, so it would be initialised with a parent it will never see and would refuse
its first entirely valid append, permanently (`A1.8`). That shape is live in PR 3,
whose loops are still the current ones because `L6` lands in PR 4.

Fortunately the ledger can compute it for any position without decoding anything:
`BlockType::block_hash` is an associated function over the *encoded* block
(`ledger_core/src/block.rs:110`), so the parent of the block at position `k` is
`block_hash(&blocks[k-1])` for any `k > 0`, and only position 0 needs the decoded
`parent_hash()`. Precompute the round's hashes in `archive_blocks<LA>` where the block
type is known, thread them down beside the blocks, and each creation takes the entry for
whatever is then at the front. Once `L6.2` limits a round to one creation the vector
degenerates to a single value, so this costs nothing afterwards — but the per-position
form is what makes PR 3 correct on its own, which is the ordering that matters.

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
the same tolerance `A5` rests on. `archive.did` gains the second argument and the
result type, both `opt` and so compatible in either direction; verify the whole of it
with `didc` and the CI Candid check rather than by inspection.

### `ic-icrc1-archive` — `encode_metrics`

One counter per ground enumerated in `A6.1`, which is the whole list — the five
chain grounds of `A1` separately (`A1.1`, `A1.5`, `A1.7`, `A1.8`, `A1.10`), `A2.2`, `A2.6`,
`A2.9`, `A4.3`, `A4.4`, `A6.4` and `A1.6`. The archive exposes none of these today, so all of them are new.

**Separately, because the grounds localise a divergence differently.** `A1.1`
means the blocks offered do not continue the archive's last block; `A2.9` means a
range it already holds was re-sent with different content, which points at a ledger
that has been rolled back; `A1.8` means a fresh archive was handed blocks from a
different chain state than the one it was created for. One mismatch counter would
collapse three different investigations into one number.

Two of them are not faults and should not read as such. `A1.6` counts a *success* —
the append the archive could not verify — and should read zero once every ledger
supplies an Expected_Parent, and `A4.3` is normal operation: archives fill up. The
chain grounds, the gap, `A2.6` and `A6.4` are conditions an operator should act on —
`A2.6` included, since once `A2.9` compares straddling appends it can only mean the
ledger's record is wrong (`L4.8`). An empty append is counted by none of them (`A6.5`), and all of them commit,
because D5 removed the traps.

## Test plan

*The baseline note, the seams the design owes, what is at risk and what is not
attempted are in the README's **Testing** section; they span the parts.*

| # | level | case | pins |
|---|---|---|---|
| 1 | archive | append a valid range, re-append it, assert nothing stored and every index still resolves to its own block | `A2.4`, `A2.7`, `A2.8` |
| 2 | archive | append a batch whose first block does not continue the tip; assert refusal and unchanged extent | `A1.1`, `A1.2` |
| 3 | archive | install with `block_index_offset = N+1000`, append at `N`; assert nothing stored and `block_index_offset = N+1000` reported. Then append `N+1000..N+1999` so the node is non-empty, re-send at `N`, and assert the reply still reports offset `N+1000` but `next_index = N+2000` — the two fields are indistinguishable on an empty node and must not be conflated | `A2.6`, `A3.1`, `A3.3` |
| 4 | archive | append `N..N+499`, then `N..N+999`; assert the extent becomes 1000 not 1500, every index resolves, and the chain check did not refuse on the covered prefix. Then re-send `N..N+999` from a chain forked at `N+200` and assert `ChainMismatch` — the covered prefix is compared, not skipped | `A2.3`, `A1.3`, `A2.9` |
| 4b | archive | fill an archive so its last stored block is `T`; send `T-9..T+9` at `T-9` and assert nothing is stored, `at_capacity` is true, and `verified` is **true** with the comparison at `T` — the straddling-into-full case that used to verify nothing | `A2.9`, `A3.9`, `A4.1` |
| 5 | archive | append 1000 blocks, then re-append the first 600; assert success, nothing stored, extent unchanged — the case a plausible implementation panics on | `A2.5` |
| 6 | archive | append at an index above the position; assert a gap and nothing stored | `A2.2` |
| 7 | archive | size `max_memory_size_bytes` so a batch only partly fits; append it **with an index** and assert a short `next_index`, `at_capacity = true`, and that the blocks that fit are readable | `A4.1`, `A4.2`, `A4.3` |
| 7b | archive | the same over-large batch **without** an index; assert the call fails and the archive holds exactly what it held before — the partial store that would make the suffix unretrievable | `A5.5` |
| 7c | archive | assert a complete append and a partial one are distinguishable from the reply alone: the first reports the whole-batch outcome, the second the partial one, and neither is told apart by `at_capacity` — which reads false for a complete append and for a platform-refused stop alike | `A3.6`, `A3.7` |
| 8 | archive | **partly written**: `test_empty_append_blocks_is_accepted_and_stores_nothing` already asserts an empty append stores nothing and consumes no capacity, on both the one-argument and null-index shapes. Extend it against the new implementation to assert an *indexed* empty append reports an extent, that an indexed empty append above the archive's position is neither refused nor counted, and that both index-less empty shapes still reply **empty** — the last of these is what fails if the empty check is ordered before the index check | `A3.5`, `A5.1`, `A6.5` |
| 9 | archive | genesis into an empty archive with offset 0; then assert a block with no parent hash is refused by an archive whose offset is non-zero, and by one that already holds blocks. Then the converse: into an empty archive with offset 0 and no Expected_Parent, append at index 0 a block that *does* carry a parent, and assert it is refused — the non-genesis block a check on A1.5 alone admits at index zero. And declare a parentless block at index 5 into an empty offset-0 archive and assert it is refused — genesis lands at zero or nowhere | `A1.5`, `A1.10`, `A2.2` |
| 9b | archive | install with no Expected_Parent, append into it, and assert it is stored and the unverifiable-first-append counter rises | `A1.4`, `A1.6` |
| 9c | archive | install with an Expected_Parent, then append a first batch whose first block carries a different parent; assert refusal and that nothing is stored. Then append one that matches and assert it is stored and the counter in A1.6 does *not* rise | `A1.8`, `A1.6` |
| 10 | archive | **written, and retired by PR 1**: `test_append_blocks_ignores_an_extra_optional_start_index` — the current one-argument archive stores the blocks, ignores the extra argument, and its empty reply reads as absent; a wrong-typed payload is rejected as a negative control. Its `Decode!(.., Option<u64>)` stops describing the archive the moment the new implementation returns `opt append_result` (`A3.1`), so row 11 replaces it rather than extending it. The ICP twin in row 12 stays valid indefinitely, which is why only that one is a release gate | the rollout premise, pre-PR-1 only |
| 10b | unit, candid | **written**: `test_old_ledger_decodes_new_archive_reply_as_unit` (`icrc1/archive/tests/tests.rs`) — encodes `(None::<append_result>,)` and decodes it as `()` the way the old ledger's `candid_tuple::<()>()` does; asserts success, and that undeclared trailing bytes still fail, so the surplus absent `opt` really is being consumed as `Reserved` by `done()`. This is the premise that lets the archive ship before the ledger | `A5.1`; a **release gate** |
| 11 | archive | against the new implementation: one argument only; assert blocks stored, empty reply, and that a chain mismatch traps rather than returning a refusal | `A5.1`, `A5.2`, `A5.3`, `A5.4` |
| 12 | archive | **written**: `should_ignore_an_extra_optional_start_index` (`icp/archive/tests/tests.rs`) — the ICP archive's hand-rolled decode tolerates the extra argument, capacity drops by the block size, and the empty reply reads as absent | D3's tolerance; a **release gate** |
| 13 | archive | on indexed appends, assert each counter in `A6.1` moves for its own cause and is readable afterwards; then drive the same refusals index-less and assert the call fails and no counter moved — the trap that keeps them uncountable | `A6.1`, `A6.2`, `A6.3`, `A6.4`, `A5.2` |
| 14b | integration | reproduce the fill-plus-lost-reconciliation sequence end to end: fill the tail, drop the callback, re-send; assert the prefix advances on the compared block, the next archive is created at the reported end, the following batch lands there at its offset, and no `BelowRange` ever occurs | `A2.9`, `L3.8`, `L2.1` |
| 7d | archive | offer a batch whose second block exceeds the configured limit and, in turn, either does not chain or does not decode; assert in both cases that the first block is stored, the stop is reported, and the append is neither refused nor counted — the block was never going to be stored | `A1.9`, `A4.1`, `A6.4` |
| 17h | unit, `ic-icrc1-archive` | decode a pre-change `ArchiveConfig` from CBOR bytes captured before this change and assert it decodes with the new field absent — a struct-level test, since the field is init-only and has no public readback — so PR 1 is not the release that breaks every archive's first upgrade | the `#[serde(default)]` above |
| 22 | archive | append `0..999`; then re-send `500..999` from a chain that diverges at 701, and assert `ChainMismatch` is returned, nothing is stored, and the covered-range counter rises while the tip-mismatch counter does not. Then re-send a range that does *not* diverge and assert success — so the check is not simply refusing every re-send | `A2.9`, `A6.1` |
| 22c | archive | append a batch whose first block continues the tip but whose fifth does not continue the fourth; assert `ChainMismatch` at that index and that nothing was stored — the case a first-block-only check accepts | `A1.7` |
| 22d | archive | append a batch containing bytes that do not decode as a block; assert `Undecodable` is returned with its index, nothing is stored, and its counter rises separately from the mismatch counters | `A6.4` |
| 22e | archive | assert every outcome of A2 carries the same `block_index_offset` and `next_index` fields, and that `at_capacity` is false on a full store and on a wholly-covered re-send | `A3.1`, `A3.3`, `A3.6`, `A4.7` |
| 22f | archive | assert a clean continuation, a straddling append and an indexed empty probe all report the same outcome, that a capacity-shortened append reports a different one, and that a wholly held re-send reports its own — the post-condition `Stored` names, and the one exception to it | `A3.8`, `A3.7` |
| 15m | integration | install the tail with no Expected_Parent, as an old ledger would, then send the first batch from the new ledger; assert `verified` is false, the unverifiable counter rises, and the Archived_Prefix does **not** advance — a stored block that was checked against nothing is not evidence | `A3.9`, `L3.8`, `A1.6` |
| 7f | archive | append starting exactly at the Archive_Position but overflowing the configured limit; assert a prefix is stored and the stop reported rather than the whole batch — the A4 exception to an otherwise unconditional A2.1 | `A2.1`, `A4.1` |
| 26 | archive | constrain growth so an append stops short for a reason other than the archive's own limit, using a route that **returns** control — the wasm's declared stable maximum, or a subnet memory cap — and assert `at_capacity` is reported false and the blocks that fit are readable | `A4.4` |
| 26b | archive | induce a reservation refusal with a low `reserved_cycles_limit`; assert the call is rejected, that nothing was stored, and that the ledger takes the graceful path — the negative case that fixes what `A4.5` gives up | `A4.5` |
| 27 | matrix | both token variants for every archive-level row: 1-9, 9b, 9c, 10, 11, 13, 22, 22c, 22d, 22e, 26 and 26b — (12) is ICP-only by nature, and 22b, 25 and 28-31 are integration rows | yes |
