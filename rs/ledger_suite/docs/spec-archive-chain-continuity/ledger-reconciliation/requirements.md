---
id: DEFI-2967-followup/ledger-reconciliation
title: Ledger Reconciliation And Retries
tags: [ledger, archive, icrc, icp]
---

# Ledger Reconciliation And Retries — Requirements

*Companion to [`design.md`](design.md), and part **L** of the specification whose
overview, glossary, non-goals and constraints are in [`../README.md`](../README.md).
This document is the **behavioural contract**: what the system must do, stated so
that each statement can be tested against the public interface. It is written before
the design and must stay readable without it.*

*Criteria are cited by document prefix: `A` for the archive append protocol, `L` for
ledger reconciliation and retries, `C` for archive creation and handover — so `A2.4`
is criterion 4 of requirement 2 in
[`archive-protocol/requirements.md`](../archive-protocol/requirements.md). Design
decisions are numbered once across the whole specification (D1–D10); each design
document says which it holds.*

## Requirements

*Criteria bind both ledgers except where a criterion exempts the ICP one, which
happens wherever an obligation needs an archive's reported range: the ICP archive is
not changed by this work (README, non-goals). Grouped by behaviour, not by delivery
order: the build order is the README's **Delivery / PR sequence**, and this document is
what PR 3 and PR 4 are checked against.*

### Requirement L1: A New Archive Continues The Previous Archive's Range


**User Story:** As a client developer, I want the archives of a ledger to tile the
block index space without gaps or overlaps, so that reading a range of blocks needs
no special cases.

#### Acceptance Criteria

1. WHEN THE Ledger creates an archive, THE Ledger SHALL set its
   `block_index_offset` to one past the last index the previously created archive
   reported holding.
2. THE ICRC Ledger SHALL publish, through `archives()` and `icrc3_get_archives`, a
   Published_Range for each archive that holds at least one block, such that those
   ranges are contiguous and non-overlapping across all of them, and SHALL report the
   same ranges through both.
3. THE Ledger SHALL derive the offset in L1.1 only from an extent an archive has
   reported, never from a count of blocks it has sent.
4. WHILE an archive exists whose reported Archive_Range does not begin where the
   previous archive's Archive_Range ends, THE Ledger SHALL NOT store further blocks
   in it and SHALL expose a distinct non-zero metric.
5. THE ICP Ledger SHALL derive a new archive's `block_index_offset` from its own
   record instead, and SHALL NOT be held to L1.1, L1.2, L1.3, L1.4 or L1.7, because its
   archives report no Archive_Range to derive one from (per L5.5) and its `archives()`
   returns canister ids without ranges, with no `icrc3_get_archives` to report them
   through — so L1.2 would require an interface change this specification does not make.
6. THE Ledger SHALL omit an archive that holds no blocks from the ranges it publishes
   until that archive stores its first block, because a published range is inclusive
   of both ends and an empty archive has no pair of indices that describes it.
7. WHEN THE ICRC Ledger creates an archive whose `block_index_offset` is above zero,
   THE ICRC Ledger SHALL supply as its Expected_Parent the hash of the block at
   `block_index_offset - 1`, taken from the block it will actually send first rather
   than from the round's first block, because A1.8 binds only an archive that was
   *given* the hash — a ledger that omitted it would leave every fresh archive in A1.4's
   unverifiable window while satisfying every other criterion here.

### Requirement L2: A Ledger Acts On A Reported Capacity Stop

**User Story:** As a canister operator, I want a ledger to act on an archive's capacity
report — rolling over when the archive is full, retrying when it was refused memory — so
that a full archive is replaced, a refused growth is waited out, and neither is mistaken
for the other.

#### Acceptance Criteria

1. IF THE Archive reports `at_capacity` as true, THEN THE Ledger SHALL create a new
   archive on a later Archiving_Round for the blocks above that archive's reported
   Archive_Position — but only once its own Archived_Prefix has reached that position,
   re-offering blocks to the full archive until it has — because a first append stored
   without a check (per A1.6) leaves a prefix the ledger may not yet give up (per L3.8),
   and an archive created above it would put every later offer of those blocks below
   its own range, whereas a re-send is one the full archive compares per A2.9 and so
   verifies.
2. IF THE Archive reports `at_capacity` as false and stopped short, THEN THE Ledger
   SHALL offer the remaining blocks to the same archive on a later attempt.
3. WHEN the next block THE Ledger would archive is on its own larger than the archive
   size it configures or than one inter-canister message per L6.3, or an archive that
   holds no blocks reports `at_capacity` as true,
   THE Ledger SHALL make no further archiving attempt and SHALL expose a distinct non-zero
   metric rather than creating another archive — whether per L2.1 or on a capacity check
   made before any append — because a block that does not fit an empty archive will not
   fit a new one carrying the same configured limit either, and rolling over would create
   one archive per round for as long as transactions kept arriving.

### Requirement L3: No Block Index Ever Becomes Unretrievable


**User Story:** As a client developer, I want every block index the ledger has ever
issued to remain retrievable, so that a history I have already read never develops
a hole.

#### Acceptance Criteria

1. THE Ledger SHALL NOT stop serving a block index unless an archive has reported
   an Archive_Range covering it.
2. WHEN the Tail_Archive reports an Archive_Range whose start is above the end of the
   Archived_Prefix, THE Ledger SHALL make no further archiving attempt and SHALL expose
   a distinct non-zero metric, because the indices between the two are held by the
   tail's predecessors only if the ledger's record is right, and a record that has
   fallen behind the tail's own start is the same wrong record L4.8 halts on from the
   archive's side — so advancing on it would discard blocks that may be held nowhere.
3. IF an archive reports an Archive_Position that is not above the last index of the
   Published_Range THE Ledger publishes for *that* archive, THEN THE Ledger SHALL make
   no further archiving attempt, SHALL discard no further blocks, and SHALL expose a
   distinct non-zero metric, because a Published_Range is inclusive of both ends per L1.6
   while an Archive_Position is the next index expected, so an archive covering its
   published range reports exactly one past that range's last index and anything lower
   leaves a block it is published as holding held nowhere — compared per archive rather
   than against the Archived_Prefix, which every archive but the Tail_Archive ends
   legitimately below.
4. WHEN an Archiving_Round does not complete, THE Ledger SHALL continue to serve
   every index it served before that round.
5. THE Ledger SHALL NOT rely on its own record of what it sent when deciding what
   to stop serving, only on what an archive has reported holding.
6. THE ICP Ledger SHALL rely on its own record instead, and SHALL NOT be held to
   L3.1, L3.2, L3.3, L3.5, L3.7, L3.8 or L3.9, since there is no reported range to
   rely on
   (per L5.5) — the exposure the corresponding non-goal accepts.
7. WHEN an archive reports an Archive_Position above the next block index THE Ledger
   would itself issue, THE Ledger SHALL make no further archiving attempt and SHALL
   expose a distinct non-zero metric, because an archive holding indices the ledger has
   never issued was built from a chain the ledger is no longer on, which neither L3.2
   nor L3.3 detects.
8. THE Ledger SHALL extend the Archived_Prefix only as far as one past the
   highest-indexed block of an append the receiving archive reports per A3.9 as checked
   — stored after a parent check against a block it held or its Expected_Parent, or
   compared per A2.9 — and never as far as the Archive_Position that append reported,
   because an append that verified nothing — an empty one per A3.5, a gap per A2.2, one
   falling wholly below the archive's range per A2.6, or the unverifiable first append
   of A1.6 — is no evidence at all, while one that verified a block at index N is
   evidence only about the indices at and below N, a hash chain propagating a divergence
   forward rather than backward, so blocks the archive holds above N remain
   uncompared.
9. WHEN any archive, the Tail_Archive included, reports a `block_index_offset` that
   differs from the start of the Published_Range THE Ledger publishes for it — or, for an
   archive that holds no blocks yet, from the offset L1.1 derived for it, which is zero
   for the first archive a suite ever has — THE Ledger SHALL leave its record as it
   stands, make no further archiving attempt, and expose a distinct non-zero metric,
   because an offset is fixed for the life of the canister, so the report and the record
   cannot both be right, and rewriting the start from the report would leave every index
   between the two held nowhere.

### Requirement L4: Archiving Attempts Are Bounded While Archiving Fails


**User Story:** As a canister operator, I want a ledger to stop retrying archiving
on every transaction once it is failing, so that a persistent cause costs a probe
per interval rather than work per transaction.

#### Acceptance Criteria

1. WHILE archiving has failed at least once and not since succeeded, THE Ledger
   SHALL NOT begin an Archiving_Round sooner than BACKOFF_INITIAL after the last
   attempt.
2. WHEN archiving fails on consecutive attempts, THE Ledger SHALL increase the
   spacing between attempts up to BACKOFF_CAP and SHALL NOT increase it beyond
   BACKOFF_CAP.
3. WHEN an Archiving_Round succeeds after failures, THE Ledger SHALL return the
   spacing to no delay.
4. WHEN a cause of failure ceases, THE Ledger SHALL resume archiving without
   operator action, because the storage pressure that prompted this work cleared on
   its own in about four and a half hours and an operator-gated recovery would have
   outlasted it.
5. WHEN an Archiving_Round fails in a way THE Ledger observes, THE Ledger SHALL
   count the failure in the metric it already exposes for archiving failures, SHALL
   continue to serve the blocks it did not archive, and SHALL reply to the
   triggering transaction as it would have had archiving succeeded — a failure that
   instead ends the round's execution is the subject of the corresponding non-goal.
6. WHEN an Archiving_Round fails, THE Ledger SHALL NOT prevent a later
   Archiving_Round from being attempted.
7. WHEN an archive refuses an append on any ground in A1, or per A2.2, A2.9 or A6.4,
   THE ICRC Ledger SHALL make no further archiving attempt and SHALL expose a distinct
   non-zero metric, rather than spacing further attempts per L4.1, because no retry can
   resolve a mismatch of chain or position or a block the archive cannot parse — while
   THE ICP Ledger, whose archive reports no outcome and can only reject, treats every
   reject as a failure under L4.1 and L4.5, the exposure the README's non-goal accepts.
8. WHEN an archive reports per A2.6 that the blocks offered fall below its own range,
   THE Ledger SHALL make no further archiving attempt and SHALL expose a distinct
   non-zero metric, separate from L4.7's, because once A2.9 compares the held prefix of a
   straddling append this can no longer follow from a lost reconciliation, leaving only a
   ledger whose record of what it has archived is wrong — a restored snapshot, or a suite
   that had already diverged — which is a different investigation from a fork and one no
   retry can resolve.
9. WHEN THE Ledger is upgraded, THE Ledger SHALL permit the next Archiving_Round
   immediately rather than observing the spacing L4.1 would otherwise require, because
   an upgrade is how an operator resumes after a halt and is usually the fix for
   whatever caused the failure.
10. WHEN an archive stops short of storing every block it was offered and reports
   `at_capacity` as false, THE Ledger SHALL treat the Archiving_Round as failed for the
   purposes of L4.1, L4.2 and L4.5 while keeping the progress the archive reported,
   because
   the call itself returned successfully and without this the refused growth would be
   provoked again by every later transaction rather than waited out by L2.2's retry.
11. WHILE a halt per L2.3, L3.2, L3.3, L3.7, L3.9, L4.7, L4.8 or C1.14 holds, THE Ledger
   SHALL attempt no Archiving_Round until it is next upgraded, and SHALL re-establish
   the halt from the first reply after that upgrade if the cause persists, because each
   of these is learned from one reply and re-derivable from the next, so forgetting it
   on upgrade costs one attempt — exactly the lever L4.9 grants an operator — whereas
   C1.1's cause cannot be re-derived and so survives an upgrade per C1.4.

### Requirement L5: A Ledger Will Not Archive Against An Archive That Cannot Report Its Range


**User Story:** As an operator of a third-party ledger suite, I want a ledger that I
have upgraded ahead of its archives to stop archiving rather than continue
unprotected, so that I find out from a metric instead of from a corrupted archive.

#### Acceptance Criteria

1. WHILE the Tail_Archive does not report an Archive_Range when asked per A3.5, THE
   ICRC Ledger SHALL move no blocks to any archive and SHALL expose a distinct
   non-zero metric, while still being able to ask again per L5.2.
2. WHEN the Tail_Archive begins reporting an Archive_Range, THE ICRC Ledger SHALL
   resume archiving without operator action and without being upgraded.
3. THE ICRC Ledger SHALL determine whether the Tail_Archive reports its range
   without storing any blocks in it, because learning this from an ordinary append
   would mean the blocks were already stored by the time the answer arrived.
4. THE ICRC Ledger SHALL NOT repeat the determination in L5.3 on every
   Archiving_Round once an archive has reported its range, except for one determination
   after an upgrade, because the answer is held in state an upgrade discards and asking
   again is one empty append that stores nothing — the same allowance L4.9 makes for the
   backoff, and for the same reason.
5. THE ICP Ledger SHALL continue archiving against an archive that reports no
   Archive_Range, and SHALL expose a distinct count of how often it does so,
   because its archives do not implement A2 or A3 and halting would stop ICP
   archiving permanently.

### Requirement L6: An Archiving Round Makes One Append


**User Story:** As a reviewer of ledger behaviour, I want a round to be a single
append to a single archive, so that there is one question about whether it landed
rather than several.

#### Acceptance Criteria

1. THE Ledger SHALL send at most one block-carrying `append_blocks` per
   Archiving_Round, and at most one carrying no blocks, so that the probe of L5.3 is
   bounded too rather than left outside the count.
2. THE Ledger SHALL create at most one archive per Archiving_Round.
3. THE Ledger SHALL choose the blocks for an Archiving_Round so that they fit one
   inter-canister message, measured in bytes rather than counted in blocks,
   because block sizes vary and a count cannot guarantee a fit.
4. THE Ledger SHALL expose the number of blocks an Archiving_Round is permitted to
   carry, so that the enforced value is observable rather than only the configured
   one.

### Requirement L7: A Ledger Does Not Wait Indefinitely For An Archive


**User Story:** As a canister operator, I want archiving to still be possible on a
subnet that is short of memory, so that the shortage which stopped archiving does not
also block the calls needed to get it going again.

#### Acceptance Criteria

1. WHEN THE ICRC Ledger sends an Indexed_Append, THE ICRC Ledger SHALL stop
   waiting for a response after at most ARCHIVE_CALL_TIMEOUT.
2. WHEN THE ICRC Ledger stops waiting per L7.1, THE ICRC Ledger SHALL treat the
   Archiving_Round as failed per L4, so that a call that never answers costs a
   backoff interval rather than blocking archiving indefinitely.
3. THE ICRC Ledger SHALL NOT treat a response it stopped waiting for as evidence
   that the archive stored nothing, because the archive may have stored the blocks
   and answered after the wait ended.
4. WHEN THE ICRC Ledger stopped waiting for an append the archive did in fact
   store, THE ICRC Ledger SHALL converge on that archive's reported extent on a
   later Archiving_Round without any block being stored twice, per A2.4 and A3.1.
5. THE Ledger SHALL NOT stop waiting for a call whose unknown outcome it has no
   means of resolving afterwards, because an unresolvable unknown outcome is the
   state C1 exists to detect and bounding such a call would make it routine
   rather than exceptional.
6. THE ICP Ledger SHALL wait unboundedly for an append, because its archives do
   not satisfy A2 and a retry against them would store the blocks a second
   time (per L5.5).
7. WHEN THE Ledger makes any other call to an archive whose unknown outcome it can
   resolve by asking again, THE Ledger SHALL likewise stop waiting after at most
   ARCHIVE_CALL_TIMEOUT, while its calls to the management canister stay unbounded,
   because those happen once per archive fill and are answered within a round, so
   bounding them buys nothing that L7.1's reservation argument measures.
8. WHILE an archive is not answering a call THE ICRC Ledger made to it, THE ICRC Ledger
   SHALL still become stoppable within ARCHIVE_CALL_TIMEOUT, because an outstanding
   callback otherwise prevents the ledger being stopped and therefore being upgraded —
   and an upgrade is the operator's lever for every other halt in this document — the
   calls this does not cover being those to the management canister, which L7.7 keeps
   unbounded and C1 reconciles or halts on instead.
