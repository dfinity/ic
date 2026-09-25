---
id: DEFI-2967
title: Archive chain continuity and bounded archiving retries
tags: [ledger, archive, icrc, icp]
---

# Archive Chain Continuity And Bounded Archiving Retries — Requirements

*Companion to [`design.md`](design.md). This document is the **behavioural contract**:
what the system must do, stated so that each statement can be tested against the public
interface. It is written before the design and stays readable without it.*

## Introduction

A ledger keeps only its most recent blocks and moves older ones to archive canisters.
Because an archive is a separate canister, the move is an inter-canister call whose two
halves commit independently: the archive commits the blocks when its message ends, and
the ledger records *that* it did so in a later message of its own. If that later message
fails, the blocks are in the archive and the ledger does not know it, so its next attempt
sends them again. `append_blocks` carries no indication of where its blocks belong, so
the archive cannot tell the re-send from a continuation and appends them a second time.
Every index above that point then shifts, permanently and silently, because an archive
maps a global index to its storage by a fixed offset chosen at creation.

Two clients are harmed differently. Rosetta checks each block's parent hash against the
block before it, so it stops synchronising. The index canister performs no such check
and serves plausible but incorrect account histories. Neither can repair the archive.

A second failure compounds the first: a ledger whose archiving keeps failing retries on
every transaction with no spacing, so one persistent cause becomes continuous wasted
work while the blocks it could not archive accumulate.

This specification makes archiving robust. An archive must be told where a batch belongs
and refuse one that does not fit; it must report its own extent, so a ledger never infers
it; a ledger must not stop serving a block until an archive has confirmed holding it; and
a ledger must space its attempts while archiving is failing. The remaining requirements
add what those four need to be safe in practice: how capacity is reported, what an
un-upgraded archive or ledger means, how a lost archive creation is detected, and what a
round may do.

Requirements 1–6 bind the ICRC archive canister (THE Archive). Requirements 7–14 bind
both ledgers (THE Ledger) except where a criterion names one of them. The ICP archive is
not changed (see Non-goals), so the ICP ledger is exempted wherever an obligation needs
an archive's reported range.

## Glossary

- **Archive**: the ICRC archive canister, `ic-icrc1-archive`. Never the ICP archive.
- **Tail_Archive**: the archive a ledger currently appends to, the most recently
  created one. Earlier archives are full and are never contacted again.
- **`block_index_offset`**: the archive's published second `init` argument, the global
  index of the first block it will ever hold. Fixed for the life of the canister.
- **Archive_Position**: the next global block index an archive expects, one past the
  last block it holds. Reported as `next_index`.
- **Archive_Range**: the span of global indices an archive holds, from its
  `block_index_offset` up to but excluding its Archive_Position, **as the archive itself
  reports it**.
- **Published_Range**: the inclusive span a ledger publishes for an archive through
  `archives()`. It is the ledger's own record, not evidence about the archive.
- **Archived_Prefix**: the blocks a ledger has stopped serving itself because an archive
  confirmed holding them. Its end is exclusive: the lowest index the ledger still serves.
- **Declared_Index**: the global index an append states its first block belongs at,
  carried as the optional second argument to `append_blocks`.
- **Indexed_Append** / **Index_Less_Append**: a call to `append_blocks` with / without a
  Declared_Index. The latter is the only shape a ledger built before this change sends.
- **Expected_Parent**: the hash an archive is told at `init` to expect as the parent of
  the first block it stores, i.e. the hash of the block at `block_index_offset - 1`.
  Absent for an archive whose offset is zero, and for one created by a ledger that does
  not supply it.
- **`at_capacity`**: a reported flag distinguishing an archive that reached its own
  configured storage limit from one that was refused memory by the platform.
- **Archiving_Round**: one attempt by a ledger to move blocks to archives, triggered by
  a transaction.
- **BACKOFF_INITIAL**, **BACKOFF_CAP**: the minimum spacing between archiving attempts
  after the first failure, and the ceiling that spacing grows to. Req 10 fixes the
  behaviour; `design.md` settles the values.
- **ARCHIVE_CALL_TIMEOUT**: the longest a ledger waits for a call it is willing to stop
  waiting for. Req 13 fixes the behaviour; `design.md` settles the value.

## Non-goals

- **Repairing a suite that has already diverged.** These requirements prevent further
  divergence; correcting an archive that already serves a block at the wrong index needs
  operator-computed intervention. The design's Delivery section gates re-enablement on
  verifying that no live suite is in that state.
- **The ICP archive's side of the indexed protocol.** The ICP archive is a separate
  canister and is not changed, so the ICP ledger gains the ledger-side obligations but
  not the addressed-append protection. Reqs 7.5, 9.8, 10.5, 11.4 and 13.4 say what the
  ICP ledger does instead, so the exemption is explicit rather than silent. The port is
  tracked as DEFI-3021.
- **Stopping an archiving failure from contradicting a transaction's reply.** Req 10.3
  states the property, but the code that delivers it is a separate change; Delivery
  orders it as a dependency.
- **Recovering the cycles of an abandoned archive canister.** Req 14 detects a creation
  whose outcome was lost and halts; reclaiming the canister is accepted as a loss.
- **Surviving a storage refusal that traps the archive.** Two platform refusals
  (cycle reservation on memory growth) end the call outright, so the archive can keep no
  partial result and report nothing. The answer is configuration, a reserved
  `memory_allocation`, not protocol (Req 4.5).
- **Bounding a ledger's memory growth.** Archiving bounds only the retained blocks;
  allowances and other per-transaction state stay. Rate limiting, fees and allowance
  pruning are separate work.
- **Making a ledger-only snapshot restore safe.** A ledger restored alone resumes issuing
  indices its archives already hold with different content. Req 9.6 detects it and
  Req 1 keeps the fork out of the archives; the coherent rollback is the whole suite.
- **Verifying the first append into a fresh archive given no Expected_Parent.** It is
  unverifiable in principle and is taken on trust (Req 1.7); refusing would halt every
  un-upgraded ledger at each archive roll-over. Req 1.8 makes the window countable.
- **Defending against an archive downgraded beneath its ledger.** A ledger that has
  cached a positive capability answer sends blocks without probing; Delivery states the
  release-order rule instead.
- **Validating the archive controller configuration.** The platform allows ten
  controllers and `ArchiveOptions` puts no bound on the list. Enforcing it in the
  ledger's `init` and `post_upgrade` is a separate, minimal change (DEFI-3015).
- **Making the archive's canister logs readable.** The archive has no `/logs` endpoint
  and its canister log is controller-gated, which is why every obligation on the archive
  is satisfiable through a committed metric.

## Requirements

### Requirement 1: Chain Continuity Is Enforced On Every Stored Block

**User Story:** As an operator of a ledger suite, I want an archive to reject blocks that
do not continue the chain it already holds, so that a ledger that has lost track of what
it sent cannot corrupt the archive by sending it again.

#### Acceptance Criteria

1. WHEN the first block THE Archive would store does not carry as its parent the hash
   of the archive's last stored block, THE Archive SHALL refuse the append.
2. WHILE THE Archive holds no blocks and was given an Expected_Parent, THE Archive SHALL
   refuse an append whose first stored block does not carry that hash as its parent.
3. WHEN a block THE Archive would store, other than the first, does not carry as its
   parent the hash of the block before it in the append, THE Archive SHALL refuse the
   append.
4. THE Archive SHALL store a block carrying no parent hash only at global index zero,
   and SHALL store at global index zero only a block carrying no parent hash, because a
   block without a parent is the genesis block and belongs at zero or nowhere.
5. WHEN THE Archive refuses an append on any ground in Req 1, THE Archive SHALL leave the
   number of blocks it holds unchanged.
6. THE Archive SHALL apply 1.1–1.4 to the blocks it would actually store, after
   placement per Req 2 and the capacity stop per Req 4, and SHALL NOT refuse an
   Indexed_Append on account of a block it was never going to store.
7. WHILE THE Archive holds no blocks and was given no Expected_Parent, THE Archive SHALL
   NOT refuse an append on the grounds of 1.1 or 1.2, because it has nothing to compare
   against and refusing would halt every un-upgraded ledger at each archive roll-over.
8. WHEN THE Archive stores blocks under 1.7, THE Archive SHALL count that append
   distinctly, because it is the one append whose content it cannot verify.

### Requirement 2: An Indexed Append Is Placed By Its Declared Index

**User Story:** As a client developer reading blocks by index, I want every index to
resolve to the block that belongs at it, so that a balance or history I compute is
correct.

#### Acceptance Criteria

1. WHEN an Indexed_Append's Declared_Index equals the Archive_Position and no ground in
   Req 1, 2.5 or 6.3 refuses it, THE Archive SHALL store all of its blocks, except where
   Req 4 has it stop short.
2. WHEN an Indexed_Append carrying at least one block has a Declared_Index above the
   Archive_Position, THE Archive SHALL refuse it as a gap and SHALL store none of its
   blocks, because the blocks between the two positions would be held by no archive.
3. WHEN an Indexed_Append's Declared_Index falls within the Archive_Range and the append
   extends beyond the Archive_Position, THE Archive SHALL store only the blocks at or
   above the Archive_Position, subject to 2.5 and Req 4.
4. WHEN every block of an Indexed_Append is at an index THE Archive already holds and 2.5
   finds no difference, THE Archive SHALL store none of them and SHALL report success,
   however far the Declared_Index falls below the Archive_Position.
5. WHEN an Indexed_Append carries blocks at indices THE Archive already holds, THE
   Archive SHALL compare the last such block against the block it holds at that index
   and SHALL refuse the append if they differ, because a forked ledger must not be told
   its re-send succeeded.
6. WHEN an Indexed_Append carrying at least one block has a Declared_Index below
   `block_index_offset`, THE Archive SHALL store none of its blocks and SHALL report
   that outcome together with its Archive_Range.
7. THE Archive SHALL NOT store a block at an index it already holds a block for, and
   SHALL return, for every index it holds, the block whose position in the chain is
   that index.

### Requirement 3: An Indexed Append Reports The Archive's Range And Outcome

**User Story:** As an operator, I want an archive to state its own extent and what it did
on every append, so that a ledger never has to infer what an archive holds.

#### Acceptance Criteria

1. WHEN THE Archive answers an Indexed_Append, THE Archive SHALL report its
   `block_index_offset` and its Archive_Position as global indices, whatever the outcome,
   with the Archive_Position as it stands *after* storing whatever the append stored.
2. THE Archive SHALL state the outcome of an Indexed_Append explicitly alongside 3.1, so
   that a ledger never infers the case by comparing what it sent against what was
   reported.
3. THE Archive SHALL report one outcome for every append after which it holds every
   block it was offered and did not already hold, whether a clean continuation, a
   straddling append, a wholly held re-send or an empty append, and a distinct outcome
   for an append that stopped short per Req 4, including when it stored nothing.
4. THE Archive SHALL report whether the append's blocks were checked against a block it
   already held or against its Expected_Parent: false for the unverifiable append of 1.8
   and for any append that stored and compared nothing.
5. WHEN THE Archive receives an Indexed_Append carrying no blocks, THE Archive SHALL
   report per 3.1 and SHALL store nothing and consume no capacity, because this is how a
   ledger asks where an archive stands without risking a write.

### Requirement 4: A Capacity Stop Is Reported, Not A Failure

**User Story:** As a canister operator, I want an archive that cannot take all the blocks
offered to keep the ones it can and say why it stopped, so that archiving makes progress
under storage pressure instead of repeating work it cannot finish.

#### Acceptance Criteria

1. WHEN the next block of an Indexed_Append would take THE Archive past its own
   configured storage limit, THE Archive SHALL store the blocks before it, report the
   Archive_Position it reached, and report `at_capacity` as true.
2. WHEN THE Archive is refused memory it asked for while storing an Indexed_Append and
   the refusal returns control to it, THE Archive SHALL behave as in 4.1 but report
   `at_capacity` as false, because a ledger must not respond by creating another archive
   with the resource that was just refused.
3. WHEN an Indexed_Append stored every block it was offered, or stored none because all
   were already held, THE Archive SHALL report `at_capacity` as false.
4. THE Archive SHALL NOT discard blocks it has already stored from an Indexed_Append in
   order to refuse it, because under a persistent cause each attempt would then make no
   progress.
5. THE Archive SHALL NOT be held to 4.2 or 4.4 for a storage refusal that terminates its
   execution rather than returning control to it.

### Requirement 5: An Index-Less Append Behaves As It Does Today

**User Story:** As an operator upgrading a ledger suite, I want an archive upgraded ahead
of its ledger to behave towards that ledger exactly as before, so that the archive can
be released on its own.

#### Acceptance Criteria

1. WHEN THE Archive receives an Index_Less_Append it can store, THE Archive SHALL store
   its blocks and SHALL return an empty reply.
2. WHEN THE Archive refuses an Index_Less_Append on any ground, THE Archive SHALL fail
   the call rather than return a description of the refusal, because such a caller cannot
   read one and would otherwise stop serving the blocks itself.
3. IF THE Archive cannot store every block of an Index_Less_Append, THEN THE Archive
   SHALL store none of them and SHALL fail the call, because such a caller accounts for
   the whole batch on success.
4. THE Archive SHALL accept an Index_Less_Append encoded with a trailing absent optional
   argument and one with no second argument at all, and SHALL NOT require a
   Declared_Index.

### Requirement 6: Every Refusal And Short Stop Is Counted

**User Story:** As an on-call engineer, I want each reason an archive refused or stopped
short to be visible in its metrics, so that I can tell an invariant violation from a
capacity problem without access to canister logs.

#### Acceptance Criteria

1. THE Archive SHALL expose, over its metrics endpoint, a separate count of
   Indexed_Appends for each of: 1.1, 1.2, 1.3, each half of 1.4, a covered-range
   mismatch per 2.5, a gap per 2.2, blocks below its range per 2.6, a stop at its own
   limit per 4.1, a platform-refused growth per 4.2 and an undecodable block per 6.3,
   and a count of every append, indexed or not, stored under 1.7, because the
   unverifiable window is open mostly to index-less callers.
2. THE Archive SHALL NOT fail the call for any outcome counted under 6.1 when the append
   carried a Declared_Index, because failing the call discards the count.
3. WHEN THE Archive cannot decode a block it would otherwise store, THE Archive SHALL
   refuse the append with an outcome distinguishable from a chain mismatch, because the
   two call for different operator responses.
4. THE Archive SHALL NOT count an append carrying no blocks under any count in 6.1.

### Requirement 7: Archives Tile The Block Index Space

**User Story:** As a client developer, I want the archives of a ledger to tile the block
index space without gaps or overlaps, so that reading a range needs no special cases.

#### Acceptance Criteria

1. WHEN THE Ledger creates an archive, THE Ledger SHALL set its `block_index_offset` to
   the Archive_Position last reported by the previously created archive, derived only
   from a reported extent and never from a count of blocks sent.
2. WHEN THE ICRC Ledger creates an archive whose `block_index_offset` is above zero, THE
   ICRC Ledger SHALL supply as its Expected_Parent the hash of the block at
   `block_index_offset - 1`.
3. THE ICRC Ledger SHALL publish through `archives()` and `icrc3_get_archives` the same
   Published_Range for each archive holding at least one block, contiguous and
   non-overlapping across archives, and SHALL omit an archive holding no blocks.
4. WHILE an archive's reported Archive_Range does not begin where the previous archive's
   ends, THE Ledger SHALL store no further blocks in it and SHALL expose a distinct
   non-zero metric.
5. THE ICP Ledger SHALL derive a new archive's `block_index_offset` from its own record
   and SHALL NOT be held to 7.1–7.4, because its archives report no range and its
   `archives()` carries none.

### Requirement 8: A Ledger Acts On A Reported Capacity Stop

**User Story:** As a canister operator, I want a ledger to roll over when an archive is
full and retry when it was refused memory, so that neither is mistaken for the other.

#### Acceptance Criteria

1. IF the Tail_Archive reports `at_capacity` as true, THEN THE Ledger SHALL create a new
   archive for the blocks above its reported Archive_Position on a later
   Archiving_Round, but only once the Archived_Prefix has reached that position,
   re-offering blocks to the full archive until it has, because 9.3 may forbid advancing
   on the reply that reported the stop.
2. IF the Tail_Archive stopped short and reports `at_capacity` as false, THEN THE Ledger
   SHALL offer the remaining blocks to the same archive on a later round.
3. WHEN the next block to archive is on its own larger than the configured archive size
   or than one inter-canister message, or an archive holding no blocks reports
   `at_capacity` as true, THE Ledger SHALL make no further archiving attempt and SHALL
   expose a distinct non-zero metric rather than create another archive, because a new
   archive with the same limit could not take the block either.

### Requirement 9: No Block Index Ever Becomes Unretrievable

**User Story:** As a client developer, I want every block index the ledger has ever
issued to remain retrievable, so that a history I have read never develops a hole.

#### Acceptance Criteria

1. THE Ledger SHALL NOT stop serving a block index unless an archive has reported an
   Archive_Range covering it, and SHALL NOT rely on its own record of what it sent.
2. WHEN an Archiving_Round does not complete, THE Ledger SHALL continue to serve every
   index it served before that round.
3. THE Ledger SHALL extend the Archived_Prefix only as far as one past the
   highest-indexed block of an append the archive reports per 3.4 as checked, never as
   far as the reported Archive_Position, because a hash chain propagates a divergence
   forward, so a match at index N is evidence about indices at and below N only.
4. WHEN the Tail_Archive reports an Archive_Range whose start is above the end of the
   Archived_Prefix, THE Ledger SHALL make no further archiving attempt and SHALL expose a
   distinct non-zero metric.
5. IF an archive reports an Archive_Position that is not above the last index of the
   Published_Range for *that* archive, THEN THE Ledger SHALL make no further archiving
   attempt, SHALL discard no further blocks, and SHALL expose a distinct non-zero metric,
   because a block it is published as holding is then held nowhere.
6. WHEN an archive reports an Archive_Position above the next block index THE Ledger
   would itself issue, THE Ledger SHALL make no further archiving attempt and SHALL
   expose a distinct non-zero metric, because the archive was built from a chain the
   ledger is no longer on.
7. WHEN any archive reports a `block_index_offset` that differs from the start THE Ledger
   has recorded for it, its Published_Range start or, for an archive not yet published,
   one past the end of the previous archive's Published_Range (zero for a ledger's first
   archive), THE Ledger SHALL leave its record unchanged, make no further archiving
   attempt, and expose a distinct non-zero metric.
8. THE ICP Ledger SHALL rely on its own record instead and SHALL NOT be held to 9.1 or
   9.3–9.7.

### Requirement 10: Archiving Attempts Are Bounded While Archiving Fails

**User Story:** As a canister operator, I want a ledger to stop retrying archiving on
every transaction once it is failing, so that a persistent cause costs a probe per
interval rather than work per transaction.

#### Acceptance Criteria

1. WHILE archiving has failed at least once and not since succeeded, THE Ledger SHALL
   NOT begin an Archiving_Round sooner than BACKOFF_INITIAL after the last attempt,
   SHALL increase the spacing on consecutive failures up to and not beyond BACKOFF_CAP,
   and SHALL return to no delay after a success.
2. WHEN a cause of failure ceases, THE Ledger SHALL resume archiving without operator
   action.
3. WHEN an Archiving_Round fails in a way THE Ledger observes, THE Ledger SHALL count it
   in its existing archiving-failure metric, SHALL continue to serve the blocks it did
   not archive, and SHALL reply to the triggering transaction as it would have had
   archiving succeeded.
4. WHEN an archive stops short and reports `at_capacity` as false, THE Ledger SHALL treat
   the round as failed for 10.1 and 10.3 while keeping the reported progress, because the
   refused growth would otherwise be provoked again by every transaction.
5. WHEN an archive refuses an append on any ground in Req 1, or per 2.2, 2.5 or 6.3, THE
   ICRC Ledger SHALL make no further archiving attempt and SHALL expose a distinct
   non-zero metric rather than back off, because no retry resolves a chain or position
   mismatch; THE ICP Ledger, whose archive can only reject, SHALL treat every reject as a
   failure under 10.1.
6. WHEN an archive reports per 2.6 that the blocks offered fall below its range, THE
   Ledger SHALL make no further archiving attempt and SHALL expose a distinct non-zero
   metric separate from 10.5's, because only a wrong ledger record reaches this.
7. WHEN THE Ledger is upgraded, THE Ledger SHALL permit the next Archiving_Round
   immediately rather than observing the spacing of 10.1, except while the state of
   14.1 holds, because an upgrade is how an operator resumes after a halt.
8. WHILE a halt per 8.3, 9.4–9.7, 10.5, 10.6 or 14.5 holds, THE Ledger SHALL attempt no
   Archiving_Round until its next upgrade, and SHALL re-establish the halt from the
   first reply after that upgrade if the cause persists.

### Requirement 11: A Ledger Will Not Archive Against An Archive That Cannot Report Its Range

**User Story:** As an operator of a third-party ledger suite, I want a ledger upgraded
ahead of its archives to stop archiving rather than continue unprotected, so that I find
out from a metric instead of from a corrupted archive.

#### Acceptance Criteria

1. WHILE the Tail_Archive does not report an Archive_Range when asked per 3.5, THE ICRC
   Ledger SHALL move no blocks to any archive and SHALL expose a distinct non-zero
   metric.
2. WHEN the Tail_Archive begins reporting an Archive_Range, THE ICRC Ledger SHALL resume
   archiving without operator action and without being upgraded.
3. THE ICRC Ledger SHALL make the determination in 11.1 without storing any blocks, and
   SHALL NOT repeat it on every round once an archive has reported its range, except
   once after an upgrade.
4. THE ICP Ledger SHALL continue archiving against an archive that reports no
   Archive_Range, and SHALL expose a distinct count of how often it does so.

### Requirement 12: An Archiving Round Makes One Append

**User Story:** As a reviewer of ledger behaviour, I want a round to be a single append
to a single archive, so that there is one question about whether it landed.

#### Acceptance Criteria

1. THE Ledger SHALL send at most one block-carrying `append_blocks` per Archiving_Round,
   and at most one carrying no blocks.
2. THE Ledger SHALL create at most one archive per Archiving_Round.
3. THE Ledger SHALL choose a round's blocks so that the encoded call fits one
   inter-canister message, measured in bytes rather than counted in blocks.
4. THE Ledger SHALL expose the number of blocks a round is permitted to carry.

### Requirement 13: A Ledger Does Not Wait Indefinitely For An Archive

**User Story:** As a canister operator, I want archiving to remain possible on a subnet
short of memory, so that the shortage that stopped archiving does not also block the
calls needed to restart it.

#### Acceptance Criteria

1. WHEN THE ICRC Ledger sends an Indexed_Append, or THE Ledger asks an archive for its
   remaining capacity, THE Ledger SHALL stop waiting after at most ARCHIVE_CALL_TIMEOUT
   and SHALL treat the round as failed per Req 10.
2. THE ICRC Ledger SHALL NOT treat a response it stopped waiting for as evidence that
   the archive stored nothing, and SHALL converge on the archive's reported extent on a
   later round without any block being stored twice.
3. THE Ledger SHALL wait unboundedly for calls to the management canister, because their
   unknown outcomes are resolved by Req 14 or are unresolvable.
4. THE ICP Ledger SHALL wait unboundedly for an append, because a retry against its
   archives would store the blocks a second time.
5. WHILE an archive is not answering a call, THE ICRC Ledger SHALL become stoppable
   within ARCHIVE_CALL_TIMEOUT, because an outstanding callback otherwise prevents the
   upgrade that is the operator's lever for every other halt.

### Requirement 14: An Unaccounted Archive Creation Halts Archiving

**User Story:** As a canister operator, I want a ledger to stop archiving when it has
begun creating an archive and cannot confirm the outcome, so that one unaddressable
canister does not become a series of them.

#### Acceptance Criteria

1. WHILE THE Ledger has begun creating an archive, has not recorded its identity per
   14.3, and has not observed the creation fail, THE Ledger SHALL move no further blocks
   to any archive, SHALL expose a distinct non-zero metric, and SHALL NOT resume on its
   own, including across an upgrade, because a canister may exist that nothing can
   address.
2. WHEN THE Ledger observes an archive creation fail before the canister exists, THE
   Ledger SHALL NOT enter the state in 14.1; WHEN it observes a failure after the
   canister exists but before its identity is recorded, THE Ledger SHALL enter it.
3. WHEN THE Ledger learns the identity of a canister it created, THE Ledger SHALL record
   it durably before doing anything else with it.
4. WHILE THE Ledger has recorded a created archive's identity but not yet adopted it,
   THE Ledger SHALL expose the identity and a metric distinct from 14.1's, and SHALL
   finish that creation before moving further blocks, determining what remains to be
   done by asking the created canister.
5. WHEN a canister THE Ledger created carries a module it did not install, THE Ledger
   SHALL make no further archiving attempt and SHALL expose a distinct non-zero metric
   with the identity, rather than reinstall, adopt or delete it.
6. THE Ledger SHALL adopt a created archive before handing its control to the configured
   controllers, and SHALL treat a handover failure as blocking neither adoption nor
   archiving.
7. WHILE any adopted archive's control has not been handed over, THE Ledger SHALL keep a
   record of every such archive, committed before the handover call is made, SHALL retry
   a handover on later rounds, and SHALL expose a metric counting the archives still
   owed one.
8. WHEN a handover retry is refused because THE Ledger is no longer a controller, THE
   Ledger SHALL treat that handover as complete, because the ledger can have lost that
   authority only by the earlier call having succeeded.
