---
id: DEFI-2967-followup
title: Archive chain continuity and bounded archiving retries
tags: [ledger, archive, icrc, icp]
---

# Archive Chain Continuity And Bounded Archiving Retries — Requirements

*Companion to [`design.md`](design.md). This document is the **behavioural
contract**: what the system must do, stated so that each statement can be tested
against the public interface. It is written before the design and must stay
readable without it.*

> **Read the requirements as a set.** The criteria interlock, and several are
> deliberately permissive on their own because a sibling constrains the case they
> leave open — `Req 1.4` allows what `Req 2.1` forbids once an index is present,
> and `Req 8.1` looks absolute until `Req 8.7` excepts the ICP ledger. A criterion
> read in isolation will therefore look either too weak or too strong more often
> than not. Where that is load-bearing the criterion says "per N.M"; where it is not
> stated, assume a sibling is carrying it and check before concluding a gap.

## Introduction

**Archiving is switched off today.** On the ckBTC and ckDOGE ledgers
`trigger_threshold` is set beyond any reachable block count, as a mitigation after
an archiving failure corrupted nothing only by luck, and blocks are accumulating in
the ledgers instead. This document is the contract archiving must satisfy before it
is switched back on. Four things have to hold: an archive must be able to tell where
an incoming batch belongs and refuse one that does not fit; it must report its own
extent, so a ledger never has to infer it; a ledger must not stop serving a block
until an archive has confirmed holding it; and a ledger must space its attempts
while archiving is failing. The rest of this section is why each of those is
needed.

A ledger keeps only its most recent blocks and moves older ones to archive
canisters. Because an archive is a separate canister, moving blocks means an
inter-canister call, and the two halves of that call commit independently: the
archive commits the blocks it stored when its message ends, while the ledger
records *that* it stored them in a later message of its own. If the ledger's later
message fails, the blocks are in the archive and the ledger does not know it.

The ledger's response is to send those blocks again on its next attempt, and
`append_blocks` gives an archive no way to tell that second send from a genuine
continuation — the call carries blocks but no indication of where they belong. So
the archive appends them a second time. Every index above that point then shifts
by the length of the duplicate, and because an archive maps a global block index
to its own storage by a fixed offset chosen when it was created, the shift is
permanent and silent. `icrc3_get_blocks` returns a block that is internally valid
and belongs at a different index.

Two clients read those blocks and are harmed differently. Rosetta verifies that
returned indices match the ones it requested and that each block's parent hash
matches the previous block, so it stops synchronising and goes stale. The index
canister performs no such check, so it attributes transactions to whichever
accounts a wrongly-placed block names, and serves plausible but incorrect account
histories. Neither can repair the archive.

A second failure compounds the first, and in one direction: a ledger whose archiving
keeps failing retries on every transaction with no spacing, so a single persistent
cause becomes continuous wasted work — the failure that prompted this work, a
refused memory growth, was persistent for about four and a half hours — while the
blocks it could not archive accumulate, so there is more to send once archiving
resumes. Switching archiving back on re-exposes both, which is why the contract
comes first.

## Glossary

- **Tail_Archive**: the archive a ledger currently appends to — the most recently
  created one. Earlier archives are full and are never written to again.
- **Archive_Range**: the contiguous span of global block indices an archive holds,
  from its `block_index_offset` up to but excluding its Archive_Position, **as the
  archive itself reports it** (Req 3). It is observed, not inferred.
- **Published_Range**: the span a ledger publishes for an archive through
  `archives()`. It is the ledger's own record, derived from what archives have
  reported, so it is not evidence about an archive on its own — Req 7.2 constrains
  what it may say.
- **Archive_Position**: the next global block index an archive expects, i.e. the
  index one past the last block it holds. Reported as `next_index`.
- **Declared_Index**: the global index an append states its first block belongs
  at, carried as the optional second argument to `append_blocks`.
- **Indexed_Append**: a call to `append_blocks` that carries a Declared_Index.
- **Index_Less_Append**: a call to `append_blocks` that carries no
  Declared_Index — the only shape a ledger built before this change can send.
- **Archiving_Round**: one attempt by a ledger to move blocks to archives,
  triggered by a transaction.
- **Archived_Prefix**: the blocks a ledger has stopped serving itself because an
  archive confirmed holding them.
- **ARCHIVE_CALL_TIMEOUT**: the longest a ledger waits for a response to a call it
  is willing to stop waiting for. Req 13 fixes the behaviour; `design.md` settles
  the number.
- **BACKOFF_INITIAL**: the minimum spacing between archiving attempts after the
  first failure. Req 9 fixes the behaviour; `design.md` settles the number.
- **BACKOFF_CAP**: the ceiling that spacing grows to under repeated failure. Req 9
  fixes the behaviour; `design.md` settles the number.
- **`block_index_offset`**: the archive's published second `init` argument, the
  global index of the first block it will ever hold. It is fixed for the life of
  the canister.
- **`at_capacity`**: a reported flag distinguishing an archive that has reached its
  own configured storage limit from one that merely could not grow.

## Non-goals

- **Repairing a suite that has already diverged.** These requirements prevent
  further divergence; they do not correct an archive that already serves a block at
  the wrong index. Detecting whether that has happened is possible today with
  existing tooling and is a prerequisite to this work rather than part of it, and
  correcting it needs deliberate, operator-computed intervention that is safe only
  once it is known to be needed.
- **The ICP archive's side of the indexed protocol.** The ICP archive is a separate
  canister from the ICRC archive and is not changed here, so the ICP ledger gains
  the ledger-side obligations but not the addressed-append ones. This leaves the ICP
  suite exposed to the divergence described above until that port lands, which is
  accepted deliberately and tracked separately. Req 10.5 pins the behaviour that
  makes the exemption safe rather than silent.
- **Ensuring an archiving failure cannot contradict a transaction's reply.** On a
  ledger that waits for archiving before replying, a failure after the transaction
  has committed turns a successful transfer into a rejection, which a client that
  retries can turn into a double credit. That is a separate change, and it is a
  prerequisite for switching archiving back on rather than something these
  requirements deliver.
- **Recovering the cycles in an abandoned archive canister.** A creation that is
  interrupted after the canister exists but before the ledger has recorded its
  identity leaves a canister nobody can address. Req 11 requires that this is
  detected and that archiving stops, because continuing past it is what turns one
  abandoned canister into many; reclaiming its cycles needs an administrative path
  that does not exist and is accepted as a loss.
- **Surviving a storage refusal that terminates the archive's execution.** Not all
  refusals return control: two of them end the call outright, so the archive cannot
  keep a partial result or report a cause, and every block it stored earlier in that
  call is discarded with it. Those are the cycle-reservation refusals, and they are
  the cause of the failure that prompted this work — so Req 4's reporting covers the
  refusals that *do* return control, and this class is out of reach of any protocol
  change (Req 4.7).

  The answer to it is to reserve the storage before writing rather than at the write:
  a canister with a reserved memory allocation is charged when the allocation is
  made, so growth inside it requires no further reservation and cannot be refused on
  reservation grounds. That is a configuration change per archive, i.e. the drafted
  `memory_allocation` proposals, and it is why they are not optional extras to this
  work.
- **Restoring a ledger from a canister snapshot as a recovery path.** A ledger
  restored alone resumes issuing block indices its archives already hold with
  different content, so its chain forks from the archived prefix and balances
  rewind. Req 8 and Req 1 require that such a fork is detected rather than
  extended into the archives; they do not make the restore safe. The only coherent
  rollback is the whole suite to a common point, accepting the loss after it.
- **Verifying the first append to a freshly created archive from a ledger that
  sends no index.** Such an append is unverifiable in principle: the archive has no
  last block to chain against and the call carries nothing saying where its blocks
  belong, so it is taken on trust (`Req 1.4`). This is the one window the
  archive-only release does not close, and it is the exact shape of the original
  failure — a node created for one index, then handed blocks from a lower one.
  Refusing instead is not available, because a ledger that sends no index does the
  same thing on the ordinary path at every node roll-over, so refusing would halt
  archiving rather than only the bad case. `Req 1.6` makes the window countable so
  it is visible while it lasts and demonstrably shut once ledgers send an index.

- **Making the archive's canister logs readable.** Some obligations here are
  satisfiable only through a metric because a canister's log is not readable by
  default. Changing that is a governance proposal, not a code change, and is out
  of scope.

## Requirements

*Grouped by behaviour, not by delivery order. Several requirements depend on each
other — Req 1's check needs Req 2's placement to know which block it applies to, and
Req 8 needs Req 3's report to have something to trust — so implementing them one
requirement at a time would mean redoing work. The build order is `design.md`'s
**Delivery / PR sequence**, where each PR covers a set of criteria; this document is
what a PR is checked against.*

### Requirement 1: Chain Continuity Is Enforced On Every Stored Block

**User Story:** As an operator of a ledger suite, I want an archive to reject
blocks that do not continue the chain it already holds, so that a ledger which has
lost track of what it sent cannot corrupt the archive by sending them again.

#### Acceptance Criteria

1. WHEN the earliest block of an append that THE Archive does not already hold
   carries a parent hash that is not the hash of the archive's last stored block,
   THE Archive SHALL refuse the append.
2. WHEN THE Archive refuses an append per 1.1, THE Archive SHALL leave the number
   of blocks it holds unchanged, because a refusal that stored a prefix would
   leave the chain in the state the refusal exists to prevent.
3. THE Archive SHALL apply 1.1 to that earliest not-already-held block — which
   follows from Req 2 for an Indexed_Append and is the first block for an
   Index_Less_Append — rather than to the append's first block, which may be one the
   archive already holds and whose parent is therefore an earlier block of its own
   rather than its last.
4. WHILE an archive holds no blocks, THE Archive SHALL NOT refuse an Index_Less_Append
   on the grounds of 1.1, because it has no last block to compare against and an
   Index_Less_Append carries nothing else that says where its blocks belong.
5. WHEN the earliest block an append would store carries no parent hash, THE Archive
   SHALL store it only if it holds no blocks and its `block_index_offset` is zero,
   because a block without a parent is the genesis block and belongs at index zero
   or nowhere.
6. WHEN THE Archive stores an Index_Less_Append while holding no blocks, THE Archive
   SHALL count it distinctly, because it is the one append whose placement the
   archive cannot verify by any means and the count reads zero once every ledger
   sends an index (per Req 2.1).

### Requirement 2: An Append Is Placed By Its Declared Index

**User Story:** As a client developer reading blocks by index, I want every index
to resolve to the block that belongs at it, so that a balance or transaction
history I compute is correct.

#### Acceptance Criteria

1. WHEN an Indexed_Append's Declared_Index equals the Archive_Position, THE Archive
   SHALL store all of its blocks.
2. WHEN an Indexed_Append's Declared_Index is above the Archive_Position, THE
   Archive SHALL refuse the append as a gap and SHALL store none of its blocks,
   because the blocks between the two positions would otherwise be held by no
   archive.
3. WHEN an Indexed_Append's Declared_Index falls at or within the Archive_Range and
   the append extends beyond the Archive_Position, THE Archive SHALL store only
   those blocks at or above the Archive_Position.
4. WHEN every block of an Indexed_Append is at an index the archive already holds,
   THE Archive SHALL store none of them and SHALL report success, because a ledger
   that lost an acknowledgement must be able to retry without being told it erred.
5. THE Archive SHALL satisfy 2.4 however far the Declared_Index falls below the
   Archive_Position, including when the archive holds more blocks than the append
   carries.
6. WHEN an Indexed_Append's Declared_Index is below the receiving archive's
   `block_index_offset`, THE Archive SHALL store none of its blocks and SHALL
   report its Archive_Range, because those blocks belong to an earlier archive and
   storing them would place them at indices they do not belong at.
7. THE Archive SHALL NOT store a block at an index it already holds a block for.
8. WHEN blocks are retrieved by index from an archive after any sequence of
   appends permitted by 2.1 through 2.7, THE Archive SHALL return, for each index,
   the block whose position in the chain is that index.
9. WHEN every block of an Indexed_Append is at an index the archive already holds,
   THE Archive SHALL compare the last such block against the block it holds at that
   index and SHALL refuse the append if they differ, because a ledger whose chain
   has forked would otherwise be told its re-send succeeded and learn nothing until
   it reached the archive's position.

### Requirement 3: An Append Reports The Archive's Range

**User Story:** As an operator, I want an archive to state its own extent on every
append, so that a ledger never has to infer what an archive holds and cannot be
wrong about it.

#### Acceptance Criteria

1. WHEN THE Archive completes an Indexed_Append, THE Archive SHALL report its
   `block_index_offset` and its Archive_Position.
2. THE Archive SHALL report the Archive_Position it holds *after* storing whatever
   the append stored, not the position before, because reporting the earlier
   position would leave a ledger permanently re-sending the same blocks.
3. THE Archive SHALL report the Archive_Position under the same meaning in every
   outcome of Req 2, so that a reader of the reply never has to know which case
   produced it.
4. THE Archive SHALL report positions as global block indices, not as counts of
   blocks it holds.
5. WHEN THE Archive receives an Indexed_Append carrying no blocks, THE Archive
   SHALL report per 3.1 and SHALL store nothing and consume no capacity, because
   this is how a ledger asks an archive where it stands without risking a write.

### Requirement 4: A Capacity Stop Is Reported, Not A Failure

**User Story:** As a canister operator, I want an archive that cannot take all the
blocks offered to keep the ones it can and say why it stopped, so that archiving
makes progress under storage pressure instead of repeating work it cannot finish.

#### Acceptance Criteria

1. WHEN the next block of an Indexed_Append would take THE Archive past its own
   configured storage limit, THE Archive SHALL store the blocks before it and SHALL
   report the Archive_Position it reached, which it can always do because it decides
   this from its own configuration and its own usage without asking for memory.
8. WHEN THE Archive is instead refused memory it asked for, and the refusal returns
   control to it, THE Archive SHALL behave as in 4.1.
2. THE Archive SHALL NOT itself discard blocks it has already stored in order to
   refuse an append, because under a persistent cause each attempt would then make
   no progress at all.
3. WHEN THE Archive stops short because it has reached its own configured storage
   limit, THE Archive SHALL report `at_capacity` as true.
4. WHEN THE Archive stops short because it was observably refused more memory, THE
   Archive SHALL report `at_capacity` as false, because a ledger must not respond by
   creating another archive when creating one needs the same resource that was just
   refused.
7. THE Archive SHALL NOT be held to 4.2, 4.4 or 4.8 for a storage refusal that
   terminates its execution rather than returning to it, because it regains no
   control and can neither keep a partial result nor report anything — the exposure
   the corresponding non-goal accepts, and one 4.1 is untouched by, since reaching a
   configured limit asks for no memory and so cannot be refused.
5. IF THE Archive reports `at_capacity` as true, THEN THE Ledger SHALL create a new
   archive on a later Archiving_Round for the remaining blocks, rather than offering
   them to the same archive again.
6. IF THE Archive reports `at_capacity` as false and stopped short, THEN THE Ledger
   SHALL offer the remaining blocks to the same archive on a later attempt.

### Requirement 5: An Index-Less Append Behaves As It Does Today

**User Story:** As an operator upgrading a ledger suite, I want an archive that has
been upgraded ahead of its ledger to behave towards that ledger exactly as before,
so that the archive can be released on its own.

#### Acceptance Criteria

1. WHEN THE Archive receives an Index_Less_Append it can store, THE Archive SHALL
   store its blocks and SHALL return an empty reply.
2. WHEN THE Archive refuses an Index_Less_Append, THE Archive SHALL fail the call
   rather than returning a description of the refusal, because a caller that sent
   no Declared_Index has no means of reading one and would otherwise treat the
   refusal as success and stop serving the blocks itself.
3. THE Archive SHALL accept an Index_Less_Append that carries a trailing absent
   optional argument and one that carries no second argument at all, because these
   are distinct encodings and both are produced in practice.
4. THE Archive SHALL NOT require a Declared_Index, because requiring one would
   break every ledger not yet upgraded.

### Requirement 6: Every Refusal And Short Stop Is Counted

**User Story:** As an on-call engineer, I want each reason an archive refused or
stopped short to be visible in its metrics, so that I can tell an invariant
violation from a capacity problem without access to canister logs.

#### Acceptance Criteria

1. THE Archive SHALL expose, over its metrics endpoint, a separate count for each
   of: a refusal per 1.1, a refusal per 2.9, a gap per 2.2, a stop at its own limit
   per 4.3, and a platform-refused growth per 4.4.
6. THE Archive SHALL count a refusal per 2.9 separately from one per 1.1, because
   the two localise the divergence differently — 1.1 means the blocks offered do not
   continue the archive's last block, while 2.9 means a range the archive already
   holds was re-sent with different content, which points at a ledger that has been
   rolled back.
2. THE Archive SHALL NOT fail the call for any outcome counted under 6.1 when the
   append carried a Declared_Index, because failing the call discards the
   count along with everything else the call changed, leaving the cause invisible.
3. WHEN an append carried a Declared_Index, THE Archive SHALL preserve each count
   in 6.1 across the outcome it counts, so that the count is readable afterwards.
4. WHEN THE Archive cannot decode a block it was sent, THE Archive SHALL make that
   outcome distinguishable from a refusal per 1.1, because the two call for
   different operator responses and a chain mismatch means an invariant has been
   violated.
5. THE Archive SHALL NOT count an append carrying no blocks under any count in 6.1,
   because such an append is how a ledger asks where an archive stands per 3.5 and
   counting it would raise an operator alarm for an ordinary question.

### Requirement 7: A New Archive Continues The Previous Archive's Range

**User Story:** As a client developer, I want the archives of a ledger to tile the
block index space without gaps or overlaps, so that reading a range of blocks needs
no special cases.

#### Acceptance Criteria

1. WHEN THE Ledger creates an archive, THE Ledger SHALL set its
   `block_index_offset` to one past the last index the previously created archive
   reported holding.
2. THE Ledger SHALL publish, through `archives()`, a Published_Range per archive
   such that the ranges are contiguous and non-overlapping across all of them.
3. THE Ledger SHALL derive the offset in 7.1 only from an extent an archive has
   reported, never from a count of blocks it has sent.
4. WHILE an archive exists whose reported Archive_Range does not begin where the
   previous archive's Archive_Range ends, THE Ledger SHALL NOT store further blocks
   in it and SHALL expose a distinct non-zero metric.
5. THE ICP Ledger SHALL derive a new archive's `block_index_offset` from its own
   record instead, and SHALL NOT be held to 7.1, 7.3 or 7.4, because its archives
   report no Archive_Range and it would otherwise be unable to create an archive at
   all (per 10.5).

### Requirement 8: No Block Index Ever Becomes Unretrievable

**User Story:** As a client developer, I want every block index the ledger has ever
issued to remain retrievable, so that a history I have already read never develops
a hole.

#### Acceptance Criteria

1. THE Ledger SHALL NOT stop serving a block index unless an archive has reported
   an Archive_Range covering it.
2. WHEN THE Archive reports an Archive_Range whose start is above the end of the
   Archived_Prefix, THE Ledger SHALL extend the Archived_Prefix only as far as
   earlier archives' reported ranges cover the intervening indices.
3. IF the indices between the Archived_Prefix and an archive's reported range are
   covered by no archive, THEN THE Ledger SHALL make no further archiving attempt
   and SHALL expose a distinct non-zero metric, because advancing past them would
   discard blocks no archive holds.
4. IF an archive reports an Archive_Position below the end of the Archived_Prefix,
   THEN THE Ledger SHALL make no further archiving attempt, SHALL discard no
   further blocks, and SHALL expose a distinct non-zero metric, because blocks it
   has already stopped serving are then held nowhere and no retry can recover
   them.
5. WHEN an Archiving_Round does not complete, THE Ledger SHALL continue to serve
   every index it served before that round.
6. THE Ledger SHALL NOT rely on its own record of what it sent when deciding what
   to stop serving, only on what an archive has reported holding.
7. THE ICP Ledger SHALL rely on its own record instead, and SHALL NOT be held to
   8.1, 8.2, 8.3, 8.4 or 8.6, because its archives report no Archive_Range and it
   would otherwise be unable to stop serving any block (per 10.5) — the exposure the
   corresponding non-goal accepts.

### Requirement 9: Archiving Attempts Are Bounded While Archiving Fails

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
   operator action, because the cause that prompted this work cleared on its own
   in about four and a half hours and an operator-gated recovery would have turned
   that into an incident.
5. WHEN an Archiving_Round fails, THE Ledger SHALL count the failure in the metric
   it already exposes for archiving failures, SHALL continue to serve the blocks
   it did not archive, and SHALL reply to the triggering transaction as it would
   have had archiving succeeded.
6. WHEN an Archiving_Round fails, THE Ledger SHALL NOT prevent a later
   Archiving_Round from being attempted.
7. WHEN an archive refuses an append per 1.1, 2.2 or 2.9, THE Ledger SHALL make no
   further archiving attempt and SHALL expose a distinct non-zero metric, rather
   than spacing further attempts per 9.1, because no retry can resolve a mismatch of
   chain or position and backing off would probe an unrecoverable state forever.

### Requirement 10: A Ledger Will Not Archive Against An Archive That Cannot Report Its Range

**User Story:** As an operator of a third-party ledger suite, I want a ledger that I
have upgraded ahead of its archives to stop archiving rather than continue
unprotected, so that I find out from a metric instead of from a corrupted archive.

#### Acceptance Criteria

1. WHILE the Tail_Archive does not report an Archive_Range when asked per 3.5, THE
   ICRC Ledger SHALL make no archiving attempt and SHALL expose a distinct non-zero
   metric.
2. WHEN the Tail_Archive begins reporting an Archive_Range, THE ICRC Ledger SHALL
   resume archiving without operator action and without being upgraded.
3. THE ICRC Ledger SHALL determine whether the Tail_Archive reports its range
   without storing any blocks in it, because learning this from an ordinary append
   would mean the blocks were already stored by the time the answer arrived.
4. THE ICRC Ledger SHALL NOT repeat the determination in 10.3 on every
   Archiving_Round once an archive has reported its range.
5. THE ICP Ledger SHALL continue archiving against an archive that reports no
   Archive_Range, and SHALL expose a distinct count of how often it does so,
   because its archives do not implement Req 2 or Req 3 and halting would stop ICP
   archiving permanently.

### Requirement 11: An Unaccounted Archive Creation Halts Archiving

**User Story:** As a canister operator, I want a ledger to stop archiving when it
has begun creating an archive and cannot confirm the outcome, so that one
unaddressable canister does not become a series of them.

#### Acceptance Criteria

1. WHILE THE Ledger has begun creating an archive and has neither recorded its
   identity nor observed the creation fail, THE Ledger SHALL make no further
   archiving attempt.
2. WHILE the condition in 11.1 holds, THE Ledger SHALL expose a distinct non-zero
   metric.
3. WHEN an archive creation fails in a way THE Ledger observes, THE Ledger SHALL
   NOT enter the state in 11.1, so that an ordinary failure is subject to Req 9
   rather than halting.
4. THE Ledger SHALL NOT resume archiving out of the state in 11.1 on its own,
   because the state means a canister may exist that nothing will ever address and
   an operator has to look.

### Requirement 12: An Archiving Round Makes One Append

**User Story:** As a reviewer of ledger behaviour, I want a round to be a single
append to a single archive, so that there is one question about whether it landed
rather than several.

#### Acceptance Criteria

1. THE Ledger SHALL send at most one block-carrying `append_blocks` per
   Archiving_Round.
2. THE Ledger SHALL create at most one archive per Archiving_Round.
3. THE Ledger SHALL choose the blocks for an Archiving_Round so that they fit one
   inter-canister message, measured in bytes rather than counted in blocks,
   because block sizes vary and a count cannot guarantee a fit.
4. THE Ledger SHALL expose the number of blocks an Archiving_Round is permitted to
   carry, so that the enforced value is observable rather than only the configured
   one.
5. THE Ledger SHALL NOT count an append carrying no blocks, made to satisfy 10.3,
   against 12.1.

### Requirement 13: A Ledger Does Not Wait Indefinitely For An Archive

**User Story:** As a canister operator, I want a ledger to give up on a call an
archive is not answering, so that archiving cannot be stuck on one call
indefinitely and the subnet need not hold response capacity for a call that may
never be answered.

#### Acceptance Criteria

1. WHEN THE ICRC Ledger sends an Indexed_Append, THE ICRC Ledger SHALL stop
   waiting for a response after at most ARCHIVE_CALL_TIMEOUT.
2. WHEN THE ICRC Ledger stops waiting per 13.1, THE ICRC Ledger SHALL treat the
   Archiving_Round as failed per Req 9, so that a call that never answers costs a
   backoff interval rather than blocking archiving indefinitely.
3. THE ICRC Ledger SHALL NOT treat a response it stopped waiting for as evidence
   that the archive stored nothing, because the archive may have stored the blocks
   and answered after the wait ended.
4. WHEN THE ICRC Ledger stopped waiting for an append the archive did in fact
   store, THE ICRC Ledger SHALL converge on that archive's reported extent on a
   later Archiving_Round without any block being stored twice, per 2.4 and 3.1.
5. THE Ledger SHALL NOT stop waiting for a call whose unknown outcome it has no
   means of resolving afterwards, because an unresolvable unknown outcome is the
   state Req 11 exists to detect and bounding such a call would make it routine
   rather than exceptional.
6. THE ICP Ledger SHALL wait unboundedly for an append, because its archives do
   not satisfy Req 2 and a retry against them would store the blocks a second
   time (per 10.5).
