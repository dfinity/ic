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
> stated, assume a sibling is carrying it and check before concluding a gap. Whole
> requirements interlock the same way — Req 1's check needs Req 2's placement to know
> which block it applies to, and Req 8 needs Req 3's report to have something to
> trust — which is why the build order below is by PR rather than by requirement.

## Introduction

**Archiving is switched off today.** On the ckBTC and ckDOGE ledgers
`trigger_threshold` is set beyond any reachable block count, so blocks accumulate in
the ledgers instead. This document is the contract archiving must satisfy before it
is switched back on. Four things carry most of it: an archive must be able to tell
where an incoming batch belongs and refuse one that does not fit; it must report its
own extent, so a ledger never has to infer it; a ledger must not stop serving a block
until an archive has confirmed holding it; and a ledger must space its attempts while
archiving is failing. The requirements below state those four precisely and add what
they need in order to be safe in practice — how capacity is reported, what an
un-upgraded archive means, how a lost archive creation is detected, and what a round
may do. The rest of this section is why the four are needed.

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
cause becomes continuous wasted work — and the storage pressure that prompted this
work sat on the subnet for about four and a half hours — while the blocks it could
not archive accumulate, so there is more to send once archiving
resumes. Switching archiving back on re-exposes both, which is why the contract
comes first.

## Glossary

- **Archive**: the ICRC archive canister, `ic-icrc1-archive`. "THE Archive" never
  means the ICP archive, which is a separate canister and is not changed here — see
  the corresponding non-goal.
- **Tail_Archive**: the archive a ledger currently appends to — the most recently
  created one. Earlier archives are full and no append ever stores a block in one
  again, though Req 10.6 and Req 9.8 send it appends that store nothing — first to ask
  whether it reports its range, then to have it confirm blocks it already holds.
- **Archive_Range**: the contiguous span of global block indices an archive holds,
  from its `block_index_offset` up to but excluding its Archive_Position, **as the
  archive itself reports it** (Req 3). It is observed, not inferred.
- **Published_Range**: the span a ledger publishes for an archive through
  `archives()`. It is the ledger's own record — derived from what archives have
  reported for every archive created since this change, and inferred for those that
  predate it — so it is not evidence about an archive on its own; Req 7.2 constrains
  what it may say, and Req 8.4 what contradicts it.
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
  archive confirmed holding them. Its *end* means the lowest index the ledger still
  serves, one past the last it has given up — exclusive, like an Archive_Position and
  unlike a Published_Range, so that the two compose without an off-by-one. Req 8.4 is
  the criterion where the inclusive form meets the exclusive one, and says so.
- **ARCHIVE_CALL_TIMEOUT**, **BACKOFF_INITIAL**, **BACKOFF_CAP**: respectively the
  longest a ledger waits for a response to a call it is willing to stop waiting for,
  the minimum spacing between archiving attempts after the first failure, and the
  ceiling that spacing grows to under repeated failure. Req 13 and Req 9 fix the
  behaviour; `design.md` settles the numbers.
- **`block_index_offset`**: the archive's published second `init` argument, the
  global index of the first block it will ever hold. It is fixed for the life of
  the canister.
- **Expected_Parent**: the hash an archive is told at `init` to expect as the parent
  of the first block it stores, i.e. the hash of the block at
  `block_index_offset - 1`. Absent for an archive whose offset is zero, and absent
  for one created by a ledger that does not supply it.
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
  accepted deliberately and tracked separately. Req 7.5, Req 8.7, Req 10.5 and
  Req 13.6 pin the behaviour that makes the exemption safe rather than silent — each
  says what the ICP ledger does *instead*, so none of it is left to inference.
- **Building the change that stops an archiving failure contradicting a transaction's
  reply.** On a ledger that waits for archiving before replying, a failure after the
  transaction has committed turns a successful transfer into a rejection, which a client
  that retries can turn into a double credit. Req 9.5 states the property that has to
  hold, because a contract for archiving failures that said nothing about the reply
  would be incomplete — but the code that delivers it is a separate change, reviewed
  separately, and `design.md` orders it as a dependency rather than as one of this
  specification's PRs. So the requirement is in scope and its implementation is not.
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
  the class that refused the ledger's upgrade on 2026-09-01 — so Req 4's reporting
  covers the refusals that *do* return control, and this class is out of reach of any
  protocol change (Req 4.7).

  The answer to it is configuration, not protocol — a higher `reserved_cycles_limit`,
  or better a reserved `memory_allocation`, inside which growth needs no further
  reservation and so cannot be refused on these grounds at all. That is why the
  drafted proposals are a dependency of this work rather than an adjacent nicety;
  `design.md` has the mechanism.
- **Bounding a ledger's memory growth.** Switching archiving back on bounds only the
  blocks a ledger retains — `trigger_threshold` of them, about 1.2 MiB at 2000 — which
  is the smaller part of what a transaction costs it: of the ~1040 B a maximal
  `icrc2_approve` takes, only the ~624 B block is archived, and the ~416 B of allowance
  and expiration entries stay for as long as the approval does. So archiving slows
  spam-driven growth by roughly 2.5x rather than bounding it, and no `memory_allocation`
  covers the remainder, because stable memory never shrinks and usage once reached is a
  permanent floor on what the canister is billed. The heap is the bounded half and
  resets on upgrade. Rate limiting, the transfer fee and allowance pruning are the
  levers for the rest, and each is separate work.
- **Restoring a ledger from a canister snapshot as a recovery path.** A ledger
  restored alone resumes issuing block indices its archives already hold with
  different content, so its chain forks from the archived prefix and balances
  rewind. Req 8.8 requires that such a fork is detected — the archives are then ahead
  of a chain tip that has moved backwards — and Req 8.9 and Req 1 require that it is
  not extended into the archives; none of them makes the restore safe. The only
  coherent rollback is the whole suite to a common point, accepting the loss after
  it.
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

- **Defending against an archive being downgraded beneath its ledger.** Once a ledger
  has learned that its Tail_Archive reports its range (Req 10.4), it sends blocks
  without asking again, and an archive rolled back to a build that ignores the
  Declared_Index would store them as new before replying with nothing. The ledger
  cannot tell in advance; `design.md` states the release-order rule that prevents it
  and bounds the exposure to a single append.
- **Making the archive's canister logs readable.** Some obligations here are
  satisfiable only through a metric because a canister's log is not readable by
  default. Changing that is a governance proposal, not a code change, and is out
  of scope.

## Requirements

*Req 1 through Req 6 bind the ICRC archive only, except Req 4.5, Req 4.6 and Req 4.10,
which bind the ledger. Req 7 through Req 13 bind both ledgers except where a criterion
exempts the ICP one. Grouped by behaviour, not by delivery order: the build order is
`design.md`'s **Delivery / PR sequence**, where each PR covers a set of criteria, and
this document is what a PR is checked against.*

### Requirement 1: Chain Continuity Is Enforced On Every Stored Block

**User Story:** As an operator of a ledger suite, I want an archive to reject
blocks that do not continue the chain it already holds, so that a ledger which has
lost track of what it sent cannot corrupt the archive by sending them again.

#### Acceptance Criteria

1. WHEN the earliest block of an append that THE Archive does not already hold
   carries a parent hash that is not the hash of the archive's last stored block,
   THE Archive SHALL refuse the append.
2. WHEN THE Archive refuses an append on any ground in Req 1, THE Archive SHALL
   leave the number of blocks it holds unchanged, because a refusal that stored a
   prefix would leave the chain in the state the refusal exists to prevent.
3. THE Archive SHALL apply 1.1 to that earliest not-already-held block — which
   follows from Req 2 for an Indexed_Append and is the first block for an
   Index_Less_Append — rather than to the append's first block, which may be one the
   archive already holds and whose parent is therefore an earlier block of its own
   rather than its last.
4. WHILE an archive holds no blocks and was given no Expected_Parent, THE Archive
   SHALL NOT refuse an Index_Less_Append on the grounds of 1.1, because it then has
   nothing at all to compare against — neither a stored block nor a declared one.
5. WHEN the earliest block an append would store carries no parent hash, THE Archive
   SHALL store it only if it holds no blocks and its `block_index_offset` is zero,
   because a block without a parent is the genesis block and belongs at index zero
   or nowhere.
6. WHEN THE Archive stores blocks while holding none and having been given no
   Expected_Parent, THE Archive SHALL count that append distinctly, because it is
   the one append whose content the archive cannot verify by any means and the count
   reads zero once every ledger supplies the hash (per 1.8).
7. THE Archive SHALL check every block it stores against the block before it, not
   only the first, because otherwise 2.8 holds only as far as the sending ledger's
   own storage is intact and the archive would be trusting exactly what it cannot
   verify.
8. WHEN an archive that holds no blocks was given an Expected_Parent, THE Archive
   SHALL refuse an append whose first stored block does not carry that hash as its
   parent, so that the only block it will ever store without checking a parent hash
   is the genesis block.
9. THE Archive SHALL NOT refuse an append on account of a block it was never going to
   store, because a block beyond its own configured limit falls outside 1.7 and
   refusing for it would deny 4.1 the prefix it requires to be stored.
10. WHEN THE Archive would store a block at global index zero, THE Archive SHALL refuse
   the append unless that block carries no parent hash, because 1.5 says only where a
   parentless block may go and not that index zero must hold one — so without this an
   append declared at zero into an empty archive given no Expected_Parent would place a
   block with a parent at the genesis position, permanently and unverifiably.

### Requirement 2: An Append Is Placed By Its Declared Index

**User Story:** As a client developer reading blocks by index, I want every index
to resolve to the block that belongs at it, so that a balance or transaction
history I compute is correct.

#### Acceptance Criteria

1. WHEN an Indexed_Append's Declared_Index equals the Archive_Position, THE Archive
   SHALL store all of its blocks, except where Req 4 has it stop short — at its own
   configured limit per 4.1, or at a growth it asked for and was refused per 4.8 — which
   is the one case where a correctly placed append stores only a prefix.
2. WHEN an Indexed_Append's Declared_Index is above the Archive_Position, THE
   Archive SHALL refuse the append as a gap and SHALL store none of its blocks,
   because the blocks between the two positions would otherwise be held by no
   archive.
3. WHEN an Indexed_Append's Declared_Index falls at or within the Archive_Range and
   the append extends beyond the Archive_Position, THE Archive SHALL store only
   those blocks at or above the Archive_Position.
4. WHEN every block of an Indexed_Append is at an index the archive already holds
   and the comparison in 2.9 finds no difference, THE Archive SHALL store none of
   them and SHALL report success, because a ledger that lost an acknowledgement must
   be able to retry without being told it erred.
5. THE Archive SHALL satisfy 2.4 however far the Declared_Index falls below the
   Archive_Position, including when the archive holds more blocks than the append
   carries.
6. WHEN an Indexed_Append's Declared_Index is below the receiving archive's
   `block_index_offset`, THE Archive SHALL store none of its blocks and SHALL
   report its Archive_Range, because those blocks belong to an earlier archive and
   storing them would place them at indices they do not belong at.
7. THE Archive SHALL NOT store a block at an index it already holds a block for.
8. WHEN blocks are retrieved by index from an archive after any sequence of
   appends permitted by 2.1 through 2.7 and 2.9, THE Archive SHALL return, for each
   index, the block whose position in the chain is that index.
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

1. WHEN THE Archive answers an Indexed_Append at all, THE Archive SHALL report its
   `block_index_offset` and its Archive_Position, whatever the outcome was.
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
6. THE Archive SHALL state the outcome of an Indexed_Append explicitly alongside the
   values in 3.1, so that a ledger never has to infer which case occurred by
   comparing what it sent against what was reported.
7. WHEN THE Archive stored fewer than all of the blocks it was offered and did not
   already hold, THE Archive SHALL state that as an outcome distinct from the one in
   3.8, including when it stored none of them per 4.10, because `at_capacity` alone does
   not separate the two — a growth refused by the platform reports it false (4.4) and so
   does a complete append (4.9).
8. THE Archive SHALL report a single outcome for every append after which it holds
   every block it was offered and did not already hold, whether or not it already held
   some of them, all of them, or none, and whether or not it was offered any, because
   the ledger's response to all of these is identical — reconcile against the reported
   Archive_Position — and 3.9's count with the number of blocks offered already
   separates the cases that differ.
9. THE Archive SHALL report how many of the blocks it was offered it stored, because
   3.7, 3.8 and 4.10 all turn on that number and no outcome of Req 2 settles it on its
   own — an append carrying nothing per 3.5, one whose first block did not fit per 4.10,
   and a re-send wholly held per 2.4 all store none, for three different reasons that
   call for three different ledger responses.
10. THE Archive SHALL report whether the append's blocks were checked against a block it
   already held or against its Expected_Parent — false for the unverifiable append of
   1.6 and for any append that stored and compared nothing — because 8.9 must not
   advance on the one store that checked nothing, and only the archive knows whether it
   had anything to check against: a ledger cannot tell whether the tail it inherited from
   an older ledger was ever given a hash.

### Requirement 4: A Capacity Stop Is Reported, Not A Failure

**User Story:** As a canister operator, I want an archive that cannot take all the
blocks offered to keep the ones it can and say why it stopped, so that archiving
makes progress under storage pressure instead of repeating work it cannot finish.

#### Acceptance Criteria

1. WHEN the next block of an Indexed_Append would take THE Archive past its own
   configured storage limit, THE Archive SHALL store the blocks before it and SHALL
   report the Archive_Position it reached, which it can always do because it decides
   this from its own configuration and its own usage without asking for memory.
2. WHEN an append carried a Declared_Index, THE Archive SHALL NOT itself discard
   blocks it has already stored in order to refuse it, because under a persistent
   cause each attempt would then make no progress at all.
3. WHEN THE Archive stops short because it has reached its own configured storage
   limit, THE Archive SHALL report `at_capacity` as true.
4. WHEN THE Archive stops short because it was observably refused more memory, THE
   Archive SHALL report `at_capacity` as false, because a ledger must not respond by
   creating another archive when creating one needs the same resource that was just
   refused.
5. IF THE Archive reports `at_capacity` as true, THEN THE Ledger SHALL create a new
   archive on a later Archiving_Round for the remaining blocks, rather than offering
   them to the same archive again.
6. IF THE Archive reports `at_capacity` as false and stopped short, THEN THE Ledger
   SHALL offer the remaining blocks to the same archive on a later attempt.
7. THE Archive SHALL NOT be held to 4.2, 4.4 or 4.8 for a storage refusal that
   terminates its execution rather than returning to it, because it regains no
   control and can neither keep a partial result nor report anything — the exposure
   the corresponding non-goal accepts, and one 4.1 is untouched by, since reaching a
   configured limit asks for no memory and so cannot be refused.
8. WHEN THE Archive is instead refused memory it asked for while storing an
   Indexed_Append, and the refusal returns control to it, THE Archive SHALL behave as
   in 4.1.
9. WHEN THE Archive stored every block it was offered, or stored none because they
   were all already held, THE Archive SHALL report `at_capacity` as false, because a
   ledger reading it as true would create an archive it does not need.
10. WHEN an archive that holds no blocks reports `at_capacity` as true, THE Ledger SHALL
   make no further archiving attempt and SHALL expose a distinct non-zero metric rather
   than creating another archive per 4.5, because a block that does not fit an empty
   archive will not fit a new one carrying the same configured limit either, and rolling
   over would create one archive per round for as long as transactions kept arriving.

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
5. IF THE Archive cannot store every block of an Index_Less_Append, THEN THE Archive
   SHALL store none of them and SHALL fail the call, rather than storing a prefix as
   it would under 4.1, because such a caller receives no reply to read and would
   account for the whole batch — leaving the unstored suffix in no archive and no
   longer served by the ledger.

### Requirement 6: Every Refusal And Short Stop Is Counted

**User Story:** As an on-call engineer, I want each reason an archive refused or
stopped short to be visible in its metrics, so that I can tell an invariant
violation from a capacity problem without access to canister logs.

#### Acceptance Criteria

1. THE Archive SHALL expose, over its metrics endpoint, a separate count of
   Indexed_Appends for each of: each chain ground of Req 1 counted separately (1.1,
   1.5, 1.7, 1.8 and 1.10), a covered-range mismatch per 2.9, a gap per 2.2, blocks
   below its own range per 2.6, a stop at its own limit per 4.3, a platform-refused
   growth per 4.4, an undecodable block per 6.4, and the unverifiable append of 1.6 —
   an Index_Less_Append being outside every count but the last, since its refusals fail
   the call per 5.2 and a failed call keeps no count.
2. THE Archive SHALL NOT fail the call for any outcome counted under 6.1 when the
   append carried a Declared_Index, because failing the call discards the
   count along with everything else the call changed, leaving the cause invisible.
3. WHEN an append carried a Declared_Index, THE Archive SHALL preserve each count
   in 6.1 across the outcome it counts, so that the count is readable afterwards.
4. WHEN THE Archive cannot decode a block it would otherwise have stored, THE Archive
   SHALL make that outcome distinguishable from a refusal per 1.1, because the two
   call for different operator responses and a chain mismatch means an invariant has
   been violated — and a block beyond its own capacity is outside this, per 1.9.
5. THE Archive SHALL NOT count an append carrying no blocks under any count in 6.1,
   because such an append is how a ledger asks where an archive stands per 3.5 and
   counting it would raise an operator alarm for an ordinary question.
6. THE Archive SHALL count 2.6 as a diagnostic rather than as a fault, because per
   9.8 it is the ordinary signal that a ledger is behind and an operator alarmed by
   it would be alarmed by ordinary recovery.

### Requirement 7: A New Archive Continues The Previous Archive's Range

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
3. THE Ledger SHALL derive the offset in 7.1 only from an extent an archive has
   reported, never from a count of blocks it has sent.
4. WHILE an archive exists whose reported Archive_Range does not begin where the
   previous archive's Archive_Range ends, THE Ledger SHALL NOT store further blocks
   in it and SHALL expose a distinct non-zero metric.
5. THE ICP Ledger SHALL derive a new archive's `block_index_offset` from its own
   record instead, and SHALL NOT be held to 7.1, 7.2, 7.3, 7.4 or 7.7, because its
   archives report no Archive_Range to derive one from (per 10.5) and its `archives()`
   returns canister ids without ranges, with no `icrc3_get_archives` to report them
   through — so 7.2 would require an interface change this specification does not make.
6. THE Ledger SHALL omit an archive that holds no blocks from the ranges it publishes
   until that archive stores its first block, because a published range is inclusive
   of both ends and an empty archive has no pair of indices that describes it.
7. WHEN THE ICRC Ledger creates an archive whose `block_index_offset` is above zero,
   THE ICRC Ledger SHALL supply as its Expected_Parent the hash of the block at
   `block_index_offset - 1`, taken from the block it will actually send first rather
   than from the round's first block, because 1.8 binds only an archive that was
   *given* the hash — a ledger that omitted it would leave every fresh archive in 1.4's
   unverifiable window while satisfying every other criterion here.

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
3. IF the indices between the Archived_Prefix and an archive's reported range fall
   outside every Published_Range THE Ledger publishes, THEN THE Ledger SHALL make no
   further archiving attempt and SHALL expose a distinct non-zero metric, because
   advancing past them would discard blocks no archive holds — whereas indices that do
   fall inside some archive's Published_Range are not this case but 9.8's, where the
   covering archive has merely not been asked yet, and halting here would pre-empt that
   recovery.
4. IF an archive reports an Archive_Position that is not above the last index of the
   Published_Range THE Ledger publishes for *that* archive, THEN THE Ledger SHALL make
   no further archiving attempt, SHALL discard no further blocks, and SHALL expose a
   distinct non-zero metric, because a Published_Range is inclusive of both ends per 7.6
   while an Archive_Position is the next index expected, so an archive covering its
   published range reports exactly one past that range's last index and anything lower
   leaves a block it is published as holding held nowhere — compared per archive rather
   than against the Archived_Prefix, which every archive but the Tail_Archive ends
   legitimately below, and 9.8 has non-tail archives report.
5. WHEN an Archiving_Round does not complete, THE Ledger SHALL continue to serve
   every index it served before that round.
6. THE Ledger SHALL NOT rely on its own record of what it sent when deciding what
   to stop serving, only on what an archive has reported holding.
7. THE ICP Ledger SHALL rely on its own record instead, and SHALL NOT be held to
   8.1, 8.2, 8.3, 8.4, 8.6, 8.8, 8.9, 8.10 or 8.11, since there is no reported range to
   rely on
   (per 10.5) — the exposure the corresponding non-goal accepts.
8. WHEN an archive reports an Archive_Position above the next block index THE Ledger
   would itself issue, THE Ledger SHALL make no further archiving attempt and SHALL
   expose a distinct non-zero metric, because an archive holding indices the ledger has
   never issued was built from a chain the ledger is no longer on, which neither 8.2
   nor 8.4 detects.
9. THE Ledger SHALL extend the Archived_Prefix only as far as one past the
   highest-indexed block of an append the receiving archive reports per 3.10 as checked
   — stored after a parent check against a block it held or its Expected_Parent, or
   compared per 2.9 — and never as far as the Archive_Position that append reported,
   because an append that verified nothing — an empty one per 3.5, a gap per 2.2, one
   falling wholly below the archive's range per 2.6, or the unverifiable first append
   of 1.6 — is no evidence at all, while one that verified a block at index N is
   evidence only about the indices at and below N, a hash chain propagating a divergence
   forward rather than backward, so blocks the archive holds above N remain
   uncompared.
10. WHEN an archive other than the Tail_Archive reports an Archive_Range that differs
   in either end from the Published_Range THE Ledger publishes for it, THE Ledger SHALL
   leave that Published_Range as it stands, make no further archiving attempt, and
   expose a distinct non-zero metric, because a full archive's offset is fixed and it is
   never appended to again, so its range cannot legitimately have changed — and widening
   the published range to match a report that reaches into the next archive would break
   7.2, while a report starting above the published start leaves blocks held nowhere
   that 9.8 would redirect to it forever.
11. WHEN any archive, the Tail_Archive included, reports a `block_index_offset` that
   differs from the start of the Published_Range THE Ledger publishes for it — or, for an
   archive that holds no blocks yet, from the offset 7.1 derived for it, which is zero
   for the first archive a suite ever has — THE Ledger SHALL leave its record as it
   stands, make no further archiving attempt, and expose a distinct non-zero metric,
   because an offset is fixed for the life of the canister, so the report and the record
   cannot both be right, and rewriting the start from the report would leave every index
   between the two held nowhere.

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
7. WHEN an archive refuses an append on any ground in Req 1, or per 2.2, 2.9 or 6.4,
   THE Ledger SHALL make no further archiving attempt and SHALL expose a distinct
   non-zero metric, rather than spacing further attempts per 9.1, because no retry can
   resolve a mismatch of chain or position or a block the archive cannot parse.
8. WHEN an archive reports per 2.6 that the blocks offered fall below its own range,
   THE Ledger SHALL NOT halt per 9.7 and SHALL instead offer, on a later
   Archiving_Round and subject to 10.6, those of the same blocks that fall inside the
   Published_Range of the archive covering the first of them — no block beyond that
   range's end, the remainder waiting for a later round — or halt per 8.3 if no range
   covers it, because only the archive actually holding those indices can confirm them
   in a way 8.9 will accept, and a batch that ran past its range end would be neither
   wholly held, so 2.9 would compare nothing, nor storable, so 8.9 could never advance
   and the recovery would not terminate.
9. WHEN THE Ledger is upgraded, THE Ledger SHALL permit the next Archiving_Round
   immediately rather than observing the spacing 9.1 would otherwise require, because
   an upgrade is how an operator resumes after a halt and is usually the fix for
   whatever caused the failure.
10. WHEN an archive stops short of storing every block it was offered and reports
   `at_capacity` as false, THE Ledger SHALL treat the Archiving_Round as failed for the
   purposes of 9.1, 9.2 and 9.5 while keeping the progress the archive reported, because
   the call itself returned successfully and without this the refused growth would be
   provoked again by every later transaction rather than waited out by 4.6's retry.
11. WHILE a halt per 4.10, 8.3, 8.4, 8.8, 8.10, 8.11 or 9.7 holds, THE Ledger SHALL
   attempt no Archiving_Round until it is next upgraded, and SHALL re-establish the halt
   from the first reply after that upgrade if the cause persists, because each of these
   is learned from one reply and re-derivable from the next, so forgetting it on upgrade
   costs one attempt — exactly the lever 9.9 grants an operator — whereas 11.1's cause
   cannot be re-derived and so survives an upgrade per 11.4.

### Requirement 10: A Ledger Will Not Archive Against An Archive That Cannot Report Its Range

**User Story:** As an operator of a third-party ledger suite, I want a ledger that I
have upgraded ahead of its archives to stop archiving rather than continue
unprotected, so that I find out from a metric instead of from a corrupted archive.

#### Acceptance Criteria

1. WHILE the Tail_Archive does not report an Archive_Range when asked per 3.5, THE
   ICRC Ledger SHALL move no blocks to any archive and SHALL expose a distinct
   non-zero metric, while still being able to ask again per 10.2.
2. WHEN the Tail_Archive begins reporting an Archive_Range, THE ICRC Ledger SHALL
   resume archiving without operator action and without being upgraded.
3. THE ICRC Ledger SHALL determine whether the Tail_Archive reports its range
   without storing any blocks in it, because learning this from an ordinary append
   would mean the blocks were already stored by the time the answer arrived.
4. THE ICRC Ledger SHALL NOT repeat the determination in 10.3 on every
   Archiving_Round once an archive has reported its range, except for one determination
   after an upgrade, because the answer is held in state an upgrade discards and asking
   again is one empty append that stores nothing — the same allowance 9.9 makes for the
   backoff, and for the same reason.
5. THE ICP Ledger SHALL continue archiving against an archive that reports no
   Archive_Range, and SHALL expose a distinct count of how often it does so,
   because its archives do not implement Req 2 or Req 3 and halting would stop ICP
   archiving permanently.
6. WHEN THE ICRC Ledger would offer blocks per 9.8 to an archive other than the
   Tail_Archive, THE ICRC Ledger SHALL first determine, as in 10.3, that this archive
   reports its range, and WHILE it does not SHALL offer it no blocks and SHALL expose a
   distinct non-zero metric while remaining able to ask again, because an archive that
   ignores the Declared_Index would append the blocks as new — the very corruption this
   specification exists to prevent — and would reply with nothing the ledger could read.

### Requirement 11: An Unaccounted Archive Creation Halts Archiving

**User Story:** As a canister operator, I want a ledger to stop archiving when it
has begun creating an archive and cannot confirm the outcome, so that one
unaddressable canister does not become a series of them.

#### Acceptance Criteria

1. WHILE THE Ledger has begun creating an archive, has not recorded its identity per
   11.6, and has not observed the creation fail, THE Ledger SHALL move no further
   blocks to any archive.
2. WHILE the condition in 11.1 or in 11.8 holds, THE Ledger SHALL expose a distinct
   non-zero metric, and SHALL distinguish the two, because one waits for an operator
   and the other resolves itself.
3. WHEN THE Ledger observes an archive creation fail *before* the canister exists,
   THE Ledger SHALL NOT enter the state in 11.1, so that an ordinary failure is
   subject to Req 9 rather than halting.
4. WHILE THE Ledger is in the state in 11.1 and recorded no identity per 11.6, THE
   Ledger SHALL NOT resume archiving on its own, because a canister may then exist
   that nothing will ever address and an operator has to look.
5. WHEN THE Ledger observes a failure *after* the canister exists but before its
   identity is recorded, THE Ledger SHALL enter the state in 11.1, because the
   canister is then unaddressable whether the failure was observed or not.
6. WHEN THE Ledger learns the identity of a canister it created, THE Ledger SHALL
   record that identity durably before doing anything else with it, so that a
   later failure leaves a canister an operator can still address rather than one
   nothing can reach.
7. WHILE the condition in 11.8 holds, THE Ledger SHALL expose the recorded identity,
   because an operator otherwise has to recover it from canister logs that are
   unreadable by default.
8. WHILE THE Ledger has recorded a created archive's identity per 11.6 but not yet
   adopted it, THE Ledger SHALL finish that creation before moving any further blocks
   — determining what remains to be done by asking the created canister — rather than
   making no attempt at all as it does under 11.1, because a canister it can name is
   one it can still adopt and an operator should not be needed for that.
9. THE Ledger SHALL adopt a created archive before handing its control to the
   configured controllers, and SHALL treat a failure of that handover as neither
   blocking adoption nor blocking archiving, because an adopted archive is already
   usable and the handover's last step removes the ledger's own authority over it
   (per 11.11), so making archiving wait on it would risk more than it protects.
10. WHILE any created archive has been adopted but its control not yet handed over, THE
   Ledger SHALL retry each such handover on later rounds and SHALL expose a distinct
   metric counting the archives still owed one, because until then those archives cannot
   be upgraded by their intended controllers.
11. THE Ledger SHALL hand over control in two steps — first adding the configured
   controllers while remaining one itself, then removing itself — so that the first
   step is verifiable by reading the archive's controller list, which it is still
   entitled to do, and the second cannot fail in a way that matters: its only outcomes
   are that the ledger is still a controller and may retry, or that it is not, which is
   the state the handover was for.
12. WHEN a retry of the second step is refused because THE Ledger is no longer a
   controller, THE Ledger SHALL treat that archive's handover as complete and remove it
   from the count in 11.10, because the archive is then governable by the configured
   controllers and nothing further is within the ledger's reach.
13. THE Ledger SHALL keep a record of every archive still owed a handover rather than
   only the most recent, because 11.9 lets archiving continue past a failed handover, so
   an archive can fill and a later one be adopted while the first is still owed one —
   and a single slot would drop the earlier archive, leaving it ledger-controlled with
   nothing recording it.
14. THE Ledger SHALL have committed the record in 11.13 before making either handover
   call for that archive, because a trap in the call's callback rolls back everything the
   same message wrote, and one arriving after the archive's controllers had already
   changed would leave it partly handed over with no entry left to retry or to clear.

### Requirement 12: An Archiving Round Makes One Append

**User Story:** As a reviewer of ledger behaviour, I want a round to be a single
append to a single archive, so that there is one question about whether it landed
rather than several.

#### Acceptance Criteria

1. THE Ledger SHALL send at most one block-carrying `append_blocks` per
   Archiving_Round, and at most one carrying no blocks, so that the probe of 10.3 is
   bounded too rather than left outside the count.
2. THE Ledger SHALL create at most one archive per Archiving_Round.
3. THE Ledger SHALL choose the blocks for an Archiving_Round so that they fit one
   inter-canister message, measured in bytes rather than counted in blocks,
   because block sizes vary and a count cannot guarantee a fit.
4. THE Ledger SHALL expose the number of blocks an Archiving_Round is permitted to
   carry, so that the enforced value is observable rather than only the configured
   one.

### Requirement 13: A Ledger Does Not Wait Indefinitely For An Archive

**User Story:** As a canister operator, I want archiving to still be possible on a
subnet that is short of memory, so that the shortage which stopped archiving does not
also block the calls needed to get it going again.

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
7. WHEN THE Ledger makes any other call whose unknown outcome it can resolve by
   asking again, THE Ledger SHALL likewise stop waiting after at most
   ARCHIVE_CALL_TIMEOUT, so that 13.5 is the exception rather than the rule.
8. WHILE an archive is not answering an in-flight call, THE ICRC Ledger SHALL still
   become stoppable within ARCHIVE_CALL_TIMEOUT, because an outstanding callback
   otherwise prevents the ledger being stopped and therefore being upgraded — and an
   upgrade is the operator's lever for every other halt in this document.
