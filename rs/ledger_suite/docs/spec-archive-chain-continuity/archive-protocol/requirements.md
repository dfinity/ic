---
id: DEFI-2967-followup/archive-protocol
title: Archive Append Protocol
tags: [ledger, archive, icrc, icp]
---

# Archive Append Protocol — Requirements

*Companion to [`design.md`](design.md), and part **A** of the specification whose
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

*Every criterion here binds `ic-icrc1-archive` — THE Archive. The ledger's obligations
in response to what the archive reports are in part L. Grouped by behaviour, not by
delivery order: the build order is the README's **Delivery / PR sequence**, and this
document is what PR 1 is checked against.*

### Requirement A1: Chain Continuity Is Enforced On Every Stored Block


**User Story:** As an operator of a ledger suite, I want an archive to reject
blocks that do not continue the chain it already holds, so that a ledger which has
lost track of what it sent cannot corrupt the archive by sending them again.

#### Acceptance Criteria

1. WHEN the earliest block of an append that THE Archive does not already hold
   carries a parent hash that is not the hash of the archive's last stored block,
   THE Archive SHALL refuse the append.
2. WHEN THE Archive refuses an append on any ground in A1, THE Archive SHALL
   leave the number of blocks it holds unchanged, because a refusal that stored a
   prefix would leave the chain in the state the refusal exists to prevent.
3. THE Archive SHALL apply A1.1 to that earliest not-already-held block — which
   follows from A2 for an Indexed_Append and is the first block for an
   Index_Less_Append — rather than to the append's first block, which may be one the
   archive already holds and whose parent is therefore an earlier block of its own
   rather than its last.
4. WHILE an archive holds no blocks and was given no Expected_Parent, THE Archive
   SHALL NOT refuse an Index_Less_Append on the grounds of A1.1, because it then has
   nothing at all to compare against — neither a stored block nor a declared one.
5. WHEN the earliest block an append would store carries no parent hash, THE Archive
   SHALL store it only at global index zero — an archive holding nothing whose
   `block_index_offset` is zero, and for an Indexed_Append a Declared_Index of zero as
   well, any other index being a gap per A2.2 — because a block without a parent is the
   genesis block and belongs at index zero or nowhere.
6. WHEN THE Archive stores blocks while holding none and having been given no
   Expected_Parent, THE Archive SHALL count that append distinctly, because it is
   the one append whose content the archive cannot verify by any means and the count
   reads zero once every ledger supplies the hash (per A1.8).
7. THE Archive SHALL check every block it stores against the block before it — the
   append's own preceding block, or for the first block it stores the tip per A1.1 or
   the Expected_Parent per A1.8 — the only stored blocks with no predecessor to check
   being the genesis block of A1.5 and the first block of the unverifiable append of
   A1.4, because otherwise A2.8 holds only as far as the sending ledger's own storage is
   intact and the archive would be trusting exactly what it cannot verify.
8. WHEN an archive that holds no blocks was given an Expected_Parent, THE Archive
   SHALL refuse an append whose first stored block does not carry that hash as its
   parent, so that the only block it will ever store without checking a parent hash
   is the genesis block.
9. THE Archive SHALL NOT refuse an Indexed_Append on account of a block it was never
   going to store, because a block beyond its own configured limit falls outside A1.7 and
   refusing for it would deny A4.1 the prefix it requires to be stored — an
   Index_Less_Append being the exception, since A5.5 has it refuse the whole batch for
   exactly that block.
10. WHEN THE Archive would store a block at global index zero, THE Archive SHALL refuse
   the append unless that block carries no parent hash, because A1.5 says only where a
   parentless block may go and not that index zero must hold one — so without this an
   append declared at zero into an empty archive given no Expected_Parent would place a
   block with a parent at the genesis position, permanently and unverifiably.

### Requirement A2: An Append Is Placed By Its Declared Index


**User Story:** As a client developer reading blocks by index, I want every index
to resolve to the block that belongs at it, so that a balance or transaction
history I compute is correct.

#### Acceptance Criteria

1. WHEN an Indexed_Append's Declared_Index equals the Archive_Position and no ground in
   A1, A2.9 or A6.4 refuses it, THE Archive SHALL store all of its blocks, except where
   A4 has it stop short — at its own configured limit per A4.1, or at a growth it asked
   for and was refused per A4.6 — which is the one case where a correctly placed and
   unrefused append stores only a prefix.
2. WHEN an Indexed_Append carrying at least one block has a Declared_Index above the
   Archive_Position, THE Archive SHALL refuse the append as a gap and SHALL store none
   of its blocks, because the blocks between the two positions would otherwise be held
   by no archive — an append carrying none being the question of A3.5, which is answered
   with the range whatever index it names.
3. WHEN an Indexed_Append's Declared_Index falls at or within the Archive_Range, the
   append extends beyond the Archive_Position, and no ground in A1, A2.9 or A6.4
   refuses it, THE Archive SHALL store only those blocks at or above the
   Archive_Position, subject to the same A4 stop as A2.1.
4. WHEN every block of an Indexed_Append is at an index the archive already holds
   and the comparison in A2.9 finds no difference, THE Archive SHALL store none of
   them and SHALL report success, because a ledger that lost an acknowledgement must
   be able to retry without being told it erred.
5. THE Archive SHALL satisfy A2.4 however far the Declared_Index falls below the
   Archive_Position, including when the archive holds more blocks than the append
   carries.
6. WHEN an Indexed_Append carrying at least one block has a Declared_Index below the
   receiving archive's `block_index_offset`, THE Archive SHALL store none of its blocks
   and SHALL report its Archive_Range, because those blocks belong to an earlier archive
   and storing them would place them at indices they do not belong at — an append
   carrying none again being A3.5's question, not this refusal.
7. THE Archive SHALL NOT store a block at an index it already holds a block for.
8. WHEN blocks are retrieved by index from an archive after any sequence of
   appends permitted by A2.1 through A2.7 and A2.9, THE Archive SHALL return, for each
   index, the block whose position in the chain is that index.
9. WHEN an Indexed_Append carries one or more blocks at indices the archive already
   holds — all of them or only a leading prefix — THE Archive SHALL compare the last
   such block against the block it holds at that index and SHALL refuse the append if
   they differ, because a ledger whose chain has forked would otherwise be told its
   re-send succeeded and learn nothing, and because a straddling re-send into a full
   archive stores nothing and so has no other block the archive could check.

### Requirement A3: An Append Reports The Archive's Range


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
   outcome of A2, so that a reader of the reply never has to know which case
   produced it.
4. THE Archive SHALL report positions as global block indices, not as counts of
   blocks it holds.
5. WHEN THE Archive receives an Indexed_Append carrying no blocks, THE Archive
   SHALL report per A3.1 and SHALL store nothing and consume no capacity, because
   this is how a ledger asks an archive where it stands without risking a write.
6. THE Archive SHALL state the outcome of an Indexed_Append explicitly alongside the
   values in A3.1, so that a ledger never has to infer which case occurred by
   comparing what it sent against what was reported.
7. WHEN THE Archive stopped short per A4.1 or A4.6 and so stored fewer than all of the
   blocks it was offered and did not already hold, THE Archive SHALL state that as an
   outcome distinct from the one in A3.8 and from every refusal of A1, A2.2, A2.6, A2.9
   and A6.4, including when it stored none of them per L2.3, because `at_capacity` alone
   does not separate a short stop from a complete append — a growth refused by the
   platform reports it false (A4.4) and so does a complete append (A4.7).
8. THE Archive SHALL report a single outcome for every append after which it holds
   every block it was offered and did not already hold, whether or not it already held
   some of them, all of them, or none, and whether or not it was offered any, because
   the ledger's response to all of these is identical — reconcile against the reported
   Archive_Position — and A3.9's count with the number of blocks offered already
   separates the cases that differ.
9. THE Archive SHALL report how many of the blocks it was offered it stored, because
   A3.7, A3.8 and L2.3 all turn on that number and no outcome of A2 settles it on its
   own — an append carrying nothing per A3.5, one whose first block did not fit per L2.3,
   and a re-send wholly held per A2.4 all store none, for three different reasons that
   call for three different ledger responses.
10. THE Archive SHALL report whether the append's blocks were checked against a block it
   already held or against its Expected_Parent — false for the unverifiable append of
   A1.6 and for any append that stored and compared nothing — because L3.8 must not
   advance on the one store that checked nothing, and only the archive knows whether it
   had anything to check against: a ledger cannot tell whether the tail it inherited from
   an older ledger was ever given a hash.

### Requirement A4: A Capacity Stop Is Reported, Not A Failure


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
5. THE Archive SHALL NOT be held to A4.2, A4.4 or A4.6 for a storage refusal that
   terminates its execution rather than returning to it, because it regains no
   control and can neither keep a partial result nor report anything — the exposure
   the corresponding non-goal accepts, and one A4.1 is untouched by, since reaching a
   configured limit asks for no memory and so cannot be refused.
6. WHEN THE Archive is instead refused memory it asked for while storing an
   Indexed_Append, and the refusal returns control to it, THE Archive SHALL behave as
   in A4.1.
7. WHEN THE Archive stored every block it was offered, or stored none because they
   were all already held, THE Archive SHALL report `at_capacity` as false, because a
   ledger reading it as true would create an archive it does not need.

### Requirement A5: An Index-Less Append Behaves As It Does Today


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
   it would under A4.1, because such a caller receives no reply to read and would
   account for the whole batch — leaving the unstored suffix in no archive and no
   longer served by the ledger.

### Requirement A6: Every Refusal And Short Stop Is Counted


**User Story:** As an on-call engineer, I want each reason an archive refused or
stopped short to be visible in its metrics, so that I can tell an invariant
violation from a capacity problem without access to canister logs.

#### Acceptance Criteria

1. THE Archive SHALL expose, over its metrics endpoint, a separate count of
   Indexed_Appends for each of: each chain ground of A1 counted separately (A1.1,
   A1.5, A1.7, A1.8 and A1.10), a covered-range mismatch per A2.9, a gap per A2.2, blocks
   below its own range per A2.6, a stop at its own limit per A4.3, a platform-refused
   growth per A4.4, an undecodable block per A6.4, and the unverifiable append of A1.6 —
   an Index_Less_Append being outside every count but the last, since its refusals fail
   the call per A5.2 and a failed call keeps no count.
2. THE Archive SHALL NOT fail the call for any outcome counted under A6.1 when the
   append carried a Declared_Index, because failing the call discards the
   count along with everything else the call changed, leaving the cause invisible.
3. WHEN an append carried a Declared_Index, THE Archive SHALL preserve each count
   in A6.1 across the outcome it counts, so that the count is readable afterwards.
4. WHEN THE Archive cannot decode a block it would otherwise have stored, THE Archive
   SHALL make that outcome distinguishable from a refusal per A1.1, because the two
   call for different operator responses and a chain mismatch means an invariant has
   been violated — and a block beyond its own capacity is outside this, per A1.9.
5. THE Archive SHALL NOT count an append carrying no blocks under any count in A6.1,
   because such an append is how a ledger asks where an archive stands per A3.5 and
   counting it would raise an operator alarm for an ordinary question.
