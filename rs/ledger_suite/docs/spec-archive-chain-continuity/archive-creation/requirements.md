---
id: DEFI-2967-followup/archive-creation
title: Archive Creation And Handover
tags: [ledger, archive, icrc, icp]
---

# Archive Creation And Handover — Requirements

*Companion to [`design.md`](design.md), and part **C** of the specification whose
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

*Criteria bind both ledgers: archive creation is shared code. Grouped by behaviour,
not by delivery order: the build order is the README's **Delivery / PR sequence**, and
this document is what PR 4 is checked against.*

### Requirement C1: An Unaccounted Archive Creation Halts Archiving


**User Story:** As a canister operator, I want a ledger to stop archiving when it
has begun creating an archive and cannot confirm the outcome, so that one
unaddressable canister does not become a series of them.

#### Acceptance Criteria

1. WHILE THE Ledger has begun creating an archive, has not recorded its identity per
   C1.6, and has not observed the creation fail, THE Ledger SHALL move no further
   blocks to any archive.
2. WHILE the condition in C1.1 or in C1.8 holds, THE Ledger SHALL expose a distinct
   non-zero metric, and SHALL distinguish the two, because one waits for an operator
   and the other resolves itself.
3. WHEN THE Ledger observes an archive creation fail *before* the canister exists,
   THE Ledger SHALL NOT enter the state in C1.1, so that an ordinary failure is
   subject to L4 rather than halting.
4. WHILE THE Ledger is in the state in C1.1 and recorded no identity per C1.6, THE
   Ledger SHALL NOT resume archiving on its own, because a canister may then exist
   that nothing will ever address and an operator has to look.
5. WHEN THE Ledger observes a failure *after* the canister exists but before its
   identity is recorded, THE Ledger SHALL enter the state in C1.1, because the
   canister is then unaddressable whether the failure was observed or not.
6. WHEN THE Ledger learns the identity of a canister it created, THE Ledger SHALL
   record that identity durably before doing anything else with it, so that a
   later failure leaves a canister an operator can still address rather than one
   nothing can reach.
7. WHILE the condition in C1.8 holds, THE Ledger SHALL expose the recorded identity,
   because an operator otherwise has to recover it from canister logs that are
   unreadable by default.
8. WHILE THE Ledger has recorded a created archive's identity per C1.6 but not yet
   adopted it, THE Ledger SHALL finish that creation before moving any further blocks
   — determining what remains to be done by asking the created canister — rather than
   making no attempt at all as it does under C1.1, because a canister it can name is
   one it can still adopt and an operator should not be needed for that.
9. THE Ledger SHALL adopt a created archive before handing its control to the
   configured controllers, and SHALL treat a failure of that handover as neither
   blocking adoption nor blocking archiving, because an adopted archive is already
   usable and the handover's last step removes the ledger's own authority over it
   (per C1.11), so making archiving wait on it would risk more than it protects.
10. WHILE any created archive has been adopted but its control not yet handed over, THE
   Ledger SHALL retry each such handover on later rounds and SHALL expose a distinct
   metric counting the archives still owed one, because until then those archives cannot
   be upgraded by their intended controllers.
11. THE Ledger SHALL hand over control in two steps — first adding the configured
   controllers while remaining one itself, or as many of them as the platform's limit on
   controllers leaves room for beside it, then replacing the list with exactly the
   configured controllers, which removes itself — so that the first step is verifiable by
   reading the archive's controller list, which it is still entitled to do, and the
   second cannot fail in a way that matters: its only outcomes are that the ledger is
   still a controller and may retry, or that it is not, which is the state the handover
   was for.
12. WHEN a retry of either step is refused because THE Ledger is no longer a
   controller, THE Ledger SHALL treat that archive's handover as complete and remove it
   from the count in C1.10, because the archive is then governable by the configured
   controllers and nothing further is within the ledger's reach — and a retry after a
   lost second step begins with the first, which is where that refusal arrives.
13. THE Ledger SHALL keep a record of every archive still owed a handover rather than
   only the most recent, because C1.9 lets archiving continue past a failed handover, so
   an archive can fill and a later one be adopted while the first is still owed one —
   and a single slot would drop the earlier archive, leaving it ledger-controlled with
   nothing recording it.
14. THE Ledger SHALL have committed the record in C1.13 before making either handover
   call for that archive, because the call's own await is what commits the message that
   wrote the entry, so a trap between the write and that await — encoding the call is
   enough — discards the entry while nothing was sent, and doing the write in a round of
   its own removes that window at the cost of one round.
