---
id: DEFI-3018
title: Archive Creation And Handover
tags: [ledger, archive, icrc, icp]
---

# Archive Creation And Handover — Design

*Companion to [`requirements.md`](requirements.md), and part **C** of the specification;
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

*Decisions are numbered across the whole specification; none is specific to this part.
The creation protocol follows from D2 (what state survives an upgrade) and D9 (which
calls are bounded), both in the ledger design.*

## Implementation

### `ledger_canister_core::archive` — `Archive` state, the creation journal

Creation state is the exception, and is persisted:

    #[serde(default)]                                      // Idle is Default
    creating: Creating,
    #[serde(default)]                                      // empty is Default
    pending_handovers: Vec<CanisterId>,

    enum Creating { Idle, Started, Created(CanisterId) }   // Default = Idle

`Started` before `create_canister`, `Created(id)` as soon as it returns — **and the
round ends there**, see below — `Idle` when `nodes.push` succeeds. `Started` needs no
round of its own: the await that issues `create_canister` is where its message ends and
commits, so a trap in the *callback* cannot roll it back, and a trap *before* the await
means no call was made and no canister exists — returning to `Idle` is then correct. Both non-`Idle` states are exposed (`C1.2`), with the id
when there is one (`C1.7`), but **they do not have the same effect and must not
be collapsed into one halt**:

| state | effect |
|---|---|
| `Started` | no blocks move, and nothing resumes on its own (`C1.1`, `C1.4`) — a canister may exist that cannot be named, so an operator has to look |
| `Created(id)` | the round *finishes the creation first* and then proceeds (`C1.8`) — it is a "do this before archiving" state, not a halt |

Treating every non-`Idle` state as a halt would make `C1.8` unreachable, because
the halt is implemented as a skip in `blocks_to_archive` *before* the guard is taken:
a `Created(id)` round would be skipped and would never reach the reconciliation it
exists to perform.

This is ICP's journaling pattern — record intent before the work and the result
after — which its guidance recommends over trying to avoid traps after an await. It
is persisted rather than `#[serde(skip)]` like the rest of D2's state, because an
orphan must outlive an upgrade or the upgrade becomes a way to forget it.

Being persisted, it needs `#[serde(default)]` with `Idle` as `Default`. `Archive` is
CBOR-decoded on every ledger upgrade, so a required new field would fail to decode
every pre-change state — the journal would break the first upgrade it shipped in,
before it could help with anything. `Archive` already does this for its later-added
fields (`archive.rs:33, 36, 39, 148`), so the pattern is established rather than
novel.

`pending_handovers` is a second field for the same reason, and it is needed because
`C1.9` moved the handover *after* adoption: `Creating` returns to `Idle` when
`nodes.push` succeeds, so without it nothing records which adopted archive still owes
a handover, and `C1.10`'s retry and metric would have nothing to work from — least
of all across an upgrade. An archive is added when it is adopted, and removed when the
handover is confirmed or its retry refused as unauthorized (`C1.11`) — the two ways the
ledger can know it is done.

**Adoption ends the round; the handover starts on the next** (`C1.13`). This is the
same durability point as `Created(id)`, and it is worth being precise about which trap
it guards against, because the obvious one is not it. A trap in `update_settings`'
*callback* cannot roll back the entry: the message that pushed it ended — and committed —
at the call's own await. The window is the stretch *between* the push and that await,
where encoding the call is enough to trap under this design's own allocation stance; a
trap there discards the entry while nothing was sent, which is merely a lost round, but
if the push shares a message with earlier work that did commit elsewhere it is a lost
record. Ending the round at adoption (`nodes.push`, the `pending_handovers` entry,
`Creating` back to `Idle`) removes the question, at the cost of one round per archive fill.

**A collection rather than one slot, because `C1.9` lets archiving continue**
(`C1.12`). A single `Option` looks sufficient and is not: a failed handover does not
stop archiving, so that archive keeps filling, and when it fills the next archive is
adopted and overwrites the slot. The first archive is then ledger-controlled forever
with nothing recording it, and the metric clears when the *second* completes — a silent
loss of exactly the governability the handover exists to establish. It takes a whole
archive to fill against a persistently failing handover, so it is remote; it is also invisible and
permanent, and a `Vec` costs nothing. One retry per round, so the work stays bounded — and the entry retried
rotates: after each attempt, success or failure, the next round takes the next entry,
so a handover that keeps failing cannot starve the ones adopted after it.

**Each entry is just a canister id.** A retry re-issues the same call; if the earlier one
had already committed, the retry comes back unauthorized, which `C1.11` clears on. Nothing
about progress needs recording.

**Two of the three orphan windows stop being write-offs, and only `Idle` may be
restored.** `create_and_initialize_node_canister` runs `create_canister` →
`install_code` → `update_settings` → `nodes.push`, each with `?` (`archive.rs:455`,
`:461`, `:489`, `:508`), so a graceful `Err` from either middle step returns with
**the canister already created** and its id dropped on the stack. Recording the id as
soon as `create_canister` returns (`C1.6`) makes those two windows *recoverable*:
an operator can finish or delete a canister the ledger can name. Only a trap in
`create_canister`'s own reply is irreducible, and `Started` covers it — a halt with no
id, precisely the "a canister may exist and I cannot name it" case.

**"Recording" means committing, and an assignment in the callback is not that.** State
written in the `create_canister` callback becomes durable only when that message ends;
until then a trap rolls it back to `Started` and the id is lost — and the very next
thing the current code does in that callback is encode the multi-megabyte
`install_code` argument, which is the allocation this design flags as a trap source. So
`C1.6` cannot be met by writing `Created(id)` and carrying on. The round records
`Created(id)` and **ends**; the next round finds it and finishes the creation, which is
the path `C1.8` already describes for a round that died after the identity was
recorded. Making that the only path rather than the recovery path means there is one
code path, the heavy encode runs at the start of a round with the id already durable,
and creation costs one extra round — which is once per archive fill, so nothing. The
`spawn.rs` allocation work below still applies to that later round.

So `C1.3` is the pre-creation case and `C1.5` the post-creation one, and the
implementation is that distinction: return to `Idle` only where `create_canister`
itself returned `Err`. Doing it anywhere later would hand those two windows back to
`L4`'s backoff and defeat `C1.1`'s halt entirely. An unknown outcome of
`update_settings` — a lost reply on a call that may well have succeeded — is resolved by
the retry rule below, not by a timeout.

### `ledger_canister_core::runtime` — the creation and handover calls

The bounded/unbounded table itself is in
[`../ledger-reconciliation/design.md`](../ledger-reconciliation/design.md); this is why
its three management-canister rows read as they do.

**All three are unbounded, and that is the simpler choice rather than a concession.**
Bounding a call buys two things: no response-memory reservation while it is in flight
(D9), and a ledger that can be stopped within `ARCHIVE_CALL_TIMEOUT` (`L7.8`). Both
matter for the calls a ledger makes on every round; neither is measurable for calls made
once per archive fill that the management canister answers within a round. An earlier
draft bounded `install_code` and the handover on the grounds that their unknown outcomes
are resolvable — which is true — and spent a page establishing it. Being *able* to bound
them is not a reason to. They stay on `Call::unbounded_wait`, as today, and `L7.7` says
so.

**A handover is one call, retried until it is known to have landed.** `update_settings`
replaces the ledger with the configured controllers (`archive.rs:366-372`, `:489-497`),
and the management canister validates the caller before applying settings
(`canister_manager.rs:690`) — so once it has succeeded the ledger is no longer a
controller and can neither retry nor query. That is not the problem it looks like. A
failure the ledger *observes* is retried on a later round while it is still a controller
(`C1.10`). A success whose reply the ledger *lost* — a reply-buffer trap after the
controllers changed — leaves the entry in `pending_handovers`, and the retry comes back
unauthorized, which is proof the earlier call landed: `C1.11` treats that refusal as
completion. Both readings of an unauthorized retry lead to the same end state, so nothing
is read into a reject code that the state does not already imply. This rests on a fact
of construction worth stating: `create_canister` is called with
`CreateCanisterArgs::default()` (`spawn.rs:41-43`), so the new canister's *only*
controller is the ledger until the handover lands, and no other principal can change its
settings in the meantime — an unauthorized retry can therefore mean nothing but that the
ledger's own call succeeded. An earlier draft split
this into two calls so the first could be verified by reading the controller list; the
single call needs no verification step, because the only way it can be unauthorized is by
having succeeded.

**The configured set must have at most ten distinct controllers, and the list sent is
de-duplicated.** The platform allows ten (`MAX_CONTROLLERS`,
`management_canister_types/src/lib.rs:51`) and its Candid type bounds the *encoded*
vector before canister state collapses duplicates (`bounded_vec.rs:111`), while
`ArchiveOptions` builds the list from `controller_id` plus an unbounded
`more_controller_ids` (`archive.rs:369-372`). A larger set is a misconfiguration under
which the handover is rejected on every retry and `C1.10` never clears. Enforcing the
bound belongs where the configuration is made — the ledger's `init` and `post_upgrade` —
and is a separate, minimal change rather than part of this work (README, non-goals).

Ordering is the other half — **adopt the archive before handing over control**
(`C1.9`) — so that an observed handover failure does not block archiving while it is
retried. Adoption ends the creation's critical path, and the handover becomes a separate
step the ledger retries on later rounds while it is still a controller (`C1.10`). A lost
handover then leaves a fully adopted, working archive that is merely still
ledger-controlled — recoverable, and visible on a metric — rather than an ambiguous state
that blocks archiving.

**`install_code`'s unknown outcome is reconciled by asking, not by timing out.** A blind
retry of `install` mode fails if a module is already installed; a reconciled one does
not. At that point the ledger is still the new canister's only controller — the handover
has not run — so it calls `canister_status` and reads `module_hash`: absent means the
install did not happen and may be retried, present and matching means it did.
`canister_status` is read-only and so resolvable by asking again, which terminates the
regress. This is what `C1.8` runs after a callback trap, and it is why the call being
unbounded costs nothing: the outcome is learned from the canister, not from the reply.

**There is a third reading, and it halts.** Present but *not* matching means the canister
carries a module this ledger did not install — reachable if the install committed, its
outcome was lost, and the ledger was upgraded to a build embedding a different archive
wasm before the next round reconciled, since `Created(id)` records only the id. The
ledger could reinstall (it is the sole controller of an empty, unadopted canister), adopt
what is there, or record the intended hash to recognise the case; it does none of them
(`C1.14`). It stops archiving, exposes the id and a distinct metric, and leaves the
decision to an operator — because the state has never been seen in production, every
automatic answer adds mechanism for a case that may never occur, and a halt with a
readable reason is the cheapest thing that is also safe. If production ever produces it,
that is the moment to choose.

This shrinks the halt population rather than the safety. `C1.8` lets the ledger finish a
creation whose identity it recorded, so what still needs an operator is a lost
`create_canister` reply — a canister that exists and cannot be named, which is what
`C1.4` is scoped to — and the foreign module of `C1.14`.

### `ledger_canister_core::spawn`

`install_code` takes `Vec<u8>`, forcing `archive_wasm().into_owned()`, and `Rt::call`
then serialises it again — two multi-MB copies in the continuation after
`create_canister` committed. Take `Cow<'static, [u8]>`, pre-reserve the encode buffer
before the first await, and `nodes.reserve(1)`. This lowers the probability of the
trap that produces an orphan; it does not remove it, which is why `C1` exists.

Correct the comment above `create_canister` (`archive.rs:452-454`): it claims a panic
there rolls the triggering transaction back, which holds only for the first node a
ledger ever creates. On a roll-over `node_and_capacity` awaits `remaining_capacity`
first (`archive.rs:547-549`), committing the transaction, so a panic rejects the reply
instead. The comment should state that condition rather than the conclusion.

### Error construction

`FailedToArchiveBlocks(pub String)` allocates on every error, so an allocation failure
turns a graceful `Err` into a trap. Replace it with an enum carrying `Copy` payloads,
rendered to text only where logged. `Rt::print` takes `impl AsRef<str>`, so
non-interpolating messages become `&'static str` for free.

**The rendering is not free either, which "only where logged" can be read as implying.**
`log!` formats before it appends (`ic_canister_log/src/lib.rs:53`), so every line
allocates a `String` sized to the message, and an argument's own `Display` may allocate
again — `CanisterId`'s goes through `to_text()`. The ring buffer itself is safe: it is
allocated once at init and evicts before pushing (`:114-119`), so it never grows. Moving
text out of the error value therefore moves the allocation to the log site rather than
removing it, which is a reason to keep logged messages short, not a reason to keep them
in the error.

**Keep** the canister id in the `create_canister` callback log — canister logs survive
traps, verified by `test_appending_logs_in_trapped_update_call`
(`rs/execution_environment/tests/canister_logging.rs`), so it is the only record of an
orphan's identity — but drop the `{result:?}` debug format. Treat it as best-effort: a
log that survives a trap is not the same as one that is certain to be written, and under
the memory pressure that produces an orphan the `format!` is itself a plausible trap
site.

Expect little from this beyond keeping graceful failures graceful: these are tens to
hundreds of bytes, and a small allocation only fails once the irreducible reply buffer
allocated moments earlier would very likely have failed too.

## Test plan

*The baseline note, the seams the design owes, what is at risk and what is not
attempted are in the README's **Testing** section; they span the parts.*

| # | level | case | pins |
|---|---|---|---|
| 17 | integration | reuse the creation-trap harness so the `create_canister` reply is lost; assert `Creating` is `Started`, that it is exposed, and that it does not self-clear — no identity was recorded, so there is nothing to finish | `C1.1`, `C1.2`, `C1.4` |
| 17b | integration | lose the `install_code` outcome *after* the identity was recorded; assert the ledger resolves it by asking the created canister, finishes the creation without an operator, and adopts that same canister rather than creating a second. Then repeat with the created canister carrying a module of a different hash — a ledger upgraded mid-creation — and assert the ledger halts on its own metric with the id exposed, neither reinstalling nor adopting | `C1.6`, `C1.8`, `C1.14` |
| 17d | integration | lose the `update_settings` outcome; assert the archive is already adopted and serving, that archiving continues, that the handover metric is non-zero, and that a later round retries the handover and clears it | `C1.9`, `C1.10` |
| 17e | upgrade | decode a pre-change `Archive` state; assert it decodes and that both new fields read their defaults — `Idle` and an empty `pending_handovers` — so the journal's own release cannot be the upgrade that fails | the two `#[serde(default)]`s above |
| 17j | integration | let the `create_canister` callback end right after recording `Created(id)`, then trap at the start of the next round before any installation work; assert `Creating` still reads `Created(id)` with the real id — not `Started` — and that the creation is finished from there without a second canister. A trap *inside* the recording callback would prove nothing, rolling the write back to `Started` as the durability paragraph explains | `C1.6`, `C1.8` |
| 17k | integration | trap the callback of the handover call after the controllers have changed; assert the archive is still listed in `pending_handovers` on the next round and the handover is retried and completes — the entry that a same-message push would have rolled back | `C1.13`, `C1.12` |
| 17f | upgrade | adopt an archive whose handover has not completed, then upgrade the ledger; assert the pending handover survives and is still retried afterwards | `C1.10` |
| 17i | integration | fail one archive's handover, keep archiving until it fills and a second archive is adopted, and assert the first is still retried and still counted — the archive a single slot would have dropped. Then keep the first failing and assert the second's handover completes on a later round — rotation, so a persistent failure starves nothing behind it | `C1.12`, `C1.10` |
| 17m | integration | configure exactly ten controllers — the platform maximum — and drive the handover; assert the single `update_settings` is accepted and the handover completes rather than being rejected, and that a configured list with a repeated principal is sent de-duplicated | `C1.10`, the controller-count precondition |
| 21 | measurement | ledger memory across an archive-creation round, as `routine_archiving_does_not_grow_the_ledger` does for a routine one; assert growth below a bound | D2's allocation work |
| 25 | integration | fail `install_code` gracefully after `create_canister` succeeded; assert archiving halts, that the metric exposes the created canister's id and the id survives a ledger upgrade, and that a failure of `create_canister` itself does not halt | `C1.1`, `C1.3`, `C1.5`, `C1.6`, `C1.7` |
