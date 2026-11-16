use ic_base_types::PrincipalId;
use ic_config::subnet_config::SchedulerConfig;
use ic_error_types::ErrorCode;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{PayloadBuilder, StateMachine, StateMachineBuilder};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::messages::MessageId;
use ic_types_cycles::Cycles;
use std::time::Instant;

/// `attack` first grows its stable memory enough to cover any charge this
/// test could ever fire (so the bounds check against the actual stable
/// memory size — which now runs *before* the charge, following an upstream
/// fix reordering that check ahead of it for stable64_read/stable64_write —
/// does not short-circuit the attack before it reaches the charge at all),
/// then burns most of the message's total instruction budget down to just
/// above `target_remaining` (through many real, legitimate DTS-paused
/// slices), then calls `stable64_read` with a length just above what is
/// actually left (charged to the instruction counter before the *heap*
/// bounds check, so the call never actually completes the copy into the
/// tiny Wasm heap).
///
/// `target_remaining` is comfortably above the slice limit (so the message
/// is never treated as being on its very last possible slice, regardless of
/// the charge) and the charge is comfortably below the slice limit, so that
/// `newly_executed` for the charge's slice — which covers *all* of that
/// slice's consumption, not just the charge, including however much of the
/// burn's last, bounded-but-not-exactly-zero tail happens to land in the
/// same (fresh) slice — stays, even in the worst case, under
/// `2 * slice_limit`: the point past which the out-of-instructions handling
/// fails the message outright instead of letting DTS continue into a new
/// slice, regardless of the cap under test here. The burn is done in small
/// chunks, re-checking `performance_counter(0)` after each, to keep that
/// tail small and bounded (a single huge burn could overshoot the target by
/// up to a whole slice, large enough to blow this budget on its own and
/// mask the cap's effect).
///
/// Only this narrow, budget-relative window exercises
/// `DeterministicTimeSlicing::newly_executed` in
/// `rs/canister_sandbox/src/dts.rs`, which has its own, separate cap from
/// (and is not exercised by) the `slice_instructions_executed` cap in
/// `rs/embedders`: a charge far below this window never leaves the
/// message's "fair share" of a slice, and one far above it (e.g. the
/// previously used `0x8000000000000000`-style "astronomic" charge) always
/// exceeds `2 * slice_limit` on its own, regardless of how much budget is
/// actually left, and so never continues either — it always fails
/// immediately via the (already fixed, independent) `slice_instructions_executed`
/// cap, before `DeterministicTimeSlicing::newly_executed` even matters.
fn make_wat() -> String {
    let scheduler_config = SchedulerConfig::application_subnet();
    let message_limit = scheduler_config.max_instructions_per_message.get();
    let slice_limit = scheduler_config.max_instructions_per_slice.get();

    let target_remaining = slice_limit * 3 / 2;
    // Empirically, this loop shape costs 9 instructions per iteration
    // (measured via `performance_counter`).
    let chunk_instructions = slice_limit / 10;
    let chunk_iterations = chunk_instructions / 9;
    // Positions the charge above what's left (so the cap on `newly_executed`
    // actually matters) while keeping `target_remaining + margin +
    // chunk_instructions` (the worst case, with a maximal burn tail bounded
    // by one chunk) comfortably under `2 * slice_limit`.
    let margin = slice_limit / 10;
    // Stable memory must actually be this large (in bytes) for the charge
    // below to reach the instruction-counter decrement at all: the bounds
    // check against the *actual* stable memory size now runs before that
    // decrement. Comfortably covers the worst-case charge
    // (`target_remaining + margin + chunk_instructions`, i.e. a bit under
    // `2 * slice_limit`), rounded up to whole pages with some slack.
    const WASM_PAGE_SIZE: u64 = 65536;
    let stable_pages = 2 * slice_limit / WASM_PAGE_SIZE + 10;

    format!(
        r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
  (import "ic0" "stable64_read" (func $s64r (param i64 i64 i64)))
  (import "ic0" "performance_counter" (func $perf_counter (param i32) (result i64)))
  (memory 1)
  (func $burn_chunk (local $i i64)
    (loop $l
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br_if $l (i64.lt_u (local.get $i) (i64.const {chunk_iterations})))))
  ;; Burns chunk by chunk, re-checking `performance_counter(0)` after each,
  ;; until at most `target_remaining` instructions are left in the total
  ;; budget. Returns how many instructions have been used so far.
  (func $burn_near_budget (result i64) (local $remaining i64)
    (local.set $remaining
      (i64.sub (i64.const {message_limit}) (call $perf_counter (i32.const 0))))
    (block $done
      (loop $l
        (br_if $done (i64.le_s (local.get $remaining) (i64.const {target_remaining})))
        (call $burn_chunk)
        (local.set $remaining
          (i64.sub (i64.const {message_limit}) (call $perf_counter (i32.const 0))))
        (br $l)))
    (i64.sub (i64.const {message_limit}) (local.get $remaining)))
  (func $attack (local $used i64) (local $remaining i64) (local $charge i64)
    ;; Grow stable memory first so the charge below passes the bounds check
    ;; against the actual stable memory size; its own (comparatively tiny,
    ;; fixed) cost is absorbed by burn_near_budget's dynamic targeting below.
    (drop (call $stable64_grow (i64.const {stable_pages})))
    (local.set $used (call $burn_near_budget))
    (local.set $remaining (i64.sub (i64.const {message_limit}) (local.get $used)))
    (local.set $charge (i64.add (local.get $remaining) (i64.const {margin})))
    (call $s64r (i64.const 0) (i64.const 0) (local.get $charge))
    (call $msg_reply))
  (export "canister_update attack" (func $attack)))
"#
    )
}

#[test]
fn round_budget_wrap() {
    let scheduler_config = SchedulerConfig::application_subnet();
    let slice_limit = scheduler_config.max_instructions_per_slice.get();

    let sm = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let canister = sm.create_canister_with_cycles(None, Cycles::new(1 << 60), None);
    sm.install_existing_canister(canister, wat::parse_str(make_wat()).unwrap(), vec![])
        .unwrap();

    let message_limit = scheduler_config.max_instructions_per_message.get();
    let err = sm
        .execute_ingress(canister, "attack", vec![])
        .expect_err("the oversized charge must not let the message complete successfully");
    assert_eq!(err.code(), ErrorCode::CanisterInstructionLimitExceeded);
    // Without the cap on `DeterministicTimeSlicing::newly_executed` in
    // `rs/canister_sandbox/src/dts.rs`, a system API call that charges more
    // instructions than are left in the total budget gets reported, for the
    // slice that contains it, as using at least `2 * slice_limit` instructions,
    // and the message fails with a `SliceOverrun` ("exceeded the slice limit")
    // even though it is the message budget that has been exhausted. With the
    // cap, the slice's consumption is bounded by what is left in the message
    // budget, so the message fails for exceeding the message instruction limit.
    let expected = format!(
        "Canister exceeded the limit of {message_limit} instructions for single message execution."
    );
    assert!(
        err.description().contains(&expected),
        "a system API call charging more instructions than are left in the total budget \
         must exhaust the message instruction limit (and not overrun the slice limit {slice_limit}), \
         got: {}",
        err.description()
    );
}

/// Regression test for the round instruction budget wrapping due to an
/// unbounded number of instructions reported as executed in a slice.
///
/// A system API call that charges a huge fee before failing (here
/// `msg_arg_data_copy` with a huge length in a Wasm64 canister, charged before
/// any bounds or context check) drives the instruction counter far below zero.
/// On a fresh (first) slice this always exceeds `2 * max_instructions_per_slice`
/// on its own (regardless of how much budget is actually left), so
/// `DeterministicTimeSlicing::newly_executed` (`rs/canister_sandbox/src/dts.rs`)
/// is not involved: the out-of-instructions handling fails the message
/// outright via `SliceOverrun`. The bug instead lived in the embedders-level
/// `slice_instructions_executed`, which reports the *final* slice's executed
/// instructions once `instance.run()` returns (whether the message completed
/// or the failure above ended it) and which feeds `update_round_limits` for
/// that slice. Unfixed, it reported this same unbounded value, and deducting
/// it from the round instruction budget twice (for the reply and the cleanup
/// callback of the same response) overflowed: with debug assertions, the
/// replica panicked with `attempt to subtract with overflow`; without them, the
/// round instruction budget wrapped, letting a single execution round drain
/// far more than its share of the queued messages.
///
/// Two fixes independently prevent this, and the test only fails if both are
/// reverted: capping `slice_instructions_executed` at the instructions left for
/// the message (in `rs/embedders`) and deducting instructions from the round
/// limits with saturating subtraction (`RoundLimits::deduct_instructions`).
mod astronomic_charge {
    use super::*;

    const N_BURNS: usize = 30;

    // `go` calls the canister itself. With env = 1 the reply callback and the
    // cleanup callback both call `msg_arg_data_copy` with a huge length; with
    // env = 0 they just trap. The canister is a Wasm64 module so that the length
    // can be (almost) as large as `i64::MAX` and it is charged (1 instruction per
    // byte) to the instruction counter before any bounds or context check
    // (unlike for `stable64_read`, whose bounds are checked before the charge).
    // The length must keep the charge within `i64::MAX` (otherwise the call
    // fails without charging anything), while the two charges together must
    // exceed it (so that deducting both from the round budget overflows).
    // `burn` executes about 1.5 billion instructions (below the 2B slice limit).
    const WAT: &str = r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "call_new" (func $call_new (param i64 i64 i64 i64 i64 i64 i64 i64)))
  (import "ic0" "call_on_cleanup" (func $call_on_cleanup (param i64 i64)))
  (import "ic0" "call_perform" (func $call_perform (result i32)))
  (import "ic0" "canister_self_size" (func $self_size (result i64)))
  (import "ic0" "canister_self_copy" (func $self_copy (param i64 i64 i64)))
  (import "ic0" "msg_arg_data_copy" (func $arg_copy (param i64 i64 i64)))
  (memory i64 1)
  (table 2 funcref)
  (elem (i32.const 0) $on_reply $on_cleanup)
  (func $on_reply (param $env i64)
    (if (i64.ne (local.get $env) (i64.const 0))
      (then (call $arg_copy (i64.const 0) (i64.const 0) (i64.const 0x7000000000000000)))
      (else unreachable)))
  (func $on_cleanup (param $env i64)
    (if (i64.ne (local.get $env) (i64.const 0))
      (then (call $arg_copy (i64.const 0) (i64.const 0) (i64.const 0x7000000000000000)))
      (else unreachable)))
  (func $call_self (param $env i64)
    (call $self_copy (i64.const 0) (i64.const 0) (call $self_size))
    (call $call_new (i64.const 0) (call $self_size) (i64.const 100) (i64.const 4)
      (i64.const 0) (local.get $env) (i64.const 0) (local.get $env))
    (call $call_on_cleanup (i64.const 1) (local.get $env))
    (drop (call $call_perform))
    (call $msg_reply))
  (func $go (call $call_self (i64.const 1)))
  (func $go_control (call $call_self (i64.const 0)))
  (func $noop (call $msg_reply))
  (func $burn (local $i i64)
    (loop $l
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br_if $l (i64.lt_u (local.get $i) (i64.const 180000000))))
    (call $msg_reply))
  (data (i64.const 100) "noop")
  (export "canister_update go" (func $go))
  (export "canister_update go_control" (func $go_control))
  (export "canister_update noop" (func $noop))
  (export "canister_update burn" (func $burn)))
"#;

    fn done(sm: &StateMachine, ids: &[MessageId]) -> usize {
        ids.iter()
            .filter(|id| {
                matches!(
                    sm.ingress_status(id),
                    IngressStatus::Known {
                        state: IngressState::Completed(_),
                        ..
                    }
                )
            })
            .count()
    }

    // Puts `trigger` and N_BURNS `burn` calls into one block, then runs
    // rounds and returns the largest number of burns completed in a single
    // round.
    fn max_burns_per_round(trigger: &str) -> usize {
        let sm = StateMachineBuilder::new()
            .with_subnet_type(SubnetType::Application)
            .build();
        let canister = sm.create_canister_with_cycles(None, Cycles::new(1 << 60), None);
        sm.install_existing_canister(canister, wat::parse_str(WAT).unwrap(), vec![])
            .unwrap();
        let user = PrincipalId::new_anonymous();
        let mut block = PayloadBuilder::new()
            .with_max_expiry_time_from_now(sm.time())
            .with_nonce(1)
            .ingress(user, canister, trigger, vec![]);
        for i in 0..N_BURNS {
            block = block.ingress(user, canister, "burn", vec![i as u8]);
        }
        let burns = block.ingress_ids()[1..].to_vec();
        sm.execute_payload(block);
        let (mut max, mut prev) = (done(&sm, &burns), done(&sm, &burns));
        for round in 1..=2 * N_BURNS {
            let t = Instant::now();
            sm.tick();
            let now = done(&sm, &burns);
            println!(
                "[{trigger}] round {round}: {} burns in {:?}",
                now - prev,
                t.elapsed()
            );
            max = max.max(now - prev);
            prev = now;
            if now == N_BURNS {
                break;
            }
        }
        assert_eq!(prev, N_BURNS);
        max
    }

    #[test]
    fn round_budget_wrap_astronomic_charge() {
        let control = max_burns_per_round("go_control");
        let attack = max_burns_per_round("go");
        println!("max burns in one round: control {control}, attack {attack}");
        assert!(
            control <= 3,
            "a round normally fits ~2 burns (4B instructions)"
        );
        assert!(
            attack <= 3,
            "huge instruction charges in callbacks must not wrap the round budget"
        );
    }
}
