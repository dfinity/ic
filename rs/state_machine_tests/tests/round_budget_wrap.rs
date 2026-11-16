use ic_base_types::PrincipalId;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{PayloadBuilder, StateMachine, StateMachineBuilder};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::messages::MessageId;
use ic_types_cycles::Cycles;

const N_BURNS: usize = 30;

// `go` calls the canister itself. With env = 1 the reply callback and the
// cleanup callback both call `msg_arg_data_copy` with a huge length; with
// env = 0 (`go_control`) they just trap. The canister is a Wasm64 module so
// that the length can be (almost) as large as `i64::MAX` and it is charged (1
// instruction per byte) to the instruction counter before any bounds or context
// check (unlike for `stable64_read`, whose bounds are checked before the
// charge). The length must keep the charge within `i64::MAX` (otherwise the
// call fails without charging anything), while the two charges together must
// exceed it (so that deducting both from the round budget overflows).
// `burn` executes about 1.6 billion instructions (below the 2B slice limit).
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

/// The outcome of running `trigger` together with `N_BURNS` `burn` calls.
struct Outcome {
    /// The largest number of burns completed in a single round.
    max_burns_per_round: usize,
    /// The cycles that the canister spent on the whole run.
    cycles_spent: u128,
}

// Puts `trigger` and `N_BURNS` `burn` calls into one block and then runs
// rounds until all burns have completed.
fn run(trigger: &str) -> Outcome {
    let sm = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let canister = sm.create_canister_with_cycles(None, Cycles::new(1 << 60), None);
    sm.install_existing_canister(canister, wat::parse_str(WAT).unwrap(), vec![])
        .unwrap();
    let initial_balance = sm.cycle_balance(canister);
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
    let mut prev = done(&sm, &burns);
    let mut max_burns_per_round = prev;
    for _ in 0..2 * N_BURNS {
        if prev == N_BURNS {
            break;
        }
        sm.tick();
        let now = done(&sm, &burns);
        max_burns_per_round = max_burns_per_round.max(now - prev);
        prev = now;
    }
    assert_eq!(prev, N_BURNS);
    Outcome {
        max_burns_per_round,
        cycles_spent: initial_balance - sm.cycle_balance(canister),
    }
}

/// Regression test for the round instruction budget wrapping due to an
/// unbounded number of instructions reported as executed in a slice.
///
/// A system API call that charges a huge fee before failing (here
/// `msg_arg_data_copy` with a huge length in a Wasm64 canister, charged before
/// any bounds or context check) drives the instruction counter far below zero.
/// The embedders-level `slice_instructions_executed` reports the instructions
/// executed in the final slice of a message and feeds `update_round_limits`.
/// Unfixed, it reported the unbounded value, and deducting it from the round
/// instruction budget twice (for the reply and the cleanup callback of the same
/// response) overflowed: with debug assertions, the replica panicked with
/// `attempt to subtract with overflow`; without them, the round instruction
/// budget wrapped, letting a single execution round drain far more than its
/// share of the queued messages.
///
/// Two fixes independently prevent this, and the test only fails if both are
/// reverted: capping `slice_instructions_executed` at the instructions left for
/// the message (in `rs/embedders`) and deducting instructions from the round
/// limits with saturating subtraction (`RoundLimits::deduct_instructions`).
#[test]
fn round_budget_wrap_astronomic_charge() {
    let control = run("go_control");
    let attack = run("go");
    // Make sure that the callbacks actually reach the oversized charge (and do
    // not, e.g., trap on a check made before it), as the test is vacuous
    // otherwise: with the charge, the canister pays for the whole message
    // instruction limit (40B instructions), which is on par with what it pays
    // for all the burns (~49B instructions) of the control run.
    assert!(
        attack.cycles_spent > control.cycles_spent + control.cycles_spent / 2,
        "the callbacks must be charged for the oversized charge: \
         control spent {} cycles, attack spent {} cycles",
        control.cycles_spent,
        attack.cycles_spent
    );
    assert!(
        control.max_burns_per_round <= 3,
        "a round normally fits ~2 burns (4B instructions)"
    );
    assert!(
        attack.max_burns_per_round <= 3,
        "huge instruction charges in callbacks must not wrap the round budget"
    );
}
