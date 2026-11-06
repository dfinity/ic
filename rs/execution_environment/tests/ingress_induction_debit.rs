use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_error_types::ErrorCode;
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig, WasmResult};
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::{CanisterId, PrincipalId};
use ic_types_cycles::Cycles;

// Regression test for charging the ingress induction debit after a long-running
// cleanup callback grows memory and burns the remaining liquid cycles balance.

const T: u128 = 1_000_000_000_000;

/// Number of universal canisters deployed to fill up the subnet memory.
const NUM_MEMORY_HOGS: usize = 20;

/// Cycles and reserved cycles limit of each memory-hog canister: 100,000T.
const MEMORY_HOG_CYCLES: u128 = 100_000 * T;
const MEMORY_HOG_RESERVED_CYCLES_LIMIT: u128 = 100_000 * T;

/// Cycles and reserved cycles limit of the canister `C`: 100T.
const C_CYCLES: u128 = 100 * T;
const C_RESERVED_CYCLES_LIMIT: u128 = 100 * T;

/// A WASM page is 64 KiB.
const WASM_PAGE_SIZE: u64 = 64 * 1024;
/// 50 GiB expressed in WASM pages (`ic0.stable64_grow` operates on pages).
const FIFTY_GIB_IN_PAGES: u64 = 50 * 1024 * 1024 * 1024 / WASM_PAGE_SIZE;
/// 1 GiB expressed in WASM pages.
const ONE_GIB_IN_PAGES: u64 = 1024 * 1024 * 1024 / WASM_PAGE_SIZE;

/// Number of instructions the cleanup callback of `C` spins for.
const SPIN_INSTRUCTIONS: u64 = 30_000_000_000;

/// The message the reply callback of `C` traps with.
const REPLY_CALLBACK_TRAP_MESSAGE: &str = "trapping-in-reply-callback";

/// Safety bound on the number of rounds the concurrent phase runs for.
const MAX_ROUNDS: usize = 1_000;

/// Creates a canister via the provisional management canister API with the given
/// amount of cycles, reserved cycles limit and (optional) freezing threshold,
/// and installs the universal canister onto it (with the given init payload).
fn create_universal_canister(
    env: &StateMachine,
    cycles: u128,
    reserved_cycles_limit: u128,
    freezing_threshold: Option<u64>,
    init_payload: Vec<u8>,
) -> CanisterId {
    let mut settings =
        CanisterSettingsArgsBuilder::new().with_reserved_cycles_limit(reserved_cycles_limit);
    if let Some(freezing_threshold) = freezing_threshold {
        settings = settings.with_freezing_threshold(freezing_threshold);
    }
    env.install_canister_with_cycles(
        UNIVERSAL_CANISTER_WASM.to_vec(),
        init_payload,
        Some(settings.build()),
        Cycles::from(cycles),
    )
    .expect("failed to create and install universal canister")
}

#[test]
fn ingress_induction_debit() {
    // Application subnet `StateMachine` with the default (production) subnet
    // memory capacity and reservation threshold, so that filling the subnet
    // memory triggers cycles reservation just like on a real subnet.
    let subnet_type = SubnetType::Application;
    let subnet_config = SubnetConfig::new(subnet_type);
    let execution_config = ExecutionConfig::default();
    let config = StateMachineConfig::new(subnet_config, execution_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .build();

    // Phase I: deploy 20 memory-hog canisters, each growing its stable memory to
    // 50 GiB. This pushes the subnet memory usage above the reservation
    // threshold, so the canisters need a high reserved cycles limit and balance.
    for index in 0..NUM_MEMORY_HOGS {
        let canister_id = create_universal_canister(
            &env,
            MEMORY_HOG_CYCLES,
            MEMORY_HOG_RESERVED_CYCLES_LIMIT,
            None,
            vec![],
        );
        // `ic0.stable64_grow` returns the previous number of stable memory pages
        // on success and `u64::MAX` on failure.
        let reply = env
            .execute_ingress(
                canister_id,
                "update",
                wasm()
                    .stable64_grow(FIFTY_GIB_IN_PAGES)
                    .reply_int64()
                    .build(),
            )
            .expect("failed to grow stable memory to 50 GiB");
        let previous_pages = match reply {
            WasmResult::Reply(bytes) => {
                u64::from_le_bytes(bytes.try_into().expect("expected an 8-byte reply"))
            }
            WasmResult::Reject(reject) => {
                panic!("unexpected reject growing stable memory: {reject}")
            }
        };
        assert_ne!(
            previous_pages,
            u64::MAX,
            "growing stable memory of memory-hog canister {index} to 50 GiB failed"
        );
    }

    // Phase II: deploy the canister `C` with a freezing threshold of 0.
    let c_id = create_universal_canister(&env, C_CYCLES, C_RESERVED_CYCLES_LIMIT, Some(0), vec![]);

    // The cleanup callback of `C`: grow stable memory to 1 GiB, burn all the
    // remaining liquid cycles balance (whose exact amount is determined via
    // `ic0.canister_liquid_cycle_balance128`) and spin for 30B instructions.
    // This cleanup runs exactly once, for the single self-call update below; the
    // background update calls do not trigger it (see below).
    let cleanup = wasm()
        .stable64_grow(ONE_GIB_IN_PAGES)
        .cycles_burn_liquid_balance()
        .instruction_counter_is_at_least(SPIN_INSTRUCTIONS)
        .build();

    // The update call executed on `C`: perform a self-call whose callee replies
    // with an empty blob; the reply callback traps and the cleanup callback above
    // runs afterwards.
    let self_call_payload = wasm()
        .inter_update(
            c_id,
            call_args()
                .other_side(wasm().reply_data(&[]))
                .on_reply(wasm().trap_with_blob(REPLY_CALLBACK_TRAP_MESSAGE.as_bytes()))
                .on_cleanup(cleanup),
        )
        .build();

    // The payload of the background update calls: a plain update call that simply
    // replies. These calls only serve to keep inducting ingress messages into `C`
    // (and paying the ingress induction cost); they do not perform a self-call, so
    // they do not trigger `C`'s cleanup callback.
    let background_payload = wasm().reply().build();

    // Phase III: submit the self-call update on `C` (without awaiting its result)
    // and then keep submitting further (plain) update calls to `C` in every round
    // while the self-call update is being processed. Once `C` can no longer pay
    // the ingress induction cost (its cleanup burns all liquid cycles), the
    // ingress filter starts rejecting the background calls, which is the ingress
    // induction debit behavior under test.
    let anonymous = PrincipalId::new_anonymous();
    let main_msg = env.send_ingress(anonymous, c_id, "update", self_call_payload);

    // Record C's pending ingress induction cycles debit in every round.
    let mut debits = Vec::new();
    let mut result = None;
    for _round in 0..MAX_ROUNDS {
        match env.ingress_status(&main_msg) {
            IngressStatus::Known {
                state: IngressState::Completed(reply),
                ..
            } => {
                result = Some(Ok(reply));
                break;
            }
            IngressStatus::Known {
                state: IngressState::Failed(error),
                ..
            } => {
                result = Some(Err(error));
                break;
            }
            _ => {}
        }
        // Keep submitting background update calls without awaiting their result;
        // `send_ingress_safe` returns an error once `C` can no longer pay the
        // ingress induction cost, which we ignore here.
        let _ = env.send_ingress_safe(anonymous, c_id, "update", background_payload.clone());
        env.tick();
        debits.push(
            env.get_latest_state()
                .canister_state(&c_id)
                .expect("C should exist in the latest state")
                .system_state
                .ingress_induction_cycles_debit(),
        );
    }
    let result = result.unwrap_or_else(|| {
        panic!("the update call on C did not complete within {MAX_ROUNDS} rounds")
    });

    // While the self-call update is being processed, C is busy executing its long
    // cleanup callback and cannot execute (and thereby charge) the queued
    // background update calls, so its pending ingress induction cycles debit keeps
    // growing as those calls are inducted.
    let increasing_steps = debits.windows(2).filter(|w| w[1] > w[0]).count();
    assert!(
        increasing_steps >= 2,
        "expected C's ingress induction cycles debit to grow while the update was being \
         processed, but observed debits: {debits:?}"
    );

    // The update call is rejected because the reply callback traps. Note that this
    // rejection is produced by the reply callback trap regardless of whether the
    // cleanup callback subsequently succeeds or itself traps, so it alone does not
    // tell us anything about the cleanup callback.
    let err = result.expect_err("the update call on C should have been rejected");
    assert_eq!(
        err.code(),
        ErrorCode::CanisterCalledTrap,
        "unexpected error from the update call on C: {err}"
    );
    assert!(
        err.description().contains(REPLY_CALLBACK_TRAP_MESSAGE),
        "the update call on C should have been rejected due to the reply callback trapping with \
         {REPLY_CALLBACK_TRAP_MESSAGE:?}, but got: {err}"
    );

    // Verify that the cleanup callback ran to completion (i.e., did not trap). A
    // trap anywhere in the cleanup callback rolls back all of its state changes,
    // so C's stable memory being 1 GiB proves that the whole cleanup callback
    // (grow stable memory + burn liquid cycles + spin) succeeded. Queries are not
    // charged cycles, so this works even though the cleanup burned all of C's
    // liquid cycles balance.
    let reply = env
        .query(c_id, "query", wasm().stable64_size().reply_int64().build())
        .expect("failed to query the stable memory size of C");
    let stable_pages = match reply {
        WasmResult::Reply(bytes) => {
            u64::from_le_bytes(bytes.try_into().expect("expected an 8-byte reply"))
        }
        WasmResult::Reject(reject) => {
            panic!("unexpected reject querying stable memory size: {reject}")
        }
    };
    assert_eq!(
        stable_pages, ONE_GIB_IN_PAGES,
        "C's cleanup callback did not grow the stable memory to 1 GiB ({ONE_GIB_IN_PAGES} pages), \
         i.e., it did not run to completion"
    );

    // The cleanup callback kept the cycles it reserved for growing its stable
    // memory. Query `canister_status` to assert that C ends up with non-zero
    // reserved cycles.
    let status = env
        .canister_status_query_as(anonymous, c_id)
        .expect("failed to query the status of C")
        .expect("canister_status of C was rejected");
    assert!(
        status.reserved_cycles() > 0,
        "C should have non-zero reserved cycles, got {}",
        status.reserved_cycles()
    );

    // By the end of the test the self-call update has completed, so C's pending
    // ingress induction cycles debit must have been applied to its balance and
    // reset back to zero.
    let final_debit = env
        .get_latest_state()
        .canister_state(&c_id)
        .expect("C should exist in the latest state")
        .system_state
        .ingress_induction_cycles_debit();
    assert_eq!(
        final_debit,
        Cycles::zero(),
        "C's ingress induction cycles debit should be zero at the end of the test, got \
         {final_debit}"
    );
}
