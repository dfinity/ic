use candid::{Decode, Encode};
use ic_nns_test_utils::common::build_node_rewards_test_wasm;
use pocket_ic::PocketIcBuilder;
use std::time::Duration;

/// Starts both a successful and a panicking `RecurringAsyncTaskNonSend`, then
/// verifies that:
///   - the successful task keeps rescheduling itself through normal execution, and
///   - the panicking task keeps being rescheduled via the recovery timer.
#[tokio::test]
async fn test_recovery_timer_rescheduling() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .build_async()
        .await;

    let canister_id = pocket_ic.create_canister().await;
    pocket_ic
        .add_cycles(canister_id, 100_000_000_000_000)
        .await;
    pocket_ic
        .install_canister(
            canister_id,
            build_node_rewards_test_wasm().bytes(),
            Encode!().unwrap(),
            None,
        )
        .await;

    pocket_ic
        .update_call(
            canister_id,
            candid::Principal::anonymous(),
            "start_recovery_test_tasks",
            Encode!().unwrap(),
        )
        .await
        .expect("Failed to start recovery test tasks");

    // Advance time enough for many cycles. The successful task reschedules
    // every 5s; the panicking task's recovery timer fires every 10s.
    for _ in 0..30 {
        pocket_ic.advance_time(Duration::from_secs(10)).await;
        pocket_ic.tick().await;
        pocket_ic.tick().await;
    }

    let response = pocket_ic
        .query_call(
            canister_id,
            candid::Principal::anonymous(),
            "get_recovery_test_counters",
            Encode!().unwrap(),
        )
        .await
        .expect("Failed to query counters");

    let (success_counter, panic_counter) = Decode!(&response, u64, u64).unwrap();

    // The successful task reschedules itself every 5s via normal execution,
    // so over 300s it should have run many times.
    assert!(
        success_counter >= 10,
        "Expected successful task to re-execute many times, but counter was {success_counter}"
    );

    // Without the recovery timer the panic counter would be exactly 1 (the
    // first execution increments before the await/trap, then the task dies).
    // With recovery it must be > 1.
    assert!(
        panic_counter > 1,
        "Expected panicking task to be re-executed after recovery, but counter was {panic_counter}"
    );
}
