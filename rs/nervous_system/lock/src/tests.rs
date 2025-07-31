use super::{acquire, acquire_for};

use futures::join;
use std::{cell::RefCell, collections::HashMap, time::Duration};
use tokio::time::sleep;

// Example of how to use acquire.
async fn disallow_more_than_on_call_at_a_time(id: u64) -> bool {
    thread_local! {
        static TRACKER: RefCell<Option<u64>> = const { RefCell::new(None) };
    }
    let release_on_drop = acquire(&TRACKER, id);
    if let Err(original_id) = release_on_drop {
        // Abort. Do not do real work.
        eprintln!("{} already in progress.", original_id);
        return false;
    }

    // Do real work here.
    sleep(Duration::from_millis(133)).await;
    true
}

#[tokio::test]
async fn test_acquire() {
    async fn delayed_call(pre_flight_delay_ms: u64, id: u64) -> bool {
        sleep(Duration::from_millis(pre_flight_delay_ms)).await;
        disallow_more_than_on_call_at_a_time(id).await
    }

    for i in 0..3 {
        let id_start = 10 * i;
        let results = join!(
            // 60 ms burst of activity.
            delayed_call(0, 1 + id_start),
            delayed_call(67, 2 + id_start), // Overlap with 1.
            delayed_call(67, 3 + id_start), // Overlap with 1.
            // Quiet period.

            // Another activity burst.
            delayed_call(200, 4 + id_start), // Wait for 1 to complete.
            delayed_call(267, 5 + id_start), // Overlap with 4.
            delayed_call(267, 6 + id_start), // Overlap with 4.
            // Second quiet period.

            // Third burst.
            delayed_call(400, 7 + id_start), // Wait for 4 to complete.
            delayed_call(467, 8 + id_start), // Overlap with 7.
        );

        assert_eq!(
            results,
            (true, false, false, true, false, false, true, false)
        );
    }

    // Hit me, baby, one more time!
    assert!(delayed_call(0, 1000).await);
}

// Example of how to use acquire_for with named locks.
async fn disallow_concurrent_operations_per_canister(canister_id: u64, operation: u64) -> bool {
    thread_local! {
        static CANISTER_LOCKS: RefCell<HashMap<u64, Option<u64>>> = RefCell::new(HashMap::new());
    }
    let release_on_drop = acquire_for(&CANISTER_LOCKS, canister_id, operation);
    if let Err(existing_operation) = release_on_drop {
        // Abort. Do not do real work.
        eprintln!(
            "Canister {} already has operation {} in progress.",
            canister_id, existing_operation
        );
        return false;
    }

    // Do real work here.
    sleep(Duration::from_millis(133)).await;
    true
}

#[tokio::test]
async fn test_acquire_for_named_locks() {
    async fn delayed_canister_call(
        pre_flight_delay_ms: u64,
        canister_id: u64,
        operation: u64,
    ) -> bool {
        sleep(Duration::from_millis(pre_flight_delay_ms)).await;
        disallow_concurrent_operations_per_canister(canister_id, operation).await
    }

    // Test that different canisters can be operated on simultaneously
    let results = join!(
        delayed_canister_call(0, 1, 100),   // Canister 1, Operation 100
        delayed_canister_call(0, 2, 200),   // Canister 2, Operation 200 (different canister)
        delayed_canister_call(67, 1, 101), // Canister 1, Operation 101 (should fail - same canister)
        delayed_canister_call(67, 2, 201), // Canister 2, Operation 201 (should fail - same canister)
        delayed_canister_call(200, 1, 102), // Canister 1, Operation 102 (should succeed after first completes)
        delayed_canister_call(200, 3, 300), // Canister 3, Operation 300 (different canister)
    );

    // First operations on each canister should succeed, overlapping ones should fail
    assert_eq!(results, (true, true, false, false, true, true));
}

#[tokio::test]
async fn test_acquire_for_same_operation_different_canisters() {
    async fn delayed_canister_call(
        pre_flight_delay_ms: u64,
        canister_id: u64,
        operation: u64,
    ) -> bool {
        sleep(Duration::from_millis(pre_flight_delay_ms)).await;
        disallow_concurrent_operations_per_canister(canister_id, operation).await
    }

    // Test that the same operation type can run on different canisters simultaneously
    let results = join!(
        delayed_canister_call(0, 1, 999),  // Canister 1, Operation 999
        delayed_canister_call(0, 2, 999), // Canister 2, Operation 999 (same operation, different canister)
        delayed_canister_call(0, 3, 999), // Canister 3, Operation 999 (same operation, different canister)
        delayed_canister_call(67, 1, 999), // Canister 1, Operation 999 (should fail - same canister)
    );

    // All different canisters should succeed, same canister should fail
    assert_eq!(results, (true, true, true, false));
}

#[tokio::test]
async fn test_acquire_for_with_string_keys() {
    // Test with string keys to ensure the generic implementation works with different key types
    async fn disallow_concurrent_operations_per_name(name: String, value: u32) -> bool {
        thread_local! {
            static NAME_LOCKS: RefCell<HashMap<String, Option<u32>>> = RefCell::new(HashMap::new());
        }
        let release_on_drop = acquire_for(&NAME_LOCKS, name, value);
        if let Err(existing_value) = release_on_drop {
            eprintln!("Name already has value {} in progress.", existing_value);
            return false;
        }

        sleep(Duration::from_millis(100)).await;
        true
    }

    let results = join!(
        disallow_concurrent_operations_per_name("alice".to_string(), 1),
        disallow_concurrent_operations_per_name("bob".to_string(), 2),
        disallow_concurrent_operations_per_name("alice".to_string(), 3), // Should fail - same name
    );

    assert_eq!(results, (true, true, false));
}
