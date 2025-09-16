use super::{acquire, acquire_for};

use futures::join;
use std::{cell::RefCell, collections::BTreeMap, time::Duration};
use tokio::time::sleep;

// Example of how to use acquire.
async fn disallow_more_than_on_call_at_a_time(id: u64) -> bool {
    thread_local! {
        static TRACKER: RefCell<Option<u64>> = const { RefCell::new(None) };
    }
    let release_on_drop = acquire(&TRACKER, id);
    if let Err(original_id) = release_on_drop {
        // Abort. Do not do real work.
        eprintln!("{original_id} already in progress.");
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileOperation {
    Read,
    Write,
    Delete,
}

// Example of how to use acquire_for with named locks for file operations.
async fn try_file_operation(file_path: String, operation: FileOperation) -> bool {
    thread_local! {
        static FILE_LOCKS: RefCell<BTreeMap<String, FileOperation>> = const { RefCell::new(BTreeMap::new()) };
    }
    let release_on_drop = acquire_for(&FILE_LOCKS, file_path.clone(), operation);
    if let Err(existing_operation) = release_on_drop {
        // Abort. Do not do real work.
        eprintln!("File '{file_path}' already has {existing_operation:?} operation in progress.");
        return false;
    }

    // Do real work here (simulate file I/O).
    sleep(Duration::from_millis(133)).await;
    true
}

async fn delayed_file_operation(
    pre_flight_delay_ms: u64,
    file_path: &str,
    operation: FileOperation,
) -> bool {
    sleep(Duration::from_millis(pre_flight_delay_ms)).await;
    try_file_operation(file_path.to_string(), operation).await
}

#[tokio::test]
async fn test_acquire_for_named_locks() {
    // Test that different files can be operated on simultaneously
    let results = join!(
        delayed_file_operation(0, "/tmp/file1.txt", FileOperation::Read), // Read file1
        delayed_file_operation(0, "/tmp/file2.txt", FileOperation::Write), // Write file2 (different file)
        delayed_file_operation(67, "/tmp/file1.txt", FileOperation::Write), // Write file1 (should fail - same file)
        delayed_file_operation(67, "/tmp/file2.txt", FileOperation::Delete), // Delete file2 (should fail - same file)
        delayed_file_operation(200, "/tmp/file1.txt", FileOperation::Delete), // Delete file1 (should succeed after read completes)
        delayed_file_operation(200, "/tmp/file3.txt", FileOperation::Read), // Read file3 (different file)
    );

    // First operations on each file should succeed, overlapping ones should fail
    assert_eq!(results, (true, true, false, false, true, true));
}

#[tokio::test]
async fn test_acquire_for_same_operation_different_targets() {
    // Test that the same operation type can run on different files simultaneously
    let results = join!(
        delayed_file_operation(0, "/var/log/app1.log", FileOperation::Write), // Write to app1.log
        delayed_file_operation(0, "/var/log/app2.log", FileOperation::Write), // Write to app2.log (same operation, different file)
        delayed_file_operation(0, "/var/log/app3.log", FileOperation::Write), // Write to app3.log (same operation, different file)
        delayed_file_operation(67, "/var/log/app1.log", FileOperation::Write), // Write to app1.log again (should fail - same file)
    );

    // All different files should succeed, same file should fail
    assert_eq!(results, (true, true, true, false));
}

#[tokio::test]
async fn test_acquire_for_mixed_targets_and_operations() {
    // Test mixed operations on different files to ensure they don't interfere
    let results = join!(
        delayed_file_operation(0, "/home/user/config.json", FileOperation::Read),
        delayed_file_operation(0, "/tmp/cache.dat", FileOperation::Delete),
        delayed_file_operation(0, "/home/user/config.json", FileOperation::Write), // Should fail - same file
    );

    assert_eq!(results, (true, true, false));
}
