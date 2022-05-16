use super::*;
use ic_interfaces::crypto::{BasicSigner, SignableMock};
use std::time::{Duration, Instant};

/// Creates a TempCryptoComponent with a remote vault, starts multiple tokio
/// tasks performing a basic-sig operation and measuring the running times, and then
/// asserts that the total running time is smaller than the sum of the individual ones.
#[tokio::test(flavor = "multi_thread")]
async fn should_run_parallel_vault_calls_from_tokio_tasks_in_parallel() {
    const NUM_TASKS: i32 = 3;
    let registry_version = REG_V1;
    let temp_crypto = TempCryptoComponent::builder()
        .with_remote_vault()
        .with_keys_in_registry_version(
            NodeKeysToGenerate::only_node_signing_key(),
            registry_version,
        )
        .build_arc();
    let msg = SignableMock::new([123; 32].to_vec());

    let mut join_handles = Vec::new();
    let start = Instant::now();
    for _ in 0..NUM_TASKS {
        let msg = msg.clone();
        let temp_crypto = Arc::clone(&temp_crypto);
        join_handles.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = temp_crypto.sign_basic(&msg, temp_crypto.get_node_id(), registry_version);
            let task_duration = start.elapsed();
            (result, task_duration)
        }));
    }

    let mut sum_of_task_durations = Duration::ZERO;
    for join_handle in join_handles {
        let (result, task_duration) = join_handle.await.expect("task panicked");
        assert!(result.is_ok());
        sum_of_task_durations += task_duration;
    }
    let total_duration = start.elapsed();
    assert!(total_duration < sum_of_task_durations);
}

/// Creates a TempCryptoComponent with a remote vault, starts multiple threads
/// performing a basic-sig operation and measuring the running times, and then asserts
/// that the total running time is smaller than the sum of the individual ones.
#[tokio::test(flavor = "multi_thread")]
async fn should_run_parallel_vault_calls_from_std_threads_in_parallel() {
    const NUM_TASKS: i32 = 3;
    let registry_version = REG_V1;
    let temp_crypto = TempCryptoComponent::builder()
        .with_remote_vault()
        .with_keys_in_registry_version(
            NodeKeysToGenerate::only_node_signing_key(),
            registry_version,
        )
        .build_arc();
    let msg = SignableMock::new([123; 32].to_vec());

    let mut thread_handles = Vec::new();
    let start = Instant::now();
    for _ in 0..NUM_TASKS {
        let msg = msg.clone();
        let temp_crypto = Arc::clone(&temp_crypto);
        thread_handles.push(std::thread::spawn(move || {
            let start = Instant::now();
            let result = temp_crypto.sign_basic(&msg, temp_crypto.get_node_id(), registry_version);
            let thread_duration = start.elapsed();
            (result, thread_duration)
        }));
    }

    let mut sum_of_thread_drations = Duration::ZERO;
    for thread_handle in thread_handles {
        let (result, thread_duration) = thread_handle.join().expect("failed to join");
        assert!(result.is_ok());
        sum_of_thread_drations += thread_duration;
    }
    let total_duration = start.elapsed();
    assert!(total_duration < sum_of_thread_drations);
}

/// Creates a TempCryptoComponent with a remote vault, starts multiple tokio
/// tasks and threads performing a basic-sig operation and measuring the
/// running time, and then asserts that the total running time is smaller than
/// the sum of the individual ones.
#[tokio::test(flavor = "multi_thread")]
async fn should_run_parallel_vault_calls_from_tokio_tasks_and_std_threads_in_parallel() {
    const NUM_TASKS_PER_CLIENT: i32 = 3;
    let registry_version = REG_V1;
    let temp_crypto = TempCryptoComponent::builder()
        .with_remote_vault()
        .with_keys_in_registry_version(
            NodeKeysToGenerate::only_node_signing_key(),
            registry_version,
        )
        .build_arc();
    let msg = SignableMock::new([123; 32].to_vec());

    let mut task_handles = Vec::new();
    let start = Instant::now();
    for _ in 0..NUM_TASKS_PER_CLIENT {
        let msg = msg.clone();
        let temp_crypto = Arc::clone(&temp_crypto);
        task_handles.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = temp_crypto.sign_basic(&msg, temp_crypto.get_node_id(), registry_version);
            let task_duration = start.elapsed();
            (result, task_duration)
        }));
    }

    let mut thread_handles = Vec::new();
    for _ in 0..NUM_TASKS_PER_CLIENT {
        let msg = msg.clone();
        let temp_crypto = Arc::clone(&temp_crypto);
        thread_handles.push(std::thread::spawn(move || {
            let start = Instant::now();
            let result = temp_crypto.sign_basic(&msg, temp_crypto.get_node_id(), registry_version);
            let thread_duration = start.elapsed();
            (result, thread_duration)
        }));
    }

    let mut sum_of_task_and_thread_durations = Duration::ZERO;
    for task_handle in task_handles {
        let (result, task_duration) = task_handle.await.expect("failed to await");
        assert!(result.is_ok());
        sum_of_task_and_thread_durations += task_duration;
    }
    for thread_handle in thread_handles {
        let (result, thread_duration) = thread_handle.join().expect("failed to join");
        assert!(result.is_ok());
        sum_of_task_and_thread_durations += thread_duration;
    }
    let total_duration = start.elapsed();
    assert!(total_duration < sum_of_task_and_thread_durations);
}

/// Creates two `TempCryptoComponent`s that both connect to the same CSP vault
/// server, starts multiple tokio tasks performing a basic-sig operation and
/// measuring the running times for one of the two, and does the same for the other
/// with standard threads, and then asserts that the total running time is smaller
/// than the sum of the individual ones.
#[tokio::test(flavor = "multi_thread")]
async fn should_run_parallel_vault_calls_from_multiple_clients_in_parallel() {
    const NUM_TASKS_PER_CLIENT: i32 = 3;
    let registry_version = REG_V1;
    let temp_crypto_1 = TempCryptoComponent::builder()
        .with_remote_vault()
        .with_keys_in_registry_version(
            NodeKeysToGenerate::only_node_signing_key(),
            registry_version,
        )
        .build_arc();
    let temp_crypto_2 = TempCryptoComponent::builder()
        .with_existing_remote_vault(temp_crypto_1.vault_server().unwrap())
        .with_node_id(temp_crypto_1.get_node_id())
        .with_registry(Arc::clone(temp_crypto_1.registry_client()))
        .build_arc();
    let msg = SignableMock::new([123; 32].to_vec());

    let mut task_handles = Vec::new();
    let start = Instant::now();
    for _ in 0..NUM_TASKS_PER_CLIENT {
        let msg = msg.clone();
        let temp_crypto = Arc::clone(&temp_crypto_1);
        task_handles.push(tokio::spawn(async move {
            let start = Instant::now();
            let result = temp_crypto.sign_basic(&msg, temp_crypto.get_node_id(), registry_version);
            let task_duration = start.elapsed();
            (result, task_duration)
        }));
    }

    let mut thread_handles = Vec::new();
    for _ in 0..NUM_TASKS_PER_CLIENT {
        let msg = msg.clone();
        let temp_crypto = Arc::clone(&temp_crypto_2);
        thread_handles.push(std::thread::spawn(move || {
            let start = Instant::now();
            let result = temp_crypto.sign_basic(&msg, temp_crypto.get_node_id(), registry_version);
            let thread_duration = start.elapsed();
            (result, thread_duration)
        }));
    }

    let mut sum_of_task_and_thread_durations = Duration::ZERO;
    for task_handle in task_handles {
        let (result, task_duration) = task_handle.await.expect("failed to await");
        assert!(result.is_ok());
        sum_of_task_and_thread_durations += task_duration;
    }
    for thread_handle in thread_handles {
        let (result, thread_duration) = thread_handle.join().expect("failed to join");
        assert!(result.is_ok());
        sum_of_task_and_thread_durations += thread_duration;
    }
    let total_duration = start.elapsed();
    assert!(total_duration < sum_of_task_and_thread_durations);
}
