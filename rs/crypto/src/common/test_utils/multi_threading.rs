use crate::CryptoComponentFatClient;
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_interfaces::registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::types::ids::node_test_id;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const NODE_ID: u64 = 42;

pub fn crypto_sharing_csp<C: CryptoServiceProvider>(
    csp: C,
) -> (
    Arc<CryptoComponentFatClient<C>>,
    Arc<CryptoComponentFatClient<C>>,
) {
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::new(
        ProtoRegistryDataProvider::new(),
    )));
    crypto_sharing_csp_and_registry(csp, registry_client)
}

pub fn crypto_sharing_csp_and_registry<C: CryptoServiceProvider>(
    csp: C,
    registry_client: Arc<dyn RegistryClient>,
) -> (
    Arc<CryptoComponentFatClient<C>>,
    Arc<CryptoComponentFatClient<C>>,
) {
    // The node ID is currently irrelevant for multi-threading tests, so we just set
    // it to a constant
    let crypto = Arc::new(CryptoComponentFatClient::new_with_csp_and_fake_node_id(
        csp,
        no_op_logger(),
        registry_client,
        node_test_id(NODE_ID),
    ));

    (Arc::clone(&crypto), crypto)
}

pub fn join_threads(thread_1: JoinHandle<()>, thread_2: JoinHandle<()>) {
    thread_1.join().expect("Threads were not joinable");
    thread_2.join().expect("Threads were not joinable");
}

/// Allows to repeat multi-threading tests in order to avoid flakiness due to
/// heavy system loads
pub fn repeat_until_success(num_reps: i32, success: fn() -> bool) {
    for _ in 0..num_reps {
        if success() {
            return;
        }
    }
    panic!("The test failed consistently for {} repetitions.", num_reps);
}

pub fn assert_elapsed_time_smaller_than(start_time: Instant, value: u64) -> bool {
    start_time.elapsed() < Duration::from_millis(value)
}
