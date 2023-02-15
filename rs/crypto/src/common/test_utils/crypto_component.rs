use crate::CryptoComponentFatClient;
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_interfaces_registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_types_test_utils::ids::node_test_id;
use std::sync::Arc;

const NODE_ID: u64 = 42;

pub fn crypto_component_with_csp<C: CryptoServiceProvider>(
    csp: C,
    registry_client: Arc<dyn RegistryClient>,
) -> CryptoComponentFatClient<C> {
    CryptoComponentFatClient::new_with_csp_and_fake_node_id(
        csp,
        no_op_logger(),
        registry_client,
        node_test_id(NODE_ID),
        Arc::new(CryptoMetrics::none()),
        None,
    )
}
