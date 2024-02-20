use crate::CryptoComponentImpl;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use ic_interfaces_registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_types_test_utils::ids::node_test_id;
use std::sync::Arc;

const NODE_ID: u64 = 42;

pub fn crypto_component_with_csp(
    csp: MockAllCryptoServiceProvider,
    registry_client: Arc<dyn RegistryClient>,
) -> CryptoComponentImpl<MockAllCryptoServiceProvider> {
    CryptoComponentImpl::new_for_test(
        csp,
        Arc::new(MockLocalCspVault::new()),
        no_op_logger(),
        registry_client,
        node_test_id(NODE_ID),
        Arc::new(CryptoMetrics::none()),
        None,
    )
}
