use std::{sync::Arc, time::Duration};

use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::{messages::CertificateDelegation, SubnetId};
use prometheus::{Histogram, IntCounter};
use tokio::{sync::watch, task::JoinHandle};

use crate::load_root_delegation;

const DELEGATION_UPDATE_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Spawns a task which periodically fetches the nns delegation.
pub fn start_nns_delegation_manager(
    metrics_registry: &MetricsRegistry,
    config: Config,
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
) -> (
    JoinHandle<()>,
    watch::Receiver<Option<CertificateDelegation>>,
) {
    let manager = DelegationManager {
        config,
        log,
        subnet_id,
        nns_subnet_id,
        registry_client,
        tls_config,
        metrics: DelegationManagerMetrics::new(metrics_registry),
    };

    let delegation = rt_handle.block_on(manager.fetch());

    let (tx, rx) = watch::channel(delegation);

    (rt_handle.spawn(manager.run(tx)), rx)
}

struct DelegationManagerMetrics {
    updates: IntCounter,
    update_duration: Histogram,
    delegation_size: Histogram,
}

impl DelegationManagerMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            updates: metrics_registry.int_counter(
                "nns_delegation_manager_updates",
                "How many times has the nns delegation been updated",
            ),
            update_duration: metrics_registry.histogram(
                "nns_delegation_manager_update_duration",
                "How long it took to update the nns delegation, in seconds",
                // (1ms, 2ms, 5ms, ..., 10s, 20s, 50s)
                decimal_buckets(-3, 1),
            ),
            delegation_size: metrics_registry.histogram(
                "nns_delegation_manager_delegation_size",
                "How big is the delegation, in bytes",
                // (1, 2, 5, ..., 1MB, 2MB, 5MB)
                decimal_buckets(0, 6),
            ),
        }
    }
}

struct DelegationManager {
    config: Config,
    log: ReplicaLogger,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    metrics: DelegationManagerMetrics,
}

impl DelegationManager {
    async fn fetch(&self) -> Option<CertificateDelegation> {
        let _timer = self.metrics.update_duration.start_timer();

        let delegation = load_root_delegation(
            &self.config,
            &self.log,
            self.subnet_id,
            self.nns_subnet_id,
            self.registry_client.as_ref(),
            self.tls_config.as_ref(),
        )
        .await;

        self.metrics.delegation_size.observe(
            delegation
                .as_ref()
                .map(|d| d.certificate.len() as f64)
                .unwrap_or_default(),
        );

        self.metrics.updates.inc();

        delegation
    }

    async fn run(self, sender: watch::Sender<Option<CertificateDelegation>>) {
        let mut interval = tokio::time::interval(DELEGATION_UPDATE_INTERVAL);

        loop {
            let _ = interval.tick().await;

            let delegation = self.fetch().await;

            // FIXME(kpop): what to do when we fail, i.e., all receivers are dropped
            let _ = sender.send(delegation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_helpers::node::{ConnectionEndpoint, NodeRecord};
    use ic_registry_keys::make_node_record_key;
    use ic_test_utilities_registry::{setup_registry_non_final, SubnetRecordBuilder};
    use ic_types::{messages::CertificateDelegation, NodeId};

    use super::start_nns_delegation_manager;

    const NNS_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_1;
    const NON_NNS_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_2;
    const NNS_NODE_ID: NodeId = ic_test_utilities_types::ids::NODE_1;

    /// Sets up all the dependencies and starts the delegation manager loop.
    fn set_up(
        subnet_id: SubnetId,
        rt_handle: tokio::runtime::Handle,
    ) -> watch::Receiver<Option<CertificateDelegation>> {
        let (data_provider, registry_client) = setup_registry_non_final(
            NNS_SUBNET_ID,
            vec![(
                1,
                SubnetRecordBuilder::new()
                    .with_committee(&[NNS_NODE_ID])
                    .build(),
            )],
        );

        let node_record = NodeRecord {
            http: Some(ConnectionEndpoint {
                ip_addr: String::from("127.0.0.1"),
                port: 8080,
            }),
            ..Default::default()
        };

        data_provider
            .add(
                &make_node_record_key(NNS_NODE_ID),
                1.into(),
                Some(node_record),
            )
            .unwrap();
        registry_client.update_to_latest_version();

        let server_crypto = TempCryptoComponent::builder()
            .with_node_id(NNS_NODE_ID)
            .with_keys(NodeKeysToGenerate::only_tls_key_and_cert())
            .build();

        let (_, rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            subnet_id,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(server_crypto),
        );

        rx
    }

    #[test]
    fn nns_test() {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let rx = set_up(NNS_SUBNET_ID, rt.handle().clone());

        assert!(rx.borrow().is_none());
    }

    #[test]
    fn non_nns_test() {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let rx = set_up(NON_NNS_SUBNET_ID, rt.handle().clone());

        assert!(rx.borrow().is_some());
    }
}
