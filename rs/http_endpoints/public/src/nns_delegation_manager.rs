use std::{sync::Arc, time::Duration};

use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::{messages::CertificateDelegation, SubnetId};
use prometheus::{Histogram, IntCounter};
use tokio::{select, sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

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
    cancellation_token: CancellationToken,
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

    (rt_handle.spawn(manager.run(tx, cancellation_token)), rx)
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

    async fn run(
        self,
        sender: watch::Sender<Option<CertificateDelegation>>,
        cancellation_token: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(DELEGATION_UPDATE_INTERVAL);

        loop {
            select! {
                // stop the event loop if the token has been cancelled
                _ = cancellation_token.cancelled() => {
                    break;
                }

                // fetch the delegation if enough time has passed
                _ = interval.tick() => {
                    let mut delegation = self.fetch().await;

                    sender.send_if_modified(
                        move |old_delegation: &mut Option<CertificateDelegation>| {
                            if &delegation != old_delegation {
                                std::mem::swap(old_delegation, &mut delegation);
                                true
                            } else {
                                false
                            }
                        },
                    );
                }
            }
        }
    }
}
