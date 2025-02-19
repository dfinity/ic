use std::{sync::Arc, time::Duration};

use futures::FutureExt;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_types::{messages::CertificateDelegation, SubnetId};
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{load_root_delegation, metrics::DelegationManagerMetrics};

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
        rt_handle: rt_handle.clone(),
    };

    // Fetch the initial delegation in a blocking fashion
    let delegation = rt_handle.block_on(manager.fetch());

    let (tx, rx) = watch::channel(delegation);
    let join_handle = rt_handle.spawn(async move {
        cancellation_token
            .run_until_cancelled(manager.run(tx))
            .map(|_| ())
            .await
    });

    (join_handle, rx)
}

struct DelegationManager {
    config: Config,
    log: ReplicaLogger,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    metrics: DelegationManagerMetrics,
    rt_handle: tokio::runtime::Handle,
}

impl DelegationManager {
    async fn fetch(&self) -> Option<CertificateDelegation> {
        let _timer = self.metrics.update_duration.start_timer();

        let delegation = load_root_delegation(
            &self.config,
            &self.log,
            &self.rt_handle,
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
            // fetch the delegation if enough time has passed
            let _ = interval.tick().await;

            let mut delegation = self.fetch().await;

            sender.send_if_modified(move |old_delegation: &mut Option<CertificateDelegation>| {
                if &delegation != old_delegation {
                    std::mem::swap(old_delegation, &mut delegation);
                    true
                } else {
                    false
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use ic_crypto_tree_hash::{lookup_path, LabeledTree};
    use ic_logger::no_op_logger;
    use ic_types::messages::Certificate;

    use crate::tests::{set_up_nns_delegation_dependencies, NNS_SUBNET_ID, NON_NNS_SUBNET_ID};

    use super::*;

    #[test]
    fn nns_test() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(rt.handle().clone());

        let start_nns_delegation_manager = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt.handle().clone(),
            NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );
        let (_, rx) = start_nns_delegation_manager;

        assert!(rx.borrow().is_none());
    }

    #[test]
    fn non_nns_test() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (registry_client, tls_config) = set_up_nns_delegation_dependencies(rt.handle().clone());

        let (_, rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt.handle().clone(),
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        let delegation = rx
            .borrow()
            .clone()
            .expect("Should return Some delegation on non NNS subnet");
        let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
            .expect("Should have returned a valid certificate");
        let tree = LabeledTree::try_from(parsed_delegation.tree)
            .expect("Should return a valid state tree");
        // Verify that the state tree has the a subtree corresponding to the requested subnet
        match lookup_path(&tree, &[b"subnet", NON_NNS_SUBNET_ID.get_ref().as_ref()]) {
            Some(LabeledTree::SubTree(..)) => (),
            _ => panic!("Didn't find the subnet path in the state tree"),
        }
    }
}
