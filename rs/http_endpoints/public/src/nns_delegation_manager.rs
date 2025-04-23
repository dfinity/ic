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

const DELEGATION_UPDATE_INTERVAL: Duration = Duration::from_secs(10 * 60);

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

    let (tx, rx) = watch::channel(None);

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
            &self.metrics,
        )
        .await;

        if let Some(delegation) = delegation.as_ref() {
            self.metrics
                .delegation_size
                .observe(delegation.certificate.len() as f64);
        }

        self.metrics.updates.inc();

        delegation
    }

    async fn run(self, sender: watch::Sender<Option<CertificateDelegation>>) {
        let mut interval = tokio::time::interval(DELEGATION_UPDATE_INTERVAL);
        // Since we can't distinguish between yet uninitialized and simply not present
        // (because we are on the NNS subnet) certification delegation, we explicitely keep
        // track whether the value has been initialized and notify all receivers when we initialize
        // it for the first time.
        let mut initialized = false;

        loop {
            // fetch the delegation if enough time has passed
            let _ = interval.tick().await;

            let mut delegation = self.fetch().await;

            sender.send_if_modified(move |old_delegation: &mut Option<CertificateDelegation>| {
                let modified = if &delegation != old_delegation {
                    std::mem::swap(old_delegation, &mut delegation);
                    true
                } else {
                    false
                };

                modified || !initialized
            });

            initialized = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use ic_crypto_tree_hash::{lookup_path, LabeledTree};
    use ic_logger::no_op_logger;
    use ic_types::messages::{Blob, Certificate};
    use tokio::time::timeout;

    use crate::tests::{set_up_nns_delegation_dependencies, NNS_SUBNET_ID, NON_NNS_SUBNET_ID};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn load_root_delegation_on_nns_should_return_none_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        rx.changed().await.unwrap();

        assert!(rx.borrow().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn load_root_delegation_on_non_nns_should_return_some_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        rx.changed().await.unwrap();

        let delegation = rx
            .borrow()
            .clone()
            .expect("Should return some delegation on non NNS subnet");
        let parsed_delegation: Certificate = serde_cbor::from_slice(&delegation.certificate)
            .expect("Should return a certificate which can be deserialized");
        let tree = LabeledTree::try_from(parsed_delegation.tree)
            .expect("Should return a state tree which can be parsed");
        // Verify that the state tree has the a subtree corresponding to the requested subnet
        match lookup_path(&tree, &[b"subnet", NON_NNS_SUBNET_ID.get_ref().as_ref()]) {
            Some(LabeledTree::SubTree(..)) => (),
            _ => panic!("Didn't find the subnet path in the state tree"),
        }
    }

    const TIMEOUT_WAIT: Duration = Duration::from_secs(3);

    #[tokio::test(start_paused = true)]
    async fn should_not_refresh_if_not_enough_time_passed_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        // The initial delegation should be fetched immediately.
        rx.changed().await.unwrap();
        // The subsequent delegations should be fetched only after `DELEGATION_UPDATE_INTERVAL`
        // has elapsed.
        tokio::time::advance(DELEGATION_UPDATE_INTERVAL / 2).await;
        tokio::time::resume();

        assert!(timeout(TIMEOUT_WAIT, rx.changed()).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn should_refresh_if_enough_time_passed_test() {
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), Arc::new(RwLock::new(None)));

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        // The initial delegation should be fetched immediately.
        rx.changed().await.unwrap();
        // The subsequent delegations should be fetched only after `DELEGATION_UPDATE_INTERVAL`
        // has passed.
        tokio::time::advance(DELEGATION_UPDATE_INTERVAL).await;
        tokio::time::resume();

        assert!(timeout(TIMEOUT_WAIT, rx.changed()).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn should_not_return_an_invalid_delegation_test() {
        let override_nns_delegation = Arc::new(RwLock::new(None));
        let rt_handle = tokio::runtime::Handle::current();
        let (registry_client, tls_config) =
            set_up_nns_delegation_dependencies(rt_handle.clone(), override_nns_delegation.clone());

        let (_, mut rx) = start_nns_delegation_manager(
            &MetricsRegistry::new(),
            Config::default(),
            no_op_logger(),
            rt_handle,
            NON_NNS_SUBNET_ID,
            NNS_SUBNET_ID,
            registry_client,
            Arc::new(tls_config),
            CancellationToken::new(),
        );

        // The initial *valid* delegation should be fetched immediately.
        assert!(rx.changed().await.is_ok());

        // Mock an *invalid* certificate delegation.
        *override_nns_delegation.write().unwrap() = Some(CertificateDelegation {
            subnet_id: Blob(vec![]),
            certificate: Blob(vec![]),
        });

        // Advance enough time to wake up the manager
        tokio::time::advance(2 * DELEGATION_UPDATE_INTERVAL).await;
        tokio::time::resume();

        // Since the returned certificate is invalid, we don't expect the manager to return
        // any new certification.
        assert!(timeout(TIMEOUT_WAIT, rx.changed()).await.is_err());

        *override_nns_delegation.write().unwrap() = None;
        // The mocked NNS node should now return a valid certification, so we expect that
        // the manager will fetch and send it to all receivers.
        assert!(rx.changed().await.is_ok());
    }
}
