use std::{sync::Arc, time::Duration};

use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_types::{messages::CertificateDelegation, SubnetId};
use tokio::{sync::watch, task::JoinHandle};

use crate::load_root_delegation;

const DELEGATION_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

struct DelegationManager {
    config: Config,
    log: ReplicaLogger,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
}

pub fn start_nns_delegation_manager(
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
    };

    let delegation = rt_handle.block_on(manager.fetch());

    let (tx, rx) = watch::channel(delegation);

    (rt_handle.spawn(manager.run(tx)), rx)
}

impl DelegationManager {
    async fn fetch(&self) -> Option<CertificateDelegation> {
        load_root_delegation(
            &self.config,
            &self.log,
            self.subnet_id,
            self.nns_subnet_id,
            self.registry_client.as_ref(),
            self.tls_config.as_ref(),
        )
        .await
    }

    async fn run(self, sender: watch::Sender<Option<CertificateDelegation>>) {
        let mut interval = tokio::time::interval(DELEGATION_UPDATE_INTERVAL);

        loop {
            let _ = interval.tick().await;

            let delegation = self.fetch().await;

            sender.send(delegation).expect("FIXME");
        }
    }
}
