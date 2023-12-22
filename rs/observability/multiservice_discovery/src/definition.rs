use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use ic_registry_client::client::ThresholdSigPublicKey;
use service_discovery::job_types::map_jobs;
use service_discovery::job_types::JobType;
use service_discovery::{
    job_types::JobAndPort, registry_sync::sync_local_registry, IcServiceDiscoveryImpl,
};
use slog::{debug, info, warn, Logger};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use url::Url;

#[derive(Clone)]
pub struct Definition {
    pub nns_urls: Vec<Url>,
    pub registry_path: PathBuf,
    pub name: String,
    log: Logger,
    pub public_key: Option<ThresholdSigPublicKey>,
    pub poll_interval: Duration,
    stop_signal: Receiver<()>,
    pub registry_query_timeout: Duration,
    pub stop_signal_sender: Sender<()>,
    pub ic_discovery: Arc<IcServiceDiscoveryImpl>,
    pub boundary_nodes: Vec<BoundaryNode>,
}

impl Definition {
    pub(crate) fn new(
        nns_urls: Vec<Url>,
        global_registry_path: PathBuf,
        name: String,
        log: Logger,
        public_key: Option<ThresholdSigPublicKey>,
        poll_interval: Duration,
        stop_signal: Receiver<()>,
        registry_query_timeout: Duration,
        stop_signal_sender: Sender<()>,
    ) -> Self {
        let registry_path = global_registry_path.join(name.clone());
        if std::fs::metadata(&registry_path).is_err() {
            std::fs::create_dir_all(registry_path.clone()).unwrap();
        }
        Self {
            nns_urls,
            registry_path: registry_path.clone(),
            name,
            log: log.clone(),
            public_key,
            poll_interval,
            stop_signal,
            registry_query_timeout,
            stop_signal_sender,
            ic_discovery: Arc::new(
                IcServiceDiscoveryImpl::new(
                    log,
                    registry_path,
                    registry_query_timeout,
                    map_jobs(&JobAndPort::all()),
                )
                .unwrap(),
            ),
            boundary_nodes: vec![],
        }
    }

    async fn initial_registry_sync(&self) {
        info!(self.log, "Syncing local registry for {} started", self.name);

        sync_local_registry(
            self.log.clone(),
            self.registry_path.join("targets"),
            self.nns_urls.clone(),
            false,
            self.public_key,
        )
        .await;

        info!(
            self.log,
            "Syncing local registry for {} completed", self.name
        );
    }

    async fn poll_loop(&mut self) {
        let interval = crossbeam::channel::tick(self.poll_interval);
        let mut tick = Instant::now();
        loop {
            debug!(
                self.log,
                "Loading new scraping targets for {}, (tick: {:?})", self.name, tick
            );
            if let Err(e) = self.ic_discovery.load_new_ics(self.log.clone()) {
                warn!(
                    self.log,
                    "Failed to load new scraping targets for {} @ interval {:?}: {:?}",
                    self.name,
                    tick,
                    e
                );
            }
            debug!(self.log, "Update registries for {}", self.name);
            if let Err(e) = self.ic_discovery.update_registries().await {
                warn!(
                    self.log,
                    "Failed to sync registry for {} @ interval {:?}: {:?}", self.name, tick, e
                );
            }

            tick = crossbeam::select! {
                recv(self.stop_signal) -> _ => {
                    info!(self.log, "Received shutdown signal in poll_loop for {}", self.name);
                    return
                },
                recv(interval) -> msg => msg.expect("tick failed!")
            }
        }
    }

    async fn run(&mut self) {
        self.initial_registry_sync().await;

        info!(
            self.log,
            "Starting to watch for changes for definition {}", self.name
        );

        self.poll_loop().await;

        if self.name == "ic" {
            return;
        }

        info!(
            self.log,
            "Removing registry dir '{}' for definition {}...",
            self.registry_path.display(),
            self.name
        );

        if let Err(e) = std::fs::remove_dir_all(self.registry_path.clone()) {
            warn!(
                self.log,
                "Failed to remove registry dir for definition {}: {:?}", self.name, e
            );
        }
    }

    pub fn add_boundary_node(&mut self, target: BoundaryNode) {
        self.boundary_nodes.push(target);
    }
}

pub fn wrap(mut definition: Definition, rt: tokio::runtime::Handle) -> impl FnMut() {
    move || {
        rt.block_on(definition.run());
    }
}

#[derive(Clone)]
pub struct BoundaryNode {
    pub name: String,
    pub targets: BTreeSet<SocketAddr>,
    pub custom_labels: BTreeMap<String, String>,
    pub job_type: JobType,
}
