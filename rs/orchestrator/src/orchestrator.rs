use crate::args::OrchestratorArgs;
use crate::catch_up_package_provider::CatchUpPackageProvider;
use crate::dashboard::{Dashboard, OrchestratorDashboard};
use crate::firewall::Firewall;
use crate::metrics::OrchestratorMetrics;
use crate::registration::NodeRegistration;
use crate::registry_helper::RegistryHelper;
use crate::replica_process::ReplicaProcess;
use crate::ssh_access_manager::SshAccessManager;
use crate::upgrade::Upgrade;
use ic_config::metrics::{Config as MetricsConfig, Exporter};
use ic_crypto::{CryptoComponent, CryptoComponentForNonReplicaProcess};
use ic_crypto_node_key_generation::get_node_keys_or_generate_if_missing;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_image_upgrader::ImageUpgrader;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, info, new_replica_logger_from_config, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_replicator::RegistryReplicator;
use ic_sys::utility_command::UtilityCommand;
use ic_types::{ReplicaVersion, SubnetId};
use slog_async::AsyncGuard;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{convert::TryFrom, time::Duration};
use tokio::sync::watch::{self, Receiver, Sender};
use tokio::{sync::RwLock, task::JoinHandle};

const CHECK_INTERVAL_SECS: Duration = Duration::from_secs(10);

pub struct Orchestrator {
    pub logger: ReplicaLogger,
    _async_log_guard: AsyncGuard,
    _metrics_runtime: MetricsHttpEndpoint,
    upgrade: Option<Upgrade>,
    firewall: Option<Firewall>,
    ssh_access_manager: Option<SshAccessManager>,
    orchestrator_dashboard: Option<OrchestratorDashboard>,
    registration: Option<NodeRegistration>,
    // A flag used to communicate to async tasks, that their job is done.
    exit_sender: Sender<bool>,
    exit_signal: Receiver<bool>,
    // The subnet id of the node.
    subnet_id: Arc<RwLock<Option<SubnetId>>>,
    // Handles of async tasks used to wait for their completion
    task_handles: Vec<JoinHandle<()>>,
}

// Loads the replica version from the file specified as argument on
// orchestrator's start.
fn load_version_from_file(logger: &ReplicaLogger, path: &Path) -> Result<ReplicaVersion, ()> {
    let contents = std::fs::read_to_string(path).map_err(|err| {
        error!(
            logger,
            "Couldn't open the version file {:?}: {:?}", path, err
        );
    })?;
    ReplicaVersion::try_from(contents.trim()).map_err(|err| {
        error!(
            logger,
            "Couldn't parse the contents of {:?}: {:?}", path, err
        );
    })
}

impl Orchestrator {
    pub async fn new(args: OrchestratorArgs) -> Result<Self, ()> {
        args.create_dirs();
        let metrics_addr = args.get_metrics_addr();
        let config = args.get_ic_config();
        let crypto_config = config.crypto.clone();
        let node_id = tokio::task::spawn_blocking(move || {
            get_node_keys_or_generate_if_missing(
                &crypto_config,
                Some(tokio::runtime::Handle::current()),
            )
            .1
        })
        .await
        .unwrap();

        let (logger, _async_log_guard) =
            new_replica_logger_from_config(&config.orchestrator_logger);
        let metrics_registry = MetricsRegistry::global();
        let replica_version = load_version_from_file(&logger, &args.version_file)?;
        info!(
            logger,
            "Orchestrator started: version={}, config={:?}", replica_version, config
        );
        UtilityCommand::notify_host("Orchestrator started.", 1);

        let registry_replicator = Arc::new(RegistryReplicator::new_from_config(
            logger.clone(),
            Some(node_id),
            &config,
        ));

        let (nns_urls, nns_pub_key) =
            registry_replicator.parse_registry_access_info_from_config(&config);
        if let Err(err) = registry_replicator
            .start_polling(nns_urls, nns_pub_key)
            .await
        {
            warn!(logger, "{}", err);
        }

        // Filesystem API to local registry copy
        let registry_local_store = registry_replicator.get_local_store();
        // Caches local registry by regularly polling local store
        let registry_client = registry_replicator.get_registry_client();
        // Wrapper to `RegistryClient`
        let registry = Arc::new(RegistryHelper::new(
            node_id,
            registry_client.clone(),
            logger.clone(),
        ));

        let c_log = logger.clone();
        let c_registry = registry.clone();
        let crypto_config = config.crypto.clone();
        let c_metrics = metrics_registry.clone();
        let crypto = tokio::task::spawn_blocking(move || {
            Arc::new(CryptoComponent::new_for_non_replica_process(
                &crypto_config,
                Some(tokio::runtime::Handle::current()),
                c_registry.get_registry_client(),
                c_log.clone(),
                Some(&c_metrics),
            ))
        })
        .await
        .unwrap();

        let mut registration = NodeRegistration::new(
            logger.clone(),
            config.clone(),
            Arc::clone(&registry_client),
            node_id,
            Arc::clone(&crypto) as Arc<dyn CryptoComponentForNonReplicaProcess>,
            registry_local_store.clone(),
        );

        if args.enable_provisional_registration {
            // will not return until the node is registered
            registration.register_node().await;
        }

        let slog_logger = logger.inner_logger.root.clone();
        let replica_process = Arc::new(Mutex::new(ReplicaProcess::new(slog_logger.clone())));
        let ic_binary_directory = args
            .ic_binary_directory
            .as_ref()
            .unwrap_or(&PathBuf::from("/tmp"))
            .clone();

        let cup_provider = Arc::new(CatchUpPackageProvider::new(
            Arc::clone(&registry),
            args.cup_dir.clone(),
            crypto.clone(),
            logger.clone(),
        ));

        let (metrics, _metrics_runtime) = Self::get_metrics(
            metrics_addr,
            &slog_logger,
            &metrics_registry,
            registry.get_registry_client(),
            crypto.clone(),
        );
        let metrics = Arc::new(metrics);

        metrics
            .orchestrator_info
            .with_label_values(&[&replica_version.to_string()])
            .set(1);

        let upgrade = Some(
            Upgrade::new(
                Arc::clone(&registry),
                Arc::clone(&metrics),
                Arc::clone(&replica_process),
                Arc::clone(&cup_provider),
                replica_version.clone(),
                args.replica_config_file.clone(),
                node_id,
                ic_binary_directory,
                registry_replicator,
                args.replica_binary_dir.clone(),
                logger.clone(),
                args.orchestrator_data_directory.clone(),
            )
            .await,
        );

        let firewall = Firewall::new(
            node_id,
            Arc::clone(&registry),
            Arc::clone(&metrics),
            config.firewall.clone(),
            logger.clone(),
        );

        let ssh_access_manager =
            SshAccessManager::new(Arc::clone(&registry), Arc::clone(&metrics), logger.clone());

        let subnet_id: Arc<RwLock<Option<SubnetId>>> = Default::default();

        let orchestrator_dashboard = Some(OrchestratorDashboard::new(
            Arc::clone(&registry),
            node_id,
            ssh_access_manager.get_last_applied_parameters(),
            firewall.get_last_applied_version(),
            replica_process,
            Arc::clone(&subnet_id),
            replica_version,
            cup_provider,
            logger.clone(),
        ));

        let (exit_sender, exit_signal) = watch::channel(false);

        Ok(Self {
            logger,
            _async_log_guard,
            _metrics_runtime,
            upgrade,
            firewall: Some(firewall),
            ssh_access_manager: Some(ssh_access_manager),
            orchestrator_dashboard,
            registration: Some(registration),
            exit_sender,
            exit_signal,
            subnet_id,
            task_handles: Default::default(),
        })
    }

    /// Starts four asynchronous tasks:
    ///
    /// 1. One that constantly monitors for a new CUP pointing to a newer
    /// replica version and executes the upgrade to this version if such a
    /// CUP was found.
    ///
    /// 2. Second task is doing two things sequentially. First, it  monitors the
    /// registry for new SSH readonly keys and deploys the detected keys
    /// into OS. Second, it monitors the registry for new data centers. If a
    /// new data center is added, orchestrator will generate a new firewall
    /// configuration allowing access from the IP range specified in the DC
    /// record.
    ///
    /// 3. Third task starts listening for incoming requests to the orchestrator
    /// dashboard.
    ///
    /// 4. Fourth task checks if this node is part of an tECDSA subnet. If so,
    /// and it is also time to rotate the iDKG encryption key, instruct crypto
    /// to do the rotation and attempt to register the rotated key.
    pub fn spawn_tasks(&mut self) {
        async fn upgrade_checks(
            maybe_subnet_id: Arc<RwLock<Option<SubnetId>>>,
            mut upgrade: Upgrade,
            exit_signal: Receiver<bool>,
            log: ReplicaLogger,
        ) {
            // This timeout is a last resort trying to revive the upgrade monitoring
            // in case it gets stuck in an unexpected situation for longer than 15 minutes.
            let timeout = Duration::from_secs(60 * 15);
            upgrade
                .upgrade_loop(exit_signal, CHECK_INTERVAL_SECS, timeout, |r| async {
                    match r {
                        Ok(Ok(val)) => *maybe_subnet_id.write().await = val,
                        e => warn!(log, "Check for upgrade failed: {:?}", e),
                    };
                })
                .await;
            info!(log, "Shut down the upgrade loop");
            if let Err(e) = upgrade.stop_replica() {
                warn!(log, "{}", e);
            }
            info!(log, "Shut down the replica process");
        }

        async fn tecdsa_key_rotation_check(
            maybe_subnet_id: Arc<RwLock<Option<SubnetId>>>,
            registration: NodeRegistration,
            mut exit_signal: Receiver<bool>,
            log: ReplicaLogger,
        ) {
            while !*exit_signal.borrow() {
                if let Some(subnet_id) = *maybe_subnet_id.read().await {
                    registration
                        .check_all_keys_registered_otherwise_register(subnet_id)
                        .await;
                }

                tokio::select! {
                    _ = tokio::time::sleep(CHECK_INTERVAL_SECS) => {}
                    _ = exit_signal.changed() => {}
                };
            }
            info!(log, "Shut down the tECDSA key rotation loop");
        }

        async fn ssh_key_and_firewall_rules_checks(
            maybe_subnet_id: Arc<RwLock<Option<SubnetId>>>,
            mut ssh_access_manager: SshAccessManager,
            mut firewall: Firewall,
            mut exit_signal: Receiver<bool>,
            log: ReplicaLogger,
        ) {
            while !*exit_signal.borrow() {
                // Check if new SSH keys need to be deployed
                ssh_access_manager
                    .check_for_keyset_changes(*maybe_subnet_id.read().await)
                    .await;
                // Check and update the firewall rules
                firewall.check_and_update().await;
                tokio::select! {
                    _ = tokio::time::sleep(CHECK_INTERVAL_SECS) => {}
                    _ = exit_signal.changed() => {}
                };
            }
            info!(log, "Shut down the ssh keys & firewall monitoring loop");
        }

        async fn serve_dashboard(
            dashboard: OrchestratorDashboard,
            exit_signal: Receiver<bool>,
            logger: ReplicaLogger,
        ) {
            dashboard.run(exit_signal).await;
            info!(logger, "Shut down the orchestrator dashboard");
        }

        if let Some(upgrade) = self.upgrade.take() {
            info!(self.logger, "Spawning the upgrade loop");
            self.task_handles.push(tokio::spawn(upgrade_checks(
                Arc::clone(&self.subnet_id),
                upgrade,
                self.exit_signal.clone(),
                self.logger.clone(),
            )));
        }

        if let (Some(ssh), Some(firewall)) = (self.ssh_access_manager.take(), self.firewall.take())
        {
            info!(
                self.logger,
                "Spawning the ssh-key and firewall rules check loop"
            );
            self.task_handles
                .push(tokio::spawn(ssh_key_and_firewall_rules_checks(
                    Arc::clone(&self.subnet_id),
                    ssh,
                    firewall,
                    self.exit_signal.clone(),
                    self.logger.clone(),
                )));
        }
        if let Some(dashboard) = self.orchestrator_dashboard.take() {
            info!(self.logger, "Spawning the orchestrator dashboard");
            self.task_handles.push(tokio::spawn(serve_dashboard(
                dashboard,
                self.exit_signal.clone(),
                self.logger.clone(),
            )));
        }
        if let Some(registration) = self.registration.take() {
            info!(self.logger, "Spawning the tECDSA key rotation loop");
            self.task_handles
                .push(tokio::spawn(tecdsa_key_rotation_check(
                    Arc::clone(&self.subnet_id),
                    registration,
                    self.exit_signal.clone(),
                    self.logger.clone(),
                )));
        }
    }

    /// Shuts down the orchestrator: stops async tasks and the replica process
    pub async fn shutdown(self) {
        info!(self.logger, "Shutting down orchestrator...");
        // Communicate to async tasks that the y should exit.
        self.exit_sender
            .send(true)
            .expect("Failed to send exit signal");
        // Wait until tasks are done.
        for handle in self.task_handles {
            let _ = handle.await;
        }
        info!(self.logger, "Orchestrator shut down");
    }

    // Construct a `OrchestratorMetrics` and its `MetricsHttpEndpoint`. If this
    // `MetricsHttpEndpoint` is dropped, metrics will no longer be
    // collected.
    fn get_metrics(
        metrics_addr: SocketAddr,
        logger: &slog::Logger,
        metrics_registry: &MetricsRegistry,
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<dyn TlsHandshake + Send + Sync>,
    ) -> (OrchestratorMetrics, MetricsHttpEndpoint) {
        let metrics_config = MetricsConfig {
            exporter: Exporter::Http(metrics_addr),
        };

        let metrics_endpoint = MetricsHttpEndpoint::new(
            tokio::runtime::Handle::current(),
            metrics_config,
            metrics_registry.clone(),
            registry_client,
            crypto,
            logger,
        );

        let metrics = OrchestratorMetrics::new(metrics_registry);

        (metrics, metrics_endpoint)
    }
}
