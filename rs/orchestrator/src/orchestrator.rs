use crate::{
    args::OrchestratorArgs,
    boundary_node::BoundaryNodeManager,
    catch_up_package_provider::CatchUpPackageProvider,
    dashboard::{Dashboard, OrchestratorDashboard},
    firewall::Firewall,
    hostos_upgrade::HostosUpgrader,
    ipv4_network::Ipv4Configurator,
    metrics::OrchestratorMetrics,
    process_manager::ProcessManager,
    registration::NodeRegistration,
    registry_helper::RegistryHelper,
    ssh_access_manager::SshAccessManager,
    upgrade::Upgrade,
};
use backoff::ExponentialBackoffBuilder;
use get_if_addrs::get_if_addrs;
use ic_config::{
    metrics::{Config as MetricsConfig, Exporter},
    Config,
};
use ic_crypto::CryptoComponent;
use ic_crypto_node_key_generation::{generate_node_keys_once, NodeKeyGenerationError};
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_image_upgrader::ImageUpgrader;
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_replicator::RegistryReplicator;
use ic_sys::utility_command::UtilityCommand;
use ic_types::{hostos_version::HostosVersion, ReplicaVersion, SubnetId};
use std::{
    collections::HashMap,
    convert::TryFrom,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    thread,
    time::Duration,
};
use tokio::{sync::watch::Receiver, task::JoinSet};

const CHECK_INTERVAL_SECS: Duration = Duration::from_secs(10);

pub struct Orchestrator {
    pub logger: ReplicaLogger,
    _metrics_runtime: MetricsHttpEndpoint,
    upgrade: Option<Upgrade>,
    hostos_upgrade: Option<HostosUpgrader>,
    boundary_node_manager: Option<BoundaryNodeManager>,
    firewall: Option<Firewall>,
    ssh_access_manager: Option<SshAccessManager>,
    orchestrator_dashboard: Option<OrchestratorDashboard>,
    registration: Option<NodeRegistration>,
    // The subnet id of the node.
    subnet_id: Arc<RwLock<Option<SubnetId>>>,
    ipv4_configurator: Option<Ipv4Configurator>,
    task_tracker: TaskTracker,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum OrchestratorInstantiationError {
    /// If an error occurs during key generation
    KeyGenerationError(String),
    /// If an error occurs while reading the replica version from the file system
    VersionFileError,
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
    pub async fn new(
        args: OrchestratorArgs,
        config: &Config,
        logger: ReplicaLogger,
    ) -> Result<Self, OrchestratorInstantiationError> {
        args.create_dirs();
        let metrics_addr = args.get_metrics_addr();
        let crypto_config = config.crypto.clone();
        let node_id = tokio::task::spawn_blocking(move || {
            generate_node_keys_once(&crypto_config, Some(tokio::runtime::Handle::current()))
                .map(|keys| keys.node_id())
                .map_err(|e| match e {
                    NodeKeyGenerationError::TransientInternalError(e) => {
                        OrchestratorInstantiationError::KeyGenerationError(e)
                    }
                })
        })
        .await
        .unwrap()?;

        let metrics_registry = MetricsRegistry::global();
        let replica_version = load_version_from_file(&logger, &args.version_file)
            .map_err(|()| OrchestratorInstantiationError::VersionFileError)?;
        info!(
            logger,
            "Orchestrator started: version={}, config={:?}", replica_version, config
        );
        UtilityCommand::notify_host(
            format!(
                "node-id {}: starting with version {}",
                node_id, replica_version
            )
            .as_str(),
            1,
        );

        UtilityCommand::notify_host("\nONBOARDING MAY NOT YET BE COMPLETE:\nIf a 'Join request successful!' message has NOT yet been logged, please wait for up to 10 minutes...\n", 3);

        let version = replica_version.clone();
        thread::spawn(move || loop {
            // Sleep early because IPv4 takes several minutes to configure
            thread::sleep(Duration::from_secs(10 * 60));
            let (ipv4, ipv6) = Self::get_ip_addresses();

            let message = indoc::formatdoc!(
                r#"
                    Node-id: {node_id}
                    Replica version: {version}
                    IPv6: {ipv6}
                    IPv4: {ipv4}

                "#
            );

            UtilityCommand::notify_host(&message, 1);
        });

        let slog_logger = logger.inner_logger.root.clone();
        let (metrics, _metrics_runtime) =
            Self::get_metrics(metrics_addr, &slog_logger, &metrics_registry);
        let metrics = Arc::new(metrics);
        let mut task_tracker = TaskTracker::new(metrics.clone(), logger.clone());

        let registry_replicator = Arc::new(RegistryReplicator::new_from_config(
            logger.clone(),
            Some(node_id),
            config,
        ));

        let (nns_urls, nns_pub_key) =
            registry_replicator.parse_registry_access_info_from_config(config);

        match registry_replicator
            .start_polling(nns_urls, nns_pub_key)
            .await
        {
            Ok(future) => task_tracker.spawn("registry_replicator", future),
            Err(err) => {
                metrics
                    .critical_error_task_failed
                    .with_label_values(&["registry_replicator", "failed_to_start"])
                    .inc();
                error!(
                    logger,
                    "Failed to start the registry replicator task: {err}"
                )
            }
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
            Arc::new(CryptoComponent::new(
                &crypto_config,
                Some(tokio::runtime::Handle::current()),
                c_registry.get_registry_client(),
                c_log.clone(),
                Some(&c_metrics),
            ))
        })
        .await
        .unwrap();

        metrics
            .orchestrator_info
            .with_label_values(&[replica_version.as_ref()])
            .set(1);

        let mut registration = NodeRegistration::new(
            logger.clone(),
            config.clone(),
            Arc::clone(&registry_client),
            Arc::clone(&metrics),
            node_id,
            Arc::clone(&crypto) as _,
            registry_local_store.clone(),
        );

        let replica_process = Arc::new(Mutex::new(ProcessManager::new(logger.clone())));
        let ic_binary_directory = args
            .ic_binary_directory
            .as_ref()
            .unwrap_or(&PathBuf::from("/tmp"))
            .clone();

        let cup_provider = Arc::new(CatchUpPackageProvider::new(
            Arc::clone(&registry),
            args.cup_dir.clone(),
            Arc::clone(&crypto) as _,
            Arc::clone(&crypto) as _,
            logger.clone(),
            node_id,
        ));

        if args.enable_provisional_registration {
            // will not return until the node is registered
            registration.register_node().await;
        }

        let upgrade = Some(
            Upgrade::new(
                Arc::clone(&registry),
                Arc::clone(&metrics),
                Arc::clone(&replica_process),
                Arc::clone(&cup_provider),
                replica_version.clone(),
                args.replica_config_file.clone(),
                node_id,
                ic_binary_directory.clone(),
                registry_replicator,
                args.replica_binary_dir.clone(),
                logger.clone(),
                args.orchestrator_data_directory.clone(),
            )
            .await,
        );

        let hostos_version = UtilityCommand::request_hostos_version()
            .await
            .and_then(|v| {
                HostosVersion::try_from(v)
                    .map_err(|e| format!("Unable to parse HostOS version: {:?}", e))
            });

        let hostos_upgrade = match hostos_version.clone() {
            Err(e) => {
                // When there is an error finding the HostOS version, don't
                // spawn the upgrade loop, to avoid unnecessarily upgrading.
                error!(logger, "{}", e);

                None
            }
            Ok(hostos_version) => Some(
                HostosUpgrader::new(
                    Arc::clone(&registry),
                    hostos_version,
                    node_id,
                    logger.clone(),
                )
                .await,
            ),
        };

        let boundary_node = BoundaryNodeManager::new(
            Arc::clone(&registry),
            Arc::clone(&metrics),
            replica_version.clone(),
            node_id,
            ic_binary_directory.clone(),
            config.crypto.clone(),
            logger.clone(),
        );

        let firewall = Firewall::new(
            node_id,
            Arc::clone(&registry),
            Arc::clone(&metrics),
            config.firewall.clone(),
            config.boundary_node_firewall.clone(),
            cup_provider.clone(),
            logger.clone(),
        );

        let ipv4_configurator = Ipv4Configurator::new(
            Arc::clone(&registry),
            Arc::clone(&metrics),
            ic_binary_directory,
            logger.clone(),
        );

        let ssh_access_manager = SshAccessManager::new(
            Arc::clone(&registry),
            Arc::clone(&metrics),
            node_id,
            logger.clone(),
        );

        let subnet_id: Arc<RwLock<Option<SubnetId>>> = Default::default();

        let orchestrator_dashboard = Some(OrchestratorDashboard::new(
            Arc::clone(&registry),
            node_id,
            ssh_access_manager.get_last_applied_parameters(),
            firewall.get_last_applied_version(),
            ipv4_configurator.get_last_applied_version(),
            replica_process,
            Arc::clone(&subnet_id),
            replica_version,
            hostos_version.ok(),
            cup_provider,
            logger.clone(),
        ));

        Ok(Self {
            logger,
            _metrics_runtime,
            upgrade,
            hostos_upgrade,
            boundary_node_manager: Some(boundary_node),
            firewall: Some(firewall),
            ssh_access_manager: Some(ssh_access_manager),
            orchestrator_dashboard,
            registration: Some(registration),
            subnet_id,
            ipv4_configurator: Some(ipv4_configurator),
            task_tracker,
        })
    }

    /// Starts asynchronous tasks and waits until they all complete. The tasks can be
    /// cancelled at any time by setting `exit_signal` to `true`.
    ///
    /// The following tasks are started:
    /// 1. One that constantly monitors for a new CUP pointing to a newer
    ///    replica version and executes the upgrade to this version if such a
    ///    CUP was found.
    ///
    /// 2. Second task is doing two things sequentially. First, it  monitors the
    ///    registry for new SSH readonly keys and deploys the detected keys
    ///    into OS. Second, it monitors the registry for new data centers. If a
    ///    new data center is added, orchestrator will generate a new firewall
    ///    configuration allowing access from the IP range specified in the DC
    ///    record.
    ///
    /// 3. Third task starts listening for incoming requests to the orchestrator
    ///    dashboard.
    ///
    /// 4. Fourth task checks if this node is part of a threshold signing subnet. If so,
    ///    and it is also time to rotate the iDKG encryption key, instruct crypto
    ///    to do the rotation and attempt to register the rotated key.
    pub async fn start_tasks(&mut self, exit_signal: Receiver<bool>) {
        async fn upgrade_checks(
            maybe_subnet_id: Arc<RwLock<Option<SubnetId>>>,
            mut upgrade: Upgrade,
            exit_signal: Receiver<bool>,
            log: ReplicaLogger,
        ) {
            // This timeout is a last resort trying to revive the upgrade monitoring
            // in case it gets stuck in an unexpected situation for longer than 15 minutes.
            let timeout = Duration::from_secs(60 * 15);
            let metrics = upgrade.metrics.clone();
            upgrade
                .upgrade_loop(exit_signal, CHECK_INTERVAL_SECS, timeout, |r| async {
                    match r {
                        Ok(Ok(val)) => {
                            *maybe_subnet_id.write().unwrap() = val;
                            metrics.failed_consecutive_upgrade_checks.reset();
                        }
                        e => {
                            warn!(log, "Check for upgrade failed: {:?}", e);
                            metrics.failed_consecutive_upgrade_checks.inc();
                        }
                    };
                })
                .await;
            info!(log, "Shut down the upgrade loop");
            if let Err(e) = upgrade.stop_replica() {
                warn!(log, "{}", e);
            }
            info!(log, "Shut down the replica process");
        }

        async fn hostos_upgrade_checks(mut upgrade: HostosUpgrader, exit_signal: Receiver<bool>) {
            // Wait for a minute before starting the first loop, to allow the
            // registry some time to catch up, after starting.
            tokio::time::sleep(Duration::from_secs(60)).await;

            // Run the HostOS upgrade loop with an exponential backoff. A 15
            // minute liveness timeout will restart the loop if no progress is
            // made, to ensure the upgrade loop does not get stuck.
            //
            // The exponential backoff between retries starts at 1 minute, and
            // increases by a factor of 1.75, maxing out at two hours.
            // e.g. (roughly) 1, 1.75, 3, 5.25, 9.5, 16.5, 28.75, 50.25, 88, 120, 120
            //
            // Additionally, there's a random +=50% range added to each delay, for jitter.
            let backoff = ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_secs(60))
                .with_randomization_factor(0.5)
                .with_multiplier(1.75)
                .with_max_interval(Duration::from_secs(2 * 60 * 60))
                .with_max_elapsed_time(None)
                .build();
            let liveness_timeout = Duration::from_secs(15 * 60);

            upgrade
                .upgrade_loop(exit_signal, backoff, liveness_timeout)
                .await;
        }

        async fn boundary_node_check(
            mut boundary_node_manager: BoundaryNodeManager,
            mut exit_signal: Receiver<bool>,
        ) {
            while !*exit_signal.borrow() {
                boundary_node_manager.check().await;

                tokio::select! {
                    _ = tokio::time::sleep(CHECK_INTERVAL_SECS) => {}
                    _ = exit_signal.changed() => {}
                }
            }
        }

        async fn key_rotation_check(
            maybe_subnet_id: Arc<RwLock<Option<SubnetId>>>,
            registration: NodeRegistration,
            mut exit_signal: Receiver<bool>,
        ) {
            while !*exit_signal.borrow() {
                let maybe_subnet_id = *maybe_subnet_id.read().unwrap();
                if let Some(subnet_id) = maybe_subnet_id {
                    registration
                        .check_all_keys_registered_otherwise_register(subnet_id)
                        .await;
                }

                tokio::select! {
                    _ = tokio::time::sleep(CHECK_INTERVAL_SECS) => {}
                    _ = exit_signal.changed() => {}
                }
            }
        }

        async fn ssh_key_and_firewall_rules_and_ipv4_config_checks(
            maybe_subnet_id: Arc<RwLock<Option<SubnetId>>>,
            mut ssh_access_manager: SshAccessManager,
            mut firewall: Firewall,
            mut ipv4_configurator: Ipv4Configurator,
            mut exit_signal: Receiver<bool>,
        ) {
            while !*exit_signal.borrow() {
                // Check if new SSH keys need to be deployed
                ssh_access_manager.check_for_keyset_changes(*maybe_subnet_id.read().unwrap());
                // Check and update the firewall rules
                firewall.check_and_update();
                // Check and update the network configuration
                ipv4_configurator.check_and_update().await;
                tokio::select! {
                    _ = tokio::time::sleep(CHECK_INTERVAL_SECS) => {}
                    _ = exit_signal.changed() => {}
                }
            }
        }

        async fn serve_dashboard(dashboard: OrchestratorDashboard, exit_signal: Receiver<bool>) {
            dashboard.run(exit_signal).await;
        }

        if let Some(upgrade) = self.upgrade.take() {
            self.task_tracker.spawn(
                "upgrade",
                upgrade_checks(
                    Arc::clone(&self.subnet_id),
                    upgrade,
                    exit_signal.clone(),
                    self.logger.clone(),
                ),
            );
        }

        if let Some(hostos_upgrade) = self.hostos_upgrade.take() {
            self.task_tracker.spawn(
                "HostOS_upgrade",
                hostos_upgrade_checks(hostos_upgrade, exit_signal.clone()),
            );
        }

        if let Some(boundary_node) = self.boundary_node_manager.take() {
            self.task_tracker.spawn(
                "boundary_node_management",
                boundary_node_check(boundary_node, exit_signal.clone()),
            );
        }

        if let (Some(ssh), Some(firewall), Some(ipv4_configurator)) = (
            self.ssh_access_manager.take(),
            self.firewall.take(),
            self.ipv4_configurator.take(),
        ) {
            self.task_tracker.spawn(
                "ssh_key_firewall_rules_ipv4_config",
                ssh_key_and_firewall_rules_and_ipv4_config_checks(
                    Arc::clone(&self.subnet_id),
                    ssh,
                    firewall,
                    ipv4_configurator,
                    exit_signal.clone(),
                ),
            );
        }

        if let Some(dashboard) = self.orchestrator_dashboard.take() {
            self.task_tracker
                .spawn("dashboard", serve_dashboard(dashboard, exit_signal.clone()));
        }

        if let Some(registration) = self.registration.take() {
            self.task_tracker.spawn(
                "key_rotation",
                key_rotation_check(
                    Arc::clone(&self.subnet_id),
                    registration,
                    exit_signal.clone(),
                ),
            );
        }

        self.task_tracker.join_all().await
    }

    // Construct a `OrchestratorMetrics` and its `MetricsHttpEndpoint`. If this
    // `MetricsHttpEndpoint` is dropped, metrics will no longer be
    // collected.
    fn get_metrics(
        metrics_addr: SocketAddr,
        logger: &slog::Logger,
        metrics_registry: &MetricsRegistry,
    ) -> (OrchestratorMetrics, MetricsHttpEndpoint) {
        let metrics_config = MetricsConfig {
            exporter: Exporter::Http(metrics_addr),
            ..Default::default()
        };

        let metrics_endpoint = MetricsHttpEndpoint::new(
            tokio::runtime::Handle::current(),
            metrics_config,
            metrics_registry.clone(),
            logger,
        );

        let metrics = OrchestratorMetrics::new(metrics_registry);

        (metrics, metrics_endpoint)
    }

    fn get_ip_addresses() -> (String, String) {
        let ifaces = get_if_addrs().unwrap_or_default();

        let ipv4 = ifaces
            .iter()
            .find_map(|iface| match iface.addr {
                get_if_addrs::IfAddr::V4(ref addr) if !addr.ip.is_loopback() => {
                    Some(addr.ip.to_string())
                }
                _ => None,
            })
            .unwrap_or_else(|| "none configured".to_string());

        let ipv6 = ifaces
            .iter()
            .find_map(|iface| match iface.addr {
                get_if_addrs::IfAddr::V6(ref addr) if !addr.ip.is_loopback() => {
                    Some(addr.ip.to_string())
                }
                _ => None,
            })
            .unwrap_or_else(|| "none configured".to_string());

        (ipv4, ipv6)
    }
}

/// A structure which keeps track of the tasks spawned by the Orchestrator and monitors
/// the completions of the tasks.
struct TaskTracker {
    tasks: JoinSet<()>,
    task_names: HashMap<tokio::task::Id, String>,
    logger: ReplicaLogger,
    metrics: Arc<OrchestratorMetrics>,
}

impl TaskTracker {
    /// Creates an empty [`TaskTracker`] without spawning any tasks.
    fn new(metrics: Arc<OrchestratorMetrics>, logger: ReplicaLogger) -> Self {
        Self {
            tasks: JoinSet::new(),
            task_names: HashMap::new(),
            logger,
            metrics,
        }
    }

    /// Spawns the provided task on the [`JoinSet`] and updates the [`Self::task_names`] field.
    /// The task will immediately start running in the background when this method is called.
    fn spawn(&mut self, task_name: &str, task: impl Future<Output = ()> + Send + 'static) {
        info!(self.logger, "Spawning the task `{task_name}`");
        let id = self.tasks.spawn(task).id();
        self.task_names.insert(id, task_name.to_string());
        info!(self.logger, "Task `{task_name}` spawned");
    }

    /// Waits until all the tasks complete.
    ///
    /// If any of the tracked tasks panics it will be caught here and
    /// [`OrchestratorMetrics::critical_error_task_panicked`] will be incremented.
    /// TODO(CON-1488): consider restarting a task if it panics.
    ///
    /// # Cancel Safety
    ///
    /// This method is cancel safe. If `join_all` is used as an event in a `tokio::select!`
    /// statement and some other branch completes first, it is guaranteed that no non-completed
    /// tasks were removed from this [`TaskTracker`].
    async fn join_all(&mut self) {
        while let Some(join_result) = self.tasks.join_next_with_id().await {
            match join_result {
                Ok((id, ())) => {
                    let task_name = self.take_task_name(&id);
                    info!(self.logger, "Task `{task_name}` finished gracefully");
                }
                Err(err) => {
                    let task_name = self.take_task_name(&err.id());

                    if err.is_panic() {
                        error!(self.logger, "Task `{task_name}` panicked: {err}");
                        self.metrics
                            .critical_error_task_failed
                            .with_label_values(&[&task_name, "panic"])
                            .inc();
                    } else {
                        info!(self.logger, "Task `{task_name}` was cancelled");
                    }
                }
            }
        }
    }

    /// Removes the `id` from the  [`Self::task_names`] and returns the removed task name.
    /// If there is no task with the given `id` in the map, returns "unknown".
    fn take_task_name(&mut self, id: &tokio::task::Id) -> String {
        self.task_names
            .remove(id)
            .unwrap_or_else(|| String::from("unknown"))
    }
}

#[cfg(test)]
mod tests {
    use ic_logger::no_op_logger;

    use super::*;

    #[tokio::test]
    async fn task_tracker_panics_are_tracked_test() {
        let metrics = Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new()));
        let mut task_tracker = TaskTracker::new(metrics.clone(), no_op_logger());

        task_tracker.spawn("panicky", async { panic!("Oh no...") });
        task_tracker.join_all().await;

        assert_eq!(
            metrics
                .critical_error_task_failed
                .get_metric_with_label_values(&["panicky", "panic"])
                .unwrap()
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn task_tracker_graceful_completions_are_ignored_test() {
        let metrics = Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new()));
        let mut task_tracker = TaskTracker::new(metrics.clone(), no_op_logger());

        task_tracker.spawn("graceful", async { println!(":)") });
        task_tracker.join_all().await;

        assert_eq!(
            metrics
                .critical_error_task_failed
                .get_metric_with_label_values(&["graceful", "panic"])
                .unwrap()
                .get(),
            0
        );
    }
}
