use crate::{
    catch_up_package_provider::CatchUpPackageProvider, process_manager::ProcessManager,
    registry_helper::RegistryHelper, ssh_access_manager::SshAccessParameters,
    upgrade::ReplicaProcess,
};
use async_trait::async_trait;
pub use ic_dashboard::Dashboard;
use ic_logger::{info, warn, ReplicaLogger};
use ic_types::{
    consensus::HasHeight, hostos_version::HostosVersion, NodeId, RegistryVersion, ReplicaVersion,
    SubnetId,
};
use std::{
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
};
use tokio::sync::RwLock;

const ORCHESTRATOR_DASHBOARD_PORT: u16 = 7070;

/// Listens to ORCHESTRATOR_DASHBOARD_PORT and responds with orchestrator state.
pub(crate) struct OrchestratorDashboard {
    registry: Arc<RegistryHelper>,
    node_id: NodeId,
    last_applied_ssh_parameters: Arc<RwLock<SshAccessParameters>>,
    last_applied_firewall_version: Arc<RwLock<RegistryVersion>>,
    last_applied_ipv4_config_version: Arc<RwLock<RegistryVersion>>,
    replica_process: Arc<Mutex<ProcessManager<ReplicaProcess>>>,
    subnet_id: Arc<RwLock<Option<SubnetId>>>,
    replica_version: ReplicaVersion,
    hostos_version: Option<HostosVersion>,
    cup_provider: Arc<CatchUpPackageProvider>,
    orchestrator_data_directory: PathBuf,
    logger: ReplicaLogger,
}

#[async_trait]
impl Dashboard for OrchestratorDashboard {
    fn port() -> u16 {
        ORCHESTRATOR_DASHBOARD_PORT
    }

    async fn build_response(&self) -> String {
        format!(
            "node id: {}\n\
             DC id: {}\n\
             last registry version: {}\n\
             subnet id: {}\n\
             replica process id: {}\n\
             replica version: {}\n\
             host os version: {}\n\
             scheduled upgrade: {}\n\
             {}\n\
             last checkpoint height: {}\n\
             recovery checkpoint data: {}\n\
             firewall config registry version: {}\n\
             ipv4 config registry version: {}\n\
             {}\n\
             readonly keys: {}\n\
             backup keys: {}\n\
             admin keys: {}",
            self.node_id,
            self.registry.dc_id().unwrap_or_default(),
            self.registry.get_latest_version().get(),
            self.get_subnet_id().await,
            self.get_pid(),
            self.replica_version,
            self.hostos_version
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.get_scheduled_upgrade().await,
            self.get_local_cup_info(),
            self.cup_provider
                .get_checkpoint_heights()
                .map(|res| res.max().map(|res| res.to_string()))
                .ok()
                .flatten()
                .unwrap_or_else(|| "None".to_string()),
            self.get_recovery_checkpoint_data(),
            *self.last_applied_firewall_version.read().await,
            *self.last_applied_ipv4_config_version.read().await,
            self.display_last_applied_ssh_parameters().await,
            self.get_authorized_keys("readonly"),
            self.get_authorized_keys("backup"),
            self.get_authorized_keys("admin"),
        )
    }

    fn log_info(&self, log_line: &str) {
        info!(self.logger, "{}", log_line);
    }
}

impl OrchestratorDashboard {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        node_id: NodeId,
        last_applied_ssh_parameters: Arc<RwLock<SshAccessParameters>>,
        last_applied_firewall_version: Arc<RwLock<RegistryVersion>>,
        last_applied_ipv4_config_version: Arc<RwLock<RegistryVersion>>,
        replica_process: Arc<Mutex<ProcessManager<ReplicaProcess>>>,
        subnet_id: Arc<RwLock<Option<SubnetId>>>,
        replica_version: ReplicaVersion,
        hostos_version: Option<HostosVersion>,
        cup_provider: Arc<CatchUpPackageProvider>,
        orchestrator_data_directory: PathBuf,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            node_id,
            last_applied_ssh_parameters,
            last_applied_firewall_version,
            last_applied_ipv4_config_version,
            replica_process,
            subnet_id,
            replica_version,
            hostos_version,
            cup_provider,
            orchestrator_data_directory,
            logger,
        }
    }

    fn get_authorized_keys(&self, account: &str) -> String {
        try_to_get_authorized_keys(account).unwrap_or_else(|e| {
            let error = format!("Failed to read the keys of the account {}: {}", account, e);
            warn!(self.logger, "{}", error);
            error
        })
    }

    async fn display_last_applied_ssh_parameters(&self) -> String {
        let parameters = self.last_applied_ssh_parameters.read().await;
        let subnet = match parameters.subnet_id {
            Some(id) => id.to_string(),
            None => "Unassigned".to_string(),
        };
        format!(
            "ssh key config registry version: {}\n\
             ssh key configuration is for subnet: {}",
            parameters.registry_version, subnet
        )
    }

    fn get_pid(&self) -> String {
        match self.replica_process.lock().unwrap().get_pid() {
            Some(pid) => pid.to_string(),
            None => "None".to_string(),
        }
    }

    async fn get_subnet_id(&self) -> String {
        match *self.subnet_id.read().await {
            Some(id) => id.to_string(),
            None => "None".to_string(),
        }
    }

    async fn get_scheduled_upgrade(&self) -> String {
        let subnet_id = match *self.subnet_id.read().await {
            Some(id) => id,
            None => return "None".to_string(),
        };

        let expected_replica_version = match self.registry.get_expected_replica_version(subnet_id) {
            Ok((v, _)) => v,
            Err(e) => return e.to_string(),
        };

        if expected_replica_version == self.replica_version {
            return "None".to_string();
        }

        format!("{} -> {}", self.replica_version, expected_replica_version)
    }

    fn get_local_cup_info(&self) -> String {
        let (height, signed, hash) = match self.cup_provider.get_local_cup() {
            None => (
                String::from("None"),
                String::from("None"),
                String::from("None"),
            ),
            Some(cup) => {
                let height = cup.height().to_string();
                let signed = cup.is_signed();
                let hash = cup.content.state_hash.get().0;
                (height, signed.to_string(), hex::encode(hash))
            }
        };
        format!(
            "cup height: {}\ncup signed: {}\ncup state hash: {}",
            height, signed, hash
        )
    }

    fn get_recovery_checkpoint_data(&self) -> String {
        match std::fs::read_to_string(
            self.orchestrator_data_directory
                .join("recovery_checkpoint.txt"),
        ) {
            Ok(data) => data,
            Err(_) => String::from("None"),
        }
    }
}

fn try_to_get_authorized_keys(account: &str) -> Result<String, String> {
    let stringify = |res| {
        std::str::from_utf8(res)
            .map(|s| s.lines().collect::<Vec<_>>().join(", "))
            .map_err(|e| e.to_string())
    };

    let output = Command::new("/opt/ic/bin/read-ssh-keys.sh")
        .arg(account)
        .output()
        .map_err(|e| format!("Failed to execute \"read-ssh-keys.sh\" : {}", e))?;
    match output.status.success() {
        true => Ok(stringify(&output.stdout)?),
        false => Err(stringify(&output.stderr)?),
    }
}
