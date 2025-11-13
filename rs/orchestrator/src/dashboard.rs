use crate::{
    catch_up_package_provider::CatchUpPackageProvider, orchestrator::SubnetAssignment,
    process_manager::ProcessManager, registry_helper::RegistryHelper,
    ssh_access_manager::SshAccessParameters, upgrade::ReplicaProcess,
};
pub use ic_dashboard::Dashboard;
use ic_logger::{ReplicaLogger, info, warn};
use ic_types::{
    NodeId, RegistryVersion, ReplicaVersion, consensus::HasHeight, hostos_version::HostosVersion,
};
use std::{
    process::Command,
    sync::{Arc, Mutex, RwLock},
};

const ORCHESTRATOR_DASHBOARD_PORT: u16 = 7070;

/// Listens to ORCHESTRATOR_DASHBOARD_PORT and responds with orchestrator state.
pub(crate) struct OrchestratorDashboard {
    registry: Arc<RegistryHelper>,
    node_id: NodeId,
    last_applied_ssh_parameters: Arc<RwLock<SshAccessParameters>>,
    last_applied_firewall_version: Arc<RwLock<RegistryVersion>>,
    last_applied_ipv4_config_version: Arc<RwLock<RegistryVersion>>,
    replica_process: Arc<Mutex<ProcessManager<ReplicaProcess>>>,
    subnet_assignment: Arc<RwLock<SubnetAssignment>>,
    replica_version: ReplicaVersion,
    hostos_version: Option<HostosVersion>,
    cup_provider: Arc<CatchUpPackageProvider>,
    logger: ReplicaLogger,
}

impl Dashboard for OrchestratorDashboard {
    fn port() -> u16 {
        ORCHESTRATOR_DASHBOARD_PORT
    }

    fn build_response(&self) -> String {
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
             firewall config registry version: {}\n\
             ipv4 config registry version: {}\n\
             {}\n\
             readonly keys: {}\n\
             backup keys: {}\n\
             admin keys: {}",
            self.node_id,
            self.registry.dc_id().unwrap_or_default(),
            self.registry.get_latest_version().get(),
            self.get_subnet_id(),
            self.get_pid(),
            self.replica_version,
            self.hostos_version
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.get_scheduled_upgrade(),
            self.get_local_cup_info(),
            *self.last_applied_firewall_version.read().unwrap(),
            *self.last_applied_ipv4_config_version.read().unwrap(),
            self.display_last_applied_ssh_parameters(),
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
        subnet_assignment: Arc<RwLock<SubnetAssignment>>,
        replica_version: ReplicaVersion,
        hostos_version: Option<HostosVersion>,
        cup_provider: Arc<CatchUpPackageProvider>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            node_id,
            last_applied_ssh_parameters,
            last_applied_firewall_version,
            last_applied_ipv4_config_version,
            replica_process,
            subnet_assignment,
            replica_version,
            hostos_version,
            cup_provider,
            logger,
        }
    }

    fn get_authorized_keys(&self, account: &str) -> String {
        try_to_get_authorized_keys(account).unwrap_or_else(|e| {
            let error = format!("Failed to read the keys of the account {account}: {e}");
            warn!(self.logger, "{}", error);
            error
        })
    }

    fn display_last_applied_ssh_parameters(&self) -> String {
        let parameters = self.last_applied_ssh_parameters.read().unwrap();
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

    fn get_subnet_id(&self) -> String {
        match *self.subnet_assignment.read().unwrap() {
            SubnetAssignment::Assigned(id) => id.to_string(),
            SubnetAssignment::Unassigned => "Unassigned".to_string(),
            SubnetAssignment::Unknown => "Subnet not known yet".to_string(),
        }
    }

    fn get_scheduled_upgrade(&self) -> String {
        let subnet_id = match *self.subnet_assignment.read().unwrap() {
            SubnetAssignment::Assigned(id) => id,
            SubnetAssignment::Unassigned => return "None".to_string(),
            SubnetAssignment::Unknown => return "Subnet not known yet".to_string(),
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
        let (height, signed, hash, timestamp) = match self.cup_provider.get_local_cup() {
            None => (
                String::from("None"),
                String::from("None"),
                String::from("None"),
                String::from("None"),
            ),
            Some(cup) => {
                let height = cup.height().to_string();
                let signed = cup.is_signed();
                let hash = cup.content.state_hash.get().0;

                let unix_timestamp = cup.content.block.get_value().context.time;
                // UNIX timestamp in nanoseconds followed by the human-readable representation
                let timestamp_str = format!(
                    "{} ({})",
                    unix_timestamp.as_nanos_since_unix_epoch(),
                    unix_timestamp
                );

                (height, signed.to_string(), hex::encode(hash), timestamp_str)
            }
        };
        format!(
            "cup height: {height}\ncup signed: {signed}\ncup state hash: {hash}\ncup timestamp: {timestamp}"
        )
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
        .map_err(|e| format!("Failed to execute \"read-ssh-keys.sh\" : {e}"))?;
    match output.status.success() {
        true => Ok(stringify(&output.stdout)?),
        false => Err(stringify(&output.stderr)?),
    }
}
