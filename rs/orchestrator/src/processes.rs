use crate::process_manager::{Process, ProcessRunner};
use ic_types::{ReplicaVersion, SubnetId};
use nix::unistd::Pid;
use std::{collections::HashMap, ffi::OsString, path::PathBuf};

// ---------------------------------------------------------------------------
// ReplicaProcess
// ---------------------------------------------------------------------------

pub(crate) struct ReplicaProcess {
    pub ic_binary_dir: PathBuf,
    pub replica_version: ReplicaVersion,
    pub cup_path: PathBuf,
    pub config_file: PathBuf,
    pub subnet_id: SubnetId,
}

impl Process for ReplicaProcess {
    const NAME: &'static str = "replica";
    type Version = ReplicaVersion;

    fn get_version(&self) -> &Self::Version {
        &self.replica_version
    }
    fn get_binary(&self) -> PathBuf {
        self.ic_binary_dir.join(Self::NAME)
    }
    fn get_args(&self) -> Vec<OsString> {
        vec![
            OsString::from("--replica-version"),
            self.replica_version.to_string().into(),
            OsString::from("--config-file"),
            self.config_file.clone().into(),
            OsString::from("--catch-up-package"),
            self.cup_path.clone().into(),
            OsString::from("--force-subnet"),
            self.subnet_id.to_string().into(),
        ]
    }
    fn get_env(&self) -> HashMap<OsString, OsString> {
        HashMap::new()
    }
}

// ---------------------------------------------------------------------------
// IcBoundaryProcess
// ---------------------------------------------------------------------------

pub(crate) struct IcBoundaryProcess {
    pub ic_binary_dir: PathBuf,
    pub replica_version: ReplicaVersion,
    pub domain_name: String,
    pub crypto_config: String,
    pub env: HashMap<String, String>,
}

impl Process for IcBoundaryProcess {
    const NAME: &'static str = "ic-boundary";
    type Version = ReplicaVersion;

    fn get_version(&self) -> &Self::Version {
        &self.replica_version
    }
    fn get_binary(&self) -> PathBuf {
        self.ic_binary_dir.join(Self::NAME)
    }
    fn get_args(&self) -> Vec<OsString> {
        vec![
            OsString::from("--tls-hostname"),
            self.domain_name.clone().into(),
            OsString::from("--crypto-config"),
            self.crypto_config.clone().into(),
        ]
    }
    fn get_env(&self) -> HashMap<OsString, OsString> {
        self.env
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ProcessManager
// ---------------------------------------------------------------------------

/// Manages all processes for this orchestrator.
///
/// Owns one runner per process type. Each field is a `Box<dyn ProcessRunner<P>>` so the runner can
/// be swapped out in tests without spawning real processes.
/// Implements `ProcessRunner<P>` for each process type, delegating to the corresponding runner.
pub(crate) struct ProcessManager {
    replica: Box<dyn ProcessRunner<ReplicaProcess>>,
    ic_boundary: Box<dyn ProcessRunner<IcBoundaryProcess>>,
}

impl ProcessManager {
    pub(crate) fn new(
        replica: Box<dyn ProcessRunner<ReplicaProcess>>,
        ic_boundary: Box<dyn ProcessRunner<IcBoundaryProcess>>,
    ) -> Self {
        Self {
            replica,
            ic_boundary,
        }
    }
}

impl ProcessRunner<ReplicaProcess> for ProcessManager {
    fn start(&mut self, process: ReplicaProcess) -> std::io::Result<()> {
        self.replica.start(process)
    }
    fn stop(&mut self) -> std::io::Result<()> {
        self.replica.stop()
    }
    fn is_running(&self) -> bool {
        self.replica.is_running()
    }
    fn get_pid(&self) -> Option<Pid> {
        self.replica.get_pid()
    }
}

impl ProcessRunner<IcBoundaryProcess> for ProcessManager {
    fn start(&mut self, process: IcBoundaryProcess) -> std::io::Result<()> {
        self.ic_boundary.start(process)
    }
    fn stop(&mut self) -> std::io::Result<()> {
        self.ic_boundary.stop()
    }
    fn is_running(&self) -> bool {
        self.ic_boundary.is_running()
    }
    fn get_pid(&self) -> Option<Pid> {
        self.ic_boundary.get_pid()
    }
}
