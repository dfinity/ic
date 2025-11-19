use crate::metrics::PROMETHEUS_HTTP_PORT;
use clap::Parser;
use ic_config::{Config, ConfigSource};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[clap(
    name = "orchestrator",
    about = "Arguments for the Internet Computer Orchestrator.",
    version
)]
/// Arguments for the orchestrator binary.
pub struct OrchestratorArgs {
    /// The directory where Orchestrator will store Replica binaries
    #[clap(long)]
    pub(crate) replica_binary_dir: PathBuf,

    /// The directory where Orchestrator will store catch-up packages (CUPs)
    #[clap(long)]
    pub(crate) cup_dir: PathBuf,

    /// The path to the Replica config file
    #[clap(long)]
    pub(crate) replica_config_file: PathBuf,

    /// The path to the Replica binary location containing the following in case
    /// of guest OS deployment: version.txt, manageboot.sh, replica,
    /// install-upgrade.sh
    #[clap(long)]
    pub(crate) ic_binary_directory: Option<PathBuf>,

    /// If not set, the default listen addr (0.0.0.0:[`PROMETHEUS_HTTP_PORT`])
    /// will be used to export metrics.
    #[clap(long)]
    pub(crate) metrics_listen_addr: Option<SocketAddr>,

    /// Provisional CLI-option intended to be used in bootstrap testing. Enables
    /// the registration procedure.
    #[clap(long)]
    pub(crate) enable_provisional_registration: bool,

    /// The path to the version file.
    #[clap(long)]
    pub(crate) version_file: PathBuf,

    /// Print the replica's current node ID.
    #[clap(long)]
    pub node_id: bool,

    /// Print the DC ID where the current replica is located.
    #[clap(long)]
    pub dc_id: bool,

    /// The path to directory that is dedicated to data specific to the orchstrator.
    /// If not provided, the relevant data are not persisted to the disk.
    #[clap(long)]
    pub(crate) orchestrator_data_directory: PathBuf,
}

impl OrchestratorArgs {
    /// Create replica binary and CUP directories associated with this object if
    /// they don't already exist
    pub(crate) fn create_dirs(&self) {
        if !&self.replica_binary_dir.exists() {
            fs::create_dir(&self.replica_binary_dir).unwrap_or_else(|err| {
                panic!(
                    "Failed to create dir {}: {}",
                    self.replica_binary_dir.display(),
                    err,
                )
            });
        }

        if !self.cup_dir.exists() {
            fs::create_dir(&self.cup_dir).unwrap_or_else(|err| {
                panic!("Failed to create dir {}: {}", self.cup_dir.display(), err)
            });
        }
    }

    /// Parse `self.replica_config_file` and persist in
    /// [`TempDir`][tempfile::TempDir] "ic_config"
    pub fn get_ic_config(&self) -> Config {
        let tmpdir = tempfile::Builder::new()
            .prefix("ic_config")
            .tempdir()
            .unwrap()
            .path()
            .to_path_buf();

        let config_source = ConfigSource::File(self.replica_config_file.clone());

        Config::load_with_tmpdir(config_source, tmpdir)
    }

    /// Return the configured metrics address or
    /// "0.0.0.0:[`PROMETHEUS_HTTP_PORT`]" if none is set
    pub(crate) fn get_metrics_addr(&self) -> SocketAddr {
        self.metrics_listen_addr.unwrap_or_else(|| {
            SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), PROMETHEUS_HTTP_PORT).into()
        })
    }
}
