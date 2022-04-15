use crate::metrics::PROMETHEUS_HTTP_PORT;
use clap::Parser;
use ic_config::{Config, ConfigSource};
use std::path::PathBuf;
use std::{
    fs,
    net::{SocketAddr, SocketAddrV4},
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
    #[clap(long, parse(from_os_str))]
    pub(crate) replica_binary_dir: PathBuf,

    /// The directory where Orchestrator will store catch-up packages (CUPs)
    #[clap(long, parse(from_os_str))]
    pub(crate) cup_dir: PathBuf,

    /// The path to the Replica config file
    #[clap(long, parse(from_os_str))]
    pub(crate) replica_config_file: PathBuf,

    /// The path to the Replica binary location containing the following in case
    /// of guest OS deployment: version.txt, manageboot.sh, replica,
    /// install-upgrade.sh
    #[clap(long, parse(from_os_str))]
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
    #[clap(long, parse(from_os_str))]
    pub(crate) version_file: PathBuf,

    /// Print the replica's current node ID.
    #[clap(long)]
    pub node_id: bool,

    /// Print the DC ID where the current replica is located.
    #[clap(long)]
    pub dc_id: bool,
}

impl OrchestratorArgs {
    /// Create replica binary and CUP directories associated with this object if
    /// they don't already exist
    pub(crate) fn create_dirs(&self) {
        if !&self.replica_binary_dir.exists() {
            fs::create_dir(&self.replica_binary_dir)
                .unwrap_or_else(|_| panic!("Failed to create dir: {:?}", &self.replica_binary_dir));
        }

        if !self.cup_dir.exists() {
            fs::create_dir(&self.cup_dir)
                .unwrap_or_else(|_| panic!("Failed to create dir: {:?}", &self.cup_dir));
        }
    }

    /// Parse `self.replica_config_file` and persist in
    /// [`TempDir`][tempfile::TempDir] "ic_config"
    pub(crate) fn get_ic_config(&self) -> Config {
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
            SocketAddrV4::new("0.0.0.0".parse().expect("can't fail"), PROMETHEUS_HTTP_PORT).into()
        })
    }
}
