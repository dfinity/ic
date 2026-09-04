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

    /// The path to the IC boundary environment file
    #[clap(long)]
    pub(crate) ic_boundary_env_file: PathBuf,

    /// The path to the IC gateway environment file
    #[clap(long)]
    pub(crate) ic_gateway_env_file: PathBuf,

    /// The path to the Replica binary location containing the following in case
    /// of guest OS deployment: replica, ic-boundary, ic-gateway, manageboot.sh,
    /// install-upgrade.sh
    #[clap(long)]
    pub(crate) ic_binary_directory: PathBuf,

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
    /// Where `ic-gateway` keeps its ACME account and the certificates it issues.
    pub(crate) fn acme_cache_dir(&self) -> PathBuf {
        self.orchestrator_data_directory
            .join("ic-gateway")
            .join("acme")
    }

    /// Create the replica binary, CUP and ACME cache directories associated with
    /// this object if they don't already exist
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

        let acme_cache_dir = self.acme_cache_dir();
        if !acme_cache_dir.exists() {
            fs::create_dir_all(&acme_cache_dir).unwrap_or_else(|err| {
                panic!("Failed to create dir {}: {}", acme_cache_dir.display(), err)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn args_for_test(data_directory: PathBuf) -> OrchestratorArgs {
        OrchestratorArgs {
            replica_binary_dir: data_directory.join("replica_binaries"),
            cup_dir: data_directory.join("cups"),
            replica_config_file: data_directory.join("ic.json5"),
            ic_boundary_env_file: data_directory.join("ic-boundary.env"),
            ic_gateway_env_file: data_directory.join("ic-gateway.env"),
            ic_binary_directory: data_directory.clone(),
            metrics_listen_addr: None,
            enable_provisional_registration: false,
            version_file: data_directory.join("version.txt"),
            node_id: false,
            dc_id: false,
            orchestrator_data_directory: data_directory,
        }
    }

    #[test]
    fn create_dirs_creates_the_acme_cache() {
        let dir = tempdir().unwrap();
        let args = args_for_test(dir.path().to_path_buf());

        args.create_dirs();

        // `ic-gateway` writes its ACME account and the private keys of the
        // certificates it issues here.
        assert!(args.acme_cache_dir().is_dir());
    }
}
