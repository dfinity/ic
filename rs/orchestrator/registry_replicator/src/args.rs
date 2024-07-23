use clap::Parser;
use ic_config::{
    logger::{Level, LogFormat},
    Config,
};
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
};
use tempfile::TempDir;

use crate::metrics::PROMETHEUS_HTTP_PORT;

#[derive(Debug, Parser)]
#[clap(
    name = "registry_replicator",
    about = "Arguments for the Internet Computer Registry Replicator."
)]
/// Arguments for the orchestrator binary.
pub struct RegistryReplicatorArgs {
    /// Flag to output debug logs
    #[clap(long)]
    pub debug: bool,

    /// Flag to output logs in full text format
    #[clap(long)]
    pub log_as_text: bool,

    /// The path to the NNS public key file
    #[clap(long, parse(from_os_str))]
    pub nns_pub_key_pem: PathBuf,

    /// Comma separated list of NNS URLs
    #[clap(long, default_value = "https://ic0.app")]
    pub nns_url: String,

    /// The registry local store path to be populated
    #[clap(long, parse(from_os_str))]
    pub local_store_path: PathBuf,

    /// If not set, the default listen addr (0.0.0.0:9092)
    /// will be used to export metrics.
    #[clap(long)]
    pub metrics_listen_addr: Option<SocketAddr>,

    /// The delay between NNS polls in milliseconds
    #[clap(long, default_value = "5000")]
    pub poll_delay_duration_ms: u64,
}

impl RegistryReplicatorArgs {
    pub fn get_ic_config(&self) -> (Config, TempDir) {
        let (mut config, _dir) = Config::temp_config();

        config.logger.level = if self.debug {
            Level::Debug
        } else {
            Level::Info
        };
        config.logger.format = if self.log_as_text {
            LogFormat::TextFull
        } else {
            LogFormat::Json
        };
        config.registration.nns_pub_key_pem = Some(self.nns_pub_key_pem.clone());
        config.registration.nns_url = Some(self.nns_url.clone());
        config
            .registry_client
            .local_store
            .clone_from(&self.local_store_path);
        config.nns_registry_replicator.poll_delay_duration_ms = self.poll_delay_duration_ms;

        (config, _dir)
    }

    /// Return the configured metrics address or
    /// "0.0.0.0:[`PROMETHEUS_HTTP_PORT`]" if none is set
    pub fn get_metrics_addr(&self) -> SocketAddr {
        self.metrics_listen_addr.unwrap_or_else(|| {
            SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), PROMETHEUS_HTTP_PORT).into()
        })
    }
}
