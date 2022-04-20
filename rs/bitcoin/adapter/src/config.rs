use bitcoin::Network;
use ic_config::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
/// The source of the unix domain socket to be used for inter-process
/// communication.
pub enum IncomingSource {
    /// We use systemd's created socket.
    Systemd,
    /// We use the corresponing path as socket.
    Path(PathBuf),
}

impl Default for IncomingSource {
    fn default() -> Self {
        IncomingSource::Systemd
    }
}

/// This struct contains configuration options for the BTC Adapter.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// The type of Bitcoin network we plan to communicate to (e.g. Mainnet, Testnet, etc.).
    pub network: Network,
    /// A list of DNS seeds for address discovery.
    #[serde(default)]
    pub dns_seeds: Vec<String>,
    /// Addresses of nodes to connect to (in case discovery from seeds is not possible/sufficient)
    #[serde(default)]
    pub nodes: Vec<SocketAddr>,
    /// This field determines whether or not we will be using a SOCKS proxy to communicate with
    /// the BTC network.
    #[serde(default)]
    pub socks_proxy: Option<SocketAddr>,
    /// The number of seconds that need to pass for the adapter to enter the
    /// `Idle` state.
    #[serde(default = "default_idle_seconds")]
    pub idle_seconds: u64,
    /// When this field is set to `true`, the adapter will only connect to Bitcoin nodes
    /// that support IPv6.
    #[serde(default)]
    pub ipv6_only: bool,
    /// Logger config.
    #[serde(default)]
    pub logger: LoggerConfig,
    /// Specifies which unix domain socket should be used for serving incoming requests.
    #[serde(default)]
    pub incoming_source: IncomingSource,
}

/// Set the default idle seconds to one hour.
fn default_idle_seconds() -> u64 {
    3600
}

impl Config {
    /// This function returns the port to use based on the Bitcoin network provided.
    pub fn port(&self) -> u16 {
        match self.network {
            Network::Bitcoin => 8333,
            Network::Testnet => 18333,
            _ => 8333,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns_seeds: Default::default(),
            network: Network::Bitcoin,
            socks_proxy: Default::default(),
            nodes: vec![],
            idle_seconds: 5,
            ipv6_only: false,
            logger: LoggerConfig::default(),
            incoming_source: Default::default(),
        }
    }
}

#[cfg(test)]
pub mod test {

    use super::*;

    pub struct ConfigBuilder {
        config: Config,
    }

    impl ConfigBuilder {
        pub fn new() -> Self {
            Self {
                config: Config::default(),
            }
        }

        pub fn with_dns_seeds(mut self, dns_seeds: Vec<String>) -> Self {
            self.config.dns_seeds = dns_seeds;
            self
        }

        pub fn with_nodes(mut self, nodes: Vec<SocketAddr>) -> Self {
            self.config.nodes = nodes;
            self
        }

        pub fn with_network(mut self, network: Network) -> Self {
            self.config.network = network;
            self
        }

        pub fn with_ipv6_only(mut self, ipv6_only: bool) -> Self {
            self.config.ipv6_only = ipv6_only;
            self
        }

        pub fn build(self) -> Config {
            self.config
        }
    }
}
