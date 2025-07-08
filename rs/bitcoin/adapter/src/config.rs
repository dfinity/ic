use crate::AdapterNetwork;
use ic_config::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
/// The source of the unix domain socket to be used for inter-process
/// communication.
pub enum IncomingSource {
    /// We use systemd's created socket.
    #[default]
    Systemd,
    /// We use the corresponding path as socket.
    Path(PathBuf),
}

/// This struct contains configuration options for the BTC Adapter.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// The type of Bitcoin or Dogecoin network we plan to communicate to (e.g. Mainnet, Testnet, etc.).
    pub network: AdapterNetwork,
    /// A list of DNS seeds for address discovery.
    #[serde(default)]
    pub dns_seeds: Vec<String>,
    /// Addresses of nodes to connect to (in case discovery from seeds is not possible/sufficient)
    #[serde(default)]
    pub nodes: Vec<SocketAddr>,
    #[serde(default)]
    /// This field determines whether or not we will be using a SOCKS proxy to communicate with  the BTC network.
    /// Testing environment shared socks proxy address: socks5://socks5.testnet.dfinity.network:1080
    /// Proxy url is validated and needs to have scheme, host and port specified. I.e socks5://socksproxy.com:1080.
    pub socks_proxy: Option<String>,
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
    /// Specifies the address limits used by the `AddressBook`.
    #[serde(default)]
    pub address_limits: (usize, usize),
}

/// Set the default idle seconds to one hour.
fn default_idle_seconds() -> u64 {
    3600
}

/// This function is used to get the address limits for the `AddressBook`
/// based on the provided `Network`.
pub fn address_limits(network: AdapterNetwork) -> (usize, usize) {
    match network {
        AdapterNetwork::Bitcoin(network) => {
            use bitcoin::Network::*;
            match network {
                Bitcoin => (500, 2000),
                Testnet => (100, 1000),
                //TODO(mihailjianu): revisit these values
                Testnet4 => (100, 1000),
                Signet => (1, 1),
                Regtest => (1, 1),
                _ => (1, 1),
            }
        }
        AdapterNetwork::Dogecoin(network) => {
            use bitcoin::dogecoin::Network::*;
            match network {
                Dogecoin => (200, 1000),
                //TODO(XC-423): revisit these values
                Testnet => (20, 100),
                Regtest => (1, 1),
                _ => (1, 1),
            }
        }
    }
}

impl Config {
    /// This function returns the port to use based on the network provided.
    pub fn network_port(&self) -> u16 {
        match self.network {
            AdapterNetwork::Bitcoin(network) => {
                use bitcoin::Network::*;
                match network {
                    Bitcoin => 8333,
                    Testnet => 18333,
                    Testnet4 => 48333,
                    _ => 8333,
                }
            }
            AdapterNetwork::Dogecoin(network) => {
                use bitcoin::dogecoin::Network::*;
                match network {
                    Dogecoin => 22556,
                    Testnet => 44556,
                    _ => 18444,
                }
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns_seeds: Default::default(),
            network: bitcoin::Network::Bitcoin.into(),
            socks_proxy: Default::default(),
            nodes: vec![],
            idle_seconds: default_idle_seconds(),
            ipv6_only: false,
            logger: LoggerConfig::default(),
            incoming_source: Default::default(),
            address_limits: address_limits(bitcoin::Network::Bitcoin.into()), // Address limits used for Bitcoin mainnet
        }
    }
}

#[cfg(test)]
pub mod test {

    use super::*;

    #[derive(Default)]
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

        pub fn with_network(mut self, network: AdapterNetwork) -> Self {
            self.config.network = network;
            self.config.address_limits = address_limits(network);
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
