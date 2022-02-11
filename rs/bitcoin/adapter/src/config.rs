use std::net::SocketAddr;

use bitcoin::Network;
use serde::Deserialize;

/// This struct contains configuration options for the BTC Adapter.
#[derive(Clone, Debug, Deserialize)]
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
}

fn default_idle_seconds() -> u64 {
    5
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

        pub fn build(self) -> Config {
            self.config
        }
    }
}
