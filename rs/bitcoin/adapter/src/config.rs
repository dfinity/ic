use crate::AdapterNetwork;
use ic_config::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
pub struct Config<Network> {
    /// The type of Bitcoin or Dogecoin network we plan to communicate to (e.g. Mainnet, Testnet, etc.).
    pub network: Network,
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
    /// Directory that stores cached data
    pub cache_dir: Option<PathBuf>,
    /// Request timeout duration.
    pub request_timeout: Option<Duration>,
}

/// Set the default idle seconds to one hour.
fn default_idle_seconds() -> u64 {
    3600
}

/// Default request timeout is 30 seconds.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// For Regtest request timeout is set to 5 seconds.
pub const REGTEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Return the request timeout duration according to the network.
fn request_timeout(network: AdapterNetwork) -> Duration {
    match network {
        AdapterNetwork::Bitcoin(bitcoin::Network::Regtest)
        | AdapterNetwork::Dogecoin(bitcoin::dogecoin::Network::Regtest) => REGTEST_REQUEST_TIMEOUT,
        _ => DEFAULT_REQUEST_TIMEOUT,
    }
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

impl<Network> Config<Network> {
    /// Return a config of a different network while retaining the rest fields.
    pub fn with_network<T>(self, network: T) -> Config<T> {
        Config {
            network,
            dns_seeds: self.dns_seeds,
            socks_proxy: self.socks_proxy,
            nodes: self.nodes,
            idle_seconds: self.idle_seconds,
            ipv6_only: self.ipv6_only,
            logger: self.logger,
            incoming_source: self.incoming_source,
            address_limits: self.address_limits,
            cache_dir: self.cache_dir,
            request_timeout: self.request_timeout,
        }
    }

    /// Return the request timeout setting, and use default value if not set.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT)
    }
}

impl<Network: Copy + Into<AdapterNetwork>> Config<Network> {
    /// Return a config of the given network with default settings for the rest fields.
    pub fn default_with(network: Network) -> Self {
        Self {
            network,
            dns_seeds: Default::default(),
            socks_proxy: Default::default(),
            nodes: vec![],
            idle_seconds: default_idle_seconds(),
            ipv6_only: false,
            logger: LoggerConfig::default(),
            incoming_source: Default::default(),
            address_limits: address_limits(network.into()),
            cache_dir: None,
            request_timeout: Some(request_timeout(network.into())),
        }
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    use crate::common::BlockchainNetwork;

    pub struct ConfigBuilder<Network> {
        config: Config<Network>,
    }

    impl<Network: BlockchainNetwork + Into<AdapterNetwork>> ConfigBuilder<Network> {
        pub fn default_with(network: Network) -> Self {
            Self {
                config: Config::default_with(network),
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
            self.config.address_limits = address_limits(network.into());
            self
        }

        pub fn with_ipv6_only(mut self, ipv6_only: bool) -> Self {
            self.config.ipv6_only = ipv6_only;
            self
        }

        pub fn build(self) -> Config<Network> {
            self.config
        }
    }
}
