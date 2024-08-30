use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Debug, PartialEq, Eq, Serialize)]
#[serde(default)]
/// Message Routing replica config.
///
/// This configuration is only needed so the DC-operator can set the Xnet-port
/// upon registration of the node.
pub struct Config {
    pub xnet_ip_addr: String,
    pub xnet_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            xnet_ip_addr: "127.0.0.1".to_string(),
            xnet_port: 2497,
        }
    }
}
