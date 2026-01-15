use serde::{Deserialize, Serialize};

/// Desired byte size of an outgoing stream.
///
/// At most `MAX_STREAM_MESSAGES` are enqueued into a stream; but only until its
/// `count_bytes()` is greater than or equal to `TARGET_STREAM_SIZE_BYTES`.
pub const TARGET_STREAM_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of messages in a stream.
///
/// At most `MAX_STREAM_MESSAGES` are enqueued into a stream; but only until its
/// `count_bytes()` is greater than or equal to `TARGET_STREAM_SIZE_BYTES`.
pub const MAX_STREAM_MESSAGES: usize = 10_000;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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
