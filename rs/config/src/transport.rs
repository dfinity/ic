use serde::{Deserialize, Serialize};
use std::default::Default;

/// The transport format specified in the ic.json
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct TransportConfig {
    pub node_ip: String,

    pub listening_port: u16,

    pub send_queue_size: usize,

    /// Transport creates 'max_streams' logical streams/channels between two peers.
    /// Channel ids should be within [0..max_streams).
    pub max_streams: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            send_queue_size: 51200,
            node_ip: String::default(),
            listening_port: u16::default(),
            max_streams: 1,
        }
    }
}
