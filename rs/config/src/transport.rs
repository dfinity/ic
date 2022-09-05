use serde::{Deserialize, Serialize};
use std::default::Default;

/// The transport format specified in the ic.json
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportConfig {
    pub node_ip: String,

    pub listening_port: u16,

    pub send_queue_size: usize,

    /// This field is deprecated and will be deleted once NET-1086 is rolled out.
    pub legacy_flow_tag: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            send_queue_size: 51200,
            node_ip: String::default(),
            listening_port: u16::default(),
            legacy_flow_tag: u32::default(),
        }
    }
}
