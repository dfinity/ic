use serde::{Deserialize, Serialize};

/// The transport format specified in the ic.json
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportConfig {
    pub node_ip: String,

    /// P2P specific config. In future, this will be made more generic.
    pub p2p_flows: Vec<TransportFlowConfig>,
}

/// Per-flow config
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportFlowConfig {
    /// The flow tag. This should be unique per transport client.
    pub flow_tag: u32,

    /// Server port for the flow connection. This should be unique across
    /// all transport clients.
    pub server_port: u16,

    /// Flow queue size
    pub queue_size: usize,
}
