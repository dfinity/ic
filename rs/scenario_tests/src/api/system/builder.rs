use ic_protobuf::registry::subnet::v1::GossipConfig;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::p2p::build_default_gossip_config;
use ic_types::Height;
use std::time::Duration;

/// A builder for the initial configuration of a subnetwork.
#[derive(Clone, Debug, PartialEq)]
pub struct Subnet {
    pub(crate) nodes: Vec<Node>,
    pub(crate) max_ingress_bytes_per_message: Option<u64>,
    pub(crate) ingress_bytes_per_block_soft_cap: Option<u64>,
    pub(crate) max_ingress_messages_per_block: Option<u64>,
    pub(crate) max_block_payload_size: Option<u64>,
    pub(crate) unit_delay: Option<Duration>,
    pub(crate) initial_notary_delay: Option<Duration>,
    pub(crate) dkg_interval_length: Option<Height>,
    pub(crate) dkg_dealings_per_block: Option<usize>,
    pub(crate) max_instructions_per_message: Option<u64>,
    pub(crate) max_instructions_per_round: Option<u64>,
    pub(crate) max_instructions_per_install_code: Option<u64>,
    pub(crate) max_number_of_canisters: Option<u64>,
    pub(crate) gossip_config: Option<GossipConfig>,
}

impl Subnet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_malicious_nodes(
        mut self,
        no_of_nodes: usize,
        malicious_behaviour: MaliciousBehaviour,
    ) -> Self {
        for _ in 0..no_of_nodes {
            let node = Node::new().with_malicious_behaviour(malicious_behaviour.clone());
            self.nodes.push(node);
        }
        self
    }

    pub fn add_nodes(mut self, no_of_nodes: usize) -> Self {
        (0..no_of_nodes).for_each(|_| self.nodes.push(Default::default()));
        self
    }

    pub fn add_node(mut self, node: Node) -> Self {
        self.nodes.push(node);
        self
    }

    pub fn with_max_ingress_message_size(mut self, limit: u64) -> Self {
        self.max_ingress_bytes_per_message = Some(limit);
        self
    }

    pub fn with_ingress_bytes_per_block_soft_cap(mut self, limit: u64) -> Self {
        self.ingress_bytes_per_block_soft_cap = Some(limit);
        self
    }

    pub fn with_unit_delay(mut self, unit_delay: Duration) -> Self {
        self.unit_delay = Some(unit_delay);
        self
    }

    pub fn with_initial_notary_delay(mut self, initial_notary_delay: Duration) -> Self {
        self.initial_notary_delay = Some(initial_notary_delay);
        self
    }

    pub fn with_dkg_interval_length(mut self, dkg_interval_length: Height) -> Self {
        self.dkg_interval_length = Some(dkg_interval_length);
        self
    }

    pub fn with_dkg_dealings_per_block(mut self, dkg_dealings_per_block: usize) -> Self {
        self.dkg_dealings_per_block = Some(dkg_dealings_per_block);
        self
    }
}

impl Default for Subnet {
    fn default() -> Self {
        Self {
            nodes: vec![],
            max_ingress_bytes_per_message: None,
            ingress_bytes_per_block_soft_cap: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay: None,
            initial_notary_delay: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            max_number_of_canisters: None,
            gossip_config: Some(build_default_gossip_config()),
        }
    }
}

/// A builder for the initial configuration of a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub(crate) malicious_behaviour: Option<MaliciousBehaviour>,
}

impl Node {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_malicious_behaviour(mut self, malicious_behaviour: MaliciousBehaviour) -> Self {
        self.malicious_behaviour = Some(malicious_behaviour);
        self
    }
}

impl Default for Node {
    fn default() -> Self {
        Self {
            malicious_behaviour: None,
        }
    }
}
