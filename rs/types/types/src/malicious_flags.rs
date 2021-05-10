//! Defines flags that can change a network's behavior.
//!
//! This module defines a global struct to control which
//! malicious behavior to enable in different components.
//! Both struct and fields have to be public
//!
//! Introducing a new malicious behavior starts with extending
//! this component struct with a new flag
//!
//! It is desirable to have a description for each flag in this file

use serde::{Deserialize, Serialize};

/// Groups all available malicious flags.
#[derive(Clone, Default, Deserialize, Debug, PartialEq, Eq, Serialize)]
pub struct MaliciousFlags {
    // malicious gossip does not send requested artifacts
    pub maliciously_gossip_drop_requests: bool,
    pub maliciously_gossip_artifact_not_found: bool,
    pub maliciously_gossip_send_many_artifacts: bool,
    pub maliciously_gossip_send_invalid_artifacts: bool,
    pub maliciously_gossip_send_late_artifacts: bool,
    pub maliciously_propose_equivocating_blocks: bool,
    pub maliciously_propose_empty_blocks: bool,
    pub maliciously_finalize_all: bool,
    pub maliciously_notarize_all: bool,
    pub maliciously_tweak_dkg: bool,
    pub maliciously_certify_invalid_hash: bool,
    pub maliciously_malfunctioning_xnet_endpoint: bool,
    pub maliciously_disable_execution: bool,
    /// If this flag is set, the result of validate_message() is ignored in the
    /// http handler.
    pub maliciously_disable_http_handler_ingress_validation: bool,
    pub maliciously_corrupt_own_state_at_heights: Vec<u64>,
}

impl MaliciousFlags {
    /// This function is to distinguish maliciousness gated by consensus's
    /// implementation.
    pub fn is_consensus_malicious(&self) -> bool {
        self.maliciously_propose_equivocating_blocks
            || self.maliciously_propose_empty_blocks
            || self.maliciously_finalize_all
            || self.maliciously_notarize_all
    }
}
