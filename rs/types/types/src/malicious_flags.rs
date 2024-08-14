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
use std::time::{Duration, Instant};

/// Groups all available malicious flags.
#[derive(Clone, Default, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct MaliciousFlags {
    pub maliciously_propose_equivocating_blocks: bool,
    pub maliciously_propose_empty_blocks: bool,
    pub maliciously_finalize_all: bool,
    pub maliciously_notarize_all: bool,
    pub maliciously_tweak_dkg: bool,
    pub maliciously_certify_invalid_hash: bool,
    pub maliciously_malfunctioning_xnet_endpoint: bool,
    pub maliciously_disable_execution: bool,
    pub maliciously_corrupt_own_state_at_heights: Vec<u64>,
    pub maliciously_disable_ingress_validation: bool,
    pub maliciously_corrupt_idkg_dealings: bool,
    /// Delay execution such that it takes at least [`Duration`] time
    pub maliciously_delay_execution: Option<Duration>,
    /// Delay state sync such that it takes at least [`Duration`] time
    pub maliciously_delay_state_sync: Option<Duration>,
    /// Alter the signed hash in the certification before verifying a
    /// stream slice's signature.
    pub maliciously_alter_certified_hash: bool,
    pub maliciously_alter_state_sync_chunk_sending_side: bool,
    pub maliciously_alter_state_sync_chunk_receiving_side: Option<InvalidChunksAllowance>,
}

#[derive(Clone, Default, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct InvalidChunksAllowance {
    pub meta_manifest_chunk_error_allowance: u32,
    pub manifest_chunk_error_allowance: u32,
    pub state_chunk_error_allowance: u32,
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

    /// This function is to distinguish maliciousness gated by idkg's
    /// implementation.
    pub fn is_idkg_malicious(&self) -> bool {
        self.maliciously_corrupt_idkg_dealings
    }

    /// Delay the execution as specified by `maliciously_delay_execution`
    pub fn delay_execution(&self, execution_start: Instant) -> Option<Duration> {
        self.maliciously_delay_execution
            .and_then(|delay| Self::delay(delay, execution_start))
    }

    /// Delay the state sync, as specified by `maliciously_delay_state_sync`
    pub fn delay_state_sync(&self, sync_start: Instant) -> Option<Duration> {
        self.maliciously_delay_state_sync
            .and_then(|delay| Self::delay(delay, sync_start))
    }

    /// Delays the execution, such that the function returns only after `min_time` has elapsed
    fn delay(min_time: Duration, start: Instant) -> Option<Duration> {
        let wait_until = start + min_time;
        let now = Instant::now();

        if wait_until > now {
            let delay_duration = wait_until - now;
            std::thread::sleep(delay_duration);
            Some(delay_duration)
        } else {
            None
        }
    }
}
