//! Defines [`MaliciousBehaviour`] that allows to control malicious flags.

use crate::malicious_flags::{InvalidChunksAllowance, MaliciousFlags};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// When testing our system we need to make some nodes act badly to make sure
/// they don't affect the system more than we expect. These options should NEVER
/// be enabled on a production system.
///
/// Enabling these options can cause your node to attack the network and the
/// network will retaliate by taking away your stake, blocking your data center
/// and generally making your life as difficult as possible. There is also the
/// possibility of data loss/leakage, damage to your hardware and various other
/// nasty things.
/// These are runtime flags because it's very easy to accidentally set compile
/// time flags in rust. It also stops you needing to compile your code against
/// every possible permutation of compile flags on CI.
#[derive(Clone, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct MaliciousBehaviour {
    pub allow_malicious_behaviour: bool,
    // No structs apart from 'allow_malicious_behaviour' should be directly accessible
    // All subsequent fields should start with 'maliciously_' just to really send home that these
    // aren't options you want to enable
    maliciously_seg_fault: bool,
    pub malicious_flags: MaliciousFlags,
}

/// The setters will panic if you try to set
impl MaliciousBehaviour {
    pub fn new(allow_malicious_behaviour: bool) -> Self {
        MaliciousBehaviour {
            allow_malicious_behaviour,
            maliciously_seg_fault: false,
            malicious_flags: Default::default(),
        }
    }

    // Getters
    pub fn maliciously_seg_fault(&self) -> bool {
        self.maliciously_seg_fault && self.allow_malicious_behaviour
    }

    pub fn set_maliciously_seg_fault(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.maliciously_seg_fault = true;
            s
        })
    }

    pub fn set_maliciously_propose_equivocating_blocks(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_propose_equivocating_blocks = true;
            s
        })
    }

    pub fn set_maliciously_propose_empty_blocks(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_propose_empty_blocks = true;
            s
        })
    }

    pub fn set_maliciously_notarize_all(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_notarize_all = true;
            s
        })
    }

    pub fn set_maliciously_finalize_all(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_finalize_all = true;
            s
        })
    }

    pub fn set_maliciously_tweak_dkg(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_tweak_dkg = true;
            s
        })
    }

    pub fn set_maliciously_certify_invalid_hash(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_certify_invalid_hash = true;
            s
        })
    }

    pub fn set_maliciously_malfunctioning_xnet_endpoint(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_malfunctioning_xnet_endpoint = true;
            s
        })
    }

    pub fn set_maliciously_disable_execution(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_disable_execution = true;
            s
        })
    }

    pub fn set_maliciously_corrupt_own_state_at_heights(self, height: u64) -> Self {
        self.set_malicious_behaviour_to(
            |mut s, height| {
                s.malicious_flags
                    .maliciously_corrupt_own_state_at_heights
                    .push(height);
                s
            },
            height,
        )
    }

    pub fn set_maliciously_disable_ingress_validation(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_disable_ingress_validation = true;
            s
        })
    }

    pub fn set_maliciously_corrupt_idkg_dealings(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_corrupt_idkg_dealings = true;
            s
        })
    }

    pub fn set_maliciously_delay_execution(self, delay: Duration) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_delay_execution = Some(delay);
            s
        })
    }

    pub fn set_maliciously_delay_state_sync(self, delay: Duration) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_delay_state_sync = Some(delay);
            s
        })
    }

    pub fn set_maliciously_alter_certified_hash(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags.maliciously_alter_certified_hash = true;
            s
        })
    }

    pub fn set_maliciously_alter_state_sync_chunk_sending_side(self) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags
                .maliciously_alter_state_sync_chunk_sending_side = true;
            s
        })
    }

    pub fn set_maliciously_alter_state_sync_chunk_receiving_side(
        self,
        meta_manifest_chunk_error_allowance: u32,
        manifest_chunk_error_allowance: u32,
        state_chunk_error_allowance: u32,
    ) -> Self {
        self.set_malicious_behaviour(|mut s| {
            s.malicious_flags
                .maliciously_alter_state_sync_chunk_receiving_side = Some(InvalidChunksAllowance {
                meta_manifest_chunk_error_allowance,
                manifest_chunk_error_allowance,
                state_chunk_error_allowance,
            });
            s
        })
    }

    fn set_malicious_behaviour<F: FnOnce(Self) -> Self>(self, f: F) -> Self {
        if self.allow_malicious_behaviour {
            f(self)
        } else {
            panic!("Attempted to enable malicious behavior without first setting allow_malicious_behavior to true")
        }
    }

    fn set_malicious_behaviour_to<T, F: FnOnce(Self, T) -> Self>(self, f: F, value: T) -> Self {
        if self.allow_malicious_behaviour {
            f(self, value)
        } else {
            panic!("Attempted to enable malicious behavior without first setting allow_malicious_behavior to true")
        }
    }
}

impl Default for MaliciousBehaviour {
    fn default() -> Self {
        MaliciousBehaviour::new(false)
    }
}
